"""The homepage, as Google's OAuth brand verifier reads it.

This file exists because verification was rejected twice, and both findings were
the same three characters of markup: `<div id="root"></div>`. The reviewer fetches
the homepage URL without executing JavaScript, so the page explained nothing ("en
la página principal, no se explica el propósito de la app") and carried no name to
compare against the consent screen's "App name" field.

`legal.py` had said so in its own docstring since the day it was written. The fix
reached /privacy and /terms and never reached the homepage. Nothing failed when it
did not, because no test had an opinion about what the homepage contains — 664 of
them passed while the page a reviewer reads was blank.

So these assertions are deliberately about CONTENT, not about status codes. A 200
answering with an empty body is the exact bug, and it passes every smoke test in
this suite. They are also deliberately about the response Flask returns rather
than about `dist/index.html` on disk: the prefix substitution happens at serve
time, and an unsubstituted `__VIGIA_PREFIX__` would send the reviewer to a 404
where the privacy policy should be.
"""
from __future__ import annotations

import os
import re

import pytest

#: The app name, spelled as it must appear BOTH on this page and in the OAuth
#: consent screen's "App name" field. Google compares them literally, so the
#: accent is part of the identity and not a typographical nicety. If this ever
#: changes, it changes in Google Cloud Console in the same sitting.
NOMBRE_APP = "Vigía"

#: Words that make the page an explanation rather than a landing. Each one is
#: something the reviewer is looking for: what it does, to what, and how.
TERMINOS_DE_PROPOSITO = [
    "Google Workspace",
    "solo lectura",
    "seguridad",
]

#: The four scopes the app actually requests. The homepage naming them is what
#: turns "trust me" into something checkable against the consent screen.
PERMISOS = [
    "admin.directory.user.readonly",
    "admin.directory.domain.readonly",
    "admin.reports.audit.readonly",
    "cloud-identity.policies.readonly",
]


@pytest.fixture(scope="module")
def cliente(tmp_path_factory):
    directorio = tmp_path_factory.mktemp("portada")
    os.environ["VIGIA_DB_PATH"] = str(directorio / "portada.db")
    os.environ["VIGIA_CONTACT_EMAIL"] = "diego@diegofarina.com"
    from vigia import create_app

    app = create_app()
    return app.test_client()


def _cuerpo(cliente) -> str:
    # `?lang=es` explícito, no `/` a secas: el cliente de pruebas guarda la cookie
    # `vigia_lang`, así que una petición sin parámetro después de un `?lang=en`
    # devuelve la portada INGLESA y estas pruebas medirían el idioma que no creen
    # estar midiendo, según el orden en que pytest las ejecute.
    respuesta = cliente.get("/?lang=es")
    assert respuesta.status_code == 200
    return respuesta.get_data(as_text=True)


def _sin_marcado(html: str) -> str:
    """The text a reader sees: comments and scripts stripped, tags removed.

    Asserting against raw HTML would let a promise hidden in a comment or in a
    JSON blob inside a <script> satisfy a test about what the page says.
    """
    cuerpo = re.search(r"<body>(.*)</body>", html, re.S)
    texto = cuerpo.group(1) if cuerpo else html
    texto = re.sub(r"<!--.*?-->", " ", texto, flags=re.S)
    texto = re.sub(r"<(script|style)\b.*?</\1>", " ", texto, flags=re.S)
    return re.sub(r"<[^>]+>", " ", texto)


def test_la_portada_no_esta_vacia(cliente):
    """The bug itself: a 200 whose body is an empty mount point."""
    texto = _sin_marcado(_cuerpo(cliente)).strip()
    assert len(texto) > 500, (
        "the homepage renders under 500 characters of text without JavaScript; "
        "this is the state Google rejected twice"
    )


def test_el_nombre_de_la_app_es_el_h1(cliente):
    """The name has to be findable, and the most findable place is the heading."""
    html = _cuerpo(cliente)
    encabezados = re.findall(r"<h1[^>]*>(.*?)</h1>", html, re.S)
    assert encabezados, "the homepage has no <h1>"
    assert any(NOMBRE_APP == h.strip() for h in encabezados), (
        f"no <h1> holds exactly {NOMBRE_APP!r}; found {[h.strip() for h in encabezados]}. "
        "It must match the consent screen's App name character for character."
    )


def test_explica_el_proposito(cliente):
    texto = _sin_marcado(_cuerpo(cliente))
    faltan = [t for t in TERMINOS_DE_PROPOSITO if t.lower() not in texto.lower()]
    assert not faltan, f"the homepage never says: {faltan}"


def test_el_proposito_esta_tambien_en_ingles(cliente):
    """One English sentence, properly tagged.

    The page is Spanish because the product is, and the reviewers who decide
    whether it explains itself work mostly in English. The `lang` attribute is part
    of the assertion, not decoration: without it a screen reader pronounces this
    paragraph with Spanish phonetics.
    """
    html = _cuerpo(cliente)
    parrafo = re.search(r'<p[^>]*\blang="en"[^>]*>(.*?)</p>', html, re.S)
    assert parrafo, 'the homepage has no <p lang="en"> purpose statement'
    texto = re.sub(r"\s+", " ", parrafo.group(1)).strip()
    for palabra in ("web application", "Google Workspace", "read-only"):
        assert palabra in texto, f"the English statement never says {palabra!r}: {texto!r}"


def test_ningun_comentario_html_habla_de_la_revision(cliente):
    """Comments in this document are served to the public, reviewers included.

    Twice now the rationale for a change went into an HTML comment and shipped —
    notes about Google's verification, readable by the person doing the
    verification. The reasoning belongs in the Python that serves the file.
    """
    comentarios = " ".join(re.findall(r"<!--(.*?)-->", _cuerpo(cliente), re.S)).lower()
    for palabra in ("google", "verificación", "verification", "revisor", "reviewer", "oauth"):
        assert palabra not in comentarios, (
            f"an HTML comment served to the public mentions {palabra!r}: {comentarios.strip()!r}"
        )


def test_nombra_los_permisos_que_pide(cliente):
    texto = _sin_marcado(_cuerpo(cliente))
    faltan = [p for p in PERMISOS if p not in texto]
    assert not faltan, f"the homepage does not name the scopes it requests: {faltan}"


def test_los_permisos_de_la_pagina_son_los_que_se_piden_de_verdad(cliente):
    """The page and the OAuth request cannot drift apart.

    A homepage that lists a scope the app no longer asks for, or omits one it
    started asking for, is worse than one that lists none: it is a specific claim
    that does not match the consent screen the reviewer sees next.
    """
    from vigia.auth.oauth import WORKSPACE_SCOPES

    pedidos = {s.rsplit("/", 1)[-1] for s in WORKSPACE_SCOPES}
    assert pedidos == set(PERMISOS), (
        "WORKSPACE_SCOPES changed without the homepage following it: "
        f"requested={sorted(pedidos)} documented={sorted(PERMISOS)}"
    )


def test_enlaza_privacidad_y_condiciones(cliente):
    """The two URLs the consent screen configuration points at."""
    html = _cuerpo(cliente)
    for ruta in ("/privacy", "/terms"):
        assert re.search(rf'href="[^"]*{ruta}"', html), f"the homepage does not link {ruta}"


def test_no_queda_ningun_marcador_de_prefijo(cliente):
    """An unsubstituted placeholder is a 404 where the privacy policy should be."""
    assert "__VIGIA_PREFIX__" not in _cuerpo(cliente)


def test_los_enlaces_llevan_el_prefijo_configurado(cliente, monkeypatch):
    """Served under /vigia, the links must carry it: they cannot be relative.

    Without JavaScript the inline `<base href>` is never written, so a relative
    "privacy" resolves against / and misses the mount point entirely.
    """
    monkeypatch.setenv("VIGIA_DB_PATH", os.environ["VIGIA_DB_PATH"])
    monkeypatch.setenv("VIGIA_PREFIX", "/vigia")
    from vigia import create_app

    html = create_app().test_client().get("/").get_data(as_text=True)
    assert 'href="/vigia/privacy"' in html
    assert 'href="/vigia/terms"' in html


# --------------------------------------------------------------------------- #
# The same page, in English.
#
# Every test above reads the Spanish homepage, which is what existed when they
# were written. The page is now bilingual, and an English homepage is not a nice
# extra here: the finding Google rejected the app on twice was about *this* page
# explaining the app's purpose, and the reviewers who read it work in English.
# A second language that nobody checks is a second language that rots.
# --------------------------------------------------------------------------- #


def _cuerpo_en(cliente) -> str:
    respuesta = cliente.get("/?lang=en")
    assert respuesta.status_code == 200
    return respuesta.get_data(as_text=True)


def test_la_portada_inglesa_se_declara_en_ingles(cliente):
    """`<html lang>` moves with the document.

    It was hardcoded `es` while the body was English, and that attribute is the
    first thing a screen reader and a translator consult: an English page
    declaring Spanish gets read aloud with Spanish phonetics.
    """
    assert '<html lang="en">' in _cuerpo_en(cliente)
    assert '<html lang="es">' in _cuerpo(cliente)


def test_la_portada_inglesa_explica_el_proposito(cliente):
    """The purpose statement, in English, in the body — not only in the echo."""
    texto = _sin_marcado(_cuerpo_en(cliente))
    assert "web application" in texto
    assert "read-only" in texto
    # The verb matters: it reviews and reports, it does not change anything.
    assert "reviews the security configuration" in texto


def test_la_portada_inglesa_no_deja_castellano(cliente):
    """No half-translated page.

    Anchored on function words rather than on any one sentence, so it keeps
    working when the prose is reworded. `Vigía` is exempt: it is the app's name,
    it carries its accent in both languages, and it has to stay byte-identical to
    the consent screen's "App name" field.
    """
    texto = _sin_marcado(_cuerpo_en(cliente))
    # The English echo of the purpose statement only appears on the Spanish page,
    # so on this one there is nothing legitimately Spanish left to allow for.
    castellano = re.findall(
        r"\b(?:de la|de los|que se|para que|con el|una|los|las|tus|sin)\b", texto
    )
    assert not castellano, f"castellano en la portada inglesa: {sorted(set(castellano))}"


def test_el_nombre_de_la_app_es_el_h1_tambien_en_ingles(cliente):
    """The consent screen's "App name" is one string, so the <h1> is too.

    A translated <h1> would reintroduce exactly the finding that was raised: "el
    nombre de la app que configuraste para la pantalla de consentimiento no
    coincide con el nombre de la app de tu página principal".
    """
    for html in (_cuerpo(cliente), _cuerpo_en(cliente)):
        h1 = re.search(r"<h1[^>]*>(.*?)</h1>", html, re.S)
        assert h1 is not None
        assert h1.group(1).strip() == "Vigía"


def test_los_permisos_se_nombran_en_los_dos_idiomas(cliente):
    """The scope list comes from `scopes.py` in the reader's language.

    Typed into the template once, it said "Cuatro permisos" while the
    authorization request asked for six — and the privacy policy listed all six,
    so the two surfaces a Google reviewer reads side by side disagreed about how
    many permissions the app wants.
    """
    from vigia import scopes

    for lang, html in (("es", _cuerpo(cliente)), ("en", _cuerpo_en(cliente))):
        texto = _sin_marcado(html)
        resumen = re.sub(r"<[^>]+>", "", scopes.resumen_permisos(lang))
        assert resumen[:40] in texto, f"{lang}: falta el resumen de permisos"
        # The generated list itself, in this language. Compared against
        # `lista_items` rather than re-derived from `SCOPES`, because what the page
        # shows is the four scopes that read the organisation with their `lee`
        # description — the summary is what accounts for all six — and a test that
        # re-derives the list is a second implementation of it.
        for linea in re.sub(r"<[^>]+>", "\n", scopes.lista_items(lang)).split("\n"):
            if linea.strip():
                assert linea.strip() in texto, f"{lang}: falta «{linea.strip()[:50]}»"
        # And the other language's summary is NOT there: half-translated is a
        # failure mode this test exists to catch.
        otro = "en" if lang == "es" else "es"
        assert re.sub(r"<[^>]+>", "", scopes.resumen_permisos(otro))[:40] not in texto


def test_el_selector_de_idioma_apunta_al_otro_idioma(cliente):
    """A reader without JavaScript can still change language.

    The React toggle does not exist on this page — it *is* the page React
    replaces — so the switch has to be a plain link.
    """
    es, en = _cuerpo(cliente), _cuerpo_en(cliente)
    assert re.search(r'class="idioma"[^>]*href="[^"]*\?lang=en"[^>]*>EN<', es)
    assert re.search(r'class="idioma"[^>]*href="[^"]*\?lang=es"[^>]*>ES<', en)
