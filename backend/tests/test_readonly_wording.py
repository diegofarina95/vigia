"""One claim, five surfaces, two languages, one wording each.

The read-only promise is the sentence that decides whether an administrator hands
over super-admin access to a stranger's tool. It existed in four different
phrasings:

* the report footer — "Vigía nunca ha solicitado permisos de Gmail, Drive ni
  ningún otro permiso restringido… lo impide la propia API de Google, no solo
  nuestra política."
* the privacy footer — "es una herramienta de solo lectura: no modifica ningún
  ajuste… y nunca solicita acceso al contenido."
* the terms — "El acceso es de solo lectura: Vigía no modifica nada."
* the React landing — "solicita únicamente permisos de solo lectura sobre
  metadatos de administración…"

All four were true. All four said it differently, which reads as carelessness
exactly where carelessness is most expensive. The report's version is now the
canonical one because it is the only one that says **why** Vigía cannot read
anything: Google's API refuses. The others asked the reader to trust a policy,
and a technical reader can verify the first claim and only trust the second.

A constant that four files are supposed to agree with is not a source of truth
unless something checks, so this checks — including the React file, which no
Python import can reach.

Now in two languages. The claim lives in the locale catalogue
(`email.solo_lectura` in `scripts/build_locales.py`) and is read with
`read_only_claim(lang)`; `wording.py` keeps the Spanish as a literal constant for
the surfaces that interpolate it into an f-string today. That is a second copy of
the Spanish, so the first test below asserts the two are the same string — the
same arrangement, and the same reason, as the sentence pinned inside
`Landing.tsx`.

Which surfaces are checked in which language, and why:

* the catalogue — both, and the English is compared against `ANCLADAS.en.claim`
  in `Landing.tsx`, so there can only ever be ONE English redaction.
* the React landing — both, because it pins both.
* /privacy and /terms — both: they take a `lang` and read the claim through
  `read_only_claim`.
* the report footer — Spanish. `report.py` still interpolates the constant, so it
  answers in Spanish whatever language the PDF is asked for; when it takes the
  claim by language, the assertion to add here is the English claim in an English
  render, not a second English sentence.
"""
from __future__ import annotations

import pathlib
import re

from vigia.wording import (
    READ_ONLY_CLAIM,
    READ_ONLY_LEAD,
    SCAN_DID_NOT_MODIFY,
    read_only_claim,
    read_only_lead,
    read_only_paragraph,
    scan_did_not_modify,
    site_link,
)

RAIZ = pathlib.Path(__file__).resolve().parents[2]
LANDING = RAIZ / "frontend" / "src" / "pages" / "Landing.tsx"


def _plano(texto: str) -> str:
    """Whitespace-normalised, tags stripped — the four surfaces wrap the same
    sentence across lines at four different indentations."""
    sin_tags = re.sub(r"<[^>]+>", " ", texto)
    sin_tags = sin_tags.replace("&laquo;", "«").replace("&raquo;", "»")
    return re.sub(r"\s+", " ", sin_tags).strip()


def _sin_concatenar(fuente: str) -> str:
    """`"…" + "…"` joined back into one string, for reading a .tsx as text.

    The Spanish claim is one long literal in `Landing.tsx` precisely so that a
    substring search finds it. The English one is wrapped across three literals,
    which no amount of whitespace normalising can put back together — so the
    concatenation is undone before the search rather than asking the frontend to
    keep a 200-character line for the benefit of a Python test.
    """
    return re.sub(r'"\s*\+\s*"', "", fuente)


#: The phrase that made the report's version the canonical one. Asserted on its
#: own so a future edit that keeps the shape but drops the reason fails loudly:
#: "we promise not to" and "the API will not let us" are different arguments and
#: only one of them survives a technical reader. Both languages, because a
#: translation that softens this into a promise has thrown away the argument.
POR_QUE = "lo impide la propia API de Google, no solo nuestra política"
POR_QUE_EN = "Google's own API prevents it, not just our policy"


def test_the_canonical_claim_says_why_not_just_what():
    assert POR_QUE in READ_ONLY_CLAIM
    assert "Gmail" in READ_ONLY_CLAIM and "Drive" in READ_ONLY_CLAIM
    # The scan-specific sentence is deliberately NOT part of the claim: the
    # privacy page and the landing describe the tool, not a particular scan.
    assert SCAN_DID_NOT_MODIFY not in READ_ONLY_CLAIM


def test_the_english_claim_says_why_too():
    ingles = read_only_claim("en")
    assert POR_QUE_EN in ingles
    assert "Gmail" in ingles and "Drive" in ingles
    assert scan_did_not_modify("en") not in ingles


def test_the_spanish_constant_and_the_catalogue_are_the_same_string():
    """The literal in `wording.py` is a copy, so it is checked like one.

    `report.py` and `legal.py` interpolate the constants, so they stayed as
    literals when the claim became bilingual. A copy nothing compares is how
    there came to be four wordings in the first place.
    """
    assert read_only_claim("es") == READ_ONLY_CLAIM
    assert read_only_lead("es") == READ_ONLY_LEAD
    assert scan_did_not_modify("es") == SCAN_DID_NOT_MODIFY


def test_neither_language_is_a_missing_catalogue_key():
    """A gap in the catalogue surfaces as the dotted path, which would otherwise
    reach a customer as "email.solo_lectura.claim"."""
    for lang in ("es", "en"):
        for pieza in (read_only_claim(lang), read_only_lead(lang), scan_did_not_modify(lang)):
            assert not pieza.startswith("email."), (lang, pieza)
            assert pieza.strip()
    # And the two languages are actually two.
    assert read_only_claim("en") != read_only_claim("es")
    # The paragraph is assembled from the same pieces, in the language asked for.
    parrafo = read_only_paragraph("en", include_scan_note=True)
    assert read_only_lead("en") in parrafo and read_only_claim("en") in parrafo
    assert scan_did_not_modify("en") in parrafo


def test_surface_1_the_report_footer():
    from tests.fakes import FakeContext
    from vigia.report import build_html_report
    from vigia.scan import collect_findings, evaluated_result
    from vigia.scoring import compute_score, severity_counts

    ctx = FakeContext(users=[
        {"primaryEmail": "jefe@x.com", "orgUnitPath": "/", "isAdmin": True,
         "isDelegatedAdmin": False, "isEnrolledIn2Sv": False, "isEnforcedIn2Sv": True,
         "suspended": False, "archived": False,
         "lastLoginTime": "1970-01-01T00:00:00.000Z"},
    ])
    findings = collect_findings(ctx, label="x.com")
    rendered = [f.to_dict() for f in findings]
    score = compute_score(findings)
    resultado = evaluated_result(rendered, score, severity_counts(findings), ctx)
    html = build_html_report(
        {"primary_domain": "x.com", "admin_email": "jefe@x.com"},
        {"score": score, "counts": severity_counts(findings), "findings": rendered,
         "manual_checks": [], "created_at": "2026-08-03T00:00:00+00:00",
         "engine_version": "v1-test", "result": resultado},
        None, {"has_baseline": False}, [],
        actions=resultado["actions"], breakdown=resultado["breakdown"],
        people=resultado["people_at_risk"],
    )
    plano = _plano(html)
    assert _plano(READ_ONLY_LEAD) in plano
    assert _plano(READ_ONLY_CLAIM) in plano
    assert _plano(SCAN_DID_NOT_MODIFY) in plano


def test_surface_2_the_privacy_footer():
    """Both languages: the privacy page takes a `lang`, so an English reader gets
    the English claim rather than the Spanish one under an English heading."""
    from vigia.legal import privacy_html

    for lang in ("es", "en"):
        plano = _plano(privacy_html("/vigia", "diego@diegofarina.com", 24, lang=lang))
        assert _plano(read_only_claim(lang)) in plano, lang


def test_surface_3_the_terms():
    from vigia.legal import terms_html

    for lang in ("es", "en"):
        plano = _plano(terms_html("/vigia", "diego@diegofarina.com", lang=lang))
        assert _plano(read_only_claim(lang)) in plano, lang


def test_surface_4_the_react_landing():
    """The one a Python import cannot reach, which is why it drifted.

    Not skipped when the file is missing: a test that quietly passes because it
    could not find what it was checking is worse than no test. Six GeoIP tests in
    this suite did exactly that once.

    Both languages: the landing pins the claim in `ANCLADAS`, one entry per
    language, and either of them can drift on its own.
    """
    assert LANDING.is_file(), f"no está {LANDING} — ¿se movió el frontend?"
    plano = _plano(_sin_concatenar(LANDING.read_text()))
    for lang in ("es", "en"):
        assert _plano(read_only_claim(lang)) in plano, (
            f"el landing de React se ha desviado del literal canónico en {lang}; "
            "edítalo en scripts/build_locales.py (email.solo_lectura.claim) y copia "
            "el texto, no lo reescribas"
        )


def test_there_is_only_one_english_redaction_of_the_claim():
    """The English half was written in `Landing.tsx` first.

    The catalogue took it verbatim instead of translating the Spanish a second
    time, because two English sentences that both mean the right thing is exactly
    the failure this file exists to prevent — it is how the Spanish ended up with
    four. Asserted by pulling the pinned literal back out of the .tsx and
    comparing it to the catalogue.
    """
    fuente = _sin_concatenar(LANDING.read_text())
    bloque = fuente.split("en: {", 1)[1]
    anclado = re.search(r'claim:\s*"(.+?)",\n', bloque, re.S)
    assert anclado, "no se encuentra ANCLADAS.en.claim en Landing.tsx"
    assert _plano(anclado.group(1)) == _plano(read_only_claim("en"))


def test_no_surface_keeps_an_old_variant():
    """The four old phrasings, by name. Each was replaced; if one comes back it
    means somebody re-wrote instead of reusing, which is how there came to be four.
    """
    VIEJAS = (
        "es una herramienta de solo lectura",
        "nunca solicita acceso al contenido",
        "solicita únicamente permisos de solo lectura",
        "El acceso es de solo lectura",
    )
    from vigia.legal import privacy_html, terms_html

    superficies = {
        "privacidad": privacy_html("/vigia", "diego@diegofarina.com", 24),
        "términos": terms_html("/vigia", "diego@diegofarina.com"),
        "Landing.tsx": LANDING.read_text(),
    }
    hallados = []
    for nombre, texto in superficies.items():
        plano = _plano(texto)
        for vieja in VIEJAS:
            if vieja in plano:
                hallados.append(f"{nombre}: «{vieja}»")
    assert hallados == [], "variantes antiguas de vuelta:\n  " + "\n  ".join(hallados)


# ------------------------------------------------- el enlace de vuelta a la web

def test_the_report_links_back_to_the_site_with_the_language():
    """The report is a PDF that gets forwarded from the technician to the manager.
    Before this it ended with "Informe generado por Vigía" and no link at all, so a
    forward went nowhere. The language is in the URL because somebody sent a
    Spanish report must not land on an English page.
    """
    assert site_link("es") == "https://diegofarina.com/?lang=es"
    assert site_link("en") == "https://diegofarina.com/?lang=en"
    assert site_link("es-ES") == "https://diegofarina.com/?lang=es"
    # Anything unrecognised falls to English rather than guessing.
    assert site_link("fr") == "https://diegofarina.com/?lang=en"


# ------------------------- garantías y prohibiciones no se pintan igual

def test_a_guarantee_is_never_marked_with_the_red_cross():
    """Colour and symbol have to say the same thing.

    Three lists in these pages describe things Vigía does NOT do, and they are not
    the same kind of statement:

      • /connect "Lo que Vigía no puede hacer" — a GUARANTEE
      • /privacy "Qué no se hace nunca"        — a GUARANTEE
      • /terms   "Uso aceptable"               — a PROHIBITION aimed at the reader

    All three carried `.no`, whose `::marker` is a red ✕. On a guarantee that reads
    as a failure: the colour says "bad" while the sentence says "you are covered".
    On /connect it was worse — the page drew a second, green ✕ with a `::before`,
    so every line showed two icons contradicting each other.

    Guarantees now use `.marcada` with a green padlock. The prohibition keeps the
    red ✕, because there "do not do this" is exactly what red means. Merging them
    is the mistake this test exists to catch.
    """
    from vigia.legal import connect_html, privacy_html, terms_html

    CANDADO_PATH = "M8 11V7a4 4 0 0 1 8 0v4"

    garantias = {
        "/connect": connect_html("/vigia", "diego@diegofarina.com", 24),
        "/privacy": privacy_html("/vigia", "diego@diegofarina.com", 24),
    }
    for ruta, html in garantias.items():
        assert CANDADO_PATH in html, f"{ruta}: la garantía perdió el candado"
        assert 'class="no"' not in html, (
            f"{ruta}: una lista de garantías ha vuelto a `.no`, que la pinta con la ✕ roja"
        )

    # Y la prohibición conserva su ✕ roja, que ahí es lo correcto.
    prohibicion = terms_html("/vigia", "diego@diegofarina.com")
    assert 'class="no"' in prohibicion, "los usos prohibidos han perdido la ✕ roja"
    assert CANDADO_PATH not in prohibicion, "un candado verde sobre una prohibición"


def test_each_marked_item_has_exactly_one_icon():
    """The duplicate, asserted by counting rather than by reading CSS.

    `.marcada` sets `display:flex` on the item, which removes the marker box
    entirely, and the icon is one SVG in the markup. So the count of icons must
    equal the count of items — the version with `.no` + `::before` gave two per
    item and looked deliberate enough that it shipped.
    """
    import re

    from vigia.legal import connect_html, privacy_html

    for nombre, html in (
        ("/connect", connect_html("/vigia", "diego@diegofarina.com", 24)),
        ("/privacy", privacy_html("/vigia", "diego@diegofarina.com", 24)),
    ):
        for lista in re.findall(r'<ul class="marcada">(.*?)</ul>', html, re.S):
            items = len(re.findall(r"<li[ >]", lista))
            svgs = len(re.findall(r"<svg", lista))
            assert items and items == svgs, (
                f"{nombre}: {items} elementos y {svgs} iconos en la misma lista"
            )


def test_the_icons_are_defined_once():
    """Both pages draw the same padlock. It lived as a module constant AND as four
    literal copies inside `connect_html`, which is how two surfaces end up with
    slightly different icons six months later."""
    import pathlib

    fuente = (
        pathlib.Path(__file__).resolve().parents[1] / "vigia" / "legal.py"
    ).read_text()
    assert fuente.count('<rect x="4" y="11" width="16" height="10" rx="2"/>') == 1
    assert fuente.count('<path d="M4 12.5l5 5L20 6.5"/>') == 1
