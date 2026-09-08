"""The DNS engine, against the shapes found auditing real domains.

Every fixture here is a reduction of a domain that was actually checked, and each
one produced a wrong report before these changes:

 · abstracta.digital — a TXT wildcard answering every `_domainkey` name
 · sunamers.com / douscents.es — the key under Mailchimp's `k2`, a selector the
   seven-item list did not have
 · douscents.es — a second, dead key published at the apex beside the SPF
 · mutare.io — DMARC reports going only to EasyDMARC, flagged as a gap
 · boxfish.studio and six others — neither SPF nor DMARC, told to start with DMARC

They are fixtures rather than live lookups on purpose: DNS changes, and a test that
depends on somebody else's zone stops being a test the day they fix it.
"""
from __future__ import annotations

import re

import pytest

from vigia.dns_email_auth import (
    DEFAULT_DKIM_SELECTORS,
    check_dkim,
    check_transport,
    classify_rua,
    parse_dmarc,
    parse_spf,
    plataforma_dmarc,
)


class ResolverFalso:
    """Answers from a dict. Any name not in it does not exist."""

    def __init__(self, txt: dict[str, list[str]], comodin: list[str] | None = None):
        self._txt = txt
        self._comodin = comodin

    def txt(self, name: str) -> list[str]:
        if name in self._txt:
            return self._txt[name]
        # A wildcard zone answers names nobody published — including the probe.
        return list(self._comodin) if self._comodin else []

    def ds(self, name):  # noqa: D102
        return []


# ───────────────────────────────────────────────────────────────── el comodín

#: What abstracta.digital returns for every name under the domain.
COMODIN = [
    "google-site-verification=SxUHPDFHGaaoK_RIMLEIfnwzKI8UjTBUbN0BxmZFHV4",
    "google-site-verification=otro-valor-cualquiera",
]


def test_un_comodin_no_produce_ni_una_sola_clave():
    """Every selector answers, none of it is DKIM, so the answer is "no key".

    The failure this prevents is not a wrong verdict but a confident one: 26
    selectors "responding" read as 26 keys to anything that tests for existence.
    """
    resolver = ResolverFalso({}, comodin=COMODIN)
    resultado = check_dkim("abstracta.example", resolver)

    assert resultado.found is None, "un comodín se leyó como clave encontrada"
    assert resultado.selector is None
    assert resultado.wildcard is True, "el comodín no se detectó"
    assert len(resultado.checked_selectors) == len(DEFAULT_DKIM_SELECTORS)


def test_con_comodin_una_clave_de_verdad_se_sigue_encontrando():
    """abstracta.digital has both: a wildcard AND a real key under `google`.

    Detecting the wildcard must not make the engine blind to the genuine record.
    """
    resolver = ResolverFalso(
        {"google._domainkey.abstracta.example": ["v=DKIM1; k=rsa; p=" + "A" * 216]},
        comodin=COMODIN,
    )
    resultado = check_dkim("abstracta.example", resolver)

    assert resultado.found is True
    assert resultado.selector == "google"
    assert resultado.wildcard is True, "el comodín sigue existiendo y hay que decirlo"


def test_un_txt_que_solo_menciona_rsa_no_es_una_clave():
    """The old test accepted `k=rsa` anywhere in the record."""
    resolver = ResolverFalso({"google._domainkey.x.example": ["algo k=rsa por aquí"]})
    assert check_dkim("x.example", resolver).found is None


# ──────────────────────────────────────────────────── el selector que faltaba


def test_la_clave_en_k2_se_encuentra():
    """Mailchimp publishes at `k2`, reached through a CNAME that resolves
    transparently — so having the selector on the list is the whole fix."""
    resolver = ResolverFalso(
        {"k2._domainkey.sunamers.example": ["v=DKIM1; k=rsa; p=" + "B" * 216]}
    )
    resultado = check_dkim("sunamers.example", resolver)

    assert resultado.found is True
    assert resultado.selector == "k2"
    # Bits are derived from the key, not asserted to a constant: the fixture's
    # padding length decides them, and pinning the number tests the fixture.
    assert resultado.key_bits is not None


@pytest.mark.parametrize("selector", ["k2", "k3", "s2", "zmail", "mxvault", "protonmail1"])
def test_los_selectores_de_la_auditoria_estan_en_la_lista(selector):
    assert selector in DEFAULT_DKIM_SELECTORS


# ─────────────────────────────────────────────── la clave en el sitio erróneo


def test_una_clave_en_la_raiz_se_detecta():
    """douscents.es publishes a 1024-bit key among the apex TXT, where no verifier
    looks. It is dead, and nothing anywhere reports it."""
    resultado = parse_spf(
        [
            "v=spf1 include:_spf.google.com ~all",
            "v=DKIM1; k=rsa; s=email; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ",
        ]
    )
    assert resultado.found is True
    assert resultado.dkim_en_raiz is not None


def test_sin_clave_en_la_raiz_no_se_inventa_nada():
    assert parse_spf(["v=spf1 -all"]).dkim_en_raiz is None


def test_una_clave_en_la_raiz_tambien_cuenta_sin_spf():
    resultado = parse_spf(["v=DKIM1; k=rsa; p=abc"])
    assert resultado.found is False
    assert resultado.dkim_en_raiz is not None


# ─────────────────────────────────────────────────────── MTA-STS y TLS-RPT


def test_un_txt_que_no_es_una_politica_no_cuenta_como_mta_sts():
    """With the wildcard, `_mta-sts` answers google-site-verification."""
    resolver = ResolverFalso({}, comodin=COMODIN)
    transporte = check_transport("abstracta.example", resolver)

    assert transporte.mta_sts is False
    assert transporte.tls_rpt is False


def test_una_politica_de_verdad_si_cuenta():
    resolver = ResolverFalso(
        {
            "_mta-sts.x.example": ["v=STSv1; id=20260804T000000;"],
            "_smtp._tls.x.example": ["v=TLSRPTv1; rua=mailto:tls@x.example"],
        }
    )
    transporte = check_transport("x.example", resolver)

    assert transporte.mta_sts is True
    assert transporte.mta_sts_id == "20260804T000000"
    assert transporte.tls_rpt is True


# ────────────────────────────────────────────── las plataformas de DMARC


def test_los_informes_a_una_plataforma_no_son_un_problema():
    """mutare.io pays for EasyDMARC. The platform IS the telemetry."""
    resultado = parse_dmarc(
        ["v=DMARC1;p=none;rua=mailto:4e204592b2@rua.easydmarc.eu;"
         "ruf=mailto:4e204592b2@ruf.easydmarc.eu;fo=1;"]
    )
    assert classify_rua("mutare.example", resultado.rua) == "platform"
    assert plataforma_dmarc(resultado.rua) == "easydmarc.eu"
    assert resultado.ruf, "el ruf no se estaba parseando"


def test_un_destino_ajeno_desconocido_si_sigue_avisando():
    """The warning is right when the reports go somewhere that is neither theirs
    nor a processor: then nobody is reading them."""
    assert classify_rua("x.example", ["informes@agencia-cualquiera.net"]) == "third_party"


def test_el_propio_dominio_sigue_siendo_lo_correcto():
    assert classify_rua("x.example", ["dmarc@x.example"]) == "own"


# ───────────────────────────────────────────────── el orden de la remediación


def test_sin_spf_y_sin_dmarc_el_estado_es_el_que_dispara_el_orden_nuevo():
    """The seven domains found in that state. The ordering itself is decided in the
    checker's UI, from exactly these two facts."""
    spf = parse_spf(["algo que no es spf"])
    dmarc = parse_dmarc([])

    assert spf.found is False and spf.record is None
    assert dmarc.found is False


# ──────────────────────────── el selector aportado por quien mira su dominio

from vigia.dns_email_auth import dkim_verdict, validar_selectores  # noqa: E402
from vigia.i18n import SUPPORTED_LANGS, catalog, text  # noqa: E402

CLAVE = ["v=DKIM1; k=rsa; p=" + "A" * 350]

#: "DKIM no verificado" / "DKIM not verified", read from the catalogue instead of
#: written here twice: the three DKIM states have to stay distinguishable in both
#: languages, and the only way to check that is to ask the catalogue what each
#: language says and then assert on it.
NO_VERIFICADO = {
    lang: text(lang, "dns.dkim.no_verificado", probados="…").split(":")[0]
    for lang in SUPPORTED_LANGS
}


@pytest.mark.parametrize("lang", SUPPORTED_LANGS)
def test_aportado_y_presente_es_correcto(lang):
    """They named it, it is there. The verdict says which one and how big."""
    resolver = ResolverFalso({"zoho2._domainkey.x.example": CLAVE})
    resultado = check_dkim("x.example", resolver, declarados=["zoho2"], lang=lang)
    estado, texto = dkim_verdict(resultado, lang)

    assert estado == "pass"
    assert resultado.selector == "zoho2"
    assert "zoho2" in texto and "2048" in texto


@pytest.mark.parametrize("lang", SUPPORTED_LANGS)
def test_aportado_y_ausente_es_fallo_no_ignorancia(lang):
    """The distinction the whole feature exists for, in both languages.

    Without a declared selector, a miss means "I cannot enumerate DKIM". With one,
    it means "I looked exactly where you said and there is nothing", which is a
    fact the reader can act on: unpublished, misspelled, or under the wrong name.
    """
    resolver = ResolverFalso({})
    resultado = check_dkim("x.example", resolver, declarados=["zoho2"], lang=lang)
    estado, texto = dkim_verdict(resultado, lang)

    assert estado == "fail", "un selector afirmado y ausente no es «no verificado»"
    assert "zoho2" in texto
    assert NO_VERIFICADO[lang].lower() not in texto.lower()


@pytest.mark.parametrize("lang", SUPPORTED_LANGS)
def test_sin_aportar_y_ausente_sigue_siendo_no_verificado(lang):
    """Unchanged, and it must stay that way: guessing names proves nothing.

    The English half is the one that costs a meeting if it drifts: "not verified"
    is a different claim from "no DKIM", and only one of them is true here.
    """
    estado, texto = dkim_verdict(check_dkim("x.example", ResolverFalso({}), lang=lang), lang)

    assert estado == "undetermined"
    assert NO_VERIFICADO[lang].lower() in texto.lower()


@pytest.mark.parametrize("lang", SUPPORTED_LANGS)
def test_lo_aportado_se_prueba_ADEMAS_de_la_lista(lang):
    """Their selector is wrong but the domain does sign: still found."""
    resolver = ResolverFalso({"google._domainkey.x.example": CLAVE})
    resultado = check_dkim("x.example", resolver, declarados=["inventado"], lang=lang)
    estado, texto = dkim_verdict(resultado, lang)

    assert estado == "pass"
    assert resultado.selector == "google"
    # …and the claim they made is not swallowed in silence.
    assert "inventado" in texto


def test_lo_aportado_se_prueba_primero():
    """When both exist, the reported selector is the one they named."""
    resolver = ResolverFalso(
        {"google._domainkey.x.example": CLAVE, "propio._domainkey.x.example": CLAVE}
    )
    resultado = check_dkim("x.example", resolver, declarados=["propio"])
    assert resultado.selector == "propio"


@pytest.mark.parametrize(
    "entrada,fragmentos",
    [
        ("zoho2._domainkey.x.com", {"es": "puntos", "en": "dots"}),
        ("mi_selector", {"es": "guiones bajos", "en": "underscores"}),
        ("dos palabras", {"es": "espacios", "en": "spaces"}),
        ("2fast", {"es": "número", "en": "number"}),
        ("sel!", {"es": "no valen", "en": "not allowed"}),
    ],
)
@pytest.mark.parametrize("lang", SUPPORTED_LANGS)
def test_la_entrada_invalida_dice_QUE_esta_mal(entrada, fragmentos, lang):
    """Not a generic rejection: somebody who pasted the whole record name is told
    that is what happened — in the language they are reading the page in."""
    selectores, error = validar_selectores(entrada, lang=lang)
    assert selectores == []
    assert error and fragmentos[lang] in error


# ──────────────────────────────────── las dos mitades del mismo veredicto


def _plantillas(nodo, prefijo=""):
    for clave, valor in nodo.items():
        ruta = f"{prefijo}.{clave}" if prefijo else clave
        if isinstance(valor, dict):
            yield from _plantillas(valor, ruta)
        else:
            yield ruta, valor


@pytest.mark.parametrize("seccion", ["dns", "proyeccion"])
def test_los_dos_idiomas_piden_los_mismos_valores(seccion):
    """Both languages of a template must take exactly the same placeholders.

    This is what stops the two languages drifting into taking different
    arguments: if the Spanish verdict says «{selector}» and «{bits}», so does the
    English one, whatever order it puts them in. A mismatch would render as a
    brace-filled sentence in front of the customer who reads the other language.
    """
    marcador = re.compile(r"{(\w+)")
    es = dict(_plantillas(catalog("es")[seccion]))
    en = dict(_plantillas(catalog("en")[seccion]))

    assert set(es) == set(en)
    for ruta, plantilla in es.items():
        assert sorted(marcador.findall(plantilla)) == sorted(marcador.findall(en[ruta])), ruta
        assert plantilla.strip() and en[ruta].strip(), ruta


def test_una_entrada_vacia_no_es_un_error():
    assert validar_selectores("") == ([], None)
    assert validar_selectores("   ") == ([], None)


def test_se_aceptan_varios_separados_por_comas():
    assert validar_selectores("zoho2, k2 ,k3")[0] == ["zoho2", "k2", "k3"]
