"""The prioritisation engine.

The cases that matter are not "does rank 1 beat rank 2" — they are the ones where
a plausible reading of the report would produce a confident sentence about
something the scanner never established. Those are grouped last and they are the
reason this engine exists as its own module.
"""
from __future__ import annotations

import pytest

from prospector.catalog import CATALOG_BY_KEY, RULES
from prospector.prioritise import (
    fired_codes,
    receives_mail,
    select_primary_finding,
)
from prospector.scanner import build_report

# --------------------------------------------------------------------------- #
# The six mechanisms, each broken on its own.
# --------------------------------------------------------------------------- #

SIN_DMARC = {"found": False, "status": "fail", "summary": "No DMARC record."}
SPF_LARGO = {"dns_lookups": 12, "status": "warn", "summary": "12 lookups, over the limit."}
DKIM_AUSENTE = {
    "found": False, "status": "fail", "declarados": ["selector1"],
    "wildcard": False, "summary": "No key at the declared selector.",
}
SPF_BLANDO = {"all_qualifier": "~", "status": "warn", "summary": "SPF ends in ~all."}
DMARC_NONE = {
    "policy": "none", "rua": [], "status": "fail",
    "summary": "DMARC is p=none with no rua.",
}
SIN_MTA_STS = {"value": False, "status": "warn", "summary": "No MTA-STS policy."}


@pytest.mark.parametrize(
    "campo, roto, esperado",
    [
        ("dmarc", SIN_DMARC, "dmarc-missing"),
        ("spf", SPF_LARGO, "spf-lookup-limit"),
        ("dkim", DKIM_AUSENTE, "dkim-missing"),
        ("spf", SPF_BLANDO, "spf-soft-all"),
        ("dmarc", DMARC_NONE, "dmarc-none-no-rua"),
        ("mta_sts", SIN_MTA_STS, "mta-sts-missing"),
    ],
)
def test_cada_hallazgo_dispara_por_su_cuenta(campo, roto, esperado):
    finding = select_primary_finding(build_report(**{campo: roto}))
    assert finding is not None
    assert finding.code == esperado


def test_el_orden_es_comercial_no_tecnico():
    """The ranking is the product decision, so it is asserted literally."""
    assert [r.code for r in RULES] == [
        "dmarc-missing",
        "spf-lookup-limit",
        "dkim-missing",
        "spf-soft-all",
        "dmarc-none-no-rua",
        "mta-sts-missing",
    ]
    assert [r.severity_rank for r in RULES] == [1, 2, 3, 4, 5, 6]


# --------------------------------------------------------------------------- #
# Several findings at once — the common case, and the one the subject line
# depends on getting right.
# --------------------------------------------------------------------------- #


def test_con_todo_roto_gana_el_de_mayor_impacto_comercial():
    report = build_report(
        dmarc=SIN_DMARC, spf={**SPF_LARGO, **SPF_BLANDO}, dkim=DKIM_AUSENTE,
        mta_sts=SIN_MTA_STS,
    )
    finding = select_primary_finding(report)
    assert finding is not None
    assert finding.code == "dmarc-missing"
    # And everything else is kept, in rank order, for the audit trail.
    assert finding.all_codes == (
        "dmarc-missing", "spf-lookup-limit", "dkim-missing", "spf-soft-all",
        "mta-sts-missing",
    )


def test_un_spf_largo_gana_a_un_dkim_ausente():
    """Rank 2 over rank 3, even though 'not signed' sounds more alarming."""
    finding = select_primary_finding(build_report(spf=SPF_LARGO, dkim=DKIM_AUSENTE))
    assert finding is not None and finding.code == "spf-lookup-limit"


def test_mta_sts_solo_gana_cuando_no_hay_nada_mas():
    """Rank 6 is the hook of last resort, and only ever alone."""
    finding = select_primary_finding(build_report(mta_sts=SIN_MTA_STS, dkim=DKIM_AUSENTE))
    assert finding is not None and finding.code == "dkim-missing"


def test_dmarc_ausente_y_dmarc_none_no_coexisten():
    """A domain either publishes a DMARC record or it does not."""
    codes = fired_codes(build_report(dmarc=SIN_DMARC))
    assert "dmarc-none-no-rua" not in codes


# --------------------------------------------------------------------------- #
# Clean domains.
# --------------------------------------------------------------------------- #


def test_un_dominio_limpio_no_produce_ningun_hallazgo():
    assert select_primary_finding(build_report()) is None


def test_dmarc_p_none_pero_con_rua_no_dispara():
    """`p=none` with reports going somewhere is a deliberate monitoring setup."""
    report = build_report(dmarc={"policy": "none", "rua": ["mailto:d@x.com"]})
    assert select_primary_finding(report) is None


def test_spf_en_menos_all_y_diez_consultas_exactas_no_dispara():
    """The RFC limit is 'more than 10'. Ten is compliant, and 11 is not."""
    assert select_primary_finding(build_report(spf={"dns_lookups": 10})) is None
    finding = select_primary_finding(build_report(spf={"dns_lookups": 11}))
    assert finding is not None and finding.code == "spf-lookup-limit"


# --------------------------------------------------------------------------- #
# Wildcard DNS. A domain with a wildcard TXT record answers EVERY selector query,
# so DKIM cannot be concluded either way — and the email that says "your mail is
# not signed" to a company whose mail is signed is exactly the false positive the
# whole review queue exists to prevent.
# --------------------------------------------------------------------------- #


def test_un_comodin_dns_impide_afirmar_que_falta_dkim():
    report = build_report(
        dkim={"found": False, "status": "fail", "wildcard": True, "declarados": ["s1"]}
    )
    assert "dkim-missing" not in fired_codes(report)


def test_con_comodin_y_nada_mas_el_dominio_se_excluye():
    """Not 'write about something else' — nothing else fired, so nothing is sent."""
    report = build_report(
        dkim={"found": False, "status": "fail", "wildcard": True, "declarados": ["s1"]}
    )
    assert select_primary_finding(report) is None


def test_el_comodin_no_bloquea_los_demas_hallazgos():
    """The wildcard makes DKIM unknowable. It says nothing about DMARC."""
    report = build_report(
        dmarc=SIN_DMARC,
        dkim={"found": False, "status": "fail", "wildcard": True, "declarados": ["s1"]},
    )
    finding = select_primary_finding(report)
    assert finding is not None and finding.code == "dmarc-missing"
    assert "dkim-missing" not in finding.all_codes


# --------------------------------------------------------------------------- #
# Domains that receive no mail.
# --------------------------------------------------------------------------- #


def test_sin_mx_el_hallazgo_sigue_siendo_real_pero_se_posterga():
    report = build_report(mx=[], dmarc=SIN_DMARC)
    finding = select_primary_finding(report)
    assert finding is not None
    assert finding.code == "dmarc-missing"
    assert finding.deprioritised is True
    assert finding.deprioritised_reason == "no-mx"


def test_sin_mx_no_se_habla_de_mta_sts():
    """MTA-STS protects inbound mail. With no MX there is no inbound mail, so this
    is not a weaker argument — it is not an argument."""
    assert "mta-sts-missing" not in fired_codes(build_report(mx=[], mta_sts=SIN_MTA_STS))


def test_sin_mx_y_solo_mta_sts_el_dominio_se_excluye():
    assert select_primary_finding(build_report(mx=[], mta_sts=SIN_MTA_STS)) is None


def test_con_mx_el_hallazgo_no_se_posterga():
    finding = select_primary_finding(build_report(dmarc=SIN_DMARC))
    assert finding is not None and finding.deprioritised is False


def test_un_fallo_al_leer_los_mx_no_degrada_al_dominio():
    """A failed lookup is not evidence that the domain receives no mail."""
    report = build_report(dmarc=SIN_DMARC)
    report["mx"] = {"records": [], "provider": None, "google_workspace": None,
                    "error": "timeout"}
    assert receives_mail(report) is True
    finding = select_primary_finding(report)
    assert finding is not None and finding.deprioritised is False


# --------------------------------------------------------------------------- #
# Undetermined. The scanner could not establish the fact; nothing may be claimed.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("campo", ["spf", "dkim", "dmarc", "mta_sts"])
def test_un_mecanismo_indeterminado_nunca_dispara(campo):
    report = build_report(**{campo: {"status": "undetermined", "found": None,
                                     "value": None, "summary": "Could not check."}})
    assert select_primary_finding(report) is None


def test_un_error_de_resolucion_nunca_dispara():
    report = build_report(dmarc={"found": False, "status": "fail",
                                "error": "SERVFAIL", "summary": ""})
    assert "dmarc-missing" not in fired_codes(report)


def test_dkim_no_verificado_no_es_dkim_ausente():
    """The three-way distinction, which is the difference between a fact and a guess.

    `found is False` with `status == "undetermined"` is what the scanner reports
    when it probed a list of common selectors and found nothing: the domain may
    well sign with a selector of its own.
    """
    report = build_report(
        dkim={"found": False, "status": "undetermined", "declarados": [],
              "checked_selectors": ["google", "default", "s1"], "summary": "Not verified."}
    )
    assert select_primary_finding(report) is None


# --------------------------------------------------------------------------- #
# What the caller gets back.
# --------------------------------------------------------------------------- #


def test_el_hallazgo_trae_las_dos_versiones_y_ningun_marcador_sin_rellenar():
    finding = select_primary_finding(build_report("acme.es", dmarc=SIN_DMARC))
    assert finding is not None
    for texto in (finding.subject_line, finding.opening_line,
                  finding.plain_language_description, finding.technical_description):
        assert "acme.es" in texto
        assert "{" not in texto, f"marcador sin rellenar: {texto}"
    # The plain version has to be the one a non-technical reader understands.
    assert "DMARC" not in finding.subject_line
    assert "DMARC" in finding.technical_description


def test_la_evidencia_es_la_frase_del_escaner():
    """What we claimed has to be traceable to what was observed."""
    finding = select_primary_finding(build_report(dmarc=SIN_DMARC))
    assert finding is not None
    assert finding.evidence == SIN_DMARC["summary"]


def test_el_idioma_lo_elige_quien_llama():
    es = select_primary_finding(build_report("acme.es", dmarc=SIN_DMARC), lang="es")
    en = select_primary_finding(build_report("acme.es", dmarc=SIN_DMARC), lang="en")
    assert es is not None and en is not None
    assert es.subject_line != en.subject_line
    assert es.lang == "es" and en.lang == "en"


def test_un_idioma_desconocido_cae_al_castellano_en_vez_de_romper():
    finding = select_primary_finding(build_report(dmarc=SIN_DMARC), lang="pt")
    assert finding is not None and finding.lang == "es"


def test_todo_codigo_tiene_entrada_en_los_dos_idiomas():
    """A missing entry would print a template to a stranger."""
    for rule in RULES:
        for lang in ("es", "en"):
            assert (rule.code, lang) in CATALOG_BY_KEY, f"falta {rule.code}/{lang}"


def test_el_rango_es_el_mismo_en_los_dos_idiomas():
    for rule in RULES:
        for lang in ("es", "en"):
            assert CATALOG_BY_KEY[(rule.code, lang)].severity_rank == rule.severity_rank


def test_los_asuntos_son_distintos_entre_si():
    """Two findings sharing a subject line would make the A/B numbers meaningless."""
    for lang in ("es", "en"):
        asuntos = {CATALOG_BY_KEY[(r.code, lang)].subject_line_template for r in RULES}
        assert len(asuntos) == len(RULES)


def test_un_informe_vacio_no_revienta():
    """Robustness at the boundary: a malformed report excludes the prospect."""
    assert select_primary_finding({}) is None
    assert select_primary_finding({"domain": "x.com"}) is None
