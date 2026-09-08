"""Localisation: fallback chain, no raw keys, and old scans re-rendering."""
import json
import re

import pytest

from vigia.i18n import (
    SUPPORTED_LANGS,
    catalog,
    localize_finding,
    localize_manual_check,
    localize_payload,
    normalize_lang,
    severity_label,
    status_label,
)
from vigia.report import build_html_report


def stored(**over):
    """A finding as an OLD scan stored it: English text, no i18n metadata."""
    base = {
        "id": "2sv-delegated-admins",
        "title": "Delegated admin accounts without 2-Step Verification",
        "description": "Every delegated admin must have 2SV.",
        "remediation": "Enroll them.",
        "cis_control": "CIS GWS §1 — 2-Step Verification",
        "severity": "critical",
        "status": "fail",
        "affected_items": [],
        "accounts": [],
    }
    base.update(over)
    return base


# ------------------------------------------------------- catalogue shape

def test_both_catalogues_have_the_same_keys():
    es, en = catalog("es"), catalog("en")
    assert set(es["findings"]) == set(en["findings"])
    assert set(es["manual"]) == set(en["manual"])
    assert set(es["status"]) == set(en["status"]) == {"pass", "fail", "warn", "undetermined"}


def test_no_catalogue_value_is_empty():
    for lang in SUPPORTED_LANGS:
        for fid, fields in catalog(lang)["findings"].items():
            for key, value in fields.items():
                assert isinstance(value, str) and value.strip(), f"{lang}/{fid}/{key}"


def test_cis_identifier_is_preserved_and_only_the_description_translates():
    """The identifier is the official name of the control and has to stay
    quotable; the words after the dash are ours to translate."""
    es = catalog("es")["findings"]["policy-drive-sharing"]["cis"]
    en = catalog("en")["findings"]["policy-drive-sharing"]["cis"]
    assert es.startswith("CIS GWS §4 (Drive) — ")
    assert en.startswith("CIS GWS §4 (Drive) — ")
    assert es != en
    assert "Restringir" in es and "Restrict" in en


def test_every_cis_entry_keeps_its_identifier_untranslated():
    ident = re.compile(r"^CIS GWS( §\d+)?( \([^)]+\))? — ")
    for lang in SUPPORTED_LANGS:
        for fid, fields in catalog(lang)["findings"].items():
            if "cis" in fields:
                assert ident.match(fields["cis"]), f"{lang}/{fid}: {fields['cis']}"


# ------------------------------------------------------------- labels

def test_status_and_severity_labels():
    assert status_label("es", "fail") == "Fallo"
    assert status_label("es", "undetermined") == "No verificado"
    assert status_label("en", "undetermined") == "Not verified"
    assert severity_label("es", "critical") == "crítico"
    assert severity_label("en", "critical") == "critical"


def test_unknown_label_returns_the_key_not_a_crash():
    assert status_label("es", "bogus") == "bogus"


def test_language_negotiation():
    assert normalize_lang(None) == "es"
    assert normalize_lang("es-ES") == "es"
    assert normalize_lang("EN") == "en"
    assert normalize_lang("en-GB,en;q=0.9") == "en"
    assert normalize_lang("fr") == "es"  # unsupported → default


# -------------------------------------------------- the actual bug fixed

def test_a_scan_stored_in_english_renders_in_spanish_without_rescanning():
    localized = localize_finding(stored(), "es")
    assert localized["title"] == "Administrador delegado sin verificación en dos pasos"
    assert localized["scope_label"] == "administradores delegados"
    assert "administradores delegados" in localized["description"]
    assert "Restablecer" in localized["remediation"] or "Inscribe" in localized["remediation"]


def test_the_same_scan_can_also_render_in_english():
    localized = localize_finding(stored(), "en")
    assert localized["title"] == "Delegated admin without 2-Step Verification"


def test_manual_check_steps_and_area_are_localized():
    old = {
        "id": "manual-drive-sharing",
        "title": "Drive external sharing defaults",
        "area": "Google Drive",
        "why_manual": "Restricted scope.",
        "instructions": ["Open console", "Check setting"],
        "cis_control": "CIS GWS §4 (Drive) — Restrict external sharing",
    }
    localized = localize_manual_check(old, "es")
    assert localized["title"] == "Uso compartido externo de Drive (valores por defecto)"
    assert len(localized["instructions"]) == 4
    assert "Consola de Administración" in localized["instructions"][0]
    assert localized["cis_control"].startswith("CIS GWS §4 (Drive) — ")


# ------------------------------------------------- never a raw key/brace

def test_a_renamed_id_never_relabels_a_historical_scan():
    """`2sv-admins` used to mean "any admin, super admins included". It now
    exists as `2sv-delegated-admins` with a narrower population, so the old
    id is deliberately absent from the catalogue: relabelling those scans
    would describe something they never measured, which is how a super admin
    ended up shown as a delegated admin."""
    old = stored(id="2sv-admins", title="Delegated admin accounts without 2-Step Verification")
    localized = localize_finding(old, "es")
    assert localized["title"] == "Delegated admin accounts without 2-Step Verification"
    assert "delegado" not in localized["title"].lower()


def test_an_unknown_finding_id_keeps_its_stored_text():
    finding = stored(id="some-future-check", title="Whatever it said")
    assert localize_finding(finding, "es")["title"] == "Whatever it said"


def test_a_templated_title_never_leaks_braces_when_values_are_missing():
    """The threshold lives in the title ("…en {days}+ días"). An old scan has
    no value for it, and showing "{days}" would be worse than the old
    wording, so the stored text is kept."""
    finding = stored(
        id="composite-superadmin-dormant",
        title="Super admin that has gone unused",
        details={},
    )
    localized = localize_finding(finding, "es")
    assert "{" not in localized["title"]
    assert localized["title"] == "Super admin that has gone unused"


def test_missing_values_are_recovered_from_details():
    """The numbers old scans need are already stored under `details`."""
    finding = stored(
        id="dormant-accounts",
        title="Active accounts with no sign-in for 90+ days",
        details={"dormant_days": 45, "count": 3},
    )
    localized = localize_finding(finding, "es")
    assert localized["title"] == "Cuentas activas sin iniciar sesión en 45+ días"
    assert "45" in localized["description"]


def test_a_status_inside_a_sentence_is_localized_too():
    finding = stored(
        id="email-spf",
        title="SPF records across 2 domain(s)",
        i18n_params={"domains": 2, "worst_status": "fail"},
    )
    assert "Fallo" in localize_finding(finding, "es")["description"]
    assert "Fail" in localize_finding(finding, "en")["description"]


def test_no_localized_payload_ever_contains_a_catalogue_path():
    payload = {"scan": {"findings": [stored()], "manual_checks": []}}
    blob = json.dumps(localize_payload(payload, "es"), ensure_ascii=False)
    for leak in ("findings.", "manual.", "{days}", "{count}", "{domains}"):
        assert leak not in blob, leak


# ----------------------------------------------- duplicated titles follow

def test_titles_duplicated_across_the_payload_are_localized_once_and_reused():
    payload = {
        "scan": {"findings": [stored()], "manual_checks": []},
        "delta": {
            "has_baseline": True,
            "new": [{"id": "2sv-delegated-admins", "title": "Delegated admin accounts without 2-Step Verification",
                     "severity": "critical"}],
            "worse": [], "improved": [], "resolved": [],
        },
        "actions": [{"id": "enforce_2sv_org", "finding_ids": ["2sv-delegated-admins"],
                     "finding_titles": ["Delegated admin accounts without 2-Step Verification"]}],
        "people_at_risk": [{"account": "a@x.com", "worst": "critical",
                            "issues": [{"id": "2sv-delegated-admins",
                                        "title": "Delegated admin accounts without 2-Step Verification",
                                        "severity": "critical"}]}],
        "breakdown": {"findings": [{"id": "2sv-delegated-admins", "title": "Delegated admins without 2SV",
                                    "severity": "critical", "status": "fail",
                                    "weight": 10, "earned": 0.0}],
                      "accounts": [], "excluded": [], "weights": {}, "credits": {},
                      "score": 0, "total_weight": 10, "earned_weight": 0.0, "lost_weight": 10.0},
    }
    result = localize_payload(payload, "es")
    expected = "Administrador delegado sin verificación en dos pasos"
    assert result["delta"]["new"][0]["title"] == expected
    assert result["actions"][0]["finding_titles"] == [expected]
    assert result["people_at_risk"][0]["issues"][0]["title"] == expected
    assert result["breakdown"]["findings"][0]["title"] == expected


# ---------------------------------------------------- the PDF follows suit

SCAN = {
    "created_at": "2026-07-31T10:00:00+00:00",
    "score": 40,
    "counts": {"critical": 1, "high": 0, "medium": 0, "low": 0},
    "findings": [stored()],
    "manual_checks": [],
}


@pytest.mark.parametrize(
    "lang,expected,unexpected",
    [
        ("es", "Administrador delegado sin verificación en dos pasos", "Delegated admin"),
        ("en", "Delegated admin without 2-Step Verification", "Administrador delegado"),
    ],
)
def test_exported_report_respects_the_requested_language(lang, expected, unexpected):
    payload = localize_payload({"scan": SCAN}, lang)
    html = build_html_report(
        {"primary_domain": "example.com"}, payload["scan"], None, None, [], lang=lang
    )
    assert expected in html
    assert unexpected not in html


def test_report_status_and_severity_words_follow_the_language():
    for lang, sev, status in (("es", "crítico", "FALLO"), ("en", "critical", "FAIL")):
        payload = localize_payload({"scan": SCAN}, lang)
        html = build_html_report(
            {"primary_domain": "example.com"}, payload["scan"], None, None, [], lang=lang
        )
        assert sev in html and status in html


# --------------------------------------------------------------------------- #
# The catalogue against the code that emits cards, not against itself.
#
# There was a parity test comparing `es.json` with `en.json`, and it passed while
# two of the six manual cards had no entry in EITHER file: they carried their
# Spanish source text straight from `checks/manual.py` into English reports.
# Comparing the two catalogues with each other cannot see that, because a missing
# key is missing symmetrically. The check that catches it compares the catalogue
# against the set of ids the checks actually produce.
# --------------------------------------------------------------------------- #


def test_toda_tarjeta_manual_tiene_entrada_en_los_dos_idiomas():
    """Every manual card `checks/manual.py` can emit is in both catalogues.

    A card with no entry does not fail loudly — `localize_manual_check` keeps
    whatever the check wrote, which is Spanish. The failure mode is a bilingual
    product quietly shipping one language.
    """
    from vigia.checks import manual as tarjetas
    from vigia.i18n import _lookup

    ids = {c["id"] for c in tarjetas.MANUAL_CHECKS}
    assert ids, "no se han encontrado tarjetas manuales"

    faltan = []
    for lang in ("es", "en"):
        for check_id in sorted(ids):
            for clave in ("title", "area", "why_manual", "instructions", "cis"):
                if not _lookup(lang, "manual", check_id, clave):
                    faltan.append(f"{lang}/{check_id}.{clave}")
    assert not faltan, f"sin traducción: {faltan}"


def test_las_instrucciones_manuales_difieren_entre_idiomas():
    """A copied Spanish block passes a presence test. It should not pass this one.

    Only the prose is compared: `area` is "Gmail" in both languages on purpose,
    and a CIS control number is a number.
    """
    from vigia.checks import manual as tarjetas
    from vigia.i18n import _lookup

    for check in tarjetas.MANUAL_CHECKS:
        cid = check["id"]
        es = _lookup("es", "manual", cid, "why_manual")
        en = _lookup("en", "manual", cid, "why_manual")
        assert es and en and es != en, f"{cid}: why_manual sin traducir"
        pasos_es = _lookup("es", "manual", cid, "instructions")
        pasos_en = _lookup("en", "manual", cid, "instructions")
        assert len(pasos_es) == len(pasos_en), f"{cid}: distinto número de pasos"
        assert pasos_es != pasos_en, f"{cid}: instructions sin traducir"
