"""Point 7: never claim absence of something checked only by heuristic.

DKIM is discovered by guessing selector names. Saying "this domain has no
DKIM" and being wrong in front of a technical audience costs the meeting,
so the wording, the score and the visual treatment must all say
"not verified" instead — in both languages. The English half is checked here
too, because "no DKIM" is the shortest and most tempting translation of a
sentence that deliberately does not say it.
"""
import pytest

from vigia.dns_email_auth import (
    DkimResult,
    DnsUnavailable,
    check_dkim,
    check_domain,
    dkim_verdict,
    dmarc_verdict,
    parse_dmarc,
    parse_spf,
    spf_verdict,
)
from vigia.i18n import SUPPORTED_LANGS, text
from vigia.report import build_html_report
from vigia.scoring import compute_score

# Phrases that assert absence. Forbidden for anything only probed by heuristic.
ABSENCE_CLAIMS_POR_IDIOMA = {
    "es": (
        "sin dkim",
        "no tiene dkim",
        "no firma",
        "dkim ausente",
        "no hay dkim",
        "no está firmado",
    ),
    "en": (
        "no dkim",
        "without dkim",
        "has no dkim",
        "does not sign",
        "is not signed",
        "dkim is absent",
        "dkim is missing",
    ),
}

#: Every language's forbidden phrases at once, for auditing a whole rendered
#: document: neither language's claim may show up in either language's report.
ABSENCE_CLAIMS = tuple(
    claim for claims in ABSENCE_CLAIMS_POR_IDIOMA.values() for claim in claims
)


def no_verificado(lang: str) -> str:
    """The catalogue's "DKIM no verificado" / "DKIM not verified" lead.

    Read from the catalogue rather than written here, so the test cannot pass by
    agreeing with a copy of the sentence that the engine no longer uses.
    """
    return text(lang, "dns.dkim.no_verificado", probados="…").split(":")[0]


class FakeResolver:
    def __init__(self, txt_map=None):
        self.txt_map = txt_map or {}

    def txt(self, name):
        value = self.txt_map.get(name, [])
        if value is DnsUnavailable:
            raise DnsUnavailable("timeout")
        return value

    def mx(self, name):
        return ["aspmx.l.google.com"]

    def ds(self, name):
        return []


# ------------------------------------------------------- the three states

#: The blunt half of the rule, spelled out per language. SPF and DMARC are
#: looked up at a name we can ask for, so their absence is a fact and the
#: sentence is allowed to say so without hedging.
SIN_REGISTRO = {
    "es": ("No se ha encontrado ningún registro SPF", "No hay registro DMARC"),
    "en": ("No SPF record was found", "There is no DMARC record"),
}


@pytest.mark.parametrize("lang", SUPPORTED_LANGS)
def test_verified_bad_is_allowed_to_assert_absence(lang):
    """SPF/DMARC are authoritative lookups at a known name, so asserting
    absence there is correct and must stay blunt — in both languages."""
    spf_esperado, dmarc_esperado = SIN_REGISTRO[lang]

    status, summary = spf_verdict(parse_spf([], lang), lang)
    assert status == "fail"
    assert summary == text(lang, "dns.spf.no_encontrado")
    assert spf_esperado in summary

    status, summary = dmarc_verdict(parse_dmarc([], lang), lang)
    assert status == "fail"
    assert summary == text(lang, "dns.dmarc.no_encontrado")
    assert dmarc_esperado in summary


def test_verified_good_does_not_penalise():
    status, _ = dmarc_verdict(parse_dmarc(["v=DMARC1; p=reject; rua=mailto:a@x.com"]))
    assert status == "pass"


@pytest.mark.parametrize("lang", SUPPORTED_LANGS)
def test_unverifiable_dkim_says_not_verified_and_never_claims_absence(lang):
    result = check_dkim(
        "example.com", FakeResolver(), ["google", "selector1", "default"], lang=lang
    )
    status, summary = dkim_verdict(result, lang)

    assert status == "undetermined"
    assert no_verificado(lang).lower() in summary.lower()
    lowered = summary.lower()
    for claim in ABSENCE_CLAIMS:
        assert claim not in lowered, f"summary claims absence: {claim!r} ({lang})"


@pytest.mark.parametrize("lang", SUPPORTED_LANGS)
def test_dkim_message_says_how_many_selectors_were_probed_and_how_to_fix_it(lang):
    """Same guarantee, new escape hatch.

    The message used to point at the Scan options panel, where a tenant could add
    its own selector. That panel is gone — the thresholds it held let the subject
    move its own yardstick — so a scan probes only Workspace's `google` selector
    and the way out is a person, not a form. The count still has to agree with
    what was actually probed, because the public DMARC checker shares this
    sentence and still tries seven.
    """
    selectors = ["google", "selector1", "selector2", "default", "k1"]
    result = check_dkim("example.com", FakeResolver(), selectors, lang=lang)
    _, summary = dkim_verdict(result, lang)
    assert str(len(selectors)) in summary
    assert "google" in summary  # names the selectors actually tried
    assert "diego@diegofarina.com" in summary  # the escape hatch, now a person

    # And with the single selector a scan uses, the sentence stays grammatical
    # instead of reading "los 1 selectores probados" / "the 1 selectors probed".
    uno = check_dkim("example.com", FakeResolver(), ["google"], lang=lang)
    _, resumen_uno = dkim_verdict(uno, lang)
    assert text(lang, "dns.dkim.probado_uno", tried="google") in resumen_uno
    assert "1 selectores" not in resumen_uno and "1 selectors" not in resumen_uno


def test_custom_selector_turns_unverified_into_verified():
    """The promised escape hatch: give the real selector and the state flips."""
    resolver = FakeResolver(
        # 392 base64 chars ≈ a 2048-bit key, so the verdict is a clean pass.
        {"mycorp2026._domainkey.example.com": ["v=DKIM1; k=rsa; p=" + "A" * 392]}
    )
    unverified = check_dkim("example.com", resolver, ["google", "default"])
    assert dkim_verdict(unverified)[0] == "undetermined"

    verified = check_dkim("example.com", resolver, ["google", "mycorp2026"])
    assert verified.found is True and verified.selector == "mycorp2026"
    assert dkim_verdict(verified)[0] == "pass"


def test_unverifiable_dkim_never_moves_the_score():
    from vigia.checks.finding import Finding

    baseline = [Finding(id="a", title="a", severity="high", status="pass")]
    with_unverified = baseline + [
        Finding(id="email-dkim", title="DKIM", severity="medium", status="undetermined")
    ]
    assert compute_score(with_unverified) == compute_score(baseline) == 100


# ------------------------------------------------- whole-report string audit

def test_no_report_string_claims_absence_for_an_unverified_check():
    """Renders a real report containing an unverified DKIM and greps it."""
    scan = {
        "created_at": "2026-07-27T10:00:00+00:00",
        "score": 40,
        "counts": {"critical": 0, "high": 1, "medium": 1, "low": 0},
        "findings": [
            {
                "id": "email-dkim",
                "title": "DKIM signing across 1 domain(s)",
                "severity": "medium",
                "status": "undetermined",
                "description": "Checked via public DNS for every configured domain.",
                "affected_items": [
                    "example.com: " + dkim_verdict(check_dkim("example.com", FakeResolver(), ["google"]))[1]
                ],
                "remediation": "Añade tu selector propio en Opciones de escaneo y vuelve a escanear.",
                "cis_control": "CIS GWS §3",
            }
        ],
        "manual_checks": [],
    }
    html = build_html_report({"primary_domain": "example.com"}, scan, None, None, [])
    lowered = html.lower()
    for claim in ABSENCE_CLAIMS:
        assert claim not in lowered, f"report claims absence: {claim!r}"
    # And it must label the state distinctly, not as a plain failure.
    assert "no verificado" in lowered


def test_report_marks_unverified_as_excluded_from_the_score():
    scan = {
        "created_at": "2026-07-27T10:00:00+00:00",
        "score": 40,
        "counts": {"critical": 0, "high": 0, "medium": 1, "low": 0},
        "findings": [
            {
                "id": "email-dkim",
                "title": "DKIM",
                "severity": "medium",
                "status": "undetermined",
                "description": "",
                "affected_items": [],
                "remediation": "",
                "cis_control": "",
            }
        ],
        "manual_checks": [],
    }
    html = build_html_report({"primary_domain": "example.com"}, scan, None, None, [])
    assert "nunca cuenta en la puntuación" in html.lower()


# ----------------------------------------------- infrastructure uncertainty

@pytest.mark.parametrize("name", ["example.com", "_dmarc.example.com"])
def test_dns_timeouts_are_undetermined_not_failures(name):
    resolver = FakeResolver({name: DnsUnavailable})
    report = check_domain("example.com", resolver=resolver, selectors=["google"])
    key = "spf" if name == "example.com" else "dmarc"
    assert report[key]["status"] == "undetermined"


def test_dkim_dataclass_defaults_to_unknown_not_absent():
    """found=None means 'unknown'; it must never default to False."""
    assert DkimResult().found is None
