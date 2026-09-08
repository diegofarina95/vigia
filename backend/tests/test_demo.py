"""The demo tenant: deterministic, isolated, and produced by the real engine."""
import re

from vigia.config import load_settings
from vigia.demo import (
    DEMO_DOMAIN,
    DEMO_NEWSLETTER_DOMAIN,
    DEMO_USERS,
    DemoResolver,
    build_demo_payload,
)

SETTINGS = load_settings()


def payload():
    return build_demo_payload(SETTINGS)


# ------------------------------------------------------------- isolation

#: Real tenant identifiers. Never, anywhere, in any form.
PROHIBIDOS = ("cluster365", "gimo.co.uk", "acme-demo")


def test_nothing_in_the_demo_touches_a_real_tenant():
    """The payload must be buildable with no database, no token and no
    network — if any of those were reachable, a real tenant could leak."""
    data = payload()
    assert data["org"]["domain"] == DEMO_DOMAIN
    blob = repr(data)
    for prohibido in PROHIBIDOS:
        assert prohibido not in blob, prohibido


def test_the_operators_own_domain_only_ever_appears_as_the_contact():
    """`diegofarina.com` used to be on the forbidden list outright, and that broke
    the day the DKIM remediation started saying "escríbeme a
    diego@diegofarina.com" — which is deliberate product copy, not a leak.

    Deleting it from the list would have thrown away the guarantee that mattered:
    the operator's own domain must never turn up as a domain the demo claims to
    have scanned. So it is allowed in exactly one shape, and asserted to be in
    that shape everywhere it occurs.
    """
    blob = repr(payload())
    apariciones = [m.start() for m in re.finditer(r"diegofarina\.com", blob)]
    assert apariciones, "si desaparece el contacto, este test ya no vigila nada"
    for posicion in apariciones:
        antes = blob[max(0, posicion - 6):posicion]
        assert antes.endswith("diego@"), (
            f"«diegofarina.com» aparece sin ser el contacto: …{blob[posicion-60:posicion+20]}"
        )


def test_resolver_never_leaves_the_fake_zone():
    resolver = DemoResolver()
    assert resolver.txt(DEMO_DOMAIN)  # known
    assert resolver.txt("google.com") == []  # unknown → empty, not a lookup
    assert resolver.mx("microsoft.com") == []
    assert resolver.ds("example.org") == []


def test_every_demo_address_is_on_the_invented_domain():
    for user in DEMO_USERS:
        assert user["primaryEmail"].endswith("@" + DEMO_DOMAIN)


# ---------------------------------------------------------- determinism

def test_two_builds_produce_the_same_report():
    first, second = payload(), payload()
    assert first["scan"]["score"] == second["scan"]["score"]
    assert first["scan"]["counts"] == second["scan"]["counts"]
    assert [f["id"] for f in first["scan"]["findings"]] == [
        f["id"] for f in second["scan"]["findings"]
    ]
    assert [f["status"] for f in first["scan"]["findings"]] == [
        f["status"] for f in second["scan"]["findings"]
    ]
    assert [p["account"] for p in first["people_at_risk"]] == [
        p["account"] for p in second["people_at_risk"]
    ]


# ------------------------------------------------- realistic distribution

def test_distribution_looks_like_a_real_tenant():
    scan = payload()["scan"]
    counts = scan["counts"]
    assert counts["critical"] >= 1, "a demo with no critical finding does not sell"
    assert counts["high"] >= 3
    passing = [f for f in scan["findings"] if f["status"] == "pass"]
    # Fewer passes than before on purpose: composites no longer hide each
    # other, so findings that used to pass falsely now fail truthfully.
    assert len(passing) >= 4, "an all-red report reads as fabricated"


def test_the_flagship_composite_fires():
    scan = payload()["scan"]
    hit = next(
        f for f in scan["findings"] if f["id"] == "composite-superadmin-dormant-no-2sv"
    )
    assert hit["status"] == "fail" and hit["severity"] == "critical"
    assert hit["accounts"] == [f"uxia.ferreiro@{DEMO_DOMAIN}"]


def test_the_functional_account_rule_fires():
    scan = payload()["scan"]
    hit = next(f for f in scan["findings"] if f["id"] == "composite-service-account-no-2sv")
    assert f"integraciones@{DEMO_DOMAIN}" in hit["accounts"]


def test_only_what_cannot_be_automated_stays_manual():
    """The cards that became real checks are gone. Two survive, for two
    different reasons, and each says which:

    * per-mailbox forwarding rules would need a restricted Gmail scope this
      product will not ask for;
    * IMAP and POP are supported settings with the right identifier, but a
      tenant that never set them has nothing to read — Google publishes no
      default for those two and returns none.
    """
    manual = {m["id"]: m for m in payload()["scan"]["manual_checks"]}
    assert set(manual) == {
        "manual-gmail-forwarding", "manual-imap-pop", "manual-gmail-routing",
    }
    # Routing rules are not in the Policy API at all, so no scope would ever
    # automate this one — and the card says so rather than implying it is
    # waiting on a permission.
    assert "no expone las reglas de enrutamiento" in manual["manual-gmail-routing"]["why_manual"]
    assert "no lo pide ni lo va a pedir" in manual["manual-gmail-forwarding"]["why_manual"]
    assert "no publica cuál es el valor por defecto" in manual["manual-imap-pop"]["why_manual"]


# -------------------------------------------------------------- DNS story

def test_spf_fails_on_the_rfc_lookup_limit():
    scan = payload()["scan"]
    spf = next(f for f in scan["findings"] if f["id"] == "email-spf")
    assert spf["status"] == "fail"
    detail = spf["details"]["domains"][DEMO_DOMAIN]
    assert detail["dns_lookups"] > 10
    assert "permerror" in detail["summary"]


def test_dmarc_is_parked_at_none_and_reports_go_to_a_third_party():
    scan = payload()["scan"]
    dmarc = next(f for f in scan["findings"] if f["id"] == "email-dmarc")
    detail = dmarc["details"]["domains"][DEMO_DOMAIN]
    assert detail["policy"] == "none"
    assert detail["rua_destination"] == "third_party"


def test_dkim_key_is_flagged_as_weak():
    scan = payload()["scan"]
    dkim = next(f for f in scan["findings"] if f["id"] == "email-dkim")
    detail = dkim["details"]["domains"][DEMO_DOMAIN]
    assert detail["key_bits"] == 1024
    assert detail["status"] == "warn"


def test_the_sending_subdomain_has_nothing():
    scan = payload()["scan"]
    spf = next(f for f in scan["findings"] if f["id"] == "email-spf")
    detail = spf["details"]["domains"][DEMO_NEWSLETTER_DOMAIN]
    assert detail["found"] is False


# --------------------------------------------------- history and deltas

def test_history_has_eight_weekly_points_on_distinct_days():
    history = payload()["history"]
    assert len(history) == 8
    days = {entry["created_at"][:10] for entry in history}
    assert len(days) == 8, "the chart needs distinct days or it looks broken"
    assert all(entry["score"] is not None for entry in history)


def test_delta_shows_new_resolved_and_a_regression():
    data = payload()
    assert data["delta"]["has_baseline"] is True
    assert len(data["delta"]["new"]) >= 1
    assert len(data["delta"]["resolved"]) >= 1
    regressions = [
        f for f in data["scan"]["findings"] if (f.get("details") or {}).get("regression")
    ]
    assert len(regressions) == 1, "exactly one regression is the story we want to tell"
    assert regressions[0]["id"] == "email-dmarc"


def test_actions_are_ranked_and_lead_with_2sv():
    actions = payload()["actions"]
    assert actions and actions[0]["id"] == "enforce_2sv_org"
    assert actions[0]["findings_closed"] >= 2
    assert actions[0]["score_gain"] > 0


# ------------------------------------------------------ report is clean

def test_exported_report_carries_no_watermark():
    from vigia.demo import DEMO_ORG
    from vigia.report import build_html_report

    data = payload()
    html = build_html_report(
        DEMO_ORG,
        data["scan"],
        data["previous_score"],
        data["delta"],
        data["domains"],
        actions=data["actions"],
        breakdown=data["breakdown"],
        people=data["people_at_risk"],
    )
    lowered = html.lower()
    for marker in ("ejemplo con datos ficticios", "demostración", "watermark", "marca de agua"):
        assert marker not in lowered, f"the attachable PDF must be clean: {marker}"
    assert DEMO_DOMAIN in html
