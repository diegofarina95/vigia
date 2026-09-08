"""Point 2 (leverage ranking), point 3 (deterministic auditable score) and
point 1's no-double-counting rule."""
import pytest

from vigia.remediation import CATALOG, rank_actions
from vigia.scoring import compute_score, people_at_risk, score_breakdown, severity_counts


def f(fid, severity, status, accounts=(), actions=(), title=None, manual=False):
    return {
        "id": fid,
        "title": title or fid,
        "severity": severity,
        "status": status,
        "accounts": list(accounts),
        "remediation_actions": list(actions),
        "manual": manual,
    }


# --------------------------------------------------- per-account dedup (P1)

def test_one_account_in_many_findings_is_counted_once():
    """The whole point: a person weak in four ways is one exposure, not four."""
    findings = [
        f("composite-x", "critical", "fail", ["ghost@x.com"]),
        f("2sv-delegated-admins", "critical", "fail", ["ghost@x.com"]),
        f("never-logged-in", "low", "warn", ["ghost@x.com"]),
        f("2sv-users", "high", "fail", ["ghost@x.com"]),
    ]
    breakdown = score_breakdown(findings)
    assert len(breakdown["accounts"]) == 1
    row = breakdown["accounts"][0]
    assert row["account"] == "ghost@x.com"
    assert row["severity"] == "critical"  # worst severity wins
    assert row["weight"] == 10
    assert breakdown["total_weight"] == 10  # not 10+10+1+6
    # The atomic findings stay listed for the reader...
    assert len(findings) == 4
    # ...but only contribute through the account row.
    assert breakdown["findings"] == []


def test_accounts_are_listed_with_the_other_findings_they_appear_in():
    findings = [
        f("composite-x", "critical", "fail", ["ghost@x.com"]),
        f("2sv-delegated-admins", "critical", "fail", ["ghost@x.com"]),
    ]
    row = score_breakdown(findings)["accounts"][0]
    assert row["also_in"]  # auditable: which other findings touch this person


def test_two_accounts_score_independently():
    findings = [f("2sv-users", "high", "fail", ["a@x.com", "b@x.com"])]
    breakdown = score_breakdown(findings)
    assert len(breakdown["accounts"]) == 2
    assert breakdown["total_weight"] == 12  # 6 + 6


def test_org_level_findings_still_score_per_finding():
    findings = [f("email-spf", "high", "fail"), f("email-dmarc", "high", "fail")]
    breakdown = score_breakdown(findings)
    assert breakdown["accounts"] == []
    assert len(breakdown["findings"]) == 2
    assert breakdown["total_weight"] == 12


def test_warn_earns_half_credit_per_account():
    findings = [f("never-logged-in", "high", "warn", ["a@x.com"])]
    breakdown = score_breakdown(findings)
    assert breakdown["earned_weight"] == 3.0
    assert breakdown["score"] == 50


def test_fail_beats_warn_on_a_severity_tie():
    findings = [
        f("one", "high", "warn", ["a@x.com"]),
        f("two", "high", "fail", ["a@x.com"]),
    ]
    row = score_breakdown(findings)["accounts"][0]
    assert row["status"] == "fail" and row["earned"] == 0.0


# ----------------------------------------------- determinism & auditability

FIXTURE = [
    f("composite-superadmin-dormant-no-2sv", "critical", "fail", ["ghost@x.com"],
      ["enforce_2sv_org", "suspend_unused_admins"]),
    f("2sv-delegated-admins", "critical", "fail", ["ghost@x.com"], ["enforce_2sv_org"]),
    f("2sv-users", "high", "fail", ["ana@x.com", "leo@x.com"], ["enforce_2sv_org"]),
    f("dormant-accounts", "medium", "fail", ["leo@x.com"], ["suspend_dormant"]),
    f("email-spf", "high", "fail", (), ["publish_spf"]),
    f("email-dkim", "medium", "undetermined", (), ["enable_dkim"]),
    f("super-admin-count", "high", "pass"),
    f("manual-thing", "high", "fail", ["ana@x.com"], manual=True),
]


def test_score_of_a_known_fixture_is_pinned():
    """Guards against silent drift in the scoring model."""
    breakdown = score_breakdown(FIXTURE)
    # Derived by hand, line by line, so a change to the model has to be
    # deliberate:
    #
    #   people   ghost critical 10 + ana high 6 + leo high 6      = 22, earned 0
    #   settings email-spf high fail 6 (earned 0)
    #            super-admin-count high pass 6 (earned 6)         = 12, earned 6
    #
    # People (22) exceed settings (12), so the people block is scaled by
    # 12/22 = 0.5454… down to 12.0 — the ceiling that stops headcount from
    # deciding the score on its own.
    #
    #   total  = 12.0 + 12 = 24.0
    #   earned = 0 + 6 = 6.0
    #   score  = round(100 × 6 / 24) = 25
    assert breakdown["org_weight"] == 12
    assert round(breakdown["people_weight"], 2) == 12.0
    assert breakdown["people_scale"] == 0.5455
    assert breakdown["total_weight"] == 24.0
    assert breakdown["earned_weight"] == 6.0
    assert breakdown["score"] == 25
    assert compute_score(FIXTURE) == 25


def test_score_is_reproducible_from_the_json_alone():
    import json

    reloaded = json.loads(json.dumps(FIXTURE))
    assert compute_score(reloaded) == compute_score(FIXTURE)


def test_undetermined_and_manual_are_excluded_and_explained():
    breakdown = score_breakdown(FIXTURE)
    excluded = {e["id"]: e["reason"] for e in breakdown["excluded"]}
    assert excluded["email-dkim"] == "no se ha podido determinar"
    assert excluded["manual-thing"] == "comprobación manual"


def test_all_pass_is_100_and_nothing_scorable_is_none():
    assert compute_score([f("a", "high", "pass"), f("b", "critical", "pass")]) == 100
    assert compute_score([]) is None
    assert compute_score([f("x", "high", "undetermined")]) is None


def test_breakdown_publishes_the_weights_it_used():
    breakdown = score_breakdown(FIXTURE)
    assert breakdown["weights"]["critical"] == 10
    assert breakdown["credits"]["warn"] == 0.5
    assert breakdown["lost_weight"] == breakdown["total_weight"] - breakdown["earned_weight"]


# -------------------------------------------------- people at risk (shared)

def test_people_at_risk_ranks_by_severity_then_count():
    people = people_at_risk(FIXTURE)
    assert people[0]["account"] == "ghost@x.com"
    assert people[0]["worst"] == "critical"
    assert {p["account"] for p in people} == {"ghost@x.com", "ana@x.com", "leo@x.com"}
    leo = next(p for p in people if p["account"] == "leo@x.com")
    assert len(leo["issues"]) == 2  # 2sv-users + dormant-accounts


def test_people_at_risk_ignores_manual_and_passing_findings():
    accounts = {p["account"] for p in people_at_risk(FIXTURE)}
    assert "ana@x.com" in accounts  # from 2sv-users, not from the manual card
    people = people_at_risk([f("x", "high", "pass", ["nobody@x.com"])])
    assert people == []


# ----------------------------------------------------- leverage ranking (P2)

def test_ranking_impact_is_derived_not_hardcoded():
    actions = rank_actions(FIXTURE, limit=3)
    top = actions[0]
    assert top["id"] == "enforce_2sv_org"
    # Closes composite + 2sv-delegated-admins + 2sv-users = 3 findings, 2 of them critical
    assert top["findings_closed"] == 3
    assert top["criticals_closed"] == 2
    assert top["highs_closed"] == 1
    # ghost, ana, leo
    assert top["accounts_affected"] == 3
    assert top["score_gain"] > 0


def test_score_gain_matches_an_actual_recomputation():
    actions = rank_actions(FIXTURE, limit=5)
    action = next(a for a in actions if a["id"] == "enforce_2sv_org")
    resolved = [
        dict(finding, status="pass", accounts=[])
        if finding["id"] in action["finding_ids"]
        else finding
        for finding in FIXTURE
    ]
    assert action["score_gain"] == compute_score(resolved) - compute_score(FIXTURE)


def test_ranking_is_by_findings_closed_per_minute_not_severity():
    actions = rank_actions(FIXTURE, limit=5)
    leverages = [a["leverage"] for a in actions]
    assert leverages == sorted(leverages, reverse=True)


def test_actions_with_user_impact_are_flagged():
    actions = rank_actions(FIXTURE, limit=5)
    enforce = next(a for a in actions if a["id"] == "enforce_2sv_org")
    assert enforce["user_impact"] and "se queda fuera" in enforce["user_impact"]


def test_only_open_findings_generate_actions():
    actions = rank_actions([f("x", "high", "pass", (), ["publish_spf"])])
    assert actions == []


def test_ranking_respects_the_limit():
    assert len(rank_actions(FIXTURE, limit=2)) == 2


def test_every_action_in_the_catalog_is_complete():
    for action_id, action in CATALOG.items():
        assert action.title and action.title[0].isupper(), action_id
        assert action.console_path and action.console_url, action_id
        assert action.minutes > 0, action_id


def test_every_action_is_complete_in_both_languages():
    """The sentences live in the locale catalogue now, so a missing English entry
    would not be an empty card — `i18n.text` returns the dotted path, and the
    report would print "remediation.publish_spf.title" to a customer. Checked by
    building both languages rather than by trusting the generator."""
    from vigia.remediation import catalog

    for lang in ("es", "en"):
        acciones = catalog(lang)
        assert set(acciones) == set(CATALOG), lang
        for action_id, action in acciones.items():
            for campo, valor in (
                ("title", action.title),
                ("console_path", action.console_path),
                ("user_impact", action.user_impact),
            ):
                if valor is None:  # not every action breaks something
                    continue
                assert valor.strip(), f"{lang}/{action_id}/{campo} vacío"
                assert not valor.startswith("remediation."), (
                    f"{lang}/{action_id}/{campo} falta en el catálogo: {valor}"
                )
            assert action.title[0].isupper(), f"{lang}/{action_id}"
    # And the two languages are actually two: an English half that fell back to
    # Spanish would satisfy everything above.
    assert catalog("en")["enforce_2sv_org"].title != catalog("es")["enforce_2sv_org"].title


def test_a_google_menu_path_keeps_googles_own_spelling():
    """The one place British English loses. The reader is following the path with
    the console open, so "Organizational unit", "Authenticate email" and
    "license" stay spelled as the menu spells them; correcting them into British
    English breaks a navigation instruction to win a spelling argument."""
    from vigia.remediation import catalog

    rutas = {aid: a.console_path for aid, a in catalog("en").items()}
    assert rutas["enable_dkim"] == "Apps > Google Workspace > Gmail > Authenticate email"
    assert rutas["enforce_2sv_org"].endswith("2-Step Verification > Enforcement")
    assert "Organisational" not in " ".join(rutas.values())
    # And the prose around the path is ours to write, so it is British.
    assert "organisation" in catalog("en")["restrict_drive_sharing"].title


def test_a_ranking_can_be_asked_for_in_english():
    """`rank_actions` renders the action text, so the language belongs to the call
    and not to the scan: the same findings ranked twice come back with the same
    numbers and different sentences."""
    es = rank_actions(FIXTURE, limit=3)
    en = rank_actions(FIXTURE, limit=3, lang="en")
    assert [a["id"] for a in es] == [a["id"] for a in en]
    assert [a["score_gain"] for a in es] == [a["score_gain"] for a in en]
    assert es[0]["title"] != en[0]["title"]
    assert "organisation" in en[0]["title"]


def test_a_stored_ranking_can_be_re_read_in_the_other_language():
    """Actions are computed at scan time and stored as rendered text, so the only
    way an old scan reads in English is to re-derive from the action id — the same
    trick `i18n` plays on findings."""
    from vigia.remediation import localize_actions

    guardadas = rank_actions(FIXTURE, limit=3)
    traducidas = localize_actions(guardadas, "en")
    assert [a["id"] for a in traducidas] == [a["id"] for a in guardadas]
    for antes, despues in zip(guardadas, traducidas):
        assert antes["title"] != despues["title"]
        assert antes["findings_closed"] == despues["findings_closed"]
        assert antes["minutes"] == despues["minutes"]
        # An action with no warning must not gain one in translation.
        assert (antes["user_impact"] is None) == (despues["user_impact"] is None)
    # An id the catalogue does not know keeps whatever the scan stored.
    desconocida = [{"id": "future_action", "title": "Lo que dijera entonces"}]
    assert localize_actions(desconocida, "en")[0]["title"] == "Lo que dijera entonces"


@pytest.mark.parametrize(
    "action_id",
    ["enforce_2sv_org", "publish_spf", "publish_dmarc", "enable_dkim",
     "restrict_drive_sharing", "disable_auto_forwarding"],
)
def test_actions_referenced_by_checks_exist_in_the_catalog(action_id):
    assert action_id in CATALOG
