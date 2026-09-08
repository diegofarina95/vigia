"""Versioning the score, so a deploy cannot masquerade as a trend.

The score is a fraction of the weight the engine could award. Ship a check that
passes and the denominator grows; ship one that fails and it shrinks. Either
way the number moves while the tenant's exposure has not changed at all, and
the report announces "▼ 7 since the last scan" for what was a git push.

That is not hypothetical here: two checks went out and the score went from 31
to 40 while the critical count went **up**.
"""
import json

import pytest

from vigia import engine_version as ev
from vigia.db import Database
from vigia.scoring import INVENTORY_FINDINGS, people_at_risk, score_breakdown


# --------------------------------------------------------- the fingerprint

def test_the_version_is_stable_across_calls():
    assert ev.engine_version() == ev.engine_version()


def test_it_looks_like_a_fingerprint_not_a_number_someone_maintains():
    version = ev.engine_version()
    assert version.startswith("v1-") and len(version) == 11


def test_adding_a_check_changes_the_fingerprint(monkeypatch):
    """The whole point: nobody has to remember to bump anything."""
    before = ev.engine_version()

    class FakeModule:
        CHECK_ID = "un-check-nuevo"

    from vigia import checks

    monkeypatch.setattr(checks, "ALL_CHECKS", list(checks.ALL_CHECKS) + [FakeModule])
    assert ev.engine_version() != before


def test_changing_a_severity_weight_changes_the_fingerprint(monkeypatch):
    before = ev.engine_version()
    from vigia import scoring

    monkeypatch.setattr(scoring, "SEVERITY_WEIGHTS", {**scoring.SEVERITY_WEIGHTS, "high": 7})
    assert ev.engine_version() != before


def test_adding_a_policy_check_changes_the_fingerprint(monkeypatch):
    before = ev.engine_version()
    from vigia.checks import check_policies

    monkeypatch.setattr(check_policies, "CHECKS", check_policies.CHECKS[:-1])
    assert ev.engine_version() != before


def test_describe_reports_what_went_into_it():
    described = ev.describe()
    assert described["version"] == ev.engine_version()
    assert described["checks"] > 0 and described["policies"] > 0


# ------------------------------------------------------- what is comparable

@pytest.mark.parametrize("one,other,expected", [
    ("v1-aaaa1111", "v1-aaaa1111", True),
    ("v1-aaaa1111", "v1-bbbb2222", False),
    ("", "v1-aaaa1111", False),
    ("v1-aaaa1111", "", False),
    ("", "", False),          # two unknowns are not "the same engine"
    (None, None, False),
])
def test_only_identical_known_engines_may_be_compared(one, other, expected):
    assert ev.comparable(one, other) is expected


# ------------------------------------------------------------- persistence

def test_the_version_is_stored_with_the_scan_and_read_back(tmp_path):
    db = Database(str(tmp_path / "v.db"))
    org = db.upsert_org("cliente.com", "admin@cliente.com", "enc")
    db.insert_scan(
        org_id=org["id"], score=40, counts={}, findings=[], manual_checks=[],
        engine_version="v1-deadbeef",
    )
    [scan] = db.latest_scans(org["id"], limit=1)
    assert scan["engine_version"] == "v1-deadbeef"
    assert db.scan_history(org["id"])[0]["engine_version"] == "v1-deadbeef"


def test_a_scan_stored_before_this_existed_reads_as_unknown(tmp_path):
    """Older rows carry an empty string, and empty is never comparable."""
    db = Database(str(tmp_path / "v.db"))
    org = db.upsert_org("cliente.com", "admin@cliente.com", "enc")
    db.insert_scan(org_id=org["id"], score=31, counts={}, findings=[], manual_checks=[])
    [scan] = db.latest_scans(org["id"], limit=1)
    assert scan["engine_version"] == ""
    assert not ev.comparable(scan["engine_version"], "v1-anything")


def test_a_real_scan_records_the_current_engine(tmp_path, monkeypatch):
    import os

    os.environ["VIGIA_DB_PATH"] = str(tmp_path / "s.db")
    from vigia import scan as scan_module

    class Ctx:
        include_directory_domains = False

        def users(self):
            return []

    db = Database(str(tmp_path / "s.db"))
    org = db.upsert_org("cliente.com", "admin@cliente.com", "enc")
    monkeypatch.setattr(scan_module, "collect_findings", lambda ctx, label="": [])
    stored = scan_module.run_scan(org, Ctx(), db)
    assert stored["engine_version"] == ev.engine_version()


# ----------------------------------------- the delta refuses to lie


def payload_for(db, org, monkeypatch=None):
    from vigia.api import routes

    return routes._scan_with_delta(org, db)


def test_two_scans_from_different_engines_produce_no_delta(tmp_path):
    db = Database(str(tmp_path / "d.db"))
    org = db.upsert_org("cliente.com", "admin@cliente.com", "enc")
    db.insert_scan(org_id=org["id"], score=31, counts={}, findings=[],
                   manual_checks=[], engine_version="v1-viejo000")
    db.insert_scan(org_id=org["id"], score=40, counts={}, findings=[],
                   manual_checks=[], engine_version="v1-nuevo000")

    _, previous_score, summary = payload_for(db, org)
    assert previous_score is None, "no se puede restar entre motores distintos"
    assert summary["engine_changed"] is True
    assert "no son comparables" in summary["note"]


def test_two_scans_from_the_same_engine_still_produce_a_delta(tmp_path):
    db = Database(str(tmp_path / "d.db"))
    org = db.upsert_org("cliente.com", "admin@cliente.com", "enc")
    for score in (31, 40):
        db.insert_scan(org_id=org["id"], score=score, counts={}, findings=[],
                       manual_checks=[], engine_version="v1-mismo000")

    _, previous_score, summary = payload_for(db, org)
    assert previous_score == 31
    assert summary["engine_changed"] is False


def test_the_chart_marks_where_the_set_of_checks_changed(tmp_path):
    """The line must not be read as a trend across a discontinuity."""
    from vigia import create_app

    import os
    os.environ["VIGIA_DB_PATH"] = str(tmp_path / "h.db")
    app = create_app()
    with app.app_context():
        from vigia.api.routes import get_db

        db = get_db()
        org = db.upsert_org("cliente.com", "admin@cliente.com", "enc")
        for version in ("v1-aaa00000", "v1-aaa00000", "v1-bbb00000"):
            db.insert_scan(org_id=org["id"], score=40, counts={}, findings=[],
                           manual_checks=[], engine_version=version)
        history = db.scan_history(org["id"])

    previous, marks = None, []
    for point in history:
        marks.append(bool(previous) and point["engine_version"] != previous)
        previous = point["engine_version"]
    assert marks == [False, False, True], "solo el tercer punto cambia de motor"


# ------------------------------- an inventory does not escalate anybody

def finding(fid, severity, status, accounts):
    return {"id": fid, "title": fid, "severity": severity, "status": status,
            "accounts": accounts, "affected_items": accounts}


SUPERS = ["diego@x.com", "marius@x.com", "saj@x.com"]


def test_the_super_admin_count_does_not_make_anybody_critical():
    """Six super admins is a fact about the organization's shape, not six
    personal failures. It used to add a second "problem" to each of them and
    push the row to critical."""
    findings = [
        finding("super-admin-count", "high", "warn", SUPERS),
        finding("2sv-users", "high", "fail", ["diego@x.com"]),
    ]
    people = {p["account"]: p for p in people_at_risk(findings)}

    assert set(people) == {"diego@x.com"}, "solo quien tiene un problema real"
    assert [i["id"] for i in people["diego@x.com"]["issues"]] == ["2sv-users"]


def test_an_inventory_is_not_attributed_per_account_in_the_breakdown():
    breakdown = score_breakdown([finding("super-admin-count", "high", "warn", SUPERS)])
    assert breakdown["accounts"] == []
    # It still scores, at organization level, where it belongs.
    assert any(row["id"] == "super-admin-count" for row in breakdown["findings"])


def test_a_real_finding_on_the_same_people_still_counts():
    findings = [
        finding("super-admin-count", "high", "warn", SUPERS),
        finding("composite-superadmin-no-2sv", "critical", "fail", SUPERS),
    ]
    people = people_at_risk(findings)
    assert len(people) == 3
    assert all(p["worst"] == "critical" for p in people)
    assert all(len(p["issues"]) == 1 for p in people), "una sola incidencia real"


def test_the_inventory_list_is_shared_with_the_coherence_checker():
    """One definition. Two copies would drift, and this one decides both who
    gets escalated and which findings may list people while passing."""
    from vigia.checks import consistency

    assert consistency.INVENTORY_FINDINGS is INVENTORY_FINDINGS


# ------------------------------------------- the drift guard the brief asked for

FIXTURE = [
    finding("composite-superadmin-no-2sv", "critical", "fail", ["a@x.com"]),
    finding("2sv-users", "high", "fail", ["a@x.com", "b@x.com"]),
    {"id": "email-spf", "title": "SPF", "severity": "high", "status": "pass"},
    {"id": "email-dmarc", "title": "DMARC", "severity": "medium", "status": "warn"},
    {"id": "audit-log", "title": "Auditoría", "severity": "low", "status": "pass"},
]


#: Derived by hand so the pin is auditable rather than copied from a run:
#:
#:   PEOPLE
#:   a@x.com   worst = critical   weight 10   earned 0     (fail)
#:   b@x.com   worst = high       weight  6   earned 0     (fail)
#:                                ────────
#:                                     16          0
#:   SETTINGS
#:   email-spf         high       weight  6   earned 6.0   (pass)
#:   email-dmarc       medium     weight  3   earned 1.5   (warn, half credit)
#:   audit-log         low        weight  1   earned 1.0   (pass)
#:                                ────────    ──────────
#:                                     10          8.5
#:
#: People (16) outweigh settings (10), so the people block is scaled by
#: 10/16 = 0.625 to 10.0 — the ceiling that keeps a company's headcount from
#: deciding its score. Total 20.0, earned 8.5.
#:
#:   round(100 × 8.5 / 20) = round(42.5) = 42
#:
#: Note 42, not 43: Python rounds halves to even. Left as-is because the
#: alternative is a rounding rule nobody can predict from the table above.
EXPECTED_SCORE = 42


def test_a_known_fixture_scores_exactly_this(tmp_path):
    """Pinned on purpose. If this number moves, either the weights changed or
    the attribution did — and both are things that must be noticed here, not
    discovered later in a customer's trend line."""
    from vigia.scoring import compute_score

    assert compute_score(FIXTURE) == EXPECTED_SCORE


def test_the_pinned_fixture_derivation_is_auditable():
    breakdown = score_breakdown(FIXTURE)
    assert breakdown["score"] == EXPECTED_SCORE
    assert breakdown["total_weight"] == 20.0
    assert breakdown["earned_weight"] == 8.5
    assert breakdown["org_weight"] == 10
    assert breakdown["people_scale"] == 0.625
    # a@x.com counted once, at its worst severity, not twice
    accounts = {row["account"]: row for row in breakdown["accounts"]}
    assert accounts["a@x.com"]["severity"] == "critical"
    assert len(accounts) == 2
    assert json.dumps(breakdown)  # serialisable for the client that audits it


# ----------------------------- the previous scan has to actually be previous

def test_the_delta_compares_against_the_scan_before_not_a_later_one(tmp_path):
    """Four deploys of the engine-version gate did nothing because the gate
    was reading the wrong row.

    `_scan_with_delta` took "the newest scan that is not the one on screen"
    from a page of two. For the latest row that is right by accident; for any
    older row it hands back a LATER scan as "previous". So a report at the
    boundary between two check sets compared itself against a scan from the
    future that happened to share an engine, found no differences, and printed
    "no changes" over a jump from 45 checks to 50.
    """
    import json
    import os

    os.environ["VIGIA_DB_PATH"] = str(tmp_path / "delta.db")
    from vigia.db import Database

    db = Database(str(tmp_path / "delta.db"))
    org_id = db.upsert_org("cliente.com", "admin@cliente.com", b"x")["id"]

    for score, engine in ((30, "v1-viejo"), (40, "v1-nuevo"), (41, "v1-nuevo")):
        db.insert_scan(org_id, score=score, counts={}, findings=[],
                     manual_checks=[], engine_version=engine)

    ids = [s["id"] for s in db.latest_scans(org_id, limit=10)]   # newest first
    primero, medio, ultimo = ids[2], ids[1], ids[0]

    assert db.scan_before(org_id, ultimo)["id"] == medio
    assert db.scan_before(org_id, medio)["id"] == primero
    assert db.scan_before(org_id, primero) is None, "el primero no tiene anterior"

    # The boundary row: its predecessor ran a different engine.
    assert db.scan_before(org_id, medio)["engine_version"] == "v1-viejo"
