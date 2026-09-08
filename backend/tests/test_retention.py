"""The 24-hour window on personal data.

The addresses in a report belong to employees of the customer's organization:
people who never used Vigía and never consented to anything. They are needed
for a day so an admin can act, and are a liability after that.

The invariant that matters most here is not that they disappear — it is that
their disappearance is *visible*. A finding that quietly loses its list would
read as "nobody was affected", which is the exact class of false statement
this product exists to catch.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from vigia import retention
from vigia.db import Database

NOW = datetime(2026, 7, 31, 18, 0, tzinfo=timezone.utc)


@pytest.fixture()
def db(tmp_path):
    return Database(str(tmp_path / "r.db"))


def findings():
    return [
        {
            "id": "2sv-users", "status": "fail", "severity": "high",
            "accounts": ["ana@cliente.com", "luis@cliente.com"],
            "affected_items": ["ana@cliente.com", "luis@cliente.com", "… y 3 más"],
        },
        {
            "id": "email-spf", "status": "fail", "severity": "high",
            # Not personal data: domains must survive the purge.
            "affected_items": ["cliente.com", "correo.cliente.com"],
            "details": {"domains": {"cliente.com": {}}},
        },
        {"id": "audit-log", "status": "pass", "severity": "info"},
    ]


def add_scan(db, org_id, created_at, data=None):
    with db._connect() as conn:
        cursor = conn.execute(
            """INSERT INTO scans (org_id, created_at, score, counts_json, findings_json, manual_json)
               VALUES (?, ?, 40, '{}', ?, '[]')""",
            (org_id, created_at.isoformat(), json.dumps(data or findings())),
        )
        return cursor.lastrowid


def org(db):
    return db.upsert_org("cliente.com", "admin@cliente.com", "enc")["id"]


def stored(db, scan_id):
    with db._connect() as conn:
        return json.loads(
            conn.execute("SELECT findings_json FROM scans WHERE id = ?", (scan_id,)).fetchone()[0]
        )


# ------------------------------------------------------- what is an address

@pytest.mark.parametrize("value", ["ana@cliente.com", " luis@x.co.uk ", "a.b+c@d.example.com"])
def test_addresses_are_recognized(value):
    assert retention.is_address(value)


@pytest.mark.parametrize("value", [
    "cliente.com",                    # a domain, from the DNS findings
    "… y 3 más",                      # the truncation marker
    "/Ventas/Comercial",              # an organizational unit, from policies
    "Slack para Google Drive",        # an app name
    "", None, 42, "sin@punto",
])
def test_everything_else_is_left_alone(value):
    assert not retention.is_address(value)


# ------------------------------------------------------------- the stripping

def test_addresses_go_and_domains_stay():
    data = findings()
    removed = retention.strip_addresses(data, NOW.isoformat())
    assert removed == 2, "dos personas, aunque aparezcan en dos campos"
    assert data[0]["accounts"] == []
    assert data[0]["affected_items"] == ["… y 3 más"]
    assert data[1]["affected_items"] == ["cliente.com", "correo.cliente.com"]


def test_the_purge_records_what_it_removed():
    """Without this the report would claim nobody was affected."""
    data = findings()
    retention.strip_addresses(data, NOW.isoformat())
    details = data[0]["details"]
    assert details["addresses_purged"] == 2
    assert details["addresses_purged_at"] == NOW.isoformat()


def test_untouched_findings_gain_no_marker():
    data = findings()
    retention.strip_addresses(data, NOW.isoformat())
    assert "addresses_purged" not in (data[1].get("details") or {})
    assert "details" not in data[2]


def test_existing_details_survive():
    data = [{"id": "x", "accounts": ["a@b.com"], "details": {"count": 7, "regression": True}}]
    retention.strip_addresses(data, NOW.isoformat())
    assert data[0]["details"]["count"] == 7
    assert data[0]["details"]["regression"] is True
    assert data[0]["details"]["addresses_purged"] == 1


def test_running_twice_does_not_inflate_the_count():
    data = findings()
    retention.strip_addresses(data, NOW.isoformat())
    assert retention.strip_addresses(data, NOW.isoformat()) == 0
    assert data[0]["details"]["addresses_purged"] == 2


# --------------------------------------------------------- the window itself

def test_a_scan_inside_the_window_keeps_its_addresses(db):
    org_id = org(db)
    fresh = add_scan(db, org_id, NOW - timedelta(hours=23))
    result = retention.purge(db, 24, now=NOW)
    assert result["scans"] == 0
    assert stored(db, fresh)[0]["accounts"] == ["ana@cliente.com", "luis@cliente.com"]


def test_a_scan_past_the_window_loses_them(db):
    org_id = org(db)
    old = add_scan(db, org_id, NOW - timedelta(hours=25))
    result = retention.purge(db, 24, now=NOW)
    assert result["scans"] == 1 and result["addresses"] == 2
    data = stored(db, old)
    assert data[0]["accounts"] == []
    assert data[0]["details"]["addresses_purged"] == 2


def test_the_score_and_the_statuses_survive_the_purge(db):
    """Everything the history needs must outlive the addresses."""
    org_id = org(db)
    old = add_scan(db, org_id, NOW - timedelta(days=9))
    retention.purge(db, 24, now=NOW)
    data = stored(db, old)
    assert [f["id"] for f in data] == ["2sv-users", "email-spf", "audit-log"]
    assert [f["status"] for f in data] == ["fail", "fail", "pass"]
    with db._connect() as conn:
        assert conn.execute("SELECT score FROM scans WHERE id = ?", (old,)).fetchone()[0] == 40


def test_regression_detection_still_works_on_purged_history(db):
    """`detect_regressions` reads ids and statuses only — proven here rather
    than assumed, because it is the reason this design is affordable."""
    from vigia.checks.finding import Finding
    from vigia.delta import detect_regressions

    org_id = org(db)
    add_scan(db, org_id, NOW - timedelta(days=9))
    retention.purge(db, 24, now=NOW)
    history = db.findings_history(org_id, limit=10)

    current = [Finding(id="2sv-users", title="t", severity="high", status="fail")]
    previous = [{"id": "2sv-users", "status": "pass"}]
    assert detect_regressions(current, previous, history) == ["2sv-users"]


def test_the_headcount_is_not_the_sum_of_the_per_finding_counts(db):
    """One person appears in several findings. The per-finding numbers are
    right, but adding them up would report 80 people where there are 15."""
    org_id = org(db)
    data = [
        {"id": "a", "status": "fail", "accounts": ["ana@c.com", "luis@c.com"]},
        {"id": "b", "status": "fail", "accounts": ["ana@c.com"]},
        {"id": "c", "status": "fail", "affected_items": ["ana@c.com", "luis@c.com"]},
    ]
    scan_id = add_scan(db, org_id, NOW - timedelta(hours=30), data)
    result = retention.purge(db, 24, now=NOW)

    assert result["addresses"] == 2, "dos personas, no cinco apariciones"
    saved = stored(db, scan_id)
    assert [f["details"]["addresses_purged"] for f in saved] == [2, 1, 2]

def test_the_same_person_in_two_scans_is_one_person(db):
    """A weekly scan repeats the same employees. Summing per scan would turn
    15 people into 30."""
    org_id = org(db)
    for hours in (30, 54):
        add_scan(db, org_id, NOW - timedelta(hours=hours),
                 [{"id": "a", "status": "fail", "accounts": ["ana@c.com", "luis@c.com"]}])
    result = retention.purge(db, 24, now=NOW)
    assert result["scans"] == 2
    assert result["addresses"] == 2, "las mismas dos personas en dos escaneos"



def test_purging_is_idempotent_so_two_workers_cannot_conflict(db):
    org_id = org(db)
    add_scan(db, org_id, NOW - timedelta(hours=30))
    first = retention.purge(db, 24, now=NOW)
    second = retention.purge(db, 24, now=NOW)
    assert first["scans"] == 1 and second["scans"] == 0


def test_a_retention_of_zero_disables_the_purge(db):
    org_id = org(db)
    old = add_scan(db, org_id, NOW - timedelta(days=400))
    assert retention.purge(db, 0, now=NOW)["scans"] == 0
    assert stored(db, old)[0]["accounts"] != []


def test_unreadable_findings_are_skipped_not_fatal(db):
    org_id = org(db)
    with db._connect() as conn:
        conn.execute(
            """INSERT INTO scans (org_id, created_at, score, counts_json, findings_json, manual_json)
               VALUES (?, ?, 1, '{}', 'no soy json', '[]')""",
            (org_id, (NOW - timedelta(days=2)).isoformat()),
        )
    good = add_scan(db, org_id, NOW - timedelta(days=2))
    assert retention.purge(db, 24, now=NOW)["scans"] == 1
    assert stored(db, good)[0]["accounts"] == []


# ------------------------------------------------- the outreach send bodies

def test_the_stored_message_text_expires_but_the_recipient_does_not(db):
    """The recipient column is the anti-spam interlock: losing it would let
    the same person be written to twice."""
    with db._connect() as conn:
        conn.execute(
            """INSERT INTO outreach_sends
                   (created_at, domains, recipient, subject, problems, ok, error, body)
               VALUES (?, 'x.com', 'quien@x.com', 's', 2, 1, '', 'cuerpo con quien@x.com')""",
            ((NOW - timedelta(hours=30)).isoformat(),),
        )
    assert retention.purge(db, 24, now=NOW)["bodies"] == 1
    with db._connect() as conn:
        row = conn.execute("SELECT recipient, body FROM outreach_sends").fetchone()
    assert row["recipient"] == "quien@x.com"
    assert row["body"] == ""
    assert db.outreach_sent_since("quien@x.com", (NOW - timedelta(days=14)).isoformat())


def test_a_recent_message_keeps_its_body(db):
    with db._connect() as conn:
        conn.execute(
            """INSERT INTO outreach_sends
                   (created_at, domains, recipient, subject, problems, ok, error, body)
               VALUES (?, 'x.com', 'q@x.com', 's', 1, 1, '', 'texto')""",
            ((NOW - timedelta(hours=2)).isoformat(),),
        )
    assert retention.purge(db, 24, now=NOW)["bodies"] == 0


# --------------------------------------------- the report cannot claim zero

def test_the_pdf_reports_the_real_count_after_a_purge():
    from vigia.report import build_html_report

    data = findings()
    retention.strip_addresses(data, NOW.isoformat())
    html = build_html_report(
        {"primary_domain": "cliente.com"},
        {"created_at": NOW.isoformat(), "score": 40,
         "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0},
         "findings": data, "manual_checks": []},
        None, None, [],
    )
    assert "Afectados (2)" in html
    assert "retención de 24 horas" in html
    assert "ana@cliente.com" not in html


def test_the_csv_reports_the_real_count_after_a_purge():
    from vigia.report import findings_csv_rows

    # No truncation marker here on purpose: the count is of affected accounts,
    # and "… y N más" is a rendering artefact, not an affected account.
    data = [{
        "id": "2sv-users", "status": "fail", "severity": "high",
        "accounts": ["ana@cliente.com", "luis@cliente.com"],
        "affected_items": ["ana@cliente.com", "luis@cliente.com"],
    }]
    retention.strip_addresses(data, NOW.isoformat())
    rows = findings_csv_rows({"findings": data})
    header, first = rows[0], rows[1]
    assert first[header.index("num_afectados")] == "2"
    assert "borradas" in first[header.index("afectados")]
    assert "ana@cliente.com" not in " ".join(str(c) for r in rows for c in r)


# ------------------------------------------------------------- the schedule

def test_the_purge_is_scheduled_and_cannot_take_the_scheduler_down(monkeypatch, tmp_path):
    import os

    os.environ["VIGIA_DB_PATH"] = str(tmp_path / "s.db")
    from vigia import create_app, jobs

    app = create_app()
    scheduler = app.extensions["vigia"]["scheduler"]
    assert scheduler and scheduler.get_job("vigia-retention-purge")

    def explode(*args, **kwargs):
        raise RuntimeError("disco lleno")

    monkeypatch.setattr(retention, "purge", explode)
    assert jobs.run_retention_purge(app) == {"error": True}
