"""SQLite data-access layer.

Every read/write goes through this module so the storage engine can be
swapped for Postgres later by reimplementing this file only. Stored data
is deliberately minimal: one org row (with the encrypted refresh token)
and one row per scan (findings as JSON).
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS orgs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    primary_domain TEXT UNIQUE NOT NULL,
    admin_email TEXT NOT NULL,
    refresh_token_enc TEXT NOT NULL,
    -- Vestigial. The product decision is that the analysis is free for
    -- everybody and the revenue comes from remediation, so there is no
    -- plan logic left to read it. Kept because dropping a column is a
    -- destructive migration with nothing to gain; if tiers ever return
    -- they are reintroduced deliberately, not resurrected from here.
    plan TEXT NOT NULL DEFAULT 'free',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    score INTEGER,
    counts_json TEXT NOT NULL DEFAULT '{}',
    findings_json TEXT NOT NULL DEFAULT '[]',
    manual_json TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_scans_org_created ON scans (org_id, created_at DESC);

-- Every outreach message that was attempted, sent or failed. Exists so a
-- domain is never contacted twice by accident, and so there is a record of
-- what was claimed to whom.
CREATE TABLE IF NOT EXISTS outreach_sends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    domains TEXT NOT NULL,
    recipient TEXT NOT NULL,
    subject TEXT NOT NULL,
    problems INTEGER NOT NULL DEFAULT 0,
    ok INTEGER NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_outreach_recipient
    ON outreach_sends (recipient, created_at DESC);

-- The accumulated OAuth picture, plus how far it has been read.
--
-- Re-reading Google's 180-day token window on every scan does not work for a
-- tenant that emits ~1600 authorize events a day: twenty pages of a thousand
-- covered six days, so three findings went from saying something wrong to
-- saying nothing at all. Neither was the goal.
--
-- So the fold is persisted and only the new events are fetched. `watermark` is
-- the timestamp of the newest event already folded in; `oldest` is the earliest
-- one ever seen, which is what the report may honestly claim to cover. The
-- window therefore GROWS with every scan instead of sliding.
CREATE TABLE IF NOT EXISTS oauth_grants (
    org_id INTEGER PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    grants_json TEXT NOT NULL DEFAULT '{}',
    watermark TEXT NOT NULL DEFAULT '',
    oldest TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS org_domains (
    org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'custom',  -- 'google' (synced) | 'custom' (user-added)
    added_at TEXT NOT NULL,
    PRIMARY KEY (org_id, domain)
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path: str) -> None:
        self.path = path
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            self._migrate(conn)

    # Columns added after the first release; applied to existing DBs on boot.
    _ADDED_COLUMNS = (
        ("settings_json", "TEXT NOT NULL DEFAULT '{}'"),
        ("schedule_frequency", "TEXT NOT NULL DEFAULT 'off'"),
        ("schedule_last_run", "TEXT"),
        ("alert_email", "TEXT NOT NULL DEFAULT ''"),
        ("alert_only_on_change", "INTEGER NOT NULL DEFAULT 1"),
        # 1 once the user has saved a schedule themselves, so the default
        # below is never re-applied over a deliberate "off".
        ("schedule_configured", "INTEGER NOT NULL DEFAULT 0"),
        # When the operator was told this organisation had run its first analysis.
        # NULL means never. A column rather than `COUNT(scans) == 1`, because the
        # retention purge deletes old scans: a counted first scan becomes a first
        # scan again months later and the alert fires twice for the same customer.
        ("operator_alerted_at", "TEXT"),
    )

    #: Columns added to `scans` after the first release.
    _ADDED_SCAN_COLUMNS = (
        # The fingerprint of the engine that produced this scan. Scores from
        # different engines are not comparable, so the delta needs to know.
        ("engine_version", "TEXT NOT NULL DEFAULT ''"),
        # The computed-once result: coverage per source, the score breakdown,
        # people at risk, ranked actions and the executive summary. Stored so
        # every channel PROJECTS it instead of re-deriving it — the CSV showing
        # 45 while the screen showed 50, and a page printing two different
        # scores after the 24-hour purge, were both re-derivation drift.
        ("result_json", "TEXT NOT NULL DEFAULT '{}'"),
    )

    @classmethod
    def _migrate(cls, conn: sqlite3.Connection) -> None:
        scan_columns = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
        for name, spec in cls._ADDED_SCAN_COLUMNS:
            if name not in scan_columns:
                conn.execute(f"ALTER TABLE scans ADD COLUMN {name} {spec}")

        columns = {row[1] for row in conn.execute("PRAGMA table_info(orgs)")}
        nuevas = [name for name, _ in cls._ADDED_COLUMNS if name not in columns]
        for name, spec in cls._ADDED_COLUMNS:
            if name not in columns:
                conn.execute(f"ALTER TABLE orgs ADD COLUMN {name} {spec}")

        # Every organisation that exists when this column is added predates the
        # feature, so none of them is news. Without this, the first customer's next
        # analysis would announce them as an arrival — the one thing this alert
        # exists not to do. Their own creation date is used, because that is when
        # they actually arrived.
        #
        # The condition is existence, NOT "has scans", which is what it said first:
        # the retention purge deletes old scans, so a long-standing customer can
        # legitimately have none on record and would have slipped through.
        if "operator_alerted_at" in nuevas:
            conn.execute(
                """
                UPDATE orgs SET operator_alerted_at = created_at
                 WHERE operator_alerted_at IS NULL
                """
            )

        # Product default: recurring scans OFF. It used to be weekly-on, which
        # was the right default for a monitoring product with a screen to turn it
        # off from — and the panel that offered that screen is gone until monthly
        # monitoring is a thing being sold. A schedule nobody can see is a
        # schedule nobody can stop, and the e-mails it sends arrive from a domain
        # whose deliverability reputation is not a thing to lend.
        #
        # The column, `set_schedule`, `orgs_due`, `claim_scheduled_run` and the
        # whole of `jobs.py` are untouched: this is one word, and putting the
        # feature back is putting the UI back.
        conn.execute(
            """
            UPDATE orgs
               SET schedule_frequency = 'off',
                   alert_email = CASE WHEN alert_email = '' THEN admin_email ELSE alert_email END
             WHERE schedule_configured = 0 AND schedule_last_run IS NULL
            """
        )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    # ------------------------------------------------------------- orgs

    def upsert_org(self, primary_domain: str, admin_email: str, refresh_token_enc: str) -> dict:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO orgs (primary_domain, admin_email, refresh_token_enc,
                                  created_at, updated_at, schedule_frequency, alert_email)
                -- 'off', not 'weekly'. This literal was the real default: every
                -- org that connected started with a live weekly schedule from its
                -- first second, and the screen to turn it off is gone until
                -- monthly monitoring is a thing being sold. A stranger connecting
                -- to try the free scan would have started receiving mail he could
                -- not stop, from a domain whose deliverability is not a thing to
                -- lend. The alert address is still stored so the feature is one
                -- word away from working again.
                VALUES (?, ?, ?, ?, ?, 'off', ?)
                ON CONFLICT (primary_domain) DO UPDATE SET
                    admin_email = excluded.admin_email,
                    refresh_token_enc = excluded.refresh_token_enc,
                    updated_at = excluded.updated_at
                """,
                (primary_domain, admin_email, refresh_token_enc, now, now, admin_email),
            )
        org = self.get_org_by_domain(primary_domain)
        assert org is not None
        return org

    def get_org(self, org_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM orgs WHERE id = ?", (org_id,)).fetchone()
        return dict(row) if row else None

    def get_org_by_domain(self, primary_domain: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM orgs WHERE primary_domain = ?", (primary_domain,)
            ).fetchone()
        return dict(row) if row else None

    def delete_org(self, org_id: int) -> None:
        """GDPR delete: removes the org, its token and every scan."""
        with self._connect() as conn:
            conn.execute("DELETE FROM orgs WHERE id = ?", (org_id,))

    # --------------------------------------------------- per-org settings

    def get_org_settings(self, org_id: int) -> dict:
        """User-tuned scan option overrides (empty dict = env defaults)."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT settings_json FROM orgs WHERE id = ?", (org_id,)
            ).fetchone()
        if not row:
            return {}
        try:
            return json.loads(row["settings_json"] or "{}")
        except ValueError:
            return {}

    def set_org_settings(self, org_id: int, overrides: dict) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE orgs SET settings_json = ?, updated_at = ? WHERE id = ?",
                (json.dumps(overrides), _now(), org_id),
            )

    # -------------------------------------------------- scheduled scans

    def claim_operator_alert(self, org_id: int) -> bool:
        """True exactly once per organisation, then False for ever.

        The `WHERE ... IS NULL` is the whole point: two scans finishing in the same
        second both read "not alerted yet" if the check and the write are separate
        statements, and the operator gets two e-mails about one customer. Here the
        database decides the winner, and `rowcount` reports it.
        """
        with self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE orgs SET operator_alerted_at = ?
                 WHERE id = ? AND operator_alerted_at IS NULL
                """,
                (_now(), org_id),
            )
            return cur.rowcount == 1

    def set_schedule(
        self, org_id: int, frequency: str, alert_email: str, alert_only_on_change: bool
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE orgs SET schedule_frequency = ?, alert_email = ?,
                                alert_only_on_change = ?, schedule_configured = 1,
                                updated_at = ?
                WHERE id = ?
                """,
                (frequency, alert_email, 1 if alert_only_on_change else 0, _now(), org_id),
            )

    def orgs_due(self, cutoffs: dict[str, str]) -> list[dict]:
        """Orgs whose schedule is due: never run, or last run at/before the
        cutoff for their frequency."""
        due: list[dict] = []
        with self._connect() as conn:
            for frequency, cutoff in cutoffs.items():
                rows = conn.execute(
                    """
                    SELECT * FROM orgs
                    WHERE schedule_frequency = ?
                      AND (schedule_last_run IS NULL OR schedule_last_run <= ?)
                    """,
                    (frequency, cutoff),
                ).fetchall()
                due.extend(dict(r) for r in rows)
        return due

    def claim_scheduled_run(self, org_id: int, now_iso: str, cutoff_iso: str) -> bool:
        """Atomically claim this org's scheduled run. Returns True for the
        single caller that wins; False for concurrent workers."""
        with self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE orgs SET schedule_last_run = ?
                WHERE id = ?
                  AND (schedule_last_run IS NULL OR schedule_last_run <= ?)
                """,
                (now_iso, org_id, cutoff_iso),
            )
        return cur.rowcount > 0

    # ---------------------------------------------------------- domains

    def list_domains(self, org_id: int) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT domain, source, added_at FROM org_domains "
                "WHERE org_id = ? ORDER BY source, added_at",
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def add_domain(self, org_id: int, domain: str, source: str = "custom") -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO org_domains (org_id, domain, source, added_at) "
                "VALUES (?, ?, ?, ?)",
                (org_id, domain, source, _now()),
            )

    def remove_domain(self, org_id: int, domain: str) -> bool:
        """Only user-added domains can be removed; Google-synced ones are
        managed by the Workspace connection."""
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM org_domains WHERE org_id = ? AND domain = ? AND source = 'custom'",
                (org_id, domain),
            )
        return cur.rowcount > 0

    def sync_google_domains(self, org_id: int, domains: list[str]) -> None:
        """Replace the Google-sourced domain rows with the current
        directory list (called after each real-mode scan)."""
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM org_domains WHERE org_id = ? AND source = 'google'", (org_id,)
            )
            now = _now()
            conn.executemany(
                "INSERT OR IGNORE INTO org_domains (org_id, domain, source, added_at) "
                "VALUES (?, ?, 'google', ?)",
                [(org_id, domain, now) for domain in domains],
            )

    # ------------------------------------------------------------ scans

    def insert_scan(
        self,
        org_id: int,
        score: int | None,
        counts: dict,
        findings: list[dict],
        manual_checks: list[dict],
        engine_version: str = "",
        result: dict | None = None,
    ) -> dict:
        now = _now()
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO scans (org_id, created_at, score, counts_json, findings_json,
                                   manual_json, engine_version, result_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    org_id,
                    now,
                    score,
                    json.dumps(counts),
                    json.dumps(findings),
                    json.dumps(manual_checks),
                    engine_version,
                    json.dumps(result or {}),
                ),
            )
            scan_id = cur.lastrowid
        scan = self.get_scan(scan_id)
        assert scan is not None
        return scan

    def get_scan(self, scan_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return self._scan_row(row) if row else None

    def latest_scans(self, org_id: int, limit: int = 2) -> list[dict]:
        """Newest first."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scans WHERE org_id = ? ORDER BY created_at DESC, id DESC LIMIT ?",
                (org_id, limit),
            ).fetchall()
        return [self._scan_row(r) for r in rows]

    def scan_before(self, org_id: int, scan_id: int) -> dict | None:
        """The scan immediately BEFORE this one, or None if it is the first.

        Asked of the database rather than derived from a page of recent scans:
        the delta used to take "the newest scan that is not the one on screen",
        which for anything other than the very latest row picks a LATER scan as
        the earlier one. That is how a report comparing two different check
        sets kept printing "no changes" — the row it compared against was from
        the future and happened to share an engine.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE org_id = ? AND id < ? "
                "ORDER BY created_at DESC, id DESC LIMIT 1",
                (org_id, scan_id),
            ).fetchone()
        return self._scan_row(row) if row else None

    #: How far back the regression detector can see. Ten scans is two and a half
    #: months on a weekly schedule, so a control fixed in spring and broken again
    #: in summer came back as a plain new finding rather than a regression —
    #: which is the one label that says "you already fixed this once".
    #: A year of weekly scans is the memory the feature was written to have.
    REGRESSION_MEMORY = 60

    # ------------------------------------------------- accumulated OAuth grants

    def get_oauth_grants(self, org_id: int) -> dict:
        """{"grants": {...}, "watermark": iso, "oldest": iso} — empty on first
        use, which is how the caller knows to do the initial sweep."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT grants_json, watermark, oldest FROM oauth_grants WHERE org_id = ?",
                (org_id,),
            ).fetchone()
        if row is None:
            return {"grants": {}, "watermark": "", "oldest": ""}
        return {
            "grants": json.loads(row["grants_json"] or "{}"),
            "watermark": row["watermark"] or "",
            "oldest": row["oldest"] or "",
        }

    def save_oauth_grants(
        self, org_id: int, grants: dict, watermark: str, oldest: str
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO oauth_grants (org_id, grants_json, watermark, oldest, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(org_id) DO UPDATE SET
                    grants_json = excluded.grants_json,
                    watermark   = excluded.watermark,
                    -- never move the earliest event forward: the accumulated
                    -- window only ever grows.
                    oldest      = CASE
                        WHEN oauth_grants.oldest = '' THEN excluded.oldest
                        WHEN excluded.oldest = '' THEN oauth_grants.oldest
                        WHEN excluded.oldest < oauth_grants.oldest THEN excluded.oldest
                        ELSE oauth_grants.oldest END,
                    updated_at  = excluded.updated_at
                """,
                (org_id, json.dumps(grants), watermark, oldest, _now()),
            )

    def findings_history(
        self, org_id: int, limit: int = REGRESSION_MEMORY
    ) -> list[list[dict]]:
        """Findings of the most recent scans, newest first — used to spot a
        finding that was fixed and has come back (a regression)."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT findings_json FROM scans WHERE org_id = ? "
                "ORDER BY created_at DESC, id DESC LIMIT ?",
                (org_id, limit),
            ).fetchall()
        history = []
        for row in rows:
            try:
                history.append(json.loads(row["findings_json"]))
            except ValueError:
                history.append([])
        return history

    def scan_history(self, org_id: int, limit: int | None = None) -> list[dict]:
        """Oldest first, without findings payloads (for the trend chart)."""
        query = (
            "SELECT id, created_at, score, counts_json, engine_version FROM scans "
            "WHERE org_id = ? ORDER BY created_at DESC, id DESC"
        )
        params: tuple = (org_id,)
        if limit is not None:
            query += " LIMIT ?"
            params = (org_id, limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        history = [
            {
                "id": r["id"],
                "created_at": r["created_at"],
                "score": r["score"],
                "counts": json.loads(r["counts_json"]),
                "engine_version": (
                    r["engine_version"] if "engine_version" in r.keys() else ""
                ),
            }
            for r in rows
        ]
        history.reverse()
        return history

    # ------------------------------------------------------------ outreach

    def login_addresses(self) -> list[dict]:
        """Addresses people use with Vigía: the account that connected the
        organization, plus its alert address when it differs."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT primary_domain, admin_email, alert_email FROM orgs ORDER BY primary_domain"
            ).fetchall()
        seen: dict[str, dict] = {}
        for row in rows:
            for kind, address in (("login", row["admin_email"]), ("alertas", row["alert_email"])):
                address = (address or "").strip()
                if not address or address in seen:
                    continue
                seen[address] = {
                    "email": address,
                    "org": row["primary_domain"],
                    "kind": kind,
                }
        return list(seen.values())

    def log_outreach(
        self,
        *,
        domains: list[str],
        recipient: str,
        subject: str,
        problems: int,
        ok: bool,
        error: str = "",
        body: str = "",
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO outreach_sends
                       (created_at, domains, recipient, subject, problems, ok, error, body)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (_now(), ",".join(domains), recipient, subject, problems,
                 1 if ok else 0, error, body),
            )

    def outreach_history(self, limit: int = 50) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT id, created_at, domains, recipient, subject, problems, ok, error
                     FROM outreach_sends ORDER BY created_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [
            {
                "id": r["id"],
                "created_at": r["created_at"],
                "domains": r["domains"].split(",") if r["domains"] else [],
                "recipient": r["recipient"],
                "subject": r["subject"],
                "problems": r["problems"],
                "ok": bool(r["ok"]),
                "error": r["error"],
            }
            for r in rows
        ]

    def outreach_sent_since(self, recipient: str, since_iso: str) -> list[dict]:
        """Successful sends to this address since a timestamp — the guard
        against contacting the same person twice."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT created_at, domains FROM outreach_sends
                    WHERE recipient = ? AND ok = 1 AND created_at >= ?
                    ORDER BY created_at DESC""",
                (recipient, since_iso),
            ).fetchall()
        return [{"created_at": r["created_at"], "domains": r["domains"]} for r in rows]

    # ----------------------------------------------------------- retention

    def scans_older_than(self, cutoff_iso: str) -> list[tuple[int, str]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, findings_json FROM scans WHERE created_at < ?", (cutoff_iso,)
            ).fetchall()
        return [(r["id"], r["findings_json"]) for r in rows]

    def update_scan_findings(self, scan_id: int, findings: list[dict]) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE scans SET findings_json = ? WHERE id = ?",
                (json.dumps(findings, ensure_ascii=False), scan_id),
            )

    def purge_outreach_bodies(self, cutoff_iso: str) -> int:
        """Drop the stored message text. `recipient` deliberately survives:
        it is what stops the same person being written to twice."""
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE outreach_sends SET body = '' WHERE body != '' AND created_at < ?",
                (cutoff_iso,),
            )
            return cursor.rowcount or 0

    @staticmethod
    def _scan_row(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "org_id": row["org_id"],
            "created_at": row["created_at"],
            "score": row["score"],
            "counts": json.loads(row["counts_json"]),
            "findings": json.loads(row["findings_json"]),
            "manual_checks": json.loads(row["manual_json"]),
            "engine_version": (
                row["engine_version"] if "engine_version" in row.keys() else ""
            ),
            # Empty for scans stored before the column existed; the read paths
            # fall back to re-deriving for those and only for those.
            "result": (
                json.loads(row["result_json"] or "{}")
                if "result_json" in row.keys()
                else {}
            ),
        }
