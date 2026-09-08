"""Schema and connection handling. SQLite, no ORM.

Two things are enforced by the database rather than by convention, because both
are promises this module makes to people who never agreed to hear from it:

* **Suppressions cannot be deleted or edited.** Triggers refuse both. "Never
  contacted again, by any campaign, ever" is not a property of the code that
  happens to check a list; it is a property of the list. Application code can be
  refactored around, a trigger cannot.
* **Enumerations are CHECK constraints.** A send whose status is a typo is a send
  nobody will ever look at again, and "never silently dropped" is the whole
  requirement for the blocked view.

Every write goes through `transaction()`, which commits once or rolls back
whole.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .catalog import CATALOG

SCHEMA_VERSION = 2


SCHEMA = """
-- A company we might write to. One row per domain, ever.
CREATE TABLE IF NOT EXISTS prospects (
    id           INTEGER PRIMARY KEY,
    domain       TEXT NOT NULL UNIQUE COLLATE NOCASE,
    company_name TEXT,
    country      TEXT,                       -- ISO-3166-1 alpha-2, picks the language
    sector       TEXT,
    source       TEXT,                       -- where the domain came from; audit trail
    created_at   TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'new'
                 CHECK (status IN ('new','scanned','queued','contacted','replied','excluded')),
    -- Commercial qualification. `qualified` is the gate into the send queue; a
    -- prospect below the threshold stays here, scanned and searchable, and is
    -- simply never contacted. The breakdown is stored because the threshold is a
    -- business judgement that will be tuned, and tuning a single number without
    -- seeing which rules fired is guesswork.
    commercial_score INTEGER,
    score_breakdown  TEXT,
    qualified        INTEGER NOT NULL DEFAULT 0 CHECK (qualified IN (0,1)),
    scored_at        TEXT
);

CREATE TABLE IF NOT EXISTS contacts (
    id           INTEGER PRIMARY KEY,
    prospect_id  INTEGER NOT NULL REFERENCES prospects(id) ON DELETE CASCADE,
    email        TEXT NOT NULL COLLATE NOCASE,
    address_type TEXT NOT NULL CHECK (address_type IN ('role','personal','unknown')),
    -- Whether we may write to it. A personal address is stored with is_valid = 0
    -- rather than discarded: "flag and exclude, don't silently drop" means the
    -- blocked view has to be able to show what was refused and why.
    is_valid     INTEGER NOT NULL DEFAULT 0 CHECK (is_valid IN (0,1)),
    notes        TEXT,
    created_at   TEXT NOT NULL,
    UNIQUE (prospect_id, email)
);

CREATE TABLE IF NOT EXISTS scans (
    id                   INTEGER PRIMARY KEY,
    prospect_id          INTEGER NOT NULL REFERENCES prospects(id) ON DELETE CASCADE,
    scanned_at           TEXT NOT NULL,
    -- The scanner's report, verbatim. The evidence for whatever we claimed, as it
    -- was on the day; re-deriving it later from a re-scan would not be the same
    -- fact, and it is the fact we would have to defend.
    raw_findings         TEXT NOT NULL,
    primary_finding_code TEXT REFERENCES finding_codes(code),
    severity             INTEGER,            -- the commercial rank, 1 = strongest
    all_finding_codes    TEXT NOT NULL DEFAULT '[]',
    deprioritised        INTEGER NOT NULL DEFAULT 0 CHECK (deprioritised IN (0,1))
);

-- The language-independent half: which findings exist, and their commercial rank.
-- It is a table of its own because `findings_catalog` is keyed by (code, lang), so
-- `code` alone is not unique there and nothing could reference it — a scan would
-- have had no way to point at a finding without pointing at a language too.
CREATE TABLE IF NOT EXISTS finding_codes (
    code          TEXT PRIMARY KEY,
    severity_rank INTEGER NOT NULL UNIQUE
);

-- Bilingual: one row per (code, lang). `severity_rank` is repeated here because
-- the brief's schema names it, and a test asserts it agrees with `finding_codes`
-- in both languages.
CREATE TABLE IF NOT EXISTS findings_catalog (
    code                        TEXT NOT NULL REFERENCES finding_codes(code),
    lang                        TEXT NOT NULL CHECK (lang IN ('es','en')),
    severity_rank               INTEGER NOT NULL,
    technical_description       TEXT NOT NULL,
    plain_language_description  TEXT NOT NULL,
    subject_line_template       TEXT NOT NULL,
    opening_line_template       TEXT NOT NULL,
    PRIMARY KEY (code, lang)
);

CREATE TABLE IF NOT EXISTS templates (
    id          INTEGER PRIMARY KEY,
    finding_code TEXT NOT NULL REFERENCES finding_codes(code),
    lang        TEXT NOT NULL CHECK (lang IN ('es','en')),
    variant     TEXT NOT NULL DEFAULT 'A',   -- A/B, so reply rates can be compared
    version     INTEGER NOT NULL DEFAULT 1,
    subject     TEXT NOT NULL,
    body        TEXT NOT NULL,
    is_active   INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0,1)),
    created_at  TEXT NOT NULL,
    UNIQUE (finding_code, lang, variant, version)
);

CREATE TABLE IF NOT EXISTS sends (
    id          INTEGER PRIMARY KEY,
    contact_id  INTEGER NOT NULL REFERENCES contacts(id),
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    template_id INTEGER REFERENCES templates(id),
    subject     TEXT NOT NULL,
    body        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'queued'
                CHECK (status IN ('queued','approved','sent','failed','skipped','blocked')),
    -- The audit trail the brief asks for, per contact per send: why we believed we
    -- were allowed to write, and what specifically made this domain relevant.
    legal_basis      TEXT NOT NULL DEFAULT 'legitimate_interest',
    justification    TEXT NOT NULL DEFAULT '',
    unsubscribe_token TEXT UNIQUE,
    queued_at   TEXT NOT NULL,
    approved_at TEXT,
    approved_by TEXT,
    sent_at     TEXT,
    error       TEXT,
    blocked_reason TEXT
);

-- Permanent. See the triggers below.
CREATE TABLE IF NOT EXISTS suppressions (
    id         INTEGER PRIMARY KEY,
    domain     TEXT COLLATE NOCASE,
    email      TEXT COLLATE NOCASE,
    reason     TEXT NOT NULL,
    created_at TEXT NOT NULL,
    CHECK (domain IS NOT NULL OR email IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS replies (
    id             INTEGER PRIMARY KEY,
    send_id        INTEGER NOT NULL REFERENCES sends(id),
    received_at    TEXT NOT NULL,
    classification TEXT NOT NULL
                   CHECK (classification IN
                          ('interested','not_interested','unsubscribe','bounce','other')),
    notes          TEXT
);

CREATE INDEX IF NOT EXISTS ix_contacts_prospect   ON contacts(prospect_id);
CREATE INDEX IF NOT EXISTS ix_scans_prospect      ON scans(prospect_id);
CREATE INDEX IF NOT EXISTS ix_sends_status        ON sends(status);
CREATE INDEX IF NOT EXISTS ix_sends_contact       ON sends(contact_id);
CREATE INDEX IF NOT EXISTS ix_replies_send        ON replies(send_id);
-- The two lookups done before every single send.
CREATE UNIQUE INDEX IF NOT EXISTS ux_suppress_domain ON suppressions(domain)
    WHERE domain IS NOT NULL AND email IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_suppress_email  ON suppressions(email)
    WHERE email IS NOT NULL;

-- "Never deleted" enforced where it cannot be refactored away.
CREATE TRIGGER IF NOT EXISTS suppressions_are_permanent
BEFORE DELETE ON suppressions
BEGIN
    SELECT RAISE(ABORT, 'suppressions are permanent and cannot be deleted');
END;

CREATE TRIGGER IF NOT EXISTS suppressions_are_immutable
BEFORE UPDATE ON suppressions
BEGIN
    SELECT RAISE(ABORT, 'suppressions are permanent and cannot be edited');
END;
"""


def now() -> str:
    """UTC, ISO-8601. One clock, so timestamps sort and compare."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(path: str | Path) -> sqlite3.Connection:
    """Open the database with the settings this module relies on."""
    conn = sqlite3.connect(str(path), isolation_level=None, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """One unit of work: commits once, or rolls back entirely.

    `isolation_level=None` turns off the driver's implicit transaction handling,
    so BEGIN/COMMIT are explicit and nested use is a visible error rather than a
    silent partial commit.
    """
    conn.execute("BEGIN")
    try:
        yield conn
    except Exception:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def migrate(conn: sqlite3.Connection) -> None:
    """Create or upgrade the schema. Safe to run on every start.

    The schema is the one write that does NOT go through `transaction()`:
    `executescript` issues a COMMIT of its own before it runs, so wrapping it
    would end the transaction under our feet and the closing COMMIT would fail on
    nothing. Every statement is `IF NOT EXISTS`, so a run that dies halfway leaves
    a partial schema that the next run completes. The invariant that every *data*
    write is transactional is unaffected.
    """
    conn.executescript(SCHEMA)
    _add_missing_columns(conn)
    with transaction(conn):
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


#: Columns added after a version shipped. `CREATE TABLE IF NOT EXISTS` does not
#: touch a table that already exists, so a database created before these columns
#: existed would keep its old shape and fail on the first write.
LATER_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("prospects", "commercial_score", "INTEGER"),
    ("prospects", "score_breakdown", "TEXT"),
    ("prospects", "qualified", "INTEGER NOT NULL DEFAULT 0"),
    ("prospects", "scored_at", "TEXT"),
)


def _add_missing_columns(conn: sqlite3.Connection) -> None:
    for tabla, columna, tipo in LATER_COLUMNS:
        existentes = {
            r["name"] for r in conn.execute(f"PRAGMA table_info({tabla})")
        }
        if columna not in existentes:
            conn.execute(f"ALTER TABLE {tabla} ADD COLUMN {columna} {tipo}")


def seed_catalog(conn: sqlite3.Connection) -> int:
    """Load `catalog.CATALOG` into the table, replacing what is there.

    The catalogue is code, not data: it is reviewed in the repository, and the
    table is a projection of it so that queries can join against it. Editing the
    table by hand is not supported and would be overwritten on the next start.
    """
    from .catalog import RULES

    rows = [
        (
            entry.code, entry.lang, entry.severity_rank,
            entry.technical_description, entry.plain_language_description,
            entry.subject_line_template, entry.opening_line_template,
        )
        for entry in CATALOG
    ]
    with transaction(conn):
        conn.executemany(
            "INSERT INTO finding_codes (code, severity_rank) VALUES (?,?) "
            "ON CONFLICT(code) DO UPDATE SET severity_rank = excluded.severity_rank",
            [(rule.code, rule.severity_rank) for rule in RULES],
        )
        conn.executemany(
            "INSERT INTO findings_catalog "
            "(code, lang, severity_rank, technical_description, "
            " plain_language_description, subject_line_template, opening_line_template) "
            "VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT(code, lang) DO UPDATE SET "
            "  severity_rank = excluded.severity_rank,"
            "  technical_description = excluded.technical_description,"
            "  plain_language_description = excluded.plain_language_description,"
            "  subject_line_template = excluded.subject_line_template,"
            "  opening_line_template = excluded.opening_line_template",
            rows,
        )
    return len(rows)


def init(path: str | Path) -> sqlite3.Connection:
    """Open, migrate and seed. The one entry point callers need."""
    conn = connect(path)
    migrate(conn)
    seed_catalog(conn)
    return conn


# --------------------------------------------------------------------------- #
# The suppression list. Checked before every send, without exception.
# --------------------------------------------------------------------------- #


def suppress(
    conn: sqlite3.Connection,
    *,
    reason: str,
    domain: str | None = None,
    email: str | None = None,
) -> None:
    """Add a permanent suppression. Idempotent.

    At least one of `domain` or `email` is required; the CHECK constraint enforces
    it too, so a caller that passes neither fails at the database rather than
    writing a row that suppresses nothing.
    """
    if not domain and not email:
        raise ValueError("una supresión necesita dominio o dirección")
    with transaction(conn):
        conn.execute(
            "INSERT OR IGNORE INTO suppressions (domain, email, reason, created_at) "
            "VALUES (?,?,?,?)",
            (domain.lower() if domain else None,
             email.lower() if email else None,
             reason, now()),
        )


def is_suppressed(
    conn: sqlite3.Connection, *, domain: str | None = None, email: str | None = None
) -> bool:
    """Whether this domain or address may never be contacted.

    A suppressed *domain* suppresses every address at it, including addresses that
    were never seen before: somebody who asks not to be contacted is asking on
    behalf of their organisation, not of one mailbox.
    """
    if email:
        dominio_de_email = email.split("@")[-1].lower()
        row = conn.execute(
            "SELECT 1 FROM suppressions WHERE email = ? OR domain = ? LIMIT 1",
            (email.lower(), dominio_de_email),
        ).fetchone()
        if row:
            return True
    if domain:
        row = conn.execute(
            "SELECT 1 FROM suppressions WHERE domain = ? LIMIT 1", (domain.lower(),)
        ).fetchone()
        if row:
            return True
    return False


# --------------------------------------------------------------------------- #
# Small helpers the later phases build on.
# --------------------------------------------------------------------------- #


def add_prospect(
    conn: sqlite3.Connection,
    *,
    domain: str,
    company_name: str | None = None,
    country: str | None = None,
    sector: str | None = None,
    source: str | None = None,
) -> int:
    """Insert a prospect, or return the existing one's id."""
    with transaction(conn):
        conn.execute(
            "INSERT OR IGNORE INTO prospects "
            "(domain, company_name, country, sector, source, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (domain.lower(), company_name, country, sector, source, now()),
        )
    row = conn.execute(
        "SELECT id FROM prospects WHERE domain = ?", (domain.lower(),)
    ).fetchone()
    return int(row["id"])


def add_contact(
    conn: sqlite3.Connection, prospect_id: int, email: str, notes: str | None = None
) -> int:
    """Insert a contact, classifying it on the way in.

    The classification is stored, not recomputed at send time: what matters in an
    audit is what the system believed when it decided, and a classifier that
    changes later must not rewrite the past.
    """
    from .addresses import classify_address

    verdict = classify_address(email)
    with transaction(conn):
        conn.execute(
            "INSERT OR IGNORE INTO contacts "
            "(prospect_id, email, address_type, is_valid, notes, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (prospect_id, verdict.email, verdict.address_type,
             1 if verdict.is_valid else 0,
             notes or verdict.reason, now()),
        )
    row = conn.execute(
        "SELECT id FROM contacts WHERE prospect_id = ? AND email = ?",
        (prospect_id, verdict.email),
    ).fetchone()
    return int(row["id"])


def record_scan(
    conn: sqlite3.Connection, prospect_id: int, report: dict[str, Any], finding: Any
) -> int:
    """Store a scan and the finding chosen from it.

    `finding` is a `PrimaryFinding` or None. None is stored too — a clean domain is
    a fact worth keeping, and it is what stops the same domain being rescanned and
    re-evaluated every time the list is imported.
    """
    with transaction(conn):
        cur = conn.execute(
            "INSERT INTO scans (prospect_id, scanned_at, raw_findings, "
            "primary_finding_code, severity, all_finding_codes, deprioritised) "
            "VALUES (?,?,?,?,?,?,?)",
            (
                prospect_id, now(), json.dumps(report, ensure_ascii=False),
                getattr(finding, "code", None),
                getattr(finding, "severity_rank", None),
                json.dumps(list(getattr(finding, "all_codes", ()))),
                1 if getattr(finding, "deprioritised", False) else 0,
            ),
        )
        estado = "scanned" if finding else "excluded"
        conn.execute("UPDATE prospects SET status = ? WHERE id = ?", (estado, prospect_id))
    return int(cur.lastrowid)


def record_qualification(conn: sqlite3.Connection, prospect_id: int, score: Any) -> None:
    """Store a commercial score and whether it clears the threshold.

    Storing the verdict as well as the number is deliberate: the threshold is
    configurable, so a row that only kept the score would silently change meaning
    the day somebody edits the setting, and a queue built from it would contact
    domains that were never qualified under the rules in force at the time.
    """
    import json as _json

    with transaction(conn):
        conn.execute(
            "UPDATE prospects SET commercial_score = ?, score_breakdown = ?, "
            "qualified = ?, scored_at = ? WHERE id = ?",
            (
                score.total,
                _json.dumps(score.as_dict(), ensure_ascii=False),
                1 if score.qualified else 0,
                now(),
                prospect_id,
            ),
        )


def qualified_prospects(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """The only prospects that may enter the send queue."""
    return list(
        conn.execute(
            "SELECT * FROM prospects WHERE qualified = 1 AND status = 'scanned' "
            "ORDER BY commercial_score DESC, domain"
        )
    )
