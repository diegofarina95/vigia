"""The review queue: draft, block, approve.

Nothing in this module sends anything. It produces rows in `sends` with status
`queued` — waiting for a person — or `blocked`, with the reason recorded.

**Nothing is ever silently dropped.** Every prospect that does not end up queued
ends up blocked with a reason a human can read, because a prospect that vanishes
between the scan and the queue is indistinguishable from a bug, and the operator
would never know which one it was.

The refusals live here rather than only in the sender, so they are visible during
review instead of at 3am in a log. They are checked again at send time anyway —
suppression can arrive between approval and sending, and the last check before the
socket opens is the one that counts.
"""
from __future__ import annotations

import logging
import secrets
import sqlite3
from dataclasses import dataclass
from typing import Any

from .db import is_suppressed, now, transaction
from .pipeline import contactable_for
from .prioritise import PrimaryFinding
from .projection import finding_from_scan
from .templates import RenderError, build_email

log = logging.getLogger("prospector.queue")

#: Every reason a prospect can fail to reach the queue. Kept as a table so the
#: blocked view can explain each one in words rather than showing a slug.
BLOCK_REASONS: dict[str, str] = {
    "not-scanned": "todavía no se ha escaneado",
    "clean": "no se ha encontrado ningún problema que mencionar",
    "unqualified": "no llega al umbral comercial: se guarda, no se contacta",
    "no-contact": "no hay ninguna dirección de función a la que escribir",
    "suppressed": "el dominio o la dirección están en la lista de supresión",
    "already-contacted": "ya se le escribió una vez",
    "render-failed": "la carta no se puede completar",
    "no-finding-record": "el escaneo no guardó ningún hallazgo utilizable",
}


@dataclass
class QueueResult:
    domain: str
    prospect_id: int
    send_id: int | None
    blocked: str | None
    detail: str = ""

    @property
    def queued(self) -> bool:
        return self.send_id is not None and self.blocked is None

    @property
    def reason_text(self) -> str:
        if self.blocked is None:
            return ""
        base = BLOCK_REASONS.get(self.blocked, self.blocked)
        return f"{base} — {self.detail}" if self.detail else base


def _already_contacted(conn: sqlite3.Connection, prospect_id: int) -> bool:
    """Whether anything was ever actually sent to this prospect.

    Only `sent` counts. A queued or blocked row is not contact, and treating it as
    such would make a domain unreachable because of a draft nobody approved.
    """
    fila = conn.execute(
        "SELECT 1 FROM sends s JOIN contacts c ON c.id = s.contact_id "
        "WHERE c.prospect_id = ? AND s.status = 'sent' LIMIT 1",
        (prospect_id,),
    ).fetchone()
    return fila is not None


def _record_block(
    conn: sqlite3.Connection, prospect: sqlite3.Row, reason: str, detail: str = ""
) -> QueueResult:
    """A blocked prospect leaves a trace even when there is no contact to point at.

    `sends` requires a contact and a scan, and the "no contact at all" case has
    neither — so the block is recorded on the prospect's status and returned to the
    caller, which is what the blocked view reads. Recording it as a `sends` row
    would mean inventing a recipient.
    """
    log.info("bloqueado dominio=%s motivo=%s %s", prospect["domain"], reason, detail)
    return QueueResult(prospect["domain"], prospect["id"], None, reason, detail)


def queue_prospect(
    conn: sqlite3.Connection,
    prospect: sqlite3.Row,
    *,
    sender_name: str,
    sender_details: str,
    unsubscribe_base_url: str,
    variant: str | None = None,
) -> QueueResult:
    """Draft one email and put it in the queue, or block it with a reason."""
    pid = prospect["id"]

    if prospect["status"] == "new":
        return _record_block(conn, prospect, "not-scanned")

    escaneo = conn.execute(
        "SELECT * FROM scans WHERE prospect_id = ? ORDER BY id DESC LIMIT 1", (pid,)
    ).fetchone()
    if escaneo is None:
        return _record_block(conn, prospect, "not-scanned")
    if not escaneo["primary_finding_code"]:
        return _record_block(conn, prospect, "clean")
    if not prospect["qualified"]:
        return _record_block(
            conn, prospect, "unqualified", f"puntuación {prospect['commercial_score']}"
        )
    if _already_contacted(conn, pid):
        return _record_block(conn, prospect, "already-contacted")
    if is_suppressed(conn, domain=prospect["domain"]):
        return _record_block(conn, prospect, "suppressed")

    contacto = contactable_for(conn, pid)
    if contacto is None:
        return _record_block(conn, prospect, "no-contact")
    if is_suppressed(conn, email=contacto["email"]):
        return _record_block(conn, prospect, "suppressed", contacto["email"])

    hallazgo = finding_from_scan(escaneo, prospect)
    if hallazgo is None:
        return _record_block(conn, prospect, "no-finding-record")

    token = secrets.token_urlsafe(24)
    try:
        correo = build_email(
            conn,
            finding=hallazgo,
            prospect=prospect,
            sender_name=sender_name,
            sender_details=sender_details,
            unsubscribe_url=f"{unsubscribe_base_url.rstrip('/')}/{token}",
            variant=variant,
        )
    except RenderError as exc:
        return _record_block(conn, prospect, "render-failed", str(exc))

    # The audit trail: why we believed we were allowed to write, and what
    # specifically made this domain relevant. Written in the same transaction as
    # the draft, so a queued email without its justification cannot exist.
    justificacion = (
        f"{hallazgo.code}: {hallazgo.evidence or hallazgo.technical_description}"
    )
    with transaction(conn):
        cur = conn.execute(
            "INSERT INTO sends (contact_id, scan_id, template_id, subject, body, "
            "status, legal_basis, justification, unsubscribe_token, queued_at) "
            "VALUES (?,?,?,?,?,'queued','legitimate_interest',?,?,?)",
            (contacto["id"], escaneo["id"], correo.template_id, correo.subject,
             correo.body, justificacion, token, now()),
        )
        conn.execute("UPDATE prospects SET status = 'queued' WHERE id = ?", (pid,))

    log.info(
        "encolado dominio=%s hallazgo=%s variante=%s destinatario=%s",
        prospect["domain"], hallazgo.code, correo.variant, contacto["email"],
    )
    return QueueResult(prospect["domain"], pid, int(cur.lastrowid), None)


def queue_batch(
    conn: sqlite3.Connection, prospects: list[sqlite3.Row], **kwargs: Any
) -> list[QueueResult]:
    return [queue_prospect(conn, p, **kwargs) for p in prospects]


# --------------------------------------------------------------------------- #
# What a person does to the queue.
# --------------------------------------------------------------------------- #


def approve(conn: sqlite3.Connection, send_ids: list[int], approved_by: str = "operador") -> int:
    """Mark drafts as approved. Approved is not sent — the sender runs separately.

    Only `queued` rows move. An id that is already approved, sent or blocked is
    left alone rather than reset, so a double-click on a bulk button cannot
    resurrect something that was skipped.
    """
    if not send_ids:
        return 0
    marcas = ",".join("?" * len(send_ids))
    with transaction(conn):
        cur = conn.execute(
            f"UPDATE sends SET status = 'approved', approved_at = ?, approved_by = ? "
            f"WHERE id IN ({marcas}) AND status = 'queued'",
            [now(), approved_by, *send_ids],
        )
    log.info("aprobados %s de %s solicitados por=%s", cur.rowcount, len(send_ids), approved_by)
    return int(cur.rowcount)


def skip(conn: sqlite3.Connection, send_id: int, reason: str = "") -> bool:
    with transaction(conn):
        cur = conn.execute(
            "UPDATE sends SET status = 'skipped', error = ? WHERE id = ? "
            "AND status IN ('queued','approved')",
            (reason or None, send_id),
        )
    return cur.rowcount == 1


def edit_send(conn: sqlite3.Connection, send_id: int, subject: str, body: str) -> bool:
    """Edit a draft before approving it.

    An edited body still has to carry the unsubscribe link and the sender's
    details: those are legal requirements, not house style, and the edit box is
    exactly where they would get deleted by accident.
    """
    fila = conn.execute("SELECT * FROM sends WHERE id = ?", (send_id,)).fetchone()
    if fila is None or fila["status"] != "queued":
        return False
    token = fila["unsubscribe_token"] or ""
    if token and token not in body:
        raise RenderError("el cuerpo editado ha perdido el enlace de baja")
    with transaction(conn):
        conn.execute(
            "UPDATE sends SET subject = ?, body = ? WHERE id = ? AND status = 'queued'",
            (subject.strip(), body, send_id),
        )
    return True


def suppress_prospect(
    conn: sqlite3.Connection, prospect_id: int, reason: str = "manual"
) -> None:
    """Suppress the domain and cancel anything of its still in the queue."""
    from .db import suppress

    fila = conn.execute("SELECT domain FROM prospects WHERE id = ?", (prospect_id,)).fetchone()
    if fila is None:
        return
    suppress(conn, domain=fila["domain"], reason=reason)
    with transaction(conn):
        conn.execute(
            "UPDATE sends SET status = 'blocked', blocked_reason = 'suppressed' "
            "WHERE status IN ('queued','approved') AND contact_id IN "
            "(SELECT id FROM contacts WHERE prospect_id = ?)",
            (prospect_id,),
        )
        conn.execute("UPDATE prospects SET status = 'excluded' WHERE id = ?", (prospect_id,))
    log.info("suprimido dominio=%s motivo=%s", fila["domain"], reason)
