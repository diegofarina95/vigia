"""Sending. Slowly, one at a time, and never without checking again.

Three ideas run through this module:

**The last check is the one that counts.** Everything the queue verified is
verified again here, immediately before the socket opens. Not because the queue is
unreliable, but because time passes between approval and sending: somebody can
unsubscribe in that window, and a suppression that arrives after approval must
still be honoured. `pre_send_checks` is the only way to a `sendmail` call.

**Slow is the feature.** A cold domain that sends 200 messages on its first day
gets listed, and then the operator's ordinary business mail — invoices, replies to
customers — starts landing in spam too. The warm-up ramp and the randomised delay
are not politeness, they are what keeps the asset alive.

**A hard bounce is a fact about an address.** It gets suppressed automatically,
because continuing to send to an address the receiver has told us does not exist
is the single strongest signal that a list was not consented to.
"""
from __future__ import annotations

import logging
import random
import re
import smtplib
import sqlite3
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from typing import Callable, Protocol

from .addresses import classify_address
from .config import Settings
from .db import is_suppressed, now, suppress, transaction

log = logging.getLogger("prospector.sender")


class SmtpPort(Protocol):
    """What sending needs. A protocol so tests never open a socket."""

    def send(self, message: EmailMessage) -> None:
        ...


class SmtpError(RuntimeError):
    """Base for send failures."""


class TransientSmtpError(SmtpError):
    """Worth retrying: a 4xx, a dropped connection, a timeout."""


class PermanentSmtpError(SmtpError):
    """Not worth retrying: a 5xx. Logged and hard-failed."""


@dataclass
class SendOutcome:
    send_id: int
    sent: bool
    blocked: str | None = None
    error: str | None = None
    attempts: int = 0


# --------------------------------------------------------------------------- #
# How many may go out today.
# --------------------------------------------------------------------------- #


def sent_today(conn: sqlite3.Connection, today: date | None = None) -> int:
    dia = (today or datetime.now(timezone.utc).date()).isoformat()
    fila = conn.execute(
        "SELECT COUNT(*) AS n FROM sends WHERE status = 'sent' AND substr(sent_at,1,10) = ?",
        (dia,),
    ).fetchone()
    return int(fila["n"])


def first_send_date(conn: sqlite3.Connection) -> date | None:
    fila = conn.execute(
        "SELECT substr(MIN(sent_at),1,10) AS d FROM sends WHERE status = 'sent'"
    ).fetchone()
    return date.fromisoformat(fila["d"]) if fila and fila["d"] else None


def daily_allowance(
    settings: Settings, conn: sqlite3.Connection, today: date | None = None
) -> int:
    """How many messages may leave today, warm-up included.

    Day 1-2: 5. Day 3-4: 10. And so on to the cap. The ramp is measured from the
    first message ever sent, not from the first of the campaign: reputation belongs
    to the domain, and starting a second campaign does not make the domain cold
    again — nor does it reset the right to blast.
    """
    if not settings.warmup_enabled:
        return settings.daily_cap
    inicio = first_send_date(conn)
    if inicio is None:
        return min(settings.warmup_start, settings.daily_cap)
    dias = ((today or datetime.now(timezone.utc).date()) - inicio).days
    escalones = max(0, dias) // max(1, settings.warmup_step_days)
    permitido = settings.warmup_start + settings.warmup_step * escalones
    return max(1, min(permitido, settings.daily_cap))


def remaining_today(
    settings: Settings, conn: sqlite3.Connection, today: date | None = None
) -> int:
    return max(0, daily_allowance(settings, conn, today) - sent_today(conn, today))


# --------------------------------------------------------------------------- #
# The checks. Every one of them, every time, with no exceptions.
# --------------------------------------------------------------------------- #


def pre_send_checks(
    conn: sqlite3.Connection, send_id: int, settings: Settings
) -> str | None:
    """Returns a blocking reason, or None if this message may go out.

    Deliberately re-derives everything from the database rather than trusting what
    the caller passes. A checklist that reads its inputs from the thing being
    checked is not a checklist.
    """
    fila = conn.execute(
        "SELECT s.*, c.email, c.is_valid, p.domain, p.id AS prospect_id "
        "FROM sends s JOIN contacts c ON c.id = s.contact_id "
        "JOIN prospects p ON p.id = c.prospect_id WHERE s.id = ?",
        (send_id,),
    ).fetchone()
    if fila is None:
        return "no existe el envío"
    if fila["status"] != "approved":
        return f"no está aprobado (estado {fila['status']})"

    # Suppression, again. This is the check that exists because of the gap between
    # approval and sending: somebody can unsubscribe in that window.
    if is_suppressed(conn, domain=fila["domain"], email=fila["email"]):
        return "suprimido"

    if not fila["is_valid"] or not classify_address(fila["email"]).is_valid:
        return "la dirección no es una dirección de función"

    if not fila["unsubscribe_token"]:
        return "sin token de baja"
    if fila["unsubscribe_token"] not in (fila["body"] or ""):
        return "el cuerpo no contiene el enlace de baja"

    faltan = settings.sender.missing()
    if faltan:
        return f"faltan datos del remitente: {', '.join(faltan)}"
    # A stand-in NIF gets a console you can explore. It must never get a letter
    # out: identifying the sender falsely is worse than not identifying them,
    # because it looks deliberate. The console starts on placeholders; sending
    # does not.
    marcadores = settings.sender.placeholders()
    if marcadores:
        return (
            f"los datos del remitente son de relleno ({', '.join(marcadores)}): "
            "pon el NIF y la dirección reales antes de enviar nada"
        )
    if settings.sender.postal_address not in fila["body"] and \
            settings.sender.company_number not in fila["body"]:
        return "el cuerpo no identifica al remitente"

    if "{" in fila["body"] and re.search(r"\{[a-z_]+\}", fila["body"]):
        return "la carta tiene marcadores sin rellenar"
    if not (fila["subject"] or "").strip():
        return "sin asunto"

    ya = conn.execute(
        "SELECT 1 FROM sends s JOIN contacts c ON c.id = s.contact_id "
        "WHERE c.prospect_id = ? AND s.status = 'sent' AND s.id != ? LIMIT 1",
        (fila["prospect_id"], send_id),
    ).fetchone()
    if ya is not None:
        return "ya se le escribió una vez"
    return None


# --------------------------------------------------------------------------- #
# The transport.
# --------------------------------------------------------------------------- #


class SmtpTransport:
    """smtplib, with the failure classes separated.

    A 4xx is the receiver saying "not now"; a 5xx is "not ever". Retrying a 5xx is
    how a sender turns one rejection into a pattern of rejections, which is what
    reputation systems measure.
    """

    def __init__(self, settings: Settings) -> None:
        self._s = settings

    def send(self, message: EmailMessage) -> None:
        s = self._s
        try:
            if s.smtp_port == 465:
                servidor = smtplib.SMTP_SSL(s.smtp_host, s.smtp_port, timeout=30)
            else:
                servidor = smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=30)
            with servidor:
                servidor.ehlo()
                if s.smtp_starttls and s.smtp_port != 465:
                    servidor.starttls()
                    servidor.ehlo()
                if s.smtp_user:
                    servidor.login(s.smtp_user, s.smtp_password)
                servidor.send_message(message)
        except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused,
                smtplib.SMTPDataError) as exc:
            codigo = getattr(exc, "smtp_code", 0) or 0
            if 400 <= codigo < 500:
                raise TransientSmtpError(str(exc)) from exc
            raise PermanentSmtpError(str(exc)) from exc
        except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError, OSError) as exc:
            raise TransientSmtpError(str(exc)) from exc
        except smtplib.SMTPException as exc:
            raise PermanentSmtpError(str(exc)) from exc


def build_message(fila: sqlite3.Row, settings: Settings) -> EmailMessage:
    """The MIME message. Plain text, and a `List-Unsubscribe` header.

    Plain text on purpose: an HTML message from a stranger about their email
    security, carrying remote images, is exactly the shape of the thing it is
    warning about. It also cannot carry a tracking pixel, which is the point.
    """
    mensaje = EmailMessage()
    mensaje["From"] = formataddr((settings.sender.name, settings.sender.email))
    mensaje["To"] = fila["email"]
    mensaje["Subject"] = fila["subject"]
    mensaje["Reply-To"] = settings.sender.reply_to or settings.sender.email
    mensaje["Message-ID"] = make_msgid()
    mensaje["Date"] = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    url = f"{settings.unsubscribe_base_url.rstrip('/')}/{fila['unsubscribe_token']}"
    # Both headers: the mail client's own unsubscribe button is more likely to be
    # used than a link at the bottom, and a message that offers it is treated more
    # kindly by receivers than one that does not.
    mensaje["List-Unsubscribe"] = f"<{url}>"
    mensaje["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
    mensaje["Auto-Submitted"] = "no"
    mensaje.set_content(fila["body"])
    return mensaje


def send_one(
    conn: sqlite3.Connection,
    send_id: int,
    settings: Settings,
    transport: SmtpPort,
    *,
    max_attempts: int = 3,
    sleep: Callable[[float], None] = time.sleep,
) -> SendOutcome:
    """Check, send, record. The only path to an outgoing message."""
    motivo = pre_send_checks(conn, send_id, settings)
    if motivo is not None:
        with transaction(conn):
            conn.execute(
                "UPDATE sends SET status = 'blocked', blocked_reason = ? WHERE id = ?",
                (motivo, send_id),
            )
        log.warning("envio bloqueado id=%s motivo=%s", send_id, motivo)
        return SendOutcome(send_id, False, blocked=motivo)

    fila = conn.execute(
        "SELECT s.*, c.email FROM sends s JOIN contacts c ON c.id = s.contact_id "
        "WHERE s.id = ?", (send_id,)
    ).fetchone()
    mensaje = build_message(fila, settings)

    ultimo = ""
    for intento in range(1, max_attempts + 1):
        try:
            transport.send(mensaje)
        except TransientSmtpError as exc:
            ultimo = str(exc)
            log.warning("fallo transitorio id=%s intento=%s error=%s", send_id, intento, exc)
            if intento < max_attempts:
                sleep(min(60, 5 * 2 ** (intento - 1)))
                continue
        except PermanentSmtpError as exc:
            with transaction(conn):
                conn.execute(
                    "UPDATE sends SET status = 'failed', error = ? WHERE id = ?",
                    (str(exc), send_id),
                )
            log.error("fallo permanente id=%s error=%s", send_id, exc)
            return SendOutcome(send_id, False, error=str(exc), attempts=intento)
        else:
            with transaction(conn):
                conn.execute(
                    "UPDATE sends SET status = 'sent', sent_at = ?, error = NULL WHERE id = ?",
                    (now(), send_id),
                )
                conn.execute(
                    "UPDATE prospects SET status = 'contacted' WHERE id = "
                    "(SELECT prospect_id FROM contacts WHERE id = ?)",
                    (fila["contact_id"],),
                )
            log.info("enviado id=%s destinatario=%s intento=%s", send_id, fila["email"], intento)
            return SendOutcome(send_id, True, attempts=intento)

    with transaction(conn):
        conn.execute(
            "UPDATE sends SET status = 'failed', error = ? WHERE id = ?", (ultimo, send_id)
        )
    return SendOutcome(send_id, False, error=ultimo, attempts=max_attempts)


def run_queue(
    conn: sqlite3.Connection,
    settings: Settings,
    transport: SmtpPort,
    *,
    limit: int | None = None,
    sleep: Callable[[float], None] = time.sleep,
    rng: random.Random | None = None,
    progress: Callable[[SendOutcome], None] | None = None,
) -> list[SendOutcome]:
    """Send approved messages, respecting today's allowance and the delay.

    The delay goes *between* messages and is randomised: a fixed interval is as
    recognisable as no interval at all. Nothing is sent that was not approved, and
    the allowance is recomputed as it goes, so a bounce-driven stop takes effect
    within the same run.
    """
    rng = rng or random.Random()
    disponibles = remaining_today(settings, conn)
    if limit is not None:
        disponibles = min(disponibles, limit)
    if disponibles <= 0:
        log.info("cupo diario agotado: no se envía nada")
        return []

    filas = list(
        conn.execute(
            "SELECT id FROM sends WHERE status = 'approved' ORDER BY approved_at, id LIMIT ?",
            (disponibles,),
        )
    )
    resultados: list[SendOutcome] = []
    for indice, fila in enumerate(filas):
        if indice:
            sleep(rng.uniform(settings.min_delay_seconds, settings.max_delay_seconds))
        resultado = send_one(conn, int(fila["id"]), settings, transport, sleep=sleep)
        resultados.append(resultado)
        if progress is not None:
            progress(resultado)
    enviados = sum(1 for r in resultados if r.sent)
    log.info("tanda terminada enviados=%s de=%s", enviados, len(filas))
    return resultados


# --------------------------------------------------------------------------- #
# Bounces.
# --------------------------------------------------------------------------- #

#: A 5.x.x enhanced status code, or a bare 5xx, means the address does not exist
#: or refuses mail permanently. 4.x.x is a temporary condition.
_HARD = re.compile(r"\b5\.\d\.\d\b|\bstatus:\s*5\.|\b55\d\b")
_SOFT = re.compile(r"\b4\.\d\.\d\b|\bstatus:\s*4\.|\b45\d\b")
_ADDRESS = re.compile(r"[\w.+-]+@[\w.-]+\.\w{2,}")


@dataclass(frozen=True)
class Bounce:
    address: str
    hard: bool
    detail: str


def parse_bounce(raw: str) -> Bounce | None:
    """Pull the address and the severity out of a bounce message.

    Deliberately crude — it reads the text a human would read. Anything it cannot
    classify comes back as a *soft* bounce, because auto-suppressing on a message
    we did not understand would silently remove prospects for no reason.
    """
    texto = (raw or "").lower()
    if not texto.strip():
        return None
    direcciones = [
        a for a in _ADDRESS.findall(texto)
        if not a.startswith(("postmaster@", "mailer-daemon@"))
    ]
    if not direcciones:
        return None
    duro = bool(_HARD.search(texto)) and not _SOFT.search(texto)
    return Bounce(address=direcciones[0], hard=duro, detail=raw.strip()[:500])


def record_bounce(conn: sqlite3.Connection, raw: str) -> Bounce | None:
    """Log a bounce and, if it is hard, suppress the address permanently."""
    rebote = parse_bounce(raw)
    if rebote is None:
        return None

    fila = conn.execute(
        "SELECT s.id FROM sends s JOIN contacts c ON c.id = s.contact_id "
        "WHERE c.email = ? AND s.status = 'sent' ORDER BY s.sent_at DESC LIMIT 1",
        (rebote.address,),
    ).fetchone()
    if fila is not None:
        with transaction(conn):
            conn.execute(
                "INSERT INTO replies (send_id, received_at, classification, notes) "
                "VALUES (?,?,'bounce',?)",
                (fila["id"], now(), ("duro: " if rebote.hard else "blando: ") + rebote.detail),
            )
    if rebote.hard:
        suppress(conn, email=rebote.address, reason="rebote duro")
        log.info("rebote duro suprimido=%s", rebote.address)
    else:
        log.info("rebote blando dirección=%s", rebote.address)
    return rebote


def bounce_rate(conn: sqlite3.Connection, days: int = 30) -> float:
    """Bounces over messages sent, in the last N days. Above a few per cent, stop."""
    desde = (datetime.now(timezone.utc) - timedelta(days=days)).date().isoformat()
    enviados = conn.execute(
        "SELECT COUNT(*) AS n FROM sends WHERE status='sent' AND substr(sent_at,1,10) >= ?",
        (desde,),
    ).fetchone()["n"]
    if not enviados:
        return 0.0
    rebotes = conn.execute(
        "SELECT COUNT(*) AS n FROM replies WHERE classification='bounce' "
        "AND substr(received_at,1,10) >= ?", (desde,),
    ).fetchone()["n"]
    return rebotes / enviados
