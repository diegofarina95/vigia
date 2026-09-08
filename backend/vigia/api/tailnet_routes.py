"""The private outreach console. Reachable only from the tailnet.

Kept out of the React bundle on purpose: the public site ships no route, no
component and no string for this, so the tool is not discoverable from the
internet even before the `tailnet_only` guard refuses the request.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request

from .. import dns_email_auth, outreach
from ..config import Settings
from ..notify import NotifyError, send_email, smtp_configured
from ..tailnet import is_tailnet_request, tailnet_only
from .routes import get_db, get_settings

log = logging.getLogger(__name__)

tailnet_bp = Blueprint("tailnet", __name__, url_prefix="/tailnet")

# A single message may cover a handful of domains; anything more is a mailing
# list, which is not what this tool is for.
MAX_DOMAINS = 10
# Do not write to the same person twice inside this window without saying so.
COOLDOWN_DAYS = 14


def _sender(settings: Settings) -> tuple[str, str]:
    """Display name and address, parsed out of VIGIA_SMTP_FROM."""
    raw = (settings.smtp_from or "").strip()
    if "<" in raw and ">" in raw:
        name = raw.split("<", 1)[0].strip().strip('"')
        address = raw.split("<", 1)[1].split(">", 1)[0].strip()
        return name or address, address
    return raw, raw


def _domains_from(payload: dict) -> tuple[list[str], str | None]:
    raw = payload.get("domains")
    if isinstance(raw, str):
        raw = raw.replace(",", "\n").split("\n")
    candidates = [str(d).strip() for d in (raw or []) if str(d).strip()]
    if not candidates:
        return [], "No has puesto ningún dominio."
    if len(candidates) > MAX_DOMAINS:
        return [], f"Máximo {MAX_DOMAINS} dominios por mensaje."

    domains, seen = [], set()
    for candidate in candidates:
        domain = dns_email_auth.normalize_domain(candidate)
        if not domain:
            return [], f"Dominio no válido: {candidate}"
        if domain not in seen:
            seen.add(domain)
            domains.append(domain)
    return domains, None


def _check(domains: list[str], settings: Settings) -> list[dict]:
    return [
        dns_email_auth.check_domain(
            domain, selectors=dns_email_auth.DEFAULT_DKIM_SELECTORS, lang="es"
        )
        for domain in domains
    ]


def _valid_email(address: str) -> bool:
    address = address.strip()
    if len(address) > 254 or address.count("@") != 1:
        return False
    local, _, host = address.partition("@")
    return bool(local) and "." in host and " " not in address and ".." not in host


@tailnet_bp.get("/api/whoami")
def whoami():
    """Deliberately ungated: the page uses it to explain the refusal."""
    allowed, reason = is_tailnet_request()
    return jsonify({"allowed": allowed, "reason": reason, "peer": request.remote_addr})


@tailnet_bp.post("/api/check")
@tailnet_only
def check():
    payload = request.get_json(silent=True) or {}
    domains, error = _domains_from(payload)
    if error:
        return jsonify({"error": "invalid_domains", "message": error}), 400

    reports = _check(domains, get_settings())
    return jsonify(
        {
            "reports": reports,
            "problems": {r["domain"]: outreach.problems(r) for r in reports},
            "summary": outreach.summarize(reports),
        }
    )


@tailnet_bp.get("/api/recipients")
@tailnet_only
def recipients():
    """The addresses people use to sign in to Vigía, offered as recipients."""
    return jsonify({"recipients": get_db().login_addresses()})


@tailnet_bp.post("/api/preview")
@tailnet_only
def preview():
    """Render exactly what would be sent. Nothing leaves the server."""
    payload = request.get_json(silent=True) or {}
    domains, error = _domains_from(payload)
    if error:
        return jsonify({"error": "invalid_domains", "message": error}), 400

    settings = get_settings()
    reports = _check(domains, settings)
    name, address = _sender(settings)
    body = outreach.render_email(
        reports,
        sender_name=str(payload.get("sender_name") or name),
        sender_email=address,
        note=str(payload.get("note") or ""),
    )
    return jsonify(
        {
            "subject": outreach.subject_for(reports),
            "body": body,
            "from": settings.smtp_from,
            "summary": outreach.summarize(reports),
        }
    )


@tailnet_bp.post("/api/send")
@tailnet_only
def send():
    payload = request.get_json(silent=True) or {}
    settings, db = get_settings(), get_db()

    if not smtp_configured(settings):
        return jsonify({"error": "smtp", "message": "El SMTP no está configurado."}), 400

    domains, error = _domains_from(payload)
    if error:
        return jsonify({"error": "invalid_domains", "message": error}), 400

    raw_to = payload.get("to")
    if isinstance(raw_to, str):
        raw_to = raw_to.replace(",", "\n").split("\n")
    destinations, seen = [], set()
    for candidate in [str(t).strip() for t in (raw_to or []) if str(t).strip()]:
        if not _valid_email(candidate):
            return (
                jsonify({"error": "invalid_email", "message": f"Dirección no válida: {candidate}"}),
                400,
            )
        if candidate.lower() not in seen:
            seen.add(candidate.lower())
            destinations.append(candidate)
    if not destinations:
        return jsonify({"error": "no_recipient", "message": "No has puesto destinatario."}), 400

    force = bool(payload.get("force"))
    if not force:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=COOLDOWN_DAYS)).isoformat()
        for destination in destinations:
            previous = db.outreach_sent_since(destination, cutoff)
            if previous:
                return (
                    jsonify(
                        {
                            "error": "cooldown",
                            "message": (
                                f"Ya se escribió a {destination} el "
                                f"{previous[0]['created_at'][:10]} (dominios: "
                                f"{previous[0]['domains']}). Marca «enviar de todas formas» "
                                f"si es intencionado."
                            ),
                        }
                    ),
                    409,
                )

    reports = _check(domains, settings)
    name, address = _sender(settings)
    subject = outreach.subject_for(reports)
    body = outreach.render_email(
        reports,
        sender_name=str(payload.get("sender_name") or name),
        sender_email=address,
        note=str(payload.get("note") or ""),
    )
    counts = outreach.summarize(reports)

    results = []
    for destination in destinations:
        try:
            send_email(settings, destination, subject, body)
        except NotifyError as exc:
            log.warning("outreach a %s falló: %s", destination, exc)
            db.log_outreach(
                domains=domains, recipient=destination, subject=subject,
                problems=counts["problems"], ok=False, error=str(exc),
            )
            results.append({"to": destination, "ok": False, "error": str(exc)})
            continue
        db.log_outreach(
            domains=domains, recipient=destination, subject=subject,
            problems=counts["problems"], ok=True, body=body,
        )
        results.append({"to": destination, "ok": True})

    return jsonify({"results": results, "subject": subject, "summary": counts})


@tailnet_bp.get("/api/log")
@tailnet_only
def log_history():
    return jsonify({"sends": get_db().outreach_history(limit=100)})


@tailnet_bp.get("/")
@tailnet_bp.get("")
@tailnet_only
def console():
    from .tailnet_ui import PAGE

    return PAGE, 200, {"Content-Type": "text/html; charset=utf-8"}
