"""Shared helpers for checks."""
from __future__ import annotations

from ..wording import con_numero

from datetime import datetime, timezone

# Directory API reports this for users who have never signed in.
NEVER_LOGGED_IN = "1970-01-01T00:00:00.000Z"

MAX_LISTED = 50  # cap affected_items so payloads stay small


def parse_google_time(value: str | None) -> datetime | None:
    if not value or value == NEVER_LOGGED_IN:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def cap_items(items: list[str]) -> list[str]:
    if len(items) <= MAX_LISTED:
        return items
    return items[:MAX_LISTED] + [f"… y {len(items) - MAX_LISTED} más"]


def is_active(user: dict) -> bool:
    return not user.get("suspended") and not user.get("archived")


def window_label(ctx, source: str, noun: str) -> str:
    """"registro de auditoría de administración (178 días leídos)".

    A scope label written by hand is a promise nobody checks. `check_audit_log`
    said "~180 días" while reading at most three pages, and `check_oauth_apps`
    said the same while covering two. The number now comes from the coverage
    the client measured, so the label cannot outlive the read that produced it.
    """
    prefijo = f"{noun} " if noun else ""
    cobertura = (getattr(ctx, "coverage", {}) or {}).get(source)
    if cobertura is None:
        return f"{prefijo}ventana sin medir".strip()
    dias = cobertura.window_days
    if dias is None:
        return f"{prefijo}{cobertura.records} eventos leídos".strip()
    if not cobertura.complete:
        return f"{prefijo}solo {con_numero(dias, 'día')} leídos: la fuente vino incompleta".strip()
    return f"{prefijo}{con_numero(dias, 'día')} leídos, {cobertura.records} eventos".strip()
