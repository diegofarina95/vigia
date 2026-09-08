"""Scheduled recurring scans.

Runs inside the web process via APScheduler. The app is served by
several gunicorn workers, so every worker would otherwise scan the same
org at the same time — the DB claim below makes the run exclusive:
whichever worker wins the atomic UPDATE does the scan, the others skip.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from .config import Settings
from .delta import alert_worthy, gated_summary
from . import retention
from .notify import (
    NotifyError,
    avisar_empresa_nueva,
    scan_alert_body,
    send_email,
    smtp_configured,
)
from .scan import run_scan

log = logging.getLogger(__name__)

FREQUENCIES = ("off", "daily", "weekly")
_INTERVALS = {"daily": timedelta(days=1), "weekly": timedelta(days=7)}

# Scans start a little early rather than drifting later every day.
_GRACE = timedelta(minutes=5)


def due_cutoffs(now: datetime) -> dict[str, str]:
    """The 'last run at or before this' cutoff per frequency."""
    return {
        frequency: (now - interval + _GRACE).isoformat()
        for frequency, interval in _INTERVALS.items()
    }


def run_due_scans(app, now: datetime | None = None) -> list[dict]:
    """Scan every org whose schedule is due. Returns a result per org."""
    now = now or datetime.now(timezone.utc)
    results: list[dict] = []

    with app.app_context():
        from .services import build_scan_context, get_db, get_settings

        db = get_db()
        settings = get_settings()
        cutoffs = due_cutoffs(now)

        for org in db.orgs_due(cutoffs):
            # Atomic claim: only one worker proceeds for this org.
            if not db.claim_scheduled_run(
                org["id"], now.isoformat(), cutoffs[org["schedule_frequency"]]
            ):
                continue
            results.append(_scan_one(db, settings, org, app))
    return results


def _scan_one(db, settings: Settings, org: dict, app) -> dict:
    domain = org["primary_domain"]
    try:
        from .services import build_scan_context

        # The predecessor is resolved AFTER the scan is stored, against the
        # row that was actually written, and through the same gate the
        # dashboard uses. Reading it before and comparing by hand is how the
        # e-mail ended up announcing a delta the dashboard refused to compute.
        ctx = build_scan_context(org)
        scan = run_scan(org, ctx, db)
        # Also here, not only on the manual route: this path is inert today because
        # nothing can set a schedule, but a first scan is a first scan whichever way
        # it was triggered, and the claim in the database makes running both safe.
        avisar_empresa_nueva(settings, db, org, scan)
        previous = db.scan_before(org["id"], scan["id"])
        previous_score, summary = gated_summary(scan, previous)

        alerted = False
        if org.get("alert_email"):
            should = alert_worthy(summary, scan["score"], previous_score) or not org.get(
                "alert_only_on_change"
            )
            if should and smtp_configured(settings):
                dashboard_url = (
                    f"{settings.base_url}{settings.prefix}/dashboard"
                    if settings.base_url
                    else "your Vigía dashboard"
                )
                subject, body = scan_alert_body(
                    org, scan, previous_score, summary, dashboard_url
                )
                try:
                    send_email(settings, org["alert_email"], subject, body)
                    alerted = True
                except NotifyError as exc:
                    log.warning("alert email failed for %s: %s", domain, exc)

        log.info("scheduled scan done for %s (score=%s, alerted=%s)", domain, scan["score"], alerted)
        return {
            "domain": domain,
            "ok": True,
            "score": scan["score"],
            "new_issues": len(summary["new"]),
            "alerted": alerted,
        }
    except Exception as exc:  # noqa: BLE001 — one org must not stop the rest
        log.exception("scheduled scan failed for %s", domain)
        return {"domain": domain, "ok": False, "error": str(exc)}


def run_retention_purge(app) -> dict:
    """Apply the personal-data retention window. Never raises: a failed purge
    must not take the scheduler down with it."""
    with app.app_context():
        settings = app.extensions["vigia"]["settings"]
        db = app.extensions["vigia"]["db"]
        try:
            return retention.purge(db, settings.pii_retention_hours)
        except Exception:  # noqa: BLE001
            log.exception("la purga de retención ha fallado")
            return {"error": True}


def start_scheduler(app, settings: Settings):
    """Start the background scheduler. Returns the scheduler or None."""
    if not settings.scheduler_enabled:
        return None
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
    except ImportError:
        log.warning("APScheduler not installed — scheduled scans disabled.")
        return None

    scheduler = BackgroundScheduler(daemon=True, timezone="UTC")
    scheduler.add_job(
        lambda: run_due_scans(app),
        "interval",
        minutes=settings.scheduler_interval_minutes,
        id="vigia-due-scans",
        max_instances=1,
        coalesce=True,
    )
    # The purge only ever removes rows, so the duplicate scheduler each
    # gunicorn worker starts is harmless here: both reach the same result.
    scheduler.add_job(
        lambda: run_retention_purge(app),
        "interval",
        minutes=60,
        id="vigia-retention-purge",
        max_instances=1,
        coalesce=True,
        next_run_time=datetime.now(timezone.utc) + timedelta(minutes=2),
    )
    scheduler.start()
    log.info(
        "scheduler started (escaneos cada %s min, purga de datos personales cada 60 min)",
        settings.scheduler_interval_minutes,
    )
    return scheduler
