"""REST API consumed by the React frontend."""
from __future__ import annotations

import csv
import io
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from flask import Blueprint, Response, jsonify, request

from .. import dns_email_auth
from ..auth.oauth import AuthError, TokenRevoked
from ..delta import gated_summary
from ..demo import DEMO_ORG, build_demo_payload
from ..google_client import GoogleApiError
from ..i18n import localize_payload, normalize_lang
from ..jobs import FREQUENCIES
from ..notify import avisar_empresa_nueva, smtp_configured
from ..projection import coverage_line, project
from ..report import build_html_report, findings_csv_rows
from ..engine_version import describe
from ..scan import consistency_diagnostic, run_scan
from ..services import (
    SCORING_THRESHOLDS,
    build_scan_context,
    current_org,
    effective_settings,
    get_db,
    get_settings,
)
from ..scoring import people_at_risk, score_breakdown

api_bp = Blueprint("api", __name__, url_prefix="/api")

MIN_SECONDS_BETWEEN_SCANS = 30

# Simple in-memory per-IP rate limit for the public checker (fine for a
# single-process MVP; move to Redis if it ever runs multi-process).
_RATE_WINDOW_SECONDS = 60
_RATE_MAX_REQUESTS = 10
_rate_buckets: dict[str, deque] = defaultdict(deque)


def _rate_limited(ip: str) -> bool:
    now = time.time()
    bucket = _rate_buckets[ip]
    while bucket and bucket[0] < now - _RATE_WINDOW_SECONDS:
        bucket.popleft()
    if len(bucket) >= _RATE_MAX_REQUESTS:
        return True
    bucket.append(now)
    # Drop idle IPs so the dict cannot grow without bound.
    if len(_rate_buckets) > 2048:
        for stale_ip in [
            key
            for key, entries in _rate_buckets.items()
            if not entries or entries[-1] < now - _RATE_WINDOW_SECONDS
        ]:
            _rate_buckets.pop(stale_ip, None)
    return False


#: Remembers an explicit language choice. Deliberately not a session value:
#: it is a display preference, it is not sensitive, and it has to survive a
#: disconnect.
LANG_COOKIE = "vigia_lang"
LANG_COOKIE_MAX_AGE = 60 * 60 * 24 * 365


def _requested_lang() -> str:
    """`?lang=` wins, then a language the reader chose before, then Spanish.

    The browser's `Accept-Language` deliberately does NOT decide. It used to,
    and the result was a Spanish product serving its whole report in English
    to anyone whose laptop was set to English — a Spanish-speaking user in
    London saw a Spanish interface wrapped around English findings and
    reasonably concluded the translation was unfinished. The content was
    translated; the browser was overriding it.
    """
    explicit = request.args.get("lang")
    if explicit:
        return normalize_lang(explicit)
    return normalize_lang(request.cookies.get(LANG_COOKIE))


def _remember_lang(response):
    """Persist an explicit `?lang=` so the choice survives the next click."""
    chosen = request.args.get("lang")
    if chosen:
        response.set_cookie(
            LANG_COOKIE,
            normalize_lang(chosen),
            max_age=LANG_COOKIE_MAX_AGE,
            samesite="Lax",
            httponly=False,  # the frontend reads it to highlight the toggle
        )
    return response


def _org_or_401():
    org = current_org()
    if org is None:
        return None, (jsonify({"error": "not_connected"}), 401)
    return org, None


@api_bp.get("/me")
def me():
    settings = get_settings()
    org = current_org()
    payload: dict = {
        "connected": org is not None,
        "mock_mode": settings.mock_mode,
        "contact_email": settings.contact_email,
    }
    if org:
        payload["org"] = {
            "domain": org["primary_domain"],
            "admin_email": org["admin_email"],
        }
    return jsonify(payload)


@api_bp.post("/scan")
def scan():
    org, err = _org_or_401()
    if err:
        return err
    db = get_db()

    latest = db.latest_scans(org["id"], limit=1)
    if latest:
        last_at = datetime.fromisoformat(latest[0]["created_at"])
        elapsed = (datetime.now(timezone.utc) - last_at).total_seconds()
        if elapsed < MIN_SECONDS_BETWEEN_SCANS:
            return (
                jsonify({"error": "too_soon", "retry_in": int(MIN_SECONDS_BETWEEN_SCANS - elapsed)}),
                429,
            )

    try:
        ctx = build_scan_context(org)
        new_scan = run_scan(org, ctx, db)
        # Outside `run_scan` on purpose: the scanner is the engine and sending mail
        # is not its job — it takes no `settings` and should not start to. The alert
        # swallows its own failures, so a broken mail server cannot turn a finished
        # analysis into an error for the customer who asked for it.
        avisar_empresa_nueva(get_settings(), db, org, new_scan)
    except TokenRevoked:
        return jsonify({"error": "reconnect_required"}), 401
    except (AuthError, GoogleApiError) as exc:
        return jsonify({"error": "google_api", "message": str(exc)}), 502

    return _latest_payload(org, db, new_scan)


@api_bp.get("/scan/latest")
def scan_latest():
    org, err = _org_or_401()
    if err:
        return err
    return _latest_payload(org, get_db())


def _scan_with_delta(org: dict, db, scan_row: dict | None = None):
    """(scan_row annotated with per-finding 'change', previous_score, summary)."""
    if scan_row is None:
        scans = db.latest_scans(org["id"], limit=1)
        scan_row = scans[0] if scans else None
    if scan_row is None:
        return None, None, None

    # Strictly the scan BEFORE this one. The old rule — "the newest scan that
    # is not the row we're showing", over a page of two — returned a LATER
    # scan whenever the row was not the very latest.
    previous = db.scan_before(org["id"], scan_row["id"])
    previous_score, summary = gated_summary(scan_row, previous)
    # The rendered sentences travel with the payload so the dashboard prints the
    # same words as the PDF, the CSV and the e-mail instead of rebuilding them in
    # TSX. Four channels phrasing one comparison independently is how "= sin
    # cambios" ended up over a score that had moved.
    from ..projection import score_explanation

    summary["score_lines"] = score_explanation(summary.get("score_change"), summary).get(
        "lines", []
    )
    return scan_row, previous_score, summary


def _latest_payload(org: dict, db, scan_row: dict | None = None):
    scan_row, previous_score, summary = _scan_with_delta(org, db, scan_row)

    if scan_row is None:
        return jsonify(
            {
                "scan": None,
                "previous_score": None,
                "delta": None,
            }
        )

    # Scans stored before the coherence check existed are verified again here,
    # on the way out: a contradiction must never reach a reader, not even from
    # the archive. Adding the diagnostic at read time cannot alter the stored
    # score — it is informative and undetermined, so it carries no weight.
    findings = scan_row["findings"]
    if not any(f.get("id") == "internal-consistency" for f in findings):
        findings.extend(
            f.to_dict()
            for f in consistency_diagnostic(findings, org.get("primary_domain", ""))
        )

    # PROJECTED, not re-derived. The score, the breakdown, the people and the
    # ranked actions were computed once at scan time next to the coverage that
    # justifies them. Recomputing here is what printed two different scores on
    # one page from the second day onwards: the 24-hour purge removes the
    # accounts the recomputation counts.
    resultado = project(scan_row)
    actions = resultado["actions"]
    breakdown = resultado["breakdown"]
    people = resultado["people_at_risk"]

    gated = dict(scan_row)
    gated.pop("org_id", None)
    return jsonify(
        localize_payload(
            {
            "scan": gated,
            "previous_score": previous_score,

            "delta": summary,
            "engine": describe(),
            "actions": actions,
            "breakdown": breakdown,
            "people_at_risk": people,
            "coverage": resultado.get("coverage", {}),
            "coverage_line": coverage_line(resultado),
            },
            _requested_lang(),
        )
    )


@api_bp.get("/scans")
def scans_history():
    org, err = _org_or_401()
    if err:
        return err
    history = get_db().scan_history(org["id"])
    gated, truncated = history, False

    # Mark the points where the set of checks changed, so the line is not read
    # as a trend across a discontinuity it never crossed.
    previous_engine = None
    for point in gated:
        engine = point.get("engine_version") or ""
        point["engine_changed"] = bool(previous_engine) and engine != previous_engine
        previous_engine = engine

    return jsonify(
        {"history": gated, "truncated": truncated, "engine": describe()}
    )


def _settings_payload(org: dict) -> dict:
    effective = effective_settings(org)
    defaults = get_settings()
    return {
        "settings": {f: getattr(effective, f) for f in SCORING_THRESHOLDS},
        "defaults": {f: getattr(defaults, f) for f in SCORING_THRESHOLDS},
    }


# The write half of these three areas is gone from the API, not just from the
# screen: a button removed while its endpoint stays is still a feature, and for
# the thresholds it is the feature that let the measured tenant move its own
# yardstick. The read halves stay — they disclose the yardstick and the domains
# covered, and the printable report uses them.
#
# `db.set_schedule`, `db.add_domain`, `db.remove_domain`, `set_org_settings`, the
# `jobs.py` scheduler and every column behind them are untouched, so putting the
# monthly-monitoring UI back is wiring, not archaeology.
@api_bp.get("/settings")
def get_scan_settings():
    org, err = _org_or_401()
    if err:
        return err
    return jsonify(_settings_payload(org))


@api_bp.get("/domains")
def list_domains():
    """Domains covered by the email-auth checks: Google-synced (real mode)
    plus user-configured ones."""
    org, err = _org_or_401()
    if err:
        return err
    return jsonify({"domains": get_db().list_domains(org["id"])})


def _schedule_payload(org: dict) -> dict:
    settings = get_settings()
    return {
        "frequency": org.get("schedule_frequency", "off"),
        # Never show a "security@yourcompany.com" placeholder: default to the
        # admin who connected, which is always a real, reachable address.
        "alert_email": org.get("alert_email") or org.get("admin_email", ""),
        "suggested_email": org.get("admin_email", ""),
        "alert_only_on_change": bool(org.get("alert_only_on_change", 1)),
        "last_run": org.get("schedule_last_run"),
        "smtp_configured": smtp_configured(settings),
        "frequencies": list(FREQUENCIES),
    }


@api_bp.get("/schedule")
def get_schedule():
    org, err = _org_or_401()
    if err:
        return err
    return jsonify(_schedule_payload(org))


@api_bp.get("/report")
def report_html():
    """Printable report (browser → Save as PDF). Pro feature."""
    org, err = _org_or_401()
    if err:
        return err

    db = get_db()
    scan_row, previous_score, summary = _scan_with_delta(org, db)
    if scan_row is None:
        return jsonify({"error": "no_scan", "message": "Ejecuta primero un escaneo."}), 404

    lang = _requested_lang()
    resultado = project(scan_row)
    localized = localize_payload(
        {
            "scan": scan_row,
            "delta": summary,
            "actions": resultado["actions"],
            "breakdown": resultado["breakdown"],
            "people_at_risk": resultado["people_at_risk"],
            "coverage": resultado.get("coverage", {}),
            "coverage_line": coverage_line(resultado),
        },
        lang,
    )
    # The coverage line is read off the row, so it travels with it.
    localized["scan"]["result"] = resultado
    html_doc = build_html_report(
        org,
        localized["scan"],
        previous_score,
        localized["delta"],
        db.list_domains(org["id"]),
        actions=localized["actions"],
        breakdown=localized["breakdown"],
        people=localized["people_at_risk"],
        lang=lang,
    )
    return Response(html_doc, mimetype="text/html; charset=utf-8")


# Two paths, one handler. The extension is the problem: Cloudflare caches
# `.csv` by default and served one tenant's export to the whole internet for
# four hours. `no-store` now goes out with it, but relying on an edge to
# honour a header it has historically overridden for static extensions is a
# bet, and this is a customer's employee list. The extensionless path is the
# one the app uses; the old one stays so a bookmarked link still works, and
# it is no longer a name any CDN treats as a file.
@api_bp.get("/report/csv")
@api_bp.get("/report.csv")
def report_csv():
    """Findings as CSV, for spreadsheets and ticketing imports. Pro feature."""
    org, err = _org_or_401()
    if err:
        return err

    db = get_db()
    scan_row, _, _ = _scan_with_delta(org, db)
    if scan_row is None:
        return jsonify({"error": "no_scan", "message": "Ejecuta primero un escaneo."}), 404

    # The same language for the rows and for the column headings. These were two
    # calls one line apart, only the first of which was told the language, so
    # `?lang=en` exported English findings under Spanish column names.
    lang = _requested_lang()
    localized = localize_payload({"scan": scan_row}, lang)
    buffer = io.StringIO()
    csv.writer(buffer).writerows(findings_csv_rows(localized["scan"], lang))
    stamp = (scan_row.get("created_at") or "")[:10]
    filename = f"vigia-{org['primary_domain']}-{stamp}.csv"
    return Response(
        buffer.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------- demo
# Unauthenticated on purpose: this is the sales artefact. It reads nothing
# but the constants in vigia/demo.py, so it cannot expose a real tenant.


@api_bp.get("/demo/scan")
def demo_scan():
    return jsonify(localize_payload(build_demo_payload(get_settings()), _requested_lang()))


@api_bp.get("/demo/scans")
def demo_scans():
    payload = build_demo_payload(get_settings())
    return jsonify({"history": payload["history"], "truncated": False})


@api_bp.get("/demo/domains")
def demo_domains_route():
    return jsonify({"domains": build_demo_payload(get_settings())["domains"]})


@api_bp.get("/demo/report")
def demo_report():
    """Deliberately identical to the paid report: no watermark, so it can be
    attached to a commercial email as-is."""
    lang = _requested_lang()
    payload = localize_payload(build_demo_payload(get_settings()), lang)
    html_doc = build_html_report(
        DEMO_ORG,
        payload["scan"],
        payload["previous_score"],
        payload["delta"],
        payload["domains"],
        actions=payload["actions"],
        breakdown=payload["breakdown"],
        people=payload["people_at_risk"],
        lang=lang,
    )
    return Response(html_doc, mimetype="text/html; charset=utf-8")


@api_bp.get("/demo/report/csv")
@api_bp.get("/demo/report.csv")
def demo_report_csv():
    lang = _requested_lang()
    payload = localize_payload(build_demo_payload(get_settings()), lang)
    buffer = io.StringIO()
    csv.writer(buffer).writerows(findings_csv_rows(payload["scan"], lang))
    return Response(
        buffer.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="vigia-demo.csv"'},
    )


@api_bp.post("/billing/upgrade")
def billing_upgrade():
    # TODO(billing): integrate Stripe Checkout here. Deliberately stubbed
    # in the MVP — the gating logic and UI states are already in place.
    return jsonify({"ok": False, "message": "El pago todavía no está activo. TODO: integrar Stripe."}), 501


@api_bp.post("/tools/email-auth")
def tools_email_auth():
    """Public, no-auth SPF/DKIM/DMARC checker (the /dmarc-checker lead-gen
    tool). Rate limited per IP."""
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()
    if _rate_limited(ip):
        return jsonify({"error": "rate_limited"}), 429

    data = request.get_json(silent=True) or {}
    domain = dns_email_auth.normalize_domain(str(data.get("domain", "")))
    if not domain:
        return jsonify({"error": "invalid_domain"}), 400

    # Selectors the visitor says they sign with. Checked IN ADDITION to the default
    # list, and their presence changes what a miss means — see `dkim_verdict`. Only
    # here: inside a tenant the selector comes from the Workspace API, so there is
    # nothing for anybody to declare.
    declarados, error = dns_email_auth.validar_selectores(
        str(data.get("selectors", "")), lang=_requested_lang()
    )
    if error:
        # The message names what is wrong with the input. A generic "invalid" would
        # leave somebody who pasted the whole record name with nothing to act on.
        return jsonify({"error": "invalid_selector", "message": error}), 400

    report = dns_email_auth.check_domain(
        domain,
        selectors=dns_email_auth.DEFAULT_DKIM_SELECTORS,
        declarados=declarados,
        lang=_requested_lang(),
    )
    return jsonify(report)
