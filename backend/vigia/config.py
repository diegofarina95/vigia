"""Application settings, loaded once from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, ""))
    except ValueError:
        return default


def _env_list(name: str, default: list[str]) -> list[str]:
    raw = os.environ.get(name)
    if not raw:
        return list(default)
    return [item.strip() for item in raw.split(",") if item.strip()]


# Selectors tried when probing DKIM. "google" is the Workspace default;
# the rest cover common mail providers so we report "found" more often.
#: What the PUBLIC DMARC checker probes. It is asked about arbitrary third-party
#: domains, most of which do not sign with Workspace, so narrowing it would make
#: a lead-generation tool worse at its one job.
# Imported, never redeclared: this file used to hold a byte-identical copy, and a
# `SCAN_DKIM_SELECTORS = ["google"]` beside it that made the scanner check one
# selector while the public checker checked seven. The same domain could come out
# "no verificado" in a customer's report and "correcto" in the free checker.
from .dns_email_auth import DEFAULT_DKIM_SELECTORS  # noqa: E402

#: What a TENANT SCAN probes, and it is not configurable. The scan options panel
#: let the tenant being measured widen or narrow its own yardstick — dormant_days
#: at 3650 and the dormant-accounts finding disappears — and every claim this
#: report makes rests on measuring against CIS rather than against a number the
#: subject picked. A tenant that signs with its own selector therefore reads as
#: "no verificado", which is why the DKIM finding now says so in words instead of
#: pointing at a panel that no longer exists.

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@dataclass
class Settings:
    secret_key: str
    data_dir: str
    db_path: str
    encryption_key: str | None
    google_client_id: str
    google_client_secret: str
    oauth_redirect_uri: str
    app_url: str  # where to send the browser after OAuth ("" = same origin)
    mock_mode: bool
    super_admin_threshold: int
    dormant_days: int
    widely_granted_threshold: int
    dkim_selectors: list[str]
    frontend_dist: str
    port: int
    debug: bool
    contact_email: str  # shown on the Privacy page (GDPR contact)
    # How long a report may name people. 0 disables the purge.
    pii_retention_hours: int
    prefix: str  # public mount path (e.g. /vigia) when behind a reverse proxy
    cookie_secure: bool
    base_url: str  # public origin, used to build links inside alert emails
    # Scheduled scans
    #: Where operator alerts go — "a new company ran an analysis". Separate from
    #: `contact_email`, which is the address shown to customers on the legal pages:
    #: the same value today, but one is a published contact and the other an inbox
    #: that gets business notifications, and conflating them means the published
    #: address cannot ever change without silently redirecting the alerts.
    operator_email: str
    scheduler_enabled: bool
    scheduler_interval_minutes: int
    # SMTP for alert emails (stdlib smtplib; no paid API)
    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_password: str
    smtp_from: str
    smtp_starttls: bool
    smtp_ssl: bool


def load_settings() -> Settings:
    port = _env_int("VIGIA_PORT", 8110)
    data_dir = os.environ.get("VIGIA_DATA_DIR", os.path.join(os.getcwd(), "data"))
    return Settings(
        secret_key=os.environ.get("VIGIA_SECRET_KEY", "dev-insecure-secret-change-me"),
        data_dir=data_dir,
        db_path=os.environ.get("VIGIA_DB_PATH", os.path.join(data_dir, "vigia.db")),
        encryption_key=os.environ.get("VIGIA_ENCRYPTION_KEY"),
        google_client_id=os.environ.get("GOOGLE_CLIENT_ID", ""),
        google_client_secret=os.environ.get("GOOGLE_CLIENT_SECRET", ""),
        oauth_redirect_uri=os.environ.get(
            "OAUTH_REDIRECT_URI", f"http://localhost:{port}/api/auth/google/callback"
        ),
        app_url=os.environ.get("VIGIA_APP_URL", "").rstrip("/"),
        mock_mode=_env_bool("MOCK_MODE", False),
        super_admin_threshold=_env_int("VIGIA_SUPER_ADMIN_THRESHOLD", 3),
        dormant_days=_env_int("VIGIA_DORMANT_DAYS", 90),
        widely_granted_threshold=_env_int("VIGIA_WIDELY_GRANTED_THRESHOLD", 10),
        dkim_selectors=_env_list("VIGIA_DKIM_SELECTORS", DEFAULT_DKIM_SELECTORS),
        frontend_dist=os.environ.get(
            "FRONTEND_DIST", os.path.join(_REPO_ROOT, "frontend", "dist")
        ),
        port=port,
        debug=_env_bool("VIGIA_DEBUG", False),
        contact_email=os.environ.get("VIGIA_CONTACT_EMAIL", ""),
        pii_retention_hours=_env_int("VIGIA_PII_RETENTION_HOURS", 24),
        prefix=os.environ.get("VIGIA_PREFIX", "").rstrip("/"),
        cookie_secure=_env_bool("VIGIA_COOKIE_SECURE", False),
        base_url=os.environ.get("VIGIA_BASE_URL", "").rstrip("/"),
        operator_email=(
            os.environ.get("VIGIA_OPERATOR_EMAIL", "").strip()
            or os.environ.get("VIGIA_CONTACT_EMAIL", "").strip()
        ),
        scheduler_enabled=_env_bool("VIGIA_SCHEDULER", True),
        scheduler_interval_minutes=max(1, _env_int("VIGIA_SCHEDULER_INTERVAL_MIN", 15)),
        smtp_host=os.environ.get("VIGIA_SMTP_HOST", ""),
        smtp_port=_env_int("VIGIA_SMTP_PORT", 587),
        smtp_user=os.environ.get("VIGIA_SMTP_USER", ""),
        smtp_password=os.environ.get("VIGIA_SMTP_PASSWORD", ""),
        smtp_from=os.environ.get("VIGIA_SMTP_FROM", ""),
        smtp_starttls=_env_bool("VIGIA_SMTP_STARTTLS", True),
        smtp_ssl=_env_bool("VIGIA_SMTP_SSL", False),
    )
