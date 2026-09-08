"""Access to app-scoped services (settings, db, cipher) from blueprints,
plus construction of per-org Google clients (real or mock)."""
from __future__ import annotations

import dataclasses

from flask import current_app, session

from .auth.oauth import AccessTokenProvider
from .config import Settings
from .crypto import TokenCipher
from .db import Database
from .google_client import DirectoryClient, GoogleSession, ReportsClient
from .google_client.mock import MockDirectoryClient, MockPolicyClient, MockReportsClient
from .google_client.policy import PolicyClient
from .scan import ScanContext


def get_settings() -> Settings:
    return current_app.extensions["vigia"]["settings"]


def get_db() -> Database:
    return current_app.extensions["vigia"]["db"]


def get_cipher() -> TokenCipher:
    return current_app.extensions["vigia"]["cipher"]


def current_org() -> dict | None:
    org_id = session.get("org_id")
    if org_id is None:
        return None
    return get_db().get_org(org_id)


#: The four thresholds the score depends on. Fixed in code, and named here so the
#: report can disclose the yardstick it used.
#:
#: They were per-org settings, editable from the panel, which meant the tenant
#: being measured could move its own yardstick: `dormant_days` at 3650 and the
#: dormant-accounts finding simply stops existing. Every claim this product makes
#: rests on measuring against CIS, so the ruler cannot belong to the subject.
SCORING_THRESHOLDS = (
    "super_admin_threshold",
    "dormant_days",
    "widely_granted_threshold",
    "dkim_selectors",
)


def effective_settings(org: dict) -> Settings:
    """The thresholds a scan uses. The same for every org, by design.

    Stored per-org overrides are deliberately NOT applied and deliberately NOT
    deleted: the rows stay so nothing is lost, and they are ignored so the
    measurement cannot be tuned by what is being measured.
    """
    return get_settings()


class _GrantStore:
    """The accumulated OAuth fold for one org, as a two-method handle.

    Passed in rather than reached for so `ScanContext` keeps not knowing about
    the database — the demo and the tests build one without a store and get the
    old whole-window behaviour, which is correct for a fixture.
    """

    def __init__(self, db, org_id: int) -> None:
        self._db = db
        self._org_id = org_id

    def load(self) -> dict:
        return self._db.get_oauth_grants(self._org_id)

    def save(self, grants: dict, watermark: str, oldest: str) -> None:
        self._db.save_oauth_grants(self._org_id, grants, watermark, oldest)


def build_scan_context(org: dict) -> ScanContext:
    settings = effective_settings(org)
    custom_domains = [
        row["domain"]
        for row in get_db().list_domains(org["id"])
        if row["source"] == "custom"
    ]
    if settings.mock_mode:
        # Demo tenant: Workspace data is simulated, but DNS checks are
        # always real — only against domains the user configured.
        return ScanContext(
            MockDirectoryClient(),
            MockReportsClient(),
            settings,
            custom_domains=custom_domains,
            include_directory_domains=False,
            policy=MockPolicyClient(),
        )
    refresh_token = get_cipher().decrypt(org["refresh_token_enc"])
    google_session = GoogleSession(AccessTokenProvider(settings, refresh_token))
    return ScanContext(
        DirectoryClient(google_session),
        ReportsClient(google_session),
        settings,
        custom_domains=custom_domains,
        policy=PolicyClient(google_session),
        grant_store=_GrantStore(get_db(), org["id"]),
    )
