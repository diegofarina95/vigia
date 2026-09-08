"""Google OAuth 2.0 admin-consent flow, implemented directly against the
OAuth endpoints (no SDK) so the exact scopes requested are auditable here.

SCOPE POLICY (critical constraint): only the four sensitive-but-NON-
restricted read-only scopes below (three Admin SDK + one Cloud Identity),
plus the basic `openid email` identity scopes (non-sensitive) used solely
to learn who connected. Never add a Gmail/Drive/other restricted scope —
that would trigger a CASA security assessment, which this product
deliberately avoids. Every scope here must be called by a live check: an
unused scope only lengthens Google's verification review.
"""
from __future__ import annotations

import base64
import json
import time
from urllib.parse import urlencode

import requests

from ..config import Settings

AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
REVOKE_ENDPOINT = "https://oauth2.googleapis.com/revoke"

# The scopes are NOT written here any more. They live in `vigia.scopes`, together
# with what each one reads and which checks break without it, because this list had
# drifted from the privacy policy and from the homepage and nothing noticed.
#
# Two facts that used to be buried in comments here and are worth keeping:
#  · admin.reports.usage.readonly was requested until 2026-07-31 and never called by
#    any check. Every unused scope lengthens Google's review and widens the consent
#    screen for nothing. Re-add it only together with the check that needs it.
#  · cloud-identity.policies.readonly was checked against Google's restricted list —
#    restricted covers Gmail, Drive, Fit, Chat, Data Portability, Photos and Health,
#    and Cloud Identity is not there. It is *sensitive only* and does NOT trigger a
#    CASA assessment.
from ..scopes import ALL_IDS, IDENTITY_IDS, WORKSPACE_IDS

#: Kept as list aliases: these names are imported elsewhere, and the request has
#: always been "identity first, then workspace".
WORKSPACE_SCOPES = list(WORKSPACE_IDS)
IDENTITY_SCOPES = list(IDENTITY_IDS)
ALL_SCOPES = list(ALL_IDS)


class AuthError(Exception):
    pass


class TokenRevoked(AuthError):
    """The refresh token is no longer valid — the org must reconnect."""


def build_auth_url(settings: Settings, state: str) -> str:
    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": settings.oauth_redirect_uri,
        "response_type": "code",
        "scope": " ".join(ALL_SCOPES),
        "access_type": "offline",  # we need a refresh token for re-scans
        "prompt": "consent",  # guarantees a refresh token is issued
        "state": state,
    }
    return f"{AUTH_ENDPOINT}?{urlencode(params)}"


def exchange_code(settings: Settings, code: str) -> dict:
    response = requests.post(
        TOKEN_ENDPOINT,
        data={
            "code": code,
            "client_id": settings.google_client_id,
            "client_secret": settings.google_client_secret,
            "grant_type": "authorization_code",
            "redirect_uri": settings.oauth_redirect_uri,
        },
        timeout=15,
    )
    payload = response.json()
    if response.status_code >= 400 or "error" in payload:
        raise AuthError(payload.get("error_description") or payload.get("error", "token exchange failed"))
    return payload


def refresh_access_token(settings: Settings, refresh_token: str) -> tuple[str, int]:
    response = requests.post(
        TOKEN_ENDPOINT,
        data={
            "refresh_token": refresh_token,
            "client_id": settings.google_client_id,
            "client_secret": settings.google_client_secret,
            "grant_type": "refresh_token",
        },
        timeout=15,
    )
    payload = response.json()
    if response.status_code >= 400 or "error" in payload:
        if payload.get("error") == "invalid_grant":
            raise TokenRevoked("refresh token revoked or expired")
        raise AuthError(payload.get("error_description") or payload.get("error", "refresh failed"))
    return payload["access_token"], int(payload.get("expires_in", 3600))


def revoke_token(refresh_token: str) -> None:
    """Best-effort revocation on disconnect (GDPR-friendly)."""
    try:
        requests.post(REVOKE_ENDPOINT, params={"token": refresh_token}, timeout=10)
    except requests.RequestException:
        pass


def decode_id_token(id_token: str) -> dict:
    """Decode the JWT payload WITHOUT signature verification — acceptable
    here because the token arrived directly from Google's token endpoint
    over TLS in the same response, not from the user."""
    try:
        payload_b64 = id_token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64))
    except (IndexError, ValueError) as exc:
        raise AuthError(f"could not decode id_token: {exc}") from exc


class AccessTokenProvider:
    """Caches the short-lived access token, refreshing 60s before expiry."""

    def __init__(self, settings: Settings, refresh_token: str) -> None:
        self._settings = settings
        self._refresh_token = refresh_token
        self._access_token: str | None = None
        self._expires_at: float = 0.0

    def token(self) -> str:
        if self._access_token is None or time.time() > self._expires_at - 60:
            self._access_token, expires_in = refresh_access_token(
                self._settings, self._refresh_token
            )
            self._expires_at = time.time() + expires_in
        return self._access_token


class StaticTokenProvider:
    """Wraps the access token we already hold right after the code
    exchange, avoiding an immediate refresh round-trip."""

    def __init__(self, access_token: str) -> None:
        self._access_token = access_token

    def token(self) -> str:
        return self._access_token
