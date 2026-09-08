"""Thin authorized HTTP session shared by the Google API wrappers.

Deliberately NOT google-api-python-client: the two APIs we call are
simple GETs, and a visible requests layer keeps the read-only guarantee
auditable — there is no code path that can issue a write.
"""
from __future__ import annotations

import requests


class GoogleApiError(Exception):
    def __init__(self, status_code: int, message: str, payload: dict | None = None) -> None:
        super().__init__(f"Google API error {status_code}: {message}")
        self.status_code = status_code
        self.message = message
        # The parsed error body. Google puts the actionable part in
        # `error.details[].metadata` — the activation URL for a disabled API
        # carries the project number, which the human message alone does not
        # let a caller use reliably.
        self.payload = payload or {}


class GoogleSession:
    """GET-only session. token_provider must expose .token() -> str."""

    def __init__(self, token_provider, timeout: float = 20.0) -> None:
        self._token_provider = token_provider
        self._timeout = timeout
        self._http = requests.Session()

    def get(self, url: str, params: dict | None = None) -> dict:
        response = self._http.get(
            url,
            params=params or {},
            headers={"Authorization": f"Bearer {self._token_provider.token()}"},
            timeout=self._timeout,
        )
        if response.status_code >= 400:
            payload: dict = {}
            try:
                payload = response.json()
                message = payload.get("error", {}).get("message", response.text)
            except ValueError:
                message = response.text
            raise GoogleApiError(response.status_code, message, payload)
        return response.json() if response.content else {}
