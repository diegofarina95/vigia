"""Admin SDK Directory API — read-only wrapper.

Scopes used: admin.directory.user.readonly, admin.directory.domain.readonly.
"""
from __future__ import annotations

from .base import GoogleSession

BASE = "https://admin.googleapis.com/admin/directory/v1"

# An explicit field mask, so anything a check needs has to be listed here.
# recoveryEmail / recoveryPhone feed check_recovery: Google omits them when
# empty, which is exactly the "not configured" signal that check looks for.
USER_FIELDS = (
    "nextPageToken,users(primaryEmail,name/fullName,isAdmin,isDelegatedAdmin,"
    "isEnrolledIn2Sv,isEnforcedIn2Sv,lastLoginTime,suspended,archived,"
    "creationTime,orgUnitPath,recoveryEmail,recoveryPhone)"
)

MAX_PAGES = 40  # 40 * 500 = 20k users; larger orgs get a truncation note


class DirectoryClient:
    def __init__(self, session: GoogleSession) -> None:
        self._session = session

    def list_users(self, max_results: int = 500) -> tuple[list[dict], bool]:
        """Returns (users, truncated)."""
        users: list[dict] = []
        page_token: str | None = None
        for _ in range(MAX_PAGES):
            params = {
                "customer": "my_customer",
                "maxResults": max_results,
                "orderBy": "email",
                "fields": USER_FIELDS,
            }
            if page_token:
                params["pageToken"] = page_token
            data = self._session.get(f"{BASE}/users", params)
            users.extend(data.get("users", []))
            page_token = data.get("nextPageToken")
            if not page_token:
                return users, False
        return users, True

    def list_domains(self) -> tuple[list[dict], bool]:
        """Returns (domains, truncated).

        This used to be one call with no loop. An agency tenant carrying its
        clients' domains would have had SPF, DKIM and DMARC checked on the
        first page only, and the rest would not have appeared anywhere — not
        as failing, not as pending, not at all.
        """
        domains: list[dict] = []
        page_token: str | None = None
        for _ in range(MAX_PAGES):
            params: dict = {}
            if page_token:
                params["pageToken"] = page_token
            data = self._session.get(f"{BASE}/customer/my_customer/domains", params)
            domains.extend(data.get("domains", []) or [])
            page_token = data.get("nextPageToken")
            if not page_token:
                return domains, False
        return domains, True
