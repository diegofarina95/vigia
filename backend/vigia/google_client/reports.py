"""Admin SDK Reports API (audit activities) — read-only wrapper.

Scope used: admin.reports.audit.readonly. Nothing here touches the usage
reports API, which is why that scope is no longer requested.
"""
from __future__ import annotations

from .base import GoogleSession
from .grants import Coverage, fold

BASE = "https://admin.googleapis.com/admin/reports/v1"

#: 20 pages × 1000 events. Measured, not guessed: a busy tenant emits ~1 600
#: `authorize` events a day (the same handful of apps refreshing their tokens),
#: so 60 pages bought 38 days and took 37 seconds — and the window still was
#: not complete. There is no page count that reaches 180 days inside a web
#: request for a tenant like that.
#:
#: So the cap is set by the time budget (~12s) and the HONESTY is where it
#: belongs: the finding reports the window it actually read and comes back
#: partial. The old cap of 5 pages covered two days while the card claimed
#: "~180 days" — that was the defect, not the number itself.
MAX_TOKEN_PAGES = 20

#: The admin and login feeds are a different animal from the token feed and the
#: numbers say so: measured on a real tenant, 483 and 423 records — ONE page
#: each — covering 178 days. About three events a day against the token feed's
#: sixteen hundred. So the cap here is defensive rather than binding: at that
#: rate twenty pages is roughly eighteen years of history, and if a tenant ever
#: does hit it the coverage says `complete=False` and every finding resting on
#: the source inherits the uncertainty. The lie in these two was never the cap;
#: it was a scope label that said "~180 days" without measuring.
MAX_ACTIVITY_PAGES = 20


class ReportsClient:
    def __init__(self, session: GoogleSession) -> None:
        self._session = session
        #: Coverage of the most recent paginated call, so a caller can ask
        #: "was that all of it?" instead of assuming.
        self.last_coverage = Coverage(source="")

    def _pages(self, application: str, max_results: int, max_pages: int,
               start_time: str = ""):
        """Yield (page_items, page_number). Stops at the cap and tells the
        caller whether the cap was what stopped it, via `self.last_coverage`."""
        page_token: str | None = None
        pagina = 0
        registros = 0
        primero = ultimo = ""
        for pagina in range(1, max_pages + 1):
            params: dict = {"maxResults": max_results}
            if start_time:
                # Only what happened after the watermark. Measured: two hours of
                # this tenant's token feed is 247 events in one page, 0.3 s and
                # complete — against 20 000 in twenty pages covering six days
                # when the whole window is re-read on every scan.
                params["startTime"] = start_time
            if page_token:
                params["pageToken"] = page_token
            data = self._session.get(
                f"{BASE}/activity/users/all/applications/{application}", params
            )
            items = data.get("items", []) or []
            registros += len(items)
            # Events arrive newest-first, so the first page holds the newest
            # timestamp and the last page the oldest.
            for item in items:
                cuando = str((item.get("id") or {}).get("time") or "")
                if cuando:
                    if not ultimo or cuando > ultimo:
                        ultimo = cuando
                    if not primero or cuando < primero:
                        primero = cuando
            yield items, pagina
            page_token = data.get("nextPageToken")
            if not page_token:
                break

        self.last_coverage = Coverage(
            source=application,
            pages=pagina,
            records=registros,
            # A token left over means the API had more to give and the cap is
            # what stopped us. That is the difference between "this is all of
            # it" and "this is as far as I got".
            complete=not page_token,
            oldest=primero,
            newest=ultimo,
            reason=(
                f"se alcanzó el tope de {max_pages} páginas y la API seguía teniendo más"
                if page_token
                else ""
            ),
        )

    def _activities(self, application: str, max_results: int, max_pages: int) -> list[dict]:
        items: list[dict] = []
        for pagina, _ in self._pages(application, max_results, max_pages):
            items.extend(pagina)
        return items

    def token_grants(
        self, max_pages: int = MAX_TOKEN_PAGES, start_time: str = ""
    ) -> tuple[dict, Coverage]:
        """Every distinct (application, person, scopes) over the whole window.

        Folded page by page rather than collected: this tenant produces over
        8 000 events and the raw list is not what any check needs. See
        `grants.py` for why the page cap stopped being the thing that decided
        what the customer was told.
        """
        grants: dict = {}
        for items, _ in self._pages(
            "token", max_results=1000, max_pages=max_pages, start_time=start_time
        ):
            fold(items, grants)
        return grants, self.last_coverage

    def token_activities(self, max_pages: int = MAX_TOKEN_PAGES) -> list[dict]:
        """Raw OAuth grant events. Prefer `token_grants`, which folds them as
        it pages; this stays for callers that genuinely want the events."""
        return self._activities("token", max_results=1000, max_pages=max_pages)

    def admin_activities(
        self, max_results: int = 1000, max_pages: int = MAX_ACTIVITY_PAGES
    ) -> list[dict]:
        """Admin Console changes ('admin' application) over the audit window."""
        return self._activities("admin", max_results=max_results, max_pages=max_pages)

    def login_activities(self, max_pages: int = MAX_ACTIVITY_PAGES) -> list[dict]:
        """Sign-in events ('login' application): successes, failures and the
        security alerts Google raises (suspicious login, password leak,
        hijack, government-backed attack)."""
        return self._activities("login", max_results=1000, max_pages=max_pages)


def event_parameters(event: dict) -> dict:
    """Flatten a Reports event's parameters into {name: value}."""
    params: dict = {}
    for param in event.get("parameters", []) or []:
        name = param.get("name")
        if not name:
            continue
        if "multiValue" in param:
            params[name] = param["multiValue"]
        elif "value" in param:
            params[name] = param["value"]
        elif "intValue" in param:
            params[name] = param["intValue"]
        elif "boolValue" in param:
            params[name] = param["boolValue"]
    return params
