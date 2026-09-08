"""Cloud Identity Policy API — read-only wrapper.

This is what turns most "manual checks" into automated ones: it reads the
settings an admin configured in the Admin console (Drive sharing, Gmail
forwarding, password policy, session length, Marketplace allowlist,
Groups sharing) without touching any user content.

Scope: https://www.googleapis.com/auth/cloud-identity.policies.readonly
That scope is *sensitive* but NOT *restricted* — Google's restricted list
covers Gmail, Drive, Fit, Chat, Data Portability, Photos and Health APIs.
So this keeps the product out of CASA, which is the whole point.

Only a super admin can read policies; a delegated admin gets 403.
"""
from __future__ import annotations

import logging
import re
import time

from .base import GoogleApiError, GoogleSession
from .grants import Coverage

log = logging.getLogger(__name__)

# The Policy API shipped as v1beta1; v1 is tried first in case the project
# is already on GA and beta is turned off.
API_VERSIONS = ("v1", "v1beta1")
BASE = "https://cloudidentity.googleapis.com"

MAX_PAGES = 20
PAGE_SIZE = 100

#: The Policy API's per-minute quota is small and a full tenant runs to a few
#: hundred policies, so a weekly scan can legitimately hit 429. Waiting is the
#: correct response: reporting "could not read your settings" over a transient
#: rate limit tells a customer their configuration is unknown when it is not.
RETRY_WAITS = (2, 5, 15)

#: …but only up to a point, and the point is a budget for the WHOLE listing,
#: not per page. Per page, 22 seconds of waiting across 20 pages is over seven
#: minutes — long past the request timeout at gunicorn (120s) and further past
#: Cloudflare's (~100s). The customer would not see a rate-limit card; they
#: would see the browser give up with "Failed to fetch" and no explanation at
#: all. Past the budget the scan stops waiting and says plainly that Google
#: is throttling, which is a worse answer than the settings but a much better
#: one than a dead connection.
RETRY_BUDGET_SECONDS = 30


class PolicyUnavailable(Exception):
    """Policies could not be read. ``reason`` explains why so the UI can
    tell the admin exactly what to fix, instead of showing a false pass."""

    def __init__(self, reason: str, hint: str, url: str = "") -> None:
        super().__init__(f"{reason}: {hint}")
        self.reason = reason
        self.hint = hint
        #: Where to go to fix it, when Google tells us. For a disabled API
        #: this is the activation page **for the right project** — a generic
        #: link to the API library opens whichever project the admin last
        #: used, which is a quiet way to enable the API in the wrong place
        #: and see no change.
        self.url = url


def _activation_url(exc: GoogleApiError) -> str:
    """The link Google hands back for a disabled service, project included."""
    for detail in (exc.payload.get("error") or {}).get("details") or []:
        url = ((detail or {}).get("metadata") or {}).get("activationUrl")
        if url:
            return str(url)
    found = re.search(r"https://console\.[^\s\"']+", exc.message or "")
    return found.group(0).rstrip(".") if found else ""


def _classify(exc: GoogleApiError) -> PolicyUnavailable:
    message = (exc.message or "").lower()
    if "scope" in message or "access_token_scope_insufficient" in message:
        return PolicyUnavailable(
            "scope_missing",
            "La conexión se autorizó antes de añadir la lectura de políticas. Desconecta y "
            "vuelve a conectar para conceder el permiso de solo lectura de políticas.",
        )
    if "has not been used" in message or "disabled" in message or "service_disabled" in message:
        url = _activation_url(exc)
        return PolicyUnavailable(
            "api_disabled",
            (
                "Activa la API de Cloud Identity en el proyecto de Google Cloud de esta "
                "aplicación y vuelve a escanear"
                + (f": {url}" if url else
                   " (ojo: tiene que ser el proyecto al que pertenece el ID de cliente OAuth, "
                   "no el que tengas abierto en la consola).")
            ),
            url,
        )
    if exc.status_code == 429 or "exhausted" in message or "quota" in message:
        return PolicyUnavailable(
            "rate_limited",
            "Google ha limitado el ritmo de consultas a la API de políticas. No es un "
            "problema de tu configuración: vuelve a escanear en unos minutos.",
        )
    if exc.status_code == 403:
        return PolicyUnavailable(
            "not_super_admin",
            "Solo un superadministrador puede leer las políticas de Workspace. Vuelve a "
            "conectar con una cuenta de superadministrador.",
        )
    if exc.status_code == 404:
        return PolicyUnavailable(
            "not_available",
            "La Policy API no está disponible para este tenant (algunos ajustes requieren "
            "Cloud Identity Premium o Workspace Enterprise/Education).",
        )
    return PolicyUnavailable("error", exc.message or "Error desconocido de la Policy API.")


class PolicyClient:
    def __init__(self, session: GoogleSession) -> None:
        self._session = session
        #: Seconds already spent sleeping on rate limits during this listing.
        self._waited = 0.0

    def list_policies(self) -> tuple[list[dict], Coverage]:
        """Every policy with an explicitly set value, across all versions
        of the endpoint we know about."""
        last_error: PolicyUnavailable | None = None
        for version in API_VERSIONS:
            try:
                return self._list(version)
            except GoogleApiError as exc:
                problem = _classify(exc)
                # A missing endpoint just means "try the other version";
                # anything else is a real problem worth reporting.
                if problem.reason != "not_available":
                    raise problem from exc
                last_error = problem
        raise last_error or PolicyUnavailable("error", "No se ha podido contactar con la Policy API.")

    def _page(self, version: str, params: dict) -> dict:
        """One page, waiting out a rate limit — within the run's total budget."""
        for attempt, wait in enumerate((*RETRY_WAITS, None)):
            try:
                return self._session.get(f"{BASE}/{version}/policies", params)
            except GoogleApiError as exc:
                rate_limited = exc.status_code == 429 or "exhausted" in (exc.message or "").lower()
                if not rate_limited or wait is None or self._waited >= RETRY_BUDGET_SECONDS:
                    raise
                wait = min(wait, RETRY_BUDGET_SECONDS - self._waited)
                self._waited += wait
                log.info(
                    "Policy API limitada, reintento %s en %ss (%.0fs de %ss gastados)",
                    attempt + 1, wait, self._waited, RETRY_BUDGET_SECONDS,
                )
                time.sleep(wait)
        raise AssertionError("inalcanzable")  # pragma: no cover

    def _list(self, version: str) -> tuple[list[dict], Coverage]:
        """Every policy, and whether that is actually every policy.

        This loop used to `return policies` with `page_token` still set — the
        byte-for-byte shape of the token-events defect, and worse in its
        consequence. A missing policy is not a missing verdict: the reduction
        engine treats absence as "Google's documented default", so a page cap
        turns a setting the customer explicitly loosened into

            status  : pass
            observed: Enlace por defecto: restringido
                      (valor por defecto de Google, que nadie ha cambiado)

        — a positive claim about their configuration, manufactured by a page
        limit. Losing the page that carries the SYSTEM policies is worse still:
        `policy_engine._root_id` then cannot identify the root unit, no policy
        applies to anybody, and all sixteen console checks fall through to
        assumed defaults at once.

        Every other paginated client here already returns its incompleteness.
        This one now does too.
        """
        policies: list[dict] = []
        page_token: str | None = None
        pagina = 0
        for pagina in range(1, MAX_PAGES + 1):
            params: dict = {"pageSize": PAGE_SIZE}
            if page_token:
                params["pageToken"] = page_token
            data = self._page(version, params)
            policies.extend(data.get("policies", []))
            page_token = data.get("nextPageToken")
            if not page_token:
                break
        return policies, Coverage(
            source="policies",
            pages=pagina,
            records=len(policies),
            complete=not page_token,
            reason=(
                f"se alcanzó el tope de {MAX_PAGES} páginas de políticas y la API seguía "
                "teniendo más; una política que no se lee se evalúa como el valor por "
                "defecto de Google, que es una afirmación sobre tu configuración"
                if page_token
                else ""
            ),
        )


def group_by_setting(policies: list[dict]) -> dict[str, list[dict]]:
    """{setting type -> [{'target': <OU/group label>, 'value': {...}}]}

    Policies can be set per organizational unit or group, so a tenant may
    have several values for one setting. Checks look at all of them: a
    single insecure OU is still an exposure.
    """
    grouped: dict[str, list[dict]] = {}
    for policy in policies:
        setting = policy.get("setting") or {}
        setting_type = setting.get("type")
        if not setting_type:
            continue
        query = policy.get("policyQuery") or {}
        target = query.get("orgUnit") or query.get("group") or "toda la organización"
        grouped.setdefault(setting_type, []).append(
            {"target": target, "value": setting.get("value") or {}}
        )
    return grouped
