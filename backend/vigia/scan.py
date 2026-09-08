"""Scan orchestrator: runs every registered check against one org and
persists the result. One failing check never aborts the scan — it becomes
an `undetermined` finding instead."""
from __future__ import annotations

import logging
from dataclasses import replace
from datetime import datetime, timezone

from . import dns_email_auth
from .checks import ALL_CHECKS
from .checks.consistency import check_consistency
from .engine_version import engine_version
from .checks.finding import Finding
from .checks.manual import MANUAL_CHECKS
from .config import Settings
from .delta import detect_regressions
from .db import Database
from .scoring import compute_score, severity_counts

log = logging.getLogger(__name__)


class ScanContext:
    """Lazily fetches and caches the API data shared across checks, so
    e.g. users are listed once even though four checks consume them."""

    def __init__(
        self,
        directory,
        reports,
        settings: Settings,
        custom_domains: list[str] | None = None,
        include_directory_domains: bool = True,
        policy=None,
        resolver=None,
        grant_store=None,
    ) -> None:
        self._directory = directory
        self._reports = reports
        self._policy = policy
        #: Persisted OAuth picture, so each scan reads only what is new.
        #: `(load() -> dict, save(grants, watermark, oldest) -> None)`, or None
        #: for the demo, which has no history to accumulate.
        self._grant_store = grant_store
        # None = real public DNS. The demo passes a fake zone so it can never
        # depend on the network or leak a lookup for an invented domain.
        self._resolver = resolver
        self.settings = settings
        self._custom_domains = custom_domains or []
        # False in mock mode: the demo tenant's fake domains must never be
        # DNS-checked — only domains the user explicitly configured are.
        self.include_directory_domains = include_directory_domains
        self._users: list[dict] | None = None
        self.users_truncated = False
        self._domains: list[dict] | None = None
        self.domains_truncated = False
        self._grants: dict | None = None
        #: {source: Coverage} — how much of each data source was actually
        #: read. `users_truncated` used to be set here and read nowhere, which
        #: is how a partial directory could produce a confident report. Every
        #: source now lands in one place and the checks consult it.
        self.coverage: dict = {}
        self._token_events: list[dict] | None = None
        self._admin_events: list[dict] | None = None
        self._login_events: list[dict] | None = None
        self._email_auth: list[dict] | None = None
        self._policies: list[dict] | None = None

    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _record(self, source: str, records: int, complete: bool, reason: str,
                pages: int = 0, oldest: str = "", newest: str = "") -> None:
        from .google_client.grants import Coverage

        self.coverage[source] = Coverage(
            source=source, pages=pages, records=records, complete=complete,
            oldest=oldest, newest=newest, reason="" if complete else reason,
        )

    def complete(self, source: str) -> bool:
        """Whether a source was read in full.

        **An unmeasured source is NOT complete.** The previous default said the
        opposite — "unknown sources count as read" — and that single line was
        the mechanism by which every source nobody had wired up became an
        assertion. A developer who wrote `if not ctx.complete("login")` got
        True for ever and shipped a guard that could never fire.

        Failing closed costs a spurious "cannot determine" the first time
        somebody adds a source and forgets to record it. Failing open costs a
        green tick on a tenant nobody looked at. Those are not comparable.
        """
        cobertura = self.coverage.get(source)
        return bool(cobertura.complete) if cobertura is not None else False

    def measured(self, source: str) -> bool:
        """Whether anybody recorded coverage for this source at all."""
        return source in self.coverage

    def users(self) -> list[dict]:
        if self._users is None:
            self._users, self.users_truncated = self._directory.list_users()
            self._record("users", len(self._users), not self.users_truncated,
                         "se alcanzó el tope de páginas del directorio")
        return self._users

    def domains(self) -> list[dict]:
        if self._domains is None:
            resultado = self._directory.list_domains()
            # Mock and demo clients still return a bare list.
            if isinstance(resultado, tuple):
                self._domains, self.domains_truncated = resultado
            else:
                self._domains, self.domains_truncated = resultado, False
            self._record("domains", len(self._domains), not self.domains_truncated,
                         "se alcanzó el tope de páginas de dominios")
        return self._domains

    def token_grants(self) -> dict:
        """The accumulated OAuth picture: what is stored, plus what is new.

        Re-reading Google's whole 180-day window every scan does not work at
        ~1600 authorize events a day — twenty pages of a thousand bought six
        days, and three findings went from saying something wrong to saying
        nothing. So the fold is persisted and only events after the watermark
        are fetched: measured, two hours of this feed is 247 events in one page
        and 0.3 s, complete.

        The consequence for honesty is the interesting part. The window is no
        longer "as far back as one scan could page"; it is "everything since we
        started looking", which GROWS. Coverage reports that accumulated window
        and `complete=True` means "we have every event in it", which is a claim
        the checks can safely affirm over — provided they say which window,
        which is what `_ventana()` in `check_oauth_apps` prints.
        """
        if self._grants is not None:
            return self._grants

        from .google_client.grants import (
            Coverage,
            dehydrate as _dehydrate,
            fold,
            merge as _merge,
            rehydrate as _rehydrate,
        )

        if not hasattr(self._reports, "token_grants"):
            # Mock/demo clients only expose the raw events, and the fixture IS
            # the whole tenant.
            eventos = self._reports.token_activities()
            self._grants = fold(eventos)
            self.coverage["token"] = Coverage(
                source="token", pages=1, records=len(eventos), complete=True
            )
            return self._grants

        guardado = self._grant_store.load() if self._grant_store else {}
        acumulado = _rehydrate(guardado.get("grants") or {})
        marca = guardado.get("watermark") or ""
        antiguo = guardado.get("oldest") or ""

        nuevos, cobertura = self._reports.token_grants(start_time=marca)
        _merge(acumulado, nuevos)

        # The watermark only moves forward, and only to something we actually
        # read: on an empty page it stays put rather than skipping a gap.
        if cobertura.newest and cobertura.newest > marca:
            marca = cobertura.newest
        if cobertura.oldest and (not antiguo or cobertura.oldest < antiguo):
            antiguo = cobertura.oldest

        if self._grant_store:
            self._grant_store.save(_dehydrate(acumulado), marca, antiguo)

        self.coverage["token"] = replace(
            cobertura,
            records=sum(len(g.users) for g in acumulado.values()),
            oldest=antiguo,
            newest=marca,
            # Incomplete only if THIS incremental read hit the cap: everything
            # before the watermark is already in hand.
            complete=cobertura.complete,
            reason=cobertura.reason,
        )
        self._grants = acumulado
        return self._grants

    def _activity(self, source: str, fetch) -> list[dict]:
        """An activity feed plus the coverage the client already measured.

        `ReportsClient` has computed a `Coverage` for every paginated call for
        a while; nothing read it. The measurement existed and was thrown away,
        which is the same defect as not measuring but harder to notice.
        """
        items = fetch()
        medida = getattr(self._reports, "last_coverage", None)
        if medida is not None and medida.source in (source, "token", "admin", "login"):
            self.coverage[source] = replace(medida, source=source)
        else:
            # Mock and demo clients do not paginate; one shot is the whole set.
            self._record(source, len(items), True, "", pages=1)
        return items

    def token_events(self) -> list[dict]:
        if self._token_events is None:
            self._token_events = self._activity("token", self._reports.token_activities)
        return self._token_events

    def admin_events(self) -> list[dict]:
        if self._admin_events is None:
            self._admin_events = self._activity("admin", self._reports.admin_activities)
        return self._admin_events

    def login_events(self) -> list[dict]:
        if self._login_events is None:
            self._login_events = self._activity("login", self._reports.login_activities)
        return self._login_events

    def policies(self) -> list[dict]:
        """Admin console settings. Raises PolicyUnavailable when the scope
        or API is missing, so the check can explain what to enable."""
        from .google_client.policy import PolicyUnavailable

        if self._policy is None:
            raise PolicyUnavailable(
                "not_configured", "Policy reading is not available in this mode."
            )
        if self._policies is None:
            resultado = self._policy.list_policies()
            if isinstance(resultado, tuple):
                self._policies, cobertura = resultado
                self.coverage["policies"] = cobertura
            else:
                # Demo/mock clients return a bare list and are complete by
                # construction: the fixture IS the whole tenant.
                self._policies = resultado
                self._record("policies", len(self._policies), True, "", pages=1)
        return self._policies

    def email_domains(self) -> list[str]:
        """Domains to DNS-check: the org's verified Google domains (real
        mode) plus every user-configured domain, deduplicated."""
        targets: list[str] = []
        seen: set[str] = set()
        if self.include_directory_domains:
            for entry in self.domains():
                name = entry.get("domainName")
                if name and entry.get("verified", True) and name not in seen:
                    seen.add(name)
                    targets.append(name)
        for name in self._custom_domains:
            if name not in seen:
                seen.add(name)
                targets.append(name)
        return targets

    def email_auth_reports(self) -> list[dict]:
        if self._email_auth is None:
            self._email_auth = [
                dns_email_auth.check_domain(
                    d,
                    resolver=self._resolver,
                    selectors=self.settings.dkim_selectors,
                )
                for d in self.email_domains()
            ]
        return self._email_auth


def collect_findings(ctx: ScanContext, label: str = "") -> list[Finding]:
    """Run every check, then verify the result does not contradict itself.

    A failing check becomes an `undetermined` finding instead of aborting the
    scan. No database involved, so the demo can use the exact same path as a
    real scan — and, because the coherence check lives here rather than in
    `run_scan`, no caller can produce a report that skipped it.
    """
    findings: list[Finding] = []
    for check in ALL_CHECKS:
        try:
            producidos = list(check.run(ctx))
            findings.extend(
                _inherit_uncertainty(producidos, getattr(check, "SOURCES", ()), ctx)
            )
        except Exception as exc:  # noqa: BLE001 — one check must not kill the scan
            log.exception("check %s failed", check.CHECK_ID)
            findings.append(
                Finding(
                    id=f"{check.CHECK_ID}-error",
                    title=f"La comprobación «{check.CHECK_ID}» no se ha podido ejecutar",
                    severity="info",
                    status="undetermined",
                    description=f"La comprobación dio un error y se ha omitido: {exc}",
                )
            )
    findings.extend(consistency_diagnostic(findings, label))
    return findings


#: What an inherited demotion says. Deliberately concrete about WHICH source
#: and WHY, because "no verificado" without a reason reads as a broken tool.
_HEREDADO = (
    "\n\nESTE VEREDICTO NO SE SOSTIENE. La comprobación depende de {fuentes}, y "
    "{verbo} leerse de forma incompleta ({motivo}).\n\nNo se ha podido evaluar sobre "
    "todos los datos, así que no se afirma ni que esté bien ni que esté mal. Un "
    "«correcto» aquí sería un correcto ganado por no haber mirado, que es la única "
    "clase de error que esta herramienta no se puede permitir."
)

_NOMBRE_FUENTE = {
    "users": "el directorio de usuarios",
    "domains": "la lista de dominios verificados",
    "token": "el registro de autorizaciones OAuth",
    "admin": "el registro de auditoría de administración",
    "login": "el registro de inicios de sesión",
    "policies": "los ajustes de la Consola de Administración",
}


def _inherit_uncertainty(
    findings: list[Finding], module_sources: tuple, ctx: ScanContext
) -> list[Finding]:
    """Demote any verdict resting on a source that was read incompletely.

    This is the structural half of the fix. Before it, thirteen of sixteen
    modules answered "pass" when their source came back empty or short, and the
    only defence was remembering to check coverage inside each one — which two
    modules did and fourteen did not. Measured on a real tenant with the user
    list truncated at its page cap: nine findings flipped from fail or warn to
    PASS, including a critical one.

    Inheritance rather than diligence: a check declares what it reads (module
    `SOURCES`, or `Finding.depends_on` when one module's findings rest on
    different things) and the demotion happens here, once, for everybody. A new
    check gets the guarantee by existing.
    """
    salida: list[Finding] = []
    for finding in findings:
        fuentes = tuple(finding.depends_on) or tuple(module_sources)
        incompletas = [f for f in fuentes if not ctx.complete(f)]
        if not incompletas or finding.status == "undetermined":
            salida.append(finding)
            continue

        nombres = ", ".join(_NOMBRE_FUENTE.get(f, f) for f in incompletas)
        motivos = "; ".join(
            (ctx.coverage[f].reason or "no se pudo recorrer la fuente completa")
            for f in incompletas
            if f in ctx.coverage
        ) or "la fuente no se midió, así que no se puede afirmar que se leyera entera"
        salida.append(
            replace(
                finding,
                status="undetermined",
                description=finding.description + _HEREDADO.format(
                    fuentes=nombres,
                    verbo="ha podido" if len(incompletas) == 1 else "han podido",
                    motivo=motivos,
                ),
                details={
                    **(finding.details or {}),
                    "demoted_from": finding.status,
                    "incomplete_sources": list(incompletas),
                },
            )
        )
    return salida


def consistency_diagnostic(findings: list[Finding], label: str = "") -> list[Finding]:
    """Empty list when the findings are coherent; one visible finding when not.

    A self-contradicting report destroys trust in every other finding on the
    page, so coherence is verified on every scan. The scan is not aborted —
    that would throw away real results — instead the problem is logged loudly
    and surfaced to the reader, while the test suite keeps it from ever
    shipping in the first place.
    """
    violations = check_consistency(findings)
    if not violations:
        return []
    log.error(
        "INCOHERENCIA en el escaneo de %s: %s",
        label or "(sin etiqueta)",
        " | ".join(violations),
    )
    return [
        Finding(
            id="internal-consistency",
            title="Incoherencia interna detectada en este escaneo",
            severity="info",
            status="undetermined",
            description=(
                "Dos o más hallazgos de este informe se contradicen entre sí, así que "
                "alguna de sus afirmaciones es falsa. Es un error de Vigía, no de tu "
                "configuración: no interpretes los hallazgos implicados hasta que se "
                "corrija.\n\n" + "\n".join(f"· {v}" for v in violations)
            ),
            remediation=(
                "Avisa al equipo de Vigía con la fecha de este escaneo. El resto de "
                "hallazgos no está afectado."
            ),
            scope_label="diagnóstico interno",
        )
    ]


def run_scan(org: dict, ctx: ScanContext, db: Database) -> dict:
    findings = collect_findings(ctx, label=org.get("primary_domain", ""))

    # Keep the stored domain list in sync with the Workspace directory. This is
    # now the ONLY way a domain gets into the list: the panel that let one be
    # added by hand is gone, along with the POST route behind it. Rows added by
    # hand before that are deliberately left in place and still checked.
    if ctx.include_directory_domains:
        try:
            names = [
                d["domainName"]
                for d in ctx.domains()
                if d.get("verified", True) and d.get("domainName")
            ]
            db.sync_google_domains(org["id"], names)
        except Exception:  # noqa: BLE001 — sync must not break the scan
            log.exception("could not sync Google domains")

    # Regressions are escalated BEFORE scoring, so the stored score always
    # matches the severities the reader sees.
    history = db.findings_history(org["id"], limit=10)
    previous = history[0] if history else None
    regressions = detect_regressions(findings, previous, history[1:])
    if regressions:
        log.info("escalated %d regression(s) for %s", len(regressions), org["primary_domain"])

    score = compute_score(findings)
    counts = severity_counts(findings)
    rendered = [f.to_dict() for f in findings]
    scan = db.insert_scan(
        org_id=org["id"],
        score=score,
        counts=counts,
        findings=rendered,
        manual_checks=remaining_manual_checks(findings),
        # Recorded so a later delta can refuse to compare across engines.
        engine_version=engine_version(),
        result=evaluated_result(rendered, score, counts, ctx),
    )
    return scan


def evaluated_result(findings: list[dict], score, counts: dict, ctx) -> dict:
    """Everything derived from a scan, computed once, at scan time.

    Every channel used to re-derive this per request: the dashboard, the
    printable report, the CSV and the alert e-mail each called their own subset
    of `score_breakdown`, `people_at_risk`, `rank_actions` and `executive`. Two
    consequences, both observed in production rather than imagined:

    * the CSV exported 45 findings while the screen showed 50, because the two
      were built by different code from the same row;
    * a single page printed two different scores — the stored one and a
      recomputed one — because the 24-hour purge removes the accounts the
      recomputation counts, so from the second day the same findings score
      differently. Measured: 50 stored against 38 recomputed.

    Derived once and stored, the channels become projections and there is
    nothing left to diverge. Coverage travels with it because a verdict without
    its provenance is the thing this whole exercise exists to stop.
    """
    from .executive import summary as executive_summary
    from .remediation import rank_actions
    from .scoring import people_at_risk, score_breakdown

    acciones = rank_actions(findings, limit=3)
    personas = people_at_risk(findings)
    return {
        "score": score,
        "counts": counts,
        "breakdown": score_breakdown(findings),
        "people_at_risk": personas,
        "actions": acciones,
        "executive": executive_summary(findings, personas, score, acciones),
        "coverage": {
            nombre: cobertura.as_dict()
            for nombre, cobertura in (getattr(ctx, "coverage", {}) or {}).items()
        },
    }


def remaining_manual_checks(findings: list[Finding]) -> list[dict]:
    """Drop manual cards whose automated counterpart produced a conclusive
    result, so the manual list only ever shows what still needs a human."""
    settled = {
        finding.id for finding in findings if finding.status != "undetermined"
    }
    return [
        check
        for check in MANUAL_CHECKS
        if check.get("automated_by") not in settled
    ]
