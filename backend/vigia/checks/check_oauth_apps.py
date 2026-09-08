"""Risky third-party OAuth apps, from Reports API 'token' events.
Spanish output.

Aggregates authorize events (last ~180 days) per client app, classifies
the risk of each granted scope, and surfaces domain-wide delegation
grants observed in the admin audit log.
"""
from __future__ import annotations

from ..wording import con_numero

from ..google_client.reports import event_parameters
from .finding import ORG_SCOPE, Finding
from .util import cap_items

#: The data sources this module's findings rest on. `collect_findings`
#: demotes every verdict here to «no verificado» when any of them was read
#: incompletely — inherited, not remembered per check.
SOURCES = ('token',)


CHECK_ID = "oauth-apps"

CONSOLE_URL = "https://admin.google.com/ac/owl/list?tab=apps"
DWD_CONSOLE_URL = "https://admin.google.com/ac/owl/domainwidedelegation"
CIS = "CIS GWS §2 — Controlar el acceso de aplicaciones de terceros a los datos de Google"

_HIGH_RISK = (
    "https://mail.google.com/",
    "auth/gmail",  # any gmail.* scope
    "auth/admin.directory",  # directory write or read
    "auth/admin.datatransfer",
    "auth/cloud-platform",
    "auth/apps.groups",
)
_HIGH_RISK_EXACT_SUFFIXES = ("auth/drive", "auth/drive.readonly", "auth/contacts")
_MEDIUM_RISK_SUFFIXES = (
    "auth/calendar",
    "auth/spreadsheets",
    "auth/documents",
    "auth/drive.metadata.readonly",
)


def scope_risk(scope: str) -> str | None:
    """'high' | 'medium' | None for a single OAuth scope."""
    lowered = scope.lower().strip()
    if any(pattern in lowered for pattern in _HIGH_RISK):
        # readonly admin scopes are still sensitive but not tenant-write
        if "admin." in lowered and lowered.endswith(".readonly"):
            return "medium"
        return "high"
    if any(lowered.endswith(suffix) for suffix in _HIGH_RISK_EXACT_SUFFIXES):
        return "high"
    if any(lowered.endswith(suffix) for suffix in _MEDIUM_RISK_SUFFIXES):
        return "medium"
    return None


def aggregate_token_events(items: list[dict]) -> dict[str, dict]:
    """{client_id: {name, scopes:set, users:set}} from 'token' activities."""
    apps: dict[str, dict] = {}
    for item in items:
        actor = (item.get("actor") or {}).get("email", "unknown")
        for event in item.get("events", []) or []:
            if event.get("name") != "authorize":
                continue
            params = event_parameters(event)
            client_id = str(params.get("client_id", "unknown"))
            app = apps.setdefault(
                client_id,
                {
                    "name": params.get("app_name") or client_id,
                    "client_id": client_id,
                    "scopes": set(),
                    "users": set(),
                },
            )
            scopes = params.get("scope", [])
            if isinstance(scopes, str):
                scopes = [scopes]
            app["scopes"].update(scopes)
            app["users"].add(actor)
    return apps


def _unnamed(app: dict) -> bool:
    """Google sometimes returns `app_name` equal to the numeric client id.

    There is no name to look up: the Reports API has none, and the Directory
    endpoint that does (`users/{id}/tokens`, which carries `displayText`)
    needs `admin.directory.user.security`, a scope this product deliberately
    does not request. So the row says so instead of presenting a 21-digit
    number as if it were an answer.
    """
    return str(app["name"]) == str(app.get("client_id", app["name"]))


def _fmt_app(app: dict, risky_scopes: list[str] | None = None) -> str:
    scopes = risky_scopes if risky_scopes is not None else sorted(app["scopes"])
    shown = ", ".join(s.rsplit("/", 1)[-1] for s in scopes[:4])
    if len(scopes) > 4:
        shown += f" (+{len(scopes) - 4})"
    nombre = (
        f"aplicación sin nombre (id {app['name']})" if _unnamed(app) else str(app["name"])
    )
    return f"{nombre} — {con_numero(len(app['users']), 'usuario')} — permisos: {shown}"


PARCIAL = (
    "\n\nVENTANA INCOMPLETA. Solo se han podido leer los últimos {dias_txt} del "
    "registro de autorizaciones ({eventos} eventos en {paginas} páginas), no los ~180 "
    "que conserva Google: {reason}.\n\nLo de arriba es lo que se vio en esos {dias} "
    "días, no todo lo que hay. Los eventos llegan del más reciente al más antiguo, así "
    "que lo que queda fuera es el pasado — y una aplicación autorizada hace meses y "
    "nunca revocada es justo lo que no aparecería. Por eso este hallazgo sale como no "
    "verificado en lugar de correcto o fallo: «no he visto nada» y «no he podido "
    "mirar» no son lo mismo, y sobre datos incompletos solo se puede afirmar lo "
    "segundo."
)


def _aviso_parcial(cobertura) -> str:
    dias_valor = getattr(cobertura, "window_days", None)
    return PARCIAL.format(
        # A template cannot make the noun agree with its own placeholder, so the
        # agreed phrase is built here. `dias` stays for the second, bare mention.
        dias_txt=(
            con_numero(dias_valor, "día") if isinstance(dias_valor, int) else "? días"
        ),
        dias=dias_valor or "?",
        eventos=getattr(cobertura, "records", 0),
        paginas=getattr(cobertura, "pages", 0),
        reason=getattr(cobertura, "reason", "") or "no se pudo recorrer toda la ventana",
    )


def _ventana(ctx) -> str:
    """The window actually read, in words. Never a number written by hand."""
    cobertura = (getattr(ctx, "coverage", {}) or {}).get("token")
    if cobertura is None:
        return "una ventana sin medir del registro de autorizaciones"
    dias = cobertura.window_days
    if dias is None:
        return f"{cobertura.records} eventos de autorización"
    return f"los últimos {con_numero(dias, 'día')} del registro de autorizaciones"


def _grants_to_apps(grants: dict) -> dict[str, dict]:
    """Adapt the folded grants to the shape this module already used."""
    return {
        client_id: {
            "name": grant.name,
            "client_id": client_id,
            "scopes": set(grant.scopes),
            "users": grant.accounts,
        }
        for client_id, grant in grants.items()
    }


def run(ctx) -> list[Finding]:
    apps = _grants_to_apps(ctx.token_grants())
    completo = ctx.complete("token")
    aviso = "" if completo else _aviso_parcial(ctx.coverage.get("token"))
    threshold = ctx.settings.widely_granted_threshold

    high_risk_apps: list[str] = []
    widely_granted: list[str] = []
    sin_nombre = 0
    for app in apps.values():
        if _unnamed(app):
            sin_nombre += 1
        risky = sorted(s for s in app["scopes"] if scope_risk(s) == "high")
        if risky:
            high_risk_apps.append(_fmt_app(app, risky))
        elif len(app["users"]) >= threshold:
            widely_granted.append(_fmt_app(app))

    findings = [
        Finding(
            scope_type=ORG_SCOPE,
            id="oauth-high-risk",
            title="Aplicaciones de terceros con permisos de alto riesgo",
            severity="high",
            status=("fail" if high_risk_apps else "pass") if completo else "undetermined",
            description=(
                f"{len(high_risk_apps)} aplicaciones de terceros tienen permisos que dan acceso "
                "amplio al contenido de Gmail, a todo Drive, a las APIs de administración o a "
                "recursos de Cloud. Una brecha en cualquiera de esos proveedores se convierte en "
                "una brecha de tus datos. "
                f"(Basado en {_ventana(ctx)}; se han visto {len(apps)} aplicaciones.)"
                + (
                    f"\n\n{sin_nombre} de ellas salen solo con su identificador numérico: "
                    "Google no devuelve ningún nombre para esas aplicaciones en el registro de "
                    "auditoría, y Vigía no pide el permiso que haría falta para consultarlo "
                    "(lectura de los tokens de cada usuario). Para identificarlas, busca el "
                    "identificador en Seguridad > Controles de API > Control de acceso de "
                    "aplicaciones, que sí muestra el nombre y el editor."
                    if sin_nombre
                    else ""
                )
                + aviso
            ),
            affected_items=cap_items(sorted(high_risk_apps)),
            remediation=(
                "Revisa cada aplicación en Seguridad > Controles de API > Control de acceso de "
                "aplicaciones. Bloquea las que no reconozcas y pon el acceso de aplicaciones en "
                "«restringido» para que las nuevas autorizaciones de alto riesgo necesiten "
                "aprobación del administrador."
            ),
            admin_console_url=CONSOLE_URL,
            cis_control=CIS,
            scope_label="aplicaciones de terceros autorizadas por usuarios",
            coverage_note=_ventana(ctx),
            remediation_actions=["restrict_app_access"],
            i18n_params={"count": len(high_risk_apps), "apps_seen": len(apps)},
            details={"apps_seen": len(apps), "high_risk": len(high_risk_apps)},
        ),
        Finding(
            scope_type=ORG_SCOPE,
            id="oauth-widely-granted",
            title="Aplicaciones autorizadas por muchos usuarios",
            severity="medium",
            status=("warn" if widely_granted else "pass") if completo else "undetermined",
            description=(
                f"{len(widely_granted)} aplicaciones han sido autorizadas por {threshold} o más "
                "usuarios. Que una aplicación sin validar se use de forma masiva multiplica el "
                "alcance del daño si se ve comprometida."
                + aviso
            ),
            affected_items=cap_items(sorted(widely_granted)),
            scope_label="aplicaciones de terceros autorizadas por usuarios",
            coverage_note=_ventana(ctx),
            remediation_actions=["restrict_app_access"],
            i18n_params={"count": len(widely_granted), "threshold": threshold},
            remediation=(
                "Valida las aplicaciones de uso extendido (proveedor, tratamiento de datos, "
                "necesidad real) y marca la decisión como de confianza o bloqueada en el Control "
                "de acceso de aplicaciones."
            ),
            admin_console_url=CONSOLE_URL,
            cis_control=CIS,
        ),
    ]

    # Domain-wide delegation grants visible in the admin audit log.
    dwd_grants: list[str] = []
    for item in ctx.admin_events():
        when = (item.get("id") or {}).get("time", "")[:10]
        actor = (item.get("actor") or {}).get("email", "unknown")
        for event in item.get("events", []) or []:
            if event.get("name") == "AUTHORIZE_API_CLIENT_ACCESS":
                params = event_parameters(event)
                client = params.get("API_CLIENT_NAME", "cliente desconocido")
                scopes = params.get("API_SCOPES", [])
                if isinstance(scopes, str):
                    scopes = [scopes]
                dwd_grants.append(
                    f"{when}: {client} recibió {con_numero(len(scopes), "permiso")}, concedidos por {actor}"
                )

    findings.append(
        Finding(
            depends_on=("admin",),
            scope_type=ORG_SCOPE,
            id="oauth-dwd",
            title="Concesiones de delegación en todo el dominio",
            severity="high",
            status="warn" if dwd_grants else "undetermined",
            description=(
                "La delegación en todo el dominio permite que una cuenta de servicio suplante a "
                "CUALQUIER usuario para los permisos concedidos: es la concesión más poderosa de "
                "Workspace. "
                + (
                    f"Se han observado {con_numero(len(dwd_grants), "evento")} de concesión en la ventana de "
                    "auditoría."
                    if dwd_grants
                    else f"No hay eventos de concesión en la ventana leída ({_ventana(ctx)}), "
                    "pero pueden existir concesiones más antiguas: verifica la lista actual en la "
                    "Consola de Administración."
                )
            ),
            affected_items=cap_items(dwd_grants),
            scope_label="clientes con delegación en todo el dominio",
            remediation_actions=["review_dwd"],
            i18n_variant="" if dwd_grants else "clean",
            i18n_params={"count": len(dwd_grants)},
            remediation=(
                "Revisa Seguridad > Controles de API > Delegación en todo el dominio. Elimina los "
                "clientes que no reconozcas y reduce los permisos al mínimo."
            ),
            admin_console_url=DWD_CONSOLE_URL,
            cis_control=CIS,
        )
    )
    return findings
