"""Admin audit log: confirm it is reachable, surface recent changes, and
flag risky administrative changes recorded in the window. Spanish output.

The audit log records CHANGES, not the current default state, so this
never claims a setting is safe — it only raises the changes that deserve
a look."""
from __future__ import annotations

from ..wording import con_numero

from ..google_client.base import GoogleApiError
from .finding import ORG_SCOPE, Finding
from .util import window_label, cap_items

#: The data sources this module's findings rest on. `collect_findings`
#: demotes every verdict here to «no verificado» when any of them was read
#: incompletely — inherited, not remembered per check.
SOURCES = ('admin',)


CHECK_ID = "audit-log"

CONSOLE_URL = "https://admin.google.com/ac/reporting/audit"
CIS = "CIS GWS §1 — Revisar los registros de auditoría con regularidad"

# Risk categories detected by substring match on the event name, so we are
# robust to Google's exact naming. Each: (label, (markers…), severity).
_RISK_CATEGORIES: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("Se abrió el uso compartido externo", ("SHARING", "OUTSIDE_DOMAIN", "EXTERNAL"), "high"),
    ("Se cambió el reenvío automático de correo", ("FORWARDING",), "high"),
    (
        "Se debilitó la verificación en dos pasos o la autenticación fuerte",
        ("2SV", "STRONG_AUTH", "ENFORCE_STRONG"),
        "critical",
    ),
    (
        "Se concedieron privilegios de administrador",
        ("ASSIGN_ROLE", "GRANT", "PRIVILEGE", "CREATE_ROLE"),
        "high",
    ),
    (
        "Se permitió acceso menos seguro o heredado",
        ("LESS_SECURE", "ALLOW_SERVICE", "BASIC_AUTH", "IMAP", "POP"),
        "medium",
    ),
    (
        "Se cambió el acceso o la lista de permitidos de aplicaciones",
        ("ALLOWLIST", "TRUST", "API_ACCESS", "OAUTH2", "MARKETPLACE"),
        "medium",
    ),
    ("Se suspendió o eliminó una cuenta", ("SUSPEND_USER", "DELETE_USER", "DELETE_ACCOUNT"), "medium"),
)
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def run(ctx) -> list[Finding]:
    try:
        items = ctx.admin_events()
    except GoogleApiError as exc:
        return [
            Finding(
                scope_type=ORG_SCOPE,
                id="audit-admin-log",
                title="Acceso al registro de auditoría de administración",
                severity="info",
                status="undetermined",
                description=(
                    f"No se ha podido leer el registro de auditoría de administración "
                    f"({exc.message}). Comprueba que el administrador conectado tiene "
                    "privilegios de Informes."
                ),
                admin_console_url=CONSOLE_URL,
                cis_control=CIS,
                i18n_variant="error",
                i18n_params={"reason": exc.message},
            )
        ]

    # One console action can emit the same event many times in the same
    # minute — signing a user out writes RESET_SIGNIN_COOKIES once per
    # session. Fifteen identical rows push everything else off the list and
    # read as fifteen separate events, so identical ones are collapsed with a
    # count. Grouped by minute, not by hour: two bursts an hour apart are two
    # things that happened, and merging them would hide the second.
    agrupados: dict[tuple, int] = {}
    for item in items:
        when = (item.get("id") or {}).get("time", "")[:16].replace("T", " ")
        actor = (item.get("actor") or {}).get("email", "desconocido")
        names = tuple(e.get("name", "?") for e in item.get("events", []) or [])[:3]
        agrupados[(when, actor, names)] = agrupados.get((when, actor, names), 0) + 1

    recent: list[str] = []
    for (when, actor, names), veces in list(agrupados.items())[:15]:
        etiqueta = ", ".join(names)
        if veces > 1:
            etiqueta += f" ×{veces}"
        recent.append(f"{when} — {actor} — {etiqueta}")

    # Bucket every admin change into risk categories by event-name markers.
    hits: dict[str, list[str]] = {}
    worst = "info"
    for item in items:
        when = (item.get("id") or {}).get("time", "")[:10]
        actor = (item.get("actor") or {}).get("email", "desconocido")
        for event in item.get("events", []) or []:
            name = (event.get("name") or "").upper()
            for label, markers, severity in _RISK_CATEGORIES:
                if any(marker in name for marker in markers):
                    hits.setdefault(label, []).append(f"{when} — {actor} — {event.get('name')}")
                    if _SEVERITY_RANK[severity] < _SEVERITY_RANK[worst]:
                        worst = severity
                    break

    risky_items: list[str] = []
    for label, events in sorted(hits.items(), key=lambda kv: -len(kv[1])):
        risky_items.append(f"{label}: {con_numero(len(events), "cambio")}")
        risky_items.extend(f"    {e}" for e in events[:3])

    total_changes = sum(len(v) for v in hits.values())
    return [
        Finding(
            scope_type=ORG_SCOPE,
            id="audit-admin-log",
            title="Acceso al registro de auditoría de administración",
            severity="info",
            status="pass",
            description=(
                "El registro de auditoría de administración es accesible. Abajo se listan los "
                "cambios recientes en la Consola de Administración: revisa cualquiera que no "
                "reconozcas."
            ),
            affected_items=cap_items(recent),
            scope_label="registro de auditoría de administración",
            coverage_note=window_label(ctx, "admin", ""),
            remediation=(
                "Configura reglas de alerta para los eventos de administración sensibles "
                "(Seguridad > Centro de alertas, Informes > Auditoría e investigación)."
            ),
            admin_console_url=CONSOLE_URL,
            cis_control=CIS,
            i18n_params={"count": len(items)},
            details={"recent_events": len(items)},
        ),
        Finding(
            scope_type=ORG_SCOPE,
            id="audit-risky-changes",
            title="Cambios de administración de riesgo en la ventana de auditoría",
            # No hits is NOT a pass — the window is bounded and only records
            # changes — so it is 'undetermined', never a clean bill of health.
            severity=worst if hits else "info",
            status="warn" if hits else "undetermined",
            description=(
                f"Se han registrado {con_numero(total_changes, 'cambio')} en "
                f"{len(hits)} categoría{'s' if len(hits) != 1 else ''} de riesgo. El registro de "
                "auditoría recoge cambios, no el estado actual por defecto, así que revisa cada "
                "uno y confirma que fue intencionado."
                if hits
                else "No se ha registrado ningún cambio de configuración de riesgo en la ventana "
                "de auditoría. Esto no confirma que los ajustes sean seguros: para los valores "
                "por defecto que no se pueden leer, mira las comprobaciones manuales."
            ),
            affected_items=cap_items(risky_items),
            scope_label="registro de auditoría de administración",
            coverage_note=window_label(ctx, "admin", ""),
            i18n_variant="" if hits else "clean",
            i18n_params={"changes": total_changes, "categories": len(hits)},
            remediation=(
                "Para cada cambio, confirma quién lo hizo y por qué. Añade reglas de alerta para "
                "estos tipos de evento en el Centro de alertas."
            ),
            admin_console_url=CONSOLE_URL,
            cis_control=CIS,
        ),
    ]
