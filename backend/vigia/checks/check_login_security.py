"""Sign-in security, from the Reports API 'login' audit log. Spanish output.

Uses only reports.audit.readonly (already granted). Surfaces the security
signals Google itself raises — compromised/hijacked accounts, leaked
passwords, government-backed attack warnings and suspicious sign-ins —
plus brute-force-looking failure bursts.
"""
from __future__ import annotations

from ..wording import con_numero

from collections import Counter

from ..google_client.base import GoogleApiError
from .finding import Finding
from .util import cap_items

#: The data sources this module's findings rest on. `collect_findings`
#: demotes every verdict here to «no verificado» when any of them was read
#: incompletely — inherited, not remembered per check.
SOURCES = ('login',)


CHECK_ID = "login-security"

CONSOLE_URL = "https://admin.google.com/ac/reporting/audit/login"
ALERT_URL = "https://admin.google.com/ac/ac/alert"
CIS = "CIS GWS §1 — Vigilar los inicios de sesión y las alertas de seguridad de cuentas"

# Reports 'login' event names that mean Google already flagged a
# compromise. Matched as substrings to stay robust to naming variants.
_COMPROMISE_MARKERS = (
    "password_leak",
    "hijack",
    "gov_attack",
    "government_attack",
    "account_disabled_generic",
)
_SUSPICIOUS_MARKERS = ("suspicious_login",)


def _by_user(items: list[dict], predicate) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for item in items:
        actor = (item.get("actor") or {}).get("email", "unknown")
        for event in item.get("events", []) or []:
            name = (event.get("name") or "").lower()
            if predicate(name):
                counts[actor] += 1
    return dict(counts)


def _undetermined(reason: str) -> list[Finding]:
    return [
        Finding(
            id="login-security",
            title="Alertas de seguridad de inicio de sesión",
            severity="high",
            status="undetermined",
            description=f"No se ha podido leer el registro de inicios de sesión ({reason}).",
            i18n_params={"reason": reason},
            remediation=(
                "Comprueba que el administrador conectado tiene privilegios de Informes."
            ),
            admin_console_url=CONSOLE_URL,
            cis_control=CIS,
        )
    ]


def run(ctx) -> list[Finding]:
    try:
        items = ctx.login_events()
    except GoogleApiError as exc:
        return _undetermined(exc.message)

    compromised = _by_user(items, lambda n: any(m in n for m in _COMPROMISE_MARKERS))
    suspicious = _by_user(items, lambda n: any(m in n for m in _SUSPICIOUS_MARKERS))
    failures = _by_user(items, lambda n: n == "login_failure")
    # A burst of failures against one account looks like password guessing.
    brute_force = {user: count for user, count in failures.items() if count >= 10}

    def listed(counts: dict[str, int]) -> list[str]:
        return cap_items(
            [
                f"{user} — {con_numero(count, 'evento')}"
                for user, count in sorted(counts.items(), key=lambda kv: -kv[1])
            ]
        )

    return [
        Finding(
            id="login-compromised",
            title="Cuentas que Google ha marcado como comprometidas",
            severity="critical",
            status="fail" if compromised else "pass",
            description=(
                "La propia detección de Google ha desactivado o señalado estas cuentas por "
                "contraseña filtrada, secuestro o ataque patrocinado por un estado. Trátalas "
                "como comprometidas hasta demostrar lo contrario."
                if compromised
                else "No hay alertas de contraseña filtrada, secuestro ni ataque en la ventana "
                "de auditoría."
            ),
            affected_items=listed(compromised),
            scope_label="toda la organización (registro de inicios de sesión)",
            accounts=sorted(compromised),
            remediation_actions=["reset_compromised_accounts"],
            i18n_variant="" if compromised else "clean",
            i18n_params={"count": len(compromised)},
            remediation=(
                "Restablece la contraseña, revoca las sesiones y los tokens de aplicaciones, y "
                "vuelve a verificar la 2FA de cada cuenta. Consulta el Centro de alertas para "
                "el contexto completo."
            ),
            admin_console_url=ALERT_URL,
            cis_control=CIS,
        ),
        Finding(
            id="login-suspicious",
            title="Actividad de inicio de sesión sospechosa",
            severity="high",
            status="warn" if suspicious else "pass",
            description=(
                f"Google ha marcado como sospechosos los inicios de sesión de "
                f"{con_numero(len(suspicious), "cuenta")} (ubicación, dispositivo o patrón inusual)."
                if suspicious
                else "Ningún inicio de sesión se ha marcado como sospechoso en la ventana de "
                "auditoría."
            ),
            affected_items=listed(suspicious),
            scope_label="toda la organización (registro de inicios de sesión)",
            accounts=sorted(suspicious),
            remediation_actions=["enforce_2sv_org"],
            i18n_variant="" if suspicious else "clean",
            i18n_params={"count": len(suspicious)},
            remediation=(
                "Confirma la actividad con cada persona. Si no la reconoce, restablece las "
                "credenciales y exige 2FA. Valora usar el Acceso Contextual para limitar desde "
                "dónde se puede iniciar sesión."
            ),
            admin_console_url=CONSOLE_URL,
            cis_control=CIS,
        ),
        Finding(
            id="login-brute-force",
            title="Posible adivinación de contraseñas (ráfagas de intentos fallidos)",
            severity="medium",
            status="warn" if brute_force else "pass",
            description=(
                f"{con_numero(len(brute_force), "cuenta")} acumulan 10 o más inicios de sesión fallidos en "
                "la ventana de auditoría, lo que puede indicar que alguien está probando "
                "contraseñas."
                if brute_force
                else "Ninguna cuenta muestra una ráfaga inusual de inicios de sesión fallidos."
            ),
            affected_items=listed(brute_force),
            scope_label="toda la organización (registro de inicios de sesión)",
            accounts=sorted(brute_force),
            remediation_actions=["enforce_2sv_org"],
            i18n_variant="" if brute_force else "clean",
            i18n_params={"count": len(brute_force)},
            remediation=(
                "Exige la 2FA (así acertar la contraseña deja de ser suficiente) y valora "
                "requisitos de contraseña más estrictos o el Acceso Contextual."
            ),
            admin_console_url=CONSOLE_URL,
            cis_control=CIS,
        ),
    ]
