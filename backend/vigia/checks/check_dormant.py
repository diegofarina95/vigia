"""Dormant accounts: active users with no sign-in for N days. Spanish output."""
from __future__ import annotations

from datetime import timedelta

from .finding import Finding
from .util import cap_items, is_active, parse_google_time

#: The data sources this module's findings rest on. `collect_findings`
#: demotes every verdict here to «no verificado» when any of them was read
#: incompletely — inherited, not remembered per check.
SOURCES = ('users',)


CHECK_ID = "dormant"

CONSOLE_URL = "https://admin.google.com/ac/users"
CIS = "CIS GWS §1 — Revisar y desactivar cuentas inactivas"


def run(ctx) -> list[Finding]:
    days = ctx.settings.dormant_days
    cutoff = ctx.now() - timedelta(days=days)

    dormant: list[tuple[str, str]] = []
    for user in ctx.users():
        if not is_active(user):
            continue
        last_login = parse_google_time(user.get("lastLoginTime"))
        if last_login is not None and last_login < cutoff:
            dormant.append((user["primaryEmail"], last_login.date().isoformat()))

    dormant.sort(key=lambda item: item[1])
    return [
        Finding(
            id="dormant-accounts",
            title=f"Cuentas activas sin iniciar sesión en {days}+ días",
            severity="medium",
            status="fail" if dormant else "pass",
            description=(
                f"{len(dormant)} cuentas habilitadas no han iniciado sesión en más de {days} "
                "días. Las cuentas dormidas son un objetivo preferente: nadie se da cuenta "
                "cuando se ven comprometidas, y además suelen seguir consumiendo licencia."
            ),
            affected_items=cap_items(
                [f"{email} — último inicio de sesión {date}" for email, date in dormant]
            ),
            remediation=(
                "Confírmalo con la persona o su responsable y después suspende la cuenta. "
                "Transfiere los datos y libera la licencia antes de eliminarla."
            ),
            admin_console_url=CONSOLE_URL,
            cis_control=CIS,
            scope_label="cuentas activas de toda la organización",
            accounts=[email for email, _ in dormant],
            i18n_params={"count": len(dormant), "days": days},
            remediation_actions=["suspend_dormant"],
            details={"dormant_days": days, "count": len(dormant)},
        )
    ]
