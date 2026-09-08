"""Super-admin sprawl (and single-admin lockout risk). Spanish output."""
from __future__ import annotations

from .finding import Finding
from .roles import delegated_admins, emails, super_admins
from .util import cap_items, is_active

#: The data sources this module's findings rest on. `collect_findings`
#: demotes every verdict here to «no verificado» when any of them was read
#: incompletely — inherited, not remembered per check.
SOURCES = ('users',)


CHECK_ID = "super-admins"

CONSOLE_URL = "https://admin.google.com/ac/roles"
CIS = "CIS GWS §1 — Limitar las cuentas de superadministrador (2-4 recomendadas)"


def run(ctx) -> list[Finding]:
    users = [u for u in ctx.users() if is_active(u)]
    supers = emails(super_admins(users))
    delegated = emails(delegated_admins(users))
    threshold = ctx.settings.super_admin_threshold

    count = len(supers)
    variant = "over" if count > threshold else "single" if count < 2 else "ok"
    if count > threshold:
        status, description = "warn", (
            f"Hay {count} cuentas de superadministrador (umbral: {threshold}). Cada "
            "superadministrador es un objetivo de máximo impacto; Google y CIS recomiendan "
            "entre 2 y 4."
        )
    elif count < 2:
        status, description = "warn", (
            f"Solo existe {count} cuenta de superadministrador. Si se pierde o se ve "
            "comprometida no hay un segundo administrador para recuperar el control: Google "
            "recomienda tener al menos 2."
        )
    else:
        status, description = "pass", (
            f"{count} cuentas de superadministrador: dentro del rango recomendado "
            f"(2-{threshold})."
        )

    return [
        Finding(
            id="super-admin-count",
            title="Número de cuentas de superadministrador",
            severity="high",
            status=status,
            description=description,
            affected_items=cap_items(supers),
            remediation=(
                "Mantén entre 2 y 4 superadministradores. Pasa la administración del día a día "
                "a roles delegados con el mínimo privilegio necesario (Cuenta > Roles de "
                "administrador)."
            ),
            admin_console_url=CONSOLE_URL,
            cis_control=CIS,
            scope_label="superadministradores",
            accounts=supers,
            remediation_actions=["reduce_super_admins"],
            i18n_variant=variant,
            i18n_params={"count": count, "threshold": threshold},
            details={"super_admins": count, "threshold": threshold},
        ),
        Finding(
            id="delegated-admins",
            title="Cuentas de administrador delegado (inventario)",
            severity="info",
            status="pass",
            description=(
                f"{len(delegated)} cuentas de administrador delegado. Es informativo: revisa que "
                "cada rol siga siendo necesario y esté ajustado al mínimo privilegio."
            ),
            affected_items=cap_items(delegated),
            remediation="Revisa la asignación de roles en Cuenta > Roles de administrador.",
            scope_label="administradores delegados",
            i18n_params={"count": len(delegated)},
            admin_console_url=CONSOLE_URL,
            cis_control=CIS,
        ),
    ]
