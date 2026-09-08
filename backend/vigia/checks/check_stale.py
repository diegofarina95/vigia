"""Stale account hygiene: never-logged-in and suspended-but-present.
Spanish output."""
from __future__ import annotations

from datetime import timedelta

from .finding import Finding
from .util import cap_items, is_active, parse_google_time

#: The data sources this module's findings rest on. `collect_findings`
#: demotes every verdict here to «no verificado» when any of them was read
#: incompletely — inherited, not remembered per check.
SOURCES = ('users',)


CHECK_ID = "stale"

CONSOLE_URL = "https://admin.google.com/ac/users"
CIS = "CIS GWS §1 — Revisar y desactivar cuentas inactivas"

GRACE_DAYS = 14  # newly created accounts get a grace period


def run(ctx) -> list[Finding]:
    grace_cutoff = ctx.now() - timedelta(days=GRACE_DAYS)

    never_logged_in: list[str] = []
    suspended: list[str] = []
    for user in ctx.users():
        if user.get("suspended"):
            suspended.append(user["primaryEmail"])
            continue
        if not is_active(user):
            continue
        last_login = parse_google_time(user.get("lastLoginTime"))
        created = parse_google_time(user.get("creationTime"))
        if last_login is None and (created is None or created < grace_cutoff):
            never_logged_in.append(user["primaryEmail"])

    return [
        Finding(
            id="never-logged-in",
            title="Cuentas activas que nunca han iniciado sesión",
            severity="low",
            status="warn" if never_logged_in else "pass",
            description=(
                f"{len(never_logged_in)} cuentas activas (creadas hace más de {GRACE_DAYS} "
                "días) nunca han iniciado sesión. Normalmente conservan la contraseña inicial "
                "que les puso informática y no tienen 2FA: objetivos fáciles que nadie vigila."
            ),
            affected_items=cap_items(sorted(never_logged_in)),
            remediation="Suspéndelas hasta que la persona necesite la cuenta de verdad.",
            admin_console_url=CONSOLE_URL,
            cis_control=CIS,
            scope_label="cuentas activas de toda la organización",
            accounts=sorted(never_logged_in),
            i18n_params={"count": len(never_logged_in), "grace": GRACE_DAYS},
            remediation_actions=["suspend_never_used"],
        ),
        Finding(
            id="suspended-accounts",
            title="Cuentas suspendidas que siguen existiendo",
            severity="low",
            status="warn" if suspended else "pass",
            description=(
                f"Quedan {len(suspended)} cuentas suspendidas en el directorio. Se pueden "
                "reactivar sin hacer ruido y puede que sigan ocupando licencia, perteneciendo a "
                "grupos y compartiendo datos."
            ),
            affected_items=cap_items(sorted(suspended)),
            remediation=(
                "Para quien ya no está en la empresa: transfiere los datos y elimina la cuenta. "
                "La suspensión debe ser solo un paso temporal de la salida."
            ),
            admin_console_url=CONSOLE_URL,
            cis_control=CIS,
            scope_label="cuentas suspendidas",
            accounts=sorted(suspended),
            i18n_params={"count": len(suspended)},
            remediation_actions=["delete_suspended"],
        ),
    ]
