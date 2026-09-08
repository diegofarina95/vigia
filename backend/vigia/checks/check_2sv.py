"""2-Step Verification enrollment and enforcement (Spanish output)."""
from __future__ import annotations

from .finding import Finding
from .roles import delegated_admins, emails
from .util import cap_items, is_active

#: The data sources this module's findings rest on. `collect_findings`
#: demotes every verdict here to «no verificado» when any of them was read
#: incompletely — inherited, not remembered per check.
SOURCES = ('users',)


CHECK_ID = "2sv"

CONSOLE_URL = "https://admin.google.com/ac/security/2sv"
CIS = "CIS GWS §1 — Verificación en dos pasos"


def run(ctx) -> list[Finding]:
    users = [u for u in ctx.users() if is_active(u)]
    # Super admins are covered by their own findings. This one owns DELEGATED
    # admins only, and `is_delegated_admin` excludes super admins by
    # construction, so the two populations are disjoint.
    delegated = delegated_admins(users)

    admins_without = emails([u for u in delegated if not u.get("isEnrolledIn2Sv")])
    users_without = sorted(
        u["primaryEmail"] for u in users if not u.get("isEnrolledIn2Sv")
    )
    not_enforced = [u for u in users if not u.get("isEnforcedIn2Sv")]

    return [
        Finding(
            id="2sv-delegated-admins",
            title="Administrador delegado sin verificación en dos pasos",
            severity="critical",
            status="fail" if admins_without else "pass",
            description=(
                "Los administradores delegados pueden gestionar usuarios, restablecer "
                "contraseñas o cambiar ajustes de servicios: sin segundo factor, una sola "
                "contraseña robada por phishing basta para usar esos privilegios. Los "
                "superadministradores se evalúan aparte, en sus propios hallazgos."
            ),
            affected_items=cap_items(admins_without),
            remediation=(
                "Inscribe ya a estos administradores en 2FA (Seguridad > Verificación en dos "
                "pasos) y después hazla obligatoria para su unidad organizativa. Para "
                "administradores, usa preferiblemente llaves de seguridad o passkeys."
            ),
            admin_console_url=CONSOLE_URL,
            cis_control=CIS,
            scope_label="administradores delegados",
            accounts=admins_without,
            remediation_actions=["enforce_2sv_org"],
            details={
                "delegated_admin_count": len(delegated),
                "without_2sv": len(admins_without),
            },
        ),
        Finding(
            id="2sv-users",
            title="Usuarios sin la verificación en dos pasos configurada",
            severity="high",
            status="fail" if users_without else "pass",
            description=(
                f"{len(users_without)} de {len(users)} usuarios activos no se han inscrito en la "
                "verificación en dos pasos. Las cuentas que solo dependen de una contraseña son "
                "la vía de entrada más habitual para el robo de cuentas."
            ),
            affected_items=cap_items(users_without),
            remediation=(
                "Lanza una campaña de inscripción y después activa la 2FA obligatoria para toda "
                "la organización con un periodo de gracia (Seguridad > Verificación en dos pasos "
                "> Obligatoriedad)."
            ),
            admin_console_url=CONSOLE_URL,
            cis_control=CIS,
            scope_label="toda la organización (todas las cuentas activas)",
            accounts=users_without,
            remediation_actions=["enforce_2sv_org"],
            i18n_params={"without": len(users_without), "total": len(users)},
            details={"total_active_users": len(users), "without_2sv": len(users_without)},
        ),
        Finding(
            id="2sv-enforcement",
            title="Cuentas fuera del alcance de la obligatoriedad de 2FA",
            severity="medium",
            status="warn" if not_enforced else "pass",
            description=(
                "Este hallazgo mide una cosa concreta y distinta de la tarjeta «Obligatoriedad "
                "de la 2FA» de los ajustes: aquella dice si la obligatoriedad está configurada, "
                "y esta dice a cuántas cuentas les alcanza de verdad.\n\n"
                f"{len(not_enforced)} cuentas activas quedan fuera de su ámbito, así que "
                "inscribirse les sigue siendo voluntario y pueden quitarse el segundo factor "
                "cuando quieran."
            ),
            affected_items=cap_items(sorted(u["primaryEmail"] for u in not_enforced)),
            remediation=(
                "Activa la obligatoriedad de la 2FA en todas las unidades organizativas "
                "(Seguridad > Verificación en dos pasos > Obligatoriedad > Activada)."
            ),
            admin_console_url=CONSOLE_URL,
            cis_control=CIS,
            scope_label="toda la organización (todas las cuentas activas)",
            accounts=sorted(u["primaryEmail"] for u in not_enforced),
            remediation_actions=["enforce_2sv_org"],
            i18n_params={"count": len(not_enforced)},
        ),
    ]
