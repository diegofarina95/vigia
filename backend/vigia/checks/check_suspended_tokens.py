"""Third-party access that a suspension may not have taken away.

Suspending someone closes the front door: they cannot sign in. What is much
less obvious is what happens to the applications they had already connected —
the CRM, the mail plug-in, the backup tool — each of which holds its own
credential and talks to Google without the person being present.

**What this check does NOT claim.** Google documents that a password change
revokes OAuth tokens; it does not document what a suspension does to them, and
this product cannot look inside Google to find out. Asserting "these tokens
are still live" would be inventing the part that matters.

So the finding states only what is on the record and can be checked by the
reader: this account was suspended, it had authorised these applications, and
**no revocation was ever recorded** for them. Whether the grant still works is
exactly the question the admin should settle by revoking it — which costs a
minute and is the right move regardless of the answer.

Both sides come from data already fetched: the directory for who is suspended,
and the `token` audit log for authorize and revoke events. No new scope.
"""
from __future__ import annotations

from ..wording import con_numero

from .finding import Finding
from .util import cap_items

#: The data sources this module's findings rest on. `collect_findings`
#: demotes every verdict here to «no verificado» when any of them was read
#: incompletely — inherited, not remembered per check.
SOURCES = ('users', 'token')


CHECK_ID = "suspended-with-tokens"

CONSOLE_URL = "https://admin.google.com/ac/owl/list?tab=apps"
CIS = "CIS GWS §3 — Retirar el acceso de terceros al dar de baja a alguien"


def run(ctx) -> list[Finding]:
    suspendidas = {
        u.get("primaryEmail", "").lower()
        for u in ctx.users()
        if u.get("suspended") and u.get("primaryEmail")
    }
    if not suspendidas:
        return [
            Finding(
                # No suspended accounts means the question is answered from the
                # directory alone, and the token feed is irrelevant to it. The
                # card used to say "no suspended account has grants pending"
                # AND carry an inherited "cannot verify" from a source it did
                # not need — asserting and retracting in the same block.
                depends_on=("users",),
                id=CHECK_ID,
                title="Aplicaciones conectadas por cuentas suspendidas",
                severity="critical",
                status="pass",
                description=(
                    "No hay ninguna cuenta suspendida, así que no hay accesos de terceros "
                    "heredados de una baja que revisar."
                ),
                remediation=(
                    "Cuando suspendas a alguien, revoca también sus aplicaciones conectadas "
                    "en el mismo paso: la suspensión y el acceso de terceros son dos cosas "
                    "distintas."
                ),
                admin_console_url=CONSOLE_URL,
                cis_control=CIS,
                scope_label="cuentas suspendidas",
                i18n_variant="clean",
            )
        ]

    try:
        concesiones = ctx.token_grants()
    except Exception:  # noqa: BLE001 — the OAuth card already explains this
        concesiones = None

    # An incomplete window is the worst possible place for a false pass: the
    # events arrive newest-first, so what falls off the end is exactly the old
    # grant nobody remembers making.
    if concesiones is not None and not ctx.complete("token"):
        cobertura = ctx.coverage.get("token")
        motivo = getattr(cobertura, "reason", "") or "no se pudo recorrer toda la ventana"
        return [
            Finding(
                id=CHECK_ID,
                title="Aplicaciones conectadas por cuentas suspendidas",
                severity="critical",
                status="undetermined",
                description=(
                    f"Hay {con_numero(len(suspendidas), "cuenta suspendida", "cuentas suspendidas")}, pero la ventana de "
                    f"autorizaciones no se ha podido leer completa ({motivo}).\n\nAquí eso "
                    "importa más que en otros sitios: los eventos llegan del más reciente al "
                    "más antiguo, así que lo que falta es el pasado — y una aplicación "
                    "autorizada hace meses por alguien que ya no está es exactamente lo que "
                    "este chequeo busca. Decir «no hay nada» sobre una ventana recortada "
                    "sería el peor falso negativo del informe."
                ),
                remediation=(
                    "Revisa a mano en Seguridad > Controles de API > Gestionar el acceso de "
                    "aplicaciones de terceros, filtrando por las cuentas suspendidas."
                ),
                admin_console_url=CONSOLE_URL,
                cis_control=CIS,
                scope_label="cuentas suspendidas",
                i18n_variant="undetermined",
                details={"suspended": len(suspendidas), "coverage_complete": False},
            )
        ]

    if not concesiones:
        return [
            Finding(
                id=CHECK_ID,
                title="Aplicaciones conectadas por cuentas suspendidas",
                severity="critical",
                status="undetermined",
                description=(
                    "Hay cuentas suspendidas, pero no se ha podido leer el registro de "
                    "autorizaciones OAuth, así que no se puede decir qué aplicaciones tenían "
                    "conectadas ni si se revocaron."
                ),
                remediation="Comprueba que la cuenta conectada tiene privilegios de Informes.",
                admin_console_url=CONSOLE_URL,
                cis_control=CIS,
                scope_label="cuentas suspendidas",
                i18n_variant="undetermined",
            )
        ]

    lineas: list[str] = []
    afectadas: list[str] = []
    for cuenta in sorted(suspendidas):
        vivas = [g for g in concesiones.values() if g.still_granted_for(cuenta)]
        if not vivas:
            continue
        afectadas.append(cuenta)
        nombres = ", ".join(sorted(str(g.name) for g in vivas)[:4])
        if len(vivas) > 4:
            nombres += f" (+{len(vivas) - 4})"
        lineas.append(f"{cuenta}: {len(vivas)} aplicación(es) sin revocar — {nombres}")

    if not lineas:
        return [
            Finding(
                id=CHECK_ID,
                title="Aplicaciones conectadas por cuentas suspendidas",
                severity="critical",
                status="pass",
                description=(
                    f"Ninguna de las {len(suspendidas)} cuentas suspendidas tiene "
                    "autorizaciones de terceros pendientes de revocar en el registro."
                ),
                remediation=(
                    "Sigue haciéndolo así: revocar las aplicaciones conectadas en el mismo "
                    "paso que la suspensión."
                ),
                admin_console_url=CONSOLE_URL,
                cis_control=CIS,
                scope_label="cuentas suspendidas",
                i18n_variant="clean",
                details={"suspended": len(suspendidas), "with_grants": 0},
            )
        ]

    return [
        Finding(
            id=CHECK_ID,
            title="Aplicaciones conectadas por cuentas suspendidas",
            severity="critical",
            status="fail",
            description=(
                f"{len(afectadas)} de las {len(suspendidas)} cuentas suspendidas autorizaron "
                "aplicaciones de terceros y no consta que esas autorizaciones se revocaran "
                "nunca.\n\nSuspender cierra la puerta de delante: esa persona ya no puede "
                "iniciar sesión. Las aplicaciones que conectó son otra cosa — cada una "
                "guarda su propia credencial y habla con Google sin que ella esté presente. "
                "Es la vía de acceso que sobrevive a una baja porque nadie la asocia con la "
                "baja.\n\nPara ser exactos: Vigía no puede mirar dentro de Google para "
                "confirmar si esas credenciales siguen funcionando, y Google no documenta "
                "qué le hace una suspensión a un token OAuth (sí documenta que un cambio de "
                "contraseña los revoca). Lo que sí consta es que la autorización se concedió "
                "y que no hay ninguna revocación posterior en el registro. Revocarlas cuesta "
                "un minuto y resuelve la duda en la dirección segura."
            ),
            affected_items=cap_items(lineas),
            accounts=sorted(afectadas),
            remediation=(
                "Seguridad > Controles de API > Gestionar el acceso de aplicaciones de "
                "terceros: busca cada aplicación y retira el acceso de esas cuentas. "
                "Añádelo además a tu proceso de baja, junto a la suspensión y al cierre de "
                "sesiones: son tres acciones distintas y solo una la hace el botón de "
                "suspender."
            ),
            admin_console_url=CONSOLE_URL,
            cis_control=CIS,
            scope_label="cuentas suspendidas",
            i18n_params={"count": len(afectadas), "suspended": len(suspendidas)},
            details={
                "suspended": len(suspendidas),
                "with_grants": len(afectadas),
            },
        )
    ]
