"""Backup codes: the second factor that undoes the second factor.

A hardware key cannot be phished. Ten printed backup codes can — they are just
strings, they never expire, and anybody holding one signs in without touching
the key. Handing a super admin a security key and then generating backup codes
for the same account leaves the account exactly as strong as the weakest of the
two, which is the paper.

The signal comes from the admin audit log (`GENERATE_2SV_SCRATCH_CODES`), which
this product already reads. What it cannot see is which second factor each
person actually uses: the directory reports *whether* someone is enrolled, not
*how*. So this check reports the generation and says plainly that it cannot
confirm the rest, rather than asserting a combination it has not observed.
"""
from __future__ import annotations

from ..wording import con_numero

from datetime import timedelta

from .finding import Finding
from .roles import is_admin, is_super_admin
from .util import cap_items, is_active, parse_google_time, utcnow

#: The data sources this module's findings rest on. `collect_findings`
#: demotes every verdict here to «no verificado» when any of them was read
#: incompletely — inherited, not remembered per check.
SOURCES = ('users', 'admin')


CHECK_ID = "2sv-backup-codes"

EVENT = "GENERATE_2SV_SCRATCH_CODES"
CONSOLE_URL = "https://admin.google.com/ac/users"
CIS = "CIS GWS §1 — Segundo factor resistente al phishing en cuentas privilegiadas"

#: Codes do not expire, so age is not what matters — but a code generated
#: years ago on an account nobody uses is a different conversation from one
#: generated last month. This is the window that gets called out.
RECENT_DAYS = 180


def _generations(items: list[dict]) -> dict[str, list]:
    """{account: [when, …]} for every backup-code generation in the log."""
    out: dict[str, list] = {}
    for item in items or []:
        names = {(e.get("name") or "").upper() for e in item.get("events") or []}
        if EVENT not in names:
            continue
        when = parse_google_time((item.get("id") or {}).get("time"))
        # The audit log records who performed it; the parameter carries who it
        # was done to, and they are often different people.
        objetivo = ""
        for event in item.get("events") or []:
            for param in event.get("parameters") or []:
                if param.get("name") in ("USER_EMAIL", "user_email"):
                    objetivo = str(param.get("value") or "").lower()
        actor = ((item.get("actor") or {}).get("email") or "").lower()
        cuenta = objetivo or actor
        if cuenta and when:
            out.setdefault(cuenta, []).append(when)
    return out


def run(ctx) -> list[Finding]:
    users = [u for u in ctx.users() if is_active(u)]
    if not users:
        return []
    por_correo = {u.get("primaryEmail", "").lower(): u for u in users}

    try:
        items = ctx.admin_events()
    except Exception:  # noqa: BLE001 — the audit card already explains this
        return []

    generado = _generations(items)
    if not generado:
        return [
            Finding(
                id="2sv-backup-codes",
                title="Códigos de respaldo de la verificación en dos pasos",
                severity="high",
                status="pass",
                description=(
                    "No consta ninguna generación de códigos de respaldo en el registro de "
                    "administración. Es la respuesta que se quiere: los códigos son un "
                    "segundo factor de papel que no caduca y que sí se puede phishear."
                ),
                remediation=(
                    "Nada que hacer. Si alguna vez hacen falta como vía de emergencia, "
                    "revócalos en cuanto la persona recupere su llave."
                ),
                admin_console_url=CONSOLE_URL,
                cis_control=CIS,
                scope_label="cuentas activas",
                i18n_variant="clean",
            )
        ]

    corte = utcnow() - timedelta(days=RECENT_DAYS)
    privilegiadas: list[str] = []
    # Everyone this finding is about, not just the privileged subset. The
    # subset decides the STATUS (a live code on an account that can change
    # everything is a failure, on anyone else a warning); it does not decide
    # who the finding names. Putting only the admins in `accounts` left the
    # other four listed on the card and absent from "people at risk" and from
    # the score table — the finding said one thing and the summary another.
    afectadas: list[str] = []
    lineas: list[str] = []
    for cuenta, momentos in sorted(generado.items()):
        user = por_correo.get(cuenta)
        if user is None:
            continue  # ya no existe o está suspendida: no hay nada que actuar
        reciente = [m for m in momentos if m >= corte]
        etiqueta = "superadministrador" if is_super_admin(user) else (
            "administrador delegado" if is_admin(user) else "usuario"
        )
        ultima = max(momentos).strftime("%Y-%m-%d")
        lineas.append(
            f"{cuenta} ({etiqueta}): {len(momentos)} generación(es), la última el {ultima}"
        )
        afectadas.append(cuenta)
        if reciente and is_admin(user):
            privilegiadas.append(cuenta)

    status = "fail" if privilegiadas else "warn"
    description = (
        f"Se han generado códigos de respaldo para {con_numero(len(lineas), "cuenta")}.\n\n"
        "Un código de respaldo es una cadena impresa: no caduca, se puede dictar por "
        "teléfono y se puede pedir en una página de phishing igual que una contraseña. "
        "Mientras siga vivo, es una vía de entrada que no pasa por la llave de seguridad "
        "— de modo que la cuenta vale lo que valga el más débil de sus dos factores, y "
        "ese es el papel."
    )
    if privilegiadas:
        description += (
            f"\n\n{len(privilegiadas)} de esas cuentas tienen privilegios de administrador y "
            f"la generación es de los últimos {RECENT_DAYS} días. Ahí la diferencia importa: "
            "un código vivo en una cuenta que puede cambiarlo todo anula buena parte de lo "
            "que aporta haber repartido llaves."
        )
    description += (
        "\n\nUn matiz honesto: Vigía ve que se generaron códigos, pero no puede ver qué "
        "segundo factor usa cada persona — el directorio dice si alguien está inscrito, no "
        "cómo. Así que no afirma que exista una llave de seguridad detrás; confírmalo tú al "
        "revisar la lista."
    )

    return [
        Finding(
            id="2sv-backup-codes",
            title="Códigos de respaldo de la verificación en dos pasos",
            severity="high",
            status=status,
            description=description,
            affected_items=cap_items(lineas),
            accounts=sorted(afectadas),
            remediation=(
                "Directorio > Usuarios > la cuenta > Seguridad > Códigos de verificación de "
                "respaldo: revoca los que sigan vivos en las cuentas con privilegios. Si "
                "hacen falta como vía de emergencia, genéralos en el momento y revócalos "
                "después, en lugar de dejarlos activos de forma indefinida."
            ),
            admin_console_url=CONSOLE_URL,
            cis_control=CIS,
            scope_label="cuentas con códigos de respaldo generados",
            i18n_params={"count": len(lineas), "privileged": len(privilegiadas)},
            details={
                "accounts_with_codes": len(lineas),
                "privileged_recent": len(privilegiadas),
                "window_days": RECENT_DAYS,
            },
        )
    ]
