"""Account-recovery details on privileged accounts.

The side door nobody looks at. Every 2SV control in this suite asks "can an
attacker get in with just the password". Recovery asks the opposite question:
**can the legitimate owner get back in**, and can an attacker use that same
path instead of the front door.

Two failures matter, and they are different:

* **No recovery phone.** If the account is compromised or the second factor
  is lost, there is no self-service way back. For a super admin with no other
  super admin available, the tenant is unrecoverable — Google's account
  recovery for a Workspace super admin without recovery details ends in a
  support process that can take days, if it succeeds at all.
* **Recovery e-mail on a consumer domain.** A `@gmail.com` recovery address
  moves the security of the whole tenant to a mailbox the organization does
  not control, cannot audit and cannot revoke. Whoever owns that inbox can
  reset the super admin. It is the cheapest privilege escalation there is,
  and it survives the employee leaving.

Both fields come from the Directory API (`recoveryEmail`, `recoveryPhone`) and
need no scope beyond `admin.directory.user.readonly`, which the app already
requests.

Honesty guard: Google omits empty fields, so an absent value normally means
"not set". But it would also be absent if the field stopped being returned at
all, and reporting "every admin lacks a recovery phone" because of an API
change would be a spectacular false positive. So if *no* account in the whole
tenant carries either field, the check reports `undetermined` instead of
accusing everyone.
"""
from __future__ import annotations

from .finding import Finding
from .roles import emails, is_admin, super_admins
from .util import cap_items, is_active

#: The data sources this module's findings rest on. `collect_findings`
#: demotes every verdict here to «no verificado» when any of them was read
#: incompletely — inherited, not remembered per check.
SOURCES = ('users',)


CHECK_ID = "recovery"

CONSOLE_URL = "https://admin.google.com/ac/users"
CIS = "CIS GWS §1 — Proteger las cuentas privilegiadas y su recuperación"

# Mailboxes the organization does not control, cannot audit and cannot revoke.
CONSUMER_DOMAINS = frozenset(
    {
        "gmail.com", "googlemail.com", "hotmail.com", "hotmail.co.uk", "outlook.com",
        "outlook.es", "live.com", "live.co.uk", "msn.com", "yahoo.com", "yahoo.es",
        "yahoo.co.uk", "ymail.com", "aol.com", "icloud.com", "me.com", "mac.com",
        "protonmail.com", "proton.me", "gmx.com", "gmx.es", "gmx.de", "mail.ru",
        "yandex.com", "yandex.ru", "zoho.com", "tutanota.com", "fastmail.com",
        "terra.es", "telefonica.net", "hotmail.fr", "libero.it",
    }
)


def _field(user: dict, *names: str) -> str:
    for name in names:
        value = user.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def recovery_email(user: dict) -> str:
    return _field(user, "recoveryEmail", "recovery_email")


def recovery_phone(user: dict) -> str:
    return _field(user, "recoveryPhone", "recovery_phone")


def is_consumer_mailbox(address: str) -> bool:
    if "@" not in address:
        return False
    return address.rsplit("@", 1)[1].strip().lower() in CONSUMER_DOMAINS


def recovery_problems(user: dict) -> list[str]:
    """Human-readable problems with this account's recovery setup."""
    problems = []
    if not recovery_phone(user):
        problems.append("sin teléfono de recuperación")
    address = recovery_email(user)
    if address and is_consumer_mailbox(address):
        domain = address.rsplit("@", 1)[1]
        problems.append(f"correo de recuperación en un dominio personal (@{domain})")
    return problems


def has_insecure_recovery(user: dict) -> bool:
    """The signal the composite engine consumes."""
    return bool(recovery_problems(user))


def fields_present(users: list[dict]) -> bool:
    """Whether the directory is returning the recovery fields at all."""
    return any(recovery_email(u) or recovery_phone(u) for u in users)


def run(ctx) -> list[Finding]:
    users = [u for u in ctx.users() if is_active(u)]
    supers = super_admins(users)

    if not supers:
        return []

    if not fields_present(users):
        return [
            Finding(
                id="recovery-super-admins",
                title="Recuperación de las cuentas de superadministrador",
                severity="critical",
                status="undetermined",
                description=(
                    "Ninguna cuenta del directorio devuelve teléfono ni correo de recuperación. "
                    "Puede que de verdad no estén configurados, o que la API haya dejado de "
                    "devolver esos campos: no se puede distinguir, así que no se acusa a nadie. "
                    "Compruébalo a mano en la ficha de cada superadministrador."
                ),
                remediation=(
                    "Abre Directorio > Usuarios, entra en cada superadministrador y revisa "
                    "«Información de seguridad»: debe tener un teléfono de recuperación "
                    "corporativo y, si usa correo de recuperación, que no sea de un dominio "
                    "personal."
                ),
                admin_console_url=CONSOLE_URL,
                cis_control=CIS,
                scope_label="superadministradores",
                # Without a variant the catalogue would render the failure text
                # over a tenant that has nothing wrong.
                i18n_variant="undetermined",
                details={"super_admins": len(supers), "recovery_fields_returned": False},
            )
        ]

    affected: list[str] = []
    detail_lines: list[str] = []
    no_phone = consumer_mail = 0
    for user in sorted(supers, key=lambda u: u.get("primaryEmail", "")):
        problems = recovery_problems(user)
        if not problems:
            continue
        affected.append(user["primaryEmail"])
        detail_lines.append(f"{user['primaryEmail']}: {', '.join(problems)}")
        if not recovery_phone(user):
            no_phone += 1
        if is_consumer_mailbox(recovery_email(user)):
            consumer_mail += 1

    if affected:
        description = (
            f"{len(affected)} de {len(supers)} superadministradores tienen la recuperación mal "
            "puesta.\n\nSin teléfono de recuperación, perder el segundo factor o sufrir un "
            "secuestro deja la cuenta fuera de alcance: no hay vía de vuelta que no pase por el "
            "soporte de Google, y eso son días. Y un correo de recuperación en un dominio "
            "personal es peor todavía: mueve la seguridad de todo el tenant a un buzón que tu "
            "organización no controla, no puede auditar y no puede revocar. Quien tenga ese "
            "buzón puede restablecer al superadministrador, y sigue pudiendo el día después de "
            "que la persona deje la empresa."
        )
    else:
        description = (
            f"Los {len(supers)} superadministradores tienen teléfono de recuperación y ningún "
            "correo de recuperación en un dominio personal."
        )

    return [
        Finding(
            id="recovery-super-admins",
            title="Recuperación de las cuentas de superadministrador",
            severity="critical",
            status="fail" if affected else "pass",
            description=description,
            affected_items=cap_items(detail_lines),
            remediation=(
                "Pon un teléfono de recuperación corporativo a cada superadministrador y "
                "sustituye cualquier correo de recuperación de dominio personal por uno del "
                "propio dominio (Directorio > Usuarios > la cuenta > Información de seguridad). "
                "Si la cuenta es de emergencia y no tiene persona detrás, guarda sus códigos de "
                "respaldo en el gestor de secretos en lugar de apuntar un buzón particular."
            ),
            admin_console_url=CONSOLE_URL,
            cis_control=CIS,
            scope_label="superadministradores",
            accounts=emails([u for u in supers if has_insecure_recovery(u)]),
            i18n_params={"affected": len(affected), "total": len(supers)},
            i18n_variant="" if affected else "clean",
            details={
                "super_admins": len(supers),
                "without_recovery_phone": no_phone,
                "consumer_recovery_email": consumer_mail,
                "recovery_fields_returned": True,
            },
        )
    ]


def admins_with_insecure_recovery(users: list[dict]) -> list[dict]:
    """Any admin, super or delegated — used by the composite engine."""
    return [u for u in users if is_admin(u) and has_insecure_recovery(u)]
