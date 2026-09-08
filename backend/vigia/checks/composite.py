"""Composite findings: risk that only exists when signals coincide.

All user-facing text is Spanish (the product ships in Spanish); code
identifiers stay English.

The atomic checks each answer one question ("who lacks 2SV?", "who never
signed in?"). An attacker asks a different one: "which single account is
weak in several ways at once?" A super admin with no second factor that
has never been used is not three medium problems — it is a permanent back
door whose misuse nobody can detect, because there is no baseline of
normal activity to compare against.

The engine is declarative on purpose: signals and rules are data, so a
new rule is a tuple, not a new branch.

Every rule an account matches reports that account. An earlier version
attributed each account to the first (most specific) matching rule only,
to avoid double counting — but that made a *false statement* possible:
a super admin with no 2FA who had never signed in was claimed by the
"never signed in" rule and therefore vanished from "Super admin without
2-Step Verification", which then reported PASS while such an account
existed. Findings must state the truth independently; double counting is
prevented downstream, where `scoring.score_breakdown` already counts each
account once at its worst severity.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from .finding import Finding
from .check_recovery import fields_present, has_insecure_recovery
from .roles import is_admin, is_super_admin
from .util import cap_items, is_active, parse_google_time

#: The data sources this module's findings rest on. `collect_findings`
#: demotes every verdict here to «no verificado» when any of them was read
#: incompletely — inherited, not remembered per check.
SOURCES = ('users',)


CHECK_ID = "composite"

# Local parts that normally mean "nobody's mailbox": shared, functional or
# integration accounts.
FUNCTIONAL_LOCAL_PARTS = (
    "admin",
    "administrator",
    "administrador",
    "integrations",
    "integraciones",
    "noreply",
    "no-reply",
    "info",
    "support",
    "soporte",
    "billing",
    "facturacion",
    "accounts",
    "sales",
    "ventas",
    "contact",
    "contacto",
    "service",
    "servicio",
    "api",
    "backup",
    "scanner",
    "printer",
    "impresora",
    "kiosk",
    "shared",
    "test",
)


def _local_part(user: dict) -> str:
    return (user.get("primaryEmail") or "").split("@")[0].strip().lower()


SIGNALS: dict[str, tuple[str, object]] = {
    "super_admin": (
        "es superadministrador",
        lambda user, settings: is_super_admin(user),
    ),
    "any_admin": (
        "tiene privilegios de administrador",
        lambda user, settings: is_admin(user),
    ),
    "no_2sv": (
        "no tiene verificación en dos pasos",
        lambda user, settings: not user.get("isEnrolledIn2Sv"),
    ),
    # Google reports the Unix epoch for accounts that never signed in.
    "never_signed_in": (
        "nunca ha iniciado sesión",
        lambda user, settings: parse_google_time(user.get("lastLoginTime")) is None,
    ),
    "inactive": (
        "no ha iniciado sesión recientemente",
        lambda user, settings: _is_inactive(user, settings),
    ),
    "insecure_recovery": (
        "tiene la recuperación de la cuenta mal puesta",
        lambda user, settings: has_insecure_recovery(user),
    ),
    # Google flags the account as subject to enforcement; the account still
    # has no second factor. On its own that is explained by never signing in,
    # so the rule below pairs it with "has signed in".
    "enforcement_applies": (
        "la obligatoriedad de la 2FA le aplica",
        lambda user, settings: bool(user.get("isEnforcedIn2Sv")),
    ),
    "has_signed_in": (
        "ha iniciado sesión al menos una vez",
        lambda user, settings: parse_google_time(user.get("lastLoginTime")) is not None,
    ),
    "functional_account": (
        "parece una cuenta compartida o funcional",
        lambda user, settings: _local_part(user) in FUNCTIONAL_LOCAL_PARTS,
    ),
}


def _is_inactive(user: dict, settings) -> bool:
    last_login = parse_google_time(user.get("lastLoginTime"))
    if last_login is None:
        return True  # never used is the most inactive an account can be
    from .util import utcnow

    return last_login < utcnow() - timedelta(days=settings.dormant_days)


@dataclass(frozen=True)
class CompositeRule:
    id: str
    signals: tuple[str, ...]
    severity: str
    title: str
    why_worse: str
    remediation: str
    admin_console_url: str
    cis_control: str
    scope_label: str = ""
    remediation_actions: tuple[str, ...] = ()


# Ordered most specific first. Ordering is presentational now (the harshest
# finding reads first); attribution is no longer exclusive.
RULES: tuple[CompositeRule, ...] = (
    CompositeRule(
        id="ENFORCED_BUT_NOT_ENROLLED",
        signals=("enforcement_applies", "has_signed_in", "no_2sv"),
        severity="high",
        title="La 2FA es obligatoria para esta cuenta y aun así entra sin ella",
        scope_label="cuentas activas con obligatoriedad aplicada",
        why_worse=(
            "Esta es la combinación que no debería poder existir, y por eso merece una "
            "mirada aparte: la obligatoriedad de la verificación en dos pasos alcanza a "
            "estas cuentas, el periodo de gracia ya ha pasado, la persona ha iniciado "
            "sesión — y sigue sin segundo factor.\n\nUn informe que enseña «obligatoriedad: "
            "correcta» junto a «N usuarios sin 2FA» deja al lector pensando que una de las "
            "dos cosas está mal medida. No lo está: las dos son ciertas, y lo que hay "
            "entre ellas es una excepción real. Las causas habituales son una unidad "
            "organizativa excluida, una exención por usuario o un acceso que no pasa por "
            "la pantalla de Google (IMAP, POP o una contraseña de aplicación), que es "
            "justamente el camino que la obligatoriedad no cubre."
        ),
        remediation=(
            "Mira cada cuenta en Directorio > Usuarios > Seguridad: comprueba si tiene una "
            "exención de la verificación en dos pasos y si su unidad organizativa está "
            "dentro del ámbito de la obligatoriedad. Revisa también si entra por IMAP, POP "
            "o con una contraseña de aplicación, porque esas vías no pasan por el segundo "
            "factor. Si es una cuenta de servicio, conviértela en cuenta de servicio de "
            "verdad en lugar de dejarla como usuario con contraseña."
        ),
        admin_console_url="https://admin.google.com/ac/security/2sv",
        cis_control="CIS GWS §1 — Verificación en dos pasos obligatoria y sin excepciones",
        remediation_actions=("enforce_2sv_org",),
    ),
    CompositeRule(
        id="SUPERADMIN_NO_2SV_NO_RECOVERY",
        signals=("super_admin", "no_2sv", "insecure_recovery"),
        severity="critical",
        title="Superadministrador sin 2FA y con la recuperación mal puesta",
        scope_label="superadministradores",
        why_worse=(
            "Los dos hechos por separado ya son graves; juntos cierran el círculo. Sin segundo "
            "factor, una contraseña robada por phishing entra directamente. Y con la "
            "recuperación mal puesta, esa entrada se vuelve permanente: si el atacante llega "
            "primero al buzón personal de recuperación, se queda con la cuenta y tú no tienes "
            "vía de vuelta, porque sin teléfono de recuperación la única salida es el soporte "
            "de Google, que tarda días. Es la diferencia entre un incidente y perder el tenant."
        ),
        remediation=(
            "Trata estas cuentas como una emergencia: inscríbelas hoy en la verificación en dos "
            "pasos con llave de seguridad, pon un teléfono de recuperación corporativo y quita "
            "cualquier correo de recuperación que esté en un dominio personal. Asegúrate de que "
            "queda al menos otro superadministrador con 2FA para no quedarte fuera."
        ),
        admin_console_url="https://admin.google.com/ac/security/2sv",
        cis_control=(
            "CIS GWS §1 — Verificación en dos pasos en cuentas privilegiadas + protección de "
            "la recuperación"
        ),
        remediation_actions=("enforce_2sv_org",),
    ),
    CompositeRule(
        id="SUPERADMIN_DORMANT_NO_2SV",
        signals=("super_admin", "no_2sv", "never_signed_in"),
        severity="critical",
        title="Superadministrador sin 2FA que nunca ha iniciado sesión",
        scope_label="superadministradores",
        why_worse=(
            "Cada uno de estos tres hechos es manejable por separado. Juntos son una puerta "
            "trasera permanente: la cuenta tiene control total del tenant, basta con robar su "
            "contraseña para usarla y, como nunca ha iniciado sesión, no existe una línea base "
            "de actividad normal con la que comparar, así que nadie notaría que otra persona "
            "empieza a usarla. Suelen ser restos de la instalación inicial o de migraciones, "
            "sin ningún responsable que las vigile."
        ),
        remediation=(
            "Suspende estas cuentas hoy. Si alguna es realmente necesaria, inscríbela en la "
            "verificación en dos pasos con una llave de seguridad antes de reactivarla y "
            "asígnale un responsable con nombre y apellidos."
        ),
        admin_console_url="https://admin.google.com/ac/users",
        cis_control="CIS GWS §1 — Limitar superadministradores + exigir 2FA + desactivar cuentas inactivas",
        remediation_actions=("enforce_2sv_org", "suspend_unused_admins"),
    ),
    CompositeRule(
        id="SUPERADMIN_NO_2SV",
        signals=("super_admin", "no_2sv"),
        severity="critical",
        title="Superadministrador sin verificación en dos pasos",
        scope_label="superadministradores",
        why_worse=(
            "Un superadministrador puede leer, cambiar o exportar cualquier cosa del tenant, y "
            "puede dejar fuera al resto de administradores. Sin segundo factor, una sola "
            "contraseña robada por phishing equivale al compromiso total del dominio: no hay "
            "segunda línea de defensa."
        ),
        remediation=(
            "Inscribe ya a estos administradores en la verificación en dos pasos, "
            "preferiblemente con llave de seguridad física o passkey, y después actívala de "
            "forma obligatoria para la unidad organizativa de administradores."
        ),
        admin_console_url="https://admin.google.com/ac/security/2sv",
        cis_control="CIS GWS §1 — Verificación en dos pasos en cuentas privilegiadas",
        remediation_actions=("enforce_2sv_org",),
    ),
    CompositeRule(
        id="SUPERADMIN_DORMANT",
        signals=("super_admin", "inactive"),
        severity="high",
        title="Superadministrador sin actividad en {days}+ días",
        scope_label="superadministradores",
        why_worse=(
            "Una cuenta de administrador sin uso conserva el privilegio máximo mientras nadie "
            "la vigila. Su uso indebido no llamaría la atención, porque no hay actividad "
            "reciente con la que contrastarlo."
        ),
        remediation=(
            "Confirma si la cuenta sigue siendo necesaria. Si no lo es, quítale el rol de "
            "administrador y suspéndela; si lo es, mantenla con 2FA y revísala cada trimestre."
        ),
        admin_console_url="https://admin.google.com/ac/roles",
        cis_control="CIS GWS §1 — Limitar superadministradores + revisar cuentas inactivas",
        remediation_actions=("suspend_unused_admins",),
    ),
    CompositeRule(
        id="DORMANT_NO_2SV",
        signals=("no_2sv", "never_signed_in"),
        severity="high",
        title="Cuenta sin 2FA que nunca ha iniciado sesión",
        scope_label="cuentas activas de toda la organización",
        why_worse=(
            "Estas cuentas siguen con la contraseña inicial que les puso informática, no tienen "
            "segundo factor y no hay nadie que entre a diario y note algo raro. Son la vía de "
            "entrada más silenciosa a un tenant."
        ),
        remediation=(
            "Suspéndelas hasta que alguien necesite la cuenta de verdad. Cuando se entregue, "
            "exige la inscripción en 2FA en el primer inicio de sesión."
        ),
        admin_console_url="https://admin.google.com/ac/users",
        cis_control="CIS GWS §1 — Exigir 2FA + desactivar cuentas sin uso",
        remediation_actions=("enforce_2sv_org", "suspend_never_used"),
    ),
    CompositeRule(
        id="SERVICE_ACCOUNT_NO_2SV",
        signals=("no_2sv", "functional_account"),
        severity="high",
        title="Cuenta compartida o funcional sin 2FA",
        scope_label="cuentas compartidas o funcionales (admin@, info@, integraciones@…)",
        why_worse=(
            "Los buzones compartidos (admin@, info@, integraciones@…) suelen tener contraseñas "
            "conocidas por varias personas, guardadas en scripts o documentos, y que casi nunca "
            "se rotan. Sin segundo factor, cualquier filtración de esa contraseña es suficiente; "
            "y como la cuenta es de todos, nadie asume la tarea de vigilarla."
        ),
        remediation=(
            "Inscribe la cuenta en la verificación en dos pasos, o sustitúyela por un grupo o "
            "por acceso delegado para que no exista ninguna contraseña compartida."
        ),
        admin_console_url="https://admin.google.com/ac/security/2sv",
        cis_control="CIS GWS §1 — Exigir 2FA en todas las cuentas",
        remediation_actions=("enforce_2sv_org", "replace_shared_accounts"),
    ),
)


def signals_for(user: dict, settings) -> set[str]:
    """Every signal that holds for one account."""
    return {
        name
        for name, (_, predicate) in SIGNALS.items()
        if predicate(user, settings)  # type: ignore[operator]
    }


def match_rules(users: list[dict], settings) -> dict[str, list[dict]]:
    """{rule id: [{'email', 'signals'}]} — every rule an account matches.

    No early exit: a rule that describes an account must report it, even if
    a more specific rule also does. Otherwise the broader finding claims
    "PASS" while the account it describes exists, which is a false
    statement in the report. Per-account de-duplication happens in scoring.
    """
    matches: dict[str, list[dict]] = {}
    # "No recovery phone" is inferred from the field being absent, and it
    # would also be absent if the Directory API stopped returning it at all.
    # In that case the signal would fire for every account and light up the
    # harshest composite for the whole tenant, so it is dropped instead of
    # trusted. `check_recovery` applies the same guard to its own finding.
    recovery_readable = fields_present(users)
    for user in users:
        if not is_active(user):
            continue
        held = signals_for(user, settings)
        if not recovery_readable:
            held.discard("insecure_recovery")
        for rule in RULES:
            if set(rule.signals) <= held:
                matches.setdefault(rule.id, []).append(
                    {"email": user["primaryEmail"], "signals": sorted(held)}
                )
    return matches


def _describe(rule: CompositeRule, entries: list[dict]) -> str:
    labels = " + ".join(SIGNALS[name][0] for name in rule.signals)
    if not entries:
        return f"Ninguna cuenta cumple a la vez: {labels}."
    plural = "s" if len(entries) != 1 else ""
    return (
        f"{len(entries)} cuenta{plural} cumple{'n' if entries and len(entries) != 1 else ''} "
        f"a la vez: {labels}.\n\n"
        f"Por qué esto es peor que los hallazgos por separado: {rule.why_worse}"
    )


def run(ctx) -> list[Finding]:
    users = ctx.users()
    matches = match_rules(users, ctx.settings)

    findings: list[Finding] = []
    for rule in RULES:
        entries = matches.get(rule.id, [])
        findings.append(
            Finding(
                id=f"composite-{rule.id.lower().replace('_', '-')}",
                # Titles may carry {days} so they state the threshold that was
                # actually applied rather than a hardcoded 90.
                title=rule.title.format(days=ctx.settings.dormant_days),
                severity=rule.severity,
                status="fail" if entries else "pass",
                description=_describe(rule, entries),
                affected_items=cap_items([entry["email"] for entry in entries]),
                accounts=[entry["email"] for entry in entries],
                remediation=rule.remediation,
                admin_console_url=rule.admin_console_url,
                cis_control=rule.cis_control,
                scope_label=rule.scope_label,
                remediation_actions=list(rule.remediation_actions),
                i18n_variant="" if entries else "clean",
                i18n_params={"count": len(entries), "days": ctx.settings.dormant_days},
                details={
                    "rule": rule.id,
                    "signals": list(rule.signals),
                    "dormant_days": ctx.settings.dormant_days,
                },
            )
        )
    return findings
