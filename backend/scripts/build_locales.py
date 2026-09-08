"""Builds vigia/locales/{es,en}.json from a single bilingual table.

English is BRITISH — organisation, authorise, recognise, enrolment — with ONE
deliberate exception: anything Google names in its own console keeps Google's
spelling. "Organizational unit", "enrollment period" and "license" are what the
administrator reads on screen, and a report that sends somebody to
"Directory > Organisational units" when the menu says "Organizational units" has
broken a navigation instruction to win a spelling argument. `test_bilingue.py`
encodes both halves of that rule.

Kept as one table on purpose: two separate JSON files drift apart the first
time someone edits only one of them. The generator is the source of truth;
run it after changing any finding text.

Each value is a ``(es, en)`` pair. CIS entries translate the description
after the dash but never the control identifier itself.
"""
from __future__ import annotations

import json
import os

ES, EN = 0, 1

# --------------------------------------------------------------- labels

SEVERITY = {
    "critical": ("crítico", "critical"),
    "high": ("alto", "high"),
    "medium": ("medio", "medium"),
    "low": ("bajo", "low"),
    "info": ("informativo", "info"),
}

STATUS = {
    "pass": ("Correcto", "Pass"),
    "fail": ("Fallo", "Fail"),
    "warn": ("Aviso", "Warn"),
    "undetermined": ("No verificado", "Not verified"),
}

# Scopes reused across findings.
S_SUPER = ("superadministradores", "super admins")
S_DELEG = ("administradores delegados", "delegated admins")
S_ORG = (
    "toda la organización (todas las cuentas activas)",
    "whole organisation (all active accounts)",
)
S_ACTIVE = ("cuentas activas de toda la organización", "active accounts, organisation-wide")
S_LOGIN = (
    "toda la organización (registro de inicios de sesión)",
    "whole organisation (sign-in audit log)",
)
S_APPS = (
    "aplicaciones de terceros autorizadas por usuarios",
    "third-party apps authorised by users",
)
S_AUDIT = (
    "registro de auditoría de administración",
    "admin audit log",
)
S_DOMAINS = (
    "{domains} dominio(s) configurado(s), por DNS público",
    "{domains} configured domain(s), via public DNS",
)
S_POLICY = ("ajustes de la Consola de Administración", "Admin console settings")

# CIS: identifier stays, description translates.
CIS_2SV = ("CIS GWS §1 — Verificación en dos pasos", "CIS GWS §1 — 2-Step Verification")
CIS_2SV_PRIV = (
    "CIS GWS §1 — Verificación en dos pasos en cuentas privilegiadas",
    "CIS GWS §1 — 2-Step Verification on privileged accounts",
)
CIS_SUPER = (
    "CIS GWS §1 — Limitar las cuentas de superadministrador (2-4 recomendadas)",
    "CIS GWS §1 — Limit super-admin accounts (2-4 recommended)",
)
CIS_INACTIVE = (
    "CIS GWS §1 — Revisar y desactivar cuentas inactivas",
    "CIS GWS §1 — Review and disable inactive accounts",
)
CIS_LOGIN = (
    "CIS GWS §1 — Vigilar los inicios de sesión y las alertas de seguridad de cuentas",
    "CIS GWS §1 — Monitor sign-in and account security alerts",
)
CIS_APPS = (
    "CIS GWS §2 — Controlar el acceso de aplicaciones de terceros a los datos de Google",
    "CIS GWS §2 — Control third-party app access to Google data",
)
CIS_AUDIT = (
    "CIS GWS §1 — Revisar los registros de auditoría con regularidad",
    "CIS GWS §1 — Review audit logs regularly",
)

FINDINGS: dict[str, dict[str, tuple[str, str] | dict]] = {
    # ---------------------------------------------------------- composites
    # ------------------------------------------------------- self-diagnosis
    # Description is intentionally absent: it carries the list of violations
    # found in that particular scan, so it is built at scan time and kept.
    "internal-consistency": {
        "title": (
            "Incoherencia interna detectada en este escaneo",
            "Internal inconsistency detected in this scan",
        ),
        "scope": ("diagnóstico interno", "internal diagnostic"),
        "remediation": (
            "Avisa al equipo de Vigía con la fecha de este escaneo. El resto de hallazgos "
            "no está afectado.",
            "Report this scan's date to the Vigía team. Every other finding is unaffected.",
        ),
    },
    "composite-superadmin-dormant-no-2sv": {
        "title": (
            "Superadministrador sin 2FA que nunca ha iniciado sesión",
            "Super admin with no 2FA that has never signed in",
        ),
        "scope": S_SUPER,
        "description": (
            "{count} cuenta(s) cumplen a la vez: es superadministrador + no tiene verificación "
            "en dos pasos + nunca ha iniciado sesión.\n\nPor qué esto es peor que los hallazgos "
            "por separado: cada uno de los tres hechos es manejable aparte. Juntos son una "
            "puerta trasera permanente: la cuenta tiene control total del tenant, basta con "
            "robar su contraseña para usarla y, como nunca ha iniciado sesión, no existe una "
            "línea base de actividad normal con la que comparar, así que nadie notaría que otra "
            "persona empieza a usarla. Suelen ser restos de la instalación inicial o de "
            "migraciones, sin ningún responsable que las vigile.",
            "{count} account(s) match all of: is a super admin + has no 2-Step Verification + "
            "has never signed in.\n\nWhy this is worse than the separate findings: each fact is "
            "manageable alone. Together they are a permanent back door — the account holds full "
            "control of the tenant, a stolen password is enough to use it, and because it has "
            "never signed in there is no baseline of normal activity, so nobody would notice "
            "someone else starting to use it. These are usually left over from setup or "
            "migrations, with no owner watching them.",
        ),
        "description_clean": (
            "Ninguna cuenta es a la vez superadministrador, sin verificación en dos pasos y "
            "sin haber iniciado sesión nunca.",
            "No account is simultaneously a super admin, without 2-Step Verification and never "
            "signed in.",
        ),
        "remediation": (
            "Suspende estas cuentas hoy. Si alguna es realmente necesaria, inscríbela en la "
            "verificación en dos pasos con una llave de seguridad antes de reactivarla y "
            "asígnale un responsable con nombre y apellidos.",
            "Suspend these accounts today. If one is genuinely needed, enroll it in 2-Step "
            "Verification with a security key before re-enabling it, and give it a named owner.",
        ),
        "cis": (
            "CIS GWS §1 — Limitar superadministradores + exigir 2FA + desactivar cuentas inactivas",
            "CIS GWS §1 — Limit super admins + enforce 2SV + disable inactive accounts",
        ),
    },
    "composite-superadmin-no-2sv": {
        "title": (
            "Superadministrador sin verificación en dos pasos",
            "Super admin without 2-Step Verification",
        ),
        "scope": S_SUPER,
        "description": (
            "{count} cuenta(s) cumplen a la vez: es superadministrador + no tiene verificación "
            "en dos pasos.\n\nPor qué esto es peor que los hallazgos por separado: un "
            "superadministrador puede leer, cambiar o exportar cualquier cosa del tenant, y "
            "puede dejar fuera al resto de administradores. Sin segundo factor, una sola "
            "contraseña robada por phishing equivale al compromiso total del dominio: no hay "
            "segunda línea de defensa.",
            "{count} account(s) match all of: is a super admin + has no 2-Step Verification."
            "\n\nWhy this is worse than the separate findings: a super admin can read, change or "
            "export anything in the tenant and can lock every other admin out. Without a second "
            "factor, one phished password is full tenant compromise — there is no second line of "
            "defence.",
        ),
        "description_clean": (
            "Todos los superadministradores tienen la verificación en dos pasos.",
            "Every super admin has 2-Step Verification.",
        ),
        "remediation": (
            "Inscribe ya a estos administradores en la verificación en dos pasos, "
            "preferiblemente con llave de seguridad física o passkey, y después actívala de "
            "forma obligatoria para la unidad organizativa de administradores.",
            "Enroll these admins in 2-Step Verification now, preferably with a hardware security "
            "key or passkey, then enforce it for the admin organizational unit.",
        ),
        "cis": CIS_2SV_PRIV,
    },
    "composite-superadmin-dormant": {
        "title": (
            "Superadministrador sin actividad en {days}+ días",
            "Super admin with no activity for {days}+ days",
        ),
        "scope": S_SUPER,
        "description": (
            "{count} cuenta(s) cumplen a la vez: es superadministrador + no ha iniciado sesión "
            "recientemente.\n\nPor qué esto es peor que los hallazgos por separado: una cuenta "
            "de administrador sin uso conserva el privilegio máximo mientras nadie la vigila. Su "
            "uso indebido no llamaría la atención, porque no hay actividad reciente con la que "
            "contrastarlo.",
            "{count} account(s) match all of: is a super admin + has not signed in recently."
            "\n\nWhy this is worse than the separate findings: an unused admin account keeps "
            "maximum privilege while nobody watches it. Its misuse would not stand out, because "
            "there is no recent activity to compare against.",
        ),
        "description_clean": (
            "Todos los superadministradores han iniciado sesión recientemente.",
            "Every super admin has signed in recently.",
        ),
        "remediation": (
            "Confirma si la cuenta sigue siendo necesaria. Si no lo es, quítale el rol de "
            "administrador y suspéndela; si lo es, mantenla con 2FA y revísala cada trimestre.",
            "Confirm whether the account is still needed. If it is not, remove the admin role and "
            "suspend it; if it is, keep it enrolled in 2SV and review it quarterly.",
        ),
        "cis": (
            "CIS GWS §1 — Limitar superadministradores + revisar cuentas inactivas",
            "CIS GWS §1 — Limit super admins + review inactive accounts",
        ),
    },
    "composite-dormant-no-2sv": {
        "title": (
            "Cuenta sin 2FA que nunca ha iniciado sesión",
            "Account with no 2FA that has never signed in",
        ),
        "scope": S_ACTIVE,
        "description": (
            "{count} cuenta(s) cumplen a la vez: no tiene verificación en dos pasos + nunca ha "
            "iniciado sesión.\n\nPor qué esto es peor que los hallazgos por separado: estas "
            "cuentas siguen con la contraseña inicial que les puso informática, no tienen segundo "
            "factor y no hay nadie que entre a diario y note algo raro. Son la vía de entrada más "
            "silenciosa a un tenant.",
            "{count} account(s) match all of: has no 2-Step Verification + has never signed in."
            "\n\nWhy this is worse than the separate findings: these accounts still hold the "
            "initial password set by IT, have no second factor, and no owner signs in to notice "
            "anything odd. They are the quietest way into a tenant.",
        ),
        "description_clean": (
            "Ninguna cuenta sin verificación en dos pasos está además sin usar.",
            "No account without 2-Step Verification is also unused.",
        ),
        "remediation": (
            "Suspéndelas hasta que alguien necesite la cuenta de verdad. Cuando se entregue, "
            "exige la inscripción en 2FA en el primer inicio de sesión.",
            "Suspend them until someone actually needs the account. When it is handed over, "
            "require 2SV enrolment at first sign-in.",
        ),
        "cis": (
            "CIS GWS §1 — Exigir 2FA + desactivar cuentas sin uso",
            "CIS GWS §1 — Enforce 2SV + disable unused accounts",
        ),
    },
    "composite-service-account-no-2sv": {
        "title": (
            "Cuenta compartida o funcional sin 2FA",
            "Shared or functional account without 2FA",
        ),
        "scope": (
            "cuentas compartidas o funcionales (admin@, info@, integraciones@…)",
            "shared or functional accounts (admin@, info@, integrations@…)",
        ),
        "description": (
            "{count} cuenta(s) cumplen a la vez: no tiene verificación en dos pasos + parece una "
            "cuenta compartida o funcional.\n\nPor qué esto es peor que los hallazgos por "
            "separado: los buzones compartidos (admin@, info@, integraciones@…) suelen tener "
            "contraseñas conocidas por varias personas, guardadas en scripts o documentos, y que "
            "casi nunca se rotan. Sin segundo factor, cualquier filtración de esa contraseña es "
            "suficiente; y como la cuenta es de todos, nadie asume la tarea de vigilarla.",
            "{count} account(s) match all of: has no 2-Step Verification + looks like a shared or "
            "functional account.\n\nWhy this is worse than the separate findings: shared mailboxes "
            "tend to have passwords known by several people, stored in scripts or documents, and "
            "rarely rotated. Without a second factor, any leak of that password is enough — and "
            "because the account is shared, nobody owns the job of noticing.",
        ),
        "description_clean": (
            "Ninguna cuenta compartida o funcional está sin verificación en dos pasos.",
            "No shared or functional account is missing 2-Step Verification.",
        ),
        "remediation": (
            "Inscribe la cuenta en la verificación en dos pasos, o sustitúyela por un grupo o por "
            "acceso delegado para que no exista ninguna contraseña compartida.",
            "Enroll the account in 2-Step Verification, or replace it with a group or delegated "
            "access so no shared password exists at all.",
        ),
        "cis": (
            "CIS GWS §1 — Exigir 2FA en todas las cuentas",
            "CIS GWS §1 — Enforce 2SV for all accounts",
        ),
    },
    # ---------------------------------------------------------------- 2SV
    # NOTE: keyed "2sv-delegated-admins", not "2sv-admins". The old id meant
    # "any admin" (super admins included); this one means delegated admins
    # only. Reusing the key would relabel historical scans as something they
    # never measured, so the old id is deliberately absent from the catalogue
    # and those scans keep the wording they were reported with.
    "2sv-delegated-admins": {
        "title": (
            "Administrador delegado sin verificación en dos pasos",
            "Delegated admin without 2-Step Verification",
        ),
        "scope": S_DELEG,
        "description": (
            "Los administradores delegados pueden gestionar usuarios, restablecer contraseñas o "
            "cambiar ajustes de servicios: sin segundo factor, una sola contraseña robada por "
            "phishing basta para usar esos privilegios. Los superadministradores se evalúan "
            "aparte, en sus propios hallazgos.",
            "Delegated admins can manage users, reset passwords or change service settings: "
            "without a second factor, one phished password is enough to use those privileges. "
            "Super admins are assessed separately, in their own findings.",
        ),
        "remediation": (
            "Inscribe ya a estos administradores en 2FA (Seguridad > Verificación en dos pasos) y "
            "después hazla obligatoria para su unidad organizativa. Para administradores, usa "
            "preferiblemente llaves de seguridad o passkeys.",
            "Enroll these admins in 2SV now (Security > 2-Step Verification), then enforce it for "
            "their organizational unit. For admins, prefer security keys or passkeys.",
        ),
        "cis": CIS_2SV,
    },
    "2sv-users": {
        "title": (
            "Usuarios sin la verificación en dos pasos configurada",
            "Users without 2-Step Verification set up",
        ),
        "scope": S_ORG,
        "description": (
            "{without} de {total} usuarios activos no se han inscrito en la verificación en dos "
            "pasos. Las cuentas que solo dependen de una contraseña son la vía de entrada más "
            "habitual para el robo de cuentas.",
            "{without} of {total} active users have not enrolled in 2-Step Verification. "
            "Password-only accounts are the most common entry point for account takeover.",
        ),
        "remediation": (
            "Lanza una campaña de inscripción y después activa la 2FA obligatoria para toda la "
            "organización con un periodo de gracia (Seguridad > Verificación en dos pasos > "
            "Obligatoriedad).",
            "Run an enrollment campaign, then enforce 2SV org-wide with a grace period "
            "(Security > 2-Step Verification > Enforcement).",
        ),
        "cis": CIS_2SV,
    },
    "2sv-enforcement": {
        "title": (
            'Cuentas fuera del alcance de la obligatoriedad de 2FA',
            'Accounts outside the scope of two-step enforcement',
        ),
        "scope": S_ORG,
        "description": (
            "Mientras la 2FA no sea obligatoria, inscribirse es voluntario. {count} usuarios "
            "activos no están cubiertos por una política de obligatoriedad, así que podrían "
            "quitarse el segundo factor en cualquier momento.",
            "Until 2SV is enforced, enrolling is voluntary. {count} active users are not covered "
            "by an enforcement policy, so they could remove their second factor at any time.",
        ),
        "remediation": (
            "Activa la obligatoriedad de la 2FA en todas las unidades organizativas (Seguridad > "
            "Verificación en dos pasos > Obligatoriedad > Activada).",
            "Turn on 2SV enforcement for every organizational unit (Security > 2-Step "
            "Verification > Enforcement > On).",
        ),
        "cis": CIS_2SV,
    },
    # ------------------------------------------------------------- admins
    "super-admin-count": {
        "title": (
            "Número de cuentas de superadministrador",
            "Number of super-admin accounts",
        ),
        "scope": S_SUPER,
        "description_over": (
            "Hay {count} cuentas de superadministrador (umbral: {threshold}). Cada "
            "superadministrador es un objetivo de máximo impacto; Google y CIS recomiendan entre "
            "2 y 4.",
            "{count} super-admin accounts found (threshold: {threshold}). Every super admin is a "
            "maximum-impact target; Google and CIS recommend 2-4.",
        ),
        "description_single": (
            "Solo existe {count} cuenta de superadministrador. Si se pierde o se ve comprometida "
            "no hay un segundo administrador para recuperar el control: Google recomienda tener "
            "al menos 2.",
            "Only {count} super-admin account exists. If it is lost or compromised there is no "
            "second admin for recovery — Google recommends at least 2.",
        ),
        "description_ok": (
            "{count} cuentas de superadministrador: dentro del rango recomendado "
            "(2-{threshold}).",
            "{count} super-admin accounts — within the recommended range (2-{threshold}).",
        ),
        "remediation": (
            "Mantén entre 2 y 4 superadministradores. Pasa la administración del día a día a "
            "roles delegados con el mínimo privilegio necesario (Cuenta > Roles de administrador).",
            "Keep 2-4 super admins. Move day-to-day administration to delegated admin roles with "
            "least privilege (Account > Admin roles).",
        ),
        "cis": CIS_SUPER,
    },
    "delegated-admins": {
        "title": (
            "Cuentas de administrador delegado (inventario)",
            "Delegated admin accounts (inventory)",
        ),
        "scope": S_DELEG,
        "description": (
            "{count} cuentas de administrador delegado. Es informativo: revisa que cada rol siga "
            "siendo necesario y esté ajustado al mínimo privilegio.",
            "{count} delegated admin accounts. Informational — review that each role is still "
            "needed and scoped to least privilege.",
        ),
        "remediation": (
            "Revisa la asignación de roles en Cuenta > Roles de administrador.",
            "Review role assignment under Account > Admin roles.",
        ),
        "cis": CIS_SUPER,
    },
    # ------------------------------------------------------ dormant/stale
    "dormant-accounts": {
        "title": (
            "Cuentas activas sin iniciar sesión en {days}+ días",
            "Active accounts with no sign-in for {days}+ days",
        ),
        "scope": S_ACTIVE,
        "description": (
            "{count} cuentas activas no han iniciado sesión en más de {days} días. Las cuentas "
            "dormidas son un objetivo preferente: nadie se da cuenta cuando se ven comprometidas, "
            "y además suelen seguir consumiendo licencia.",
            "{count} active accounts have not signed in for over {days} days. Dormant accounts "
            "are prime targets: nobody notices when they get compromised, and they often keep "
            "paid licenses.",
        ),
        "remediation": (
            "Confírmalo con la persona o su responsable y después suspende la cuenta. Transfiere "
            "los datos y libera la licencia antes de eliminarla.",
            "Confirm with the owner or their manager, then suspend the account. Transfer data and "
            "free the license before deletion.",
        ),
        "cis": CIS_INACTIVE,
    },
    "never-logged-in": {
        "title": (
            "Cuentas activas que nunca han iniciado sesión",
            "Active accounts that have never signed in",
        ),
        "scope": S_ACTIVE,
        "description": (
            "{count} cuentas activas (creadas hace más de {grace} días) nunca han iniciado "
            "sesión. Normalmente conservan la contraseña inicial que les puso informática y no "
            "tienen 2FA: objetivos fáciles que nadie vigila.",
            "{count} active accounts (older than {grace} days) have never signed in. They usually "
            "hold the initial password set by IT and have no 2SV — easy targets nobody monitors.",
        ),
        "remediation": (
            "Suspéndelas hasta que la persona necesite la cuenta de verdad.",
            "Suspend them until the owner actually needs the account.",
        ),
        "cis": CIS_INACTIVE,
    },
    "suspended-accounts": {
        "title": (
            "Cuentas suspendidas que siguen existiendo",
            "Suspended accounts still present",
        ),
        "scope": ("cuentas suspendidas", "suspended accounts"),
        "description": (
            "Quedan {count} cuentas suspendidas en el directorio. Se pueden reactivar sin hacer "
            "ruido y puede que sigan ocupando licencia, perteneciendo a grupos y compartiendo "
            "datos.",
            "{count} suspended accounts remain in the directory. They can be silently re-enabled "
            "and may still hold licenses, group memberships and data shares.",
        ),
        "remediation": (
            "Para quien ya no está en la empresa: transfiere los datos y elimina la cuenta. La "
            "suspensión debe ser solo un paso temporal de la salida.",
            "For leavers: transfer data, then delete. Keep suspension only as a short-term "
            "offboarding step.",
        ),
        "cis": CIS_INACTIVE,
    },
    # -------------------------------------------------------------- login
    "login-compromised": {
        "title": (
            "Cuentas que Google ha marcado como comprometidas",
            "Accounts Google flagged as compromised",
        ),
        "scope": S_LOGIN,
        "description": (
            "La propia detección de Google ha desactivado o señalado estas cuentas por contraseña "
            "filtrada, secuestro o ataque patrocinado por un estado. Trátalas como comprometidas "
            "hasta demostrar lo contrario.",
            "Google's own detection disabled or flagged these accounts for a leaked password, "
            "hijacking or a government-backed attack. Treat them as breached until proven "
            "otherwise.",
        ),
        "description_clean": (
            "No hay alertas de contraseña filtrada, secuestro ni ataque en la ventana de "
            "auditoría.",
            "No leaked-password, hijack or attack alerts in the audit window.",
        ),
        "remediation": (
            "Restablece la contraseña, revoca las sesiones y los tokens de aplicaciones, y vuelve "
            "a verificar la 2FA de cada cuenta. Consulta el Centro de alertas para el contexto "
            "completo.",
            "Reset the password, revoke sessions and app tokens, and re-verify 2SV for each "
            "account. Review the Alert center for the full context.",
        ),
        "cis": CIS_LOGIN,
    },
    "login-suspicious": {
        "title": ("Actividad de inicio de sesión sospechosa", "Suspicious sign-in activity"),
        "scope": S_LOGIN,
        "description": (
            "Google ha marcado como sospechosos los inicios de sesión de {count} cuenta(s) "
            "(ubicación, dispositivo o patrón inusual).",
            "Google flagged sign-ins as suspicious for {count} account(s) (unusual location, "
            "device or pattern).",
        ),
        "description_clean": (
            "Ningún inicio de sesión se ha marcado como sospechoso en la ventana de auditoría.",
            "No sign-ins were flagged as suspicious in the audit window.",
        ),
        "remediation": (
            "Confirma la actividad con cada persona. Si no la reconoce, restablece las "
            "credenciales y exige 2FA. Valora usar el Acceso Contextual para limitar desde dónde "
            "se puede iniciar sesión.",
            "Confirm the activity with each user. If unrecognised, reset credentials and enforce "
            "2SV. Consider Context-Aware Access to limit sign-in locations.",
        ),
        "cis": CIS_LOGIN,
    },
    "login-brute-force": {
        "title": (
            "Posible adivinación de contraseñas (ráfagas de intentos fallidos)",
            "Possible password-guessing (failed sign-in bursts)",
        ),
        "scope": S_LOGIN,
        "description": (
            "{count} cuenta(s) acumulan 10 o más inicios de sesión fallidos en la ventana de "
            "auditoría, lo que puede indicar que alguien está probando contraseñas.",
            "{count} account(s) had 10+ failed sign-ins in the audit window, which can indicate "
            "password-guessing.",
        ),
        "description_clean": (
            "Ninguna cuenta muestra una ráfaga inusual de inicios de sesión fallidos.",
            "No accounts showed an unusual burst of failed sign-ins.",
        ),
        "remediation": (
            "Exige la 2FA (así acertar la contraseña deja de ser suficiente) y valora requisitos "
            "de contraseña más estrictos o el Acceso Contextual.",
            "Enforce 2SV (a correct password alone then fails), and consider stronger password "
            "requirements or Context-Aware Access.",
        ),
        "cis": CIS_LOGIN,
    },
    "login-security": {
        "title": (
            "Alertas de seguridad de inicio de sesión",
            "Sign-in security alerts",
        ),
        "scope": S_LOGIN,
        "description": (
            "No se ha podido leer el registro de inicios de sesión ({reason}).",
            "Could not read the sign-in audit log ({reason}).",
        ),
        "remediation": (
            "Comprueba que el administrador conectado tiene privilegios de Informes.",
            "Confirm the connecting admin has Reports privileges.",
        ),
        "cis": CIS_LOGIN,
    },
    # --------------------------------------------------------- oauth apps
    "oauth-high-risk": {
        "title": (
            "Aplicaciones de terceros con permisos de alto riesgo",
            "Third-party apps holding high-risk scopes",
        ),
        "scope": S_APPS,
        "description": (
            "{count} aplicaciones de terceros tienen permisos que dan acceso amplio al contenido "
            "de Gmail, a todo Drive, a las APIs de administración o a recursos de Cloud. Una "
            "brecha en cualquiera de esos proveedores se convierte en una brecha de tus datos. "
            "(La ventana de autorizaciones leída se indica en el alcance del hallazgo; se han visto "
            "{apps_seen} aplicaciones.)",
            "{count} third-party apps hold scopes granting broad access to Gmail content, all of "
            "Drive, admin APIs or Cloud resources. A breach at any of those vendors becomes a "
            "breach of your data. (The authorisation window actually read is stated in the "
            "finding's scope; "
            "{apps_seen} apps seen.)",
        ),
        "remediation": (
            "Revisa cada aplicación en Seguridad > Controles de API > Control de acceso de "
            "aplicaciones. Bloquea las que no reconozcas y pon el acceso de aplicaciones en "
            "«restringido» para que las nuevas autorizaciones de alto riesgo necesiten aprobación "
            "del administrador.",
            "Review each app under Security > API controls > App access control. Block apps you "
            "don't recognise and switch app access to 'restricted' so new high-risk grants "
            "require admin approval.",
        ),
        "cis": CIS_APPS,
    },
    "oauth-widely-granted": {
        "title": (
            "Aplicaciones autorizadas por muchos usuarios",
            "Apps authorised by many users",
        ),
        "scope": S_APPS,
        "description": (
            "{count} aplicaciones han sido autorizadas por {threshold} o más usuarios. Que una "
            "aplicación sin validar se use de forma masiva multiplica el alcance del daño si se ve "
            "comprometida.",
            "{count} apps have been authorised by {threshold}+ users. Broad adoption of an "
            "unvetted app multiplies the blast radius if it is compromised.",
        ),
        "remediation": (
            "Valida las aplicaciones de uso extendido (proveedor, tratamiento de datos, necesidad "
            "real) y marca la decisión como de confianza o bloqueada en el Control de acceso de "
            "aplicaciones.",
            "Vet widely-used apps (vendor, data handling, need) and mark decisions as "
            "trusted/blocked under App access control.",
        ),
        "cis": CIS_APPS,
    },
    "oauth-dwd": {
        "title": (
            "Concesiones de delegación en todo el dominio",
            "Domain-wide delegation grants",
        ),
        "scope": (
            "clientes con delegación en todo el dominio",
            "domain-wide delegation clients",
        ),
        "description": (
            "La delegación en todo el dominio permite que una cuenta de servicio suplante a "
            "CUALQUIER usuario para los permisos concedidos: es la concesión más poderosa de "
            "Workspace. Se han observado {count} evento(s) de concesión en la ventana de "
            "auditoría.",
            "Domain-wide delegation lets a service account impersonate EVERY user for the granted "
            "scopes — the most powerful grant in Workspace. {count} grant event(s) observed in "
            "the audit window.",
        ),
        "description_clean": (
            "La delegación en todo el dominio permite que una cuenta de servicio suplante a "
            "CUALQUIER usuario para los permisos concedidos: es la concesión más poderosa de "
            "Workspace. No hay eventos de concesión en la ventana de auditoría , pero "
            "pueden existir concesiones más antiguas: verifica la lista actual en la Consola de "
            "Administración.",
            "Domain-wide delegation lets a service account impersonate EVERY user for the granted "
            "scopes — the most powerful grant in Workspace. No grant events in the audit window "
            "; older grants may exist, so verify the current list in the Admin console.",
        ),
        "remediation": (
            "Revisa Seguridad > Controles de API > Delegación en todo el dominio. Elimina los "
            "clientes que no reconozcas y reduce los permisos al mínimo.",
            "Review Security > API controls > Domain-wide delegation. Remove clients you don't "
            "recognise and narrow scopes to the minimum.",
        ),
        "cis": CIS_APPS,
    },
    # -------------------------------------------------------------- audit
    "audit-admin-log": {
        "title": (
            "Acceso al registro de auditoría de administración",
            "Admin audit log accessibility",
        ),
        "scope": S_AUDIT,
        "description": (
            "El registro de auditoría de administración es accesible. Abajo se listan los cambios "
            "recientes en la Consola de Administración: revisa cualquiera que no reconozcas.",
            "The admin audit log is accessible. Recent Admin console changes are listed below — "
            "review anything you don't recognise.",
        ),
        "description_error": (
            "No se ha podido leer el registro de auditoría de administración ({reason}). "
            "Comprueba que el administrador conectado tiene privilegios de Informes.",
            "Could not read the admin audit log ({reason}). Confirm the connecting admin has "
            "Reports privileges.",
        ),
        "remediation": (
            "Configura reglas de alerta para los eventos de administración sensibles (Seguridad > "
            "Centro de alertas, Informes > Auditoría e investigación).",
            "Set up alerting rules for sensitive admin events (Security > Alert center, "
            "Reporting > Audit and investigation).",
        ),
        "cis": CIS_AUDIT,
    },
    "audit-risky-changes": {
        "title": (
            "Cambios de administración de riesgo en la ventana de auditoría",
            "Risky administrative changes in the audit window",
        ),
        "scope": S_AUDIT,
        "description": (
            "Se han registrado {changes} cambio(s) en {categories} categoría(s) de riesgo. El "
            "registro de auditoría recoge cambios, no el estado actual por defecto, así que revisa "
            "cada uno y confirma que fue intencionado.",
            "{changes} change(s) across {categories} risk categor(y/ies) were recorded. The audit "
            "log captures changes, not the current default state, so review each one and confirm "
            "it was intended.",
        ),
        "description_clean": (
            "No se ha registrado ningún cambio de configuración de riesgo en la ventana de "
            "auditoría. Esto no confirma que los ajustes sean seguros: para los valores por "
            "defecto que no se pueden leer, mira las comprobaciones manuales.",
            "No risky configuration changes were recorded in the audit window. This does not "
            "confirm the settings are safe — for defaults that cannot be read, see the manual "
            "checks.",
        ),
        "remediation": (
            "Para cada cambio, confirma quién lo hizo y por qué. Añade reglas de alerta para estos "
            "tipos de evento en el Centro de alertas.",
            "For each change, confirm who made it and why. Add alerting rules for these event "
            "types in the Alert center.",
        ),
        "cis": CIS_AUDIT,
    },
}

# ------------------------------------------------- email auth / transport
# Built in a loop: the shape is identical and only the mechanism changes.
_MECHANISMS = [
    (
        "email-spf",
        ("Registros SPF en {domains} dominio(s)", "SPF records across {domains} domain(s)"),
        (
            "Publica un registro TXT del tipo «v=spf1 include:_spf.google.com ~all» en cada "
            "dominio que envíe correo, mantén un único registro y termínalo en ~all o -all. "
            "Vigila también el límite de 10 consultas DNS del RFC 7208.",
            "Publish a TXT record like 'v=spf1 include:_spf.google.com ~all' on every sending "
            "domain, keep it to a single record, and end it with ~all or -all. Watch the RFC 7208 "
            "limit of 10 DNS lookups too.",
        ),
        ("CIS GWS §3 (Gmail) — Configurar SPF", "CIS GWS §3 (Gmail) — Configure SPF"),
    ),
    (
        "email-dkim",
        ("Firma DKIM en {domains} dominio(s)", "DKIM signing across {domains} domain(s)"),
        (
            "Genera una clave DKIM en la Consola de Administración (Aplicaciones > Google "
            "Workspace > Gmail > Autenticar el correo electrónico), publica el registro DNS y "
            "pulsa «Iniciar autenticación». Solo se comprueba el selector «google», que es el "
            "que usa Workspace: si firmas con un selector propio, escríbeme a "
            "diego@diegofarina.com y lo verificamos a mano.",
            "Generate a DKIM key in the Admin console (Apps > Google Workspace > Gmail > "
            "Authenticate email), publish the DNS record, then click 'Start authentication'. "
            "Only the 'google' selector is checked, the one Workspace uses: if you sign with a "
            "custom selector, write to diego@diegofarina.com and we verify it by hand.",
        ),
        ("CIS GWS §3 (Gmail) — Configurar DKIM", "CIS GWS §3 (Gmail) — Configure DKIM"),
    ),
    (
        "email-dmarc",
        ("Política DMARC en {domains} dominio(s)", "DMARC policy across {domains} domain(s)"),
        (
            "Publica un TXT en «_dmarc» empezando por «v=DMARC1; p=none; rua=mailto:…» para "
            "recoger informes y después endurece a p=quarantine y finalmente p=reject.",
            "Publish a '_dmarc' TXT starting at 'v=DMARC1; p=none; rua=mailto:…' to collect "
            "reports, then ratchet to p=quarantine and finally p=reject.",
        ),
        ("CIS GWS §3 (Gmail) — Configurar DMARC", "CIS GWS §3 (Gmail) — Configure DMARC"),
    ),
    (
        "mail-mta-sts",
        (
            "MTA-STS (TLS obligatorio en el correo entrante) en {domains} dominio(s)",
            "MTA-STS (enforced TLS for inbound mail) across {domains} domain(s)",
        ),
        (
            "Publica una política MTA-STS: un registro TXT en «_mta-sts» más un fichero de "
            "política en https://mta-sts.<dominio>/.well-known/mta-sts.txt con tus servidores MX. "
            "Empieza en modo «testing» y pasa después a «enforce».",
            "Publish an MTA-STS policy: a '_mta-sts' TXT record plus a policy file at "
            "https://mta-sts.<domain>/.well-known/mta-sts.txt listing your MX hosts. Start in "
            "'testing' mode, then move to 'enforce'.",
        ),
        (
            "CIS GWS §3 (Gmail) — Exigir TLS en el correo en tránsito",
            "CIS GWS §3 (Gmail) — Enforce TLS for mail in transit",
        ),
    ),
    (
        "mail-tls-rpt",
        (
            "TLS-RPT (informes de fallos de TLS) en {domains} dominio(s)",
            "TLS-RPT (TLS failure reporting) across {domains} domain(s)",
        ),
        (
            "Publica un registro TXT en «_smtp._tls»: «v=TLSRPTv1; rua=mailto:tls@<dominio>» para "
            "enterarte cuando falle la entrega con TLS hacia tu dominio.",
            "Publish a '_smtp._tls' TXT record: 'v=TLSRPTv1; rua=mailto:tls@<domain>' so you "
            "learn when TLS delivery to your domain fails.",
        ),
        (
            "CIS GWS §3 (Gmail) — Vigilar la seguridad del transporte de correo",
            "CIS GWS §3 (Gmail) — Monitor mail transport security",
        ),
    ),
    (
        "dns-dnssec",
        ("DNSSEC (DNS firmado) en {domains} dominio(s)", "DNSSEC (signed DNS) across {domains} domain(s)"),
        (
            "Activa DNSSEC en tu proveedor de DNS (en Cloudflare es un solo interruptor) y añade "
            "el registro DS en tu registrador. Sin DNSSEC, tus propios registros SPF, DKIM y "
            "DMARC se pueden falsificar.",
            "Enable DNSSEC at your DNS provider (one switch in Cloudflare), then add the DS record "
            "at your registrar. Without it, your own SPF, DKIM and DMARC records can be spoofed.",
        ),
        (
            "CIS GWS — Proteger la integridad del DNS",
            "CIS GWS — Protect DNS integrity",
        ),
    ),
]

for _id, _title, _rem, _cis in _MECHANISMS:
    FINDINGS[_id] = {
        "title": _title,
        "scope": S_DOMAINS,
        "description": (
            "Comprobado contra el DNS público en cada dominio configurado. Peor resultado: "
            "{worst_status}.",
            "Checked against public DNS for every configured domain. Worst result: {worst_status}.",
        ),
        "remediation": _rem,
        "cis": _cis,
    }

FINDINGS["email-auth"] = {
    "title": (
        "Autenticación del correo (SPF/DKIM/DMARC)",
        "Email authentication (SPF/DKIM/DMARC)",
    ),
    "scope": ("dominios configurados", "configured domains"),
    "description_nodomains": (
        "Todavía no hay dominios configurados, así que no se ha comprobado nada. Los dominios se "
        "sincronizan solos desde Workspace en cada escaneo y se verifican contra el DNS público; "
        "si esto sigue vacío después de escanear, escríbeme a diego@diegofarina.com.",
        "No domains are configured yet, so nothing was checked. Domains sync themselves from "
        "Workspace on every scan and are verified against public DNS; if this is still empty "
        "after a scan, write to diego@diegofarina.com.",
    ),
    "remediation": (
        "Vuelve a escanear: los dominios se sincronizan desde Workspace.",
        "Re-scan: domains sync from Workspace automatically.",
    ),
}

# ----------------------------------------------------- Admin console policies
_POLICIES = [
    (
        "policy-drive-sharing",
        ("Uso compartido externo de Drive", "Drive external sharing"),
        (
            "Los archivos compartidos fuera de la organización son la vía más habitual por la que "
            "los datos salen de un tenant. «Permitido» significa que cualquier usuario puede "
            "compartir cualquier cosa con cualquiera.",
            "Files shared outside the organisation are the most common route for data to leave a "
            "tenant. 'Allowed' means any user can share anything with anyone.",
        ),
        (
            "Consola de Administración > Aplicaciones > Google Workspace > Drive y Documentos > "
            "Configuración de uso compartido: pon el uso compartido fuera de la organización en "
            "DESACTIVADO o solo dominios permitidos, y el uso compartido por enlace por defecto "
            "en «Restringido».",
            "Admin console > Apps > Google Workspace > Drive and Docs > Sharing settings: set "
            "sharing outside the organisation to OFF or allowlisted domains, and default link "
            "sharing to 'Restricted'.",
        ),
        (
            "CIS GWS §4 (Drive) — Restringir el uso compartido externo",
            "CIS GWS §4 (Drive) — Restrict external sharing",
        ),
    ),
    (
        "policy-gmail-forwarding",
        ("Reenvío automático de Gmail", "Gmail automatic forwarding"),
        (
            "Quien compromete un buzón suele añadir una regla de reenvío silenciosa para seguir "
            "leyendo el correo después de que se cambie la contraseña. Desactivar el reenvío "
            "automático cierra esa vía.",
            "Attackers who compromise a mailbox routinely add a silent forwarding rule to keep "
            "reading mail after the password is reset. Disabling auto-forwarding removes that "
            "path.",
        ),
        (
            "Consola de Administración > Aplicaciones > Google Workspace > Gmail > Acceso de "
            "usuario final: desactiva el «Reenvío automático», al menos en las unidades "
            "organizativas sensibles.",
            "Admin console > Apps > Google Workspace > Gmail > End User Access: turn off "
            "'Automatic forwarding', at least for sensitive organizational units.",
        ),
        (
            "CIS GWS §3 (Gmail) — Restringir el reenvío automático",
            "CIS GWS §3 (Gmail) — Restrict auto-forwarding",
        ),
    ),
    (
        "policy-password",
        ("Política de contraseñas", "Password policy"),
        (
            "Las contraseñas cortas o reutilizables hacen que el relleno de credenciales sea "
            "barato. Apunta a 12+ caracteres, sin reutilización y sin rotación periódica forzada.",
            "Short or reusable passwords make credential stuffing cheap. Aim for 12+ characters, "
            "no reuse, and no forced periodic rotation.",
        ),
        (
            "Consola de Administración > Seguridad > Autenticación > Gestión de contraseñas: "
            "mínimo 12 caracteres, prohibir la reutilización y quitar la caducidad forzada.",
            "Admin console > Security > Authentication > Password management: minimum 12 "
            "characters, disallow reuse, and drop forced expiry.",
        ),
        (
            "CIS GWS §1 — Exigir una política de contraseñas robusta",
            "CIS GWS §1 — Enforce strong password policy",
        ),
    ),
    (
        "policy-session",
        ("Duración de la sesión de Google", "Google session length"),
        (
            "Una cookie de sesión robada sigue siendo válida hasta que la sesión caduca. Las "
            "sesiones con límite acotan cuánto tiempo sirve un token robado, sobre todo en "
            "administradores.",
            "A stolen session cookie stays valid until the session expires. Finite sessions limit "
            "how long a stolen token is useful, especially for admins.",
        ),
        (
            "Consola de Administración > Seguridad > Control de acceso y datos > Control de sesión "
            "de Google: establece una duración máxima de sesión web (12-24 h en unidades "
            "privilegiadas).",
            "Admin console > Security > Access and data control > Google session control: set a "
            "finite web session length (12-24h for privileged units).",
        ),
        (
            "CIS GWS §1 — Limitar la duración de las sesiones",
            "CIS GWS §1 — Limit session duration",
        ),
    ),
    (
        "policy-marketplace",
        (
            "Lista de aplicaciones de Marketplace permitidas",
            "Marketplace app allowlist",
        ),
        (
            "Una lista de permitidas significa que los usuarios solo pueden instalar aplicaciones "
            "de Marketplace que tú hayas validado, en lugar de dar acceso a sus datos a cualquier "
            "cosa que encuentren.",
            "An allowlist means users can only install Marketplace apps you have vetted, instead "
            "of granting data access to anything they find.",
        ),
        (
            "Consola de Administración > Aplicaciones > Aplicaciones de Google Workspace "
            "Marketplace > Configuración: permite solo las aplicaciones de la lista y revisa lo "
            "que ya está instalado.",
            "Admin console > Apps > Google Workspace Marketplace apps > Settings: allow only "
            "allowlisted apps, and review what is already installed.",
        ),
        (
            "CIS GWS §2 — Controlar la instalación de aplicaciones de Marketplace",
            "CIS GWS §2 — Control Marketplace app installation",
        ),
    ),
    (
        "policy-groups-sharing",
        ("Acceso externo a los Grupos de Google", "Google Groups external access"),
        (
            "Los grupos accesibles públicamente pueden exponer conversaciones internas y permitir "
            "que gente de fuera publique en listas de correo internas.",
            "Publicly accessible groups can expose internal discussions and let outsiders post to "
            "internal mailing lists.",
        ),
        (
            "Consola de Administración > Aplicaciones > Google Workspace > Grupos para empresas > "
            "Configuración de uso compartido: pon el acceso desde fuera de la organización en "
            "Privado.",
            "Admin console > Apps > Google Workspace > Groups for Business > Sharing settings: "
            "set access from outside the organisation to Private.",
        ),
        (
            "CIS GWS — Configuración de uso compartido de Grupos",
            "CIS GWS — Groups sharing settings",
        ),
    ),
]

_UNSET = (
    "No hay ninguna política establecida explícitamente para esta opción, así que el tenant está "
    "con el valor por defecto de Google. La API solo informa de los valores configurados a mano, "
    "de modo que esto no se puede confirmar automáticamente: compruébalo una vez de forma manual.",
    "No explicit policy is set for this option, so the tenant is on Google's default. The API only "
    "reports values that were explicitly configured, so this cannot be confirmed automatically — "
    "check it once by hand.",
)

for _id, _title, _desc, _rem, _cis in _POLICIES:
    FINDINGS[_id] = {
        "title": _title,
        "scope": S_POLICY,
        "description": _desc,
        "description_unset": _UNSET,
        "remediation": _rem,
        "cis": _cis,
    }

FINDINGS["policy-automation"] = {
    "title": (
        "La lectura automática de los ajustes de la consola no está activa",
        "Automatic reading of Admin console settings is not active",
    ),
    "scope": S_POLICY,
    "description": (
        "Vigía puede comprobar automáticamente el uso compartido de Drive, el reenvío de Gmail, la "
        "política de contraseñas, la duración de sesión, la lista de aplicaciones de Marketplace y "
        "el acceso a Grupos usando el permiso de solo lectura de políticas de Cloud Identity "
        "(sensible, no restringido, sin CASA). Ahora mismo no puede: {hint}",
        "Vigía can check Drive sharing, Gmail forwarding, password policy, session length, "
        "Marketplace allowlisting and Groups access automatically using the read-only Cloud "
        "Identity policy scope (sensitive, not restricted — no CASA). Right now it cannot: {hint}",
    ),
}

# ------------------------------------------------------- manual checks

MANUAL = {
    "manual-drive-sharing": {
        "title": (
            "Uso compartido externo de Drive (valores por defecto)",
            "Drive external sharing defaults",
        ),
        "area": ("Google Drive", "Google Drive"),
        "why_manual": (
            "Aparece porque Vigía no ha podido leer este ajuste automáticamente. Concede el "
            "permiso de solo lectura de políticas (reconectando) y pasa a ser una comprobación "
            "automática.",
            "Shown because Vigía could not read this setting automatically. Grant the read-only "
            "policy scope (reconnect) and it becomes an automatic check.",
        ),
        "instructions": (
            [
                "Consola de Administración > Aplicaciones > Google Workspace > Drive y Documentos "
                "> Configuración de uso compartido.",
                "Pon «Uso compartido fuera de tu organización» en DESACTIVADO o solo con dominios "
                "de la lista de permitidos.",
                "Pon el uso compartido por enlace por defecto para los archivos nuevos en "
                "«Restringido» (no en «Cualquier persona con el enlace»).",
                "Activa los avisos cuando alguien comparta archivos fuera de la organización.",
            ],
            [
                "Admin console > Apps > Google Workspace > Drive and Docs > Sharing settings.",
                "Set 'Sharing outside your organisation' to OFF or allowlisted domains only.",
                "Set default link sharing for new files to 'Restricted' (not 'Anyone with the "
                "link').",
                "Enable warnings when users share files outside the organisation.",
            ],
        ),
        "cis": (
            "CIS GWS §4 (Drive) — Restringir el uso compartido externo",
            "CIS GWS §4 (Drive) — Restrict external sharing",
        ),
    },
    "manual-gmail-forwarding": {
        "title": (
            "Reenvío automático de correo a direcciones externas",
            "Automatic email forwarding to external addresses",
        ),
        "area": ("Gmail", "Gmail"),
        "why_manual": (
            "La política de reenvío de toda la organización se lee automáticamente en cuanto se "
            "concede el permiso de políticas. Las reglas de reenvío de cada usuario necesitarían "
            "un permiso restringido de Gmail, así que esas hay que auditarlas con la Búsqueda en "
            "el registro de correo.",
            "The org-wide forwarding policy is read automatically once the policy scope is "
            "granted. Per-user forwarding rules would need a restricted Gmail scope, so audit "
            "those with Email Log Search.",
        ),
        "instructions": (
            [
                "Consola de Administración > Aplicaciones > Google Workspace > Gmail > Acceso de "
                "usuario final.",
                "Valora desactivar el «Reenvío automático» en toda la organización o en las "
                "unidades organizativas sensibles.",
                "Informes > Búsqueda en el registro de correo: audita el correo reenviado a "
                "dominios externos.",
            ],
            [
                "Admin console > Apps > Google Workspace > Gmail > End User Access.",
                "Consider disabling 'Automatic forwarding' org-wide or per sensitive OU.",
                "Reporting > Email Log Search: audit mail forwarded to external domains.",
            ],
        ),
        "cis": (
            "CIS GWS §3 (Gmail) — Restringir el reenvío automático",
            "CIS GWS §3 (Gmail) — Restrict auto-forwarding",
        ),
    },
    "manual-marketplace": {
        "title": (
            "Lista de aplicaciones permitidas de Google Workspace Marketplace",
            "Google Workspace Marketplace app allowlisting",
        ),
        "area": ("Aplicaciones", "Apps"),
        "why_manual": (
            "Aparece porque no se ha podido leer automáticamente la lista de aplicaciones "
            "permitidas de Marketplace.",
            "Shown because the Marketplace allowlist could not be read automatically.",
        ),
        "instructions": (
            [
                "Consola de Administración > Aplicaciones > Aplicaciones de Google Workspace "
                "Marketplace > Configuración.",
                "Elige «Permitir que los usuarios instalen solo aplicaciones de la lista de "
                "permitidas».",
                "Revisa las aplicaciones de Marketplace ya instaladas y quita las que no se usen.",
            ],
            [
                "Admin console > Apps > Google Workspace Marketplace apps > Settings.",
                "Choose 'Allow users to install only allowlisted apps'.",
                "Review already-installed Marketplace apps and remove unused ones.",
            ],
        ),
        "cis": (
            "CIS GWS §2 — Controlar la instalación de aplicaciones de Marketplace",
            "CIS GWS §2 — Control Marketplace app installation",
        ),
    },
    "manual-password-policy": {
        "title": (
            "Política de longitud y reutilización de contraseñas",
            "Password length and reuse policy",
        ),
        "area": ("Autenticación", "Authentication"),
        "why_manual": (
            "Aparece porque no se ha podido leer automáticamente la política de contraseñas.",
            "Shown because the password policy could not be read automatically.",
        ),
        "instructions": (
            [
                "Consola de Administración > Seguridad > Autenticación > Gestión de contraseñas.",
                "Pon la longitud mínima en 12 caracteres o más y aplícalo en el siguiente inicio "
                "de sesión.",
                "Desactiva la reutilización de contraseñas y evita los cambios periódicos "
                "obligatorios (recomendación del NIST).",
            ],
            [
                "Admin console > Security > Authentication > Password management.",
                "Set minimum length to 12+ characters and enforce at next sign-in.",
                "Disable password reuse; avoid mandatory periodic resets (NIST guidance).",
            ],
        ),
        "cis": (
            "CIS GWS §1 — Exigir una política de contraseñas robusta",
            "CIS GWS §1 — Enforce strong password policy",
        ),
    },
}


def _pick(node, index: int):
    """Recursively take one side of every (es, en) pair."""
    if isinstance(node, tuple):
        return _pick(node[index], index) if isinstance(node[index], (tuple, list, dict)) else node[index]
    if isinstance(node, dict):
        return {key: _pick(value, index) for key, value in node.items()}
    return node


# ------------------------------- hallazgos del motor de políticas por cuenta
# Añadidos cuando la reducción pasó a evaluarse por unidad organizativa. Las
# variantes "clean" y "undetermined" no son opcionales: sin ellas un tenant
# sano leería el texto del fallo con un cero delante.

FINDINGS["policy-2sv-enforcement"] = {
    "title": (
        'Obligatoriedad de la 2FA: cómo está configurada en la consola',
        'Two-step enforcement: how it is configured in the console',
        ),
    "scope": (
        'ajustes de la Consola de Administración',
        'Admin console settings',
    ),
    "description": (
        'Mientras la verificación en dos pasos no sea obligatoria, inscribirse es voluntario: quien no lo haga entra solo con contraseña, y quien ya la tenga puede quitársela cuando quiera. La obligatoriedad se configura por unidad organizativa, así que lo que importa no es si está activada, sino a quién alcanza.',
        'Until 2-Step Verification is enforced, enrolling is optional: anyone who skips it signs in with nothing but a password, and anyone already enrolled can turn it off whenever they like. Enforcement is set per organizational unit, so the question is not whether it is switched on — it is who it actually covers.',
    ),
    "remediation": (
        'Consola de Administración > Seguridad > Autenticación > Verificación en dos pasos > Obligatoriedad: actívala para toda la organización, no solo para una unidad.',
        'Admin console > Security > Authentication > 2-Step Verification > Enforcement: turn it on for the whole organisation, not just one organizational unit.',
    ),
    "cis": (
        'CIS GWS §1 — Verificación en dos pasos',
        'CIS GWS §1 — 2-Step Verification',
    ),
}

FINDINGS["policy-2sv-methods"] = {
    "title": (
        'Métodos de segundo factor permitidos',
        'Allowed second-factor methods',
    ),
    "scope": (
        'ajustes de la Consola de Administración',
        'Admin console settings',
    ),
    "description": (
        'El SMS y la llamada de voz no son un segundo factor de verdad: se interceptan con un cambio de SIM, con un desvío en la operadora o con una página de phishing que pide el código y lo reenvía en el momento. Contra un ataque dirigido, una cuenta con 2FA por SMS está casi tan expuesta como una sin 2FA, con el agravante de que todo el mundo la considera protegida. Solo las passkeys y las llaves de seguridad resisten el phishing, porque la credencial está atada al dominio real.',
        'SMS and voice calls are not a real second factor: they can be intercepted with a SIM swap, with a divert set up at the carrier, or with a phishing page that asks for the code and replays it on the spot. Against a targeted attacker, an account protected by SMS is almost as exposed as one with no second factor at all — with the added problem that everyone assumes it is protected. Only passkeys and security keys resist phishing, because the credential is bound to the real domain.',
    ),
    "remediation": (
        'Consola de Administración > Seguridad > Autenticación > Verificación en dos pasos, apartado «Métodos»: quita el SMS y la llamada de voz. Empieza por las unidades de administradores y reparte llaves o passkeys antes de endurecerlo para todos.',
        "Admin console > Security > Authentication > 2-Step Verification, 'Methods' section: remove SMS and voice call. Start with the admin organizational units, and hand out security keys or passkeys before you tighten this for everyone.",
    ),
    "cis": (
        'CIS GWS §1 — Verificación en dos pasos resistente al phishing',
        'CIS GWS §1 — Phishing-resistant 2-Step Verification',
    ),
}

FINDINGS["policy-2sv-grace"] = {
    "title": (
        'Periodo de gracia de la verificación en dos pasos',
        '2-Step Verification grace period',
    ),
    "scope": (
        'ajustes de la Consola de Administración',
        'Admin console settings',
    ),
    "description": (
        'El periodo de gracia es el tiempo que una cuenta nueva puede seguir entrando solo con contraseña. Durante esos días la obligatoriedad está anunciada pero no aplicada: es exactamente la ventana que busca quien roba credenciales, porque la cuenta ya existe y ya tiene permisos.',
        'The grace period is how long a new account can keep signing in with a password alone. For those days enforcement is announced but not applied, and that is exactly the window credential thieves look for: the account already exists and already carries its permissions.',
    ),
    "remediation": (
        'Consola de Administración > Seguridad > Autenticación > Verificación en dos pasos: baja el periodo de gracia a una semana o menos.',
        'Admin console > Security > Authentication > 2-Step Verification: bring the enrollment grace period down to a week or less.',
    ),
    "cis": (
        'CIS GWS §1 — Verificación en dos pasos',
        'CIS GWS §1 — 2-Step Verification',
    ),
}

FINDINGS["policy-imap"] = {
    "title": (
        'Acceso IMAP a Gmail',
        'IMAP access to Gmail',
    ),
    "scope": (
        'ajustes de la Consola de Administración',
        'Admin console settings',
    ),
    "description": (
        'IMAP permite entrar al buzón con usuario y contraseña desde cualquier cliente de correo, sin pasar por el desafío de la verificación en dos pasos. Es la puerta lateral clásica: quien tenga la contraseña lee todo el correo sin tocar la pantalla de acceso de Google y sin dejar el rastro de un inicio de sesión web.',
        "IMAP gets you into the mailbox with a username and a password, from any mail client, without ever meeting the two-step verification challenge. It is the classic side door: whoever holds the password reads all the mail without touching Google's sign-in screen and without leaving the trail a web sign-in would.",
    ),
    "remediation": (
        'Consola de Administración > Aplicaciones > Google Workspace > Gmail > Acceso de usuario final: desactiva IMAP o limítalo a los clientes que hayas aprobado.',
        'Admin console > Apps > Google Workspace > Gmail > End User Access: turn IMAP off, or limit it to the clients you have approved.',
    ),
    "cis": (
        'CIS GWS §3 (Gmail) — Restringir los protocolos de correo heredados',
        'CIS GWS §3 (Gmail) — Restrict legacy mail protocols',
    ),
}

FINDINGS["policy-pop"] = {
    "title": (
        'Acceso POP a Gmail',
        'POP access to Gmail',
    ),
    "scope": (
        'ajustes de la Consola de Administración',
        'Admin console settings',
    ),
    "description": (
        'POP tiene el mismo problema que IMAP y uno peor: descarga los mensajes a la máquina del cliente, así que una vez copiados quedan fuera de tu control, de tu retención y de cualquier borrado que hagas después.',
        'POP has the same problem as IMAP, plus a worse one: it downloads messages onto the client machine, so once they are copied they sit outside your control, outside your retention policy and outside any deletion you carry out later.',
    ),
    "remediation": (
        'Consola de Administración > Aplicaciones > Google Workspace > Gmail > Acceso de usuario final: desactiva POP. Casi nunca hace falta.',
        'Admin console > Apps > Google Workspace > Gmail > End User Access: turn POP off. It is almost never needed.',
    ),
    "cis": (
        'CIS GWS §3 (Gmail) — Restringir los protocolos de correo heredados',
        'CIS GWS §3 (Gmail) — Restrict legacy mail protocols',
    ),
}

FINDINGS["policy-less-secure-apps"] = {
    "title": (
        'Aplicaciones menos seguras (acceso solo con contraseña)',
        'Less secure apps (password-only access)',
    ),
    "scope": (
        'ajustes de la Consola de Administración',
        'Admin console settings',
    ),
    "description": (
        'Las aplicaciones menos seguras acceden con usuario y contraseña, sin OAuth y sin el desafío de la verificación en dos pasos. Este ajuste importa MÁS, no menos, cuando ya tienes la 2FA obligatoria: es precisamente la vía que la deja sin efecto. Y como la conexión no es interactiva, tampoco genera el aviso de inicio de sesión sospechoso.',
        'Less secure apps sign in with a username and a password: no OAuth, no two-step verification challenge. This setting matters MORE, not less, once you have already enforced 2SV — it is the exact route that cancels the enforcement out. And because the connection is not interactive, it never raises a suspicious sign-in alert either.',
    ),
    "remediation": (
        'Consola de Administración > Seguridad > Acceso y control de datos > Aplicaciones menos seguras: desactívalo. Lo que lo necesite debe migrar a OAuth.',
        'Admin console > Security > Access and data control > Less secure apps: turn it off. Anything that still depends on it has to move to OAuth.',
    ),
    "cis": (
        'CIS GWS §1 — Bloquear el acceso solo con contraseña',
        'CIS GWS §1 — Block password-only access',
    ),
}

FINDINGS["policy-drive-link-default"] = {
    "title": (
        'Acceso por defecto de los archivos nuevos de Drive',
        'Default access for new Drive files',
    ),
    "scope": (
        'ajustes de la Consola de Administración',
        'Admin console settings',
    ),
    "description": (
        'Es el valor que lleva cada archivo que alguien crea. Si por defecto es «cualquiera con el enlace», la fuga no necesita un error humano: ocurre sola cada vez que se comparte un documento sin mirar.',
        "This is the access level every file carries the moment someone creates it. If the default is 'anyone with the link', a leak does not need a human mistake: it happens on its own every time a document is shared without a second look.",
    ),
    "remediation": (
        'Consola de Administración > Aplicaciones > Google Workspace > Drive y Documentos > Configuración de uso compartido > Acceso general por defecto: ponlo en «Restringido».',
        "Admin console > Apps > Google Workspace > Drive and Docs > Sharing settings > Default general access: set it to 'Restricted'.",
    ),
    "cis": (
        'CIS GWS §4 (Drive) — Acceso por defecto de los archivos',
        'CIS GWS §4 (Drive) — Default file access',
    ),
}

FINDINGS["composite-superadmin-no-2sv-no-recovery"] = {
    "title": (
        'Superadministrador sin 2FA y con la recuperación mal puesta',
        'Super admin with no 2FA and unsafe account recovery',
    ),
    "scope": (
        'superadministradores',
        'super admins',
    ),
    "description": (
        '{count} cuenta(s) cumplen a la vez: es superadministrador + no tiene verificación en dos pasos + tiene la recuperación de la cuenta mal puesta.\n\nPor qué esto es peor que los hallazgos por separado: los dos hechos por separado ya son graves; juntos cierran el círculo. Sin segundo factor, una contraseña robada por phishing entra directamente. Y con la recuperación mal puesta, esa entrada se vuelve permanente: si el atacante llega primero al buzón personal de recuperación, se queda con la cuenta y tú no tienes vía de vuelta, porque sin teléfono de recuperación la única salida es el soporte de Google, que tarda días. Es la diferencia entre un incidente y perder el tenant.',
        '{count} account(s) match all of: is a super admin + has no 2-Step Verification + has unsafe account recovery.\n\nWhy this is worse than the separate findings: each fact is already serious on its own; together they close the loop. With no second factor, a phished password walks straight in. With recovery left unsafe, that access becomes permanent: if the attacker reaches the personal recovery mailbox first, the account is theirs and you have no way back, because without a recovery phone your only route is Google support, and that takes days. It is the difference between an incident and losing the tenant.',
    ),
    "remediation": (
        'Trata estas cuentas como una emergencia: inscríbelas hoy en la verificación en dos pasos con llave de seguridad, pon un teléfono de recuperación corporativo y quita cualquier correo de recuperación que esté en un dominio personal. Asegúrate de que queda al menos otro superadministrador con 2FA para no quedarte fuera.',
        'Treat these accounts as an emergency: enroll them in 2-Step Verification with a security key today, set a corporate recovery phone, and remove any recovery e-mail on a personal domain. Make sure at least one other super admin already has 2FA, so you cannot lock yourself out.',
    ),
    "cis": (
        'CIS GWS §1 — Verificación en dos pasos en cuentas privilegiadas + protección de la recuperación',
        'CIS GWS §1 — 2-Step Verification on privileged accounts + recovery protection',
    ),
    "description_clean": (
        'Ningún superadministrador está a la vez sin verificación en dos pasos y con la recuperación mal puesta.',
        'No super admin is simultaneously without 2-Step Verification and with unsafe account recovery.',
    ),
}

FINDINGS["recovery-super-admins"] = {
    "title": (
        'Recuperación de las cuentas de superadministrador',
        'Account recovery on super-admin accounts',
    ),
    "scope": (
        'superadministradores',
        'super admins',
    ),
    "description": (
        '{affected} de {total} superadministradores tienen la recuperación mal puesta.\n\nSin teléfono de recuperación, perder el segundo factor o sufrir un secuestro deja la cuenta fuera de alcance: no hay vía de vuelta que no pase por el soporte de Google, y eso son días. Y un correo de recuperación en un dominio personal es peor todavía: mueve la seguridad de todo el tenant a un buzón que tu organización no controla, no puede auditar y no puede revocar. Quien tenga ese buzón puede restablecer al superadministrador, y sigue pudiendo el día después de que la persona deje la empresa.',
        '{affected} of {total} super admins have unsafe account recovery.\n\nWith no recovery phone, losing the second factor or being locked out by an attacker puts the account out of reach: the only way back runs through Google support, and that takes days. A recovery e-mail on a consumer domain is worse still: it moves the security of the whole tenant into a mailbox your organisation does not control, cannot audit and cannot revoke. Whoever owns that inbox can reset the super admin — and can still do it the day after that person leaves the company.',
    ),
    "remediation": (
        'Abre Directorio > Usuarios, entra en cada superadministrador y revisa «Información de seguridad»: todos deben tener un teléfono de recuperación corporativo y ningún correo de recuperación en un dominio personal; sustituye los que lo estén por una dirección del propio dominio. Si la cuenta es de emergencia y no tiene a nadie detrás, guarda sus códigos de respaldo en el gestor de secretos en lugar de apuntar un buzón particular.',
        "Open Directory > Users, go into each super admin and check 'Security info': every one needs a corporate recovery phone and no recovery e-mail on a consumer domain — replace any you find with an address on your own domain. If the account is a break-glass account with nobody behind it, keep its backup codes in your secrets manager instead of pointing it at someone's personal mailbox.",
    ),
    "cis": (
        'CIS GWS §1 — Proteger las cuentas privilegiadas y su recuperación',
        'CIS GWS §1 — Protect privileged accounts and their recovery',
    ),
    "description_clean": (
        'Los {total} superadministradores tienen teléfono de recuperación y ningún correo de recuperación en un dominio personal.',
        'All {total} super admins have a recovery phone and no recovery e-mail on a consumer domain.',
    ),
    "description_undetermined": (
        'Ninguna cuenta del directorio devuelve teléfono ni correo de recuperación. Puede que de verdad no estén configurados, o que la API haya dejado de devolver esos campos: no se puede distinguir, así que no se acusa a nadie. Compruébalo a mano en la ficha de cada superadministrador.',
        "No account in the directory returns a recovery phone or a recovery e-mail. They may genuinely not be set, or the API may have stopped returning those fields — the two cannot be told apart, so nobody is accused. Check it by hand on each super admin's record.",
    ),
}


FINDINGS["admin-login-countries"] = {
    "title": (
        'Países desde los que entran los superadministradores',
        'Countries the super admins sign in from',
    ),
    "scope": (
        'superadministradores',
        'super admins',
    ),
    "description": (
        '{seen} de {admins} superadministradores tienen accesos en el registro, sobre una ventana de {days} día(s).\n\nEs un inventario, no un fallo: sirve para que reconozcas de un vistazo desde dónde se entra normalmente a las cuentas que controlan todo el tenant. El país sale de una base de datos local; ninguna dirección IP sale de este servidor.',
        '{seen} of {admins} super admins appear in the sign-in log, over a window of {days} day(s).\n\nThis is an inventory, not a failure: it is here so you can recognise at a glance where the accounts that control the whole tenant are normally used from. The country comes from a local database — no IP address leaves this server.',
    ),
    "remediation": (
        'Repasa la lista con quien corresponda: lo que importa no es el país en sí, sino que cuadre con dónde trabaja de verdad esa persona.',
        'Go through the list with the people concerned: what matters is not the country itself, but whether it matches where that person actually works.',
    ),
    "cis": (
        'CIS GWS §1 — Vigilar los inicios de sesión de las cuentas privilegiadas',
        'CIS GWS §1 — Monitor sign-ins to privileged accounts',
    ),
    "description_no-geodb": (
        '{seen} de {admins} superadministradores tienen accesos en el registro, sobre una ventana de {days} día(s).\n\nNo hay base de datos de países instalada, así que se listan las direcciones IP sin traducir a país. El inventario sigue sirviendo para reconocer desde qué redes se entra normalmente.',
        '{seen} of {admins} super admins appear in the sign-in log, over a window of {days} day(s).\n\nNo country database is installed, so the IP addresses are listed without being resolved to a country. The inventory is still useful for recognising which networks are normally used.',
    ),
    "description_undetermined": (
        'No se ha podido leer el registro de inicios de sesión, así que no se puede decir desde dónde entran las cuentas con más privilegios.',
        'The sign-in log could not be read, so there is nothing to say about where the most privileged accounts are used from.',
    ),
}

FINDINGS["admin-login-new-country"] = {
    "title": (
        'Accesos de superadministrador desde un país nuevo',
        'Super-admin sign-ins from a new country',
    ),
    "scope": (
        'superadministradores',
        'super admins',
    ),
    "description": (
        '{count} superadministrador(es) han entrado en los últimos {days} días desde un país en el que no constaba ningún acceso suyo antes, en {window} días de registro.\n\nNo es que el país sea peligroso: lo que llama la atención es el cambio. Una cuenta con meses de historial en un sitio que de pronto entra desde otro es el indicio más barato que existe de que alguien más la está usando, y en un superadministrador eso es el tenant entero.\n\nAntes de alarmarte: un viaje, una VPN nueva o un móvil en itinerancia dan exactamente la misma señal. Se confirma con una llamada, no con el informe.',
        '{count} super admin(s) signed in during the last {days} days from a country with no earlier sign-in of theirs on record, across {window} days of log.\n\nThe country is not the point; the change is. An account with months of history in one place that suddenly appears from another is the cheapest signal there is that somebody else is using it — and on a super admin that means the entire tenant.\n\nBefore you panic: a trip, a new VPN or a phone roaming abroad produce exactly the same signal. This is confirmed with a phone call, not with a report.',
    ),
    "remediation": (
        'Pregunta a esa persona si el acceso es suyo. Si no lo reconoce: cierra sus sesiones (Directorio > Usuarios > la cuenta > Seguridad > Cerrar sesión), restablece la contraseña, revisa las aplicaciones con acceso a su cuenta y mira el registro de administración por si tocó algún ajuste.',
        "Ask that person whether the sign-in was theirs. If they do not recognise it: sign out their sessions (Directory > Users > the account > Security > Sign out), reset the password, review the apps with access to their account, and check the admin audit log in case any setting was changed.",
    ),
    "cis": (
        'CIS GWS §1 — Vigilar los inicios de sesión de las cuentas privilegiadas',
        'CIS GWS §1 — Monitor sign-ins to privileged accounts',
    ),
    "description_clean": (
        'Ningún superadministrador ha entrado desde un país nuevo en los últimos {days} días, sobre {window} días de registro.',
        'No super admin has signed in from a new country in the last {days} days, across {window} days of log.',
    ),
    "description_no-baseline": (
        'El registro solo cubre {days} día(s), menos de los {needed} que hacen falta para distinguir «un país nuevo» de «el único país que hay». Sin línea base, marcar algo como nuevo sería inventárselo.',
        'The log only covers {days} day(s), fewer than the {needed} needed to tell "a new country" from "the only country there is". With no baseline, calling anything new would be making it up.',
    ),
}


FINDINGS["composite-enforced-but-not-enrolled"] = {
    "title": (
        'La 2FA es obligatoria para esta cuenta y aun así entra sin ella',
        'Two-step is mandatory for this account and it still signs in without it',
    ),
    "scope": (
        'cuentas activas con obligatoriedad aplicada',
        'active accounts the enforcement applies to',
    ),
    "description": (
        '{count} cuenta(s) están en esta situación.\n\nEs la combinación que no debería poder existir, y por eso merece una mirada aparte: la obligatoriedad de la verificación en dos pasos les alcanza, el periodo de gracia ya ha pasado, la persona ha iniciado sesión — y sigue sin segundo factor.\n\nUn informe que enseña «obligatoriedad: correcta» junto a «N usuarios sin 2FA» deja al lector pensando que una de las dos cosas está mal medida. No lo está: las dos son ciertas, y lo que hay entre ellas es una excepción real. Las causas habituales son una unidad organizativa excluida, una exención por usuario, o un acceso que no pasa por la pantalla de Google (IMAP, POP o una contraseña de aplicación), que es justamente el camino que la obligatoriedad no cubre.',
        '{count} account(s) are in this position.\n\nThis is the combination that should not be able to exist, which is why it gets its own card: two-step enforcement reaches these accounts, the grace period has long passed, the person has signed in — and there is still no second factor.\n\nA report showing "enforcement: pass" next to "N users without 2SV" leaves the reader assuming one of the two is measured wrong. Neither is: both are true, and what sits between them is a real exception. The usual causes are an excluded organizational unit, a per-user exemption, or a sign-in path that never reaches Google\'s screen — IMAP, POP or an app password, which is precisely what enforcement does not cover.',
    ),
    "remediation": (
        'Mira cada cuenta en Directorio > Usuarios > Seguridad: comprueba si tiene una exención de la verificación en dos pasos y si su unidad organizativa está dentro del ámbito de la obligatoriedad. Revisa también si entra por IMAP, POP o con una contraseña de aplicación, porque esas vías no pasan por el segundo factor. Si es una cuenta de servicio, conviértela en cuenta de servicio de verdad en lugar de dejarla como usuario con contraseña.',
        "Open each account in Directory > Users > Security: check whether it has a two-step exemption and whether its organizational unit falls inside the enforcement scope. Check too whether it signs in over IMAP, POP or with an app password, none of which go through the second factor. If it is a service account, make it a real service account instead of leaving it as a user with a password.",
    ),
    "cis": (
        'CIS GWS §1 — Verificación en dos pasos obligatoria y sin excepciones',
        'CIS GWS §1 — Two-step verification enforced without exceptions',
    ),
}


FINDINGS["alert-rules"] = {
    "title": (
        'Reglas de alerta de seguridad: quién se entera',
        'Security alert rules: who actually hears about it',
    ),
    "scope": ('reglas de alerta del tenant', 'tenant alert rules'),
    "description": (
        'De las {total} reglas de alerta que trae Google, {active} están activas y {off} apagadas.\n\nEsto es lo que separa «Google lo detectaría» de «alguien se enteraría». Una regla apagada no llega a dispararse. Una regla activa sin destinatario deja una tarjeta en el Centro de alertas, que es una pantalla que nadie tiene abierta un martes por la tarde.',
        'Of the {total} alert rules Google ships, {active} are active and {off} are switched off.\n\nThis is what separates "Google would detect it" from "somebody would hear about it". A rule that is off never fires. An active rule with no recipient files a card in the Alert Center, which is a screen nobody has open on a Tuesday afternoon.',
    ),
    "remediation": (
        'Consola de Administración > Reglas > Reglas definidas por el sistema. Activa al menos las de cambios de configuración, cuentas comprometidas, acceso sospechoso y dispositivos, y ponles un destinatario real: una lista de correo que alguien lea.',
        "Admin console > Rules > System-defined rules. Switch on at least the ones for configuration changes, compromised accounts, suspicious sign-ins and devices, and give them a real recipient: a mailbox somebody reads.",
    ),
    "cis": (
        'CIS GWS §1 — Activar y encaminar las alertas de seguridad',
        'CIS GWS §1 — Enable and route security alerts',
    ),
    "description_clean": (
        'Las {total} reglas de alerta del sistema están activas y todas avisan a alguien. Google detecta el incidente y hay quien lo recibe.',
        'All {total} system alert rules are active and every one of them notifies somebody. Google detects the incident and there is someone on the other end.',
    ),
    "description_undetermined": (
        'No se ha podido leer ninguna regla de alerta, así que no se puede decir si alguien está vigilando.',
        'No alert rule could be read, so there is nothing to say about whether anyone is watching.',
    ),
}

FINDINGS["2sv-backup-codes"] = {
    "title": (
        'Códigos de respaldo de la verificación en dos pasos',
        'Two-step verification backup codes',
    ),
    "scope": (
        'cuentas con códigos de respaldo generados',
        'accounts with backup codes generated',
    ),
    "description": (
        'Se han generado códigos de respaldo para {count} cuenta(s).\n\nUn código de respaldo es una cadena impresa: no caduca, se puede dictar por teléfono y se puede pedir en una página de phishing igual que una contraseña. Mientras siga vivo, es una vía de entrada que no pasa por la llave de seguridad — de modo que la cuenta vale lo que valga el más débil de sus dos factores, y ese es el papel.',
        'Backup codes have been generated for {count} account(s).\n\nA backup code is a printed string: it never expires, it can be read out over the phone, and it can be asked for on a phishing page exactly like a password. While one is alive it is a way in that never touches the security key — so the account is worth whatever its weaker factor is worth, and that is the paper.',
    ),
    "remediation": (
        'Directorio > Usuarios > la cuenta > Seguridad > Códigos de verificación de respaldo: revoca los que sigan vivos en las cuentas con privilegios. Si hacen falta como vía de emergencia, genéralos en el momento y revócalos después.',
        "Directory > Users > the account > Security > Backup verification codes: revoke any still alive on privileged accounts. If they are needed as a break-glass path, generate them at the time and revoke them afterwards.",
    ),
    "cis": (
        'CIS GWS §1 — Segundo factor resistente al phishing en cuentas privilegiadas',
        'CIS GWS §1 — Phishing-resistant second factor on privileged accounts',
    ),
    "description_clean": (
        'No consta ninguna generación de códigos de respaldo en el registro de administración. Es la respuesta que se quiere: los códigos son un segundo factor de papel que no caduca y que sí se puede phishear.',
        'No backup-code generation appears in the admin audit log. That is the answer you want: the codes are a paper second factor that never expires and can be phished.',
    ),
}

FINDINGS["policy-calendar-secondary"] = {
    "title": (
        'Calendarios secundarios visibles desde fuera',
        'Secondary calendars visible from outside',
    ),
    "scope": S_POLICY,
    "description": (
        'Los calendarios secundarios —el de la sala de reuniones, el del equipo, el de guardias— salen por defecto con TODOS los detalles visibles desde fuera de la organización, no solo el libre/ocupado. Y son justo los que nadie revisa, porque nadie los siente suyos.\n\nEl título de una reunión suele ser el secreto entero: «Due diligence Acme», «Rescisión de Juan», «Consejo extraordinario». Quien pueda leerlos desde fuera sabe qué va a hacer la empresa antes de que lo sepa la plantilla.',
        'Secondary calendars — the meeting room, the team, the on-call rota — default to showing ALL event details outside the organisation, not just free/busy. And they are precisely the ones nobody reviews, because nobody feels they own them.\n\nA meeting title is often the whole secret: "Due diligence Acme", "Termination – Juan", "Emergency board meeting". Anyone who can read them from outside knows what the company is about to do before the staff does.',
    ),
    "remediation": (
        'Consola de Administración > Aplicaciones > Google Workspace > Calendar > Opciones de uso compartido: para los calendarios secundarios, deja «Solo información de libre/ocupado» como máximo permitido hacia fuera.',
        "Admin console > Apps > Google Workspace > Calendar > Sharing settings: for secondary calendars, cap external sharing at 'Free/busy information only'.",
    ),
    "cis": (
        'CIS GWS §5 (Calendar) — Limitar la compartición externa a libre/ocupado',
        'CIS GWS §5 (Calendar) — Limit external sharing to free/busy',
    ),
}

FINDINGS["policy-calendar-primary"] = {
    "title": (
        'Calendarios personales visibles desde fuera',
        'Personal calendars visible from outside',
    ),
    "scope": S_POLICY,
    "description": (
        'Lo que un tercero puede ver del calendario de cada persona. Con libre/ocupado basta para coordinar una reunión; con los detalles se filtra con quién se reúne cada uno, cuándo y sobre qué.',
        'What an outsider can see of each person\'s calendar. Free/busy is enough to arrange a meeting; details leak who meets whom, when, and about what.',
    ),
    "remediation": (
        'Consola de Administración > Aplicaciones > Google Workspace > Calendar > Opciones de uso compartido: limita el máximo externo a «Solo libre/ocupado».',
        "Admin console > Apps > Google Workspace > Calendar > Sharing settings: cap external sharing at 'Free/busy only'.",
    ),
    "cis": (
        'CIS GWS §5 (Calendar) — Limitar la compartición externa a libre/ocupado',
        'CIS GWS §5 (Calendar) — Limit external sharing to free/busy',
    ),
}


FINDINGS["suspended-with-tokens"] = {
    "title": (
        'Aplicaciones conectadas por cuentas suspendidas',
        'Apps connected by suspended accounts',
    ),
    "scope": ('cuentas suspendidas', 'suspended accounts'),
    "description": (
        '{count} de las {suspended} cuentas suspendidas autorizaron aplicaciones de terceros y no consta que esas autorizaciones se revocaran nunca.\n\nSuspender cierra la puerta de delante: esa persona ya no puede iniciar sesión. Las aplicaciones que conectó son otra cosa — cada una guarda su propia credencial y habla con Google sin que ella esté presente. Es la vía de acceso que sobrevive a una baja porque nadie la asocia con la baja.\n\nPara ser exactos: Vigía no puede mirar dentro de Google para confirmar si esas credenciales siguen funcionando, y Google no documenta qué le hace una suspensión a un token OAuth (sí documenta que un cambio de contraseña los revoca). Lo que sí consta es que la autorización se concedió y que no hay ninguna revocación posterior en el registro.',
        '{count} of the {suspended} suspended accounts authorised third-party apps, and no revocation was ever recorded for them.\n\nSuspending closes the front door: that person can no longer sign in. The apps they connected are a different matter — each holds its own credential and talks to Google without them being present. It is the access path that survives an offboarding because nobody associates it with the offboarding.\n\nTo be exact: Vigía cannot look inside Google to confirm whether those credentials still work, and Google does not document what a suspension does to an OAuth token (it does document that a password change revokes them). What is on the record is that the grant was made and that no later revocation appears in the log.',
    ),
    "remediation": (
        'Seguridad > Controles de API > Gestionar el acceso de aplicaciones de terceros: busca cada aplicación y retira el acceso de esas cuentas. Añádelo a tu proceso de baja, junto a la suspensión y al cierre de sesiones: son tres acciones distintas y solo una la hace el botón de suspender.',
        "Security > API controls > Manage third-party app access: find each app and remove those accounts' access. Add it to your offboarding process alongside the suspension and the session sign-out: they are three separate actions and the suspend button only does one.",
    ),
    "cis": (
        'CIS GWS §3 — Retirar el acceso de terceros al dar de baja a alguien',
        'CIS GWS §3 — Remove third-party access when offboarding',
    ),
    "description_clean": (
        'Ninguna cuenta suspendida tiene autorizaciones de terceros pendientes de revocar en el registro.',
        'No suspended account has third-party grants left unrevoked in the log.',
    ),
    "description_undetermined": (
        'Hay cuentas suspendidas, pero no se ha podido leer el registro de autorizaciones OAuth, así que no se puede decir qué aplicaciones tenían conectadas ni si se revocaron.',
        'There are suspended accounts, but the OAuth authorisation log could not be read, so there is nothing to say about which apps they had connected or whether those were revoked.',
    ),
}

# El código renombró esta tarjeta a propósito: la mitad de organización ya la
# cubre policy-gmail-forwarding, y lo que queda manual son las reglas de cada
# buzón. El catálogo la devolvía al nombre viejo, que es la misma clase de
# error que reetiquetó un superadministrador como delegado.
# The two manual cards that had no catalogue entry at all, so they printed their
# Spanish source text inside an English report. Same gap class as the two DNS
# findings: a check whose prose lives only in `checks/` can never be translated,
# and nothing was watching for it — the parity test compares the two catalogues
# with each other, not the catalogue against the checks that emit cards.
#
# The Admin console path segments and the option names are kept as Google's own
# English console spells them ("Routing", "Recipient address map", "Outbound
# gateway", "Content compliance", "IMAP access"), because these are navigation
# instructions: a reader retyping a translated label into Google's search box
# finds nothing. Our own prose around them is British.
MANUAL["manual-gmail-routing"] = {
    "title": (
        "Reglas de enrutamiento y pasarela de salida de Gmail",
        "Gmail routing rules and outbound gateway",
    ),
    "area": ("Gmail", "Gmail"),
    "why_manual": (
        "El Policy API no expone las reglas de enrutamiento, así que esto no se puede "
        "comprobar automáticamente ni pidiendo más permisos. Vale el minuto que cuesta: "
        "una regla de enrutamiento maliciosa es exfiltración que sobrevive a un cambio "
        "de contraseña, a un cierre de sesiones y a activar la verificación en dos "
        "pasos. Sigue copiando el correo hasta que alguien mire esta pantalla, y nadie "
        "la mira nunca.",
        "The Policy API does not expose routing rules, so this cannot be checked "
        "automatically, not even by asking for more permissions. It is worth the minute it "
        "costs: a malicious routing rule is exfiltration that survives a password change, a "
        "sign-out of every session and turning on 2-Step Verification. It keeps copying the "
        "mail until somebody looks at this screen, and nobody ever looks at it.",
    ),
    "instructions": (
        [
            "Consola de Administración > Aplicaciones > Google Workspace > Gmail > "
            "Enrutamiento.",
            "Repasa una a una las reglas de «Enrutamiento», «Recipient address map» y "
            "«Enrutamiento de destinatarios»: cualquier regla que copie o desvíe correo a "
            "un dominio que no sea vuestro debe tener un dueño y un motivo escrito.",
            "Mira «Pasarelas de salida» (outbound gateway): si hay un servidor SMTP "
            "externo configurado, confirma que es el vuestro y no un relé que alguien dejó "
            "puesto.",
            "Comprueba también «Cumplimiento de contenido» por si hay una regla que envíe "
            "copia silenciosa de los mensajes que cumplan cierto patrón.",
            "Si encuentras algo que no reconoces, no lo borres sin más: apunta quién la "
            "creó y cuándo (aparece en el registro de auditoría) antes de quitarla.",
        ],
        [
            "Admin console > Apps > Google Workspace > Gmail > Routing.",
            "Go through the 'Routing', 'Recipient address map' and 'Default routing' rules one "
            "by one: any rule that copies or diverts mail to a domain that is not yours must "
            "have an owner and a written reason.",
            "Look at 'Outbound gateway': if an external SMTP server is configured, confirm it "
            "is yours and not a relay somebody left behind.",
            "Check 'Content compliance' too, in case there is a rule sending a silent copy of "
            "messages that match some pattern.",
            "If you find something you do not recognise, do not simply delete it: note who "
            "created it and when (it is in the audit log) before removing it.",
        ],
    ),
    "cis": (
        "CIS GWS §2 (Gmail) — Revisar el enrutamiento y las pasarelas de salida",
        "CIS GWS §2 (Gmail) — Review routing and outbound gateways",
    ),
}

MANUAL["manual-imap-pop"] = {
    "title": ("Acceso IMAP y POP a Gmail", "IMAP and POP access to Gmail"),
    "area": ("Gmail", "Gmail"),
    "why_manual": (
        "Vigía sí pide y tiene el permiso para leer este ajuste, y el identificador es el "
        "que documenta Google (gmail.imap_access y gmail.pop_access). Lo que pasa es otra "
        "cosa: tu organización nunca ha fijado una política explícita para ellos, y Google "
        "—a diferencia de casi todos los demás ajustes— no publica cuál es el valor por "
        "defecto ni lo devuelve por API. No hay nada que leer, así que decir «permitido» o "
        "«bloqueado» sería inventárselo. Se mira a mano en un minuto.",
        "Vigía does ask for and hold the permission to read this setting, and the identifier "
        "is the one Google documents (gmail.imap_access and gmail.pop_access). What is going "
        "on is something else: your organisation has never set an explicit policy for them, "
        "and Google — unlike almost every other setting — neither publishes what the default "
        "value is nor returns it over the API. There is nothing to read, so saying 'allowed' "
        "or 'blocked' would be making it up. It takes a minute to look by hand.",
    ),
    "instructions": (
        [
            "Consola de Administración > Aplicaciones > Google Workspace > Gmail > Acceso de "
            "usuario final.",
            "Mira «Acceso IMAP» y «Acceso POP». Desactiva los dos si nadie usa un cliente de "
            "correo de escritorio; casi nunca hace falta ninguno.",
            "Si necesitas IMAP, limítalo a los clientes de correo aprobados por OAuth en lugar "
            "de dejarlo abierto a cualquier cliente.",
            "Importante: estas dos vías entran con usuario y contraseña sin pasar por el "
            "desafío de la verificación en dos pasos, así que dejarlas abiertas anula buena "
            "parte de lo que te da la 2FA.",
        ],
        [
            "Admin console > Apps > Google Workspace > Gmail > End User Access.",
            "Look at 'IMAP access' and 'POP access'. Turn both off if nobody uses a desktop "
            "mail client; it is very rarely needed.",
            "If you do need IMAP, restrict it to OAuth-approved mail clients rather than "
            "leaving it open to any client.",
            "Important: both of these routes sign in with a username and password without "
            "going through the 2-Step Verification challenge, so leaving them open cancels out "
            "much of what 2SV gives you.",
        ],
    ),
    "cis": (
        "CIS GWS §2 (Gmail) — Desactivar los protocolos de acceso heredados",
        "CIS GWS §2 (Gmail) — Disable legacy access protocols",
    ),
}

MANUAL["manual-gmail-forwarding"]["title"] = (
        'Reglas de reenvío puestas por cada usuario',
        'Forwarding rules set by individual users',
    )


# ------------------------------------------------- the DNS engine's verdicts
# Every sentence `dns_email_auth.py` produces: the per-mechanism verdict a
# customer forwards to their manager, plus the `issues` each parser records and
# the input errors the public checker answers with.
#
# Two rules bite harder here than anywhere else in this table:
#
#  · DKIM has THREE states and the distinction is the whole value of the check.
#    A declared selector that is present passes; a declared selector that is
#    missing FAILS (we looked exactly where they said); nothing found with
#    nobody declaring anything is "not verified", because DKIM cannot be
#    enumerated. English must never collapse the third into "no DKIM".
#  · `dmarc_verdict` picks its several-records branch by looking for the word
#    "multiple" inside the recorded issue. Neither language's issue contains it,
#    so the branch is unreachable in both — identically. Do NOT translate
#    `dmarc.varios_registros` with the word "multiple": the English report would
#    then take a branch the Spanish one does not, and the two languages would
#    describe the same DNS differently.
DNS = {
    # Quotes, once. Spanish quotes with «», English with '' — and the names of
    # selectors are assembled in code, so the quoting has to be a template too.
    "comillas": ("«{valor}»", "'{valor}'"),
    "spf": {
        "sin_registro": (
            "No hay ningún registro SPF publicado.",
            "No SPF record is published.",
        ),
        "varios_registros": (
            "Hay {count} registros SPF publicados: tener varios es inválido (permerror) y los "
            "receptores pueden ignorar el SPF por completo.",
            "There are {count} SPF records published: having several is invalid (permerror) and "
            "receivers may ignore SPF altogether.",
        ),
        "all_permisivo": (
            "«+all» autoriza a CUALQUIER remitente de internet: eso anula la protección del SPF.",
            "'+all' authorises ANY sender on the internet: that cancels out SPF's protection.",
        ),
        "all_neutro": (
            "«?all» es neutro; es mejor «~all» o «-all».",
            "'?all' is neutral; '~all' or '-all' is better.",
        ),
        "sin_all": (
            "El registro no tiene mecanismo «all» ni «redirect»: la política está incompleta.",
            "The record has neither an 'all' mechanism nor a 'redirect': the policy is incomplete.",
        ),
        "terminos_primer_nivel": (
            "~{count} términos con consulta DNS en el primer nivel; el SPF permite 10 en total "
            "(riesgo de permerror).",
            "~{count} DNS-lookup terms at the top level; SPF allows 10 in total (permerror risk).",
        ),
        "limite_consultas": (
            "{lookups} consultas DNS, por encima del límite de {limit} del RFC 7208: los "
            "receptores devuelven permerror y dejan de evaluar el SPF.",
            "{lookups} DNS lookups, above the RFC 7208 limit of {limit}: receivers return "
            "permerror and stop evaluating SPF.",
        ),
        "sin_determinar": (
            "Falló la consulta DNS: no se ha podido determinar el estado del SPF.",
            "The DNS lookup failed: the state of SPF could not be determined.",
        ),
        "no_encontrado": (
            "No se ha encontrado ningún registro SPF. Cualquiera puede suplantar el correo de "
            "este dominio.",
            "No SPF record was found. Anyone can spoof mail from this domain.",
        ),
        "fail_all_permisivo": (
            "El SPF termina en «+all»: en la práctica, sin protección.",
            "SPF ends in '+all': in practice, no protection.",
        ),
        "fail_varios": (
            "El registro SPF es inválido (hay varios registros): los receptores pueden ignorarlo.",
            "The SPF record is invalid (there are several records): receivers may ignore it.",
        ),
        "fail_limite": (
            "El SPF supera el límite de {limit} consultas ({lookups}): los receptores devuelven "
            "permerror, así que el SPF no se evalúa en absoluto.",
            "SPF is over the limit of {limit} lookups ({lookups}): receivers return permerror, so "
            "SPF is not evaluated at all.",
        ),
        "debilidades": (
            "Existe un registro SPF, pero tiene debilidades que conviene corregir.",
            "An SPF record exists, but it has weaknesses worth fixing.",
        ),
        "correcto": (
            "Registro SPF encontrado, terminado en «{qualifier}all».",
            "SPF record found, ending in '{qualifier}all'.",
        ),
    },
    # The selectors somebody types into the public checker. The message names
    # what is wrong with the input rather than saying "invalid": whoever pasted
    # the whole record name deserves to be told that is what happened.
    "selector": {
        "demasiados": (
            "Son demasiados: como mucho {max} selectores. Si firmas con más, escríbeme y lo "
            "miramos.",
            "That is too many: at most {max} selectors. If you sign with more, write to me and we "
            "will look at it.",
        ),
        "con_puntos": (
            "«{token}» lleva puntos. Escribe solo el selector, sin el resto del nombre: «zoho2», "
            "no «zoho2._domainkey.tudominio.com».",
            "'{token}' has dots in it. Write the selector only, without the rest of the name: "
            "'zoho2', not 'zoho2._domainkey.yourdomain.com'.",
        ),
        "con_guion_bajo": (
            "«{token}» lleva guiones bajos. El «_domainkey» lo añade la herramienta; aquí va solo "
            "el selector.",
            "'{token}' has underscores in it. The tool adds the '_domainkey' part; only the "
            "selector goes here.",
        ),
        "con_espacios": (
            "«{token}» lleva espacios. Separa varios selectores con comas.",
            "'{token}' has spaces in it. Separate several selectors with commas.",
        ),
        "empieza_por_numero": (
            "«{token}» empieza por un número, y un selector empieza por letra.",
            "'{token}' starts with a number, and a selector starts with a letter.",
        ),
        "caracteres_invalidos": (
            "«{token}» tiene caracteres que no valen ({malos}). Un selector lleva solo letras, "
            "números y guiones.",
            "'{token}' has characters that are not allowed ({malos}). A selector contains only "
            "letters, numbers and hyphens.",
        ),
    },
    "dkim": {
        "clave_vacia": (
            "El selector «{selector}» publica una clave vacía (p=): la clave está revocada.",
            "Selector '{selector}' publishes an empty key (p=): the key is revoked.",
        ),
        # Appended to a found-key verdict when the selector they declared is not
        # the one that holds the key. Not a failure, but their claim is not
        # swallowed in silence either.
        "aviso_otro_selector": (
            "Ojo: en {nombres} no hay nada, así que la clave que usas no está donde creías.",
            "Careful: there is nothing at {nombres}, so the key you use is not where you thought "
            "it was.",
        ),
        "sufijo_bits": (" (clave de {bits} bits)", " ({bits}-bit key)"),
        "warn_problemas": (
            "Clave DKIM encontrada en el selector «{selector}», pero con problemas.{aviso}",
            "DKIM key found at selector '{selector}', but with problems.{aviso}",
        ),
        "warn_bits": (
            "Clave DKIM encontrada en el selector «{selector}», pero es de solo {bits} bits; el "
            "mínimo actual es 2048.{aviso}",
            "DKIM key found at selector '{selector}', but it is only {bits} bits; the current "
            "minimum is 2048.{aviso}",
        ),
        "encontrada": (
            "Clave DKIM encontrada en el selector «{selector}»{sufijo}.{aviso}",
            "DKIM key found at selector '{selector}'{sufijo}.{aviso}",
        ),
        "sin_determinar": (
            "Falló la consulta DNS: no se ha podido determinar el estado del DKIM.",
            "The DNS lookup failed: the state of DKIM could not be determined.",
        ),
        # The declared-and-absent case: a fact, not ignorance. We looked exactly
        # where they said and there was nothing there.
        "un_selector": ("el selector", "the selector"),
        "varios_selectores": ("los selectores", "the selectors"),
        "fail_declarado": (
            "No hay ninguna clave DKIM en {plural} que has indicado ({nombres}). El registro no "
            "está publicado, está mal escrito, o está en un nombre distinto de "
            "«<selector>._domainkey».",
            "There is no DKIM key at {plural} you gave ({nombres}). The record is not published, "
            "or it is misspelled, or it sits under a name other than '<selector>._domainkey'.",
        ),
        "aviso_comodin": (
            "Ojo: este dominio tiene un comodín TXT, así que el nombre responde aunque no haya "
            "clave.",
            "Careful: this domain has a TXT wildcard, so the name answers even when there is no "
            "key.",
        ),
        # Not "no DKIM": a miss across guessed names proves nothing, and the
        # count comes from what was actually probed.
        "probado_uno": ("el selector probado ({tried})", "the selector probed ({tried})"),
        "probados_varios": (
            "los {count} selectores probados ({tried})",
            "the {count} selectors probed ({tried})",
        ),
        "no_verificado": (
            "DKIM no verificado: no se ha encontrado ninguna clave en {probados}. Un dominio que "
            "firme con un selector propio no lo encuentra esta comprobación, así que esto no "
            "significa que no firmes; se verifica a mano escribiendo a diego@diegofarina.com.",
            "DKIM not verified: no key was found at {probados}. This check does not find a domain "
            "that signs with a selector of its own, so this does not mean that you do not sign; "
            "it is verified by hand by writing to diego@diegofarina.com.",
        ),
    },
    "dmarc": {
        "sin_registro": (
            "No hay ningún registro DMARC publicado.",
            "No DMARC record is published.",
        ),
        # See the note at the top of this section: the English must not contain
        # the word "multiple".
        "varios_registros": (
            "Hay {count} registros DMARC publicados: tener varios es inválido y los receptores "
            "ignorarán el DMARC.",
            "There are {count} DMARC records published: having several is invalid and receivers "
            "will ignore DMARC.",
        ),
        "sin_p": (
            "Falta la etiqueta obligatoria «p» o es inválida: el registro no se puede aplicar.",
            "The mandatory 'p' tag is missing or invalid: the record cannot be enforced.",
        ),
        "pct_invalido": ("Valor de pct inválido: {valor}.", "Invalid pct value: {valor}."),
        "pct_parcial": (
            "pct={pct}: la política solo se aplica al {pct}% del correo.",
            "pct={pct}: the policy applies to only {pct}% of the mail.",
        ),
        "sin_rua": (
            "No hay dirección de informes «rua»: no recibes ningún informe de visibilidad.",
            "There is no 'rua' reporting address: you receive no visibility reports.",
        ),
        "rua_ajena": (
            "Los informes agregados van solo a una dirección externa, así que nunca ves tu propia "
            "telemetría de suplantación. Añade una dirección de tu propio dominio a la etiqueta "
            "«rua».",
            "The aggregate reports go only to an external address, so you never see your own "
            "spoofing telemetry. Add an address at your own domain to the 'rua' tag.",
        ),
        "sin_determinar": (
            "Falló la consulta DNS: no se ha podido determinar el estado del DMARC.",
            "The DNS lookup failed: the state of DMARC could not be determined.",
        ),
        "no_encontrado": (
            "No hay registro DMARC. El correo suplantado de este dominio no se controla.",
            "There is no DMARC record. Spoofed mail from this domain is not controlled.",
        ),
        "fail_varios": (
            "Varios registros DMARC: es inválido y los receptores ignoran el DMARC.",
            "Several DMARC records: this is invalid and receivers ignore DMARC.",
        ),
        "fail_sin_politica": (
            "Hay un registro DMARC, pero sin política válida (p=).",
            "There is a DMARC record, but no valid policy (p=).",
        ),
        "fail_none": (
            "La política DMARC es p=none: solo monitoriza, el correo suplantado se sigue "
            "entregando.",
            "The DMARC policy is p=none: it only monitors, spoofed mail is still delivered.",
        ),
        "warn_quarantine": (
            "DMARC en p=quarantine: bien; pasa a p=reject cuando los informes salgan limpios.",
            "DMARC at p=quarantine: good; move to p=reject once the reports come back clean.",
        ),
        "warn_pct": (
            "DMARC en p=reject pero con pct={pct}: la aplicación es parcial.",
            "DMARC at p=reject but with pct={pct}: enforcement is partial.",
        ),
        "correcto": (
            "La política DMARC es p=reject al 100%: se aplica por completo.",
            "The DMARC policy is p=reject at 100%: it is fully enforced.",
        ),
    },
    "mta_sts": {
        "sin_determinar": (
            "Falló la consulta DNS: no se ha podido determinar el estado de MTA-STS.",
            "The DNS lookup failed: the state of MTA-STS could not be determined.",
        ),
        "correcto": (
            "Política MTA-STS publicada: el correo entrante exige TLS válido.",
            "MTA-STS policy published: inbound mail requires valid TLS.",
        ),
        "ausente": (
            "No hay política MTA-STS. Un atacante situado en la red puede degradar el correo "
            "dirigido a este dominio a texto plano.",
            "There is no MTA-STS policy. An attacker sitting on the network can downgrade mail "
            "addressed to this domain to plain text.",
        ),
    },
    "tls_rpt": {
        "sin_determinar": (
            "Falló la consulta DNS: no se ha podido determinar el estado de TLS-RPT.",
            "The DNS lookup failed: the state of TLS-RPT could not be determined.",
        ),
        "correcto": (
            "TLS-RPT publicado: recibes informes cuando falla la entrega con TLS.",
            "TLS-RPT published: you receive reports when TLS delivery fails.",
        ),
        "ausente": (
            "No hay registro TLS-RPT, así que los fallos de entrega con TLS pasan desapercibidos.",
            "There is no TLS-RPT record, so TLS delivery failures go unnoticed.",
        ),
    },
    "dnssec": {
        "sin_determinar": (
            "No se ha podido determinar si DNSSEC está activado.",
            "Whether DNSSEC is enabled could not be determined.",
        ),
        "correcto": (
            "DNSSEC está activado: las respuestas DNS de este dominio van firmadas.",
            "DNSSEC is enabled: this domain's DNS answers are signed.",
        ),
        "ausente": (
            "DNSSEC no está activado. Un atacante a nivel de resolutor puede falsificar las "
            "respuestas DNS, incluidos tus registros SPF, DKIM y DMARC.",
            "DNSSEC is not enabled. An attacker at resolver level can forge the DNS answers, "
            "including your own SPF, DKIM and DMARC records.",
        ),
    },
}

# ------------------------------------------- the four channels' shared wording
# `projection.py`: the coverage line, the change label and the score
# explanation. One implementation each, read by the dashboard, the PDF, the CSV
# and the alert e-mail — so these sentences are translated once here rather than
# four times at the point of use.
PROYECCION = {
    "cobertura": {
        "users": ("usuarios", "users"),
        "domains": ("dominios", "domains"),
        "token": ("autorizaciones OAuth", "OAuth authorisations"),
        "admin": ("eventos de administración", "admin events"),
        "login": ("eventos de acceso", "sign-in events"),
        "policies": ("ajustes de consola", "console settings"),
        "un_dia": ("{n} día", "{n} day"),
        "varios_dias": ("{n} días", "{n} days"),
        "ventana": (" en {dias}", " over {dias}"),
        # Lower case and with the figure: a known limit and a broken tool must
        # not look the same, and the number is what tells them apart.
        "parcial": (" — cobertura parcial en {detalle}", " — partial coverage in {detalle}"),
        # The denominator is a parameter, not a written figure: a catalogue that
        # spells out the window is exactly the defect `test_invariants.py`
        # guards against — the CSV once printed "(~180 días)" over a label that
        # said 178 measured. The number comes from the code, next to the read.
        "parcial_detalle": (
            "{nombre}: {dias} de {maximo} días",
            "{nombre}: {dias} of {maximo} days",
        ),
    },
    # Feminine in Spanish: these agree with "severidad", not with "hallazgo",
    # which is why they are not the labels in `severity`.
    "severidad": {
        "critical": ("crítica", "critical"),
        "high": ("alta", "high"),
        "medium": ("media", "medium"),
        "low": ("baja", "low"),
        "info": ("informativa", "info"),
    },
    "cambio": {
        "new": ("nuevo", "new"),
        "worse": ("ha empeorado", "has got worse"),
        "improved": ("ha mejorado", "has improved"),
        "resolved": ("resuelto", "resolved"),
        "coverage_gained": ("antes no se podía comprobar", "could not be checked before"),
        "coverage_lost": ("ha dejado de poder comprobarse", "can no longer be checked"),
        "same": ("sin cambios", "no change"),
        "baseline": ("primer escaneo", "first scan"),
        "cuenta": ("{etiqueta} (de {desde} a {hasta})", "{etiqueta} (from {desde} to {hasta})"),
        "severidad": (
            "{etiqueta} (severidad de {desde} a {hasta}{sufijo})",
            "{etiqueta} (severity from {desde} to {hasta}{sufijo})",
        ),
        "por_regresion": (" por regresión", " through regression"),
        "ahora_si": (
            "{etiqueta}; ahora sí, y el resultado es {resultado}",
            "{etiqueta}; now it can, and the result is {resultado}",
        ),
    },
    "puntuacion": {
        "titular": ("{ahora} (antes {antes})", "{ahora} (was {antes})"),
        "cobertura_ganada_una": (
            "{delta} porque ahora se pueden comprobar {n} cosa más",
            "{delta} because {n} more thing can be checked now",
        ),
        "cobertura_ganada_varias": (
            "{delta} porque ahora se pueden comprobar {n} cosas más",
            "{delta} because {n} more things can be checked now",
        ),
        "cobertura_perdida_una": (
            "{delta} porque {n} cosa dejaron de poder comprobarse",
            "{delta} because {n} thing can no longer be checked",
        ),
        "cobertura_perdida_varias": (
            "{delta} porque {n} cosas dejaron de poder comprobarse",
            "{delta} because {n} things can no longer be checked",
        ),
        "exposicion": (
            "{delta} por cambios en tu organización",
            "{delta} from changes in your organisation",
        ),
        # Stating the fact and stopping: the score holds still because the net
        # exposure is zero, not because each change is small.
        "sin_efecto_uno": (
            "{n} cambio en tu organización, sin efecto en la puntuación",
            "{n} change in your organisation, with no effect on the score",
        ),
        "sin_efecto_varios": (
            "{n} cambios en tu organización, sin efecto en la puntuación",
            "{n} changes in your organisation, with no effect on the score",
        ),
        # Only true when the organisation did not move; the coverage movement is
        # named on its own line.
        "sin_cambios": ("sin cambios en tu organización", "no change in your organisation"),
    },
}


# ------------------------------------------------ the "fix this first" actions
# `remediation.py`: the action graph the report ranks. Only the sentences live
# here — `minutes` and `console_url` are not language and stay in the module.
#
# The menu paths are the exception to British English that matters most in this
# file, because the reader is following them on screen with the console open. An
# instruction that sends somebody to "Organisational units" when the menu says
# "Organizational units" has broken the navigation to win a spelling argument,
# so Google's own spelling wins inside a path: "Authenticate email", "End User
# Access", "license", "enrollment period". British spelling applies to
# everything that is ours to write — the titles and the user-impact warnings.
REMEDIATION: dict[str, dict[str, tuple[str, str]]] = {
    "enforce_2sv_org": {
        "title": (
            "Exige la verificación en dos pasos en toda la organización",
            "Enforce 2-Step Verification across the whole organisation",
        ),
        "console_path": (
            "Seguridad > Autenticación > Verificación en dos pasos > Obligatoriedad",
            "Security > Authentication > 2-Step Verification > Enforcement",
        ),
        "user_impact": (
            "Quien no tenga configurado un segundo factor se queda fuera hasta que lo "
            "registre. Avisa antes y usa el periodo de gracia para nuevos usuarios que "
            "ofrece Google; inscribe a los administradores a mano antes de activar la "
            "obligatoriedad.",
            "Anyone without a second factor set up is locked out until they register one. "
            "Warn people first and use the new user enrollment period Google offers; enrol "
            "the admins by hand before you turn enforcement on.",
        ),
    },
    "suspend_unused_admins": {
        "title": (
            "Suspende o quita privilegios a las cuentas de administrador que nadie usa",
            "Suspend or remove privileges from the admin accounts nobody uses",
        ),
        "console_path": (
            "Directorio > Usuarios (filtrando por rol de administrador)",
            "Directory > Users (filtered by admin role)",
        ),
    },
    "suspend_never_used": {
        "title": (
            "Suspende las cuentas que nunca han iniciado sesión",
            "Suspend the accounts that have never signed in",
        ),
        "console_path": (
            "Directorio > Usuarios > filtro «Nunca ha iniciado sesión»",
            "Directory > Users > 'Never logged in' filter",
        ),
    },
    "suspend_dormant": {
        "title": (
            "Suspende las cuentas sin inicio de sesión reciente",
            "Suspend the accounts with no recent sign-in",
        ),
        "console_path": (
            "Directorio > Usuarios > ordenar por último inicio de sesión",
            "Directory > Users > sort by last sign-in",
        ),
        "user_impact": (
            "Confírmalo antes con cada responsable: suspender una cuenta que sigue en uso "
            "bloquea a esa persona de inmediato.",
            "Confirm it with each manager first: suspending an account that is still in use "
            "locks that person out immediately.",
        ),
    },
    "replace_shared_accounts": {
        "title": (
            "Sustituye los buzones compartidos por grupos o acceso delegado",
            "Replace shared mailboxes with groups or delegated access",
        ),
        "console_path": ("Directorio > Grupos", "Directory > Groups"),
        "user_impact": (
            "Quien use la contraseña compartida tendrá que pasar a su propia cuenta.",
            "Anyone using the shared password will have to move to their own account.",
        ),
    },
    "reduce_super_admins": {
        "title": (
            "Reduce los superadministradores a 2-4 y pasa el resto a roles delegados",
            "Reduce super admins to 2-4 and move the rest to delegated roles",
        ),
        "console_path": ("Cuenta > Roles de administrador", "Account > Admin roles"),
        "user_impact": (
            "Quien pierda el rol de superadministrador ya no podrá cambiar ajustes que "
            "afecten a todo el dominio.",
            "Anyone who loses the super-admin role will no longer be able to change settings "
            "that affect the whole domain.",
        ),
    },
    "reset_compromised_accounts": {
        "title": (
            "Restablece credenciales y revoca sesiones de las cuentas señaladas",
            "Reset credentials and revoke sessions on the flagged accounts",
        ),
        "console_path": (
            "Directorio > Usuarios > (cuenta) > Restablecer contraseña / Cerrar sesión",
            "Directory > Users > (account) > Reset password / Sign out",
        ),
        "user_impact": (
            "Esas personas se desconectan de todos sus dispositivos y tendrán que poner una "
            "contraseña nueva.",
            "Those people are signed out of every device and will have to set a new password.",
        ),
    },
    "restrict_app_access": {
        "title": (
            "Pon el acceso de aplicaciones de terceros en «restringido» y bloquea las desconocidas",
            "Set third-party app access to 'restricted' and block the ones you don't recognise",
        ),
        "console_path": (
            "Seguridad > Control de acceso y datos > Controles de API > Control de acceso de aplicaciones",
            "Security > Access and data control > API controls > App access control",
        ),
        "user_impact": (
            "Las aplicaciones que la gente ya usa dejarán de funcionar hasta que las marques "
            "como de confianza. Revisa antes la lista de aplicaciones ya autorizadas.",
            "Apps people already use will stop working until you mark them as trusted. Review "
            "the list of already-authorised apps first.",
        ),
    },
    "review_dwd": {
        "title": (
            "Revisa cada cliente con delegación en todo el dominio y elimina los que no reconozcas",
            "Review every domain-wide delegation client and remove the ones you don't recognise",
        ),
        "console_path": (
            "Seguridad > Control de acceso y datos > Controles de API > Delegación en todo el dominio",
            "Security > Access and data control > API controls > Domain-wide delegation",
        ),
        "user_impact": (
            "Las integraciones que dependan de un cliente eliminado dejarán de funcionar.",
            "Integrations that depend on a removed client will stop working.",
        ),
    },
    "publish_spf": {
        "title": (
            "Publica un registro SPF válido en cada dominio que envíe correo",
            "Publish a valid SPF record on every domain that sends mail",
        ),
        "console_path": (
            "Tu proveedor de DNS (registro TXT en el dominio raíz)",
            "Your DNS provider (TXT record on the root domain)",
        ),
        "user_impact": (
            "Asegúrate de tener la lista completa de remitentes antes de terminar en -all, o "
            "el correo legítimo de alguna herramienta que hayas olvidado empezará a rebotar.",
            "Make sure you have the complete list of senders before ending in -all, or "
            "legitimate mail from some tool you have forgotten will start bouncing.",
        ),
    },
    "enable_dkim": {
        "title": (
            "Activa la firma DKIM y publica la clave",
            "Turn on DKIM signing and publish the key",
        ),
        "console_path": (
            "Aplicaciones > Google Workspace > Gmail > Autenticar el correo electrónico",
            "Apps > Google Workspace > Gmail > Authenticate email",
        ),
    },
    "publish_dmarc": {
        "title": (
            "Publica DMARC, empezando en p=none con informes",
            "Publish DMARC, starting at p=none with reporting",
        ),
        "console_path": (
            "Tu proveedor de DNS (registro TXT en _dmarc.<dominio>)",
            "Your DNS provider (TXT record at _dmarc.<domain>)",
        ),
        "user_impact": (
            "En p=none es inofensivo. Pasa a quarantine o reject solo cuando los informes "
            "muestren que tu propio correo pasa la validación; si no, bloquearás a tus "
            "propios remitentes.",
            "At p=none it is harmless. Move to quarantine or reject only when the reports show "
            "your own mail passes validation; otherwise you will block your own senders.",
        ),
    },
    "publish_mta_sts": {
        "title": (
            "Publica una política MTA-STS para exigir TLS válido en el correo entrante",
            "Publish an MTA-STS policy to require valid TLS on inbound mail",
        ),
        "console_path": (
            "Tu proveedor de DNS + un fichero estático en mta-sts.<dominio>",
            "Your DNS provider + a static file at mta-sts.<domain>",
        ),
        "user_impact": (
            "En modo «enforce», los remitentes se niegan a entregar si los certificados de "
            "tus MX están mal. Empieza en modo «testing».",
            "In 'enforce' mode, senders refuse to deliver if the certificates on your MX hosts "
            "are wrong. Start in 'testing' mode.",
        ),
    },
    "publish_tls_rpt": {
        "title": (
            "Publica un registro TLS-RPT para recibir informes de fallos de TLS",
            "Publish a TLS-RPT record to receive reports of TLS failures",
        ),
        "console_path": (
            "Tu proveedor de DNS (TXT en _smtp._tls.<dominio>)",
            "Your DNS provider (TXT at _smtp._tls.<domain>)",
        ),
    },
    "enable_dnssec": {
        "title": (
            "Activa DNSSEC y añade el registro DS en tu registrador",
            "Enable DNSSEC and add the DS record at your registrar",
        ),
        "console_path": (
            "Tu proveedor de DNS y después el registrador",
            "Your DNS provider, then your registrar",
        ),
        "user_impact": (
            "Un registro DS mal puesto deja el dominio entero sin resolver. Verifica la "
            "cadena justo después de activarlo.",
            "A wrong DS record leaves the whole domain unresolvable. Verify the chain right "
            "after enabling it.",
        ),
    },
    "restrict_drive_sharing": {
        "title": (
            "Restringe el uso compartido de Drive fuera de la organización",
            "Restrict Drive sharing outside the organisation",
        ),
        "console_path": (
            "Aplicaciones > Google Workspace > Drive y Documentos > Configuración de uso compartido",
            "Apps > Google Workspace > Drive and Docs > Sharing settings",
        ),
        "user_impact": (
            "La gente ya no podrá compartir archivos con colaboradores externos (o solo con "
            "dominios de la lista de permitidos). Comprueba antes quién lo necesita.",
            "People will no longer be able to share files with external collaborators (or only "
            "with allowlisted domains). Check who needs it first.",
        ),
    },
    "disable_auto_forwarding": {
        "title": (
            "Desactiva el reenvío automático de correo a direcciones externas",
            "Turn off automatic mail forwarding to external addresses",
        ),
        "console_path": (
            "Aplicaciones > Google Workspace > Gmail > Acceso de usuario final",
            "Apps > Google Workspace > Gmail > End User Access",
        ),
        "user_impact": (
            "Las reglas de reenvío que ya existan dejarán de funcionar: comprueba que nadie "
            "dependa de una.",
            "Forwarding rules that already exist will stop working: check that nobody depends "
            "on one.",
        ),
    },
    "strengthen_password_policy": {
        "title": (
            "Exige contraseñas de 12+ caracteres y prohíbe reutilizarlas",
            "Require passwords of 12+ characters and disallow reuse",
        ),
        "console_path": (
            "Seguridad > Autenticación > Gestión de contraseñas",
            "Security > Authentication > Password management",
        ),
        "user_impact": (
            "A quien tenga una contraseña más corta se le pedirá cambiarla en el siguiente "
            "inicio de sesión.",
            "Anyone with a shorter password will be asked to change it at their next sign-in.",
        ),
    },
    "set_session_limit": {
        "title": (
            "Establece una duración máxima de sesión web",
            "Set a maximum web session length",
        ),
        "console_path": (
            "Seguridad > Control de acceso y datos > Control de sesión de Google",
            "Security > Access and data control > Google session control",
        ),
        "user_impact": (
            "La gente tendrá que volver a iniciar sesión con más frecuencia.",
            "People will have to sign in again more often.",
        ),
    },
    "restrict_marketplace": {
        "title": (
            "Permite solo las aplicaciones de Marketplace de la lista de permitidas",
            "Allow only the allowlisted Marketplace apps",
        ),
        "console_path": (
            "Aplicaciones > Aplicaciones de Google Workspace Marketplace > Configuración",
            "Apps > Google Workspace Marketplace apps > Settings",
        ),
        "user_impact": (
            "Los usuarios ya no podrán instalar aplicaciones de Marketplace por su cuenta.",
            "Users will no longer be able to install Marketplace apps on their own.",
        ),
    },
    "restrict_groups_external": {
        "title": (
            "Haz que los Grupos de Google sean privados de la organización",
            "Make Google Groups private to the organisation",
        ),
        "console_path": (
            "Aplicaciones > Google Workspace > Grupos para empresas > Configuración de uso compartido",
            "Apps > Google Workspace > Groups for Business > Sharing settings",
        ),
        "user_impact": (
            "Los miembros externos dejarán de poder leer o publicar en los grupos.",
            "External members will no longer be able to read or post in the groups.",
        ),
    },
    "delete_suspended": {
        "title": (
            "Transfiere los datos y elimina a las personas que ya no están, suspendidas",
            "Transfer the data and delete the suspended people who have left",
        ),
        "console_path": (
            "Directorio > Usuarios > filtro «Suspendidas»",
            "Directory > Users > 'Suspended' filter",
        ),
        "user_impact": (
            "La eliminación es permanente: transfiere antes Drive y el correo.",
            "Deletion is permanent: transfer Drive and mail first.",
        ),
    },
}

# ------------------------------------------------------------ the e-mails
# Everything Vigía sends: the scan alert a customer keeps in their inbox
# (`notify.py`), the cold message about a domain's public DNS (`outreach.py`)
# and the read-only promise shared with the report and the legal pages
# (`wording.py`).
#
# Counting nouns are stored as explicit singular/plural PAIRS — `…_uno` and
# `…_varios`, read by `wording.contar` — instead of going through
# `wording.plural`, whose `+s` is a rule about Spanish. English needs "1 point"
# / "2 points" but would need its own rules the moment a noun is irregular, and
# a subject line reading "2 findings nuevos" is exactly the kind of seam this
# table exists to prevent.
#
# NOT here on purpose: `nueva_empresa_asunto` / `nueva_empresa_cuerpo`. That
# alert goes to the operator, who is one Spanish-speaking person, and inventing
# an English half for an audience of one would be two wordings to keep in step
# for nobody's benefit.
EMAIL = {
    # ---------------------------------------- the read-only promise (wording.py)
    # ONE wording, shared by five surfaces: the report footer, /privacy, /terms,
    # the React landing and the outreach invitation. The Spanish is byte-for-byte
    # what `wording.READ_ONLY_CLAIM` holds and what `Landing.tsx` pins in its
    # `ANCLADAS` block; the English is byte-for-byte `ANCLADAS.en.claim`. A second
    # English redaction is the thing `test_readonly_wording.py` exists to stop.
    "solo_lectura": {
        "lead": ("Solo lectura por diseño.", "Read-only by design."),
        "claim": (
            "Vigía nunca ha solicitado permisos de Gmail, Drive ni ningún otro permiso "
            "restringido, así que no puede leer el contenido de mensajes ni de archivos: lo "
            "impide la propia API de Google, no solo nuestra política.",
            "Vigía has never requested Gmail, Drive or any other restricted permission, so "
            "it cannot read the content of messages or files: Google's own API prevents "
            "it, not just our policy.",
        ),
        # Only true next to a scan that actually ran, so it is separate: the
        # privacy page and the landing describe the tool, not a particular scan.
        "escaneo_sin_cambios": (
            "Este escaneo no ha modificado ningún ajuste de Workspace.",
            "This scan has not modified any Workspace setting.",
        ),
    },
    # ------------------------------------------------- the scan alert (notify.py)
    "alerta": {
        # Three words have to agree at once in Spanish, so the whole phrase is one
        # entry per number rather than a noun with an adjective bolted on.
        "criticos_nuevos_uno": ("{n} hallazgo CRÍTICO nuevo", "{n} new CRITICAL finding"),
        "criticos_nuevos_varios": ("{n} hallazgos CRÍTICOS nuevos", "{n} new CRITICAL findings"),
        "nuevos_uno": ("{n} hallazgo nuevo", "{n} new finding"),
        "nuevos_varios": ("{n} hallazgos nuevos", "{n} new findings"),
        "asunto_empeorado": ("La postura ha empeorado", "The posture has got worse"),
        # Its own subject, because it is its own event: Vigía stopped being able to
        # check something, which is not the same news as the tenant getting worse.
        "asunto_cobertura_perdida": (
            "Hay {count} comprobación(es) que ya no se pueden hacer",
            "{count} check(s) can no longer be done",
        ),
        "asunto_informe": ("Informe de escaneo", "Scan report"),
        "asunto_puntuacion_al_alza": (
            "Cambios con la puntuación al alza ({total})",
            "Changes with the score up ({total})",
        ),
        "cabecera": (
            "Escaneo de postura de seguridad de {dominio}",
            "Security posture scan of {dominio}",
        ),
        "puntuacion": ("Puntuación: {valor}/100{delta}", "Score: {valor}/100{delta}"),
        "sin_puntuacion": ("N/D", "N/A"),
        "delta_anterior": (
            " ({cambio} respecto al escaneo anterior)",
            " ({cambio} compared with the previous scan)",
        ),
        # Said rather than omitted: an e-mail that quietly drops the comparison
        # reads as "nothing changed", which is the same false statement.
        "sin_comparativa": (
            " (sin comparativa: el conjunto de comprobaciones ha cambiado)",
            " (no comparison: the set of checks has changed)",
        ),
        "problemas_abiertos": ("Problemas abiertos: {detalle}", "Open problems: {detalle}"),
        "recuento": {
            "critical": ("críticos", "critical"),
            "high": ("altos", "high"),
            "medium": ("medios", "medium"),
            "low": ("bajos", "low"),
        },
        # Upper case because they are a tag in a plain-text list, not prose.
        "severidad": {
            "critical": ("CRÍTICO", "CRITICAL"),
            "high": ("ALTO", "HIGH"),
            "medium": ("MEDIO", "MEDIUM"),
            "low": ("BAJO", "LOW"),
            "info": ("INFO", "INFO"),
        },
        "y_mas": ("  … y {n} más", "  … and {n} more"),
        "titulo_porque": (
            "POR QUÉ SE HA MOVIDO LA PUNTUACIÓN",
            "WHY THE SCORE MOVED",
        ),
        "titulo_nuevos": ("PROBLEMAS NUEVOS", "NEW PROBLEMS"),
        "titulo_empeorado": (
            "HAN EMPEORADO EN TU ORGANIZACIÓN",
            "GOT WORSE IN YOUR ORGANISATION",
        ),
        "titulo_resueltos": (
            "RESUELTOS DESDE EL ÚLTIMO ESCANEO",
            "RESOLVED SINCE THE LAST SCAN",
        ),
        # Worded so it cannot be read as a change in the tenant: this block is what
        # the 3 August e-mail should have said instead of congratulating a customer
        # for "resolving" a finding that had merely become readable.
        "titulo_cobertura_ganada": (
            "ANTES NO SE PODÍAN COMPROBAR, Y AHORA SÍ",
            "COULD NOT BE CHECKED BEFORE, AND NOW THEY CAN",
        ),
        "nota_cobertura_ganada": (
            "  (esto no es un cambio en tu organización: es lo que Vigía alcanza a ver)",
            "  (this is not a change in your organisation: it is what Vigía can see)",
        ),
        "cobertura_abierta_uno": (
            "  De esas, {n} ha resultado ser un problema abierto. No es nuevo:",
            "  Of those, {n} has turned out to be an open problem. It is not new:",
        ),
        "cobertura_abierta_varios": (
            "  De esas, {n} han resultado ser un problema abierto. No es nuevo:",
            "  Of those, {n} have turned out to be an open problem. It is not new:",
        ),
        "nota_invisible": (
            "  era invisible, no inexistente.",
            "  it was invisible, not non-existent.",
        ),
        "titulo_cobertura_perdida": (
            "VIGÍA HA DEJADO DE PODER COMPROBAR",
            "VIGÍA CAN NO LONGER CHECK",
        ),
        "nota_cobertura_perdida": (
            "  (tampoco es un cambio en tu organización; puede ser un permiso revocado o un "
            "límite de Google)",
            "  (this is not a change in your organisation either; it may be a revoked scope or "
            "a Google rate limit)",
        ),
        "informe_completo": ("Informe completo: {url}", "Full report: {url}"),
        "firma": (
            "— Vigía (escáner de postura de Google Workspace, solo lectura)",
            "— Vigía (read-only Google Workspace posture scanner)",
        ),
    },
    # ----------------------------------------- the outreach message (outreach.py)
    # Sent to somebody who did not ask for it, about a domain that is not ours to
    # touch, so every sentence here has to survive being read by a stranger who is
    # deciding whether this is a heads-up or a threat. Nothing may be added that
    # claims more than public DNS can support.
    "outreach": {
        "mecanismos": {
            "spf": {
                "etiqueta": (
                    "SPF (quién puede enviar en tu nombre)",
                    "SPF (who is allowed to send on your behalf)",
                ),
                "arreglo": (
                    "Publica o corrige el registro TXT de SPF del dominio, incluyendo todos los "
                    "servicios que envían en tu nombre y terminándolo en «-all» cuando estés seguro "
                    "de que la lista está completa. Ojo al límite de 10 consultas DNS del RFC 7208: "
                    "pasarse invalida el registro entero.",
                    "Publish or fix the domain's SPF TXT record, including every service that sends "
                    "on your behalf and ending it in '-all' once you are sure the list is complete. "
                    "Watch the RFC 7208 limit of 10 DNS lookups: going over it invalidates the whole "
                    "record.",
                ),
            },
            "dkim": {
                "etiqueta": (
                    "DKIM (firma criptográfica de tus mensajes)",
                    "DKIM (cryptographic signature on your messages)",
                ),
                "arreglo": (
                    "Activa la firma DKIM en tu proveedor de correo y publica su clave pública como "
                    "TXT en «<selector>._domainkey». El mínimo actual son 2048 bits.",
                    "Turn on DKIM signing at your mail provider and publish its public key as a TXT "
                    "record at '<selector>._domainkey'. The current minimum is 2048 bits.",
                ),
            },
            "dmarc": {
                "etiqueta": (
                    "DMARC (qué hacer con el correo que falla)",
                    "DMARC (what to do with mail that fails)",
                ),
                "arreglo": (
                    "Publica un TXT en «_dmarc» con «v=DMARC1; p=quarantine;» y una dirección «rua=» "
                    "tuya para recibir los informes. Sube a «p=reject» cuando los informes confirmen "
                    "que nada legítimo falla.",
                    "Publish a '_dmarc' TXT record with 'v=DMARC1; p=quarantine;' and a 'rua=' "
                    "address of yours to receive the reports. Move up to 'p=reject' once the reports "
                    "confirm nothing legitimate is failing.",
                ),
            },
            "mta_sts": {
                "etiqueta": (
                    "MTA-STS (cifrado obligatorio en tránsito)",
                    "MTA-STS (enforced encryption in transit)",
                ),
                "arreglo": (
                    "Publica el TXT «_mta-sts» y el fichero de política en "
                    "«https://mta-sts.<dominio>/.well-known/mta-sts.txt» para que los servidores que "
                    "te escriben exijan TLS y no acepten una degradación a texto claro.",
                    "Publish the '_mta-sts' TXT record and the policy file at "
                    "'https://mta-sts.<domain>/.well-known/mta-sts.txt' so that the servers writing "
                    "to you require TLS and refuse a downgrade to plain text.",
                ),
            },
            "tls_rpt": {
                "etiqueta": (
                    "TLS-RPT (informes de fallos de cifrado)",
                    "TLS-RPT (reporting of encryption failures)",
                ),
                "arreglo": (
                    "Publica un TXT en «_smtp._tls» con una dirección «rua=» para enterarte de los "
                    "fallos de cifrado en la entrega en lugar de descubrirlos por casualidad.",
                    "Publish a '_smtp._tls' TXT record with a 'rua=' address so you hear about "
                    "encryption failures on delivery instead of discovering them by chance.",
                ),
            },
            "dnssec": {
                "etiqueta": (
                    "DNSSEC (integridad de tus respuestas DNS)",
                    "DNSSEC (integrity of your DNS answers)",
                ),
                "arreglo": (
                    "Activa DNSSEC en el registrador del dominio. Sin él, quien controle un resolutor "
                    "puede falsificar las respuestas DNS, incluidos los propios registros SPF y DMARC "
                    "en los que se apoya todo lo anterior.",
                    "Enable DNSSEC at the domain's registrar. Without it, whoever controls a resolver "
                    "can forge the DNS answers, including the SPF and DMARC records everything above "
                    "rests on.",
                ),
            },
        },
        "puntos_uno": ("{n} punto", "{n} point"),
        "puntos_varios": ("{n} puntos", "{n} points"),
        "asunto_un_dominio": (
            "Autenticación de correo de {dominio}: {puntos} a revisar",
            "Email authentication for {dominio}: {puntos} to review",
        ),
        "asunto_varios_dominios": (
            "Autenticación de correo de {n} dominios: {puntos} a revisar",
            "Email authentication for {n} domains: {puntos} to review",
        ),
        "saludo": ("Hola:", "Hello,"),
        # Answers "how do you know that" in the first paragraph, because it is the
        # first thing a stranger wonders and the whole defensibility of the message.
        "intro": (
            "He revisado la configuración pública de autenticación de correo de {dominios} "
            "y he encontrado algunos puntos que conviene mirar. Te los paso por si son "
            "útiles.\n\n"
            "Todo lo que sigue sale EXCLUSIVAMENTE de registros DNS públicos, los mismos "
            "que puede consultar cualquiera. No he accedido a ningún sistema vuestro, no he "
            "enviado correo a vuestros buzones ni he intentado ningún acceso: solo he "
            "resuelto los registros del dominio. Comprobación del {fecha}.",
            "I have reviewed the public email authentication settings for {dominios} and "
            "found a few points worth looking at. I am passing them on in case they are "
            "useful.\n\n"
            "Everything that follows comes EXCLUSIVELY from public DNS records, the same "
            "ones anybody can look up. I have not accessed any system of yours, I have not "
            "sent mail to your mailboxes and I have not attempted any access: I have only "
            "resolved the domain's records. Checked on {fecha}.",
        ),
        "dominio": ("DOMINIO: {dominio}", "DOMAIN: {dominio}"),
        "proveedor": (
            "   (proveedor de correo detectado: {proveedor})",
            "   (mail provider detected: {proveedor})",
        ),
        "nada_que_senalar": (
            "\nNo he encontrado nada que señalar: SPF, DKIM, DMARC y el resto de "
            "registros que he podido comprobar están en orden. Enhorabuena, es menos "
            "habitual de lo que parece.",
            "\nI found nothing to flag: SPF, DKIM, DMARC and the rest of the records I was "
            "able to check are in order. Congratulations, that is rarer than it sounds.",
        ),
        "etiqueta_problema": ("PROBLEMA", "PROBLEM"),
        "etiqueta_aviso": ("AVISO", "WARNING"),
        "como_se_arregla": ("   Cómo se arregla: {arreglo}", "   How to fix it: {arreglo}"),
        "titulo_workspace": (
            "REVISA TAMBIÉN TU GOOGLE WORKSPACE",
            "CHECK YOUR GOOGLE WORKSPACE TOO",
        ),
        "workspace_oferta": (
            "Todo lo anterior es solo lo que se ve desde fuera, en el DNS. Si usáis Google "
            "Workspace, en https://diegofarina.com/vigia podéis obtener un informe automático "
            "y completo de la seguridad del dominio: cuentas sin verificación en dos pasos, "
            "superadministradores de más, cuentas sin usar que siguen abiertas, aplicaciones "
            "de terceros con acceso a vuestros datos, políticas de Drive y Gmail, y una "
            "puntuación con lo que conviene arreglar primero.",
            "Everything above is only what can be seen from outside, in DNS. If you use Google "
            "Workspace, at https://diegofarina.com/vigia you can get an automatic, complete "
            "report on the domain's security: accounts without 2-Step Verification, more super "
            "admins than you need, unused accounts still open, third-party apps with access to "
            "your data, Drive and Gmail policies, and a score with what is worth fixing first.",
        ),
        # The read-only promise, in the words the consent screen will confirm. If
        # this paragraph overclaimed, the first admin to read the screen would
        # catch it — which is why it is asserted by a test.
        "workspace_solo_lectura": (
            "Se conecta la cuenta de administrador con permisos de SOLO LECTURA. Vigía no "
            "puede modificar ni un ajuste de vuestro Workspace, y nunca pide acceso al "
            "contenido de Gmail ni de Drive: solo lee la configuración. El acceso se revoca "
            "cuando queráis desde la propia cuenta de Google.",
            "You connect the administrator account with READ-ONLY permissions. Vigía cannot "
            "modify a single setting in your Workspace, and it never asks for access to the "
            "content of Gmail or Drive: it only reads the configuration. Access can be revoked "
            "whenever you like from the Google account itself.",
        ),
        "workspace_sin_conectar_nada": (
            "Y si preferís comprobar por vuestra cuenta lo que os cuento arriba sin conectar "
            "nada, la herramienta de SPF, DKIM y DMARC es pública y no pide ningún acceso: "
            "https://diegofarina.com/vigia/dmarc-checker",
            "And if you would rather check what I describe above yourselves without connecting "
            "anything, the SPF, DKIM and DMARC tool is public and asks for no access at all: "
            "https://diegofarina.com/vigia/dmarc-checker",
        ),
        "titulo_importa": ("POR QUÉ IMPORTA", "WHY IT MATTERS"),
        "cuerpo_importa": (
            "SPF, DKIM y DMARC son lo que impide que alguien envíe correo haciéndose pasar "
            "por tu dominio. Cuando faltan o están a medias, un atacante puede escribir a "
            "tus clientes, a tus proveedores o a tu propio equipo desde una dirección que "
            "parece vuestra, y el mensaje llega a la bandeja de entrada. Es la base de la "
            "mayoría de los fraudes de facturas y de suplantación de directivos.",
            "SPF, DKIM and DMARC are what stops somebody sending mail while pretending to be "
            "your domain. When they are missing or half-done, an attacker can write to your "
            "customers, to your suppliers or to your own team from an address that looks like "
            "yours, and the message lands in the inbox. It is the basis of most invoice fraud "
            "and executive impersonation.",
        ),
        "firma": (
            "Te escribe {nombre} <{correo}>.",
            "This is {nombre} <{correo}> writing.",
        ),
        # The opt-out keyword is translated: nothing parses the reply, a person
        # reads it, and a Spanish keyword in an English message is one more thing
        # for the reader to distrust.
        "baja": (
            "Si no quieres recibir nada más, responde con «BAJA» a {baja} y no volveré "
            "a escribirte. Si prefieres que hable con otra persona de tu equipo, dime con "
            "quién.",
            "If you would rather not hear from me again, reply 'UNSUBSCRIBE' to {baja} and I "
            "will not write to you any more. If you would prefer me to speak to somebody else "
            "on your team, tell me who.",
        ),
        "generado": ("Informe generado con Vigía.", "Report generated with Vigía."),
    },
}


# ------------------------------------------------------ the printed report
# The report's chrome: section titles, column headers, the sentences that explain
# a number. Everything the reader sees around the findings, which used to be
# Spanish f-strings and therefore could never answer in English.
#
# Two rules hold this section together:
#
#  · Nouns that have to agree with a count are NOT written into the template.
#    The caller builds the agreed phrase with `wording.con_numero` out of the
#    singular/plural pair below and passes it in, so "{cuentas} en riesgo"
#    renders "1 cuenta en riesgo" and never "1 cuenta(s) en riesgo".
#  · Score bands are not re-thresholded here. `report.py` reads them from
#    `scoring.SCORE_BANDS`; if a band ever needs a WORD, it belongs in this
#    section keyed by the band name, not as a fifth copy of the numbers.

REPORT: dict[str, tuple[str, str] | dict] = {
    # --- nouns that agree with a count (passed through wording.con_numero)
    "cuenta": ("cuenta", "account"),
    "cuentas": ("cuentas", "accounts"),
    "hallazgo": ("hallazgo", "finding"),
    "hallazgos": ("hallazgos", "findings"),
    # English does not inflect the severity adjective: "2 critical", not "2 criticals".
    "critico": ("crítico", "critical"),
    "criticos": ("críticos", "critical"),
    "alto": ("alto", "high"),
    "altos": ("altos", "high"),
    # --- headline
    "cuentas_en_riesgo": ("{cuentas} en riesgo", "{cuentas} at risk"),
    "de_ellas_graves": (
        "{n} de ellas con un problema crítico o alto",
        "{n} of them with a critical or high problem",
    ),
    "sin_exposicion_de_cuentas": (
        "No se ha encontrado exposición a nivel de cuenta.",
        "No account-level exposure was found.",
    ),
    "puntuacion_postura": ("puntuación de postura", "posture score"),
    "delta_anterior": (
        "{flecha} {n} respecto al anterior",
        "{flecha} {n} versus the previous scan",
    ),
    "sin_cambios_anterior": (
        "sin cambios respecto al anterior",
        "no change versus the previous scan",
    ),
    # --- fix this first
    "arregla_primero": ("Arregla esto primero", "Fix this first"),
    "arregla_primero_nota": (
        "Ordenado por hallazgos cerrados por minuto de trabajo, no por severidad. Hacer "
        "estas tres cosas, en este orden, elimina la mayor exposición con el menor esfuerzo.",
        "Ordered by findings closed per minute of work, not by severity. Doing these three "
        "things, in this order, removes the most exposure for the least effort.",
    ),
    "accion_numero": ("ACCIÓN {n}", "ACTION {n}"),
    "impacto": ("Impacto", "Impact"),
    "impacto_frase": (
        "cierra {hallazgos}{severidades}, afecta a {cuentas}{ganancia}.",
        "closes {hallazgos}{severidades}, affects {cuentas}{ganancia}.",
    ),
    "ganancia_puntuacion": (", puntuación +{n}", ", score +{n}"),
    "esfuerzo": ("Esfuerzo", "Effort"),
    "minutos": ("unos {n} minutos", "about {n} minutes"),
    "aviso_usuarios": ("Aviso para los usuarios", "Warning for users"),
    # --- changes since the previous scan
    "cambios_titulo": (
        "Cambios desde el escaneo anterior",
        "Changes since the previous scan",
    ),
    "cambios_motor": (
        "El conjunto de comprobaciones ha cambiado desde el último análisis: los resultados "
        "no son comparables, así que no se calcula la diferencia. Motor {antes} → {ahora}. "
        "La comparativa vuelve en el próximo escaneo, que ya usará el mismo conjunto que "
        "éste.",
        "The set of checks has changed since the last analysis: the results are not "
        "comparable, so no difference is calculated. Engine {antes} → {ahora}. The comparison "
        "returns with the next scan, which will already use the same set as this one.",
    ),
    "desconocido": ("desconocido", "unknown"),
    "primer_escaneo": (
        "Primer escaneo: todavía no hay comparativa disponible. El siguiente escaneo mostrará "
        "qué es nuevo, qué ha empeorado y qué se ha resuelto.",
        "First scan: no comparison is available yet. The next scan will show what is new, what "
        "got worse and what has been resolved.",
    ),
    "nuevos": ("Nuevos", "New"),
    "empeorados": ("Empeorados", "Worse"),
    "resueltos": ("Resueltos", "Resolved"),
    "cambios_organizacion": ("Cambios en tu organización", "Changes in your organisation"),
    "cobertura_titulo": (
        "Cambios en lo que Vigía alcanza a ver",
        "Changes in what Vigía can see",
    ),
    "cobertura_nota": (
        "Esto <strong>no</strong> son cambios en tu organización. Son comprobaciones que antes "
        "no se podían hacer y ahora sí, o al contrario: un permiso concedido o revocado, o un "
        "límite de la API de Google. Se listan aparte justamente para que no se confundan con "
        "una mejora o un empeoramiento de tu postura.",
        "These are <strong>not</strong> changes in your organisation. They are checks that "
        "could not be made before and now can, or the other way round: a scope granted or "
        "revoked, or a limit of Google's API. They are listed separately precisely so they are "
        "not mistaken for an improvement or a worsening of your posture.",
    ),
    "antes_no_comprobables": (
        "Antes no se podían comprobar",
        "Could not be checked before",
    ),
    "con_problema_abierto": ("{n} con un problema abierto", "{n} with an open problem"),
    "ya_no_comprobables": (
        "Han dejado de poder comprobarse",
        "Can no longer be checked",
    ),
    # --- one finding
    "flag_nuevo": ("NUEVO", "NEW"),
    "flag_ahora_visible": ("AHORA VISIBLE", "NOW VISIBLE"),
    "flag_ya_no_comprobable": ("YA NO SE PUEDE COMPROBAR", "NO LONGER CHECKABLE"),
    "flag_regresion": ("REGRESIÓN", "REGRESSION"),
    "afectados": ("Afectados ({n})", "Affected ({n})"),
    "y_mas": ("… y {n} más", "… and {n} more"),
    "direcciones_borradas": (
        "Las direcciones se han borrado según la política de retención de {horas} horas. "
        "Vuelve a escanear para verlas.",
        "The addresses were deleted under the {horas}-hour retention policy. Re-scan to see "
        "them.",
    ),
    "valor_actual": ("Valor actual", "Current value"),
    "como_mantenerlo": ("Cómo mantenerlo", "How to keep it"),
    "como_se_arregla": ("Cómo se arregla", "How to fix it"),
    "alcance": ("Alcance", "Scope"),
    "no_confirmado": (
        "Esta comprobación no se ha podido confirmar, así que nunca cuenta en la puntuación, "
        "ni a favor ni en contra.",
        "This check could not be confirmed, so it never counts towards the score, neither for "
        "nor against.",
    ),
    # --- people at risk
    "personas_riesgo": ("Personas en riesgo ({n})", "People at risk ({n})"),
    "personas_orden": ("Ordenadas por severidad combinada.", "Sorted by combined severity."),
    "personas_apiladas": (
        "{n} de ellas acumulan más de un problema a la vez: son las cuentas que un atacante "
        "solo tiene que acertar una vez.",
        "{n} of them carry more than one problem at once: they are the accounts an attacker "
        "only has to get right once.",
    ),
    "col_peor": ("Peor", "Worst"),
    "col_cuenta": ("Cuenta", "Account"),
    "col_problemas": ("Problemas", "Problems"),
    "col_aparece_en": ("Aparece en", "Appears in"),
    # --- mail and DNS records
    "registros_correo_dns": ("Registros de correo y DNS", "Email and DNS records"),
    "dominio_workspace": ("dominio de Workspace", "Workspace domain"),
    "dominio_manual": ("añadido manualmente", "added manually"),
    "col_comprobacion": ("Comprobación", "Check"),
    "col_estado": ("Estado", "Status"),
    "col_detalle": ("Detalle", "Detail"),
    "col_cambio": ("Cambio", "Change"),
    "col_hallazgos": ("Hallazgos", "Findings"),
    "col_comprobaciones": ("Comprobaciones", "Checks"),
    "spf_consultas": (
        "Consultas DNS: {n} del límite de 10 del RFC 7208",
        "DNS lookups: {n} of the RFC 7208 limit of 10",
    ),
    "spf_sobre_limite": (
        "por encima del límite: los receptores devuelven permerror y dejan de evaluar el SPF",
        "over the limit: receivers return permerror and stop evaluating SPF",
    ),
    "spf_mecanismo_final": ("mecanismo final: {mecanismo}", "final mechanism: {mecanismo}"),
    "dkim_tamano_clave": ("tamaño de clave: {bits} bits", "key size: {bits} bits"),
    "dkim_clave_debil": ("débil, rota a 2048 o más", "weak, rotate to 2048 or more"),
    "dkim_clave_adecuada": ("adecuado", "adequate"),
    "no_verificado": ("No verificado.", "Not verified."),
    "dkim_selector_no_encontrado": (
        "Se ha probado {selectores}, que es el selector que usa Workspace. Un dominio que "
        "firme con un selector propio no lo encuentra esta comprobación; no significa que no "
        "firmes. Escríbeme y lo verificamos a mano.",
        "{selectores} was tried, which is the selector Workspace uses. This check does not "
        "find a domain that signs with a selector of its own; that does not mean you are not "
        "signing. Write to me and we verify it by hand.",
    ),
    "dmarc_destino_propio": ("tu propio dominio", "your own domain"),
    "dmarc_destino_tercero": (
        "solo a un tercero: nunca ves tu propia telemetría",
        "only to a third party: you never see your own telemetry",
    ),
    "dmarc_destino_ninguno": (
        "a ningún sitio: sin etiqueta rua, así que no hay informes",
        "nowhere: no rua tag, so there are no reports",
    ),
    "dmarc_politica": ("política: p={p}", "policy: p={p}"),
    "sin_definir": ("sin definir", "not set"),
    "dmarc_alineacion": (
        "alineación: DKIM {dkim}, SPF {spf}",
        "alignment: DKIM {dkim}, SPF {spf}",
    ),
    "alineacion_estricta": ("estricta", "strict"),
    "alineacion_relajada": ("relajada", "relaxed"),
    "dmarc_informes_van_a": ("los informes van a: {destino}", "reports go to: {destino}"),
    # --- how the score was calculated
    "puntuacion_calculo": (
        "Cómo se ha calculado la puntuación",
        "How the score was calculated",
    ),
    "pesos_y_credito": (
        "Pesos por severidad: {pesos}. Crédito: correcto 100%, aviso 50%, fallo 0%. La "
        "puntuación se reparte en dos bloques que se leen distinto:",
        "Severity weights: {pesos}. Credit: pass 100%, warn 50%, fail 0%. The score is split "
        "into two blocks that read differently:",
    ),
    "bloque_ajustes": (
        "<strong>Ajustes de la organización</strong> (Consola de Administración, DNS, registro "
        "de auditoría, aplicaciones de terceros): cada uno cuenta <strong>una sola vez</strong>. "
        "Es una decisión de un administrador, no un fallo de cada empleado, y contarla por "
        "cabeza hacía que un solo interruptor pesara tanto como la plantilla entera.",
        "<strong>Organisation settings</strong> (Admin console, DNS, audit log, third-party "
        "apps): each one counts <strong>once only</strong>. It is one administrator's decision, "
        "not a failure by each employee, and counting it per head made a single switch weigh as "
        "much as the entire payroll.",
    ),
    "bloque_cuentas": (
        "<strong>Cuentas</strong>: cada persona cuenta una sola vez, con la peor severidad en "
        "la que aparece, así que alguien con varias debilidades es una exposición y no cuatro.",
        "<strong>Accounts</strong>: each person counts once only, at the worst severity they "
        "appear in, so somebody with several weaknesses is one exposure and not four.",
    ),
    "escala_cuentas": (
        "En este tenant el bloque de cuentas se ha reducido al {porcentaje} de su peso bruto "
        "para que no supere al de ajustes: si no, en una organización grande la configuración "
        "quedaría reducida a un decimal solo por tener más plantilla.",
        "In this tenant the accounts block was scaled down to {porcentaje} of its raw weight so "
        "it cannot outweigh the settings one: otherwise, in a large organisation the "
        "configuration would be reduced to a decimal place just for having more staff.",
    ),
    "excluidos_de_la_puntuacion": (
        "Los hallazgos informativos, manuales o no verificados quedan excluidos por completo: "
        "la incertidumbre nunca suma ni resta.",
        "Informational, manual and unverified findings are excluded entirely: uncertainty never "
        "adds and never subtracts.",
    ),
    "col_elemento": ("Elemento", "Item"),
    "col_severidad": ("Severidad", "Severity"),
    "col_peso": ("Peso", "Weight"),
    "col_obtenido": ("Obtenido", "Earned"),
    "col_de": ("De", "From"),
    "total": ("Total", "Total"),
    "puntuacion_sobre_cien": ("puntuación {n}/100", "score {n}/100"),
    # The account also appears in N further findings, shown next to its id.
    "tambien_en": ("(+{n} más)", "(+{n} more)"),
    # --- the page where the reader can answer the report
    "correo_asunto": (
        "Vigía — arreglar los hallazgos de {dominio}",
        "Vigía — fixing the findings for {dominio}",
    ),
    "correo_cuerpo": (
        "Hola Diego:\n\nHe pasado el informe de Vigía en {dominio}{puntuacion}.\n\nMe gustaría "
        "hablar de la remediación.\n\n",
        "Hello Diego,\n\nI have run the Vigía report on {dominio}{puntuacion}.\n\nI would like "
        "to talk about remediation.\n\n",
    ),
    "correo_puntuacion": (" (puntuación {n}/100)", " (score {n}/100)"),
    "arreglamos_titulo": ("¿Quieres que lo arreglemos?", "Would you like us to fix it?"),
    "arreglamos_intro": (
        "Este informe dice qué está mal y dónde se toca. Si prefieres que lo haga alguien que "
        "ya ha hecho esto antes, lo hago yo contigo:",
        "This report says what is wrong and where it is changed. If you would rather it were "
        "done by somebody who has done this before, I do it with you:",
    ),
    "arreglamos_auditoria": (
        "<strong>Auditoría del informe contigo</strong>: repasamos hallazgo por hallazgo qué "
        "aplica a vuestro caso y qué no. No todo lo crítico lo es para todas las "
        "organizaciones.",
        "<strong>A walk-through of the report with you</strong>: we go finding by finding "
        "through what applies to your case and what does not. Not everything critical is "
        "critical for every organisation.",
    ),
    "arreglamos_criticos": (
        "<strong>Arreglo de los hallazgos críticos y altos</strong>, en tu Consola de "
        "Administración, con vosotros delante y explicando cada cambio.",
        "<strong>Fixing the critical and high findings</strong>, in your Admin console, with "
        "you watching and every change explained.",
    ),
    "arreglamos_sesion": (
        "<strong>Sesión con quien lleve la informática</strong> en casa, para que quede quien "
        "sepa mantenerlo, no una dependencia de mí.",
        "<strong>A session with whoever runs IT</strong> in-house, so somebody is left there "
        "who knows how to keep it up, rather than a dependency on me.",
    ),
    "arreglamos_documentacion": (
        "<strong>Documentación</strong> de lo que se cambió y por qué, que os sirve además para "
        "auditorías y para clientes que os la pidan.",
        "<strong>Documentation</strong> of what was changed and why, which also serves you for "
        "audits and for customers who ask you for it.",
    ),
    "arreglamos_repeticion": (
        "Y si quieres, <strong>repetimos la revisión cada cierto tiempo</strong>: es lo que "
        "impide volver al punto de partida en seis meses.",
        "And if you want, <strong>we repeat the review every so often</strong>: that is what "
        "stops you ending up back where you started in six months.",
    ),
    "arreglamos_precio": (
        "Escríbeme y te contesto yo. El precio depende de lo que haya que hacer, así que lo "
        "hablamos por correo con el informe delante.",
        "Write to me and I answer you myself. The price depends on what needs doing, so we "
        "discuss it by e-mail with the report in front of us.",
    ),
    # --- provenance
    "datos_analizados": ("Datos analizados", "Data analysed"),
    # --- the one page a stranger reads
    "resumen_direccion": ("Resumen para dirección", "Executive summary"),
    "resumen_lead": (
        "análisis de solo lectura de Google Workspace. Esta página se lee en un minuto; el "
        "detalle técnico viene después.",
        "read-only analysis of Google Workspace. This page reads in a minute; the technical "
        "detail comes afterwards.",
    ),
    "puntuacion_sobre_100": ("puntuación sobre 100", "score out of 100"),
    "cuentas_realmente_en_riesgo": (
        "cuentas realmente en riesgo",
        "accounts genuinely at risk",
    ),
    "sin_problemas_abiertos": (
        "No se ha encontrado ningún problema abierto.",
        "No open problems were found.",
    ),
    "lo_mas_grave": ("Lo más grave, en tres frases", "The worst of it, in three sentences"),
    "por_donde_empezar": ("Por dónde empezar", "Where to start"),
    "cierra_hallazgos": ("cierra {hallazgos}", "closes {hallazgos}"),
    "nada_pendiente": ("Nada pendiente.", "Nothing outstanding."),
    # --- document chrome
    "titulo_documento": (
        "Informe de Vigía — {dominio}",
        "Vigía report — {dominio}",
    ),
    # The browser's own menu labels, so the instruction matches what the reader is
    # looking at while following it.
    "guardar_pdf": (
        "<strong>Para guardarlo en PDF:</strong> pulsa Ctrl+P (⌘P en Mac) y elige “Guardar como "
        "PDF”. Deja activada la opción “Gráficos de fondo” para que se mantengan los colores de "
        "severidad. Este aviso no aparece en la versión impresa.",
        "<strong>To save it as a PDF:</strong> press Ctrl+P (⌘P on Mac) and choose “Save as "
        "PDF”. Leave the “Background graphics” option on so the severity colours survive. This "
        "notice does not appear in the printed version.",
    ),
    "informe_postura": ("Informe de postura de seguridad", "Security posture report"),
    "escaneado_el": (
        "Escaneado el {fecha} · análisis de solo lectura de Google Workspace · nunca se han "
        "solicitado permisos de contenido de Gmail ni de Drive",
        "Scanned on {fecha} · read-only analysis of Google Workspace · content scopes for Gmail "
        "and Drive were never requested",
    ),
    "ajustes_organizacion": ("Ajustes de la organización ({n})", "Organisation settings ({n})"),
    "ajustes_organizacion_nota": (
        "Configuración del tenant: lo decide un administrador en la Consola de Administración y "
        "afecta a todo el mundo por igual. No es un fallo de ninguna persona en concreto.",
        "Tenant configuration: an administrator decides it in the Admin console and it affects "
        "everybody alike. It is not any one person's failure.",
    ),
    "hallazgos_por_cuenta": ("Hallazgos por cuenta ({n})", "Account-level findings ({n})"),
    "hallazgos_por_cuenta_nota": (
        "Cosas que son ciertas de personas concretas: sin segundo factor, nunca han iniciado "
        "sesión, privilegios de administrador, recuperación mal puesta, acceso desde un país "
        "nuevo.",
        "Things that are true of specific people: no second factor, never signed in, admin "
        "privileges, recovery set up badly, access from a new country.",
    ),
    "comprobaciones_manuales": ("Comprobaciones manuales ({n})", "Manual checks ({n})"),
    "comprobaciones_manuales_nota": (
        "Vigía no ha podido leer estos ajustes automáticamente, así que verifícalos a mano. "
        "Desaparecen de esta lista en cuanto una comprobación automática pueda confirmarlos.",
        "Vigía could not read these settings automatically, so verify them by hand. They leave "
        "this list as soon as an automatic check can confirm them.",
    ),
    "comprobacion_manual": ("Comprobación manual", "Manual check"),
    "generado_por": ("Informe generado por Vigía", "Report generated by Vigía"),
    "motor": ("motor {version}", "engine {version}"),
    # --- CSV export. The column names are the headings a spreadsheet shows, read
    # by the same customer who reads the PDF.
    "csv": {
        "id": ("id", "id"),
        "titulo": ("titulo", "title"),
        "severidad": ("severidad", "severity"),
        "estado": ("estado", "status"),
        "alcance": ("alcance", "scope"),
        "ventana_leida": ("ventana_leida", "window_read"),
        "cambio": ("cambio", "change"),
        "regresion": ("regresion", "regression"),
        "num_afectados": ("num_afectados", "affected_count"),
        "afectados": ("afectados", "affected"),
        "cuentas": ("cuentas", "accounts"),
        "control_cis": ("control_cis", "cis_control"),
        "remediacion": ("remediacion", "remediation"),
    },
    "csv_direcciones_borradas": (
        "(direcciones borradas: retención de {horas} h)",
        "(addresses deleted: {horas} h retention)",
    ),
}


# ------------------------------------------------ the page for the decider
# The plain-language cover. Written for the person who decides whether the work
# happens, so it avoids the vocabulary of the trade in BOTH languages: no 2SV,
# no scopes, no DKIM — "second factor", "third-party application", "signing".
#
# `plain` is keyed by finding id. Its ORDER is deliberately not here: the
# editorial order that breaks ties between two overlapping findings is ranking
# logic and lives in `executive.PLAIN`.

EXECUTIVE: dict[str, tuple[str, str] | dict] = {
    # Nouns the sentences need already agreed with their count.
    "cuenta": ("cuenta", "account"),
    "cuentas": ("cuentas", "accounts"),
    "cuenta_compartida": ("cuenta compartida", "shared account"),
    "cuentas_compartidas": ("cuentas compartidas", "shared accounts"),
    "plain": {
        "composite-superadmin-no-2sv-no-recovery": (
            "{cuentas} con control total del dominio no tienen segundo factor ni forma de "
            "recuperación: si le roban la contraseña a cualquiera de ellas, se pierde el "
            "control del correo de la empresa y no hay manera rápida de recuperarlo.",
            "{cuentas} with full control of the domain have no second factor and no way back "
            "in: if the password of any one of them is stolen, control of the company's email "
            "is lost and there is no quick way to recover it.",
        ),
        "composite-superadmin-dormant-no-2sv": (
            "{cuentas} con control total del dominio no se usan y no tienen segundo factor. "
            "Nadie las vigila y nadie notaría que alguien ha entrado en ellas.",
            "{cuentas} with full control of the domain are not in use and have no second "
            "factor. Nobody is watching them and nobody would notice somebody getting in.",
        ),
        "composite-superadmin-no-2sv": (
            "{cuentas} que pueden cambiar cualquier cosa en la organización entran solo con "
            "contraseña. Una contraseña se roba con un correo de phishing bien hecho.",
            "{cuentas} that can change anything in the organisation get in with nothing but a "
            "password. A password is stolen with one well-made phishing email.",
        ),
        "recovery-super-admins": (
            "{n} de las cuentas con más permisos no tienen forma segura de recuperarse: si se "
            "pierden, la única vía de vuelta es el soporte de Google, que tarda días.",
            "{n} of the accounts with the most permissions have no safe way back: if they are "
            "lost, the only route in is Google support, which takes days.",
        ),
        "composite-enforced-but-not-enrolled": (
            "{cuentas} se saltan la obligación de usar segundo factor que la propia "
            "organización tiene activada: existe la norma y hay quien no la cumple.",
            "{cuentas} get around the second-factor requirement the organisation itself has "
            "switched on: the rule exists and some people are not following it.",
        ),
        "composite-dormant-no-2sv": (
            "{cuentas} sin usar y sin segundo factor siguen activas. Son las que un atacante "
            "prefiere, porque nadie va a notar la actividad.",
            "{cuentas} that are unused and have no second factor are still active. They are the "
            "ones an attacker prefers, because nobody is going to notice the activity.",
        ),
        "composite-service-account-no-2sv": (
            "{compartidas} o de servicio entran solo con contraseña, y esa contraseña suele "
            "estar en un documento que ha visto mucha gente.",
            "{compartidas} or service accounts get in with nothing but a password, and that "
            "password is usually in a document plenty of people have seen.",
        ),
        "composite-superadmin-dormant": (
            "{cuentas} con control total llevan meses sin usarse. Si nadie las necesita, cada "
            "día que siguen abiertas es riesgo sin contrapartida.",
            "{cuentas} with full control have gone months without being used. If nobody needs "
            "them, every day they stay open is risk with nothing in return.",
        ),
        "2sv-users": (
            "{n} personas entran a su correo de trabajo solo con contraseña. Es el camino por "
            "el que entra la mayoría de los incidentes de correo.",
            "{n} people get into their work email with nothing but a password. It is the route "
            "most email incidents come in by.",
        ),
        "admin-login-new-country": (
            "{cuentas} con control total del dominio han entrado desde un país donde nunca "
            "antes se habían usado. Puede ser un viaje, o puede no serlo.",
            "{cuentas} with full control of the domain have been used from a country they had "
            "never been used from before. It may be a trip, or it may not.",
        ),
        "policy-2sv-methods": (
            "El segundo factor admite código por SMS, que se intercepta duplicando la tarjeta "
            "del móvil. Protege menos de lo que la gente cree que protege.",
            "The second factor accepts a code by text message, which is intercepted by cloning "
            "the mobile's card. It protects less than people believe it does.",
        ),
        "policy-gmail-forwarding": (
            "Cualquiera puede configurar que su correo de trabajo se copie automáticamente a "
            "una dirección de fuera, y sigue copiándose después de que deje la empresa.",
            "Anybody can set their work email to be copied automatically to an outside address, "
            "and it keeps being copied after they leave the company.",
        ),
        "policy-drive-sharing": (
            "Cualquier documento de la organización se puede compartir con alguien de fuera en "
            "dos clics, sin que nadie se entere ni quede aviso.",
            "Any document in the organisation can be shared with somebody outside in two "
            "clicks, with nobody finding out and no warning left behind.",
        ),
        "policy-password": (
            "Las contraseñas admitidas son más cortas de lo aconsejable, lo que las deja al "
            "alcance de un ataque automático de prueba y error.",
            "The passwords allowed are shorter than is advisable, which puts them within reach "
            "of an automated trial-and-error attack.",
        ),
        "policy-marketplace": (
            "Cualquiera puede conectar una aplicación de terceros a los datos de la empresa sin "
            "que un administrador lo apruebe.",
            "Anybody can connect a third-party application to the company's data without an "
            "administrator approving it.",
        ),
        "policy-groups-sharing": (
            "Las listas de correo internas son accesibles desde fuera de la organización, con "
            "años de conversaciones que nadie ha revisado.",
            "The internal mailing lists can be reached from outside the organisation, with "
            "years of conversations nobody has reviewed.",
        ),
        "oauth-high-risk": (
            "Hay aplicaciones de terceros con acceso amplio al correo y a los archivos de la "
            "empresa. Si una de ellas sufre una brecha, es una brecha vuestra.",
            "There are third-party applications with broad access to the company's email and "
            "files. If one of them suffers a breach, it is a breach of yours.",
        ),
        "oauth-dwd": (
            "Hay aplicaciones que pueden actuar en nombre de cualquier empleado sin que esa "
            "persona lo autorice ni se entere.",
            "There are applications that can act in the name of any employee without that "
            "person authorising it or even knowing.",
        ),
        "email-spf": (
            "Cualquiera puede enviar correo haciéndose pasar por vuestro dominio, y a quien lo "
            "reciba le va a parecer auténtico.",
            "Anybody can send email pretending to be your domain, and it will look genuine to "
            "whoever receives it.",
        ),
        "email-dmarc": (
            "No le decís a los servidores de correo qué hacer con los mensajes falsos que usan "
            "vuestro dominio, así que muchos los entregan igual.",
            "You are not telling mail servers what to do with the fake messages that use your "
            "domain, so many of them deliver those anyway.",
        ),
        "audit-risky-changes": (
            "Se han hecho cambios de configuración con impacto en seguridad. No significa que "
            "sean maliciosos, pero conviene que alguien confirme que son suyos.",
            "Configuration changes with an impact on security have been made. It does not mean "
            "they are malicious, but somebody should confirm they are theirs.",
        ),
        "super-admin-count": (
            "Hay {n} personas con control total del dominio. Cada una es una llave maestra, y "
            "cada llave maestra es una forma de perderlo todo.",
            "There are {n} people with full control of the domain. Each one is a master key, "
            "and each master key is a way of losing everything.",
        ),
    },
    # A finding nobody wrote a sentence for. Serviceable rather than clever: the
    # title already says what it is.
    "frase_generica": ("{titulo} — afecta a {n}.", "{titulo} — affects {n}."),
    # The critical figure and its split, so page one and page two cannot disagree.
    "criticos": ("{n} críticos", "{n} critical"),
    "criticos_desglose": (
        ", {fallos} en fallo y {avisos} en aviso",
        ", {fallos} failing and {avisos} warning",
    ),
    "criticos_en_fallo": (" en fallo", " failing"),
    "ninguno_critico": ("ninguno crítico", "none critical"),
    # What happens if nobody does anything. Never a threat: every clause can be
    # checked against the pages that follow.
    "cierre_limpio": (
        "No hay nada urgente. Lo que queda son ajustes que conviene apretar cuando haya un "
        "rato, no cosas que quiten el sueño.",
        "There is nothing urgent. What is left are settings worth tightening when there is a "
        "moment, not things to lose sleep over.",
    ),
    "cierre_criticos": (
        "Si no se toca nada: {criticos} de estos problemas están clasificados como críticos, y "
        "todos ellos comparten la misma consecuencia — que una sola contraseña robada baste "
        "para controlar el correo de la organización. No hace falta un ataque sofisticado; "
        "basta con que una persona pique una vez. Los {ajustes} ajustes de configuración "
        "pendientes son, además, los que deciden lo lejos que llega quien entre.",
        "If nothing is touched: {criticos} of these problems are classified as critical, and "
        "all of them share the same consequence — that one stolen password is enough to "
        "control the organisation's email. No sophisticated attack is needed; one person taking "
        "the bait once is enough. The {ajustes} configuration settings still pending are, on "
        "top of that, the ones that decide how far whoever gets in can go.",
    ),
    # The two counted phrases are assembled by `wording.contar` and arrive already
    # agreed, so the sentence never has to guess. It used to read "hay 1 cuenta
    # expuestas" — the adjective was fixed in the plural outside the number — and
    # the English inherited the same shape as "there are 1 account exposed". Both
    # were in reports going to customers. The verb is now inside the counted pair,
    # which is the only place that knows whether it is one or several.
    "cierre_sin_criticos": (
        "Si no se toca nada: {cuentas} y {ajustes}. Ninguno es una emergencia hoy, pero cada "
        "uno amplía lo que puede hacer alguien que entre por cualquier otra vía.",
        "If nothing is touched: {cuentas} and {ajustes}. Neither is an emergency today, but "
        "each one widens what somebody who gets in by any other route can do.",
    ),
    # And when there is nothing loose on the organisation side, the clause is not
    # printed as "y 0 ajustes": it is dropped, and the closing pronoun changes with
    # it, because "ninguno" needs more than one thing to refer to.
    "cierre_sin_criticos_sin_ajustes": (
        "Si no se toca nada: {cuentas}. No es una emergencia hoy, pero amplía lo que puede "
        "hacer alguien que entre por cualquier otra vía.",
        "If nothing is touched: {cuentas}. It is not an emergency today, but it widens what "
        "somebody who gets in by any other route can do.",
    ),
    "cuentas_expuestas_uno": (
        "hay {n} cuenta expuesta",
        "there is {n} exposed account",
    ),
    "cuentas_expuestas_varios": (
        "hay {n} cuentas expuestas",
        "there are {n} exposed accounts",
    ),
    "ajustes_flojos_uno": (
        "{n} ajuste de la organización sin apretar",
        "{n} organisation setting left loose",
    ),
    "ajustes_flojos_varios": (
        "{n} ajustes de la organización sin apretar",
        "{n} organisation settings left loose",
    ),
}


def build(index: int) -> dict:
    return {
        "severity": {k: v[index] for k, v in SEVERITY.items()},
        "status": {k: v[index] for k, v in STATUS.items()},
        "findings": {fid: _pick(fields, index) for fid, fields in FINDINGS.items()},
        "manual": {mid: _pick(fields, index) for mid, fields in MANUAL.items()},
        "dns": _pick(DNS, index),
        "proyeccion": _pick(PROYECCION, index),
        "remediation": {aid: _pick(fields, index) for aid, fields in REMEDIATION.items()},
        "email": _pick(EMAIL, index),
        "report": _pick(REPORT, index),
        "executive": _pick(EXECUTIVE, index),
    }


def main() -> None:
    out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vigia", "locales")
    os.makedirs(out_dir, exist_ok=True)
    for lang, index in (("es", ES), ("en", EN)):
        catalog = build(index)
        path = os.path.join(out_dir, f"{lang}.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(catalog, handle, ensure_ascii=False, indent=2)
        print(
            f"{lang}.json: {len(catalog['findings'])} hallazgos, "
            f"{len(catalog['manual'])} manuales, "
            f"{len(catalog['remediation'])} acciones, "
            f"{len(catalog['email'])} bloques de correo"
        )


if __name__ == "__main__":
    main()
