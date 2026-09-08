"""Admin-console settings, read through the Cloud Identity Policy API.

Every verdict here runs through `policy_engine`, which reduces the raw
policies to an effective value **per account** and distinguishes three states
instead of two:

* explicitly set to something unsafe        → fail
* explicitly set to something safe          → pass
* no policy at all                          → Google's documented default is
  evaluated. Five of these settings default to the permissive value, so the
  old behaviour — reporting "not verified" and printing a manual card — was
  hiding the most common real exposure there is.

Because policies are scoped to organizational units and the directory gives us
each account's `orgUnitPath`, a finding does not say "sharing is on". It says
*which* accounts are exposed and which organizational units are already
locked down.

Every predicate is fail-closed: an enum Google adds later, a field that gets
renamed, or a group-scoped policy whose membership we cannot read all put
accounts in "unresolved", never in "safe".
"""
from __future__ import annotations

from ..wording import con_numero

from ..google_client.policy import PolicyUnavailable
from . import policy_engine as pe
from .finding import ORG_SCOPE, Finding
from .util import cap_items, is_active

#: The data sources this module's findings rest on. `collect_findings`
#: demotes every verdict here to «no verificado» when any of them was read
#: incompletely — inherited, not remembered per check.
SOURCES = ('users', 'policies')


CHECK_ID = "policies"

_ACTIONS = {
    "policy-drive-sharing": ["restrict_drive_sharing"],
    "policy-gmail-forwarding": ["disable_auto_forwarding"],
    "policy-password": ["strengthen_password_policy"],
    "policy-session": ["set_session_limit"],
    "policy-marketplace": ["restrict_marketplace"],
    "policy-groups-sharing": ["restrict_groups_external"],
    "policy-2sv-methods": ["enforce_2sv_org"],
    "policy-2sv-grace": ["enforce_2sv_org"],
    "policy-2sv-enforcement": ["enforce_2sv_org"],
}


def _duration_seconds(raw) -> int | None:
    """Protobuf durations arrive as '36000s' (or a plain number)."""
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        return int(raw)
    try:
        return int(float(str(raw).strip().rstrip("s")))
    except ValueError:
        return None


def _enum(effective, field: str) -> str:
    return str(effective.value.get(field) or "").upper()


def _flag(effective, field: str):
    """A boolean field, or None when it is absent or not a boolean."""
    value = effective.value.get(field)
    return value if isinstance(value, bool) else None


# ------------------------------------------------------------ predicates
# True = exposed, False = safe, None = cannot tell. None is never a pass: it
# moves those accounts into the unresolved list.

def _unsafe_drive_sharing(effective):
    mode = _enum(effective, "external_sharing_mode")
    if mode not in ("ALLOWED", "ALLOWLISTED_DOMAINS", "DISALLOWED"):
        return None
    if mode == "ALLOWED":
        return True
    # An allowlist is better than wide open, but it is still a way out.
    return "warn" if mode == "ALLOWLISTED_DOMAINS" else False


def _unsafe_link_default(effective):
    access = _enum(effective, "default_file_access")
    # Google spells the safe value two ways across its own pages.
    safe = ("PRIVATE_TO_OWNER", "LINK_SHARING_PRIVATE")
    known = safe + ("PRIMARY_AUDIENCE_WITH_LINK", "PRIMARY_AUDIENCE_WITH_LINK_OR_SEARCH")
    if access not in known:
        return None
    return access not in safe


def _unsafe_forwarding(effective):
    return _flag(effective, "enable_auto_forwarding")


def _unsafe_imap(effective):
    return _flag(effective, "enable_imap_access")


def _unsafe_pop(effective):
    return _flag(effective, "enable_pop_access")


def _unsafe_lsa(effective):
    return _flag(effective, "allow_less_secure_apps")


def _unsafe_password(effective):
    minimum = effective.value.get("minimum_length")
    reuse = effective.value.get("allow_reuse")
    if not isinstance(minimum, (int, float)) and not isinstance(reuse, bool):
        return None
    if isinstance(minimum, (int, float)) and minimum < 12:
        return True
    if reuse is True:
        return True
    # Forced rotation is not a failure, but NIST advises against it.
    expiry = _duration_seconds(effective.value.get("expiration_duration"))
    return "warn" if expiry else False


def _unsafe_session(effective):
    seconds = _duration_seconds(effective.value.get("web_session_duration"))
    if seconds is None:
        return None
    return "warn" if seconds > 24 * 7 * 3600 else False


def _unsafe_2sv_grace(effective):
    """Two tiers on purpose: over a fortnight is a window worth flagging, over
    a month it has stopped being a rollout margin and is a permanent hole."""
    seconds = _duration_seconds(effective.value.get("enrollment_grace_period"))
    if seconds is None:
        return None
    if seconds > 30 * 86400:
        return True
    return "warn" if seconds > 14 * 86400 else False


def _unsafe_2sv_factor(effective):
    factor = _enum(effective, "allowed_sign_in_factor_set")
    known = ("ALL", "NO_TELEPHONY", "PASSKEY_ONLY", "PASSKEY_PLUS_SECURITY_CODE",
             "PASSKEY_PLUS_IP_BOUND_SECURITY_CODE")
    if factor not in known:
        return None
    return factor == "ALL"


def _unsafe_2sv_enforcement(effective):
    """No enforcement date means the second factor is optional."""
    return not effective.value.get("enforced_from")


_CALENDARIO = {
    "EXTERNAL_FREE_BUSY_ONLY": "solo libre/ocupado, sin detalles",
    "EXTERNAL_ALL_INFO_READ_ONLY": "todos los detalles del evento, en solo lectura",
    "EXTERNAL_ALL_INFO_READ_WRITE": "todos los detalles, y además se pueden modificar",
    "EXTERNAL_ALL_INFO_READ_WRITE_MANAGE": "todos los detalles y gestión completa",
    "EXTERNAL_SHARING_DISALLOWED": "nada: no se comparte fuera",
}


def _unsafe_calendar(effective):
    """Free/busy is fine; anything that leaks the event itself is not.

    The title of a meeting is often the whole secret: "Due diligence Acme",
    "Rescisión Juan", "Consejo extraordinario". Someone outside the company
    reading a director's calendar learns what the company is about to do.
    """
    nivel = _enum(effective, "max_allowed_external_sharing")
    if nivel not in _CALENDARIO:
        return None
    if nivel in ("EXTERNAL_SHARING_DISALLOWED", "EXTERNAL_FREE_BUSY_ONLY"):
        return False
    return nivel != "EXTERNAL_ALL_INFO_READ_ONLY" or "warn"


def _calendar_observed(e) -> str:
    nivel = _enum(e, "max_allowed_external_sharing")
    return f"Visible desde fuera: {_CALENDARIO.get(nivel, nivel.lower())}" if nivel else ""


def _unsafe_marketplace(effective):
    level = _enum(effective, "access_level")
    if level not in ("ALLOW_ALL", "ALLOW_LISTED_APPS", "ALLOW_NONE"):
        return None
    return level == "ALLOW_ALL"


def _unsafe_groups(effective):
    capability = _enum(effective, "collaboration_capability")
    if capability not in ("ANYONE_CAN_ACCESS", "DOMAIN_USERS_ONLY"):
        return None
    return capability == "ANYONE_CAN_ACCESS"


# --------------------------------------------------------------- the table

class Check:
    def __init__(self, setting, finding_id, severity, title, why, remediation,
                 cis, console_url, unsafe, observed=None, no_default=False):
        self.setting = setting
        self.finding_id = finding_id
        self.severity = severity
        self.title = title
        self.why = why
        self.remediation = remediation
        self.cis = cis
        self.console_url = console_url
        self.unsafe = unsafe
        #: Optional: turn the reduced value into one plain sentence of fact.
        #: A verdict of "fail" on a setting with three knobs does not tell the
        #: admin which knob is wrong, and guessing costs them a trip to the
        #: console — or worse, they "fix" the two that were already right.
        self.observed = observed
        #: Google documents this setting but publishes no default value, so a
        #: tenant that never configured it has no readable answer. Flagged so
        #: the card can say that instead of leaving a bare "undetermined",
        #: which reads as a broken tool.
        self.no_default = no_default


def _dias(seconds) -> str:
    if seconds is None:
        return "?"
    if seconds == 0:
        return "ninguno"
    if seconds % 86400 == 0:
        return f"{con_numero(seconds // 86400, 'día')}"
    return f"{con_numero(round(seconds / 3600), "hora")}"


# --------------------------------------------------- what the setting says
#
# Every organization-scope finding shows the VALUE first and where it comes
# from second. "Política propia" tells the reader nothing they can act on;
# "periodo de gracia: 30 días" makes them pick up the phone. When the value is
# Google's default the reduction has already filled it in, so the same
# function prints the default itself rather than the fact that it is one.
#
# Each returns a short phrase, no trailing full stop: it gets composed into
# "<unidad>: <valor> · <procedencia>".

def _grace_observed(e) -> str:
    seconds = _duration_seconds(e.value.get("enrollment_grace_period"))
    if seconds is None:
        return ""
    if seconds == 0:
        return "Periodo de gracia: ninguno (2FA obligatoria desde el primer acceso)"
    return f"Periodo de gracia: {_dias(seconds)}"


def _enforcement_observed(e) -> str:
    desde = e.value.get("enforced_from")
    if not desde:
        return "Obligatoriedad: desactivada"
    return f"Obligatoriedad: activada desde {str(desde)[:10]}"


def _session_observed(e) -> str:
    seconds = _duration_seconds(e.value.get("web_session_duration"))
    if seconds is None:
        return "Duración máxima de sesión: sin límite"
    return f"Duración máxima de sesión: {_dias(seconds)}"


_FACTORES = {
    "ALL": "todos, incluidos SMS y llamada de voz",
    "NO_TELEPHONY": "todos menos SMS y llamada de voz",
    "PASSKEY_ONLY": "solo passkeys y llaves de seguridad",
    "PASSKEY_PLUS_SECURITY_CODE": "passkeys, llaves y código de seguridad",
    "PASSKEY_PLUS_IP_BOUND_SECURITY_CODE": "passkeys, llaves y código atado a la IP",
}


def _factor_observed(e) -> str:
    factor = _enum(e, "allowed_sign_in_factor_set")
    return f"Métodos permitidos: {_FACTORES.get(factor, factor.lower())}" if factor else ""


def _password_observed(e) -> str:
    minimum = e.value.get("minimum_length")
    reuse = e.value.get("allow_reuse")
    expiry = _duration_seconds(e.value.get("expiration_duration"))

    partes = []
    if isinstance(minimum, (int, float)):
        partes.append(f"Longitud mínima: {int(minimum)}")
    if isinstance(reuse, bool):
        partes.append(f"reutilización: {'permitida' if reuse else 'prohibida'}")
    if expiry is not None:
        partes.append(f"caducidad: {'ninguna' if not expiry else _dias(expiry)}")
    return " · ".join(partes)


_DRIVE = {
    "ALLOWED": "permitida sin restricción",
    "ALLOWLISTED_DOMAINS": "solo con dominios de la lista de permitidos",
    "DISALLOWED": "bloqueada",
}


def _drive_observed(e) -> str:
    mode = _enum(e, "external_sharing_mode")
    return f"Compartición externa: {_DRIVE.get(mode, mode.lower())}" if mode else ""


_ENLACE = {
    "PRIVATE_TO_OWNER": "restringido (solo quien lo cree)",
    "LINK_SHARING_PRIVATE": "restringido (solo quien lo cree)",
    "PRIMARY_AUDIENCE_WITH_LINK": "cualquiera de la organización con el enlace",
    "PRIMARY_AUDIENCE_WITH_LINK_OR_SEARCH": "cualquiera de la organización, incluso buscándolo",
}


def _link_observed(e) -> str:
    access = _enum(e, "default_file_access")
    return f"Enlace por defecto: {_ENLACE.get(access, access.lower())}" if access else ""


def _forwarding_observed(e) -> str:
    flag = _flag(e, "enable_auto_forwarding")
    if flag is None:
        return ""
    return f"Reenvío automático: {'permitido' if flag else 'bloqueado'}"


def _imap_observed(e) -> str:
    flag = _flag(e, "enable_imap_access")
    return "" if flag is None else f"IMAP: {'permitido' if flag else 'bloqueado'}"


def _pop_observed(e) -> str:
    flag = _flag(e, "enable_pop_access")
    return "" if flag is None else f"POP: {'permitido' if flag else 'bloqueado'}"


def _lsa_observed(e) -> str:
    flag = _flag(e, "allow_less_secure_apps")
    if flag is None:
        return ""
    return f"Acceso solo con contraseña: {'permitido' if flag else 'bloqueado'}"


_MARKET = {
    "ALLOW_ALL": "cualquier aplicación",
    "ALLOW_LISTED_APPS": "solo las de la lista de permitidas",
    "ALLOW_NONE": "ninguna sin aprobación",
}


def _marketplace_observed(e) -> str:
    level = _enum(e, "access_level")
    return f"Instalación: {_MARKET.get(level, level.lower())}" if level else ""


_GRUPOS = {
    "ANYONE_CAN_ACCESS": "público, accesible desde fuera de la organización",
    "DOMAIN_USERS_ONLY": "solo usuarios del dominio",
}


def _groups_observed(e) -> str:
    cap = _enum(e, "collaboration_capability")
    return f"Acceso desde fuera: {_GRUPOS.get(cap, cap.lower())}" if cap else ""


CONSOLE_2SV = "https://admin.google.com/ac/security/2sv"
CONSOLE_GMAIL = "https://admin.google.com/ac/apps/gmail/enduseraccess"
CONSOLE_DRIVE = "https://admin.google.com/ac/appsettings/55656082996"
CIS_2SV = "CIS GWS §1 — Verificación en dos pasos"

CHECKS: tuple[Check, ...] = (
    Check(
        "security.two_step_verification_enforcement", "policy-2sv-enforcement", "critical",
        "Obligatoriedad de la 2FA: cómo está configurada en la consola",
        "Mientras la 2FA no sea obligatoria, inscribirse es voluntario: quien no lo haga "
        "entra solo con contraseña, y quien ya la tenga puede quitársela cuando quiera. La "
        "obligatoriedad se configura por unidad organizativa, así que lo que importa no es "
        "si está activada, sino a quién alcanza.",
        "Consola de Administración > Seguridad > Autenticación > Verificación en dos pasos "
        "> Obligatoriedad: actívala para toda la organización, no solo para una unidad.",
        CIS_2SV, CONSOLE_2SV, _unsafe_2sv_enforcement,
        _enforcement_observed
    ),
    Check(
        "security.two_step_verification_enforcement_factor", "policy-2sv-methods", "high",
        "Métodos de segundo factor permitidos",
        "El SMS y la llamada de voz no son un segundo factor de verdad: se interceptan con "
        "un cambio de SIM, con un desvío en la operadora o con una página de phishing que "
        "pide el código y lo reenvía en el momento. Contra un ataque dirigido, una cuenta "
        "con 2FA por SMS está casi tan expuesta como una sin 2FA, con el agravante de que "
        "todo el mundo la considera protegida. Solo las passkeys y las llaves de seguridad "
        "resisten el phishing, porque la credencial está atada al dominio real.",
        "Consola de Administración > Seguridad > Autenticación > Verificación en dos pasos, "
        "apartado «Métodos»: quita el SMS y la llamada de voz. Empieza por las unidades de "
        "administradores y reparte llaves o passkeys antes de endurecerlo para todos.",
        "CIS GWS §1 — Verificación en dos pasos resistente al phishing",
        CONSOLE_2SV, _unsafe_2sv_factor,
        _factor_observed
    ),
    Check(
        "security.two_step_verification_grace_period", "policy-2sv-grace", "medium",
        "Periodo de gracia de la verificación en dos pasos",
        "El periodo de gracia es el tiempo que una cuenta nueva puede seguir entrando solo "
        "con contraseña. Durante esos días la obligatoriedad está anunciada pero no "
        "aplicada: es exactamente la ventana que busca quien roba credenciales, porque la "
        "cuenta ya existe y ya tiene permisos.",
        "Consola de Administración > Seguridad > Autenticación > Verificación en dos pasos: "
        "baja el periodo de gracia a una semana o menos.",
        CIS_2SV, CONSOLE_2SV, _unsafe_2sv_grace,
        _grace_observed
    ),
    Check(
        "gmail.imap_access", "policy-imap", "high",
        "Acceso IMAP a Gmail",
        "IMAP permite entrar al buzón con usuario y contraseña desde cualquier cliente de "
        "correo, sin pasar por el desafío de la verificación en dos pasos. Es la puerta "
        "lateral clásica: quien tenga la contraseña lee todo el correo sin tocar la "
        "pantalla de acceso de Google y sin dejar el rastro de un inicio de sesión web.",
        "Consola de Administración > Aplicaciones > Google Workspace > Gmail > Acceso de "
        "usuario final: desactiva IMAP o limítalo a los clientes que hayas aprobado.",
        "CIS GWS §3 (Gmail) — Restringir los protocolos de correo heredados",
        CONSOLE_GMAIL, _unsafe_imap,
        _imap_observed, no_default=True
    ),
    Check(
        "gmail.pop_access", "policy-pop", "high",
        "Acceso POP a Gmail",
        "POP tiene el mismo problema que IMAP y uno peor: descarga los mensajes a la "
        "máquina del cliente, así que una vez copiados quedan fuera de tu control, de tu "
        "retención y de cualquier borrado que hagas después.",
        "Consola de Administración > Aplicaciones > Google Workspace > Gmail > Acceso de "
        "usuario final: desactiva POP. Casi nunca hace falta.",
        "CIS GWS §3 (Gmail) — Restringir los protocolos de correo heredados",
        CONSOLE_GMAIL, _unsafe_pop,
        _pop_observed, no_default=True
    ),
    Check(
        "security.less_secure_apps", "policy-less-secure-apps", "high",
        "Aplicaciones menos seguras (acceso solo con contraseña)",
        "Las aplicaciones menos seguras acceden con usuario y contraseña, sin OAuth y sin "
        "el desafío de 2FA. Este ajuste importa MÁS, no menos, cuando ya tienes la 2FA "
        "obligatoria: es precisamente la vía que la deja sin efecto. Y como la conexión no "
        "es interactiva, tampoco genera el aviso de inicio de sesión sospechoso.",
        "Consola de Administración > Seguridad > Acceso y control de datos > Aplicaciones "
        "menos seguras: desactívalo. Lo que lo necesite debe migrar a OAuth.",
        "CIS GWS §1 — Bloquear el acceso solo con contraseña",
        "https://admin.google.com/ac/security/lsa", _unsafe_lsa,
        _lsa_observed
    ),
    Check(
        "gmail.auto_forwarding", "policy-gmail-forwarding", "high",
        "Reenvío automático de Gmail",
        "El reenvío automático saca copia de todo el correo a un buzón de fuera, y sigue "
        "funcionando después de que la persona deje la empresa. Es la forma más silenciosa "
        "de exfiltrar correo que existe, y Google lo deja ACTIVADO por defecto.",
        "Consola de Administración > Aplicaciones > Google Workspace > Gmail > Acceso de "
        "usuario final: desactiva el reenvío automático, al menos en las unidades "
        "sensibles. Las reglas que cada persona ya tenga puestas se auditan aparte, en "
        "Informes > Búsqueda en registros de correo.",
        "CIS GWS §3 (Gmail) — Restringir el reenvío automático",
        CONSOLE_GMAIL, _unsafe_forwarding,
        _forwarding_observed
    ),
    Check(
        "drive_and_docs.external_sharing", "policy-drive-sharing", "high",
        "Uso compartido externo de Drive",
        "Con el uso compartido externo abierto, cualquiera puede sacar un documento de la "
        "organización con dos clics y sin dejar aviso. Google lo deja PERMITIDO por "
        "defecto, así que no tocar este ajuste no es una postura neutra.",
        "Consola de Administración > Aplicaciones > Google Workspace > Drive y Documentos "
        "> Configuración de uso compartido: pon el uso compartido fuera de la organización "
        "en DESACTIVADO o solo dominios permitidos.",
        "CIS GWS §4 (Drive) — Restringir el uso compartido externo",
        CONSOLE_DRIVE, _unsafe_drive_sharing,
        _drive_observed
    ),
    Check(
        "drive_and_docs.general_access_default", "policy-drive-link-default", "medium",
        "Acceso por defecto de los archivos nuevos de Drive",
        "Es el valor que lleva cada archivo que alguien crea. Si por defecto es «cualquiera "
        "con el enlace», la fuga no necesita un error humano: ocurre sola cada vez que se "
        "comparte un documento sin mirar.",
        "Consola de Administración > Aplicaciones > Google Workspace > Drive y Documentos "
        "> Configuración de uso compartido > Acceso general por defecto: ponlo en "
        "«Restringido».",
        "CIS GWS §4 (Drive) — Acceso por defecto de los archivos",
        CONSOLE_DRIVE, _unsafe_link_default,
        _link_observed
    ),
    Check(
        "security.password", "policy-password", "medium",
        "Política de contraseñas",
        "La longitud mínima y la prohibición de reutilizar son lo único que separa una "
        "contraseña de un ataque de diccionario. Google trae 8 caracteres por defecto, por "
        "debajo de lo que hoy se considera aceptable.",
        "Consola de Administración > Seguridad > Autenticación > Gestión de contraseñas: "
        "mínimo 12 caracteres, prohibir la reutilización y quitar la caducidad forzada (el "
        "NIST recomienda no forzarla).",
        "CIS GWS §1 — Exigir una política de contraseñas robusta",
        "https://admin.google.com/ac/security/passwordmanagement", _unsafe_password,
        _password_observed,
    ),
    Check(
        "workspace_marketplace.apps_access_options", "policy-marketplace", "medium",
        "Instalación de aplicaciones de Marketplace",
        "Es el ajuste que decide de verdad la postura: mientras esté en «permitir todas», "
        "cualquiera puede dar a una aplicación de terceros acceso a los datos de la "
        "organización, y la lista de permitidas no tiene ningún efecto. Google lo deja en "
        "«permitir todas» por defecto salvo en cuentas educativas K-12.",
        "Consola de Administración > Aplicaciones > Aplicaciones de Google Workspace "
        "Marketplace > Configuración: elige «Permitir solo las aplicaciones de la lista».",
        "CIS GWS §2 — Controlar la instalación de aplicaciones de Marketplace",
        "https://admin.google.com/ac/appslist/marketplace", _unsafe_marketplace,
        _marketplace_observed
    ),
    Check(
        "security.session_controls", "policy-session", "low",
        "Duración de la sesión de Google",
        "Una cookie de sesión robada sigue valiendo hasta que la sesión caduca. Un límite "
        "acota cuánto tiempo sirve un token robado, sobre todo en cuentas privilegiadas.",
        "Consola de Administración > Seguridad > Control de acceso y datos > Control de "
        "sesión de Google: fija una duración máxima (12-24 h en unidades privilegiadas).",
        "CIS GWS §1 — Limitar la duración de las sesiones",
        "https://admin.google.com/ac/security/session", _unsafe_session,
        _session_observed
    ),
    Check(
        "calendar.secondary_calendar_max_allowed_external_sharing",
        "policy-calendar-secondary", "medium",
        "Calendarios secundarios visibles desde fuera",
        "Los calendarios secundarios —el de la sala de reuniones, el del equipo, el de "
        "guardias— salen por defecto con TODOS los detalles visibles desde fuera de la "
        "organización, no solo el libre/ocupado. Y son justo los que nadie revisa, porque "
        "nadie los siente suyos.\n\nEl título de una reunión suele ser el secreto entero: "
        "«Due diligence Acme», «Rescisión de Juan», «Consejo extraordinario». Quien pueda "
        "leerlos desde fuera sabe qué va a hacer la empresa antes de que lo sepa la "
        "plantilla, y no hace falta entrar en ningún sitio para verlo.",
        "Consola de Administración > Aplicaciones > Google Workspace > Calendar > "
        "Opciones de uso compartido: para los calendarios secundarios, deja «Solo "
        "información de libre/ocupado» como máximo permitido hacia fuera.",
        "CIS GWS §5 (Calendar) — Limitar la compartición externa a libre/ocupado",
        "https://admin.google.com/ac/apps/calendar/sharing",
        _unsafe_calendar, _calendar_observed,
    ),
    Check(
        "calendar.primary_calendar_max_allowed_external_sharing",
        "policy-calendar-primary", "medium",
        "Calendarios personales visibles desde fuera",
        "Lo que un tercero puede ver del calendario de cada persona. Con libre/ocupado "
        "basta para coordinar una reunión; con los detalles se filtra con quién se reúne "
        "cada uno, cuándo y sobre qué.",
        "Consola de Administración > Aplicaciones > Google Workspace > Calendar > "
        "Opciones de uso compartido: limita el máximo externo a «Solo libre/ocupado».",
        "CIS GWS §5 (Calendar) — Limitar la compartición externa a libre/ocupado",
        "https://admin.google.com/ac/apps/calendar/sharing",
        _unsafe_calendar, _calendar_observed,
    ),
    Check(
        "groups_for_business.groups_sharing", "policy-groups-sharing", "medium",
        "Acceso externo a los Grupos de Google",
        "Un grupo accesible desde fuera expone su archivo de mensajes, que suele contener "
        "años de conversación interna que nadie ha revisado nunca.",
        "Consola de Administración > Aplicaciones > Google Workspace > Grupos para "
        "empresas > Configuración de uso compartido: pon el acceso desde fuera en Privado.",
        "CIS GWS — Configuración de uso compartido de Grupos",
        "https://admin.google.com/ac/appsettings/553547912911", _unsafe_groups,
        _groups_observed
    ),
)

#: Finding ids this module owns, so the manual cards know what replaces them.
AUTOMATED_FINDING_IDS = frozenset(c.finding_id for c in CHECKS)


# ------------------------------------------------------------- rendering

def _scope_story(result, check=None) -> tuple[str, list[str]]:
    """The sentence that makes this worth paying for: not "it is on", but who
    is covered and who is not — plus, per unit, WHAT the setting actually says.

    The provenance used to be the whole line ("/: política propia"), which
    tells a reader nothing they can act on. It is still there, because a value
    the customer never set reads differently from one they chose, but it comes
    second now.
    """
    origins = {
        "explicit": "política propia",
        "default": "valor por defecto de Google",
        "unresolved": "sin determinar",
    }
    lines = []
    for ou in sorted(result.by_ou):
        efectivo = result.by_ou[ou]
        origen = origins[efectivo.source]
        valor = ""
        if check is not None and check.observed and efectivo.resolved:
            valor = check.observed(efectivo)
        lines.append(f"{ou}: {valor} · {origen}" if valor else f"{ou}: {origen}")

    exposed = len(result.exposed) + len(result.warned)
    total = result.total_accounts
    if result.partial:
        safe = ", ".join(result.safe_org_units) or "otras unidades"
        story = (
            f"Aplicado solo en {safe}. {exposed} de {total} cuentas quedan fuera y siguen "
            "expuestas."
        )
    elif exposed:
        story = f"Afecta a las {exposed} cuentas activas: no hay ninguna unidad protegida."
    elif result.unresolved:
        story = f"{len(result.unresolved)} de {total} cuentas no se han podido determinar."
    else:
        story = f"Cubre las {total} cuentas activas."
    return story, lines


def _finding(check: Check, result, users_total: int, listing_complete: bool = True) -> Finding:
    from_default = any(e.from_default for e in result.by_ou.values())

    if result.exposed:
        status = "fail"
    elif result.warned:
        status = "warn"
    elif users_total and len(result.unresolved) == users_total:
        status = "undetermined"
    else:
        status = "pass"

    story, lines = _scope_story(result, check)
    description = check.why + "\n\n" + story

    if status == "undetermined" and not listing_complete:
        description += (
            "\n\nEl listado de políticas de la Consola de Administración no se ha podido "
            "leer completo, así que no se puede distinguir «este ajuste no está configurado» "
            "de «este ajuste está en una página que no llegamos a pedir». La diferencia "
            "importa: una política que no se lee se evaluaría como el valor por defecto de "
            "Google, y eso es una afirmación sobre tu configuración que no se sostiene."
        )
    elif status == "undetermined" and check.no_default:
        description += (
            "\n\nNo es un fallo de permisos ni de identificador: Vigía tiene el permiso de "
            "lectura de políticas y usa el identificador que documenta Google. Lo que ocurre "
            "es que tu organización no ha fijado una política explícita para este ajuste y "
            "Google no publica su valor por defecto ni lo devuelve por API, así que no hay "
            "nada que leer. Afirmar que está permitido o bloqueado sería inventárselo. Queda "
            "como comprobación manual, con la ruta exacta en la tarjeta correspondiente."
        )

    observed_value = ""
    if check.observed:
        medido = next((e for e in result.by_ou.values() if e.resolved), None)
        if medido is not None:
            frase = check.observed(medido)
            if frase:
                origen = (
                    "valor por defecto de Google, que nadie ha cambiado"
                    if medido.from_default
                    else "configurado en la Consola de Administración"
                )
                observed_value = f"{frase} ({origen})"

    if from_default and (result.exposed or result.warned):
        description += (
            "\n\nNo hay ninguna política configurada para este ajuste, así que la "
            "organización está en el valor por defecto de Google, que es el permisivo. "
            "No tocarlo no lo deja en un punto neutro."
        )
    if result.group_policies:
        description += (
            "\n\nHay políticas aplicadas por grupo ("
            + ", ".join(result.group_policies)
            + "). Vigía no lee la pertenencia a grupos, así que no puede confirmar el "
            "valor efectivo de quien esté en ellos: esas cuentas se cuentan como no "
            "determinadas, nunca como correctas."
        )
    elif result.unresolved and result.exposed:
        description += f"\n\n{con_numero(len(result.unresolved), "cuenta")} sin determinar."

    return Finding(
        id=check.finding_id,
        title=check.title,
        severity=check.severity,
        status=status,
        description=description,
        # The setting and where it is set — never the payroll. Listing the
        # whole company under "SMS is allowed as a second factor" made every
        # employee look personally at fault for one console toggle, and it
        # buried the handful of people who really do have a problem.
        # Undetermined shows nothing: if it could not be read there is
        # nobody and nothing to report.
        affected_items=[] if status == "undetermined" else cap_items(lines),
        remediation=check.remediation,
        admin_console_url=check.console_url,
        cis_control=check.cis,
        scope_label="ajustes de la Consola de Administración",
        scope_type=ORG_SCOPE,
        observed_value=observed_value,
        accounts=[],
        remediation_actions=_ACTIONS.get(check.finding_id, []),
        i18n_params={"exposed": len(result.exposed), "total": result.total_accounts},
        details={
            "setting": check.setting,
            "exposed": len(result.exposed),
            "warned": len(result.warned),
            "unresolved": len(result.unresolved),
            "total_accounts": result.total_accounts,
            "partial_coverage": result.partial,
            "from_default": from_default,
            "org_units": {ou: e.source for ou, e in result.by_ou.items()},
            "group_policies": list(result.group_policies),
        },
    )


def _setup_finding(problem: PolicyUnavailable) -> Finding:
    """One card explaining why the settings checks are off, with the action
    that unblocks them. A delegated admin is told so plainly instead of being
    handed a wall of "not verified"."""
    if problem.reason == "not_super_admin":
        title = "Estas comprobaciones necesitan una cuenta de superadministrador"
        description = (
            "Los ajustes de la Consola de Administración solo puede leerlos un "
            "superadministrador. Estás conectado como administrador delegado, así que "
            "Google rechaza la consulta.\n\nNo es un fallo de tu configuración ni de "
            "Vigía: es el permiso que exige la API. El resto del informe —cuentas, 2FA, "
            "aplicaciones de terceros, registros de auditoría y DNS— sí está completo."
        )
    elif problem.reason == "rate_limited":
        title = "Google ha limitado el ritmo de consultas a la API de políticas"
        description = (
            "Google ha devuelto «cuota agotada» al leer los ajustes de la Consola de "
            "Administración. Es un límite de ritmo temporal, no un problema de tu "
            "configuración ni de tus permisos.\n\nNo se afirma nada sobre esos ajustes "
            "mientras no se puedan leer: el resto del informe está completo."
        )
    elif problem.reason == "scope_missing":
        title = "Reconecta para activar las comprobaciones automáticas de la consola"
        description = (
            "La conexión se autorizó antes de que Vigía pidiera el permiso de lectura de "
            "políticas, y los permisos no se añaden a un acceso ya concedido.\n\nPulsa "
            "«Desconectar» y vuelve a conectar: verás un permiso más en la pantalla de "
            "Google y se activarán 13 comprobaciones de la Consola de Administración que "
            "ahora tienes como manuales."
        )
    else:
        title = "La lectura automática de los ajustes de la consola no está activa"
        description = (
            "Vigía puede comprobar automáticamente la obligatoriedad y los métodos de 2FA, "
            "el uso compartido de Drive, el reenvío de Gmail, IMAP y POP, la política de "
            "contraseñas, la duración de sesión, el Marketplace y el acceso a Grupos con el "
            "permiso de solo lectura de políticas de Cloud Identity (sensible, no "
            f"restringido, sin CASA). Ahora mismo no puede: {problem.hint}"
        )
    return Finding(
        id="policy-automation",
        title=title,
        severity="info",
        status="undetermined",
        description=description,
        remediation=problem.hint,
        i18n_params={"hint": problem.hint},
        i18n_variant=problem.reason,
        admin_console_url=(
            problem.url
            or "https://console.cloud.google.com/apis/library/cloudidentity.googleapis.com"
        ),
        details={
            "reason": problem.reason,
            "needs_reconnect": problem.reason == "scope_missing",
            "activation_url": problem.url,
        },
    )


def run(ctx) -> list[Finding]:
    try:
        raw = ctx.policies()
    except PolicyUnavailable as problem:
        # Nothing breaks: the manual cards stay visible and this one says
        # exactly what to do about it.
        return [_setup_finding(problem)]

    users = [u for u in ctx.users() if is_active(u)]
    if not users:
        return []

    policies = pe.parse(raw)
    # A truncated listing must not let an absence become a default: see
    # `policy_engine.reduce_for`. Threaded rather than looked up inside the
    # engine so the engine stays a pure function of what it was handed.
    completo = ctx.complete("policies")
    return [
        _finding(
            check,
            pe.coverage(policies, check.setting, users, check.unsafe, completo),
            len(users),
            listing_complete=completo,
        )
        for check in CHECKS
    ]
