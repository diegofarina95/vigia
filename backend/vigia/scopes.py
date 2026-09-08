"""Every OAuth scope Vigía requests, defined exactly once.

There were three hand-written lists — the authorization request, the privacy
policy's table, and the homepage's no-JavaScript block — plus a fourth outside the
repository, the scope list in Google Cloud Console. Three of them happened to
agree about the four Workspace scopes; the homepage said "cuatro permisos" while
the privacy page listed six, because `openid` and `email` are requested too and
only one surface admitted it. Nothing detected the disagreement, and a human
reviewer at Google compares precisely these lists against each other.

So: the tuple below is the source of truth. `auth/oauth.py` builds the
authorization request from it, `legal.py` renders the privacy table from it, and
Flask substitutes the homepage's list from it when it serves index.html. Adding a
scope means adding it here, and `tests/test_scopes_single_source.py` fails if a
scope identifier is written by hand anywhere else.

The `checks` field is not decoration. It records which checks stop working when a
scope is missing, and it was derived by reading which `ctx` attribute each check
actually consumes — `ctx.users`, `ctx.policies`, `ctx.admin_events` and so on —
rather than from what any comment claimed. It is what a justification to Google
has to be able to point at.
"""
from __future__ import annotations

from dataclasses import dataclass

Lang = str  # "es" | "en"


@dataclass(frozen=True)
class Scope:
    """One scope: what Google calls it, what it reads, and what depends on it."""

    #: The full identifier, exactly as it goes into the authorization request and
    #: exactly as it must appear in Google Cloud Console.
    id: str
    #: Human name, per language.
    nombre: dict[Lang, str]
    #: What data it reads. This is the sentence that goes on the privacy policy and
    #: on the homepage, so it has to be true of the API calls actually made.
    lee: dict[Lang, str]
    #: Checks that consume the data this scope yields, by their `check_*.py` name.
    checks: tuple[str, ...]
    #: "workspace" scopes read the customer's tenant; "identidad" only identifies
    #: the administrator who authorised the connection.
    familia: str

    @property
    def corto(self) -> str:
        """The last path segment, which is how the consent screen abbreviates it."""
        return self.id.rsplit("/", 1)[-1]


_BASE = "https://www.googleapis.com/auth/"


#: In the order they are sent. Identity first, matching `ALL_SCOPES`.
SCOPES: tuple[Scope, ...] = (
    Scope(
        id="openid",
        nombre={"es": "Identificador de la sesión", "en": "Session identifier"},
        lee={
            "es": "Obtener el identificador de la sesión de Google que autoriza la conexión.",
            "en": "The identifier of the Google session that authorises the connection.",
        },
        checks=(),
        familia="identidad",
    ),
    Scope(
        id="email",
        nombre={"es": "Dirección del administrador", "en": "Administrator address"},
        lee={
            "es": "Saber con qué dirección de administrador se ha conectado, para mostrarla en "
            "la interfaz y asociar la autorización a tu organización.",
            "en": "Which administrator address connected, so it can be shown in the interface "
            "and the authorisation tied to your organisation.",
        },
        checks=(),
        familia="identidad",
    ),
    Scope(
        id=f"{_BASE}admin.directory.user.readonly",
        nombre={"es": "Lectura de cuentas", "en": "Read accounts"},
        lee={
            "es": "Listar las cuentas y sus indicadores de seguridad: inscripción en la "
            "verificación en dos pasos, rol de administrador, último inicio de sesión, estado "
            "de suspensión, fecha de creación, datos de recuperación y unidad organizativa.",
            "en": "List the accounts and their security metadata: 2-Step Verification "
            "enrolment, administrator role, last sign-in, suspension state, creation date, "
            "recovery details and organizational unit.",
        },
        checks=(
            "2sv",
            "dormant",
            "stale",
            "super_admins",
            "recovery",
            "backup_codes",
            "admin_logins",
            "suspended_tokens",
            "policies",
        ),
        familia="workspace",
    ),
    Scope(
        id=f"{_BASE}admin.directory.domain.readonly",
        nombre={"es": "Lectura de dominios", "en": "Read domains"},
        lee={
            "es": "Listar tus dominios verificados, para comprobar SPF, DKIM, DMARC y MTA-STS "
            "en cada uno a través del DNS público.",
            "en": "List your verified domains, so SPF, DKIM, DMARC and MTA-STS can be checked "
            "for each one through public DNS.",
        },
        checks=("email_auth", "mail_transport"),
        familia="workspace",
    ),
    Scope(
        id=f"{_BASE}admin.reports.audit.readonly",
        nombre={"es": "Lectura del registro de auditoría", "en": "Read the audit log"},
        lee={
            "es": "Leer el registro de auditoría: qué aplicaciones de terceros se han "
            "autorizado, los cambios recientes de administración y los eventos de inicio de "
            "sesión.",
            "en": "Read the audit log: which third-party applications have been authorised, "
            "recent administrative changes, and sign-in events.",
        },
        checks=(
            "oauth_apps",
            "audit_log",
            "admin_logins",
            "login_security",
            "suspended_tokens",
            "backup_codes",
        ),
        familia="workspace",
    ),
    Scope(
        id=f"{_BASE}cloud-identity.policies.readonly",
        nombre={"es": "Lectura de ajustes de la consola", "en": "Read console settings"},
        lee={
            "es": "Leer los ajustes que has configurado en la Consola de Administración (uso "
            "compartido de Drive, reenvío de Gmail, política de contraseñas, duración de "
            "sesión, Marketplace y Grupos) para comprobarlos automáticamente en lugar de "
            "pedirte que los mires a mano.",
            "en": "Read the settings configured in your Admin console (Drive sharing, Gmail "
            "forwarding, password policy, session length, Marketplace and Groups) so they are "
            "checked automatically instead of by hand.",
        },
        checks=("policies", "alert_rules"),
        familia="workspace",
    ),
)


ALL_IDS: tuple[str, ...] = tuple(s.id for s in SCOPES)
WORKSPACE_IDS: tuple[str, ...] = tuple(s.id for s in SCOPES if s.familia == "workspace")
IDENTITY_IDS: tuple[str, ...] = tuple(s.id for s in SCOPES if s.familia == "identidad")

#: Every identifier a surface is allowed to print, including the abbreviated form
#: the consent screen uses. The invariant test scans for these.
IDENTIFICADORES: frozenset[str] = frozenset(
    {s.id for s in SCOPES} | {s.corto for s in SCOPES}
)

_CUENTA = {
    "es": {2: "Dos", 3: "Tres", 4: "Cuatro", 5: "Cinco", 6: "Seis", 7: "Siete"},
    "en": {2: "Two", 3: "Three", 4: "Four", 5: "Five", 6: "Six", 7: "Seven"},
}


def cuantos(lang: Lang = "es") -> str:
    """"Seis" / "Six" — so no surface can hardcode a count that drifts.

    The homepage said "Cuatro permisos de Google" while requesting six.
    """
    return _CUENTA[lang].get(len(SCOPES), str(len(SCOPES)))


def _escapar(texto: str) -> str:
    return texto.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def filas_tabla(lang: Lang = "es") -> str:
    """The privacy policy's table body: one `<tr>` per scope, in request order."""
    filas = []
    for s in SCOPES:
        filas.append(
            f"  <tr><td><code>{_escapar(s.corto)}</code></td>\n"
            f"      <td>{_escapar(s.lee[lang])}</td></tr>"
        )
    return "\n".join(filas)


def lista_items(lang: Lang = "es") -> str:
    """The homepage's list: `<li><code>scope</code> — what it reads.</li>`.

    Only the Workspace scopes carry a `<code>` identifier here; `openid` and `email`
    are named in the sentence that introduces the list, because printing them as
    API identifiers next to the others implies they read tenant data.
    """
    items = []
    for s in SCOPES:
        if s.familia != "workspace":
            continue
        items.append(
            f"          <li>\n"
            f"            <code>{_escapar(s.corto)}</code> — {_escapar(s.lee[lang])}\n"
            f"          </li>"
        )
    return "\n".join(items)


def resumen_permisos(lang: Lang = "es") -> str:
    """The sentence that introduces the list, counting what is actually requested."""
    ws = _CUENTA[lang][len(WORKSPACE_IDS)].lower()
    identidad = " y ".join(f"<code>{s.corto}</code>" for s in SCOPES if s.familia == "identidad")
    if lang == "en":
        identidad = identidad.replace(" y ", " and ")
        return (
            f"{cuantos('en')} Google permissions in total: {ws} that read your organisation, "
            f"<strong>all read-only and none restricted</strong>, plus {identidad}, which only "
            f"identify the administrator who connects."
        )
    return (
        f"{cuantos('es')} permisos de Google en total: {ws} que leen tu organización, "
        f"<strong>todos de solo lectura y ninguno restringido</strong>, más {identidad}, que "
        f"solo identifican al administrador que conecta."
    )
