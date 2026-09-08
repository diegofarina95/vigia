"""Role address or personal address — the question the GDPR turns on.

Writing to `info@empresa.com` is a message to a company. Writing to
`maria.gonzalez@empresa.com` is processing a named person's personal data, and the
legitimate-interest balancing test that covers the first does not obviously cover
the second. So this module's job is not to guess well on average; it is to be
**unable to let a personal address through**.

That is why classification is an allowlist. A local part is `role` only if it is
recognised as one. Everything else is refused — either as `personal`, when it
matches a human-name shape, or as `unknown`, when it simply is not recognised.
Both are blocked. The distinction exists so Phase 3 can let a human take
responsibility for an `unknown` (a company whose contact address is its own
brand name, say) while never offering that choice for a `personal`.

The failure this design accepts is refusing a legitimate role address that is not
on the list. That costs one prospect. The failure it refuses to accept is emailing
a named individual who never asked to hear from us, which costs a complaint to the
AEPD and is the kind of thing that ends the whole exercise.

Spanish naming shapes are first-class here, not an afterthought: `nombre.apellido@`,
`nombre.apellido1.apellido2@` (two surnames, which the English-shaped patterns miss),
`napellido@` and a bare `nombre@`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

AddressType = Literal["role", "personal", "unknown"]

#: Local parts that address a function rather than a person. Spanish and English,
#: because the prospect list is both.
ROLE_LOCALS: frozenset[str] = frozenset(
    {
        # generic
        "info", "informacion", "información", "contacto", "contact", "contacta",
        "hello", "hola", "hi", "mail", "email", "correo", "buzon", "buzón",
        "general", "office", "oficina", "team", "equipo", "empresa", "company",
        # commercial
        "sales", "ventas", "comercial", "shop", "tienda", "pedidos", "orders",
        "marketing", "prensa", "press", "partners", "negocio", "business",
        # support
        "support", "soporte", "ayuda", "help", "helpdesk", "atencion",
        "atencioncliente", "atencionalcliente", "clientes", "customers",
        "servicio", "service", "sac", "cau", "incidencias",
        # administrative
        "admin", "administracion", "administración", "administrator",
        "facturacion", "facturación", "billing", "invoices", "accounts",
        "contabilidad", "finanzas", "finance", "compras", "purchasing",
        "pagos", "payments", "cobros",
        # people & legal
        "rrhh", "hr", "jobs", "empleo", "trabajo", "careers", "seleccion",
        "legal", "juridico", "jurídico", "privacy", "privacidad", "dpo", "dpd",
        "proteecciondedatos", "proteccion", "compliance",
        # technical
        "it", "sistemas", "tecnico", "técnico", "tech", "developers", "dev",
        "reservas", "booking", "citas", "agenda", "recepcion", "recepción",
        "reception", "direccion", "dirección", "gerencia", "secretaria",
        "secretaría", "secretariat",
    }
)

#: Role addresses that exist for machines. Real role accounts, and contacting them
#: is still wrong: `postmaster` and `abuse` are reserved by RFC 2142 for reporting
#: problems with mail, and a marketing message to `abuse@` is precisely the thing
#: that address exists to report.
DO_NOT_CONTACT_LOCALS: frozenset[str] = frozenset(
    {
        "postmaster", "abuse", "noreply", "no-reply", "no_reply", "donotreply",
        "do-not-reply", "mailer-daemon", "bounce", "bounces", "webmaster",
        "hostmaster", "root", "daemon", "nobody", "spam", "phishing",
        "security", "seguridad", "soc", "cert", "unsubscribe", "baja",
    }
)

#: Given names common enough in Spain and the UK that a bare local part matching
#: one is a person, not a department. Short by design: it only has to cover the
#: `nombre@` shape, and everything not on it is refused as `unknown` anyway.
COMMON_GIVEN_NAMES: frozenset[str] = frozenset(
    {
        "antonio", "jose", "josé", "manuel", "francisco", "david", "juan",
        "javier", "daniel", "carlos", "miguel", "rafael", "pedro", "angel",
        "ángel", "alejandro", "fernando", "sergio", "pablo", "jorge", "alberto",
        "luis", "alvaro", "álvaro", "adrian", "adrián", "raul", "raúl", "enrique",
        "ramon", "ramón", "vicente", "diego", "andres", "andrés", "ivan", "iván",
        "ruben", "rubén", "oscar", "óscar", "joaquin", "joaquín", "santiago",
        "maria", "maría", "carmen", "ana", "isabel", "dolores", "pilar", "teresa",
        "rosa", "cristina", "marta", "julia", "lucia", "lucía", "laura", "elena",
        "sara", "paula", "raquel", "patricia", "beatriz", "silvia", "nuria",
        "eva", "susana", "monica", "mónica", "irene", "alba", "sofia", "sofía",
        "noelia", "rocio", "rocío", "sandra", "veronica", "verónica", "lourdes",
        "james", "john", "robert", "michael", "william", "richard", "thomas",
        "charles", "daniel", "matthew", "andrew", "peter", "simon", "gary",
        "mary", "patricia", "jennifer", "linda", "barbara", "susan", "jessica",
        "sarah", "karen", "emma", "olivia", "sophie", "hannah", "rachel",
        "claire", "louise", "helen", "katie", "lisa", "amy", "jane",
        "brais", "uxia", "uxía", "iago", "anxo", "xoan", "xoán", "lois",
    }
)

#: Particles that appear inside Spanish surnames and must not be read as separate
#: name tokens: `maria.de.la.fuente@` is one person, not four.
SURNAME_PARTICLES: frozenset[str] = frozenset(
    {"de", "del", "la", "las", "los", "van", "von", "da", "do", "dos", "di", "mc", "mac"}
)

_SEPARATORS = re.compile(r"[._\-]+")
_SYNTAX = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


@dataclass(frozen=True)
class AddressClassification:
    """What an address is, and whether we may write to it."""

    email: str
    address_type: AddressType
    #: True only for a role address we are allowed to contact. Everything else is
    #: False, and `reason` says which rule refused it.
    is_valid: bool
    reason: str
    #: The local part after normalisation, kept for the audit record.
    local: str
    domain: str

    @property
    def is_personal(self) -> bool:
        return self.address_type == "personal"


def _normalise(email: str) -> str:
    return (email or "").strip().strip("<>").lower()


def _strip_subaddress(local: str) -> str:
    """`info+web@` addresses `info@`. The tag is routing, not identity."""
    return local.split("+", 1)[0]


def _strip_trailing_digits(token: str) -> str:
    """`info2` addresses the same desk as `info`. `2024` keeps its digits."""
    stripped = token.rstrip("0123456789")
    return stripped or token


def _looks_like_person(tokens: list[str]) -> bool:
    """Two or more name-shaped tokens, once surname particles are set aside.

    `nombre.apellido`, `nombre.apellido1.apellido2`, `apellido.nombre`,
    `nombre_apellido`, `nombre-apellido`, and `j.smith` — a single letter counts as
    an initial, but only alongside a full name-shaped token, so `it.support` is not
    read as a person. A token of digits never counts, so `info.2024` is not one
    either.
    """
    meaningful = [t for t in tokens if t and t not in SURNAME_PARTICLES]
    if len(meaningful) < 2:
        return False
    if not all(t.isalpha() for t in meaningful):
        return False
    iniciales = [t for t in meaningful if len(t) == 1]
    nombres = [t for t in meaningful if len(t) >= 3]
    if iniciales:
        # `j.smith` is a person; `a.b` is not enough to say so.
        return bool(nombres) and len(iniciales) + len(nombres) == len(meaningful)
    return all(len(t) >= 2 for t in meaningful)


def _looks_like_initial_surname(local: str) -> bool:
    """`dfarina@`, `mgonzalez@` — one initial welded to a surname.

    Deliberately conservative: at least five letters in total, so `it`, `hr` and
    `sac` are not swept up, and the whole thing must be alphabetic.
    """
    if not local.isalpha() or len(local) < 5:
        return False
    return local not in ROLE_LOCALS and local not in DO_NOT_CONTACT_LOCALS


def classify_address(email: str) -> AddressClassification:
    """Classify one address. Never raises.

    The order of the checks is the order of certainty: syntax, then the two known
    lists, then the human-name shapes, then a catch-all refusal.
    """
    raw = _normalise(email)
    if not raw or not _SYNTAX.match(raw) or raw.count("@") != 1:
        return AddressClassification(
            email=raw, address_type="unknown", is_valid=False,
            reason="syntax", local="", domain="",
        )

    local_raw, domain = raw.split("@", 1)
    local = _strip_subaddress(local_raw)
    if ".." in local or local.startswith(".") or local.endswith("."):
        return AddressClassification(
            email=raw, address_type="unknown", is_valid=False,
            reason="syntax", local=local, domain=domain,
        )

    base = AddressClassification(
        email=raw, address_type="unknown", is_valid=False,
        reason="unrecognised", local=local, domain=domain,
    )

    tokens = _SEPARATORS.split(local)
    #: The same tokens with a numeric suffix removed, for matching against the
    #: lists only. `info2` is the `info` desk; the raw token is what gets stored.
    raiz = [_strip_trailing_digits(t) for t in tokens]
    base_local = _strip_trailing_digits(local)

    if base_local in DO_NOT_CONTACT_LOCALS or any(t in DO_NOT_CONTACT_LOCALS for t in raiz):
        # A real role address that exists to receive complaints and automated
        # traffic. Contacting it is both useless and, for `abuse@`, self-reporting.
        return AddressClassification(**{**base.__dict__, "address_type": "role",
                                        "reason": "role-do-not-contact"})

    if base_local in ROLE_LOCALS:
        return AddressClassification(**{**base.__dict__, "address_type": "role",
                                        "is_valid": True, "reason": "role"})

    tiene_palabra_de_funcion = any(t in ROLE_LOCALS for t in raiz)
    tiene_nombre_de_pila = any(t in COMMON_GIVEN_NAMES for t in raiz)

    # A role word with a qualifier — `ventas.madrid`, `contacto-es`, `info2` — is
    # still a role address. Unless one of the tokens is a person's given name:
    # `maria.ventas@` is a named individual with her department appended, and the
    # given name is the half that decides.
    if tiene_palabra_de_funcion and not tiene_nombre_de_pila:
        return AddressClassification(**{**base.__dict__, "address_type": "role",
                                        "is_valid": True, "reason": "role-compound"})

    if tiene_palabra_de_funcion and tiene_nombre_de_pila:
        return AddressClassification(**{**base.__dict__, "address_type": "personal",
                                        "reason": "personal-name-with-role-word"})

    if _looks_like_person(tokens):
        return AddressClassification(**{**base.__dict__, "address_type": "personal",
                                        "reason": "personal-name-pattern"})

    if local in COMMON_GIVEN_NAMES:
        return AddressClassification(**{**base.__dict__, "address_type": "personal",
                                        "reason": "personal-given-name"})

    if _looks_like_initial_surname(local):
        return AddressClassification(**{**base.__dict__, "address_type": "personal",
                                        "reason": "personal-initial-surname"})

    # Not recognised as either. Refused, but recorded as `unknown` rather than
    # `personal`, because Phase 3 may put an unknown in front of a human and must
    # never do that with a personal address.
    return base


def is_contactable(email: str) -> bool:
    """Shorthand for the one question the queue asks."""
    return classify_address(email).is_valid
