"""Templates, and a renderer that refuses to produce a half-filled email.

The rule that shapes this module: **a template that cannot be filled completely
does not render.** It raises, the send is blocked with a reason, and a person sees
it in the blocked view. There is no partial output and no empty-string fallback,
because the failure mode of a fallback is `Hola {company_name},` arriving in a
stranger's inbox — which does not just lose that prospect, it tells them exactly
how the message was made.

Templates live in the database and are versioned, so the wording that went out
last March can still be read next March. `catalog.py` holds the *findings*;
this holds the letters built around them.

A/B variants exist so reply rates can be compared per finding type. The variant is
chosen deterministically from the domain, not at random: the same prospect always
gets the same letter, so a re-render during review shows what will actually be
sent, and the split stays balanced without storing an assignment.
"""
from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass
from typing import Any

from .catalog import RULES
from .db import now, transaction

#: Every placeholder a template may use. A template referring to anything else is
#: rejected when it is stored, not when it is sent to somebody.
PLACEHOLDERS: frozenset[str] = frozenset(
    {
        "domain",
        "company_name",
        "finding_plain",
        "finding_technical",
        "sender_name",
        "sender_details",
        "unsubscribe_url",
    }
)

_PLACEHOLDER_RE = re.compile(r"\{([a-z_]+)\}")

#: Countries whose prospects are written to in English. Everything else gets
#: Spanish, which is the operator's own language and the safer default: a Spanish
#: letter to an English reader is odd, an English letter to a Spanish SME is a
#: reason not to reply.
ENGLISH_COUNTRIES: frozenset[str] = frozenset({"GB", "UK", "IE", "US", "CA", "AU", "NZ"})


class RenderError(RuntimeError):
    """A template could not be filled completely. Never send the result."""


@dataclass(frozen=True)
class RenderedEmail:
    subject: str
    body: str
    template_id: int
    variant: str
    lang: str


def lang_for_country(country: str | None) -> str:
    return "en" if (country or "").strip().upper() in ENGLISH_COUNTRIES else "es"


def placeholders_in(text: str) -> set[str]:
    return set(_PLACEHOLDER_RE.findall(text or ""))


def validate_template(subject: str, body: str) -> None:
    """Reject a template that names a placeholder nobody can fill.

    Checked when the template is stored. Finding this at send time would mean
    finding it once per recipient, in a queue somebody is approving in batches.
    """
    desconocidos = (placeholders_in(subject) | placeholders_in(body)) - PLACEHOLDERS
    if desconocidos:
        raise RenderError(
            f"la plantilla usa marcadores que no existen: {sorted(desconocidos)}. "
            f"Disponibles: {sorted(PLACEHOLDERS)}"
        )
    if "{unsubscribe_url}" not in body:
        raise RenderError("toda plantilla debe llevar {unsubscribe_url}: es obligatorio")
    if "{sender_details}" not in body:
        raise RenderError(
            "toda plantilla debe llevar {sender_details}: la identificación del "
            "remitente es obligatoria en todo correo comercial (LSSI art. 10)"
        )


def render(text: str, values: dict[str, Any]) -> str:
    """Fill a template, or raise. Never returns a partially filled string.

    Three ways to fail, all of them loud: a placeholder with no value, a
    placeholder whose value is empty or whitespace, and a brace left standing
    after substitution.
    """
    necesarios = placeholders_in(text)
    faltan = sorted(n for n in necesarios if not str(values.get(n, "")).strip())
    if faltan:
        raise RenderError(f"marcadores sin rellenar: {faltan}")

    salida = text
    for nombre in necesarios:
        salida = salida.replace("{" + nombre + "}", str(values[nombre]))

    # A stray `{` means either a placeholder we do not know about or a literal
    # brace somebody typed. Both are reasons not to send this.
    if _PLACEHOLDER_RE.search(salida):
        raise RenderError(f"quedan marcadores sin sustituir: {sorted(placeholders_in(salida))}")
    return salida


# --------------------------------------------------------------------------- #
# The default letters. Two variants per finding per language.
#
# Variant A is direct: what is wrong, in one line, then the offer. Variant B leads
# with the consequence before naming the problem. They exist to be measured
# against each other, so they differ in structure, not in wording of the same
# structure — comparing two paraphrases would measure nothing.
#
# Both are short on purpose. This is an unsolicited message from a stranger; the
# reader decides in the first two lines, and every extra paragraph is a reason to
# close it.
# --------------------------------------------------------------------------- #

_ES_A = """Hola,

{finding_plain}

Lo he visto revisando la configuración pública de correo de {domain} — es
información que cualquiera puede consultar en el DNS, no he accedido a nada
vuestro.

En detalle: {finding_technical}

Si os interesa, os paso el informe completo (SPF, DKIM, DMARC y MTA-STS de
{domain}) sin coste ni compromiso. Y si preferís arreglarlo por vuestra cuenta,
os digo igualmente qué hay que tocar.

Un saludo,
{sender_name}

--
{sender_details}
Si no quieres recibir más correos míos: {unsubscribe_url}
"""

_ES_B = """Hola,

Una nota rápida sobre el correo de {domain}, por si os resulta útil.

{finding_plain}

Es algo que se ve desde fuera, en el DNS público: no he accedido a ningún sistema
vuestro. Técnicamente: {finding_technical}

Reviso este tipo de configuración para empresas pequeñas. Si queréis, os mando el
informe completo de {domain} sin coste, y decidís vosotros qué hacer con él.

Un saludo,
{sender_name}

--
{sender_details}
Para no recibir más correos: {unsubscribe_url}
"""

_EN_A = """Hello,

{finding_plain}

I noticed it while reviewing the public mail configuration of {domain} — this is
information anyone can look up in DNS. I have not accessed anything of yours.

In detail: {finding_technical}

If it is useful, I can send you the full report (SPF, DKIM, DMARC and MTA-STS for
{domain}) at no cost and with no obligation. If you would rather fix it
yourselves, I will tell you what to change anyway.

Best regards,
{sender_name}

--
{sender_details}
If you would rather not hear from me again: {unsubscribe_url}
"""

_EN_B = """Hello,

A quick note about email at {domain}, in case it is useful.

{finding_plain}

This is visible from outside, in public DNS — I have not accessed any system of
yours. Technically: {finding_technical}

I review this kind of configuration for small companies. If you would like, I can
send you the full report for {domain} at no cost, and you decide what to do with
it.

Best regards,
{sender_name}

--
{sender_details}
To stop receiving these: {unsubscribe_url}
"""

BODIES: dict[tuple[str, str], str] = {
    ("es", "A"): _ES_A,
    ("es", "B"): _ES_B,
    ("en", "A"): _EN_A,
    ("en", "B"): _EN_B,
}

#: The subject is the finding's own subject line, from `catalog.py`. It is not
#: duplicated per template: the hook is a property of the finding, and having two
#: places to change it is how they end up disagreeing.
SUBJECTS: dict[str, str] = {
    "es": "{finding_subject}",
    "en": "{finding_subject}",
}


def seed_templates(conn: sqlite3.Connection) -> int:
    """Install the default letters. Idempotent; never touches an edited row.

    `INSERT OR IGNORE` on (finding_code, lang, variant, version): a letter you have
    edited in the database keeps its wording, and a new default only lands as a new
    version. Overwriting an operator's edit on restart would be its own kind of
    silent send.
    """
    filas = []
    for rule in RULES:
        for lang in ("es", "en"):
            for variant in ("A", "B"):
                cuerpo = BODIES[(lang, variant)]
                validate_template("x", cuerpo)
                filas.append((rule.code, lang, variant, 1, "{finding_subject}", cuerpo, now()))
    with transaction(conn):
        conn.executemany(
            "INSERT OR IGNORE INTO templates "
            "(finding_code, lang, variant, version, subject, body, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            filas,
        )
    return len(filas)


def variant_for(domain: str, variants: tuple[str, ...] = ("A", "B")) -> str:
    """Which variant this domain gets. Stable, and balanced across a large list.

    Deterministic rather than random so that the preview a person approves is the
    letter that gets sent, and so that a re-queued prospect does not silently
    switch letter and spoil the comparison.
    """
    digest = hashlib.sha256(domain.lower().encode("utf-8")).digest()
    return variants[digest[0] % len(variants)]


def pick_template(
    conn: sqlite3.Connection, finding_code: str, lang: str, variant: str
) -> sqlite3.Row | None:
    """The active template for this finding, language and variant — latest version."""
    return conn.execute(
        "SELECT * FROM templates WHERE finding_code = ? AND lang = ? AND variant = ? "
        "AND is_active = 1 ORDER BY version DESC LIMIT 1",
        (finding_code, lang, variant),
    ).fetchone()


def build_email(
    conn: sqlite3.Connection,
    *,
    finding: Any,
    prospect: sqlite3.Row | dict[str, Any],
    sender_name: str,
    sender_details: str,
    unsubscribe_url: str,
    variant: str | None = None,
) -> RenderedEmail:
    """Render one email, or raise `RenderError`.

    Raising is the point. Every caller treats a `RenderError` as "block this one
    and show the reason", so an unfillable letter costs one prospect and never
    reaches anybody.
    """
    domain = prospect["domain"]
    lang = finding.lang or lang_for_country(prospect["country"])
    variant = variant or variant_for(domain)

    fila = pick_template(conn, finding.code, lang, variant)
    if fila is None:
        raise RenderError(
            f"no hay plantilla activa para {finding.code}/{lang}/{variant}"
        )

    valores = {
        "domain": domain,
        # No fallback to the domain: if the company's name is not known, the
        # letter that would go out says "Hola," and nothing else — which is fine —
        # but a template that greets by name must not quietly get a hostname
        # instead. Templates that use it and lack it are blocked, deliberately.
        "company_name": prospect["company_name"] or "",
        "finding_plain": finding.plain_language_description,
        "finding_technical": finding.technical_description,
        "sender_name": sender_name,
        "sender_details": sender_details,
        "unsubscribe_url": unsubscribe_url,
    }

    asunto = fila["subject"].replace("{finding_subject}", finding.subject_line)
    return RenderedEmail(
        subject=render(asunto, valores),
        body=render(fila["body"], valores),
        template_id=int(fila["id"]),
        variant=variant,
        lang=lang,
    )
