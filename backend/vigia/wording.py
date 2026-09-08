"""Sentences that must read the same everywhere, defined once.

The read-only claim existed in four different wordings: the report footer, two
places in the privacy pages, and the React landing. All four were true and all
four said it differently, which is what makes a product look assembled by
somebody who was not paying attention — and this one is the sentence that decides
whether an administrator hands over super-admin access at all.

The report's version won because it is the only one that says **why** Vigía
cannot read anything: Google's API refuses, rather than Vigía promising not to.
A technical reader can verify the first claim and can only take the second on
trust, and the difference between those two is the whole argument.

`tests/test_readonly_wording.py` fails if any surface drifts from these strings,
including the React one — a constant that four files are supposed to agree with
is not a source of truth unless something checks.

Bilingual, since the claim is also the sentence an English reader decides on. The
two languages live in the locale catalogue, under `email.solo_lectura`, and are
read with `read_only_claim(lang)`.

The constants below stay as Spanish literals on purpose, for two reasons:

 · `report.py` and `legal.py` interpolate them into f-strings today, and turning
   a constant into a function call is not something to do to another module by
   surprise. They keep working, in Spanish, until they take a language.
 · `i18n` imports this module, so importing `i18n.text` at the top of this one
   would close a circle. The functions below import it at call time instead,
   which cannot deadlock at import and cannot be reached before the catalogue
   is loadable.

The literals are therefore a second copy of the Spanish, and
`test_readonly_wording.py` asserts they equal the catalogue's — the same
arrangement, and the same reason, as the sentence pinned inside `Landing.tsx`.
"""
from __future__ import annotations

DEFAULT_LANG = "es"

#: The canonical claim. Two sentences: what is not requested, and who enforces it.
READ_ONLY_CLAIM = (
    "Vigía nunca ha solicitado permisos de Gmail, Drive ni ningún otro permiso "
    "restringido, así que no puede leer el contenido de mensajes ni de archivos: lo "
    "impide la propia API de Google, no solo nuestra política."
)

#: The lead-in used where the claim is a heading of its own.
READ_ONLY_LEAD = "Solo lectura por diseño."

#: Only true next to a scan that actually ran, so it is separate: the privacy page
#: and the landing describe the tool, not a particular scan.
SCAN_DID_NOT_MODIFY = "Este escaneo no ha modificado ningún ajuste de Workspace."


def _texto(lang: str, clave: str) -> str:
    """The catalogue, imported late to keep `i18n` → `wording` a one-way street."""
    from .i18n import text

    return text(lang or DEFAULT_LANG, f"email.solo_lectura.{clave}")


def read_only_claim(lang: str = DEFAULT_LANG) -> str:
    return _texto(lang, "claim")


def read_only_lead(lang: str = DEFAULT_LANG) -> str:
    return _texto(lang, "lead")


def scan_did_not_modify(lang: str = DEFAULT_LANG) -> str:
    return _texto(lang, "escaneo_sin_cambios")


def read_only_paragraph(lang: str = DEFAULT_LANG, *, include_scan_note: bool = False) -> str:
    """The claim as one paragraph of plain text."""
    partes = [f"{read_only_lead(lang)} {read_only_claim(lang)}"]
    if include_scan_note:
        partes.append(scan_did_not_modify(lang))
    return " ".join(partes)


# --------------------------------------------------- back to the website

#: Where a reader of the report goes to find out who wrote it. The report is a PDF
#: that gets forwarded from the technician to the manager, so this link is what
#: turns a forward into a visit — and it carries the language, because somebody
#: who was sent a Spanish report should not land on an English page.
SITE_URL = "https://diegofarina.com"


def site_link(lang: str = "es") -> str:
    codigo = "es" if (lang or "es").startswith("es") else "en"
    return f"{SITE_URL}/?lang={codigo}"


# ────────────────────────────────────────────────────────────── plurales


def plural(n: int, singular: str, muchos: str | None = None) -> str:
    """The noun, agreed with `n`. Defaults to Spanish's regular `+s`.

    Vigía printed "1 cambio(s)" in 56 places — the report, the CSV, the dashboard
    and the subject lines of the e-mails a customer keeps. "(s)" is the shape of a
    program that could not be bothered, in a product whose whole argument is that
    somebody was paying attention.

    Pass `muchos` when the plural is not just `+s`, or when more than one word has
    to agree: `plural(n, "cuenta suspendida", "cuentas suspendidas")`.

    SPANISH ONLY. `+s` is a rule about Spanish, and the default silently produces
    "2 childs" for anything irregular in English. A bilingual sentence counts with
    `contar()` instead, which reads explicit singular and plural forms out of the
    catalogue and so cannot invent a plural for either language.
    """
    if n == 1:
        return singular
    return muchos if muchos is not None else f"{singular}s"


def con_numero(n: int, singular: str, muchos: str | None = None) -> str:
    """"1 cambio" / "2 cambios" — the number and its noun, agreed.

    The form to reach for by default in Spanish: the count and the word are one
    decision, and splitting them is how they drift apart. For text that has to
    exist in English too, use `contar()`.
    """
    return f"{n} {plural(n, singular, muchos)}"


def contar(lang: str, n: int, ruta: str) -> str:
    """"1 punto" / "2 puntos" / "1 point" / "2 points" — from the catalogue.

    `ruta` names a PAIR of entries, `<ruta>_uno` and `<ruta>_varios`, each with
    `{n}` in it. Storing both forms per language is the only way English gets its
    own agreement without this module growing a second set of grammar rules — and
    it lets a language put the number somewhere else in the phrase, which `+s`
    cannot.
    """
    from .i18n import text

    return text(lang or DEFAULT_LANG, f"{ruta}_uno" if n == 1 else f"{ruta}_varios", n=n)
