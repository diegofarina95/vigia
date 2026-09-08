"""The legal pages, rendered on the server.

These are the only pages in Vigía that are NOT part of the React app, and the
reason is Google: the OAuth brand verifier fetches the privacy-policy and
homepage URLs without executing JavaScript, and the SPA answers every route
with `<div id="root"></div>`. A policy a crawler cannot read is a policy that
does not exist for the purpose it was written for.

Serving them from Flask also removes a second problem — two sources of truth.
The in-app links are plain anchors, so the page a human reads and the page
Google reads are byte-for-byte the same document.

No external fonts, stylesheets or scripts: a privacy policy that phones a
third party while it is being read undercuts its own text.

Both languages, and the prose organised as `{"es": …, "en": …}` per string — the
same shape as `scopes.Scope.nombre` and `.lee`. Deliberately NOT `i18n.text()`:
that catalogue keys short sentences by finding id and interpolates measurements
into them, while these are long blocks of a legal document. What each page keeps
in its own skeleton is the STRUCTURE — the headings, the tables, the list
classes, the two icons — written once for both languages, so the English page
cannot quietly lose a padlock or gain the red ✕ that means "do not do this".

The English is BRITISH: organisation, authorise, recognise, licence, behaviour.
One exception, on purpose: anything Google names on its own screens keeps
Google's spelling — `organizational unit`, `enrollment period`, `license`,
«Advanced» — because these pages and the report send an administrator to menus
called exactly that, and "Organisational units" would break a navigation
instruction. Quoted UI labels also follow the app: `'…'` in English where the
Spanish uses «…», which is what `locales/en.json` already does.
"""
from __future__ import annotations

import pathlib

from datetime import date
from urllib.parse import quote

from . import scopes

# One wording of the read-only claim, shared with the report and the React
# landing. These pages had two of the four variants between them. Taken as
# functions and not as the Spanish constants, because these pages now have an
# English half: `wording` reads both languages from the locale catalogue, so the
# English here is the SAME sentence as the English on the landing rather than a
# second translation of the Spanish — which is how the Spanish came to have four.
from .wording import read_only_claim, read_only_lead

Lang = str  # "es" | "en", the same alias as `scopes.py`

#: Per language, because "31 de julio de 2026" is not a date in English. Both
#: entries are the same day and have to be edited together.
UPDATED: dict[Lang, str] = {"es": "31 de julio de 2026", "en": "31 July 2026"}

CONTROLLER = "Diego Fariña"

LIMITED_USE_URL = (
    "https://developers.google.com/terms/api-services-user-data-policy"
    "#additional_requirements_for_specific_api_scopes"
)

# ---------------------------------------------------------------- the shell

# --------------------------------------------------------------- tipografía

#: The three faces the app uses, and the filename prefix each ships under in the
#: Vite build. Latin subsets only: they cover Spanish including «», and anything
#: outside them falls back to the system stack rather than to a fourth face.
_CARAS = (
    ("Bricolage Grotesque", "bricolage-grotesque-latin-wght-normal", "200 800", "normal"),
    ("Inter", "inter-latin-wght-normal", "100 900", "normal"),
    ("IBM Plex Mono", "ibm-plex-mono-latin-400-normal", "400", "normal"),
    ("IBM Plex Mono", "ibm-plex-mono-latin-500-normal", "500", "normal"),
    ("IBM Plex Mono", "ibm-plex-mono-latin-600-normal", "600", "normal"),
)

_FUENTES_CACHE: dict = {}


def _dist_dir() -> str:
    """Where the built frontend lives, asked of the running app when there is one."""
    try:
        from flask import current_app

        return current_app.extensions["vigia"]["settings"].frontend_dist
    except Exception:
        try:
            from .config import load_settings

            return load_settings().frontend_dist
        except Exception:
            return ""


def font_faces(prefix: str) -> str:
    """`@font-face` rules pointing at the app's OWN self-hosted woff2 files.

    Same fonts as the dashboard, from the same origin. That last part is not a
    detail: the privacy page these rules style promises that "las tipografías se
    sirven desde este mismo dominio y no hay scripts, analítica, telemetría ni
    imágenes externas en ninguna página". Loading Inter from fonts.googleapis.com
    on the page making that promise would send every reader's IP to Google — which
    is the exact thing the page exists to say does not happen.

    The filenames carry a Vite content hash, so they are resolved at runtime and
    cached against the assets directory's mtime: a rebuild changes the hash and
    this notices, instead of silently serving 404s and falling back to system
    fonts nobody would spot.

    Returns "" when the build is not present (tests, a fresh checkout), and the
    font stacks fall back to the system faces.
    """
    dist = _dist_dir()
    assets = pathlib.Path(dist) / "assets" if dist else None
    if not assets or not assets.is_dir():
        return ""

    clave = (prefix, assets.stat().st_mtime_ns)
    if clave in _FUENTES_CACHE:
        return _FUENTES_CACHE[clave]

    reglas = []
    for familia, comienzo, peso, estilo in _CARAS:
        encontrado = next(
            (f.name for f in sorted(assets.glob(f"{comienzo}-*.woff2"))), None
        )
        if not encontrado:
            continue
        reglas.append(
            f"@font-face{{font-family:'{familia}';font-style:{estilo};"
            f"font-weight:{peso};font-display:swap;"
            f"src:url('{prefix}/assets/{encontrado}') format('woff2')}}"
        )
    css = "\n".join(reglas)
    _FUENTES_CACHE.clear()          # one entry is enough; the key is the mtime
    _FUENTES_CACHE[clave] = css
    return css


# The palette below is Vigía's own, from `frontend/src/index.css`. These pages
# used to carry an indigo-on-near-black palette that matched neither Vigía nor the
# website — it was closer to diegofarina.com's dark theme than to the app a
# visitor is standing in the middle of when they read them.
#
# Light, with no `prefers-color-scheme` block, BECAUSE the app has no dark mode:
# `body { @apply bg-paper text-body }` and nothing switches it. A privacy page
# that goes dark while the dashboard behind it stays light is the discontinuity,
# not the fix.
#
# Every pair is measured, not guessed:
#     body #24333e on paper .......... 11.83:1  AAA
#     headings #0d1f2d on paper ...... 15.30:1  AAA
#     dim #5c7183 on paper ............ 4.62:1  AA
#     links #1e415e on paper .......... 9.70:1  AA
#     ink on beacon (the button) ...... 9.22:1  AAA
#
# The amber is deliberately NOT a text colour: #f2b63c on paper is 1.66:1 and
# even beacon-deep only reaches 3.31:1. It is a button fill and a focus ring,
# which is exactly how the app uses it.
#
# This explanation lives in Python and not in a CSS comment: a comment inside the
# `<style>` block ships to every visitor. Third time today that mattered.
# The dark theme in `_CSS` below follows the app's choice by two routes, because
# these pages are rendered by Flask and cannot read the app's localStorage:
#   · `html.dark` / `html.light`, written by the server from the `vigia_theme`
#     cookie the toggle sets, so an explicit choice wins here too;
#   · `prefers-color-scheme` for the default (`system`), which sets no cookie.
# Without it, a reader on dark clicked "Privacidad" and landed on a white page.
#
# Measured against the real backgrounds:
#     body   #dbe6ee on #0b1620 .... 14.41:1  AAA
#     head   #f2f7fa .............. 16.92:1  AAA
#     dim    #93a8b6 ..............  7.41:1  AAA
#     links  #95c1dc ..............  9.51:1  AAA
#     warn text on #2a2113 ........ 12.50:1  AAA
#     padlock #5fd39b .............  9.81:1  — the light green #217050 is only
#                                    3.04:1 here, which is why it is lifted.
#
# The ES|EN link needs a rule of its own because it is a direct child of `.top`,
# and `.top>a` is the WORDMARK's rule: 18px, Bricolage, bold, white. Without an
# override the language switch printed as a second brand next to «Vigía». It is
# painted like the app's own `LangToggle` instead — mono, 11px, `--ink-3` border,
# `--ink-2` on hover — because that is the control a reader has just been using in
# the dashboard, and `margin-left:auto` puts it at the far end of the bar rather
# than in the middle of the navigation.
#
# This explanation is a Python comment because a CSS comment inside `<style>`
# ships to the reader. It did, in English, inside a Spanish privacy policy —
# the fourth time today an explanation of mine reached the served output.
_CSS = """
:root {
  --bg:#f2f5f4;        /* paper */
  --card:#ffffff;
  --panel:#ffffff;
  --line:#dde5e3;
  --ink:#24333e;       /* body text */
  --head:#0d1f2d;      /* headings, wordmark — harbor ink */
  /* The nav bar's own surface, and the ink that goes on it. NOT `--head`.
     `--head` is the colour of heading TEXT, so it inverts with the theme: in dark
     it becomes near-white, and using it as this bar's background turned the bar
     white with its white wordmark and light links on top — 1.17:1, invisible.
     One token cannot be both "the colour type is printed in" and "the colour a
     surface is painted with"; they move in opposite directions.
     Constant across themes on purpose: the app's own header is `bg-ink` in light
     and dark alike, and this bar exists to give the page the same first 60 pixels
     as the dashboard the visitor came from. */
  --bar:#0d1f2d;
  --on-bar:#ffffff;
  --ink-2:#14324a;
  --ink-3:#1e415e;
  --mist:#9db4c4;      /* on ink only */
  --dim:#5c7183;
  --accent:#1e415e;    /* links: ink-3, because amber fails on light */
  --beacon:#f2b63c;
  --beacon-deep:#b07d10;
  --bad:#b93a48; --ok:#2f8f63;
  /* The warning box. Border is #a97a12 (3.83:1 on white) rather than the beacon,
     which only reached 1.66:1 and was the sole cue marking the box as a warning. */
  --warn-bg:#fdf7e8; --warn-line:#a97a12;
  color-scheme: light;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:16px/1.65 "Inter",ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  -webkit-font-smoothing:antialiased}
a{color:var(--accent);text-underline-offset:2px}
/* The beacon focus ring, same as the app: `:focus-visible{outline:2px solid #f2b63c}`. */
a:focus-visible,summary:focus-visible,button:focus-visible{outline:2px solid var(--beacon);
  outline-offset:2px;border-radius:3px}
/* The app's nav: ink bar, wordmark in the display face, links in mist. Gives the
   page the same first 60 pixels as the dashboard the visitor came from. */
.top{background:var(--bar);padding:13px 20px;display:flex;align-items:center;
  flex-wrap:wrap;gap:6px 0;
  /* A hairline, because on the dark theme the bar (#0d1f2d) sits within a couple of
     steps of the page (#0b1620) and without an edge it does not read as a bar at
     all — legible text floating on nothing. */
  border-bottom:1px solid rgba(255,255,255,.10)}
.top>a{font-family:"Bricolage Grotesque","Inter",ui-sans-serif,system-ui,sans-serif;
  font-weight:700;font-size:18px;letter-spacing:-.01em;text-decoration:none;
  color:var(--on-bar)}
.top nav{display:inline-flex;gap:18px;margin-left:24px;font-size:14px}
.top nav a{color:var(--mist);text-decoration:none}
.top nav a:hover{color:var(--on-bar)}
.top a.idioma{margin-left:auto;font-family:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
  font-size:11px;font-weight:600;letter-spacing:.04em;line-height:1;color:var(--mist);
  text-decoration:none;border:1px solid var(--ink-3);border-radius:5px;padding:6px 9px}
.top a.idioma:hover{background:var(--ink-2);color:var(--on-bar)}
/* 70ch, not 760px. Measured at 760px the line ran to 79 characters, above the
   65-75 that reads comfortably; `ch` also keeps the measure right if the font
   changes. `margin-inline` is explicit so the centring does not depend on the
   older `margin:0 auto` shorthand surviving an edit. */
main{max-width:70ch;margin-inline:auto;padding:36px 20px 72px}
h1,h2,h3{font-family:"Bricolage Grotesque","Inter",ui-sans-serif,system-ui,sans-serif;
  color:var(--head)}
h1{font-size:31px;line-height:1.18;margin:0 0 6px;letter-spacing:-.02em}
.sub{color:var(--dim);font-size:14px;margin:0 0 30px}
h2{font-size:20px;margin:38px 0 8px;letter-spacing:-.015em}
h3{font-size:15px;margin:22px 0 6px}
p,li{color:var(--ink)}
p{margin:8px 0}
ul,ol{padding-left:22px}
li{margin:5px 0}
.muted{color:var(--dim);font-size:14px}
code{font:13px "IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--panel);
  border:1px solid var(--line);border-radius:4px;padding:1px 5px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;
  padding:16px 18px;margin:14px 0}
.card p:first-child{margin-top:0}
.card p:last-child{margin-bottom:0}
table{width:100%;border-collapse:collapse;margin:14px 0;font-size:14.5px;display:block;
  overflow-x:auto}
th,td{text-align:left;padding:9px 12px 9px 0;border-bottom:1px solid var(--line);
  vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--dim)}
/* Two list treatments, and the difference between them is the point.
   `.no` keeps the red ✕ and belongs on PROHIBITIONS — the acceptable-use list in
   the terms, where "do not do this" is exactly what red means.
   `.marcada` is for GUARANTEES: things Vigía cannot do, which read as protection.
   Those had the red ✕ too, so the colour said "bad" while the sentence said "you
   are covered", and on /connect a second green ✕ was drawn on top of it by a
   ::before, giving every line two icons that contradicted each other.
   Do not merge these two. */
.no li::marker{content:"✕  ";color:var(--bad);font-weight:700}
.yes li::marker{content:"✓  ";color:var(--ok);font-weight:700}
.marcada{list-style:none;padding-left:0;margin:12px 0}
.marcada li{display:flex;gap:10px;align-items:flex-start;margin:9px 0}
.marcada svg{flex:0 0 auto;width:17px;height:17px;margin-top:4px;color:var(--ok)}
footer{border-top:1px solid var(--line);margin-top:48px;padding-top:18px;
  color:var(--dim);font-size:13.5px}

html.dark {
  --bg:#0b1620;
  --card:#12222e;
  --panel:#12222e;
  --line:#22394a;
  --ink:#dbe6ee;
  --head:#f2f7fa;
  --ink-2:#24455a;
  --ink-3:#2f5a75;
  --mist:#b9cdda;
  --dim:#93a8b6;
  --accent:#95c1dc;
  --beacon:#f2b63c;
  --beacon-deep:#e8a72c;
  --bad:#ff8a94;
  --ok:#5fd39b;
  --warn-bg:#2a2113;
  --warn-line:#f2b63c;
  color-scheme: dark;
}

@media (prefers-color-scheme: dark) {
  html:not(.light) {
    --bg:#0b1620;
    --card:#12222e;
    --panel:#12222e;
    --line:#22394a;
    --ink:#dbe6ee;
    --head:#f2f7fa;
    --ink-2:#24455a;
    --ink-3:#2f5a75;
    --mist:#b9cdda;
    --dim:#93a8b6;
    --accent:#95c1dc;
    --beacon:#f2b63c;
    --beacon-deep:#e8a72c;
    --bad:#ff8a94;
    --ok:#5fd39b;
    --warn-bg:#2a2113;
    --warn-line:#f2b63c;
    color-scheme: dark;
  }
}
"""


#: The two icons, in the markup rather than in a pseudo-element, so they can be
#: SVGs and can be told apart. A padlock for a guarantee, a tick for something
#: that is done. Both inherit `--ok`, so they follow the theme.
CANDADO = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" '
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    '<rect x="4" y="11" width="16" height="10" rx="2"/>'
    '<path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>'
)
TIC = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" '
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
    '<path d="M4 12.5l5 5L20 6.5"/></svg>'
)


def idioma_pedido() -> str:
    """The language for a server-rendered page: `?lang=` first, then the cookie.

    Same precedence and the same cookie as `_requested_lang()` in `api/routes.py`,
    so a visitor who picked EN with the toggle in the app and then clicked
    "Connect" does not land on a Spanish page. Deliberately NOT `Accept-Language`:
    that was removed from the API for a documented reason, and a legal page
    disagreeing with the app about the language is worse than either choice.
    """
    from flask import request

    from .i18n import normalize_lang

    try:
        explicito = request.args.get("lang")
        if explicito:
            return normalize_lang(explicito)
        return normalize_lang(request.cookies.get("vigia_lang"))
    except RuntimeError:  # outside a request context (a test calling the renderer)
        return "es"


def _tema_clase() -> str:
    """`class="dark"`, `class="light"`, or nothing.

    Nothing is the honest default: with no cookie the reader has expressed no
    preference here, and the media query above lets their operating system answer
    instead of this page guessing. The cookie only ever exists because somebody
    pressed the toggle.
    """
    try:
        from flask import request

        elegido = request.cookies.get("vigia_theme")
    except Exception:
        return ""
    if elegido in ("dark", "light"):
        return f' class="{elegido}"'
    return ""


def selector_idioma(prefix: str, lang: str, ruta: str) -> str:
    """ES|EN on a server-rendered page.

    These pages are reached from Google's consent flow and from search, so a reader
    can arrive without ever having touched the app's toggle. `?lang=` is honoured
    on the way in, so the link only has to carry it.
    """
    otro = "en" if lang == "es" else "es"
    etiqueta = "EN" if otro == "en" else "ES"
    titulo = "Read this in English" if otro == "en" else "Leer en español"
    return (
        f'<a class="idioma" hreflang="{otro}" lang="{otro}" '
        f'href="{prefix}{ruta}?lang={otro}" title="{titulo}">{etiqueta}</a>'
    )


def _ruta_actual(por_defecto: str = "/") -> str:
    """The path being served, without the mount prefix, URL-quoted.

    Only the 404 needs it. The other four pages know their own address, but this
    one is rendered for whatever address did NOT exist, and the ES|EN link has to
    come back to the same address instead of dropping the reader on the homepage.

    Quoted, not interpolated raw: `request.path` is URL-DECODED, so a request for
    `/%22%3E%3Cscript%3E` arrives as `/"><script>` and putting that straight into
    an `href` is a reflected injection on the one page an attacker can choose the
    path of. `quote` turns it back into an escaped path, which is also what a
    correct URL needs.
    """
    try:
        from flask import request

        return quote(request.path or por_defecto, safe="/")
    except Exception:  # outside a request context (a test calling the renderer)
        return por_defecto


def _lang(lang: str) -> Lang:
    """`es` | `en`, and anything else is Spanish.

    The five renderers are public and are called from tests and from a route, so
    each one normalises what it is given instead of trusting it: `scopes.filas_tabla`
    and `UPDATED` index by language and a stray `"fr"` would be a `KeyError` in the
    middle of a legal page rather than a page in the wrong language.
    """
    return "en" if (lang or "").lower().startswith("en") else "es"


def _elige(valores: dict[Lang, str], lang: Lang) -> str:
    """One language's string, falling back to Spanish rather than to a key.

    Spanish and not English, unlike `i18n.py`: these documents are written in
    Spanish first and the translation follows, so the last resort is the original.
    """
    return valores.get(lang) or valores["es"]


def _textos(bloques: dict[str, dict[Lang, str]], lang: Lang, **valores: object) -> dict[str, str]:
    """A page's prose in one language, with its own numbers already in place.

    `bloques` has the shape `scopes.py` uses — `{"clave": {"es": …, "en": …}}` —
    and each string may carry `{retention_hours}`, `{mailto}`, `{prefix}` and the
    like, so the retention window stays a variable INSIDE the sentence that
    promises it. That is not decoration: /privacy hardcoded "24 horas" in five
    places once, and two pages of the same product then disagreed about a
    data-protection commitment.
    """
    return {clave: _elige(valor, lang).format(**valores) for clave, valor in bloques.items()}


#: What three of these pages print where the contact address should be when none is
#: configured. Not an address of its own: a page that invents one is worse than a
#: page that admits the operator has not set one.
_SIN_CONTACTO: dict[Lang, str] = {"es": "(sin configurar)", "en": "(not configured)"}


def _mailto(contact: str, lang: Lang) -> str:
    """The contact address as a link, or the placeholder, in this language."""
    if contact:
        return f'<a href="mailto:{contact}">{contact}</a>'
    return _elige(_SIN_CONTACTO, lang)


#: The chrome every legal page shares: the nav labels, the meta description and the
#: two footer labels. The nav wording matches the React header and footer
#: (`frontend/src/content/ui.ts`), so the bar does not rename itself when a reader
#: leaves the dashboard.
_SHELL: dict[str, dict[Lang, str]] = {
    "privacidad": {"es": "Privacidad", "en": "Privacy"},
    "terminos": {"es": "Términos", "en": "Terms"},
    "tus_datos": {"es": "Tus datos", "en": "Your data"},
    "descripcion": {
        "es": "de Vigía, el escáner de postura de seguridad de solo lectura para "
        "Google Workspace.",
        "en": "for Vigía, the read-only security posture scanner for Google Workspace.",
    },
    "responsable": {"es": "Responsable del tratamiento", "en": "Data controller"},
    "actualizado": {"es": "Última actualización", "en": "Last updated"},
}


def _page(prefix: str, title: str, body: str, lang: str = "es", ruta: str = "/") -> str:
    """The shell. `ruta` is this page's own path, so ES|EN links back to itself."""
    lang = _lang(lang)
    t = _textos(_SHELL, lang)
    # Not a literal and not a translation made here: one redaction per language,
    # and both of them live in the catalogue behind `wording`.
    lead, claim = read_only_lead(lang), read_only_claim(lang)
    return f"""<!doctype html>
<html lang="{lang}"{_tema_clase()}>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · Vigía</title>
<meta name="description" content="{title} {t['descripcion']}">
<style>{font_faces(prefix)}\n{_CSS}</style>
</head>
<body>
<div class="top">
  <a href="{prefix}/">Vigía</a>
  <nav>
    <a href="{prefix}/privacy">{t['privacidad']}</a>
    <a href="{prefix}/terms">{t['terminos']}</a>
    <a href="{prefix}/help/data">{t['tus_datos']}</a>
  </nav>
  {selector_idioma(prefix, lang, ruta)}
</div>
<main>
{body}
<footer>
  {t['responsable']}: {CONTROLLER}. {t['actualizado']}: {_elige(UPDATED, lang)}.<br>
  {lead} {claim}
</footer>
</main>
</body>
</html>"""


# --------------------------------------------------------------- privacidad


#: Every sentence of the privacy policy, both languages. The HTML structure is NOT
#: here: it is in `privacy_html` below, written once, so the two documents cannot
#: drift in shape — only in wording.
_PRIVACIDAD: dict[str, dict[Lang, str]] = {
    "titulo": {"es": "Política de privacidad", "en": "Privacy policy"},
    "sub": {
        "es": "Qué datos ve Vigía, qué guarda, cuánto tiempo y quién responde por ellos.",
        "en": "What data Vigía sees, what it stores, for how long, and who answers for it.",
    },
    "esencial": {
        "es": "<strong>Lo esencial en cuatro frases.</strong> Vigía solo lee: no puede "
        "modificar ningún ajuste de tu Google Workspace porque no solicita ningún permiso de "
        "escritura. Nunca pide acceso al contenido de Gmail, de Drive ni de ningún archivo. "
        "Las direcciones de correo de las personas de tu organización que aparecen en un "
        "informe se borran automáticamente a las <strong>{retention_hours} horas</strong>. Al "
        "desconectar, se borra todo y se revoca el acceso en Google.",
        "en": "<strong>The essentials in four sentences.</strong> Vigía only reads: it cannot "
        "change any setting in your Google Workspace because it does not request any write "
        "permission. It never asks for access to the content of Gmail, of Drive or of any "
        "file. The e-mail addresses of the people in your organisation that appear in a report "
        "are deleted automatically after <strong>{retention_hours} hours</strong>. When you "
        "disconnect, everything is deleted and access is revoked at Google.",
    },
    # ---------------------------------------------------- quién responde
    "h_responsable": {"es": "Quién es el responsable", "en": "Who the data controller is"},
    "responsable": {
        "es": "El responsable del tratamiento es <strong>{controller}</strong>, a título "
        "personal, como desarrollador y operador de Vigía. Contacto para cualquier cuestión de "
        "datos o para ejercer tus derechos: {mailto}.",
        "en": "The data controller is <strong>{controller}</strong>, in a personal capacity, "
        "as the developer and operator of Vigía. Contact for any question about data or to "
        "exercise your rights: {mailto}.",
    },
    "sin_empresa": {
        "es": "Vigía no pertenece a ninguna empresa ni actúa por cuenta de ninguna "
        "organización distinta de la tuya.",
        "en": "Vigía does not belong to any company and does not act on behalf of any "
        "organisation other than yours.",
    },
    # ------------------------------------------------------ los dos papeles
    "h_papeles": {"es": "Los dos papeles de Vigía", "en": "Vigía's two roles"},
    "papeles": {
        "es": "La distinción importa porque determina quién decide sobre cada dato:",
        "en": "The distinction matters because it determines who decides about each piece of "
        "data:",
    },
    "papel_responsable": {
        "es": "<strong>Responsable</strong> de los datos de tu propia cuenta de "
        "administrador: la dirección con la que conectas y tu dominio principal. Los trata "
        "Vigía para poder darte el servicio.",
        "en": "<strong>Controller</strong> of the data of your own administrator account: the "
        "address you connect with and your primary domain. Vigía processes them in order to "
        "provide you with the service.",
    },
    "papel_encargado": {
        "es": "<strong>Encargado del tratamiento</strong> de los datos de las demás personas "
        "de tu organización que aparecen en un informe. La responsable de esos datos es tu "
        "organización; Vigía los procesa por tu cuenta, siguiendo tus instrucciones, solo para "
        "producir el informe que has pedido, y los borra a las {retention_hours} horas.",
        "en": "<strong>Processor</strong> of the data of the other people in your organisation "
        "who appear in a report. The controller of that data is your organisation; Vigía "
        "processes it on your behalf, following your instructions, only to produce the report "
        "you asked for, and deletes it after {retention_hours} hours.",
    },
    # -------------------------------------------------------- base jurídica
    "h_base": {"es": "Base jurídica", "en": "Legal basis"},
    "th_tratamiento": {"es": "Tratamiento", "en": "Processing"},
    # The regulation is the same one; only the way it is cited changes, which is
    # why the article numbers are written the way each language cites them.
    "th_base": {"es": "Base (RGPD)", "en": "Basis (GDPR)"},
    "base_leer": {
        "es": "Leer la configuración de tu Workspace para generar el informe",
        "en": "Reading your Workspace configuration in order to generate the report",
    },
    "base_leer_por": {
        "es": "Tu consentimiento explícito, otorgado en la pantalla de Google (art. 6.1.a). Es "
        "revocable en cualquier momento y revocarlo detiene el tratamiento.",
        "en": "Your explicit consent, given on Google's screen (art. 6(1)(a)). It can be "
        "withdrawn at any time, and withdrawing it stops the processing.",
    },
    "base_guardar": {
        "es": "Guardar la puntuación y el estado de cada control para mostrarte la evolución",
        "en": "Storing the score and the state of each control to show you how they change "
        "over time",
    },
    "base_guardar_por": {
        "es": "Ejecución del servicio que has solicitado (art. 6.1.b).",
        "en": "Performance of the service you requested (art. 6(1)(b)).",
    },
    "base_registros": {
        "es": "Registros técnicos mínimos para que el servicio funcione y sea seguro",
        "en": "Minimal technical logs so the service works and is secure",
    },
    "base_registros_por": {
        "es": "Interés legítimo (art. 6.1.f), limitado a lo imprescindible.",
        "en": "Legitimate interest (art. 6(1)(f)), limited to what is indispensable.",
    },
    # ------------------------------------------------------------ permisos
    "h_permisos": {
        "es": "Permisos que se solicitan, y para qué sirve cada uno",
        "en": "The permissions requested, and what each one is for",
    },
    "permisos": {
        "es": "Todos son de <strong>solo lectura</strong> y ninguno pertenece a la categoría "
        "«restringida» de Google, que es precisamente la que daría acceso al contenido de los "
        "mensajes y de los archivos. Esta es la lista completa, la misma que verás en la "
        "pantalla de consentimiento:",
        "en": "All of them are <strong>read-only</strong> and none belongs to Google's "
        "'restricted' category, which is precisely the one that would give access to the "
        "content of messages and files. This is the complete list, the same one you will see "
        "on the consent screen:",
    },
    "th_permiso": {"es": "Permiso", "en": "Permission"},
    "th_para_que": {"es": "Para qué", "en": "What for"},
    "sin_profile": {
        "es": "No se solicita <code>profile</code>: Vigía no lee tu nombre ni tu foto.",
        "en": "<code>profile</code> is not requested: Vigía does not read your name or your "
        "photo.",
    },
    # ------------------------------------------------- qué se guarda y cuánto
    "h_guardado": {"es": "Qué se guarda y cuánto tiempo", "en": "What is stored, and for how long"},
    "th_dato": {"es": "Dato", "en": "Data"},
    "th_cuanto": {"es": "Cuánto", "en": "How long"},
    "cookie_dato": {
        "es": "Una cookie <code>vigia_theme</code> con el valor <code>light</code> o "
        "<code>dark</code>, y nada más",
        "en": "A <code>vigia_theme</code> cookie holding the value <code>light</code> or "
        "<code>dark</code>, and nothing else",
    },
    "cookie_para": {
        "es": "Recordar si has elegido tema claro u oscuro, para que estas páginas no te "
        "cambien el fondo al salir del panel. No contiene ningún identificador, no permite "
        "reconocerte y solo existe si pulsas el interruptor: por defecto se respeta la "
        "preferencia de tu sistema operativo y no se guarda nada",
        "en": "Remembering whether you chose the light or the dark theme, so these pages do "
        "not change the background on you when you leave the dashboard. It contains no "
        "identifier, it cannot be used to recognise you, and it only exists if you press the "
        "toggle: by default your operating system's preference is respected and nothing is "
        "stored",
    },
    "cookie_cuanto": {
        "es": "Un año, o hasta que vuelvas a «el del sistema»",
        "en": "One year, or until you set it back to your system's theme",
    },
    "dominios_dato": {
        "es": "Tu dominio principal y tus dominios verificados",
        "en": "Your primary domain and your verified domains",
    },
    "dominios_para": {
        "es": "Identificar tu organización y saber qué comprobar",
        "en": "Identifying your organisation and knowing what to check",
    },
    "hasta_desconectar": {"es": "Hasta que desconectes", "en": "Until you disconnect"},
    "admin_dato": {
        "es": "La dirección del administrador que conecta",
        "en": "The address of the administrator who connects",
    },
    "admin_para": {
        "es": "Mostrarte qué autorización está activa y enviarte los avisos",
        "en": "Showing you which authorisation is active and sending you the alerts",
    },
    "token_dato": {
        "es": "Un token de refresco OAuth, <strong>cifrado en reposo</strong> (Fernet, AES-128 "
        "en modo CBC con HMAC)",
        "en": "An OAuth refresh token, <strong>encrypted at rest</strong> (Fernet, AES-128 in "
        "CBC mode with HMAC)",
    },
    "token_para": {
        "es": "Repetir el escaneo programado sin volver a pedirte consentimiento",
        "en": "Repeating the scheduled scan without asking you for consent again",
    },
    "puntuacion_dato": {
        "es": "Puntuación, recuentos y el resultado de cada control (identificador y estado)",
        "en": "The score, the counts and the result of each control (identifier and state)",
    },
    "puntuacion_para": {
        "es": "Enseñarte la evolución, las mejoras y las regresiones",
        "en": "Showing you the progress, the improvements and the regressions",
    },
    "correos_dato": {
        "es": "<strong>Direcciones de correo de las personas de tu organización</strong> que "
        "aparecen como afectadas por un hallazgo",
        "en": "<strong>E-mail addresses of the people in your organisation</strong> who appear "
        "as affected by a finding",
    },
    "correos_para": {
        "es": "Que puedas saber sobre quién actuar",
        "en": "So that you can tell who to act on",
    },
    "borrado_auto": {
        "es": "<strong>{retention_hours} horas</strong>, y después se borran automáticamente",
        "en": "<strong>{retention_hours} hours</strong>, and then they are deleted "
        "automatically",
    },
    "ips_dato": {
        "es": "<strong>Las direcciones IP desde las que han entrado tus "
        "superadministradores</strong>, leídas del registro de acceso, y el país al que "
        "corresponden",
        "en": "<strong>The IP addresses your super administrators have signed in "
        "from</strong>, read from the login audit log, and the country they correspond to",
    },
    "ips_para": {
        "es": "Enseñarte desde dónde se entra normalmente a las cuentas que controlan todo el "
        "tenant, y avisarte si aparece un país en el que no constaba ningún acceso anterior",
        "en": "Showing you where the accounts that control the whole tenant are normally "
        "signed in from, and warning you if a country appears in which no previous sign-in was "
        "on record",
    },
    "pasadas_horas": {
        "es": "Pasadas esas {retention_hours} horas, el informe sigue diciendo cuántas cuentas "
        "estaban afectadas por cada hallazgo, pero ya no quién. Para volver a verlo basta con "
        "lanzar un escaneo nuevo.",
        "en": "After those {retention_hours} hours the report still says how many accounts "
        "were affected by each finding, but no longer who. To see it again you only have to "
        "run a new scan.",
    },
    # ------------------------------------------- las personas que no consintieron
    "h_personas": {
        "es": "Sobre las personas de tu organización",
        "en": "About the people in your organisation",
    },
    "personas": {
        "es": "Conviene decirlo con claridad: un informe nombra a empleados y empleadas tuyas "
        "que nunca han usado Vigía ni han dado su consentimiento a nada. Por eso su "
        "información es la única que tiene un plazo de borrado corto y automático y es la "
        "mínima posible: la dirección de correo, el hallazgo que les afecta y —solo en el caso "
        "de los superadministradores— la dirección IP desde la que han entrado, porque sin ella "
        "no hay forma de decirte que una de esas cuentas ha empezado a usarse desde otro sitio. "
        "Nada más. Nunca incluye el contenido de sus mensajes, sus archivos ni el resto de su "
        "actividad.",
        "en": "It is worth saying plainly: a report names employees of yours who have never "
        "used Vigía and have never consented to anything. That is why their information is the "
        "only kind with a short, automatic deletion deadline, and why it is the least possible: "
        "the e-mail address, the finding that affects them and —only in the case of super "
        "administrators— the IP address they signed in from, because without it there is no way "
        "to tell you that one of those accounts has started being used from somewhere else. "
        "Nothing more. It never includes the content of their messages, their files or the rest "
        "of their activity.",
    },
    "ips_no_salen": {
        "es": "Esas direcciones IP <strong>no salen de este servidor</strong>. El país se "
        "calcula aquí, con un fichero local: no se consulta ningún servicio de "
        "geolocalización, porque hacerlo significaría enviar a una empresa más las direcciones "
        "de los administradores de tu organización.",
        "en": "Those IP addresses <strong>never leave this server</strong>. The country is "
        "worked out here, with a local file: no geolocation service is queried, because doing "
        "so would mean sending your organisation's administrators' addresses to one more "
        "company.",
    },
    # ------------------------------------------------------ las garantías
    "h_nunca": {"es": "Qué no se hace nunca", "en": "What is never done"},
    "nunca_contenido": {
        "es": "Leer, guardar o transmitir el contenido de correos, adjuntos o archivos de "
        "Drive: no se solicitan los permisos que lo permitirían, así que es técnicamente "
        "imposible.",
        "en": "Reading, storing or transmitting the content of e-mails, attachments or Drive "
        "files: the permissions that would allow it are not requested, so it is technically "
        "impossible.",
    },
    "nunca_modificar": {
        "es": "Modificar cualquier ajuste de tu Workspace. No existe ninguna ruta de escritura "
        "en la aplicación; la remediación se limita a darte el enlace a la pantalla donde "
        "actuar tú.",
        "en": "Changing any setting in your Workspace. There is no write path in the "
        "application; remediation goes no further than giving you the link to the screen where "
        "you act yourself.",
    },
    "nunca_vender": {
        "es": "Vender tus datos, cederlos con fines comerciales o publicitarios, o usarlos "
        "para entrenar modelos de inteligencia artificial.",
        "en": "Selling your data, passing it on for commercial or advertising purposes, or "
        "using it to train artificial intelligence models.",
    },
    "nunca_otros_usos": {
        "es": "Usar tus datos para nada que no sea mostrarte tus propios resultados.",
        "en": "Using your data for anything other than showing you your own results.",
    },
    # --------------------------------------------------------- uso limitado
    "h_uso_limitado": {
        "es": "Uso limitado de los datos de Google",
        "en": "Limited use of Google data",
    },
    # The policy's own name, as Google publishes it in each language, and the link
    # keeps the single URL constant rather than a second copy of it.
    "uso_limitado": {
        "es": "El uso que Vigía hace de la información recibida a través de las API de Google "
        "Workspace se atiene a la <a href=\"{limited_use_url}\" rel=\"noreferrer\">Política de "
        "datos de usuario de los servicios de las API de Google</a>, incluidos sus "
        "<strong>requisitos de Uso Limitado</strong>. En concreto: los datos se usan únicamente "
        "para ofrecerte y mejorar la funcionalidad visible del producto, no se transfieren a "
        "terceros salvo lo estrictamente necesario para prestar el servicio o cuando lo exija "
        "la ley, no se usan con fines publicitarios, y ninguna persona los lee, salvo con tu "
        "permiso explícito, por motivos de seguridad, para cumplir la ley, o cuando estén "
        "agregados y anonimizados.",
        "en": "Vigía's use of information received through the Google Workspace APIs adheres "
        "to the <a href=\"{limited_use_url}\" rel=\"noreferrer\">Google API Services User Data "
        "Policy</a>, including its <strong>Limited Use requirements</strong>. Specifically: "
        "the data is used only to provide and improve the user-facing functionality of the "
        "product, it is not transferred to third parties except as strictly necessary to "
        "provide the service or where the law requires it, it is not used for advertising "
        "purposes, and no person reads it, except with your explicit permission, for security "
        "reasons, to comply with the law, or when it is aggregated and anonymised.",
    },
    # ------------------------------------------------------------- terceros
    "h_terceros": {"es": "Terceros que intervienen", "en": "The third parties involved"},
    "terceros": {
        "es": "Vigía no vende ni cede datos, pero prestar el servicio implica a estos "
        "proveedores. Se enumeran todos, incluidos los que solo ven metadatos técnicos:",
        "en": "Vigía does not sell or pass on data, but providing the service involves these "
        "providers. All of them are listed, including those that only see technical metadata:",
    },
    "th_proveedor": {"es": "Proveedor", "en": "Provider"},
    "th_que_ve": {"es": "Qué ve", "en": "What it sees"},
    "th_por_que": {"es": "Por qué", "en": "Why"},
    "google_quien": {
        "es": "Google (Admin SDK y Cloud Identity)",
        "en": "Google (Admin SDK and Cloud Identity)",
    },
    "google_ve": {
        "es": "Las peticiones de lectura que se le hacen",
        "en": "The read requests made to it",
    },
    "google_por": {
        "es": "Es la fuente de los datos que se analizan",
        "en": "It is the source of the data being analysed",
    },
    "cloudflare_ve": {
        "es": "Dirección IP y metadatos de conexión de quien visita el sitio; termina el "
        "cifrado TLS",
        "en": "The IP address and connection metadata of whoever visits the site; it "
        "terminates the TLS encryption",
    },
    "cloudflare_por": {
        "es": "Publica el sitio y lo protege",
        "en": "It publishes the site and protects it",
    },
    "zoho_quien": {"es": "Zoho (correo)", "en": "Zoho (e-mail)"},
    "zoho_ve": {
        "es": "Tu dirección de aviso y el asunto y cuerpo del correo, que incluye el nombre de "
        "tu dominio y los títulos de tus hallazgos",
        "en": "Your alert address and the subject and body of the message, which includes your "
        "domain name and the titles of your findings",
    },
    "zoho_por": {
        "es": "Entregar los avisos por correo que hayas activado",
        "en": "Delivering the e-mail alerts you have switched on",
    },
    "dns_quien": {
        "es": "Resolutores DNS públicos (Cloudflare 1.1.1.1, Google 8.8.8.8)",
        "en": "Public DNS resolvers (Cloudflare 1.1.1.1, Google 8.8.8.8)",
    },
    "dns_ve": {
        "es": "Los nombres de dominio que se consultan",
        "en": "The domain names being queried",
    },
    "dns_por": {
        "es": "Comprobar SPF, DKIM, DMARC y el resto de registros públicos",
        "en": "Checking SPF, DKIM, DMARC and the rest of the public records",
    },
    "geoip": {
        "es": "La lista anterior son los cuatro proveedores que intervienen. La base de datos "
        "que traduce una IP a un país <strong>no es uno de ellos</strong>: es un fichero "
        "descargado que se consulta en este servidor, no un servicio, así que no recibe nada. "
        "Se usa <a href=\"https://db-ip.com\" rel=\"noreferrer\">DB-IP IP-to-Country Lite</a>, "
        "publicada bajo <a href=\"https://creativecommons.org/licenses/by/4.0/\" "
        "rel=\"noreferrer\">CC BY 4.0</a>, cuya licencia exige esta mención.",
        "en": "The list above is the four providers involved. The database that turns "
        "an IP address into a country <strong>is not one of them</strong>: it is a downloaded "
        "file, queried on this server, not a service, so it receives nothing. It uses "
        "<a href=\"https://db-ip.com\" rel=\"noreferrer\">DB-IP IP-to-Country Lite</a>, "
        "published under <a href=\"https://creativecommons.org/licenses/by/4.0/\" "
        "rel=\"noreferrer\">CC BY 4.0</a>, whose licence requires this attribution.",
    },
    "sin_terceros_navegador": {
        "es": "Vigía no carga nada de terceros en el navegador: las tipografías se sirven desde "
        "este mismo dominio y no hay scripts, analítica, telemetría ni imágenes externas en "
        "ninguna página. Puedes comprobarlo en la pestaña de red de tu navegador.",
        "en": "Vigía loads nothing from third parties in the browser: the fonts are served "
        "from this same domain and there are no scripts, analytics, telemetry or external "
        "images on any page. You can check this in your browser's network tab.",
    },
    # ------------------------------------------------------------- derechos
    "h_derechos": {"es": "Tus derechos", "en": "Your rights"},
    "derechos": {
        "es": "Puedes ejercer en cualquier momento los derechos de <strong>acceso</strong>, "
        "<strong>rectificación</strong>, <strong>supresión</strong>, "
        "<strong>limitación</strong>, <strong>oposición</strong> y "
        "<strong>portabilidad</strong> escribiendo a {mailto}. La respuesta llega en un plazo "
        "máximo de un mes.",
        "en": "You can exercise your rights of <strong>access</strong>, "
        "<strong>rectification</strong>, <strong>erasure</strong>, "
        "<strong>restriction</strong>, <strong>objection</strong> and "
        "<strong>portability</strong> at any time by writing to {mailto}. The answer arrives "
        "within a maximum of one month.",
    },
    "derechos_directos": {
        "es": "Dos de ellos, además, los puedes ejercer tú directamente y de forma inmediata, "
        "sin pedir permiso a nadie: la <strong>supresión</strong> pulsando «Desconectar», y la "
        "<strong>oposición</strong> retirando el acceso desde tu propia cuenta de Google. Cómo "
        "hacerlo está en <a href=\"{prefix}/help/data\">Tus datos</a>.",
        "en": "Two of them, moreover, you can exercise yourself, immediately and without "
        "asking anybody's permission: <strong>erasure</strong> by pressing 'Disconnect', and "
        "<strong>objection</strong> by removing access from your own Google account. How to do "
        "it is in <a href=\"{prefix}/help/data\">Your data</a>.",
    },
    "reclamar": {
        "es": "Si consideras que el tratamiento no es correcto, puedes reclamar ante la "
        "autoridad de protección de datos que te corresponda: en España la Agencia Española de "
        "Protección de Datos (AEPD), en el Reino Unido la Information Commissioner's Office "
        "(ICO).",
        "en": "If you consider that the processing is not right, you can complain to the data "
        "protection authority that applies to you: in Spain the Agencia Española de Protección "
        "de Datos (AEPD), in the United Kingdom the Information Commissioner's Office (ICO).",
    },
    # ------------------------------------------------------------ seguridad
    "h_seguridad": {"es": "Seguridad", "en": "Security"},
    "seg_token": {
        "es": "El token de refresco se guarda cifrado; la clave vive fuera de la base de datos.",
        "en": "The refresh token is stored encrypted; the key lives outside the database.",
    },
    "seg_https": {
        "es": "Todo el tráfico va por HTTPS.",
        "en": "All traffic goes over HTTPS.",
    },
    "seg_sin_escritura": {
        "es": "La aplicación no tiene ninguna operación de escritura contra las API de Google.",
        "en": "The application has no write operation against the Google APIs.",
    },
    "seg_minimo": {
        "es": "Se guarda el mínimo necesario, y lo que caduca se borra sin intervención "
        "humana.",
        "en": "The minimum necessary is stored, and what expires is deleted with no human "
        "intervention.",
    },
    # -------------------------------------------------------------- cambios
    "h_cambios": {"es": "Cambios en esta política", "en": "Changes to this policy"},
    "cambios": {
        "es": "Si cambia algo sustancial —qué datos se tratan, cuánto se guardan o qué "
        "terceros intervienen— se actualizará la fecha del pie y, si el cambio te afecta, se "
        "avisará por correo a la dirección de administrador conectada.",
        "en": "If anything substantial changes —what data is processed, how long it is kept or "
        "which third parties are involved— the date in the footer will be updated and, if the "
        "change affects you, notice will be sent by e-mail to the connected administrator "
        "address.",
    },
}


def privacy_html(prefix: str, contact: str, retention_hours: int = 24, lang: str = "es") -> str:
    lang = _lang(lang)
    mailto = _mailto(contact, lang)
    t = _textos(
        _PRIVACIDAD,
        lang,
        retention_hours=retention_hours,
        mailto=mailto,
        controller=CONTROLLER,
        prefix=prefix,
        limited_use_url=LIMITED_USE_URL,
    )
    # Generated from `vigia.scopes`, never typed here: this table and the
    # authorization request disagreed once, and a reviewer at Google compares them.
    # `filas_tabla` is already bilingual, so the language goes in rather than the
    # table being translated a second time in this file.
    filas_permisos = scopes.filas_tabla(lang)
    body = f"""
<h1>{t['titulo']}</h1>
<p class="sub">{t['sub']}</p>

<div class="card">
  <p>{t['esencial']}</p>
</div>

<h2>{t['h_responsable']}</h2>
<p>{t['responsable']}</p>
<p class="muted">{t['sin_empresa']}</p>

<h2>{t['h_papeles']}</h2>
<p>{t['papeles']}</p>
<ul>
  <li>{t['papel_responsable']}</li>
  <li>{t['papel_encargado']}</li>
</ul>

<h2>{t['h_base']}</h2>
<table>
  <tr><th>{t['th_tratamiento']}</th><th>{t['th_base']}</th></tr>
  <tr><td>{t['base_leer']}</td>
      <td>{t['base_leer_por']}</td></tr>
  <tr><td>{t['base_guardar']}</td>
      <td>{t['base_guardar_por']}</td></tr>
  <tr><td>{t['base_registros']}</td>
      <td>{t['base_registros_por']}</td></tr>
</table>

<h2>{t['h_permisos']}</h2>
<p>{t['permisos']}</p>
<table>
  <tr><th>{t['th_permiso']}</th><th>{t['th_para_que']}</th></tr>
{filas_permisos}
</table>
<p class="muted">{t['sin_profile']}</p>

<h2>{t['h_guardado']}</h2>
<table>
  <tr><th>{t['th_dato']}</th><th>{t['th_para_que']}</th><th>{t['th_cuanto']}</th></tr>
  <tr><td>{t['cookie_dato']}</td>
      <td>{t['cookie_para']}</td>
      <td>{t['cookie_cuanto']}</td></tr>
  <tr><td>{t['dominios_dato']}</td>
      <td>{t['dominios_para']}</td>
      <td>{t['hasta_desconectar']}</td></tr>
  <tr><td>{t['admin_dato']}</td>
      <td>{t['admin_para']}</td>
      <td>{t['hasta_desconectar']}</td></tr>
  <tr><td>{t['token_dato']}</td>
      <td>{t['token_para']}</td>
      <td>{t['hasta_desconectar']}</td></tr>
  <tr><td>{t['puntuacion_dato']}</td>
      <td>{t['puntuacion_para']}</td>
      <td>{t['hasta_desconectar']}</td></tr>
  <tr><td>{t['correos_dato']}</td>
      <td>{t['correos_para']}</td>
      <td>{t['borrado_auto']}</td></tr>
  <tr><td>{t['ips_dato']}</td>
      <td>{t['ips_para']}</td>
      <td>{t['borrado_auto']}</td></tr>
</table>
<p>{t['pasadas_horas']}</p>

<h3>{t['h_personas']}</h3>
<p>{t['personas']}</p>
<p>{t['ips_no_salen']}</p>

<h2>{t['h_nunca']}</h2>
<ul class="marcada">
  <li>{CANDADO}<span>{t['nunca_contenido']}</span></li>
  <li>{CANDADO}<span>{t['nunca_modificar']}</span></li>
  <li>{CANDADO}<span>{t['nunca_vender']}</span></li>
  <li>{CANDADO}<span>{t['nunca_otros_usos']}</span></li>
</ul>

<h2>{t['h_uso_limitado']}</h2>
<div class="card">
  <p>{t['uso_limitado']}</p>
</div>

<h2>{t['h_terceros']}</h2>
<p>{t['terceros']}</p>
<table>
  <tr><th>{t['th_proveedor']}</th><th>{t['th_que_ve']}</th><th>{t['th_por_que']}</th></tr>
  <tr><td>{t['google_quien']}</td>
      <td>{t['google_ve']}</td>
      <td>{t['google_por']}</td></tr>
  <tr><td>Cloudflare</td>
      <td>{t['cloudflare_ve']}</td>
      <td>{t['cloudflare_por']}</td></tr>
  <tr><td>{t['zoho_quien']}</td>
      <td>{t['zoho_ve']}</td>
      <td>{t['zoho_por']}</td></tr>
  <tr><td>{t['dns_quien']}</td>
      <td>{t['dns_ve']}</td>
      <td>{t['dns_por']}</td></tr>
</table>
<p class="muted">{t['geoip']}</p>
<p class="muted">{t['sin_terceros_navegador']}</p>

<h2>{t['h_derechos']}</h2>
<p>{t['derechos']}</p>
<p>{t['derechos_directos']}</p>
<p>{t['reclamar']}</p>

<h2>{t['h_seguridad']}</h2>
<ul class="yes">
  <li>{t['seg_token']}</li>
  <li>{t['seg_https']}</li>
  <li>{t['seg_sin_escritura']}</li>
  <li>{t['seg_minimo']}</li>
</ul>

<h2>{t['h_cambios']}</h2>
<p>{t['cambios']}</p>
"""
    return _page(prefix, t["titulo"], body, lang, "/privacy")


# ----------------------------------------------------------------- términos



#: The interstitial, both languages. This is the page a stranger reads immediately
#: before granting super-admin access, so the English is held to the same standard
#: as the Spanish: plain words, no jargon, no urgency, and the way out named as
#: plainly as the way forward. The two strings Google puts on its own screens —
#: «Google hasn't verified this app» and the «Advanced» link — are quoted the way
#: Google writes them in English, because they are what the reader is about to see
#: and a translated button name is an instruction that does not match the screen.
_CONECTAR: dict[str, dict[Lang, str]] = {
    "titulo": {
        "es": "Antes de conectar tu Google Workspace",
        "en": "Before you connect your Google Workspace",
    },
    "entradilla": {
        "es": "Vigía revisa la seguridad de tu Google Workspace y te da un informe. Para "
        "hacerlo necesita <strong>leer</strong> la configuración de tu organización — y solo "
        "leerla. Esta página existe para que sepas exactamente qué va a pasar en la siguiente "
        "pantalla.",
        "en": "Vigía reviews the security of your Google Workspace and gives you a report. To "
        "do that it needs to <strong>read</strong> your organisation's configuration — and only "
        "to read it. This page exists so that you know exactly what is going to happen on the "
        "next screen.",
    },
    "aviso_titulo": {
        "es": "<strong>Google te va a mostrar un aviso, y es normal.</strong>",
        "en": "<strong>Google is going to show you a warning, and that is normal.</strong>",
    },
    "aviso_por_que": {
        "es": "Va a decir algo parecido a «Google no ha verificado esta aplicación». Aparece "
        "porque la verificación de Vigía está en curso: es un proceso de Google que tarda "
        "semanas y que consiste, entre otras cosas, en que una persona revise la política de "
        "privacidad y los permisos que se piden. Mientras dura, el aviso sale igual.",
        "en": "It will say something like 'Google hasn't verified this app'. It appears because "
        "Vigía's verification is under way: it is a Google process that takes weeks and "
        "consists, among other things, of a person reviewing the privacy policy and the "
        "permissions requested. While it lasts, the warning appears anyway.",
    },
    "aviso_no_dice": {
        "es": "<strong>Ese aviso no dice que la aplicación sea insegura.</strong> Dice que "
        "Google todavía no ha terminado de revisarla. Para continuar tendrás que pulsar en "
        "«Configuración avanzada» y luego en el enlace para continuar.",
        "en": "<strong>That warning does not say the application is unsafe.</strong> It says "
        "that Google has not finished reviewing it yet. To continue you will have to click "
        "'Advanced' and then the link to continue.",
    },
    "h_no_puede": {
        "es": "Lo que Vigía no puede hacer, ni pidiéndolo",
        "en": "What Vigía cannot do, even if it asked",
    },
    "compruebalo": {
        "es": "Esto es lo importante y lo puedes comprobar tú en la propia pantalla de Google, "
        "leyendo la lista de permisos antes de aceptar:",
        "en": "This is the important part, and you can check it yourself on Google's own "
        "screen, by reading the list of permissions before you accept:",
    },
    "no_correos": {
        "es": "No puede leer tus correos, ni sus asuntos, ni sus adjuntos.",
        "en": "It cannot read your e-mails, or their subjects, or their attachments.",
    },
    "no_drive": {
        "es": "No puede abrir ni descargar ningún archivo de Drive.",
        "en": "It cannot open or download any Drive file.",
    },
    "no_ajustes": {
        "es": "No puede cambiar ni un ajuste de tu organización: no existe ninguna vía de "
        "escritura en el código.",
        "en": "It cannot change a single setting in your organisation: there is no write path "
        "in the code.",
    },
    "no_suplantar": {
        "es": "No puede actuar en nombre de nadie ni enviar correo desde tus cuentas.",
        "en": "It cannot act on anybody's behalf or send e-mail from your accounts.",
    },
    "restringidos": {
        "es": "Los permisos que sí se piden son de solo lectura y ninguno pertenece a la "
        "categoría «restringida» de Google, que es precisamente la que daría acceso al "
        "contenido. Si en la pantalla de consentimiento ves algo que mencione el contenido de "
        "Gmail o de Drive, no continúes y escríbeme.",
        "en": "The permissions that are requested are read-only and none belongs to Google's "
        "'restricted' category, which is precisely the one that would give access to content. "
        "If on the consent screen you see anything that mentions the content of Gmail or of "
        "Drive, do not continue, and write to me.",
    },
    "h_que_se_hace": {
        "es": "Qué se hace con lo que se lee",
        "en": "What is done with what is read",
    },
    "se_calcula": {
        "es": "Se calcula tu informe y se guarda la puntuación y el estado de cada "
        "comprobación.",
        "en": "Your report is worked out, and the score and the state of each check are stored.",
    },
    "se_borran": {
        "es": "Las direcciones de correo de tu personal que aparezcan como afectadas se borran "
        "automáticamente a las <strong>{retention_hours} horas</strong>.",
        "en": "The e-mail addresses of your staff that appear as affected are deleted "
        "automatically after <strong>{retention_hours} hours</strong>.",
    },
    "al_desconectar": {
        "es": "Al desconectar se borra todo y se revoca el acceso en Google, en el momento.",
        "en": "When you disconnect, everything is deleted and access is revoked at Google, "
        "there and then.",
    },
    "continuar": {"es": "Continuar a Google", "en": "Continue to Google"},
    "prefiero_no": {
        "es": "Prefiero no conectar todavía",
        "en": "I would rather not connect yet",
    },
    "antes_de_seguir": {
        "es": "Antes de continuar puedes leer la <a href=\"{prefix}/privacy\">política de "
        "privacidad</a> y los <a href=\"{prefix}/terms\">términos</a>. Si tienes cualquier duda, "
        "o si quieres que te acompañe por teléfono mientras lo haces, escríbeme a "
        "<a href=\"mailto:{contact}\">{contact}</a> — contesto yo, no un formulario.",
        "en": "Before continuing you can read the <a href=\"{prefix}/privacy\">privacy "
        "policy</a> and the <a href=\"{prefix}/terms\">terms</a>. If you have any question, or "
        "if you would like me to walk you through it over the phone, write to me at "
        "<a href=\"mailto:{contact}\">{contact}</a> — I answer, not a form.",
    },
}


def connect_html(prefix: str, contact: str, retention_hours: int, lang: str = "es") -> str:
    """The page before Google's consent screen.

    Google shows "esta aplicación no ha sido verificada" until verification
    finishes, and a non-technical reader interprets that exactly as phishing —
    which it is reasonable of them to do, because that warning is what phishing
    looks like. Landing on it with no context is the point where a prospect
    stops, and no amount of report quality recovers a prospect who never
    connected.

    So the warning is named BEFORE they see it, and the argument that actually
    unlocks the consent is put next to it: the permissions requested cannot read
    a message or a file, and that is verifiable on the consent screen itself
    while they are standing on it.

    Written for the manager of a twenty-person agency, not for an
    administrator: no jargon, no urgency, and the way out is as visible as the
    way forward.
    """
    lang = _lang(lang)
    t = _textos(_CONECTAR, lang, retention_hours=retention_hours, prefix=prefix, contact=contact)
    barra = _textos(_SHELL, lang)   # the same nav labels as the other four pages
    return f"""<!doctype html>
<html lang="{lang}"{_tema_clase()}><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{t['titulo']} — Vigía</title>
<style>{font_faces(prefix)}
{_CSS}
.aviso {{ border-left: 4px solid var(--warn-line); background: var(--warn-bg);
          color: var(--ink); padding: 14px 18px; border-radius: 6px; margin: 22px 0 }}

.botones {{ display: flex; flex-wrap: wrap; gap: 12px; align-items: center;
            margin: 28px 0 12px }}
/* The app's primary button: beacon fill, ink text. 9.22:1, and the same shape a
   visitor just clicked on the landing page to get here. */
.principal {{ background: var(--beacon); color: var(--head); padding: 14px 26px;
              border-radius: 6px; text-decoration: none; font-weight: 600;
              display: inline-block; font-size: 15px }}
.principal:hover {{ background: #e7a92b }}
.secundario {{ color: var(--dim); text-decoration: none; padding: 14px 6px }}
.secundario:hover {{ color: var(--head); text-decoration: underline }}
</style></head>
<body>
<!-- The same ink bar as the dashboard and the legal pages. This page had none,
     which made the one screen where a visitor decides whether to trust Vigía the
     only screen that did not look like Vigía. It is not an escape hatch either:
     the page already offers "Prefiero no conectar todavía" further down. -->
<div class="top">
  <a href="{prefix}/">Vigía</a>
  <nav>
    <a href="{prefix}/privacy">{barra['privacidad']}</a>
    <a href="{prefix}/terms">{barra['terminos']}</a>
  </nav>
  {selector_idioma(prefix, lang, "/connect")}
</div>
<main>
  <h1>{t['titulo']}</h1>
  <p class="lead">{t['entradilla']}</p>

  <div class="aviso">
    <p>{t['aviso_titulo']}</p>
    <p>{t['aviso_por_que']}</p>
    <p>{t['aviso_no_dice']}</p>
  </div>

  <h2>{t['h_no_puede']}</h2>
  <p>{t['compruebalo']}</p>
  <!-- A padlock, in green, and the items stay in the negative. A green ✕ said two
       opposite things at once: the colour promised a guarantee and the symbol
       denied something. The list IS a guarantee, so the icon says "locked" and
       the sentence says what is locked. -->
  <ul class="marcada">
    <li>{CANDADO}<span>{t['no_correos']}</span></li>
    <li>{CANDADO}<span>{t['no_drive']}</span></li>
    <li>{CANDADO}<span>{t['no_ajustes']}</span></li>
    <li>{CANDADO}<span>{t['no_suplantar']}</span></li>
  </ul>
  <p>{t['restringidos']}</p>

  <h2>{t['h_que_se_hace']}</h2>
  <ul class="marcada">
    <li>{TIC}<span>{t['se_calcula']}</span></li>
    <li>{TIC}<span>{t['se_borran']}</span></li>
    <li>{TIC}<span>{t['al_desconectar']}</span></li>
  </ul>

  <div class="botones">
    <a class="principal" href="{prefix}/api/auth/google/start">{t['continuar']}</a>
    <a class="secundario" href="{prefix}/">{t['prefiero_no']}</a>
  </div>

  <p class="muted">{t['antes_de_seguir']}</p>
</main>
</body></html>"""

#: The terms, both languages. Every promise, every limit and every obligation is
#: the same sentence in both: what is not promised in Spanish (availability, an
#: audit, compliance) is not promised in English either, and the paragraph that
#: excludes liability excludes exactly as much and no more.
_TERMINOS: dict[str, dict[Lang, str]] = {
    "titulo": {"es": "Términos del servicio", "en": "Terms of service"},
    "sub": {
        "es": "Qué te ofrece Vigía, qué no te promete, y qué se espera de ti.",
        "en": "What Vigía offers you, what it does not promise you, and what is expected of "
        "you.",
    },
    "h_que_es": {"es": "Qué es Vigía", "en": "What Vigía is"},
    "que_es": {
        "es": "Vigía analiza la configuración de seguridad de un dominio de Google Workspace y "
        "de sus registros DNS públicos, y produce un informe con lo que conviene revisar. Lo "
        "opera {controller} a título personal.",
        "en": "Vigía analyses the security configuration of a Google Workspace domain and of "
        "its public DNS records, and produces a report with what is worth reviewing. It is "
        "operated by {controller} in a personal capacity.",
    },
    "h_necesitas": {
        "es": "Lo que necesitas para usarlo",
        "en": "What you need in order to use it",
    },
    "necesitas_admin": {
        "es": "Ser <strong>superadministrador</strong> del dominio que vas a analizar, o tener "
        "autorización expresa de quien lo sea. Analizar un dominio ajeno sin permiso no es un "
        "uso aceptable de este servicio.",
        "en": "Being a <strong>super administrator</strong> of the domain you are going to "
        "analyse, or having express authorisation from somebody who is. Analysing somebody "
        "else's domain without permission is not an acceptable use of this service.",
    },
    "necesitas_consentimiento": {
        "es": "Conectar la cuenta mediante el consentimiento de Google. Puedes retirarlo cuando "
        "quieras.",
        "en": "Connecting the account through Google's consent. You can withdraw it whenever "
        "you want.",
    },
    "h_no_promete": {"es": "Qué NO se promete", "en": "What is NOT promised"},
    "no_promete": {
        "es": "Vigía señala problemas de configuración detectables desde las API de lectura de "
        "Google y desde el DNS público. <strong>No es una auditoría de seguridad completa, ni "
        "una garantía de que tu organización esté segura, ni un certificado de cumplimiento "
        "normativo.</strong> Una puntuación alta significa que los controles comprobados están "
        "bien puestos, no que no existan otros riesgos.",
        "en": "Vigía points out configuration problems that are detectable from Google's read "
        "APIs and from public DNS. <strong>It is not a complete security audit, nor a "
        "guarantee that your organisation is secure, nor a certificate of regulatory "
        "compliance.</strong> A high score means that the controls that were checked are "
        "properly set, not that no other risks exist.",
    },
    # "no verificado" / "Not verified" is the status word the report prints, taken
    # from `locales/{es,en}.json` so the terms name the label the reader will see.
    "incertidumbre": {
        "es": "Cuando Vigía no puede comprobar algo con certeza, lo dice: lo marca como «no "
        "verificado» o te pide una comprobación manual, en lugar de darlo por bueno. Fiarse de "
        "un control que Vigía no ha podido verificar es un riesgo que asumes tú.",
        "en": "When Vigía cannot check something with certainty, it says so: it marks it as "
        "'Not verified' or asks you for a manual check, instead of taking it as fine. Relying "
        "on a control Vigía has not been able to verify is a risk you take on yourself.",
    },
    "h_disponibilidad": {"es": "Disponibilidad", "en": "Availability"},
    "disponibilidad": {
        "es": "El servicio se ofrece «tal cual» y sin compromiso de disponibilidad. Puede haber "
        "interrupciones por mantenimiento, por límites de las API de Google o por causas ajenas. "
        "El plan gratuito no incluye ningún acuerdo de nivel de servicio.",
        "en": "The service is offered 'as is' and with no availability commitment. There may be "
        "interruptions for maintenance, because of Google API limits or for reasons outside our "
        "control. The free plan includes no service level agreement.",
    },
    "h_uso_aceptable": {"es": "Uso aceptable", "en": "Acceptable use"},
    "prohibido_dominios": {
        "es": "Analizar dominios sobre los que no tienes autorización.",
        "en": "Analysing domains you are not authorised over.",
    },
    "prohibido_acceso": {
        "es": "Intentar acceder a los datos de otra organización, o eludir los controles de "
        "acceso.",
        "en": "Attempting to access another organisation's data, or to circumvent the access "
        "controls.",
    },
    "prohibido_ritmo": {
        "es": "Automatizar peticiones a un ritmo que degrade el servicio para el resto.",
        "en": "Automating requests at a rate that degrades the service for everybody else.",
    },
    "prohibido_atacar": {
        "es": "Usar los informes para atacar una organización en lugar de para protegerla.",
        "en": "Using the reports to attack an organisation instead of to protect it.",
    },
    "incumplimiento": {
        "es": "El incumplimiento puede suponer la suspensión inmediata del acceso.",
        "en": "Failure to comply may mean immediate suspension of access.",
    },
    "h_tus_datos": {"es": "Tus datos y tu contenido", "en": "Your data and your content"},
    "tus_datos": {
        "es": "Los datos de tu organización siguen siendo tuyos. Su tratamiento se rige por la "
        "<a href=\"{prefix}/privacy\">política de privacidad</a>, que forma parte de estos "
        "términos. Puedes borrarlo todo en cualquier momento desde "
        "<a href=\"{prefix}/help/data\">Tus datos</a>.",
        "en": "Your organisation's data remains yours. Its processing is governed by the "
        "<a href=\"{prefix}/privacy\">privacy policy</a>, which forms part of these terms. You "
        "can delete all of it at any time from <a href=\"{prefix}/help/data\">Your data</a>.",
    },
    "h_fin": {"es": "Fin del servicio", "en": "End of the service"},
    "fin": {
        "es": "Puedes dejar de usar Vigía cuando quieras pulsando «Desconectar», lo que borra "
        "tus datos y revoca el acceso. Si el servicio dejara de ofrecerse, se avisaría con "
        "antelación razonable a la dirección de administrador conectada, con tiempo para "
        "exportar tus informes.",
        "en": "You can stop using Vigía whenever you want by pressing 'Disconnect', which "
        "deletes your data and revokes access. If the service were to stop being offered, "
        "reasonable advance notice would be sent to the connected administrator address, with "
        "time to export your reports.",
    },
    "h_responsabilidad": {"es": "Responsabilidad", "en": "Liability"},
    "responsabilidad": {
        "es": "En la medida que permita la ley aplicable, {controller} no responde de daños "
        "indirectos derivados del uso del servicio, ni de decisiones tomadas a partir de un "
        "informe. Nada de lo anterior limita responsabilidades que la ley no permita excluir.",
        "en": "To the extent permitted by applicable law, {controller} is not liable for "
        "indirect damages arising from the use of the service, nor for decisions taken on the "
        "basis of a report. None of the above limits liabilities that the law does not permit "
        "to be excluded.",
    },
    "h_ley": {"es": "Ley aplicable y contacto", "en": "Governing law and contact"},
    "ley": {
        "es": "Estos términos se rigen por la legislación española, sin perjuicio de los "
        "derechos que te correspondan como consumidor en tu país de residencia. Para cualquier "
        "cuestión: {mailto}.",
        "en": "These terms are governed by Spanish law, without prejudice to the rights you "
        "have as a consumer in your country of residence. For any question: {mailto}.",
    },
}


def terms_html(prefix: str, contact: str, lang: str = "es") -> str:
    lang = _lang(lang)
    t = _textos(
        _TERMINOS,
        lang,
        mailto=_mailto(contact, lang),
        controller=CONTROLLER,
        prefix=prefix,
    )
    lead, claim = read_only_lead(lang), read_only_claim(lang)
    body = f"""
<h1>{t['titulo']}</h1>
<p class="sub">{t['sub']}</p>

<h2>{t['h_que_es']}</h2>
<p>{t['que_es']}</p>
<p><strong>{lead}</strong> {claim}</p>

<h2>{t['h_necesitas']}</h2>
<ul>
  <li>{t['necesitas_admin']}</li>
  <li>{t['necesitas_consentimiento']}</li>
</ul>

<h2>{t['h_no_promete']}</h2>
<div class="card">
  <p>{t['no_promete']}</p>
  <p>{t['incertidumbre']}</p>
</div>

<h2>{t['h_disponibilidad']}</h2>
<p>{t['disponibilidad']}</p>

<h2>{t['h_uso_aceptable']}</h2>
<ul class="no">
  <li>{t['prohibido_dominios']}</li>
  <li>{t['prohibido_acceso']}</li>
  <li>{t['prohibido_ritmo']}</li>
  <li>{t['prohibido_atacar']}</li>
</ul>
<p>{t['incumplimiento']}</p>

<h2>{t['h_tus_datos']}</h2>
<p>{t['tus_datos']}</p>

<h2>{t['h_fin']}</h2>
<p>{t['fin']}</p>

<h2>{t['h_responsabilidad']}</h2>
<p>{t['responsabilidad']}</p>

<h2>{t['h_ley']}</h2>
<p>{t['ley']}</p>
"""
    return _page(prefix, t["titulo"], body, lang, "/terms")


# --------------------------------------------------------- gestión de datos


#: How to see, export and delete everything — in both languages, because the
#: employee who did not consent to any of this is the reader least likely to share
#: the administrator's language.
_DATOS: dict[str, dict[Lang, str]] = {
    "titulo": {
        "es": "Tus datos: cómo verlos, exportarlos y borrarlos",
        "en": "Your data: how to see it, export it and delete it",
    },
    "titulo_corto": {"es": "Tus datos", "en": "Your data"},
    "sub": {
        "es": "Todo lo que Vigía guarda sobre ti, y cómo quitarlo sin pedir permiso a nadie.",
        "en": "Everything Vigía stores about you, and how to remove it without asking anybody's "
        "permission.",
    },
    "h_ver": {"es": "Ver lo que hay", "en": "Seeing what there is"},
    "ver": {
        "es": "Entra en el panel: el informe que ves es, literalmente, todo lo que Vigía sabe "
        "de tu organización. No hay ningún dato oculto que no aparezca en pantalla.",
        "en": "Go into the dashboard: the report you see is, literally, everything Vigía knows "
        "about your organisation. There is no hidden data that does not appear on screen.",
    },
    "h_exportar": {"es": "Exportarlo", "en": "Exporting it"},
    "exportar": {
        "es": "Desde el panel puedes descargar el informe en PDF (botón de imprimir) y en CSV. "
        "Ese CSV contiene todos los hallazgos con su estado y las cuentas afectadas, así que "
        "sirve como copia de tus datos en formato reutilizable.",
        "en": "From the dashboard you can download the report as a PDF (the print button) and "
        "as a CSV. That CSV contains every finding with its state and the affected accounts, so "
        "it works as a copy of your data in a reusable format.",
    },
    "h_borrar": {"es": "Borrarlo todo, ahora", "en": "Deleting everything, now"},
    "borrar": {
        "es": "<strong>Pulsa «Desconectar» en la cabecera de la aplicación.</strong> En ese "
        "mismo momento:",
        "en": "<strong>Press 'Disconnect' in the application's header.</strong> At that very "
        "moment:",
    },
    "borrar_oauth": {
        "es": "Se revoca la autorización OAuth contra Google.",
        "en": "The OAuth authorisation against Google is revoked.",
    },
    "borrar_token": {
        "es": "Se borra el token de refresco cifrado.",
        "en": "The encrypted refresh token is deleted.",
    },
    "borrar_org": {
        "es": "Se borra el registro de tu organización.",
        "en": "Your organisation's record is deleted.",
    },
    "borrar_escaneos": {
        "es": "Se borran <em>todos</em> tus escaneos y su historial, en cascada.",
        "en": "<em>All</em> your scans and their history are deleted, in cascade.",
    },
    "sin_vuelta": {
        "es": "No queda nada, no hay periodo de gracia y no hay copia de seguridad de la que se "
        "pueda restaurar. Si vuelves a conectar, empiezas de cero.",
        "en": "Nothing is left, there is no grace period and there is no backup anything could "
        "be restored from. If you connect again, you start from scratch.",
    },
    "h_retirar": {
        "es": "Retirar el acceso desde Google",
        "en": "Removing access from Google",
    },
    "retirar": {
        "es": "También puedes cortar por tu lado, sin entrar en Vigía, desde "
        "<a href=\"https://myaccount.google.com/permissions\" rel=\"noreferrer\">"
        "myaccount.google.com/permissions</a>: busca Vigía y quita el acceso. A partir de ese "
        "momento Vigía no puede leer nada más de tu Workspace.",
        "en": "You can also cut it off from your side, without going into Vigía, from "
        "<a href=\"https://myaccount.google.com/permissions\" rel=\"noreferrer\">"
        "myaccount.google.com/permissions</a>: look for Vigía and remove access. From that "
        "moment on, Vigía cannot read anything else from your Workspace.",
    },
    "retirar_ojo": {
        "es": "Ojo a la diferencia: retirar el acceso en Google <em>corta la lectura</em>, pero "
        "lo que ya estuviera guardado sigue en la base de datos hasta que pulses «Desconectar» "
        "o lo pidas por correo. Si quieres las dos cosas, haz las dos.",
        "en": "Mind the difference: removing access at Google <em>stops the reading</em>, but "
        "whatever was already stored stays in the database until you press 'Disconnect' or ask "
        "for it by e-mail. If you want both things, do both.",
    },
    "h_solo": {"es": "Lo que se borra solo", "en": "What is deleted on its own"},
    "solo": {
        "es": "Las direcciones de correo de las personas de tu organización que aparecen en un "
        "informe se borran automáticamente <strong>{retention_hours} horas</strong> después del "
        "escaneo, sin que tengas que hacer nada. Lo que queda es cuántas cuentas estaban "
        "afectadas por cada hallazgo, nunca quiénes.",
        "en": "The e-mail addresses of the people in your organisation that appear in a report "
        "are deleted automatically <strong>{retention_hours} hours</strong> after the scan, "
        "without you having to do anything. What is left is how many accounts were affected by "
        "each finding, never who they were.",
    },
    "h_empleado": {
        "es": "Si eres empleado o empleada, no administrador",
        "en": "If you are an employee, not an administrator",
    },
    "empleado": {
        "es": "Puede que tu dirección aparezca en un informe de tu organización sin que tú hayas "
        "usado Vigía nunca. En ese caso:",
        "en": "Your address may appear in a report of your organisation without you ever having "
        "used Vigía. In that case:",
    },
    "empleado_responsable": {
        "es": "La responsable de esos datos es <strong>tu organización</strong>, que es quien "
        "encargó el informe; Vigía solo los procesa por su cuenta.",
        "en": "The controller of that data is <strong>your organisation</strong>, which is who "
        "commissioned the report; Vigía only processes it on their behalf.",
    },
    "empleado_plazo": {
        "es": "Tu dirección desaparece por sí sola a las {retention_hours} horas.",
        "en": "Your address disappears on its own after {retention_hours} hours.",
    },
    "empleado_antes": {
        "es": "Si quieres que se borre antes, o saber qué hay sobre ti, escribe a {mailto} y se "
        "atenderá. Se te pedirá que confirmes tu dirección, y se avisará al administrador de tu "
        "organización, porque es quien decide sobre esos datos.",
        "en": "If you want it deleted sooner, or want to know what there is about you, write to "
        "{mailto} and it will be dealt with. You will be asked to confirm your address, and "
        "your organisation's administrator will be told, because they are the one who decides "
        "about that data.",
    },
    "h_otra_cosa": {"es": "Cualquier otra cosa", "en": "Anything else"},
    "otra_cosa": {
        "es": "Escribe a {mailto}. Respuesta en un mes como máximo, normalmente mucho antes.",
        "en": "Write to {mailto}. An answer within one month at most, normally much sooner.",
    },
}


def data_help_html(prefix: str, contact: str, retention_hours: int, lang: str = "es") -> str:
    lang = _lang(lang)
    t = _textos(
        _DATOS,
        lang,
        retention_hours=retention_hours,
        mailto=_mailto(contact, lang),
    )
    body = f"""
<h1>{t['titulo']}</h1>
<p class="sub">{t['sub']}</p>

<h2>{t['h_ver']}</h2>
<p>{t['ver']}</p>

<h2>{t['h_exportar']}</h2>
<p>{t['exportar']}</p>

<h2>{t['h_borrar']}</h2>
<div class="card">
  <p>{t['borrar']}</p>
  <ul>
    <li>{t['borrar_oauth']}</li>
    <li>{t['borrar_token']}</li>
    <li>{t['borrar_org']}</li>
    <li>{t['borrar_escaneos']}</li>
  </ul>
  <p>{t['sin_vuelta']}</p>
</div>

<h2>{t['h_retirar']}</h2>
<p>{t['retirar']}</p>
<p class="muted">{t['retirar_ojo']}</p>

<h2>{t['h_solo']}</h2>
<p>{t['solo']}</p>

<h2>{t['h_empleado']}</h2>
<p>{t['empleado']}</p>
<ul>
  <li>{t['empleado_responsable']}</li>
  <li>{t['empleado_plazo']}</li>
  <li>{t['empleado_antes']}</li>
</ul>

<h2>{t['h_otra_cosa']}</h2>
<p>{t['otra_cosa']}</p>
"""
    return _page(prefix, t["titulo_corto"], body, lang, "/help/data")


#: The 404. Short, and still bilingual: it is reachable from a mistyped link in
#: either language, and it is the page that has to prove the service is not broken.
_NO_ENCONTRADA: dict[str, dict[Lang, str]] = {
    "titulo": {"es": "Página no encontrada", "en": "Page not found"},
    "h1": {"es": "Esta página no existe", "en": "This page does not exist"},
    "sub": {
        "es": "Error 404. No es un fallo del servicio: la dirección no corresponde a ninguna "
        "página.",
        "en": "Error 404. It is not a service failure: the address does not correspond to any "
        "page.",
    },
    "salidas": {
        "es": "Desde aquí puedes ir a <a href=\"{prefix}/\">la página principal</a>, al "
        "<a href=\"{prefix}/dmarc-checker\">comprobador de SPF, DKIM y DMARC</a> —que no "
        "necesita conectar nada— o a la <a href=\"{prefix}/privacy\">política de "
        "privacidad</a>.",
        "en": "From here you can go to <a href=\"{prefix}/\">the home page</a>, to the "
        "<a href=\"{prefix}/dmarc-checker\">SPF, DKIM and DMARC checker</a> —which does not "
        "need to connect anything— or to the <a href=\"{prefix}/privacy\">privacy policy</a>.",
    },
    "enlace_roto": {
        "es": "Si has llegado desde un enlace nuestro que está roto, avísanos y lo arreglamos.",
        "en": "If you got here from a broken link of ours, tell us and we will fix it.",
    },
}


def not_found_html(prefix: str, lang: str = "es") -> str:
    lang = _lang(lang)
    t = _textos(_NO_ENCONTRADA, lang, prefix=prefix)
    body = f"""
<h1>{t['h1']}</h1>
<p class="sub">{t['sub']}</p>
<p>{t['salidas']}</p>
<p class="muted">{t['enlace_roto']}</p>
"""
    return _page(prefix, t["titulo"], body, lang, _ruta_actual())


def stamp() -> str:
    return date.today().isoformat()


# --------------------------------------------------------------------------- #
# The homepage a reader without JavaScript sees.
#
# It lives here, in Python, and not in `index.html` where it used to, for the
# same reason the legal pages do: it has to exist in two languages, and prose
# written into a static file can only ever have one. Flask substitutes it into
# `#root`, and React replaces the whole thing the moment it mounts — so this is
# the version served to a reader with scripts off, to a text browser, and to
# Google's OAuth brand verifier, which fetches the homepage WITHOUT running
# JavaScript. Verification was rejected twice on findings that were both the
# empty `<div id="root">` this replaces.
#
# Three constraints, each learned the hard way:
#
# * **Inline styles only.** The stylesheet is a relative URL and the inline
#   `<base href>` never runs either, so a `<link>` would not load.
# * **Absolute links.** Same reason: `href="privacy"` would resolve against `/`
#   and hand the reviewer a 404 where the policy should be. Flask is the only
#   party that knows the mount prefix without running a script.
# * **The `<h1>` is `Vigía` in both languages** and must stay byte-identical to
#   the consent screen's "App name" field, accent included, or the mismatch
#   finding comes back. It is a proper noun, so this costs the translation
#   nothing.
#
# The Spanish page keeps a short English echo of the purpose statement, because
# the reviewers who read it work mostly in English and the finding to clear is
# precisely "no se explica el propósito". The English page does not echo it back
# in Spanish: there the main statement is already English, and a duplicate
# paragraph would be noise rather than help.
# --------------------------------------------------------------------------- #

_PORTADA: dict[str, dict[Lang, str]] = {
    "kicker": {
        "es": "Aplicación web · Google Workspace · solo lectura",
        "en": "Web application · Google Workspace · read-only",
    },
    "proposito": {
        "es": "Vigía es una aplicación web que revisa la configuración de seguridad de un "
        "dominio de Google Workspace en modo solo lectura y entrega un informe con lo que "
        "conviene arreglar, ordenado por prioridad.",
        "en": "Vigía is a web application that reviews the security configuration of a Google "
        "Workspace domain in read-only mode and delivers a report of what should be fixed, "
        "ordered by priority.",
    },
    "operador": {
        "es": "La administra {controller} a título personal. El análisis es gratuito y se puede "
        "repetir cuando quieras. Vigía no modifica ningún ajuste de tu Workspace: no existe "
        "ninguna ruta en el programa capaz de escribir en tu organización.",
        "en": "It is run by {controller} in a personal capacity. The analysis is free and you "
        "can repeat it whenever you like. Vigía does not modify any setting in your Workspace: "
        "there is no route in the program capable of writing to your organisation.",
    },
    "h_que_hace": {"es": "Qué hace", "en": "What it does"},
    "hace_tenant": {
        "es": "Comprueba unos 50 controles de postura del tenant contra el "
        "<em>CIS Google Workspace Benchmark</em>: administradores sin verificación en dos "
        "pasos, aplicaciones OAuth de terceros con permisos peligrosos, cuentas dormidas, "
        "reenvío automático de correo, ajustes de compartición de Drive y política de "
        "contraseñas, entre otros.",
        "en": "It checks around 50 posture controls of the tenant against the "
        "<em>CIS Google Workspace Benchmark</em>: administrators without 2-Step Verification, "
        "third-party OAuth applications with dangerous permissions, dormant accounts, "
        "automatic mail forwarding, Drive sharing settings and password policy, among others.",
    },
    "hace_dns": {
        "es": "Revisa en el DNS público la autenticación de correo del dominio: SPF, DKIM, "
        "DMARC y MTA-STS.",
        "en": "It reviews the domain's email authentication in public DNS: SPF, DKIM, DMARC "
        "and MTA-STS.",
    },
    "hace_informe": {
        "es": "Calcula una puntuación de postura y una lista de arreglos priorizada, con "
        "informe descargable en PDF y CSV. Cuando algo no se puede verificar con certeza, lo "
        "marca como no verificado en lugar de darlo por bueno.",
        "en": "It works out a posture score and a prioritised list of fixes, with a report "
        "downloadable as PDF and CSV. When something cannot be verified with certainty, it is "
        "marked as not verified rather than assumed to be fine.",
    },
    "h_permisos": {
        "es": "Qué permisos pide y para qué",
        "en": "What permissions it asks for, and what for",
    },
    "sin_contenido": {
        "es": "<strong>Vigía nunca solicita acceso al contenido de Gmail, de Drive, del "
        "calendario ni de ningún otro dato personal</strong>, y no puede leer tus correos, sus "
        "asuntos, sus adjuntos ni tus archivos. Puedes retirar el acceso cuando quieras, lo "
        "que borra tus datos.",
        "en": "<strong>Vigía never requests access to the contents of Gmail, of Drive, of the "
        "calendar or of any other personal data</strong>, and it cannot read your messages, "
        "their subjects, their attachments or your files. You can withdraw access whenever you "
        "like, which deletes your data.",
    },
    "h_entrar": {"es": "Entrar y saber más", "en": "Get started and find out more"},
    "enlace_conectar": {
        "es": "Conectar tu Google Workspace",
        "en": "Connect your Google Workspace",
    },
    "enlace_dmarc": {
        "es": "Comprobador de SPF, DKIM y DMARC",
        "en": "SPF, DKIM and DMARC checker",
    },
    "dmarc_nota": {
        "es": " — libre, sin conectar nada.",
        "en": " — free, without connecting anything.",
    },
    "enlace_demo": {"es": "Ver un informe de ejemplo", "en": "See a sample report"},
    "enlace_privacidad": {
        "es": "Política de privacidad y permisos",
        "en": "Privacy policy and permissions",
    },
    "enlace_terminos": {"es": "Condiciones del servicio", "en": "Terms of service"},
    "enlace_datos": {
        "es": "Tus datos: ver, exportar y borrar",
        "en": "Your data: view, export and delete",
    },
    "contacto": {"es": "Contacto:", "en": "Contact:"},
}

#: The English echo shown on the Spanish page only. Not a `_PORTADA` entry with an
#: empty English side, because an empty string in a bilingual table reads as a
#: missing translation and the parity test would be right to complain.
_PORTADA_ECO_EN = _PORTADA["proposito"]["en"]


def portada_sin_js(prefix: str, contact_email: str, lang: str = "es") -> str:
    """The `#root` body for a reader without JavaScript, in one language."""
    lang = _lang(lang)
    t = _textos(_PORTADA, lang, controller=CONTROLLER)

    eco = (
        f'<p lang="en" style="margin: 0.75rem 0 0; font-size: 0.9375rem; '
        f'font-style: italic; color: #8fa6b5">{_PORTADA_ECO_EN}</p>'
        if lang == "es"
        else ""
    )
    # The links carry no `?lang=`, on purpose. Seeing this page with an explicit
    # `?lang=` sets the `vigia_lang` cookie (`_remember_lang`, an after_request on
    # the whole app), and every one of these destinations reads that cookie — a
    # clean `/privacy` after `/?lang=en` renders English, verified. So the
    # parameter would add nothing, and it would cost something: the privacy and
    # terms URLs are the exact strings registered on Google's consent screen, and
    # they are worth linking to unchanged.
    a = 'style="color: #f2b63c"'
    return f"""<main style="min-height: 100vh; margin: 0; padding: 3rem 1.25rem 4rem; background: #0d1f2d; font-family: ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif; line-height: 1.65; color: #c3d3de">
        <div style="max-width: 46rem; margin: 0 auto">
        <p style="margin: 0; display: flex; justify-content: space-between; gap: 1rem; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.75rem; font-weight: 600; letter-spacing: 0.18em; text-transform: uppercase; color: #f2b63c">
          <span>{t['kicker']}</span>
          {selector_idioma(prefix, lang, '/')}
        </p>

        <h1 style="margin: 0.75rem 0 0; font-size: 2.5rem; line-height: 1.1; color: #ffffff">
          Vigía
        </h1>

        <p style="margin: 1.25rem 0 0; font-size: 1.125rem"><strong>{t['proposito']}</strong></p>
        {eco}

        <p style="margin: 1rem 0 0">{t['operador']}</p>

        <h2 style="margin: 2.25rem 0 0; font-size: 1.25rem; color: #ffffff">{t['h_que_hace']}</h2>
        <ul style="margin: 0.75rem 0 0; padding-left: 1.25rem">
          <li>{t['hace_tenant']}</li>
          <li>{t['hace_dns']}</li>
          <li>{t['hace_informe']}</li>
        </ul>

        <h2 style="margin: 2.25rem 0 0; font-size: 1.25rem; color: #ffffff">{t['h_permisos']}</h2>
        <p style="margin: 0.75rem 0 0">{scopes.resumen_permisos(lang)}</p>
        <ul style="margin: 0.75rem 0 0; padding-left: 1.25rem">
{scopes.lista_items(lang)}
        </ul>
        <p style="margin: 1rem 0 0">{t['sin_contenido']}</p>

        <h2 style="margin: 2.25rem 0 0; font-size: 1.25rem; color: #ffffff">{t['h_entrar']}</h2>
        <ul style="margin: 0.75rem 0 0; padding-left: 1.25rem">
          <li><a href="{prefix}/connect" {a}>{t['enlace_conectar']}</a></li>
          <li><a href="{prefix}/dmarc-checker" {a}>{t['enlace_dmarc']}</a>{t['dmarc_nota']}</li>
          <li><a href="{prefix}/demo" {a}>{t['enlace_demo']}</a></li>
          <li><a href="{prefix}/privacy" {a}>{t['enlace_privacidad']}</a></li>
          <li><a href="{prefix}/terms" {a}>{t['enlace_terminos']}</a></li>
          <li><a href="{prefix}/help/data" {a}>{t['enlace_datos']}</a></li>
        </ul>

        <p style="margin: 2.25rem 0 0; font-size: 0.9375rem; color: #8fa6b5">
          {t['contacto']}
          <a href="mailto:{contact_email}" {a}>{contact_email}</a>
        </p>
        </div>
      </main>"""
