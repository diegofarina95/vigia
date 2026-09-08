"""Localisation of report content, keyed by finding id.

Why keyed by *id* and applied at render time, rather than at scan time:

A scan is stored as rendered text (title, description, remediation…). That
means a scan taken before a wording or language change keeps the old text
for ever — which is exactly the bug this module fixes. Because the finding
`id` is stable and already present in every stored scan, the id can act as
the translation key: we translate on the way *out*, so old scans render in
the language and wording that are current today, with no re-scan and
without rewriting history in the database.

Fallback chain, in order, so a missing key can never surface to a user:

    requested language → English → the text the scan stored → (never a key)

The CIS control identifiers are deliberately NOT translated: only the
descriptive part after the dash is. "CIS GWS §4 (Drive)" is the official
name of the control and has to stay quotable.
"""
from __future__ import annotations

from .wording import con_numero

import json
import logging
import os
from functools import lru_cache

log = logging.getLogger(__name__)

DEFAULT_LANG = "es"
FALLBACK_LANG = "en"
SUPPORTED_LANGS = ("es", "en")

_LOCALE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "locales")

# Fields on a Finding that come from the catalogue. `description` is handled
# separately because it needs interpolation.
_STATIC_FIELDS = (
    ("title", "title"),
    ("remediation", "remediation"),
    ("cis_control", "cis"),
    ("scope_label", "scope"),
)


def normalize_lang(raw: str | None) -> str:
    """Map anything user-supplied to a supported language, defaulting to es."""
    if not raw:
        return DEFAULT_LANG
    # Accept "es", "es-ES", "ES", "en-GB,en;q=0.9"…
    primary = raw.split(",")[0].strip().lower().replace("_", "-").split("-")[0]
    return primary if primary in SUPPORTED_LANGS else DEFAULT_LANG


@lru_cache(maxsize=len(SUPPORTED_LANGS) + 1)
def catalog(lang: str) -> dict:
    path = os.path.join(_LOCALE_DIR, f"{lang}.json")
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        log.warning("could not load locale %s: %s", lang, exc)
        return {}


def _lookup(lang: str, *path: str):
    """Nested catalogue lookup with the language→English fallback."""
    for candidate in (lang, FALLBACK_LANG):
        node = catalog(candidate)
        for step in path:
            if not isinstance(node, dict) or step not in node:
                node = None
                break
            node = node[step]
        if node not in (None, "", []):
            return node
    return None


def text(lang: str, ruta: str, **params) -> str:
    """One user-facing sentence, from the catalogue, in the language asked for.

    THE convention for backend strings. Everything that a customer reads — the
    report's chrome, the DNS verdicts, the remediation catalogue, the e-mails, the
    legal pages — goes through here instead of being written as an f-string at the
    point of use. Two reasons:

     · An f-string cannot have a second language. Every Spanish sentence written
       inline is a surface that can never answer in English, and there were 261 of
       them.
     · Placeholders survive translation. `"{selector} tiene {bits} bits"` and
       `"{selector} has {bits} bits"` are the same template with the same names, so
       the two languages cannot drift into taking different arguments.

    `ruta` is dotted: `text(lang, "dns.dkim.encontrada", selector="zoho2")`.
    Missing keys fall back to English and then to the path itself, so a gap shows up
    as a visible key rather than as a crash in front of a customer.
    """
    plantilla = _lookup(lang, *ruta.split("."))
    if not isinstance(plantilla, str):
        return ruta
    try:
        return plantilla.format(**params) if params else plantilla
    except (KeyError, IndexError):
        # A template asking for a parameter the caller did not pass. Returning the
        # raw template beats raising inside a report that is already rendering.
        log.warning("plantilla %s: faltan parámetros %s", ruta, sorted(params))
        return plantilla


def severity_label(lang: str, severity: str) -> str:
    return _lookup(lang, "severity", severity) or severity


def status_label(lang: str, status: str) -> str:
    return _lookup(lang, "status", status) or status


def _describe(lang: str, finding: dict) -> str | None:
    """Interpolated description, or None to keep whatever the scan stored.

    Old scans carry no ``i18n_params``, so their description cannot be
    rebuilt; the caller keeps the stored text rather than showing a
    template with braces in it.
    """
    variant = finding.get("i18n_variant") or ""
    key = f"description_{variant}" if variant else "description"
    template = _lookup(lang, "findings", finding.get("id", ""), key)
    if template is None and variant:
        template = _lookup(lang, "findings", finding.get("id", ""), "description")
    if not isinstance(template, str):
        return None

    # A template needing values an old scan never stored falls back to the
    # stored description rather than leaking braces to the reader.
    return _safe_format(template, _params(lang, finding))


# Values a template may need that older scans recorded under `details`
# instead of `i18n_params`. Recovering them there means a scan stored before
# the locale existed still renders fully, instead of falling back to its
# original wording.
_DERIVABLE = {
    "days": lambda d: d.get("dormant_days"),
    "domains": lambda d: len(d["domains"]) if isinstance(d.get("domains"), dict) else None,
    "count": lambda d: d.get("count"),
    "threshold": lambda d: d.get("threshold"),
    "total": lambda d: d.get("total_active_users"),
    "without": lambda d: d.get("without_2sv"),
    "apps_seen": lambda d: d.get("apps_seen"),
}


def _params(lang: str, finding: dict) -> dict:
    """The finding's template values, with status keys localised."""
    params = dict(finding.get("i18n_params") or {})

    details = finding.get("details") or {}
    if isinstance(details, dict):
        for name, extract in _DERIVABLE.items():
            if name in params:
                continue
            try:
                value = extract(details)
            except (TypeError, KeyError):
                value = None
            if value is not None:
                params[name] = value
    # A param naming a status carries the raw key ("fail"), so the sentence
    # reads in the requested language instead of the scan's language.
    for key, value in list(params.items()):
        if key.endswith("_status") and isinstance(value, str):
            params[key] = status_label(lang, value)
    return params


def _safe_format(template: str, params: dict) -> str | None:
    """Interpolate, or None if the template needs a value we do not have.

    Some titles carry the threshold that was applied ("…en {days}+ días").
    A scan stored before ``i18n_params`` existed has no values for those, and
    a title reading "{days}" is worse than the old wording — so the caller
    keeps whatever the scan stored instead.
    """
    if "{" not in template:
        return template
    try:
        return template.format(**params)
    except (KeyError, IndexError, ValueError):
        return None


def localize_finding(finding: dict, lang: str) -> dict:
    """A copy of the finding with its catalogue text applied.

    `observed_value` is deliberately untouched: it is a measurement of the
    customer's tenant, not a sentence about it, and the catalogue has no
    business overwriting "Periodo de gracia: {con_numero(14, 'día')}".
    """
    localized = dict(finding)
    finding_id = finding.get("id", "")
    params = _params(lang, finding)

    for field, key in _STATIC_FIELDS:
        value = _lookup(lang, "findings", finding_id, key)
        if isinstance(value, str) and value:
            rendered = _safe_format(value, params)
            if rendered:
                localized[field] = rendered

    description = _describe(lang, finding)
    if description:
        localized["description"] = description

    return localized


def localize_manual_check(check: dict, lang: str) -> dict:
    localized = dict(check)
    check_id = check.get("id", "")
    for field, key in (
        ("title", "title"),
        ("area", "area"),
        ("why_manual", "why_manual"),
        ("cis_control", "cis"),
    ):
        value = _lookup(lang, "manual", check_id, key)
        if isinstance(value, str) and value:
            localized[field] = value
    steps = _lookup(lang, "manual", check_id, "instructions")
    if isinstance(steps, list) and steps:
        localized["instructions"] = list(steps)
    return localized


def _title_map(findings: list[dict]) -> dict[str, str]:
    return {f["id"]: f["title"] for f in findings if f.get("id")}


def localize_payload(payload: dict, lang: str) -> dict:
    """Localise a whole dashboard/report payload in place-ish (returns a copy).

    Titles are duplicated across the delta, the ranked actions, the
    people-at-risk rows and the score breakdown; all of those carry the
    finding id, so they are re-derived from the localised findings instead
    of being translated twice.
    """
    result = dict(payload)
    scan = payload.get("scan")
    if not scan:
        return result

    localized_scan = dict(scan)
    localized_scan["findings"] = [
        localize_finding(f, lang) for f in scan.get("findings", [])
    ]
    localized_scan["manual_checks"] = [
        localize_manual_check(m, lang) for m in scan.get("manual_checks", [])
    ]

    titles = _title_map(localized_scan["findings"])

    # The stored evaluated result carries its own copy of the breakdown, and it was
    # the one surface nothing translated: `localize_payload` handled a *top-level*
    # `breakdown`, but `projection.project` reads the breakdown out of
    # `scan["result"]`, computed once at scan time in the language of the scan. The
    # English dashboard was showing "La 2FA es obligatoria para esta cuenta y aun
    # así entra sin ella" in the score panel. Re-derived from the localised
    # findings by id, like every other duplicated title here, so a scan taken
    # months ago reads in whatever language is asked for today.
    stored = scan.get("result")
    if isinstance(stored, dict) and isinstance(stored.get("breakdown"), dict):
        desglose = stored["breakdown"]
        localized_scan["result"] = {
            **stored,
            "breakdown": {
                **desglose,
                "findings": [
                    {**row, "title": titles.get(row.get("id", ""), row.get("title", ""))}
                    for row in desglose.get("findings", [])
                ],
            },
        }

    result["scan"] = localized_scan

    def retitle(entries):
        return [
            {**entry, "title": titles.get(entry.get("id", ""), entry.get("title", ""))}
            for entry in entries or []
        ]

    delta = payload.get("delta")
    if delta:
        result["delta"] = {
            **delta,
            **{key: retitle(delta.get(key)) for key in ("new", "worse", "improved", "resolved")},
        }

    actions = payload.get("actions")
    if actions:
        # Two different translations, and both are needed. `finding_titles` come
        # from the localised findings; the action's OWN title, console path and
        # user impact come from the remediation catalogue by action id — they are
        # stored as rendered text at scan time, so without this the English report
        # printed "Suspende o quita privilegios a las cuentas de administrador…"
        # over an otherwise English fix list.
        from .remediation import localize_actions

        result["actions"] = [
            {
                **action,
                "finding_titles": [
                    titles.get(fid, fid) for fid in action.get("finding_ids", [])
                ],
            }
            for action in localize_actions(actions, lang)
        ]

    people = payload.get("people_at_risk")
    if people:
        result["people_at_risk"] = [
            {**person, "issues": retitle(person.get("issues"))} for person in people
        ]

    breakdown = payload.get("breakdown")
    if breakdown:
        result["breakdown"] = {
            **breakdown,
            "findings": [
                {**row, "title": titles.get(row.get("id", ""), row.get("title", ""))}
                for row in breakdown.get("findings", [])
            ],
        }

    return result
