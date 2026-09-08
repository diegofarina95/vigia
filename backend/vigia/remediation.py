"""The finding→action graph, and the "Fix this first" ranking.

Identifiers stay English; the sentences live in the locale catalogue, under
`remediation.<action id>`, so an action reads in the language the reader asked
for. Nothing user-facing is written here as a literal any more: what is left in
this module is what is not language — how long the action takes, which console
URL it opens, and which findings it closes.

A report that only says what is wrong makes the reader do the triage. This
module answers the next question: of everything available, which single
action buys the most safety for the least time?

Impact is *derived*, never written down: for each action we take the open
findings that declare it, then recompute the score with those findings
resolved. That way the numbers cannot drift away from the findings.

The console paths deliberately keep Google's own spelling in each language —
"Organizational unit", "Authenticate email" — because the reader is following
them with the console open, and a path that has been corrected into British
English is a path that is not on screen.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from .i18n import DEFAULT_LANG, SUPPORTED_LANGS, text
from .scoring import SEVERITY_WEIGHTS, compute_score

OPEN_STATUSES = ("fail", "warn")


@dataclass(frozen=True)
class Action:
    id: str
    title: str  # imperative, one sentence
    console_path: str  # exact Admin console route, as the console spells it
    console_url: str
    minutes: int
    # Set when applying this breaks something for end users.
    user_impact: str | None = None


#: id, console URL, minutes, and whether the catalogue carries a user-impact
#: warning for it. The three text fields are looked up by id, so adding an
#: action means adding a row here and an entry to `REMEDIATION` in
#: `scripts/build_locales.py` — a row without its entry shows up as a visible
#: catalogue path rather than as an empty card.
_ACTIONS: tuple[tuple[str, str, int, bool], ...] = (
    ("enforce_2sv_org", "https://admin.google.com/ac/security/2sv", 15, True),
    ("suspend_unused_admins", "https://admin.google.com/ac/users", 10, False),
    ("suspend_never_used", "https://admin.google.com/ac/users", 10, False),
    ("suspend_dormant", "https://admin.google.com/ac/users", 20, True),
    ("replace_shared_accounts", "https://admin.google.com/ac/groups", 30, True),
    ("reduce_super_admins", "https://admin.google.com/ac/roles", 20, True),
    ("reset_compromised_accounts", "https://admin.google.com/ac/users", 15, True),
    ("restrict_app_access", "https://admin.google.com/ac/owl/list?tab=apps", 25, True),
    ("review_dwd", "https://admin.google.com/ac/owl/domainwidedelegation", 15, True),
    ("publish_spf", "https://admin.google.com/ac/apps/gmail/authenticateemail", 15, True),
    ("enable_dkim", "https://admin.google.com/ac/apps/gmail/authenticateemail", 15, False),
    ("publish_dmarc", "https://admin.google.com/ac/apps/gmail/authenticateemail", 10, True),
    ("publish_mta_sts", "https://admin.google.com/ac/apps/gmail", 30, True),
    ("publish_tls_rpt", "https://admin.google.com/ac/apps/gmail", 5, False),
    ("enable_dnssec", "https://admin.google.com/ac/apps/gmail", 20, True),
    ("restrict_drive_sharing", "https://admin.google.com/ac/appsettings/55656082996", 10, True),
    ("disable_auto_forwarding", "https://admin.google.com/ac/apps/gmail/enduseraccess", 5, True),
    ("strengthen_password_policy", "https://admin.google.com/ac/security/passwordmanagement", 10, True),
    ("set_session_limit", "https://admin.google.com/ac/security/session", 10, True),
    ("restrict_marketplace", "https://admin.google.com/ac/appslist/marketplace", 10, True),
    ("restrict_groups_external", "https://admin.google.com/ac/appsettings/553547912911", 10, True),
    ("delete_suspended", "https://admin.google.com/ac/users", 20, True),
)


@lru_cache(maxsize=len(SUPPORTED_LANGS) + 1)
def _catalog(lang: str) -> dict[str, Action]:
    return {
        action_id: Action(
            id=action_id,
            title=text(lang, f"remediation.{action_id}.title"),
            console_path=text(lang, f"remediation.{action_id}.console_path"),
            console_url=url,
            minutes=minutes,
            user_impact=text(lang, f"remediation.{action_id}.user_impact") if impact else None,
        )
        for action_id, url, minutes, impact in _ACTIONS
    }


def catalog(lang: str = DEFAULT_LANG) -> dict[str, Action]:
    """The action catalogue in one language. Read-only: it is cached and shared."""
    return _catalog(lang if lang in SUPPORTED_LANGS else DEFAULT_LANG)


#: The Spanish catalogue, kept as a module constant for the callers that had it
#: before there was a second language.
CATALOG: dict[str, Action] = catalog(DEFAULT_LANG)


def _as_dict(finding) -> dict:
    return finding if isinstance(finding, dict) else finding.to_dict()


def _resolved_copy(findings: list[dict], closing_ids: set[str]) -> list[dict]:
    """The same findings with the closable ones marked resolved, so the score
    can be recomputed to measure the gain."""
    simulated = []
    for finding in findings:
        if finding["id"] in closing_ids:
            clone = dict(finding)
            clone["status"] = "pass"
            clone["accounts"] = []  # nobody is exposed by it any more
            simulated.append(clone)
        else:
            simulated.append(finding)
    return simulated


def rank_actions(findings: list, limit: int = 3, lang: str = DEFAULT_LANG) -> list[dict]:
    """Highest-leverage actions first: findings closed per minute of work."""
    data = [_as_dict(f) for f in findings]
    baseline = compute_score(data)
    acciones = catalog(lang)

    by_action: dict[str, list[dict]] = {}
    for finding in data:
        if finding.get("status") not in OPEN_STATUSES or finding.get("manual"):
            continue
        for action_id in finding.get("remediation_actions") or []:
            if action_id in acciones:
                by_action.setdefault(action_id, []).append(finding)

    ranked: list[dict] = []
    for action_id, closes in by_action.items():
        action = acciones[action_id]
        closing_ids = {f["id"] for f in closes}
        accounts = {a for f in closes for a in (f.get("accounts") or [])}

        simulated_score = compute_score(_resolved_copy(data, closing_ids))
        score_gain = (
            0
            if baseline is None or simulated_score is None
            else max(0, simulated_score - baseline)
        )

        severities = [f["severity"] for f in closes]
        ranked.append(
            {
                "id": action_id,
                "title": action.title,
                "console_path": action.console_path,
                "console_url": action.console_url,
                "minutes": action.minutes,
                "user_impact": action.user_impact,
                "findings_closed": len(closes),
                "criticals_closed": severities.count("critical"),
                "highs_closed": severities.count("high"),
                "accounts_affected": len(accounts),
                "score_gain": score_gain,
                "finding_ids": sorted(closing_ids),
                "finding_titles": [f.get("title", "") for f in closes],
                # Ranking key, surfaced so the ordering is auditable too.
                "leverage": round(len(closes) / action.minutes, 4),
            }
        )

    # Findings closed per minute of effort — not raw severity, because the
    # point of this block is what to do first, not what is scariest.
    ranked.sort(
        key=lambda a: (
            -a["leverage"],
            -a["criticals_closed"],
            -a["score_gain"],
            a["minutes"],
        )
    )
    return ranked[:limit]


def localize_actions(actions: list[dict], lang: str) -> list[dict]:
    """Ranked actions with their sentences re-read in `lang`, by action id.

    The same trick `i18n` uses on findings, and for the same reason: the ranking
    is computed once, at scan time, and stored as rendered text. Translating on
    the way out means a scan taken months ago reads in whatever language is asked
    for today, with no re-scan. The derived numbers (`minutes`, `score_gain`,
    `findings_closed`…) are not touched, and an id that is not in the catalogue
    keeps the text the scan stored rather than losing it.
    """
    acciones = catalog(lang)
    localized = []
    for action in actions or []:
        entry = acciones.get(action.get("id", ""))
        if entry is None:
            localized.append(dict(action))
            continue
        traducida = {**action, "title": entry.title, "console_path": entry.console_path}
        # The warning is translated only when the stored action carried one:
        # adding one invents a consequence, dropping one hides it.
        if action.get("user_impact") and entry.user_impact:
            traducida["user_impact"] = entry.user_impact
        localized.append(traducida)
    return localized


def severity_weight_note() -> str:
    return ", ".join(f"{sev} {w}" for sev, w in SEVERITY_WEIGHTS.items() if w)
