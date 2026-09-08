"""Post-scan coherence checks: a report must never contradict itself.

Two classes of contradiction have reached production before, and both are
worse than a missing finding because they destroy trust in everything else
on the page:

1. **Population overlap.** The same account reported as a super admin and
   as a delegated admin. Those sets are disjoint by definition.
2. **Broken implication.** A specific finding fails while the broader
   finding that describes a superset of the same accounts passes — e.g.
   "Super admin with no 2FA that has never signed in: FAIL" next to
   "Super admin without 2-Step Verification: PASS". The second statement
   is simply false.

The implications between composite rules are derived from their signal
sets rather than hand-listed, so a new rule is covered the moment it is
added. Composite→atomic implications are declared explicitly because they
cross module boundaries.
"""
from __future__ import annotations

from ..wording import con_numero

import re

from ..scoring import INVENTORY_FINDINGS
from .composite import RULES

OPEN_STATUSES = ("fail", "warn")

# Findings whose accounts are super admins, and findings whose accounts are
# delegated admins. No account may appear on both sides.
SUPER_ADMIN_FINDINGS = frozenset(
    {
        "super-admin-count",
        "composite-superadmin-dormant-no-2sv",
        "composite-superadmin-no-2sv",
        "composite-superadmin-dormant",
        "composite-superadmin-no-2sv-no-recovery",
        "recovery-super-admins",
    }
)
DELEGATED_ADMIN_FINDINGS = frozenset({"2sv-delegated-admins", "delegated-admins"})

# INVENTORY_FINDINGS comes from the scorer: one definition, shared, because the
# scorer must not let those findings escalate anybody either.

# Signal implications: holding the key implies holding the values too.
# An account that has never signed in is, by definition, inactive.
SIGNAL_IMPLIES = {"never_signed_in": {"inactive"}}

# (specific, broader) pairs that cross modules: if the specific finding is
# open, the broader one describes a superset of those accounts and cannot
# report a clean pass.
CROSS_MODULE_IMPLICATIONS: tuple[tuple[str, str], ...] = (
    ("composite-superadmin-no-2sv", "2sv-users"),
    ("composite-dormant-no-2sv", "2sv-users"),
    ("composite-service-account-no-2sv", "2sv-users"),
    ("composite-superadmin-dormant-no-2sv", "2sv-users"),
    ("2sv-delegated-admins", "2sv-users"),
)


def _rule_finding_id(rule_id: str) -> str:
    return f"composite-{rule_id.lower().replace('_', '-')}"


def _closure(signals: frozenset[str] | set[str]) -> set[str]:
    """Signals held, plus everything they imply."""
    result = set(signals)
    for signal in signals:
        result |= SIGNAL_IMPLIES.get(signal, set())
    return result


def derived_implications() -> list[tuple[str, str]]:
    """Composite→composite pairs, computed from the rules themselves.

    If rule A's signals (with implications applied) are a superset of rule
    B's, then A's accounts are a subset of B's, so A being open forces B to
    be open too.
    """
    pairs: list[tuple[str, str]] = []
    for specific in RULES:
        for broader in RULES:
            if specific.id == broader.id:
                continue
            if _closure(specific.signals) > set(broader.signals):
                pairs.append((_rule_finding_id(specific.id), _rule_finding_id(broader.id)))
    return pairs


def all_implications() -> list[tuple[str, str]]:
    return derived_implications() + list(CROSS_MODULE_IMPLICATIONS)


def _as_dict(finding) -> dict:
    return finding if isinstance(finding, dict) else finding.to_dict()


def _listed_accounts(finding: dict) -> list[str]:
    """Every address the reader can see on this finding.

    Both fields are inspected on purpose: `accounts` drives the score, but
    `affected_items` is what the report actually prints, and the overlap
    reported in production was visible there. `affected_items` is capped with
    a "… y N más" marker, so only real addresses are kept.
    """
    seen: list[str] = []
    for field in ("accounts", "affected_items"):
        for item in finding.get(field) or []:
            if isinstance(item, str) and "@" in item and item not in seen:
                seen.append(item)
    return seen


from ..scoring import is_inventory as _is_inventory, is_org_scope as _is_org_scope

_ADDRESS = re.compile(r"[\w.+-]+@[\w.-]+\.\w+")


def check_consistency(findings: list) -> list[str]:
    """Human-readable violations. Empty list means the report is coherent."""
    data = [_as_dict(f) for f in findings]
    by_id = {f.get("id"): f for f in data}
    violations: list[str] = []

    # 1) super admins and delegated admins are disjoint populations
    super_accounts: dict[str, str] = {}
    for finding_id in SUPER_ADMIN_FINDINGS:
        for account in _listed_accounts(by_id.get(finding_id, {})):
            super_accounts.setdefault(account, finding_id)
    for finding_id in DELEGATED_ADMIN_FINDINGS:
        for account in _listed_accounts(by_id.get(finding_id, {})):
            if account in super_accounts:
                violations.append(
                    f"{account} aparece como superadministrador en "
                    f"«{super_accounts[account]}» y como administrador delegado en "
                    f"«{finding_id}»; los dos conjuntos son disjuntos."
                )

    # 2) a specific finding cannot fail while its broader finding passes
    for specific_id, broader_id in all_implications():
        specific = by_id.get(specific_id)
        broader = by_id.get(broader_id)
        if not specific or not broader:
            continue
        if specific.get("status") in OPEN_STATUSES and broader.get("status") == "pass":
            violations.append(
                f"«{specific_id}» está en {specific['status']} mientras «{broader_id}» "
                "informa de «correcto», pero describe un superconjunto de las mismas "
                "cuentas: una de las dos afirmaciones es falsa."
            )

    # 3) outside declared inventories, a finding that names accounts cannot
    #    claim to pass — that combination means the status was computed from
    #    something other than the list it is showing.
    for finding in data:
        if finding.get("id") in INVENTORY_FINDINGS:
            continue
        if finding.get("status") == "pass" and finding.get("accounts"):
            violations.append(
                f"«{finding['id']}» informa de «correcto» pero lista "
                f"{con_numero(len(finding['accounts']), "cuenta afectada", "cuentas afectadas")}."
            )

    # 5) every person an account-scope finding names must reach the summary
    #
    # `people_at_risk` and the score table are built from `accounts`; the card
    # the reader sees is built from `affected_items`. When a check fills the
    # second and only part of the first, somebody is accused on one page and
    # absent from the next — which happened with the backup-codes check, where
    # only the administrators went into `accounts` and the other four people
    # existed on the card and nowhere else.
    for finding in data:
        if finding.get("manual") or finding.get("status") not in ("fail", "warn"):
            continue
        if _is_org_scope(finding) or _is_inventory(finding):
            continue
        nombrados = set()
        for item in finding.get("affected_items") or []:
            nombrados |= set(_ADDRESS.findall(str(item)))
        fuera = nombrados - set(finding.get("accounts") or [])
        if fuera:
            violations.append(
                f"{finding.get('id')} nombra a {con_numero(len(fuera), "cuenta")} en su lista visible "
                f"que no están en `accounts`, así que no llegan ni a «personas en riesgo» "
                f"ni a la tabla de puntuación: {', '.join(sorted(fuera)[:3])}"
                + ("…" if len(fuera) > 3 else "")
            )

    return violations
