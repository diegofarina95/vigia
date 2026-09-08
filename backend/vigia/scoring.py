"""Posture score, 0-100, and the auditable breakdown behind it.

Methodology (shown in the UI and the report, and reproducible from the
findings JSON alone):

* Severity weights: critical 10, high 6, medium 3, low 1, info 0.
* Status credit: pass 100%, warn 50%, fail 0%.
* **Each affected account is counted once**, at the worst severity it
  appears under. Without this, one person who is a super admin, has no
  2SV and has never signed in would be punished three or four times over
  — once per finding they show up in — and composite findings would
  double-count by construction.
* Findings whose scope is the ORGANIZATION (DNS, Admin console settings,
  audit log, third-party apps) contribute **once each**. A console toggle is
  one decision by one administrator, not one failure per employee: counting
  it per head made a single setting weigh seventeen times in a seventeen-
  person tenant and buried everything else.
* The per-account block is capped so it never outweighs the organization
  block (``PEOPLE_BLOCK_CEILING``). Otherwise the settings become rounding
  error in a large tenant purely because it has more staff.
* ``undetermined``, ``info`` and manual checks are EXCLUDED. Uncertainty
  never counts for or against the score, so a heuristic that could not
  confirm something can never move the number.
* score = round(100 * earned / total); ``None`` when nothing is scorable.
"""
from __future__ import annotations

from .checks.finding import ORG_SCOPE, Finding

#: What a score MEANS, in one place.
#:
#: Five bands, not four. The old set had a single 65–84 band labelled "requiere
#: atención", which put a well-run domain scoring 79 in the same box as a mediocre
#: one scoring 65, and then jumped straight to "postura sólida" six points later.
#: A customer reading 79 was told to pay attention with no hint that they were
#: nearly there.
#:
#: The thresholds were also written TWICE — here as colours in `report.py` and again
#: as labels in `ScoreGauge.tsx`. They agreed by luck. A panel and the PDF the
#: customer forwards to their manager disagreeing about the same number is the
#: failure this consolidation prevents; `test_bandas_puntuacion.py` keeps the
#: frontend copy honest.
#:
#: Descending, and the last entry is the floor. The label is a KEY: the words live
#: in the locale catalogue so the report reads in the language it was asked for.
SCORE_BANDS: tuple[tuple[int, str], ...] = (
    (85, "solid"),
    (72, "good"),
    (58, "attention"),
    (40, "risk"),
    (0, "exposed"),
)

#: Colour per band. Measured on the report's white paper, where the score is set
#: large: `good` is a darker green than `solid` on purpose, because the mid-greens
#: that read well on screen fall under 4.5:1 on print — the same trap that made
#: `ok #2f8f63` unusable as text earlier.
SCORE_BAND_COLORS: dict[str, str] = {
    "solid": "#2f8f63",
    "good": "#4a7d2e",
    "attention": "#b98a1d",
    "risk": "#cf6f33",
    "exposed": "#b93a48",
    "undetermined": "#5c7183",
}


def score_band(score: int | None) -> str:
    """The band a score falls in, as a key. `None` is not a band, it is unknown."""
    if score is None:
        return "undetermined"
    for minimo, clave in SCORE_BANDS:
        if score >= minimo:
            return clave
    return SCORE_BANDS[-1][1]


SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 10,
    "high": 6,
    "medium": 3,
    "low": 1,
    "info": 0,
}

#: Findings that name accounts as an INVENTORY, not as a problem with those
#: people. "Six super admins" is a fact about the organization's shape; it is
#: not six personal failures, and it must never push anybody up to critical or
#: add a bullet to their row. The finding still scores at organization level.
INVENTORY_FINDINGS = frozenset(
    {"super-admin-count", "delegated-admins", "admin-login-countries"}
)


def is_org_scope(finding) -> bool:
    """Organization-level, from the finding's own declaration.

    Scans stored before the field existed have no `scope_type`; those fall
    back to the old rule (names accounts → about accounts) so a historical
    scan keeps rendering the number it was given. It is not comparable to a
    new one anyway — the engine fingerprint already says so.
    """
    data = _as_dict(finding)
    declared = data.get("scope_type")
    if declared:
        return declared == ORG_SCOPE
    return not data.get("accounts")


def is_inventory(finding) -> bool:
    return _as_dict(finding).get("id") in INVENTORY_FINDINGS


STATUS_CREDIT: dict[str, float] = {
    "pass": 1.0,
    "warn": 0.5,
    "fail": 0.0,
}

OPEN_STATUSES = ("fail", "warn")

#: How much the per-account block may weigh relative to the organization
#: block, at most. 1.0 means "never more than the settings" — the two halves
#: of posture, configuration and population hygiene, stay comparable whatever
#: the headcount. Raise it to let people dominate, lower it to let settings.
PEOPLE_BLOCK_CEILING = 1.0


def _as_dict(finding) -> dict:
    """Accept both Finding objects and the dicts stored in the DB."""
    return finding.to_dict() if isinstance(finding, Finding) else finding


def is_scorable(finding) -> bool:
    data = _as_dict(finding)
    return (
        not data.get("manual")
        and data.get("status") in STATUS_CREDIT
        and SEVERITY_WEIGHTS.get(data.get("severity"), 0) > 0
    )


def _weight(severity: str) -> int:
    return SEVERITY_WEIGHTS.get(severity, 0)


def score_breakdown(findings: list) -> dict:
    """Deterministic, line-by-line derivation of the score.

    Returns account rows (one per person, at their worst severity),
    finding rows (org-level and passing controls) and the excluded list,
    so a client can audit the number instead of taking it on trust.
    """
    scorable = [_as_dict(f) for f in findings if is_scorable(f)]
    excluded = [
        {
            "id": _as_dict(f).get("id"),
            "severity": _as_dict(f).get("severity"),
            "status": _as_dict(f).get("status"),
            "reason": (
                "comprobación manual"
                if _as_dict(f).get("manual")
                else "no se ha podido determinar"
                if _as_dict(f).get("status") == "undetermined"
                else "solo informativo"
            ),
        }
        for f in findings
        if not is_scorable(f)
    ]

    # Split: open findings that name accounts are scored per account; the
    # rest (org-level, and passing controls, which name nobody) per finding.
    per_account_findings = [
        f
        for f in scorable
        if not is_org_scope(f)
        and f.get("accounts")
        and f["status"] in OPEN_STATUSES
        and not is_inventory(f)
    ]
    per_finding = [f for f in scorable if f not in per_account_findings]

    # Worst-severity attribution, deterministic: highest weight wins, and on
    # a tie the lowest credit (the more damning status) wins.
    worst: dict[str, dict] = {}
    also_in: dict[str, list[str]] = {}
    for finding in per_account_findings:
        weight = _weight(finding["severity"])
        credit = STATUS_CREDIT[finding["status"]]
        for account in finding["accounts"]:
            also_in.setdefault(account, []).append(finding["id"])
            current = worst.get(account)
            if (
                current is None
                or weight > current["weight"]
                or (weight == current["weight"] and credit < current["credit"])
            ):
                worst[account] = {
                    "account": account,
                    "severity": finding["severity"],
                    "status": finding["status"],
                    "finding_id": finding["id"],
                    "weight": weight,
                    "credit": credit,
                }

    account_rows = []
    for account in sorted(worst):
        row = dict(worst[account])
        row["earned"] = row["weight"] * row["credit"]
        row["also_in"] = sorted(set(also_in[account]) - {row["finding_id"]})
        account_rows.append(row)

    finding_rows = [
        {
            "id": f["id"],
            "title": f.get("title", ""),
            "severity": f["severity"],
            "status": f["status"],
            "weight": _weight(f["severity"]),
            "earned": _weight(f["severity"]) * STATUS_CREDIT[f["status"]],
        }
        for f in per_finding
    ]

    # The people block must not drown the settings block. Its size grows with
    # headcount — 500 affected people in a 2 000-seat tenant is 3 000 points
    # against a settings block that stays around 130 — so without a ceiling a
    # large company could leave every console setting wide open and still
    # score well, because the toggles would be 4% of the number. The cap keeps
    # the two comparable at worst 50/50 and changes nothing for the small
    # tenants where the people block is already the smaller of the two.
    org_weight = sum(r["weight"] for r in finding_rows)
    people_weight = sum(r["weight"] for r in account_rows)
    scale = 1.0
    if org_weight and people_weight > org_weight * PEOPLE_BLOCK_CEILING:
        scale = org_weight * PEOPLE_BLOCK_CEILING / people_weight
        for row in account_rows:
            row["weight"] *= scale
            row["earned"] *= scale
            row["scaled_by"] = round(scale, 4)

    total = sum(r["weight"] for r in account_rows) + org_weight
    earned = sum(r["earned"] for r in account_rows) + sum(r["earned"] for r in finding_rows)
    score = None if total == 0 else round(100 * earned / total)

    return {
        "score": score,
        "people_scale": round(scale, 4),
        "people_weight": sum(r["weight"] for r in account_rows),
        "org_weight": org_weight,
        "total_weight": total,
        "earned_weight": earned,
        "lost_weight": total - earned,
        "accounts": account_rows,
        "findings": finding_rows,
        "excluded": excluded,
        "weights": dict(SEVERITY_WEIGHTS),
        "credits": dict(STATUS_CREDIT),
    }


def compute_score(findings: list) -> int | None:
    return score_breakdown(findings)["score"]


def severity_counts(findings: list) -> dict[str, int]:
    """Open findings (fail or warn) per severity — the report headline."""
    counts = {sev: 0 for sev in SEVERITY_WEIGHTS}
    for finding in findings:
        data = _as_dict(finding)
        if not data.get("manual") and data.get("status") in OPEN_STATUSES:
            counts[data["severity"]] += 1
    return counts


def people_at_risk(findings: list) -> list[dict]:
    """One row per account that appears in an open finding, worst severity
    first. Single source of truth for the dashboard panel, the report and
    the headline sentence, so they can never disagree.
    """
    people: dict[str, dict] = {}
    for finding in findings:
        data = _as_dict(finding)
        if data.get("manual") or data.get("status") not in OPEN_STATUSES:
            continue
        if _weight(data.get("severity", "info")) == 0:
            continue
        # An inventory lists people without accusing them of anything, and an
        # organization setting is nobody's personal failing.
        if is_inventory(data) or is_org_scope(data):
            continue
        for account in data.get("accounts") or []:
            entry = people.setdefault(
                account, {"account": account, "issues": [], "weight": 0, "worst": "low"}
            )
            entry["issues"].append(
                {
                    "id": data["id"],
                    "title": data.get("title", ""),
                    "severity": data["severity"],
                }
            )
            entry["weight"] += _weight(data["severity"])
            if _weight(data["severity"]) > _weight(entry["worst"]):
                entry["worst"] = data["severity"]

    return sorted(
        people.values(),
        key=lambda p: (-_weight(p["worst"]), -len(p["issues"]), p["account"]),
    )
