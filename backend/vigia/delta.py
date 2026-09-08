"""Change tracking between two scans.

Two different things move a verdict between two scans, and this module used to
treat them as one:

* **the tenant's exposure changed** — somebody enforced 2SV, somebody lost their
  recovery phone. This is what the customer pays to be told.
* **what we could look at changed** — a scope granted or revoked, a 429 from
  Google, an incremental read reaching further back than last time. The exposure
  is identical; our visibility is not.

`undetermined` is not a severity sitting between `pass` and `warn`. It belongs to
the other axis: whether we know. Ranking it on the badness scale produced two
false statements, and the second is the expensive one:

* `undetermined → pass` fell into "got better" and came out as **resolved**, so
  the alert congratulated the customer for fixing something we had merely started
  being able to read. Measured on 3 August: `suspended-with-tokens`,
  `oauth-widely-granted` and `oauth-high-risk` entered the score when the
  incremental token read went live, the denominator went 238 → 257, and the
  e-mail announced two of them as resolved. Nothing had been resolved.
* `pass → undetermined` fell into "got worse" and came out as **new**. Revoke a
  scope, or take a single 429 from Google, and a monitoring product mails its
  customer about a problem that does not exist. For a watchman, false alarms cost
  trust faster than silence does.

So the scale below covers verdicts only, transitions into and out of
`undetermined` are their own category with their own two directions, and neither
direction raises a security alert. Losing visibility is worth reporting — under
its own name, never mixed into the findings.
"""
from __future__ import annotations

#: How bad each *verdict* is. `undetermined` is deliberately absent: it is not a
#: degree of badness, and a dict that ranks it is a dict that will eventually
#: subtract it from something.
BADNESS = {"pass": 0, "warn": 1, "fail": 2}

UNDETERMINED = "undetermined"

OPEN_STATUSES = ("fail", "warn")

#: Labels that mean "our visibility moved", never "the tenant moved". Named, so
#: every consumer can ask the question instead of hard-coding the two strings and
#: then missing a third one later.
COVERAGE_CHANGES = ("coverage_gained", "coverage_lost")

#: Labels that mean the tenant's exposure got worse — the only ones that may
#: raise an alert.
ALERTING_CHANGES = ("new", "worse")


def _badness(status: str) -> int:
    """Only verdicts have a badness.

    Asking for `undetermined`'s is precisely the bug this module was rewritten to
    remove, so it now fails loudly instead of answering 1.
    """
    if status == UNDETERMINED:
        raise ValueError(
            "undetermined no está en la escala de gravedad: pertenece a la otra "
            "dimensión, la de si sabemos o no. Clasifícalo como cambio de cobertura."
        )
    return BADNESS[status]


def _severity_weight(severity: str | None) -> int:
    """Severity order taken from the scorer rather than restated here.

    A second ordering in this file would drift from the one that computes the
    number, and then "worse" and "the score went down" would disagree.
    """
    from .scoring import SEVERITY_WEIGHTS

    return SEVERITY_WEIGHTS.get(severity or "", 0)


def _affected(finding: dict) -> int | None:
    """How many things this finding is about, or None when it counted nothing.

    Accounts first, because "3 people without 2SV" is the number the customer
    recognises; `affected_items` covers the findings whose subject is not a
    person. None means "this scan did not count", which is not zero and must not
    be compared as if it were.
    """
    accounts = finding.get("accounts") or []
    if accounts:
        return len(accounts)
    items = finding.get("affected_items") or []
    if items:
        return len(items)
    return None


def _classify(old: dict | None, now: dict) -> tuple[str, dict]:
    """(label, detail) for one finding. The whole decision, in one place."""
    status = now["status"]

    if old is None:
        # A check id with no predecessor. Two scans from different engines are
        # never compared, so reaching here means the check set is the same and
        # this id is new *data*, not a new check.
        if status == UNDETERMINED:
            return "same", {}
        return ("new" if status in OPEN_STATUSES else "same"), {}

    was = old.get("status")
    was_unknown = was == UNDETERMINED
    now_unknown = status == UNDETERMINED

    if was_unknown and now_unknown:
        return "same", {}
    if was_unknown:
        # "Antes no se podía comprobar; ahora sí, y el resultado es X." The
        # result travels with the label so the reader is told which X, and
        # `open` so an issue that has just become visible can get its own
        # sentence without being filed as a new problem in the tenant.
        return "coverage_gained", {"to_status": status, "open": status in OPEN_STATUSES}
    if now_unknown:
        return "coverage_lost", {"from_status": was}

    # Both sides are verdicts, so the badness scale applies.
    now_bad, was_bad = _badness(status), _badness(was)
    if now_bad > was_bad:
        return ("new" if was_bad == 0 else "worse"), {"from_status": was, "to_status": status}
    if now_bad < was_bad:
        return ("resolved" if status == "pass" else "improved"), {
            "from_status": was,
            "to_status": status,
        }

    # Same verdict — and this is where a moving score used to hide, because the
    # comparison stopped here and reported `same` for all 50 rows while the
    # number moved. Severity and headcount move the score too, so they are part
    # of the comparison now.
    sev_was = _severity_weight(old.get("severity"))
    sev_now = _severity_weight(now.get("severity"))
    if sev_now != sev_was:
        detail = {"from_severity": old.get("severity"), "to_severity": now.get("severity")}
        if (now.get("details") or {}).get("regression"):
            # A regression escalates severity at scan time. Say so: a control
            # that broke again is a change in the tenant, not drift.
            detail["regression"] = True
        return ("worse" if sev_now > sev_was else "improved"), detail

    was_n, now_n = _affected(old), _affected(now)
    if was_n is not None and now_n is not None and now_n != was_n:
        return (
            "worse" if now_n > was_n else "improved",
            {"from_count": was_n, "to_count": now_n},
        )

    return "same", {}


def annotate_changes(current: list[dict], previous: list[dict] | None) -> dict:
    """Adds a ``change`` key to each finding in ``current`` and returns a
    summary. ``change`` is one of:

    * ``new``             — an open issue that did not exist (or was passing) before
    * ``worse``          — exposure degraded: worse verdict, higher severity, or
                           more people affected
    * ``improved``       — the same three, the other way, still not passing
    * ``resolved``       — was an open issue, now passes
    * ``coverage_gained``— could not be checked before, can be now. NOT
                           ``resolved``: nothing in the tenant moved.
    * ``coverage_lost``  — could be checked before, cannot be now. NOT ``new``
                           and NOT ``worse``.
    * ``same``           — no change
    * ``baseline``       — there is no previous scan to compare against
    """
    summary: dict = {
        "has_baseline": previous is not None,
        "new": [],
        "worse": [],
        "improved": [],
        "resolved": [],
        "coverage_gained": [],
        "coverage_lost": [],
    }
    if previous is None:
        for finding in current:
            finding["change"] = "baseline"
        return summary

    before = {f["id"]: f for f in previous}
    for finding in current:
        label, detail = _classify(before.get(finding["id"]), finding)
        finding["change"] = label
        if detail:
            # Kept on the finding too, so a dashboard row can say "de 3 a 8"
            # without its renderer having to look the entry up in the summary.
            finding["change_detail"] = detail
        if label in summary:
            entry = {
                "id": finding["id"],
                "title": finding.get("title", ""),
                "severity": finding.get("severity", "info"),
            }
            entry.update(detail)
            summary[label].append(entry)
    return summary


_ESCALATION = {"low": "medium", "medium": "high", "high": "critical", "critical": "critical"}


def detect_regressions(findings: list, previous: list[dict] | None, history: list[list[dict]]) -> list[str]:
    """Mark findings that were fixed and have come back.

    A control that keeps flipping back is worse than one that was never set:
    it means the change did not stick, so it gets escalated one severity
    level. This runs at SCAN time, before scoring, so the stored score always
    matches the severities shown — the score stays reproducible from the JSON.

    Returns the ids escalated.
    """
    if previous is None:
        return []

    was_passing = {f["id"] for f in previous if f.get("status") == "pass"}
    # Any earlier scan where the finding was an open issue.
    previously_open = {
        f["id"]
        for scan_findings in history
        for f in scan_findings
        if f.get("status") in OPEN_STATUSES
    }

    escalated: list[str] = []
    for finding in findings:
        if (
            finding.status in OPEN_STATUSES
            and finding.id in was_passing
            and finding.id in previously_open
        ):
            finding.details = dict(finding.details or {})
            finding.details["regression"] = True
            finding.details["severity_before_regression"] = finding.severity
            bumped = _ESCALATION[finding.severity] if finding.severity in _ESCALATION else finding.severity
            if bumped != finding.severity:
                finding.severity = bumped
            finding.description = (
                "**Regresión:** esto ya se había resuelto y ha vuelto a aparecer. Un control que "
                "no se mantiene es peor que uno que nunca se aplicó, así que su severidad se ha "
                f"elevado a {finding.severity}.\n\n" + (finding.description or "")
            )
            escalated.append(finding.id)
    return escalated


# --------------------------------------------- why the number moved, by cause

#: Said out loud rather than shown as a bare number, for the scans stored before
#: the audit breakdown existed.
NO_DECOMPOSITION = (
    "No se puede separar cuánto del cambio es de tu organización y cuánto de lo que "
    "Vigía pudo comprobar, porque uno de los dos escaneos se guardó sin el desglose."
)


def _scored_items(breakdown: dict) -> dict[str, dict]:
    """`key -> {weight, earned}` for everything that entered the denominator.

    Accounts and findings share one namespace, prefixed, so intersecting two
    scans cannot collide a person named `2sv-users` with the check of that name.
    """
    items: dict[str, dict] = {}
    for row in breakdown.get("accounts") or []:
        items[f"account:{row.get('account')}"] = {
            "weight": float(row.get("weight") or 0),
            "earned": float(row.get("earned") or 0),
        }
    for row in breakdown.get("findings") or []:
        items[f"finding:{row.get('id')}"] = {
            "weight": float(row.get("weight") or 0),
            "earned": float(row.get("earned") or 0),
        }
    return items


def explain_score(current: dict | None, previous: dict | None) -> dict:
    """Split the score's movement into the part the tenant caused and the part
    our own coverage caused.

    This is the answer to the denominator problem, and it is deliberately *not*
    "put the denominator in the engine fingerprint". The fingerprint measures the
    engine, and on 3 August the engine did not change: 238 → 257 happened because
    three findings left `undetermined` and entered the calculation. That is
    coverage, and the fingerprint was right not to move.

    What was missing is the decomposition. The score is recomputed for both scans
    over the **items scored in both**, which cancels everything only one of them
    could see; whatever is left is the tenant::

        35 (antes 33)
          +2 porque ahora se pueden comprobar 3 cosas más
           0 por cambios en tu organización

    A severity escalated by `detect_regressions` sits on a common item, so it
    lands in the exposure component — correct, because a control that broke again
    is a real change in the tenant and not drift in what we can see.

    Known limitation, stated rather than hidden: `people_scale` rescales the
    account block when headcount grows, which moves the weight of common items
    and therefore reads as exposure. It is 1.0 for every tenant small enough for
    that cap not to bite.
    """
    now_break, before_break = current or {}, previous or {}
    score_now, score_before = now_break.get("score"), before_break.get("score")

    out: dict = {
        "score": score_now,
        "previous_score": score_before,
        "total": None,
        "exposure": None,
        "coverage": None,
        "gained": [],
        "lost": [],
        "common": 0,
        "reason": "",
    }
    if score_now is None or score_before is None:
        out["reason"] = NO_DECOMPOSITION
        return out

    out["total"] = score_now - score_before

    now_items, before_items = _scored_items(now_break), _scored_items(before_break)
    if not now_items or not before_items:
        out["reason"] = NO_DECOMPOSITION
        return out

    common = set(now_items) & set(before_items)
    out["gained"] = sorted(set(now_items) - set(before_items))
    out["lost"] = sorted(set(before_items) - set(now_items))
    out["common"] = len(common)

    weight_now = sum(now_items[k]["weight"] for k in common)
    weight_before = sum(before_items[k]["weight"] for k in common)
    if not weight_now or not weight_before:
        out["reason"] = NO_DECOMPOSITION
        return out

    earned_now = sum(now_items[k]["earned"] for k in common)
    earned_before = sum(before_items[k]["earned"] for k in common)
    out["exposure"] = round(100 * earned_now / weight_now) - round(
        100 * earned_before / weight_before
    )
    out["coverage"] = out["total"] - out["exposure"]
    return out


def alert_worthy(summary: dict, score: int | None, previous_score: int | None) -> bool:
    """True when a scheduled scan found something worth e-mailing about.

    Only the tenant can trigger this. A coverage change never reaches the
    conditions below, and the score drop is read from the **exposure** component
    rather than the raw difference — otherwise one 429 from Google, or a revoked
    scope, sends a paying customer an alert about a problem that does not exist.
    That failure mode is worse than a missed notification: it teaches the customer
    to ignore the product.
    """
    summary = summary or {}
    if any(summary.get(label) for label in ALERTING_CHANGES):
        return True

    explanation = summary.get("score_change") or {}
    exposure = explanation.get("exposure")
    if exposure is not None:
        return exposure < 0

    # No decomposition available (one side stored before the breakdown existed).
    if score is not None and previous_score is not None and score < previous_score:
        return True
    return False


def coverage_worthy(summary: dict) -> bool:
    """True when visibility moved. Its own question, for its own notice, never
    folded into `alert_worthy`."""
    summary = summary or {}
    return any(summary.get(label) for label in COVERAGE_CHANGES)


# --------------------------------------------------- the one gate, one place

NO_COMPARABLE = (
    "El conjunto de comprobaciones cambió entre este escaneo y el anterior, así que las "
    "dos puntuaciones no son comparables y no se calcula la diferencia."
)


def _breakdown(scan: dict | None) -> dict | None:
    return ((scan or {}).get("result") or {}).get("breakdown")


def gated_summary(scan: dict, previous: dict | None) -> tuple[int | None, dict]:
    """(previous_score, summary) — refusing to compare across engine versions.

    This lived inside the dashboard route, so the scheduled e-mail did not pass
    through it: `jobs.py` called `annotate_changes` directly and mailed the
    customer "1 new CRITICAL finding · 50/100 (−30 since the last scan)" for the
    very same stored row the dashboard was describing as "not comparable".
    Verified by execution before this function existed.

    A gate that one of two callers can walk around is not a gate. There is one
    implementation, every caller uses it, and `tests/test_delta_gate.py` fails if
    a new caller reaches past it.
    """
    from .engine_version import comparable

    if previous is None:
        summary = annotate_changes(scan.get("findings") or [], None)
        summary["engine_changed"] = False
        summary["score_change"] = None
        return None, summary

    if not comparable(scan.get("engine_version"), previous.get("engine_version")):
        summary = annotate_changes(scan.get("findings") or [], None)
        summary["engine_changed"] = True
        summary["previous_engine"] = previous.get("engine_version") or "desconocido"
        summary["engine_version"] = scan.get("engine_version") or "desconocido"
        summary["note"] = NO_COMPARABLE
        summary["score_change"] = None
        return None, summary

    summary = annotate_changes(scan.get("findings") or [], previous.get("findings"))
    summary["engine_changed"] = False
    summary["engine_version"] = scan.get("engine_version") or "desconocido"
    summary["score_change"] = explain_score(_breakdown(scan), _breakdown(previous))
    return previous.get("score"), summary
