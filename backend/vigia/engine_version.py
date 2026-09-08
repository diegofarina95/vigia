"""A fingerprint of the scoring engine, so a delta cannot lie.

The score is a fraction of the weight the tenant earned out of the weight it
could have earned. Add a check that passes and the denominator grows; add one
that fails and it shrinks. Either way the number moves **without the tenant's
exposure having changed at all**, and the report cheerfully announces "▼ 7
since the last scan" for what was actually a deploy.

That already happened here, twice in one day: two checks went out and the score
went from 31 to 40 while the critical count went up.

So every scan records the fingerprint of the engine that produced it, and two
scans from different engines are never subtracted from one another. The reader
is told the set of checks changed instead of being handed a fake trend.

It is a hash rather than a number somebody remembers to increment, because the
number somebody remembers to increment is the number somebody forgets. The
inputs are exactly the things that can move a score:

* which check modules run
* which composite rules exist
* which admin-console settings are evaluated
* the severity weights and the status credits

Renaming a variable does not change it. Adding a check does.
"""
from __future__ import annotations

import hashlib
import json


def _fingerprint_inputs() -> dict:
    # Imported lazily: this module is read by the report and the API, and it
    # must not drag the whole check registry into every import.
    from .checks import ALL_CHECKS
    from .checks.check_policies import CHECKS as POLICY_CHECKS
    from .checks.composite import RULES
    from .scoring import SEVERITY_WEIGHTS, STATUS_CREDIT

    return {
        "checks": sorted(module.CHECK_ID for module in ALL_CHECKS),
        "composites": sorted(rule.id for rule in RULES),
        "policies": sorted(check.finding_id for check in POLICY_CHECKS),
        "weights": dict(sorted(SEVERITY_WEIGHTS.items())),
        "credits": dict(sorted(STATUS_CREDIT.items())),
    }


def engine_version() -> str:
    """A short, stable fingerprint like `v1-9f3c2a7b`.

    The `v1-` prefix is the *format* of the fingerprint, not the version of
    the engine: if the way this hash is computed ever changes, the prefix moves
    and every old scan is correctly treated as incomparable.
    """
    payload = json.dumps(_fingerprint_inputs(), sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:8]
    return f"v1-{digest}"


def describe() -> dict:
    """What went into the fingerprint, for the report and for debugging."""
    inputs = _fingerprint_inputs()
    return {
        "version": engine_version(),
        "checks": len(inputs["checks"]),
        "composites": len(inputs["composites"]),
        "policies": len(inputs["policies"]),
    }


def comparable(one: str | None, other: str | None) -> bool:
    """Whether two scans may be subtracted from each other.

    Unknown is not comparable to anything, including another unknown: scans
    stored before this existed came from an engine nobody recorded, so there is
    no honest way to claim they measured the same thing.
    """
    return bool(one) and bool(other) and one == other
