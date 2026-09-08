"""Delete the personal data in a report once it has done its job.

A scan names the people who are exposed, because that is the only way an
admin can act on it. But 24 hours later that list has stopped being useful
and started being a liability: they are addresses belonging to employees of
the customer's organization, people who never used Vigía and never consented
to anything.

So the addresses live for `pii_retention_hours` and are then removed, while
everything the product needs long-term stays: the score, the counts, and each
finding's id and status. Nothing about the history, the chart, the deltas or
the regression detection depends on knowing *who* — `delta.detect_regressions`
reads only ids and statuses.

Two decisions worth keeping:

1. **Only addresses are removed, not whole lists.** `affected_items` also
   carries domain names (`email-spf`), organizational-unit targets (the
   policy checks) and app names. None of that is personal, and all of it is
   worth keeping, so the purge filters by "looks like an address" instead of
   emptying the field.
2. **The purge leaves a trace.** A finding that silently loses its list would
   read as "nobody was affected", which is a lie of exactly the kind this
   product exists to prevent. Every purged finding records how many addresses
   were removed and when, so the report can say "12 accounts, addresses
   deleted after 24 h".
"""
from __future__ import annotations

from .wording import con_numero

import json
import logging
import re
from datetime import datetime, timedelta, timezone

log = logging.getLogger(__name__)

PII_FIELDS = ("accounts", "affected_items")

# Deliberately loose: the cost of removing one extra string is nothing, and
# the cost of leaving an address behind is the whole point of this module.
ADDRESS = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_address(value: object) -> bool:
    """An e-mail address, or a line that contains one.

    Findings do not only store bare addresses: the recovery and sign-in checks
    print "someone@x.com: no recovery phone" and "someone@x.com: Spain×12".
    Those lines are just as personal as the address alone, so a purge that
    only matched bare addresses would leave the person named in the report
    for ever.
    """
    if not isinstance(value, str):
        return False
    text = value.strip()
    if ADDRESS.match(text):
        return True
    return bool(_EMBEDDED_ADDRESS.search(text)) or bool(_EMBEDDED_IP.search(text))


#: An address anywhere inside a longer line.
_EMBEDDED_ADDRESS = re.compile(r"[^@\s]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
#: An IP address identifies a person's connection and location, so under the
#: GDPR it is personal data too. The sign-in checks print them.
_EMBEDDED_IP = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"          # IPv4
    r"|\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b"  # IPv6
)


def strip_addresses(findings: list[dict], stamp: str) -> int:
    """Remove addresses in place. Returns how many PEOPLE were removed.

    Two different counts live here on purpose:

    * Each finding records its own `addresses_purged`, because "12 accounts,
      addresses deleted" is a statement about that finding.
    * The RETURN value is the distinct people across every finding, because
      one person shows up in several findings at once — a super admin with no
      2FA is named by four of them. Summing the per-finding numbers would say
      "3 people" about 2, and that inflated figure is the same mistake this
      counter already made twice: once per field, once per finding.
    """
    everyone: set[str] = set()
    for finding in findings:
        gone: set[str] = set()
        for field in PII_FIELDS:
            values = finding.get(field)
            if not isinstance(values, list):
                continue
            kept = []
            for value in values:
                if is_address(value):
                    # Keyed by WHO, not by the string. The same person appears
                    # as a bare address in `accounts` and inside a sentence in
                    # `affected_items` ("a@x.com: no recovery phone"), and
                    # counting those as two would inflate the number printed
                    # in the report — the exact mistake this count already
                    # made twice.
                    gone.add(identity(value))
                else:
                    kept.append(value)
            finding[field] = kept
        if gone:
            details = finding.get("details")
            if not isinstance(details, dict):
                details = {}
            details["addresses_purged"] = details.get("addresses_purged", 0) + len(gone)
            details["addresses_purged_at"] = stamp
            finding["details"] = details
            everyone |= gone
    return len(everyone)


def addresses_in(findings: list[dict]) -> set[str]:
    """The distinct people named anywhere in a scan."""
    return {
        identity(v)
        for finding in findings
        for field in PII_FIELDS
        for v in (finding.get(field) or [])
        if is_address(v)
    }


def identity(value: str) -> str:
    """Who a purged string is about: the address if there is one, else the
    IP, else the line itself."""
    text = str(value).strip()
    found = _EMBEDDED_ADDRESS.search(text)
    if found:
        return found.group(0).lower()
    found = _EMBEDDED_IP.search(text)
    if found:
        return found.group(0).lower()
    return text.lower()


def contains_addresses(findings: list[dict]) -> bool:
    return bool(addresses_in(findings))


def purge(db, retention_hours: int, now: datetime | None = None) -> dict:
    """Apply the retention window. Safe to run repeatedly and concurrently:
    it only ever removes, so two workers racing reach the same result."""
    if retention_hours <= 0:
        return {"skipped": "retention disabled", "scans": 0, "addresses": 0, "bodies": 0}

    now = now or datetime.now(timezone.utc)
    cutoff = (now - timedelta(hours=retention_hours)).isoformat()
    stamp = now.isoformat()

    scans = 0
    everyone: set[str] = set()  # distinct across the whole run, not per scan
    for scan_id, raw in db.scans_older_than(cutoff):
        try:
            findings = json.loads(raw)
        except (TypeError, ValueError):
            log.warning("escaneo %s tiene findings_json ilegible, se omite", scan_id)
            continue
        # Counted before stripping, and as a set: the per-finding numbers add
        # up to more than the headcount because one person shows up in several
        # findings, and "80 addresses deleted" for 15 people is not a true
        # sentence to put in a log.
        people = addresses_in(findings)
        if not people:
            continue
        strip_addresses(findings, stamp)
        db.update_scan_findings(scan_id, findings)
        scans += 1
        everyone |= people

    bodies = db.purge_outreach_bodies(cutoff)

    if scans or bodies:
        log.info(
            "retención: %s borradas en %s, %s de correo",
            con_numero(len(everyone), "persona"),
            con_numero(scans, "escaneo"),
            con_numero(bodies, "cuerpo"),
        )
    return {"scans": scans, "addresses": len(everyone), "bodies": bodies, "cutoff": cutoff}
