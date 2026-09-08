"""Which single finding goes in the subject line.

One rule governs everything here: **a finding fires only when the scanner can
assert the fact, never when it merely failed to establish it.** `status ==
"undetermined"` is not a weak failure, it is the absence of evidence, and the
whole cost model of this module is asymmetric — a hook that is 5% weaker loses a
reply, a hook that is wrong loses the domain's reputation and cannot be taken
back. Every guard below exists because some way of reading the report would have
produced a confident sentence out of an unknown.

The order is commercial, not technical, and lives in `catalog.RULES`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .catalog import CATALOG_BY_KEY, RULES, RULES_BY_CODE
from .scanner import Report, UNDETERMINED

#: RFC 7208 §4.6.4. Above this, receivers return permerror.
SPF_LOOKUP_LIMIT = 10

#: SPF qualifiers that do not reject an unauthorised sender.
PERMISSIVE_ALL = ("~", "+")


@dataclass(frozen=True)
class PrimaryFinding:
    """The one finding the outreach email is built around."""

    code: str
    severity_rank: int
    lang: str
    subject_line: str
    opening_line: str
    plain_language_description: str
    technical_description: str
    #: The scanner's own sentence about the mechanism. This is the audit trail:
    #: what was observed, in the scanner's words, at scan time.
    evidence: str
    #: Every code that fired, best-ranked first. The email uses one; the record
    #: keeps all of them, because "why did you write to me" is answered from here.
    all_codes: tuple[str, ...]
    #: True when the domain receives no mail. The finding is still real, but a
    #: parked domain's owner is less likely to care, so the queue sorts these last
    #: rather than dropping them.
    deprioritised: bool = False
    deprioritised_reason: str | None = None


#: Which report key each code draws its evidence from.
MECHANISM_FOR: dict[str, str] = {
    "dmarc-missing": "dmarc",
    "spf-lookup-limit": "spf",
    "dkim-missing": "dkim",
    "spf-soft-all": "spf",
    "dmarc-none-no-rua": "dmarc",
    "mta-sts-missing": "mta_sts",
}


def _section(report: Report, key: str) -> dict[str, Any]:
    section = report.get(key)
    return section if isinstance(section, dict) else {}


def _is_undetermined(report: Report, key: str) -> bool:
    """The scanner could not establish this mechanism's state.

    A resolver timeout, a SERVFAIL, or — for DKIM — no way to enumerate selectors.
    Never a reason to write to anybody.
    """
    section = _section(report, key)
    return section.get("status") == UNDETERMINED or bool(section.get("error"))


def receives_mail(report: Report) -> bool:
    """Whether the domain has MX records.

    Strictly this governs *inbound* mail, and a domain with no MX can still send
    (transactional-only domains do exactly that). It is used here as the brief
    specifies — as a commercial signal that the owner probably does not care —
    rather than as a claim about sending. The one place it is treated as a hard
    fact is MTA-STS, which really is about inbound mail and nothing else.
    """
    mx = _section(report, "mx")
    if mx.get("error"):
        # Could not tell. Assume it does, so the domain is not silently demoted on
        # the strength of a failed lookup.
        return True
    return bool(mx.get("records"))


# --------------------------------------------------------------------------- #
# One predicate per code. Each returns True only on an asserted fact.
# --------------------------------------------------------------------------- #


def _dmarc_missing(report: Report) -> bool:
    return _section(report, "dmarc").get("found") is False


def _spf_lookup_limit(report: Report) -> bool:
    spf = _section(report, "spf")
    lookups = spf.get("dns_lookups")
    return isinstance(lookups, int) and lookups > SPF_LOOKUP_LIMIT


def _dkim_missing(report: Report) -> bool:
    """Only when the absence is assertable.

    DKIM selectors cannot be enumerated: a domain signing with a selector nobody
    guessed is indistinguishable from one that does not sign. The scanner encodes
    that as three states, and only `fail` — a selector the domain itself declared,
    with no key at it — is an assertion. A wildcard TXT record makes every selector
    resolve, so nothing about DKIM can be concluded at all.
    """
    dkim = _section(report, "dkim")
    if dkim.get("wildcard"):
        return False
    return dkim.get("status") == "fail" and dkim.get("found") is False


def _spf_soft_all(report: Report) -> bool:
    spf = _section(report, "spf")
    return spf.get("found") is True and spf.get("all_qualifier") in PERMISSIVE_ALL


def _dmarc_none_no_rua(report: Report) -> bool:
    dmarc = _section(report, "dmarc")
    if dmarc.get("found") is not True:
        return False
    return dmarc.get("policy") == "none" and not dmarc.get("rua")


def _mta_sts_missing(report: Report) -> bool:
    return _section(report, "mta_sts").get("value") is False


PREDICATES: dict[str, Callable[[Report], bool]] = {
    "dmarc-missing": _dmarc_missing,
    "spf-lookup-limit": _spf_lookup_limit,
    "dkim-missing": _dkim_missing,
    "spf-soft-all": _spf_soft_all,
    "dmarc-none-no-rua": _dmarc_none_no_rua,
    "mta-sts-missing": _mta_sts_missing,
}


def fired_codes(report: Report) -> tuple[str, ...]:
    """Every finding that is true of this domain, best-ranked first.

    Used for the audit trail and the review table. `select_primary_finding` picks
    the first of these; nothing else is allowed to reorder them.
    """
    has_mx = receives_mail(report)
    codes: list[str] = []
    for rule in RULES:  # already in rank order
        mechanism = MECHANISM_FOR[rule.code]
        if _is_undetermined(report, mechanism):
            continue
        if not has_mx and not rule.meaningful_without_mx:
            continue
        if PREDICATES[rule.code](report):
            codes.append(rule.code)
    return tuple(codes)


def select_primary_finding(
    scan_results: Report, lang: str = "es"
) -> PrimaryFinding | None:
    """The single finding this domain's email is built around, or None.

    None means "do not write to them": either nothing fired, or everything that
    could have fired was undetermined. Both are the same instruction to the
    caller, and a prospect with no primary finding never reaches the queue.
    """
    codes = fired_codes(scan_results)
    if not codes:
        return None

    code = codes[0]
    rule = RULES_BY_CODE[code]
    entry = CATALOG_BY_KEY.get((code, lang)) or CATALOG_BY_KEY[(code, "es")]
    domain = scan_results.get("domain", "")
    values = {"domain": domain}

    has_mx = receives_mail(scan_results)
    return PrimaryFinding(
        code=code,
        severity_rank=rule.severity_rank,
        lang=entry.lang,
        subject_line=entry.subject_line_template.format(**values),
        opening_line=entry.opening_line_template.format(**values),
        plain_language_description=entry.plain_language_description.format(**values),
        technical_description=entry.technical_description.format(**values),
        evidence=_section(scan_results, MECHANISM_FOR[code]).get("summary", ""),
        all_codes=codes,
        deprioritised=not has_mx,
        deprioritised_reason=None if has_mx else "no-mx",
    )
