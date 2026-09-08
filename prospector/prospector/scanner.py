"""The boundary between this module and Vigía's scanner.

The brief said to assume an interface and mock it. There was no need to assume:
`vigia.dns_email_auth.check_domain(domain, resolver, lang)` already returns exactly
the per-domain report this module needs, so the port below is written against the
shape that function really returns, and `FakeScanner` produces that same shape.
A mock built from a guess would have let Phase 1 pass its tests and then fail on
contact with the real thing.

The report, as the scanner emits it::

    {
      "domain": "example.com",
      "mx":      {"records": [...], "provider": str|None,
                  "google_workspace": bool|None, "error": str|None},
      "spf":     {**SpfResult, "status": ..., "summary": ...},
      "dkim":    {**DkimResult, "status": ..., "summary": ...},
      "dmarc":   {**DmarcResult, "status": ..., "summary": ...},
      "mta_sts": {"status", "summary", "value", "record"},
      "tls_rpt": {...}, "dnssec": {...},
    }

`status` is one of `pass` | `fail` | `warn` | `undetermined`, and **undetermined is
not a failure**. It means the scanner could not establish the fact — DKIM selectors
cannot be enumerated, so a domain that signs with a selector nobody guessed looks
identical to one that does not sign at all. Everything downstream of here treats
those two as different, because an email telling a company their mail is unsigned
when it is signed is the false positive that costs the sender their reputation.

The real adapter is imported lazily. Phase 1 has no dependency on Vigía's package
being importable, and the tests run on the standard library alone.
"""
from __future__ import annotations

from typing import Any, Protocol

#: The keys a report carries per mechanism, besides `domain` and `mx`.
MECHANISMS: tuple[str, ...] = ("spf", "dkim", "dmarc", "mta_sts", "tls_rpt", "dnssec")

#: A verdict that means "we could not tell", as opposed to "it is broken".
UNDETERMINED = "undetermined"

#: The report type. A plain dict rather than a dataclass on purpose: it crosses a
#: process boundary as JSON (it is stored verbatim in `scans.raw_findings`), and
#: freezing it into a class here would mean a scanner change breaks this module at
#: import time rather than at the one place that reads the new field.
Report = dict[str, Any]


class ScannerPort(Protocol):
    """What this module needs from a scanner. Nothing more."""

    def check(self, domain: str) -> Report:
        """One domain's DNS email-authentication report.

        Must not raise for an ordinary DNS failure: an unreachable resolver is
        reported per mechanism as `status == "undetermined"` with the reason in
        `error`, because a timeout is not evidence that a record is missing.
        """
        ...


class VigiaScanner:
    """The real scanner, adapting `vigia.dns_email_auth.check_domain`."""

    def __init__(self, lang: str = "es") -> None:
        self._lang = lang

    def check(self, domain: str) -> Report:
        # Imported here, not at module level: this module is developed and tested
        # without Vigía on the path, and Phase 1 ships before the two are wired.
        #
        # `DnsResolverAdapter` and not a `Resolver` from a `dns_resolver` module:
        # that module does not exist. The guess was written down as an assumption,
        # checked, and found wrong — which is the whole reason for writing
        # assumptions down instead of leaving them in an import.
        from vigia.dns_email_auth import DnsResolverAdapter, check_domain

        return check_domain(domain, DnsResolverAdapter(), lang=self._lang)


# --------------------------------------------------------------------------- #
# The fake, for tests and for developing Phase 2-5 without touching the network.
# --------------------------------------------------------------------------- #


def _mechanism(status: str, summary: str = "", **fields: Any) -> dict[str, Any]:
    return {"status": status, "summary": summary, "error": None, **fields}


def build_report(
    domain: str = "example.com",
    *,
    mx: list[str] | None = None,
    spf: dict[str, Any] | None = None,
    dkim: dict[str, Any] | None = None,
    dmarc: dict[str, Any] | None = None,
    mta_sts: dict[str, Any] | None = None,
    tls_rpt: dict[str, Any] | None = None,
    dnssec: dict[str, Any] | None = None,
) -> Report:
    """A report in the scanner's shape, defaulting to a domain with nothing wrong.

    Defaults are deliberately *clean*, so a test that wants one broken mechanism
    says so and says nothing else. A test whose fixture is broken in six ways
    cannot show which one drove the outcome.
    """
    mx_records = ["aspmx.l.google.com"] if mx is None else mx
    return {
        "domain": domain,
        "mx": {
            "records": list(mx_records),
            "provider": "Google Workspace" if mx_records else None,
            "google_workspace": bool(mx_records),
            "error": None,
        },
        "spf": {
            **_mechanism(
                "pass",
                "SPF ends in -all.",
                found=True,
                multiple_records=False,
                record="v=spf1 include:_spf.google.com -all",
                all_qualifier="-",
                dns_lookups=3,
                lookup_terms=[],
                issues=[],
                dkim_en_raiz=False,
            ),
            **(spf or {}),
        },
        "dkim": {
            **_mechanism(
                "pass",
                "DKIM key found.",
                found=True,
                selector="google",
                record="v=DKIM1; k=rsa; p=…",
                checked_selectors=["google"],
                key_bits=2048,
                issues=[],
                wildcard=False,
                declarados=[],
            ),
            **(dkim or {}),
        },
        "dmarc": {
            **_mechanism(
                "pass",
                "DMARC policy is p=reject at 100%.",
                found=True,
                record="v=DMARC1; p=reject; rua=mailto:d@example.com",
                multiple_records=False,
                policy="reject",
                subdomain_policy=None,
                rua=["mailto:d@example.com"],
                ruf=[],
                rua_destination="example.com",
                rua_platform=None,
                adkim="r",
                aspf="r",
                pct=100,
                issues=[],
            ),
            **(dmarc or {}),
        },
        "mta_sts": {**_mechanism("pass", "MTA-STS is published.", value=True, record="id"),
                    **(mta_sts or {})},
        "tls_rpt": {**_mechanism("pass", "TLS-RPT is published.", value=True, record="r"),
                    **(tls_rpt or {})},
        "dnssec": {**_mechanism("pass", "DNSSEC is on.", value=True, record=None),
                   **(dnssec or {})},
    }


class FakeScanner:
    """A scanner that returns canned reports, by domain."""

    def __init__(self, reports: dict[str, Report] | None = None) -> None:
        self._reports = reports or {}
        self.calls: list[str] = []

    def add(self, domain: str, report: Report) -> None:
        self._reports[domain] = report

    def check(self, domain: str) -> Report:
        self.calls.append(domain)
        return self._reports.get(domain) or build_report(domain)


def scanner_disponible() -> tuple[bool, str]:
    """Whether the real scanner can be imported, and why not if it cannot.

    Checked at startup and shown in the console. Without it the failure surfaces
    as `ModuleNotFoundError` inside a background thread, which is where an error
    goes to be ignored: the job page shows "0 de 0" and nothing says why.
    """
    try:
        from vigia.dns_email_auth import DnsResolverAdapter, check_domain  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        return False, (
            f"{exc}. El paquete `vigia` no está en el PYTHONPATH: añade "
            "/home/diego/vigia/backend, que es lo que hace run.sh."
        )
    return True, ""
