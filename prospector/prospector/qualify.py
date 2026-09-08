"""Is this company worth spending a send on?

The prospect pool is effectively unlimited: every domain with an MX record is a
technical candidate, and scanning is free. Sending is not. The scarce resource is
sender reputation and the operator's credibility, and neither of them scales.

So this module exists to **throw prospects away**. Five thousand poorly-qualified
sends destroy the domain and the operator's name; three hundred well-qualified
ones with a specific, true finding do not. Every rule below is therefore written
as a filter, not as a way to find more.

One design rule matters more than the weights: **an unmeasured signal scores
zero, never a penalty.** A qualification batch that hits a network problem should
qualify nobody, not disqualify everybody — the second is silent and permanent,
because a prospect scored -3 for "no website" during an outage never gets looked
at again.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .scanner import Report
from .signals import (
    CONTACT_FORM_HTML,
    ECOMMERCE_HTML,
    ECOMMERCE_PATHS,
    ECOMMERCE_TXT,
    MARKETING_SPF,
    PARKING_HTML,
    PARKING_NAMESERVERS,
    SiteSignals,
    is_public_administration,
)

#: Sectors where an email-security finding turns into a conversation: they hold
#: client data, they are regulated, or their business runs on email.
HIGH_VALUE_SECTORS: frozenset[str] = frozenset(
    {
        "legal", "abogados", "abogacia", "law", "solicitors", "notaria",
        "accounting", "contabilidad", "asesoria", "gestoria", "auditoria",
        "accountants", "fiscal",
        "agency", "agencia", "marketing", "publicidad", "consultoria",
        "consulting", "creative",
        "healthcare", "salud", "clinica", "clinic", "dental", "medico",
        "sanidad", "veterinaria",
        "logistics", "logistica", "transporte", "transport", "freight",
        "aduanas", "shipping",
        "b2b", "servicios", "services", "software", "saas", "it",
        "inmobiliaria", "seguros", "insurance", "finanzas", "fintech",
    }
)

#: The threshold's default. The positive signals top out at 11; 5 means a prospect
#: has to clear a real bar — a high-value sector or a shop, plus at least one
#: corroborating signal — rather than merely existing and having a website.
DEFAULT_THRESHOLD = 5


@dataclass(frozen=True)
class Signal:
    """One scoring rule that fired, with the evidence for it."""

    name: str
    points: int
    evidence: str = ""


@dataclass(frozen=True)
class CommercialScore:
    """The score, and every rule that produced it.

    The breakdown is not decoration: the threshold is a business judgement that
    will be tuned, and tuning a single number without seeing which rules fired is
    guesswork. It is also what the review table shows when you ask why a domain is
    in the queue.
    """

    total: int
    signals: tuple[Signal, ...] = ()
    qualified: bool = False
    threshold: int = DEFAULT_THRESHOLD
    #: True when nothing could be observed. Distinct from a low score: a domain we
    #: failed to measure is not a domain we judged.
    unmeasured: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "qualified": self.qualified,
            "threshold": self.threshold,
            "unmeasured": self.unmeasured,
            "signals": [
                {"name": s.name, "points": s.points, "evidence": s.evidence}
                for s in self.signals
            ],
        }


def _any_in(needles: tuple[str, ...], haystack: str) -> str | None:
    for needle in needles:
        if needle in haystack:
            return needle
    return None


def _spf_record(report: Report) -> str:
    spf = report.get("spf")
    return (spf.get("record") or "").lower() if isinstance(spf, dict) else ""


def _mx_records(report: Report) -> list[str]:
    mx = report.get("mx")
    return list(mx.get("records") or []) if isinstance(mx, dict) else []


# --------------------------------------------------------------------------- #
# The rules. Each returns a Signal or None.
# --------------------------------------------------------------------------- #


def _ecommerce(report: Report, site: SiteSignals) -> Signal | None:
    """+3 — a shop has revenue tied to email and a reason to care today."""
    hit = _any_in(ECOMMERCE_HTML, site.html)
    if hit:
        return Signal("ecommerce", 3, f"huella en el HTML: {hit}")
    hit = _any_in(ECOMMERCE_PATHS, " ".join(site.paths_found).lower())
    if hit:
        return Signal("ecommerce", 3, f"ruta de compra: {hit}")
    txt = " ".join(site.txt_records).lower()
    hit = _any_in(ECOMMERCE_TXT, txt)
    if hit:
        return Signal("ecommerce", 3, f"pasarela de pago en DNS: {hit}")
    return None


def _high_value_sector(sector: str | None) -> Signal | None:
    """+3 — sectors that hold client data, are regulated, or run on email."""
    if not sector:
        return None
    limpio = sector.strip().lower()
    if limpio in HIGH_VALUE_SECTORS:
        return Signal("sector", 3, limpio)
    # A free-text sector from a CSV: match on any word in it.
    for palabra in limpio.replace("/", " ").replace(",", " ").split():
        if palabra in HIGH_VALUE_SECTORS:
            return Signal("sector", 3, palabra)
    return None


def _marketing_platform(report: Report) -> Signal | None:
    """+2 — they already pay somebody for deliverability, so they buy the problem."""
    spf = _spf_record(report)
    hit = _any_in(MARKETING_SPF, spf)
    return Signal("marketing-platform", 2, f"include: {hit}") if hit else None


def _contact_form(site: SiteSignals) -> Signal | None:
    """+2 — a live site with a way in."""
    if site.resolves is not True or not site.html:
        return None
    hit = _any_in(CONTACT_FORM_HTML, site.html)
    return Signal("contact-form", 2, f"formulario: {hit}") if hit else None


def _mature_mail(report: Report) -> Signal | None:
    """+1 — more than one MX is somebody who set mail up on purpose."""
    registros = _mx_records(report)
    if len(registros) > 1:
        return Signal("mature-mail", 1, f"{len(registros)} registros MX")
    return None


def _no_website(site: SiteSignals) -> Signal | None:
    """-3 — but only when we actually looked and found nothing.

    `resolves is None` means the check never ran; that is not evidence of absence
    and must not be scored, or a network outage silently buries a batch.
    """
    if site.resolves is False and site.error is None:
        return Signal("no-website", -3, "el sitio no responde")
    return None


def _public_admin(domain: str) -> Signal | None:
    """-5 — a public body does not buy this, and cold-emailing one is a bad look."""
    if is_public_administration(domain):
        return Signal("public-admin", -5, domain)
    return None


def _parked(report: Report, site: SiteSignals) -> Signal | None:
    """-5 — nobody is home."""
    ns = " ".join(site.nameservers).lower()
    hit = _any_in(PARKING_NAMESERVERS, ns)
    if hit:
        return Signal("parked", -5, f"nameserver de aparcamiento: {hit}")
    hit = _any_in(PARKING_HTML, site.html)
    if hit:
        return Signal("parked", -5, f"página de venta: {hit}")
    # A resolving site with no MX at all and almost no content is a placeholder.
    if site.resolves is True and not _mx_records(report) and len(site.html) < 500:
        return Signal("parked", -5, "sin MX y con una página vacía")
    return None


def score_prospect(
    report: Report,
    site: SiteSignals | None = None,
    *,
    sector: str | None = None,
    domain: str | None = None,
    threshold: int = DEFAULT_THRESHOLD,
) -> CommercialScore:
    """Score one prospect from signals that cost nothing to gather.

    `report` is the scanner's DNS report; `site` is what `signals.py` observed.
    Either may be missing — a prospect that has not been observed yet scores what
    the DNS alone supports, and is marked `unmeasured` so the queue can tell "not
    interesting" apart from "not looked at".
    """
    site = site or SiteSignals(domain=domain or report.get("domain", ""))
    nombre = domain or site.domain or report.get("domain", "")

    reglas = (
        _ecommerce(report, site),
        _high_value_sector(sector),
        _marketing_platform(report),
        _contact_form(site),
        _mature_mail(report),
        _no_website(site),
        _public_admin(nombre),
        _parked(report, site),
    )
    signals = tuple(s for s in reglas if s is not None)
    total = sum(s.points for s in signals)
    return CommercialScore(
        total=total,
        signals=signals,
        qualified=total >= threshold,
        threshold=threshold,
        unmeasured=not site.measured,
    )
