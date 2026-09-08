"""What can be observed about a domain without writing to it.

The mail-authentication report answers "is there a finding worth mentioning".
This module answers the other question: "is this company worth spending a send
on". Both are read-only observations of public infrastructure; neither requires
contacting anybody.

Same pattern as `scanner.py`: a port, a real implementation, and a fake that
produces the identical shape. The real one is stdlib-only (`urllib`) with hard
timeouts and a small read cap — a qualification pass over a few thousand domains
must not be able to hang on one slow host, and must not download whatever a
hostile server decides to serve.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol

#: How much of a homepage is read before deciding. Fingerprints live in the head
#: and the first part of the body; a shop that cannot be recognised in 200 kB is
#: not going to be recognised in two megabytes either.
MAX_BYTES = 200_000

#: Per-request timeout. The qualification pass is a batch job over an unbounded
#: list, so the cost of a slow host has to be bounded.
TIMEOUT_SECONDS = 8


@dataclass(frozen=True)
class SiteSignals:
    """One domain's observable footprint, outside the mail-auth report.

    Every field defaults to the *uninformative* value, not the pessimistic one:
    an unmeasured signal must score zero, never a penalty. A batch that hits a
    network problem should qualify nobody, not disqualify everybody.
    """

    domain: str = ""
    #: Whether the site answered at all. `None` = not measured.
    resolves: bool | None = None
    final_url: str = ""
    status_code: int | None = None
    #: Lower-cased HTML, truncated to `MAX_BYTES`.
    html: str = ""
    #: Paths that answered on the site, e.g. `/checkout`, `/carrito`.
    paths_found: tuple[str, ...] = ()
    #: TXT records at the apex — payment and platform verification tokens live here.
    txt_records: tuple[str, ...] = ()
    #: Authoritative nameservers, which is where parking shows up most reliably.
    nameservers: tuple[str, ...] = ()
    #: Set when the fetch failed. Presence of an error means "not measured".
    error: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def measured(self) -> bool:
        return self.error is None and self.resolves is not None


class SignalsPort(Protocol):
    """What the qualification engine needs. Must not raise on a dead domain."""

    def observe(self, domain: str) -> SiteSignals:
        ...


# --------------------------------------------------------------------------- #
# Fingerprints. Kept as data so they can be argued with and extended without
# touching the scoring logic.
# --------------------------------------------------------------------------- #

#: Ecommerce platforms, by what they leave in the HTML.
ECOMMERCE_HTML: tuple[str, ...] = (
    "cdn.shopify.com", "myshopify.com", "shopify-features",
    "woocommerce", "wp-content/plugins/woocommerce", "wc-ajax",
    "prestashop", "/modules/ps_", "prestashop-core",
    "magento", "mage/cookies", "/static/version",
    "bigcommerce.com", "shopware", "squarespace-commerce",
    "opencart", "vtex.com.br", "salesforce commerce cloud", "demandware",
)

#: Checkout and basket paths, Spanish and English.
ECOMMERCE_PATHS: tuple[str, ...] = (
    "/checkout", "/cart", "/carrito", "/cesta", "/tienda", "/shop",
    "/comprar", "/finalizar-compra", "/basket", "/store",
)

#: Payment providers that publish a verification record in DNS. `redsys` is the
#: Spanish bank-consortium gateway and is the one most likely to appear here.
ECOMMERCE_TXT: tuple[str, ...] = (
    "stripe-verification", "stripe_verification", "adyen-domain-verification",
    "paypal-domain-verification", "redsys", "braintree", "checkout.com",
    "shopify-verification", "klarna-domain-verification", "sumup",
)

#: Marketing platforms, seen as `include:` in SPF. A domain that already pays one
#: of these has a budget line for email and somebody who cares about delivery.
MARKETING_SPF: tuple[str, ...] = (
    "servers.mcsv.net", "spf.mandrillapp.com",          # Mailchimp
    "sendgrid.net",                                      # SendGrid
    "spf.sendinblue.com", "spf.brevo.com",               # Brevo / Sendinblue
    "_spf.klaviyo.com", "klaviyomail.com",               # Klaviyo
    "spf.hubspotemail.net",                              # HubSpot
    "_spf.salesforce.com", "cust-spf.exacttarget.com",   # Salesforce / SFMC
    "spf.activecampaign.com", "acemsa.com",              # ActiveCampaign
    "_spf.mailerlite.com", "spf.mailjet.com",
    "cmail1.com", "spf.createsend.com",                  # Campaign Monitor
    "amazonses.com", "spf.protection.outlook.com.mailgun",  # SES / Mailgun
    "mailgun.org", "spf.mtasv.net", "postmarkapp.com",
    "constantcontact.com", "spf.dotdigital.com",
)

#: Contact-form markers. A form is what turns a site into a way in.
CONTACT_FORM_HTML: tuple[str, ...] = (
    'type="email"', "type='email'", "<form", "contact-form", "wpcf7",
    "formulario de contacto", "contact form", "gravity-form", "hs-form",
    "mailto:",
)

#: Domain parking and for-sale services, by nameserver or by page text.
PARKING_NAMESERVERS: tuple[str, ...] = (
    "sedoparking.com", "bodis.com", "parkingcrew.net", "above.com",
    "afternic.com", "dan.com", "undeveloped.com", "parklogic.com",
    "voodoo.com", "smartname.com", "namedrive.com", "parkingpage",
)
PARKING_HTML: tuple[str, ...] = (
    "this domain is for sale", "buy this domain", "domain for sale",
    "dominio en venta", "este dominio está en venta", "comprar este dominio",
    "parked domain", "dominio aparcado", "godaddy.com/domainfind",
    "the domain you are looking for is for sale", "inquire about this domain",
)

#: Public administration, by suffix and by name. Spain and the UK.
PUBLIC_ADMIN_SUFFIXES: tuple[str, ...] = (
    ".gob.es", ".gov.uk", ".gov", ".mil", ".gencat.cat", ".xunta.gal",
    ".juntadeandalucia.es", ".madrid.org", ".euskadi.eus", ".navarra.es",
    ".jcyl.es", ".carm.es", ".larioja.org", ".aragon.es", ".gva.es",
    ".nhs.uk", ".police.uk", ".parliament.uk", ".europa.eu",
)
PUBLIC_ADMIN_WORDS: tuple[str, ...] = (
    "ayuntamiento", "ayto", "concello", "diputacion", "diputacio",
    "ministerio", "gobierno", "generalitat", "seguridadsocial",
    "councils", "boroughcouncil", "countycouncil", "citycouncil",
)


def _domain_words(domain: str) -> str:
    return re.sub(r"[^a-z]", "", domain.lower())


def is_public_administration(domain: str) -> bool:
    """Whether the domain belongs to a public body.

    Suffix first, because it is a fact; then a word match against the domain
    label, which is a heuristic. `-council` and `ayuntamiento` are distinctive
    enough to be safe; single words like `junta` or `gov` are not, and are
    deliberately absent — `lajuntadeaccionistas.com` is a company.
    """
    d = domain.lower().strip(".")
    if any(d == s.lstrip(".") or d.endswith(s) for s in PUBLIC_ADMIN_SUFFIXES):
        return True
    palabras = _domain_words(d)
    return any(w in palabras for w in PUBLIC_ADMIN_WORDS)


# --------------------------------------------------------------------------- #
# Implementations.
# --------------------------------------------------------------------------- #


class FakeSignals:
    """Canned observations, for tests and for developing without a network."""

    def __init__(self, observations: dict[str, SiteSignals] | None = None) -> None:
        self._observations = observations or {}
        self.calls: list[str] = []

    def add(self, domain: str, signals: SiteSignals) -> None:
        self._observations[domain] = signals

    def observe(self, domain: str) -> SiteSignals:
        self.calls.append(domain)
        return self._observations.get(domain) or SiteSignals(domain=domain, resolves=False)


class HttpSignals:
    """The real one: one HTTPS GET of the homepage, plus optional DNS lookups.

    Deliberately shallow. It does not crawl, it does not follow more than a few
    redirects, and it reads at most `MAX_BYTES`. Qualification is a filter, not a
    survey, and a heavier implementation would be both slower and ruder to the
    sites being measured.

    NOT exercised by the Phase 1 tests: they run without a network, against
    `FakeSignals`. Treat this class as unverified until the first real batch.
    """

    def __init__(self, resolver: object | None = None, user_agent: str = "") -> None:
        self._resolver = resolver
        self._sin_ns = False
        self._ua = user_agent or (
            "Mozilla/5.0 (compatible; VigiaProspector/1.0; +https://diegofarina.com/vigia)"
        )

    def observe(self, domain: str) -> SiteSignals:
        import urllib.error
        import urllib.request

        url = f"https://{domain}/"
        try:
            peticion = urllib.request.Request(url, headers={"User-Agent": self._ua})
            with urllib.request.urlopen(peticion, timeout=TIMEOUT_SECONDS) as respuesta:
                cuerpo = respuesta.read(MAX_BYTES).decode("utf-8", "replace").lower()
                return SiteSignals(
                    domain=domain,
                    resolves=True,
                    final_url=respuesta.geturl(),
                    status_code=respuesta.status,
                    html=cuerpo,
                    txt_records=self._txt(domain),
                    nameservers=self._ns(domain),
                    notes=self._notas(),
                )
        except urllib.error.HTTPError as exc:
            # A 403 or a 500 is still a site that exists and answers.
            return SiteSignals(
                domain=domain, resolves=True, status_code=exc.code, final_url=url,
                txt_records=self._txt(domain), nameservers=self._ns(domain),
                notes=self._notas(),
            )
        except Exception as exc:  # noqa: BLE001 — a dead domain is data, not an error
            return SiteSignals(domain=domain, resolves=False, error=str(exc))

    def _notas(self) -> list[str]:
        """Signals that could not be gathered, so their absence is not read as a
        measurement. A rule that never fires must be distinguishable from a rule
        that fired and found nothing."""
        return ["sin resolutor de NS: la señal de dominio aparcado no se evalúa"] if self._sin_ns else []

    def _txt(self, domain: str) -> tuple[str, ...]:
        if self._resolver is None:
            return ()
        try:
            return tuple(r.lower() for r in self._resolver.txt(domain))  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            return ()

    def _ns(self, domain: str) -> tuple[str, ...]:
        """Authoritative nameservers, which is where parking shows up most reliably.

        Vigía's `DnsResolverAdapter` has `txt`, `mx` and `ds` but **no `ns`** — it
        was written for mail authentication, which never needs one. The first
        version of this method called `resolver.ns()` inside a bare `except`, so on
        the real resolver it would have returned an empty tuple forever and the
        parking signal would simply never have fired. Silently: no error, no log,
        just a rule that never matched.

        So the lookup is done here when the resolver cannot do it, and when neither
        route is available that fact is recorded rather than swallowed.
        """
        metodo = getattr(self._resolver, "ns", None)
        if callable(metodo):
            try:
                return tuple(r.lower() for r in metodo(domain))
            except Exception:  # noqa: BLE001
                return ()
        try:
            import dns.resolver  # type: ignore[import-not-found]

            respuesta = dns.resolver.resolve(domain, "NS", lifetime=TIMEOUT_SECONDS)
            return tuple(str(r.target).rstrip(".").lower() for r in respuesta)
        except ImportError:
            self._sin_ns = True
            return ()
        except Exception:  # noqa: BLE001 — NXDOMAIN, timeout: no evidence either way
            return ()
