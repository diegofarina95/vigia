"""SPF / DKIM / DMARC checks over public DNS. No Google API involved.

Design:

* Pure parsing/verdict functions are separated from network lookups so
  they can be unit-tested without touching the network.
* Any object with ``.txt(name)`` and ``.mx(name)`` can be injected as a
  resolver; the default uses dnspython.
* Uncertainty policy: when a lookup fails for infrastructure reasons
  (timeout, SERVFAIL) the result is marked unknown (``error`` set) and
  the verdict is ``undetermined`` — never a false ``fail``. NXDOMAIN /
  empty answers ARE conclusive ("record does not exist").
* DKIM is special: we can only probe common selectors, so "not found"
  is always ``undetermined``, never ``fail`` — unless the person told us
  the selector they sign with, which turns a miss into a fact.
* Every sentence this module produces comes from the catalogue via
  ``i18n.text`` and exists in both languages. ``lang`` defaults to Spanish
  so a caller that has no language to offer keeps the old behaviour, and
  the templates take named placeholders, never pre-formatted text.
"""
from __future__ import annotations

import base64
import re
import uuid
from dataclasses import asdict, dataclass, field

import dns.exception
import dns.resolver

from .i18n import text

#: Every DKIM selector Vigía probes, in one place.
#:
#: It lived in three: this list, an identical copy in `config.py`, and a
#: one-element `SCAN_DKIM_SELECTORS` that made the scanner check only `google`
#: while the public checker checked seven. A domain could therefore be "no
#: verificado" in the report and "correcto" in the free checker on the same day.
#:
#: Seven was also too few. Auditing ten real domains, three published their key in
#: a selector not on the list — Mailchimp's `k2`/`k3`, reached through a CNAME to
#: `dkim2.mcsv.net`, which resolves transparently, so listing the selector is all
#: it takes. The rest are the selectors the common senders publish under.
#:
#: The cost of a longer list is one DNS query each, and `check_dkim` stops at the
#: first real key, so the full sweep only happens on domains that have none.
DEFAULT_DKIM_SELECTORS = [
    # Google Workspace, and the generic ones
    "google", "default", "mail", "dkim", "smtp", "dkim1", "zmail",
    # Zoho — `zoho2` is what diegofarina.com actually signs with, and the seven-item
    # list missed it, so the tool reported "no verificado" on its own author's domain.
    "zoho", "zoho1", "zoho2",
    # Microsoft 365
    "selector1", "selector2",
    # Mailchimp / Mandrill
    "k1", "k2", "k3", "mandrill", "mailchimp",
    # SendGrid, Sendinblue/Brevo, Mailjet, Postmark, Proton
    "s1", "s2", "sendgrid", "em", "sib", "mailjet", "pm", "protonmail1",
    # HubSpot, Campaign Monitor, MXVault
    "hs1", "hs2", "cm", "mxvault",
]

# SPF terms that trigger a DNS lookup (RFC 7208 caps them at 10).
_SPF_LOOKUP_TERMS = re.compile(r"(?:^|\s)[+\-~?]?(include:|a\b|a:|mx\b|mx:|ptr\b|ptr:|exists:|redirect=)", re.I)

# Mechanisms that cost a DNS lookup, for the recursive RFC 7208 count.
# Ported from prospector.py, which already proved this shape in the field.
_LOOKUP_MECHS = ("include:", "a:", "mx:", "ptr", "exists:", "redirect=")
SPF_LOOKUP_LIMIT = 10  # RFC 7208 §4.6.4 — above this receivers return permerror
_SPF_MAX_DEPTH = 5

# MX needle -> provider label. Trimmed from prospector.py's list to the
# providers that actually change how remediation is explained.
_MX_PROVIDERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("google", ("google.com", "googlemail.com")),
    ("microsoft", ("outlook.com", "protection.outlook", "microsoft.com")),
    ("zoho", ("zoho.", "zohomail.")),
    ("proofpoint", ("pphosted.", "ppe-hosted.")),
    ("mimecast", ("mimecast.",)),
    ("barracuda", ("barracudanetworks.",)),
    ("ovh", ("ovh.net", "ovh.ca")),
    ("ionos", ("ionos.", "1and1.", "kundenserver.")),
    ("arsys", ("arsys.", "hostalia.")),
    ("mailgun", ("mailgun.org",)),
    ("sendgrid", ("sendgrid.net",)),
)


def mail_provider(mx_records: list[str]) -> str:
    """Best-effort mail provider from the MX hosts."""
    if not mx_records:
        return "none"
    joined = " ".join(mx_records).lower()
    return next(
        (name for name, needles in _MX_PROVIDERS if any(n in joined for n in needles)),
        "other",
    )


def dkim_key_bits(public_key: str) -> int | None:
    """Approximate RSA key size from the base64 ``p=`` value.

    Ported from prospector.py: the DER wrapper makes the encoded length a
    reliable proxy for the modulus size, which is what we need to flag
    1024-bit keys as weak.
    """
    try:
        raw = base64.b64decode(public_key + "=" * (-len(public_key) % 4))
    except (ValueError, TypeError):
        return None
    if not raw:
        return None
    if len(raw) < 200:
        return 1024
    if len(raw) < 350:
        return 2048
    return 4096


def count_spf_lookups(domain: str, resolver, _seen: set | None = None, _depth: int = 0) -> int:
    """DNS lookups an SPF record costs, following include: and redirect=.

    RFC 7208 caps this at 10; above it receivers return **permerror** and
    stop evaluating SPF entirely — a hard failure almost nobody notices,
    because the record still "looks fine". Guards against include loops
    (``_seen``) and runaway chains (``_depth``).
    """
    if _seen is None:
        _seen = set()
    if _depth > _SPF_MAX_DEPTH or domain in _seen:
        return 0
    _seen.add(domain)

    try:
        records = [r for r in resolver.txt(domain) if r.lower().startswith("v=spf1")]
    except DnsUnavailable:
        return 0
    if not records:
        return 0

    total = 0
    for term in records[0].split():
        lowered = term.lower().lstrip("+-~?")
        if lowered in ("a", "mx", "ptr") or any(
            lowered.startswith(mech) for mech in _LOOKUP_MECHS
        ):
            total += 1
            if lowered.startswith(("include:", "redirect=")):
                target = term.split(":", 1)[-1].split("=")[-1].strip()
                if target:
                    total += count_spf_lookups(target, resolver, _seen, _depth + 1)
    return total


#: DMARC report processors. Sending aggregate reports ONLY to one of these is the
#: correct configuration, not a gap: the platform IS the telemetry, and it exists
#: precisely so nobody has to read raw XML every morning. Telling a customer who
#: pays for EasyDMARC to also mail the reports to themselves says we do not know
#: what a DMARC platform is.
#:
#: Found on mutare.io: rua and ruf at easydmarc.eu with fo=1 — a deliberate,
#: competent setup that the check was flagging as a problem.
PLATAFORMAS_DMARC: tuple[str, ...] = (
    "easydmarc.eu", "easydmarc.com", "dmarcian.com", "valimail.com",
    "postmarkapp.com", "uriports.com", "powerdmarc.com", "ondmarc.redsift.com",
    "mxtoolbox.com", "agari.com", "proofpoint.com", "fraudmarc.com",
    "dmarcadvisor.com",
)


def plataforma_dmarc(valores: list[str]) -> str | None:
    """The report processor these addresses belong to, if it is a known one."""
    for direccion in valores or []:
        destino = direccion.split("@")[-1].strip().lower().rstrip(">")
        for plataforma in PLATAFORMAS_DMARC:
            if destino == plataforma or destino.endswith("." + plataforma):
                return plataforma
    return None


def classify_rua(domain: str, rua_values: list[str]) -> str:
    """Where DMARC aggregate reports go: 'none', 'own' or 'third_party'.

    Reports landing only at a third party mean the customer never sees
    their own spoofing telemetry — a finding worth raising on its own.
    """
    if not rua_values:
        return "none"
    root = domain.lower()
    for address in rua_values:
        target = address.split("@")[-1].strip().lower().rstrip(">")
        if target == root or target.endswith("." + root) or root.endswith("." + target):
            return "own"
    if plataforma_dmarc(rua_values):
        return "platform"
    return "third_party"


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)


class DnsUnavailable(Exception):
    """Lookup failed for infrastructure reasons — result is unknown."""


def normalize_domain(raw: str) -> str | None:
    """Return a validated, lowercased, IDNA-encoded domain, or None."""
    candidate = (raw or "").strip().lower().rstrip(".")
    candidate = re.sub(r"^https?://", "", candidate).split("/")[0].split(":")[0]
    if candidate.startswith("www.") and candidate.count(".") >= 2:
        candidate = candidate[4:]
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return None
    return candidate if _DOMAIN_RE.match(candidate) else None


class DnsResolverAdapter:
    """dnspython-backed resolver. txt()/mx() return [] when the record
    conclusively does not exist and raise DnsUnavailable on timeouts."""

    def __init__(self, timeout: float = 5.0) -> None:
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = timeout
        self._resolver.timeout = timeout

    def txt(self, name: str) -> list[str]:
        try:
            answers = self._resolver.resolve(name, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.exception.DNSException) as exc:
            raise DnsUnavailable(str(exc) or exc.__class__.__name__) from exc
        return [b"".join(rdata.strings).decode("utf-8", "replace") for rdata in answers]

    def mx(self, name: str) -> list[str]:
        try:
            answers = self._resolver.resolve(name, "MX")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.exception.DNSException) as exc:
            raise DnsUnavailable(str(exc) or exc.__class__.__name__) from exc
        return [str(rdata.exchange).rstrip(".").lower() for rdata in answers]

    def ds(self, name: str) -> list[str]:
        """Delegation Signer records — their presence means the parent zone
        signs this domain, i.e. DNSSEC is enabled."""
        try:
            answers = self._resolver.resolve(name, "DS")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.exception.DNSException) as exc:
            raise DnsUnavailable(str(exc) or exc.__class__.__name__) from exc
        return [str(rdata) for rdata in answers]


# ---------------------------------------------------------------- SPF


@dataclass
class SpfResult:
    found: bool | None = None  # None = could not determine
    multiple_records: bool = False  # several SPF records = permerror
    record: str | None = None
    all_qualifier: str | None = None  # '-', '~', '+', '?'
    lookup_terms: int = 0  # top-level terms only (no recursion)
    dns_lookups: int | None = None  # recursive, RFC 7208 count
    issues: list[str] = field(default_factory=list)
    error: str | None = None
    #: A `v=DKIM1` record found among the apex TXT records, where it does nothing.
    #: Detected here because the apex TXT are already in memory for the SPF: a
    #: verifier looks for the key at `<selector>._domainkey.<domain>` and never at
    #: the root, so a key published there is dead — signed mail is not verified by
    #: it and nothing reports the mistake. Seen on douscents.es, 1024 bits, beside
    #: a working 2048-bit key at the right name.
    dkim_en_raiz: str | None = None


def parse_spf(txt_records: list[str], lang: str = "es") -> SpfResult:
    spf_records = [r.strip() for r in txt_records if r.strip().lower().startswith("v=spf1")]
    mal_ubicada = next((r.strip() for r in txt_records if _es_dkim(r)), None)
    if not spf_records:
        # Reported on both branches: a misplaced key is just as dead on a domain
        # with no SPF as on one with it.
        return SpfResult(
            found=False,
            issues=[text(lang, "dns.spf.sin_registro")],
            dkim_en_raiz=mal_ubicada,
        )

    result = SpfResult(found=True, record=spf_records[0], dkim_en_raiz=mal_ubicada)
    if len(spf_records) > 1:
        result.multiple_records = True
        result.issues.append(
            text(lang, "dns.spf.varios_registros", count=len(spf_records))
        )

    record = spf_records[0]
    match = re.search(r"(?:^|\s)([+\-~?]?)all(?:\s|$)", record)
    if match:
        result.all_qualifier = match.group(1) or "+"
        if result.all_qualifier == "+":
            result.issues.append(text(lang, "dns.spf.all_permisivo"))
        elif result.all_qualifier == "?":
            result.issues.append(text(lang, "dns.spf.all_neutro"))
    elif "redirect=" not in record.lower():
        result.issues.append(text(lang, "dns.spf.sin_all"))

    # Heuristic: top-level lookup terms only (includes are not resolved
    # recursively), so the real count may be higher.
    result.lookup_terms = len(_SPF_LOOKUP_TERMS.findall(record))
    if result.lookup_terms > 10:
        result.issues.append(
            text(lang, "dns.spf.terminos_primer_nivel", count=result.lookup_terms)
        )
    return result


def check_spf(domain: str, resolver, lang: str = "es") -> SpfResult:
    try:
        result = parse_spf(resolver.txt(domain), lang)
    except DnsUnavailable as exc:
        return SpfResult(found=None, error=str(exc))

    if result.found:
        # Recursive count: this is the number receivers actually enforce.
        result.dns_lookups = count_spf_lookups(domain, resolver)
        if result.dns_lookups > SPF_LOOKUP_LIMIT:
            result.issues.append(
                text(
                    lang,
                    "dns.spf.limite_consultas",
                    lookups=result.dns_lookups,
                    limit=SPF_LOOKUP_LIMIT,
                )
            )
    return result


def spf_verdict(result: SpfResult, lang: str = "es") -> tuple[str, str]:
    if result.error is not None or result.found is None:
        return "undetermined", text(lang, "dns.spf.sin_determinar")
    if not result.found:
        return "fail", text(lang, "dns.spf.no_encontrado")
    if result.all_qualifier == "+":
        return "fail", text(lang, "dns.spf.fail_all_permisivo")
    if result.multiple_records:
        return "fail", text(lang, "dns.spf.fail_varios")
    if result.dns_lookups is not None and result.dns_lookups > SPF_LOOKUP_LIMIT:
        return (
            "fail",
            text(
                lang,
                "dns.spf.fail_limite",
                limit=SPF_LOOKUP_LIMIT,
                lookups=result.dns_lookups,
            ),
        )
    if result.all_qualifier == "?" or result.all_qualifier is None or result.lookup_terms > 10:
        return "warn", text(lang, "dns.spf.debilidades")
    return "pass", text(lang, "dns.spf.correcto", qualifier=result.all_qualifier)


# --------------------------------------------------------------- DKIM


@dataclass
class DkimResult:
    # True = a DKIM key was found; None = nothing at the probed selectors
    # (NOT conclusive — the domain may use a custom selector). Never False.
    found: bool | None = None
    selector: str | None = None
    record: str | None = None
    checked_selectors: list[str] = field(default_factory=list)
    key_bits: int | None = None
    issues: list[str] = field(default_factory=list)
    error: str | None = None
    #: True when the zone answers TXT for names that do not exist. Every selector
    #: then "responds" and none of it means anything.
    wildcard: bool = False
    #: Selectors the person told us they sign with. Their presence changes what a
    #: miss MEANS: with none, not finding a key is ignorance, because DKIM cannot be
    #: enumerated; with one, it is a fact — they asserted it exists and the DNS says
    #: it does not. Only the public checker fills this in; inside a tenant the
    #: selector comes from the Workspace API and there is nothing to declare.
    declarados: list[str] = field(default_factory=list)


_SELECTOR_VALIDO = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")
MAX_SELECTORES_APORTADOS = 10


def validar_selectores(bruto: str, lang: str = "es") -> tuple[list[str], str | None]:
    """Parse a comma-separated list of selectors typed by a person.

    Returns `(selectores, error)`. The error names what is wrong with the input
    rather than saying "invalid": somebody who pastes the full record name deserves
    to be told that is what happened, not to be handed a generic rejection and left
    to guess. That is the standard the rest of this tool holds itself to.
    """
    if not bruto or not bruto.strip():
        return [], None

    crudos = [t.strip() for t in bruto.split(",")]
    crudos = [t for t in crudos if t]
    if len(crudos) > MAX_SELECTORES_APORTADOS:
        return [], text(lang, "dns.selector.demasiados", max=MAX_SELECTORES_APORTADOS)

    limpios: list[str] = []
    for token in crudos:
        if "." in token:
            return [], text(lang, "dns.selector.con_puntos", token=token)
        if "_" in token:
            return [], text(lang, "dns.selector.con_guion_bajo", token=token)
        if " " in token:
            return [], text(lang, "dns.selector.con_espacios", token=token)
        if token[0].isdigit():
            return [], text(lang, "dns.selector.empieza_por_numero", token=token)
        if not _SELECTOR_VALIDO.match(token):
            malos = sorted({c for c in token if not (c.isalnum() or c == "-")})
            return [], text(
                lang,
                "dns.selector.caracteres_invalidos",
                token=token,
                malos=", ".join(malos),
            )
        if token.lower() not in [x.lower() for x in limpios]:
            limpios.append(token)
    return limpios, None


def _es_dkim(record: str) -> bool:
    """A TXT record counts as DKIM only if it says so.

    The test used to be `"v=dkim1" in r or "k=rsa" in r or r.startswith("p=")`,
    which accepts a record that merely mentions RSA somewhere. RFC 6376 §3.6.1 is
    explicit: when v= is present it MUST be the first tag and its value is DKIM1.
    Anchoring on that is what makes a wildcard zone answer "no" instead of "yes".
    """
    return record.replace(" ", "").lower().lstrip(";").startswith("v=dkim1")


def _hay_comodin(domain: str, resolver) -> bool:
    """Does this zone answer for a name nobody published?

    A `*.domain TXT` wildcard makes every selector return something, so "the record
    exists" stops being evidence of anything. Probed with a name that cannot
    plausibly have been configured; a zone that answers it answers everything.

    Real case: abstracta.digital returns two google-site-verification records for
    any `_domainkey` name, and for `_mta-sts` and `_smtp._tls` as well.
    """
    sonda = f"zzz-vigia-{uuid.uuid4().hex[:12]}._domainkey.{domain}"
    try:
        return bool(resolver.txt(sonda))
    except DnsUnavailable:
        return False
    except Exception:  # noqa: BLE001 — a probe that fails proves nothing
        return False


def _entre_comillas(lang: str, valores) -> str:
    """The names, quoted the way the language quotes them: «zoho2» / 'zoho2'."""
    return ", ".join(text(lang, "dns.comillas", valor=valor) for valor in valores)


def check_dkim(
    domain: str,
    resolver,
    selectors: list[str] | None = None,
    declarados: list[str] | None = None,
    lang: str = "es",
) -> DkimResult:
    declarados = list(declarados or [])
    # Declared first, and IN ADDITION to the default list, never instead of it: the
    # person may be right about one selector and still have another we would find.
    # Probing theirs first means the reported selector is the one they named.
    selectors = declarados + [
        s for s in (selectors or DEFAULT_DKIM_SELECTORS)
        if s.lower() not in {d.lower() for d in declarados}
    ]
    result = DkimResult(checked_selectors=list(selectors), declarados=declarados)
    # Probed BEFORE the sweep, so the answer is on the result even when a real key
    # is also found: abstracta.digital has both a wildcard and a genuine key under
    # `google`, and the reader needs to be told about the first either way.
    result.wildcard = _hay_comodin(domain, resolver)
    saw_error = False
    for selector in selectors:
        name = f"{selector}._domainkey.{domain}"
        try:
            records = resolver.txt(name)
        except DnsUnavailable as exc:
            saw_error = True
            result.error = str(exc)
            continue
        for record in records:
            if _es_dkim(record):
                result.found = True
                result.selector = selector
                result.record = record
                result.error = None
                key_match = re.search(r"p=([A-Za-z0-9+/=]+)", record.replace(" ", ""))
                if key_match and len(key_match.group(1)) > 20:
                    # Weak keys are reported by dkim_verdict, which owns the
                    # wording; adding an issue here too would shadow it.
                    result.key_bits = dkim_key_bits(key_match.group(1))
                if re.search(r"(^|;)\s*p=\s*(;|$)", record.replace(" ", "")):
                    result.issues.append(
                        text(lang, "dns.dkim.clave_vacia", selector=selector)
                    )
                return result
    if not saw_error:
        result.error = None
    return result


def dkim_verdict(result: DkimResult, lang: str = "es") -> tuple[str, str]:
    if result.found:
        bits = result.key_bits
        # Declared one selector, found another. Not a failure — the domain signs,
        # with a real key — but saying only "correcto" would quietly swallow the
        # claim they made. They believe the key lives somewhere it does not, which
        # is how a rotation ends up revoking the wrong record.
        fallidos = [
            d for d in result.declarados if d.lower() != (result.selector or "").lower()
        ]
        aviso = ""
        if fallidos:
            aviso = " " + text(
                lang,
                "dns.dkim.aviso_otro_selector",
                nombres=_entre_comillas(lang, fallidos),
            )
        if result.issues:
            return "warn", text(
                lang, "dns.dkim.warn_problemas", selector=result.selector, aviso=aviso
            )
        if bits and bits < 2048:
            return (
                "warn",
                text(
                    lang,
                    "dns.dkim.warn_bits",
                    selector=result.selector,
                    bits=bits,
                    aviso=aviso,
                ),
            )
        suffix = text(lang, "dns.dkim.sufijo_bits", bits=bits) if bits else ""
        return "pass", text(
            lang,
            "dns.dkim.encontrada",
            selector=result.selector,
            sufijo=suffix,
            aviso=aviso,
        )
    if result.error is not None:
        return "undetermined", text(lang, "dns.dkim.sin_determinar")

    # A declared selector turns ignorance into a fact.
    #
    # Everything below this branch says "no verificado" because DKIM cannot be
    # enumerated: a miss across guessed names proves nothing. But when somebody
    # tells us the name and the DNS has nothing there, we are no longer guessing —
    # we looked exactly where they said and it was empty. That is not "I do not
    # know", it is "I checked and it is missing", and it is actionable: the record
    # was never published, or it is misspelled, or it sits under the wrong name.
    if result.declarados:
        plural = text(
            lang,
            "dns.dkim.varios_selectores"
            if len(result.declarados) > 1
            else "dns.dkim.un_selector",
        )
        return (
            "fail",
            text(
                lang,
                "dns.dkim.fail_declarado",
                plural=plural,
                nombres=_entre_comillas(lang, result.declarados),
            )
            + (
                " " + text(lang, "dns.dkim.aviso_comodin")
                if result.wildcard
                else ""
            ),
        )

    # NOT VERIFIED, not absent. DKIM is discovered by guessing selector
    # names, so a miss proves nothing: the domain may sign with a custom
    # selector we did not try. Saying "no DKIM" here and being wrong in
    # front of a technical audience costs the whole meeting.
    count = len(result.checked_selectors)
    tried = ", ".join(result.checked_selectors[:6])
    if count > 6:
        tried += ", …"
    # The count comes from what was actually probed, not from a number written into
    # the sentence: scanner and public checker now share one list, and a person can
    # add their own on top of it.
    probados = text(
        lang,
        "dns.dkim.probado_uno" if count == 1 else "dns.dkim.probados_varios",
        count=count,
        tried=tried,
    )
    return "undetermined", text(lang, "dns.dkim.no_verificado", probados=probados)


# -------------------------------------------------------------- DMARC


@dataclass
class DmarcResult:
    found: bool | None = None
    record: str | None = None
    #: Several DMARC records at `_dmarc` = receivers ignore DMARC entirely, the
    #: same way several SPF records are a permerror. A flag rather than something
    #: read back out of `issues`: the verdict used to look for the word "multiple"
    #: in the prose, which no language's sentence contains, so the branch never
    #: ran and a domain with two records was told it had *one* record "with no
    #: valid policy (p=)" — both halves false, and the advice sends the customer
    #: to edit a `p=` that is already correct in both copies.
    multiple_records: bool = False
    policy: str | None = None  # none | quarantine | reject
    subdomain_policy: str | None = None
    rua: list[str] = field(default_factory=list)
    #: Forensic report addresses. Parsed for the same reason as `rua`: a domain can
    #: point its forensic reports at a DMARC processor too, and mutare.io does.
    ruf: list[str] = field(default_factory=list)
    rua_destination: str | None = None  # none | own | platform | third_party
    #: Name of the DMARC processor when the reports go to a known one.
    rua_platform: str | None = None
    adkim: str = "r"  # r = relaxed (default), s = strict
    aspf: str = "r"
    pct: int = 100
    issues: list[str] = field(default_factory=list)
    error: str | None = None


def parse_dmarc(txt_records: list[str], lang: str = "es") -> DmarcResult:
    dmarc_records = [
        r.strip() for r in txt_records if r.strip().lower().replace(" ", "").startswith("v=dmarc1")
    ]
    if not dmarc_records:
        return DmarcResult(found=False, issues=[text(lang, "dns.dmarc.sin_registro")])

    result = DmarcResult(found=True, record=dmarc_records[0])
    if len(dmarc_records) > 1:
        result.multiple_records = True
        result.issues.append(
            text(lang, "dns.dmarc.varios_registros", count=len(dmarc_records))
        )
        return result

    tags: dict[str, str] = {}
    for part in dmarc_records[0].split(";"):
        if "=" in part:
            key, _, value = part.partition("=")
            tags[key.strip().lower()] = value.strip()

    result.policy = tags.get("p", "").lower() or None
    result.subdomain_policy = tags.get("sp", "").lower() or None
    result.rua = [addr.strip() for addr in tags.get("rua", "").split(",") if addr.strip()]
    result.ruf = [addr.strip() for addr in tags.get("ruf", "").split(",") if addr.strip()]
    result.adkim = (tags.get("adkim", "r") or "r").lower()[:1]
    result.aspf = (tags.get("aspf", "r") or "r").lower()[:1]

    if result.policy not in ("none", "quarantine", "reject"):
        result.issues.append(text(lang, "dns.dmarc.sin_p"))
        result.policy = None
    if "pct" in tags:
        try:
            result.pct = max(0, min(100, int(tags["pct"])))
        except ValueError:
            result.issues.append(
                text(lang, "dns.dmarc.pct_invalido", valor=repr(tags["pct"]))
            )
        if result.pct < 100:
            result.issues.append(text(lang, "dns.dmarc.pct_parcial", pct=result.pct))
    if not result.rua:
        result.issues.append(text(lang, "dns.dmarc.sin_rua"))
    return result


def check_dmarc(domain: str, resolver, lang: str = "es") -> DmarcResult:
    try:
        result = parse_dmarc(resolver.txt(f"_dmarc.{domain}"), lang)
    except DnsUnavailable as exc:
        return DmarcResult(found=None, error=str(exc))

    if result.found:
        result.rua_destination = classify_rua(domain, result.rua)
        result.rua_platform = plataforma_dmarc(result.rua) or plataforma_dmarc(result.ruf)
        if result.rua_destination == "third_party":
            result.issues.append(text(lang, "dns.dmarc.rua_ajena"))
    return result


def dmarc_verdict(result: DmarcResult, lang: str = "es") -> tuple[str, str]:
    if result.error is not None or result.found is None:
        return "undetermined", text(lang, "dns.dmarc.sin_determinar")
    if not result.found:
        return "fail", text(lang, "dns.dmarc.no_encontrado")
    # The structured flag, not a word search over the prose: this is the same
    # shape `spf_verdict` uses two hundred lines up, and reading a verdict back
    # out of a translated sentence is what broke it in the first place.
    if result.multiple_records:
        return "fail", text(lang, "dns.dmarc.fail_varios")
    if result.policy is None:
        return "fail", text(lang, "dns.dmarc.fail_sin_politica")
    if result.policy == "none":
        return "fail", text(lang, "dns.dmarc.fail_none")
    if result.policy == "quarantine":
        return "warn", text(lang, "dns.dmarc.warn_quarantine")
    if result.pct < 100:
        return "warn", text(lang, "dns.dmarc.warn_pct", pct=result.pct)
    return "pass", text(lang, "dns.dmarc.correcto")


# ----------------------------------------------- transport & DNS integrity


@dataclass
class TransportResult:
    """MTA-STS (enforced TLS for inbound mail), TLS-RPT (TLS failure
    reports) and DNSSEC (signed DNS). All are DNS-only signals."""

    mta_sts: bool | None = None
    mta_sts_id: str | None = None
    tls_rpt: bool | None = None
    tls_rpt_record: str | None = None
    dnssec: bool | None = None
    errors: dict = field(default_factory=dict)


def check_transport(domain: str, resolver) -> TransportResult:
    result = TransportResult()

    try:
        records = resolver.txt(f"_mta-sts.{domain}")
        # Prefix, not substring. RFC 8461 §3.1 puts `v=STSv1` first; a record that
        # merely mentions it somewhere is not a policy. Same reasoning as `_es_dkim`.
        sts = [r for r in records if r.replace(" ", "").lower().lstrip(";").startswith("v=stsv1")]
        result.mta_sts = bool(sts)
        if sts:
            match = re.search(r"id\s*=\s*([^;\s]+)", sts[0], re.I)
            result.mta_sts_id = match.group(1) if match else None
    except DnsUnavailable as exc:
        result.errors["mta_sts"] = str(exc)

    try:
        records = resolver.txt(f"_smtp._tls.{domain}")
        rpt = [r for r in records if r.replace(" ", "").lower().lstrip(";").startswith("v=tlsrptv1")]
        result.tls_rpt = bool(rpt)
        result.tls_rpt_record = rpt[0] if rpt else None
    except DnsUnavailable as exc:
        result.errors["tls_rpt"] = str(exc)

    try:
        result.dnssec = bool(resolver.ds(domain))
    except DnsUnavailable as exc:
        result.errors["dnssec"] = str(exc)
    except AttributeError:
        # Resolver without DS support (e.g. a test double) — unknown, not a failure.
        result.errors["dnssec"] = "unsupported by resolver"

    return result


def mta_sts_verdict(result: TransportResult, lang: str = "es") -> tuple[str, str]:
    if "mta_sts" in result.errors or result.mta_sts is None:
        return "undetermined", text(lang, "dns.mta_sts.sin_determinar")
    if result.mta_sts:
        return "pass", text(lang, "dns.mta_sts.correcto")
    return "warn", text(lang, "dns.mta_sts.ausente")


def tls_rpt_verdict(result: TransportResult, lang: str = "es") -> tuple[str, str]:
    if "tls_rpt" in result.errors or result.tls_rpt is None:
        return "undetermined", text(lang, "dns.tls_rpt.sin_determinar")
    if result.tls_rpt:
        return "pass", text(lang, "dns.tls_rpt.correcto")
    return "warn", text(lang, "dns.tls_rpt.ausente")


def dnssec_verdict(result: TransportResult, lang: str = "es") -> tuple[str, str]:
    if "dnssec" in result.errors or result.dnssec is None:
        return "undetermined", text(lang, "dns.dnssec.sin_determinar")
    if result.dnssec:
        return "pass", text(lang, "dns.dnssec.correcto")
    return "warn", text(lang, "dns.dnssec.ausente")


# ----------------------------------------------------------- combined


def check_domain(
    domain: str,
    resolver=None,
    selectors: list[str] | None = None,
    declarados: list[str] | None = None,
    lang: str = "es",
) -> dict:
    """Full SPF/DKIM/DMARC report for one domain, JSON-serializable,
    with per-mechanism status + plain-language summary already derived.

    `lang` decides the language of every summary and issue in the report. It
    defaults to Spanish so a caller with no language to offer — the scanner —
    behaves as before; the public checker passes the visitor's."""
    resolver = resolver or DnsResolverAdapter()

    spf = check_spf(domain, resolver, lang)
    dkim = check_dkim(domain, resolver, selectors, declarados=declarados, lang=lang)
    dmarc = check_dmarc(domain, resolver, lang)

    try:
        mx_records = resolver.mx(domain)
        mx = {
            "records": mx_records,
            "provider": mail_provider(mx_records),
            "google_workspace": any(
                host.endswith("google.com") or host.endswith("googlemail.com")
                for host in mx_records
            ),
            "error": None,
        }
    except DnsUnavailable as exc:
        mx = {"records": [], "provider": None, "google_workspace": None, "error": str(exc)}

    report: dict = {"domain": domain, "mx": mx}
    for key, result, verdict_fn in (
        ("spf", spf, spf_verdict),
        ("dkim", dkim, dkim_verdict),
        ("dmarc", dmarc, dmarc_verdict),
    ):
        status, summary = verdict_fn(result, lang)
        entry = asdict(result)
        entry["status"] = status
        entry["summary"] = summary
        report[key] = entry

    transport = check_transport(domain, resolver)
    transport_dict = asdict(transport)
    for key, verdict_fn in (
        ("mta_sts", mta_sts_verdict),
        ("tls_rpt", tls_rpt_verdict),
        ("dnssec", dnssec_verdict),
    ):
        status, summary = verdict_fn(transport, lang)
        report[key] = {
            "status": status,
            "summary": summary,
            "value": transport_dict.get(key),
            "record": transport_dict.get(f"{key}_record") or transport_dict.get(f"{key}_id"),
        }
    return report
