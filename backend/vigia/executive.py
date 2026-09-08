"""The first page: what a stranger reads before deciding whether to call you.

The rest of the report is written for the administrator who will do the work.
This page is written for the person who decides whether the work happens. They
are not going to read twenty pages of an unsolicited PDF from someone they have
never met, and if the first thing they see is forty-five findings sorted by
severity, they close it.

One job: **readable in a minute, and enough to decide whether to phone
somebody.** Three numbers, the three worst things in a sentence each, the three
cheapest fixes, and what happens if nobody does anything.

The sentences deliberately avoid the vocabulary of the trade. Not "three super
admins without 2SV enrolment" but "three accounts that control the whole
company's email have no second lock on the door". A finance director knows what
losing the company's email means; they do not know what enrolment is, and a
sentence they have to decode is a sentence they skip.

That rule holds in both languages, and the sentences themselves live in the
bilingual catalogue (`executive.*`) rather than as f-strings here: this is the page
that gets forwarded, and English scaffolding around a Spanish cover — or the other
way round — is the same defect one layer out.
"""
from __future__ import annotations

from .wording import con_numero, contar

from .i18n import DEFAULT_LANG, text
from .scoring import SEVERITY_WEIGHTS, is_inventory, is_org_scope

#: The findings that have a hand-written plain sentence, worst first.
#:
#: The sentences themselves live in the bilingual catalogue, under
#: `executive.plain.<id>`; what stays here is the LIST and its order, because both
#: are logic rather than text: membership decides which findings get a written
#: sentence instead of a composed one, and the order below breaks ties in the
#: ranking (see `_PRIORIDAD`).
#:
#: The placeholders those sentences take are pre-agreed phrases, not bare numbers:
#: `{cuentas}` arrives as "1 cuenta" / "3 accounts", because the noun has to agree
#: with the count and a template cannot do that. `{n}` is still available for a
#: bare number where no noun follows it. Only the findings that can realistically
#: reach the top three are written by hand; everything else composes a serviceable
#: sentence from its own title.
PLAIN: tuple[str, ...] = (
    "composite-superadmin-no-2sv-no-recovery",
    "composite-superadmin-dormant-no-2sv",
    "composite-superadmin-no-2sv",
    "recovery-super-admins",
    "composite-enforced-but-not-enrolled",
    "composite-dormant-no-2sv",
    "composite-service-account-no-2sv",
    "composite-superadmin-dormant",
    "2sv-users",
    "admin-login-new-country",
    "policy-2sv-methods",
    "policy-gmail-forwarding",
    "policy-drive-sharing",
    "policy-password",
    "policy-marketplace",
    "policy-groups-sharing",
    "oauth-high-risk",
    "oauth-dwd",
    "email-spf",
    "email-dmarc",
    "audit-risky-changes",
    "super-admin-count",
)

#: PLAIN is written worst-first on purpose, so its order breaks ties. Three
#: findings about the same three super admins have the same severity, the same
#: status and the same count; without this the alphabet decided which one the
#: customer read, and "dormant without 2SV" beat "no 2SV and no way back" by
#: virtue of the letter d. The order here is an editorial judgement and is
#: meant to be argued with, which is more than the alphabet offered.
_PRIORIDAD = {fid: index for index, fid in enumerate(PLAIN)}


#: What each finding is ABOUT. Two lines that say "the super admins have no
#: safe way back" and "the super admins have no second factor" are one point
#: made twice, and they push out the two settings that are wide open. The
#: cover has three lines; it should spend them on three subjects.
TEMA: dict[str, str] = {
    "composite-superadmin-no-2sv-no-recovery": "acceso-privilegiado",
    "composite-superadmin-dormant-no-2sv": "acceso-privilegiado",
    "composite-superadmin-no-2sv": "acceso-privilegiado",
    "composite-superadmin-dormant": "acceso-privilegiado",
    "recovery-super-admins": "acceso-privilegiado",
    "super-admin-count": "acceso-privilegiado",
    "composite-enforced-but-not-enrolled": "segundo-factor",
    "composite-dormant-no-2sv": "segundo-factor",
    "composite-service-account-no-2sv": "segundo-factor",
    "2sv-users": "segundo-factor",
    "policy-2sv-methods": "segundo-factor",
    "2sv-backup-codes": "segundo-factor",
    "admin-login-new-country": "accesos-sospechosos",
    "audit-risky-changes": "cambios-sin-vigilar",
    "alert-rules": "cambios-sin-vigilar",
    "policy-gmail-forwarding": "salida-de-datos",
    "policy-drive-sharing": "salida-de-datos",
    "policy-groups-sharing": "salida-de-datos",
    "policy-calendar-secondary": "salida-de-datos",
    "oauth-high-risk": "terceros",
    "oauth-dwd": "terceros",
    "suspended-with-tokens": "terceros",
    "policy-marketplace": "terceros",
    "email-spf": "suplantacion",
    "email-dmarc": "suplantacion",
    "policy-password": "contrasenas",
}


#: Never the headline. An inventory names people without accusing them, and a
#: DNS niceness is not what you phone somebody about.
NEVER_HEADLINE = frozenset({"super-admin-count", "delegated-admins", "admin-login-countries"})


def _count(finding: dict) -> int:
    accounts = finding.get("accounts") or []
    if accounts:
        return len(accounts)
    details = finding.get("details") or {}
    for key in ("exposed", "flagged", "affected"):
        value = details.get(key)
        if isinstance(value, int) and value:
            return value
    return len(finding.get("affected_items") or [])


def plain_sentence(finding: dict, lang: str = DEFAULT_LANG) -> str:
    """One sentence a non-technical reader can act on."""
    n = _count(finding)
    fid = finding.get("id", "")
    if fid in PLAIN:
        # Agreement happens here, once, rather than in eight templates that cannot
        # see the number. These strings used to print "1 cuenta(s)".
        return text(
            lang,
            f"executive.plain.{fid}",
            n=n,
            cuentas=con_numero(
                n, text(lang, "executive.cuenta"), text(lang, "executive.cuentas")
            ),
            compartidas=con_numero(
                n,
                text(lang, "executive.cuenta_compartida"),
                text(lang, "executive.cuentas_compartidas"),
            ),
        )
    # Serviceable rather than clever: the title already says what it is, and
    # inventing prose for a finding nobody wrote a sentence for risks saying
    # something untrue about the customer.
    titulo = (finding.get("title") or fid).rstrip(".")
    if n:
        return text(lang, "executive.frase_generica", titulo=titulo, n=n)
    return f"{titulo}."


def headline_findings(findings: list[dict], limit: int = 3) -> list[dict]:
    """The worst few, worst first. Organization settings and account findings
    compete on the same list on purpose: the reader does not care which of the
    two buckets a problem came from, only how bad it is."""
    abiertos = [
        f
        for f in findings
        if f.get("status") in ("fail", "warn")
        and not f.get("manual")
        and f.get("id") not in NEVER_HEADLINE
        and not is_inventory(f)
        and SEVERITY_WEIGHTS.get(f.get("severity"), 0) > 0
    ]
    def peso(f: dict) -> float:
        """Severity, discounted for a warning — the same 50% the score uses.

        Ranking on raw severity put a critical WARNING ("somebody changed a
        setting, probably fine") above outright failures like "the internal
        mailing lists are readable from outside". A warning is by definition
        something that might be nothing; a failure is something that is.
        """
        bruto = SEVERITY_WEIGHTS.get(f.get("severity"), 0)
        return bruto * (0.5 if f.get("status") == "warn" else 1.0)

    abiertos.sort(
        key=lambda f: (
            -peso(f),
            f.get("status") != "fail",
            _PRIORIDAD.get(f.get("id", ""), len(_PRIORIDAD)),
            -_count(f),
            f.get("id", ""),
        )
    )

    # Three lines, three different things. The composites overlap by design —
    # "super admin without 2SV", "super admin dormant without 2SV" and "super
    # admin with bad recovery" can be the same three people — and a summary
    # that spends all three lines on one group of accounts tells the reader
    # about a third of what it could. A candidate whose people are already
    # covered by a worse line is dropped.
    def escoger(permitir_repetir_tema: bool) -> list[dict]:
        elegidos: list[dict] = []
        cubiertos: set[str] = set()
        temas: set[str] = set()
        for finding in abiertos:
            fid = finding.get("id", "")
            tema = TEMA.get(fid, fid)
            if not permitir_repetir_tema and tema in temas:
                continue
            cuentas = {a.lower() for a in (finding.get("accounts") or [])}
            if cuentas and cuentas <= cubiertos:
                continue
            elegidos.append(finding)
            cubiertos |= cuentas
            temas.add(tema)
            if len(elegidos) == limit:
                break
        return elegidos

    # First pass insists on three different subjects. If the tenant genuinely
    # has fewer than three, repeating is better than showing two lines.
    elegidos = escoger(permitir_repetir_tema=False)
    if len(elegidos) < limit:
        vistos = {id(f) for f in elegidos}
        for extra in escoger(permitir_repetir_tema=True):
            if id(extra) not in vistos and len(elegidos) < limit:
                elegidos.append(extra)
                vistos.add(id(extra))
    return elegidos


def closing_line(findings: list[dict], people: list[dict], lang: str = DEFAULT_LANG) -> str:
    """What happens if nobody does anything. Concrete, and never a threat: the
    reader can check every clause of it against the pages that follow."""
    # Same criterion as the figure above it: open criticals, failures and
    # warnings alike. Counting differently in two paragraphs of the same page
    # is how the cover ended up arguing with itself.
    criticos = sum(
        1
        for f in findings
        if f.get("severity") == "critical"
        and f.get("status") in ("fail", "warn")
        and not f.get("manual")
    )
    ajustes = sum(
        1
        for f in findings
        if f.get("status") in ("fail", "warn") and is_org_scope(f) and not f.get("manual")
    )

    if not criticos and not people:
        return text(lang, "executive.cierre_limpio")
    if criticos:
        return text(lang, "executive.cierre_criticos", criticos=criticos, ajustes=ajustes)
    # Both counts agree with their own nouns before the sentence sees them, and the
    # sentence itself changes when there is nothing loose on the organisation side —
    # "y 0 ajustes de la organización sin apretar" is a true statement written as if
    # it were a problem.
    cuentas = contar(lang, len(people), "executive.cuentas_expuestas")
    if not ajustes:
        return text(lang, "executive.cierre_sin_criticos_sin_ajustes", cuentas=cuentas)
    return text(
        lang,
        "executive.cierre_sin_criticos",
        cuentas=cuentas,
        ajustes=contar(lang, ajustes, "executive.ajustes_flojos"),
    )


def summary(
    findings: list[dict],
    people: list[dict],
    score,
    actions: list[dict],
    lang: str = DEFAULT_LANG,
) -> dict:
    """Everything the first page needs, computed once so the page and any
    future channel (email digest, API) cannot drift apart."""
    criticos = [
        f
        for f in findings
        if f.get("severity") == "critical"
        and f.get("status") in ("fail", "warn")
        and not f.get("manual")
    ]
    abiertos_criticos = len(criticos)
    fallos_criticos = sum(1 for f in criticos if f.get("status") == "fail")

    return {
        "score": score,
        "people_at_risk": len(people),
        # The body counts open findings — failures AND warnings — per
        # severity. The cover used to count only failures, so it said "4
        # critical" on page one and the reader turned to "5 crítico" on page
        # two. Same criterion now, and the split is spelled out instead of
        # left for the reader to reconcile.
        "critical": abiertos_criticos,
        "critical_failing": fallos_criticos,
        "critical_label": (
            text(lang, "executive.criticos", n=abiertos_criticos)
            + (
                text(
                    lang,
                    "executive.criticos_desglose",
                    fallos=fallos_criticos,
                    avisos=abiertos_criticos - fallos_criticos,
                )
                if abiertos_criticos != fallos_criticos
                else text(lang, "executive.criticos_en_fallo")
            )
            if abiertos_criticos
            else text(lang, "executive.ninguno_critico")
        ),
        "headlines": [
            {
                "id": f.get("id"),
                "severity": f.get("severity"),
                "sentence": plain_sentence(f, lang),
            }
            for f in headline_findings(findings)
        ],
        "actions": [
            {
                "title": a.get("title", ""),
                "minutes": a.get("minutes"),
                "findings_closed": a.get("findings_closed"),
            }
            for a in (actions or [])[:3]
        ],
        "closing": closing_line(findings, people, lang),
    }
