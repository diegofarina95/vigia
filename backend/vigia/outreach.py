"""Turn an email-auth report into a message you can send to a third party.

This is the private (tailnet-only) side of Vigía: you check a domain you do
not own, and email whoever is responsible for it a description of what its
public DNS records reveal.

Two rules shape everything here:

1. **Only public DNS is ever described.** Every claim in the message comes
   from a record anyone can resolve — SPF, DKIM, DMARC, MTA-STS, TLS-RPT,
   DNSSEC. Nothing is probed, no mailbox is touched, no login is attempted.
   The message says so explicitly, because the first question a stranger
   asks on receiving one of these is "how do you know that".
2. **The message identifies its sender and offers a way out.** Unsolicited
   mail to a business address needs both to be defensible (UK PECR / GDPR),
   and it is also what separates a useful heads-up from spam.

The prose is not re-invented here: `dns_email_auth` already produces a
plain-language summary per mechanism, and those are reused so the email and
the app can never drift apart. Everything this module adds — the mechanism
labels, the fixes and the message's own paragraphs — lives in the locale
catalogue under `email.outreach`, in both languages, and `lang` picks one.

Note that the per-mechanism `summary` comes in with the report, in whatever
language the DNS engine rendered it: asking for an English message does not
retranslate a Spanish summary that was handed to us already written.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .i18n import DEFAULT_LANG, text
from .wording import contar

# Only these two statuses are worth telling someone about. `pass` is noise
# in an outreach message and `undetermined` is not a claim we can defend.
OPEN = ("fail", "warn")

SEVERITY_RANK = {"fail": 0, "warn": 1}

#: The mechanisms, in the order they are reported. The label and the fix for
#: each one are `email.outreach.mecanismos.<key>` in the catalogue; keeping only
#: the keys here is what stops the list and the wording from disagreeing.
MECHANISMS = ("spf", "dkim", "dmarc", "mta_sts", "tls_rpt", "dnssec")


def _mecanismo(lang: str, key: str, campo: str) -> str:
    return text(lang, f"email.outreach.mecanismos.{key}.{campo}")


def _section(report: dict, key: str) -> dict:
    value = report.get(key)
    if value is None:
        return {}
    return value if isinstance(value, dict) else getattr(value, "__dict__", {})


def problems(report: dict, lang: str = DEFAULT_LANG) -> list[dict]:
    """The mechanisms worth reporting, worst first."""
    found = []
    for key in MECHANISMS:
        data = _section(report, key)
        status = data.get("status")
        if status not in OPEN:
            continue
        found.append(
            {
                "key": key,
                "label": _mecanismo(lang, key, "etiqueta"),
                "status": status,
                "summary": (data.get("summary") or "").strip(),
                "issues": [str(i) for i in (data.get("issues") or [])],
                # Short, concrete next step. Deliberately vendor-neutral: we do
                # not know what they use to send mail.
                "fix": _mecanismo(lang, key, "arreglo"),
            }
        )
    found.sort(key=lambda p: (SEVERITY_RANK.get(p["status"], 9), p["key"]))
    return found


def mail_provider(report: dict) -> str:
    mx = _section(report, "mx")
    return str(mx.get("provider") or "") if mx else ""


def subject_for(reports: list[dict], lang: str = DEFAULT_LANG) -> str:
    domains = [r.get("domain", "?") for r in reports]
    total = sum(len(problems(r, lang)) for r in reports)
    puntos = contar(lang, total, "email.outreach.puntos")
    if len(domains) == 1:
        return text(lang, "email.outreach.asunto_un_dominio", dominio=domains[0], puntos=puntos)
    return text(lang, "email.outreach.asunto_varios_dominios", n=len(domains), puntos=puntos)


def _rule(char: str = "-", width: int = 68) -> str:
    return char * width


def render_email(
    reports: list[dict],
    *,
    sender_name: str,
    sender_email: str,
    note: str = "",
    opt_out_to: str = "",
    lang: str = DEFAULT_LANG,
) -> str:
    """The plain-text body. Plain text on purpose: it lands in the inbox
    instead of the promotions tab, and it cannot carry a tracking pixel,
    which matters when the whole point is to be believed."""
    stamp = datetime.now(timezone.utc).strftime("%d/%m/%Y")
    domains = ", ".join(r.get("domain", "?") for r in reports)
    opt_out = opt_out_to or sender_email

    def t(clave: str, **params) -> str:
        return text(lang, f"email.outreach.{clave}", **params)

    out: list[str] = []
    out.append(t("saludo") + "\n\n" + t("intro", dominios=domains, fecha=stamp))
    if note.strip():
        out.append(_rule() + "\n" + note.strip())

    for report in reports:
        domain = report.get("domain", "?")
        items = problems(report, lang)
        provider = mail_provider(report)
        head = t("dominio", dominio=domain)
        if provider:
            head += t("proveedor", proveedor=provider)
        block = [_rule("="), head, _rule("=")]

        if not items:
            block.append(t("nada_que_senalar"))
        else:
            for n, item in enumerate(items, start=1):
                etiqueta = t(
                    "etiqueta_problema" if item["status"] == "fail" else "etiqueta_aviso"
                )
                block.append(f"\n{n}. [{etiqueta}] {item['label']}")
                if item["summary"]:
                    block.append(f"   {item['summary']}")
                for issue in item["issues"]:
                    block.append(f"   · {issue}")
                if item["fix"]:
                    block.append(t("como_se_arregla", arreglo=item["fix"]))
        out.append("\n".join(block))

    out.append(
        _rule("=")
        + "\n"
        + t("titulo_workspace")
        + "\n\n"
        + t("workspace_oferta")
        + "\n\n"
        + t("workspace_solo_lectura")
        + "\n\n"
        + t("workspace_sin_conectar_nada")
    )
    out.append(_rule() + "\n" + t("titulo_importa") + "\n\n" + t("cuerpo_importa"))
    out.append(
        _rule()
        + "\n"
        + t("firma", nombre=sender_name, correo=sender_email)
        + "\n"
        + t("baja", baja=opt_out)
        + "\n\n"
        + t("generado")
    )
    return "\n\n".join(out) + "\n"


def summarize(reports: list[dict]) -> dict:
    """Counts for the send log and the UI."""
    everything = [p for r in reports for p in problems(r)]
    return {
        "domains": [r.get("domain", "?") for r in reports],
        "problems": len(everything),
        "fail": sum(1 for p in everything if p["status"] == "fail"),
        "warn": sum(1 for p in everything if p["status"] == "warn"),
    }
