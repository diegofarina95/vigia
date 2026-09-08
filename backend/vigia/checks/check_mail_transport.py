"""Mail transport security and DNS integrity (MTA-STS, TLS-RPT, DNSSEC).
Spanish output.

Reuses the DNS reports already gathered for the email-auth check, so this
costs no extra lookups. Public DNS only — no Google API.
"""
from __future__ import annotations

from ..wording import con_numero

from .finding import ORG_SCOPE, Finding
from .util import cap_items

#: The data sources this module's findings rest on. `collect_findings`
#: demotes every verdict here to «no verificado» when any of them was read
#: incompletely — inherited, not remembered per check.
SOURCES = ()


CHECK_ID = "mail-transport"

_STATUS_ORDER = {"fail": 0, "warn": 1, "undetermined": 2, "pass": 3}

_STATUS_ES = {
    "fail": "fallo",
    "warn": "aviso",
    "undetermined": "no verificado",
    "pass": "correcto",
}

_ACTIONS = {
    "mail-mta-sts": ["publish_mta_sts"],
    "mail-tls-rpt": ["publish_tls_rpt"],
    "dns-dnssec": ["enable_dnssec"],
}

_MECHANISMS = (
    (
        "mta_sts",
        "mail-mta-sts",
        "medium",
        "MTA-STS (TLS obligatorio en el correo entrante)",
        "Publica una política MTA-STS: un registro TXT en «_mta-sts» más un fichero de política "
        "en https://mta-sts.<dominio>/.well-known/mta-sts.txt con tus servidores MX. Empieza en "
        "modo «testing» y pasa después a «enforce».",
        "CIS GWS §3 (Gmail) — Exigir TLS en el correo en tránsito",
    ),
    (
        "tls_rpt",
        "mail-tls-rpt",
        "low",
        "TLS-RPT (informes de fallos de TLS)",
        "Publica un registro TXT en «_smtp._tls»: «v=TLSRPTv1; rua=mailto:tls@<dominio>» para "
        "enterarte cuando falle la entrega con TLS hacia tu dominio.",
        "CIS GWS §3 (Gmail) — Vigilar la seguridad del transporte de correo",
    ),
    (
        "dnssec",
        "dns-dnssec",
        "medium",
        "DNSSEC (DNS firmado)",
        "Activa DNSSEC en tu proveedor de DNS (en Cloudflare es un solo interruptor) y añade el "
        "registro DS en tu registrador. Sin DNSSEC, tus propios registros SPF, DKIM y DMARC se "
        "pueden falsificar.",
        "CIS GWS — Proteger la integridad del DNS",
    ),
)


def run(ctx) -> list[Finding]:
    reports = ctx.email_auth_reports()
    if not reports:
        return []

    findings: list[Finding] = []
    for key, finding_id, severity, title, remediation, cis in _MECHANISMS:
        worst = "pass"
        per_domain: list[str] = []
        for report in reports:
            entry = report.get(key)
            if not entry:
                continue
            per_domain.append(f"{report['domain']}: {entry['summary']}")
            if _STATUS_ORDER[entry["status"]] < _STATUS_ORDER[worst]:
                worst = entry["status"]

        if not per_domain:
            continue

        plural = "s" if len(per_domain) != 1 else ""
        findings.append(
            Finding(
                scope_type=ORG_SCOPE,
                id=finding_id,
                title=f"{title} en {len(per_domain)} dominio{plural}",
                severity=severity,
                status=worst,
                description=(
                    "Comprobado contra el DNS público en cada dominio configurado. "
                    f"Peor resultado: {_STATUS_ES[worst]}."
                ),
                affected_items=cap_items(per_domain),
                remediation=remediation,
                admin_console_url="https://admin.google.com/ac/apps/gmail",
                cis_control=cis,
                scope_label=f"{con_numero(len(per_domain), "dominio configurado", "dominios configurados")}, por DNS público",
                remediation_actions=_ACTIONS.get(finding_id, []),
                i18n_params={"domains": len(per_domain), "worst_status": worst},
                details={"domains": {r["domain"]: r.get(key) for r in reports if r.get(key)}},
            )
        )
    return findings
