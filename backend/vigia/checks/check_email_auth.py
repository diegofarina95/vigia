"""Email authentication (SPF / DKIM / DMARC) for every configured domain —
public DNS only, no Google API. Spanish output."""
from __future__ import annotations

from ..wording import con_numero

from .finding import ORG_SCOPE, Finding
from .util import cap_items

#: The data sources this module's findings rest on. `collect_findings`
#: demotes every verdict here to «no verificado» when any of them was read
#: incompletely — inherited, not remembered per check.
SOURCES = ()


CHECK_ID = "email-auth"

CONSOLE_URL = "https://admin.google.com/ac/apps/gmail/authenticateemail"

_STATUS_ORDER = {"fail": 0, "warn": 1, "undetermined": 2, "pass": 3}

# finding id -> remediation action id (drives the "Fix this first" block)
_ACTIONS = {
    "email-spf": ["publish_spf"],
    "email-dkim": ["enable_dkim"],
    "email-dmarc": ["publish_dmarc"],
}

_MECHANISMS = (
    # (key, finding id, severity, title, remediation, cis label)
    (
        "spf",
        "email-spf",
        "high",
        "Registros SPF",
        "Publica un registro TXT del tipo «v=spf1 include:_spf.google.com ~all» en cada dominio "
        "que envíe correo, mantén un único registro y termínalo en ~all o -all. Vigila también "
        "el límite de 10 consultas DNS del RFC 7208.",
        "CIS GWS §3 (Gmail) — Configurar SPF",
    ),
    (
        "dkim",
        "email-dkim",
        "medium",
        "Firma DKIM",
        "Genera una clave DKIM en la Consola de Administración (Aplicaciones > Google Workspace "
        "> Gmail > Autenticar el correo electrónico), publica el registro DNS y pulsa «Iniciar "
        "autenticación». Solo se comprueba el selector «google», que es el que usa Workspace: "
        "si firmas con un selector propio, escríbeme a diego@diegofarina.com y lo verificamos "
        "a mano.",
        "CIS GWS §3 (Gmail) — Configurar DKIM",
    ),
    (
        "dmarc",
        "email-dmarc",
        "high",
        "Política DMARC",
        "Publica un TXT en «_dmarc» empezando por «v=DMARC1; p=none; rua=mailto:…» para recoger "
        "informes y después endurece a p=quarantine y finalmente p=reject.",
        "CIS GWS §3 (Gmail) — Configurar DMARC",
    ),
)

_STATUS_ES = {
    "fail": "fallo",
    "warn": "aviso",
    "undetermined": "no verificado",
    "pass": "correcto",
}


def run(ctx) -> list[Finding]:
    reports = ctx.email_auth_reports()
    if not reports:
        return [
            Finding(
                scope_type=ORG_SCOPE,
                id="email-auth",
                title="Autenticación del correo (SPF/DKIM/DMARC)",
                severity="high",
                status="undetermined",
                description=(
                    "Todavía no hay dominios configurados, así que no se ha comprobado nada. "
                    "Los dominios se sincronizan solos desde Workspace en cada escaneo y se "
                    "verifican contra el DNS público; si esto sigue vacío después de escanear, "
                    "escríbeme a diego@diegofarina.com."
                ),
                remediation="Vuelve a escanear: los dominios se sincronizan desde Workspace.",
                scope_label="dominios configurados",
                i18n_variant="nodomains",
                admin_console_url=CONSOLE_URL,
            )
        ]

    findings: list[Finding] = []
    for key, finding_id, severity, title, remediation, cis in _MECHANISMS:
        worst = "pass"
        per_domain: list[str] = []
        for report in reports:
            entry = report[key]
            per_domain.append(f"{report['domain']}: {entry['summary']}")
            if _STATUS_ORDER[entry["status"]] < _STATUS_ORDER[worst]:
                worst = entry["status"]

        plural = "s" if len(reports) != 1 else ""
        findings.append(
            Finding(
                scope_type=ORG_SCOPE,
                id=finding_id,
                title=f"{title} en {len(reports)} dominio{plural}",
                severity=severity,
                status=worst,
                description=(
                    "Comprobado contra el DNS público en cada dominio configurado. "
                    f"Peor resultado: {_STATUS_ES[worst]}."
                ),
                affected_items=cap_items(per_domain),
                remediation=remediation,
                admin_console_url=CONSOLE_URL,
                cis_control=cis,
                scope_label=f"{con_numero(len(reports), "dominio configurado", "dominios configurados")}, por DNS público",
                remediation_actions=_ACTIONS.get(finding_id, []),
                i18n_params={"domains": len(reports), "worst_status": worst},
                details={"domains": {r["domain"]: r[key] for r in reports}},
            )
        )

    findings.extend(_comodin(reports))
    findings.extend(_clave_mal_ubicada(reports))
    return findings


def _comodin(reports: list[dict]) -> list[Finding]:
    """A TXT wildcard makes "does not exist" impossible to distinguish from "exists".

    Every DKIM selector answers, so no selector proves anything; and a mail client
    looking for the MTA-STS policy finds a TXT that is not one instead of finding
    nothing, which is a worse failure than the absence it replaces. No online tool
    reports this.
    """
    afectados = [r["domain"] for r in reports if (r.get("dkim") or {}).get("wildcard")]
    if not afectados:
        return []
    return [
        Finding(
            scope_type=ORG_SCOPE,
            id="dns-wildcard-txt",
            title=f"Comodín TXT en el DNS de {con_numero(len(afectados), 'dominio')}",
            severity="medium",
            status="fail",
            description=(
                "El DNS de estos dominios responde a consultas TXT de nombres que no existen, "
                "porque hay un registro comodín. Eso hace que cualquier selector DKIM "
                "«responda» sin que haya ninguna clave, y que un cliente que busque la política "
                "MTA-STS encuentre un TXT que no lo es en lugar de no encontrar nada. "
                "Las comprobaciones de este informe validan el contenido, no la existencia, "
                "así que no se dejan engañar; otras herramientas sí."
            ),
            affected_items=cap_items(afectados),
            remediation=(
                "Quita el registro comodín (*) de los TXT de la zona y publica cada TXT en su "
                "nombre concreto. Si el comodín está para verificar un servicio, sustitúyelo por "
                "el registro exacto que ese servicio pide."
            ),
            scope_label=f"{con_numero(len(afectados), 'dominio')}, por DNS público",
            i18n_params={"domains": len(afectados)},
        )
    ]


def _clave_mal_ubicada(reports: list[dict]) -> list[Finding]:
    """A `v=DKIM1` record published at the domain apex, where nothing reads it.

    A verifier looks the key up at `<selector>._domainkey.<domain>`. At the root it
    is invisible, so mail signed with it fails verification exactly as if no key
    existed — and nothing anywhere reports the mistake.
    """
    afectados = [
        f"{r['domain']}: clave publicada en la raíz, junto al SPF"
        for r in reports
        if (r.get("spf") or {}).get("dkim_en_raiz")
    ]
    if not afectados:
        return []
    return [
        Finding(
            scope_type=ORG_SCOPE,
            id="dkim-key-misplaced",
            title=f"Clave DKIM en el nombre equivocado en {con_numero(len(afectados), 'dominio')}",
            severity="low",
            status="fail",
            description=(
                "Hay una clave DKIM publicada entre los TXT de la raíz del dominio, junto al "
                "SPF, en lugar de en «selector._domainkey». Ahí no la lee ningún verificador: "
                "es una clave muerta. No hace daño, pero quien la publicó cree tener firmado "
                "algo que no lo está."
            ),
            affected_items=cap_items(afectados),
            remediation=(
                "Publica la clave en «<selector>._domainkey.<dominio>» y borra el TXT de la "
                "raíz. Si ya hay otra clave funcionando en su selector correcto, basta con "
                "borrar la de la raíz."
            ),
            scope_label=f"{con_numero(len(afectados), 'dominio')}, por DNS público",
            i18n_params={"domains": len(afectados)},
        )
    ]
