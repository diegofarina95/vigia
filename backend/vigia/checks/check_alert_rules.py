"""Is anybody actually listening?

Google ships around sixty system-defined alert rules — someone changed the
Drive sharing settings, a device was compromised, a suspicious login happened.
Every one of them can be switched off, and every one of them can be left on
while notifying nobody, in which case it files a card in a console nobody has
open.

That is the finding this module exists for, and it is the one that justifies a
monitoring retainer more plainly than anything else in the report: *Google
would tell you. There is nobody on the other end.*

Two distinct failures, kept apart because they are fixed differently:

* **switched off** — the rule will not fire at all;
* **on but silent** — the rule fires into the Alert Center and no e-mail goes
  anywhere, so it is seen only by whoever happens to look.

Read from `rule.system_defined_alerts` in the Policy API, which is already
wired: no new scope, no new call.
"""
from __future__ import annotations

from .finding import ORG_SCOPE, Finding
from .util import cap_items

#: The data sources this module's findings rest on. `collect_findings`
#: demotes every verdict here to «no verificado» when any of them was read
#: incompletely — inherited, not remembered per check.
SOURCES = ('policies',)


CHECK_ID = "alert-rules"

SETTING = "rule.system_defined_alerts"
CONSOLE_URL = "https://admin.google.com/ac/ac/rules"
CIS = "CIS GWS §1 — Activar y encaminar las alertas de seguridad"

#: Not every rule is worth an argument. Google's billing and legal
#: announcements are noise for this purpose; these are the ones that tell you
#: somebody touched security, and switching them off is a decision worth
#: surfacing by name.
SEGURIDAD = (
    "settings changed", "suspicious", "compromised", "leaked", "phishing",
    "malware", "exfiltration", "hijack", "admin", "2-step", "two-step",
    "password", "sharing", "device", "government-backed", "spike",
)


def _rules(policies: list[dict]) -> list[dict]:
    return [
        (p.get("setting") or {}).get("value") or {}
        for p in policies or []
        if str((p.get("setting") or {}).get("type", "")).endswith(SETTING)
    ]


def _recipients(rule: dict) -> list[dict]:
    action = (rule.get("action") or {}).get("alertCenterAction") or {}
    return action.get("recipients") or []


def _is_security(rule: dict) -> bool:
    texto = f"{rule.get('displayName', '')} {rule.get('description', '')}".lower()
    return any(marker in texto for marker in SEGURIDAD)


def run(ctx) -> list[Finding]:
    try:
        policies = ctx.policies()
    except Exception:  # noqa: BLE001 — the policy card already explains why
        return []

    rules = _rules(policies)
    if not rules:
        # Not the same as "none configured": the tenant may simply not return
        # them, and claiming nobody is watching would be an accusation built
        # on an absence.
        return [
            Finding(
                id="alert-rules",
                title="Reglas de alerta de seguridad",
                severity="medium",
                status="undetermined",
                description=(
                    "No se ha podido leer ninguna regla de alerta, así que no se puede decir "
                    "si alguien está vigilando. Compruébalo en Reglas > Reglas definidas por "
                    "el sistema."
                ),
                remediation="Revisa las reglas en la Consola de Administración > Reglas.",
                admin_console_url=CONSOLE_URL,
                cis_control=CIS,
                scope_label="reglas de alerta del tenant",
                scope_type=ORG_SCOPE,
                i18n_variant="undetermined",
            )
        ]

    apagadas = [r for r in rules if str(r.get("state", "")).upper() != "ACTIVE"]
    mudas = [r for r in rules if str(r.get("state", "")).upper() == "ACTIVE" and not _recipients(r)]
    apagadas_seguridad = [r for r in apagadas if _is_security(r)]
    mudas_seguridad = [r for r in mudas if _is_security(r)]

    lineas = [f"APAGADA — {r.get('displayName', '?')}" for r in apagadas_seguridad]
    lineas += [f"activa pero sin avisar a nadie — {r.get('displayName', '?')}" for r in mudas_seguridad]
    lineas += [f"APAGADA — {r.get('displayName', '?')}" for r in apagadas if r not in apagadas_seguridad]

    if apagadas_seguridad:
        status, severity = "fail", "medium"
    elif apagadas or mudas:
        status, severity = "warn", "medium"
    else:
        status, severity = "pass", "medium"

    activas = len(rules) - len(apagadas)
    if status == "pass":
        description = (
            f"Las {len(rules)} reglas de alerta del sistema están activas y todas avisan a "
            "alguien. Google detecta el incidente y hay quien lo recibe."
        )
    else:
        description = (
            f"De las {len(rules)} reglas de alerta que trae Google, {activas} están activas y "
            f"{len(apagadas)} apagadas"
            + (f", y {len(mudas)} de las activas no avisan a nadie" if mudas else "")
            + ".\n\nEsto es lo que separa «Google lo detectaría» de «alguien se enteraría». "
            "Una regla apagada no llega a dispararse. Una regla activa sin destinatario "
            "deja una tarjeta en el Centro de alertas, que es una pantalla que nadie tiene "
            "abierta un martes por la tarde."
        )
        if apagadas_seguridad:
            description += (
                f"\n\nDe las apagadas, {len(apagadas_seguridad)} son de seguridad: avisan "
                "precisamente de que alguien ha tocado la configuración o de que una cuenta "
                "está en apuros. Son las que este informe señala en otras páginas, y ahora "
                "mismo nadie las está escuchando."
            )

    return [
        Finding(
            id="alert-rules",
            title="Reglas de alerta de seguridad: quién se entera",
            severity=severity,
            status=status,
            description=description,
            affected_items=cap_items(lineas),
            remediation=(
                "Consola de Administración > Reglas > Reglas definidas por el sistema. "
                "Activa al menos las de cambios de configuración, cuentas comprometidas, "
                "acceso sospechoso y dispositivos, y ponles un destinatario real: una lista "
                "de correo que alguien lea, no solo «todos los superadministradores» si esa "
                "bandeja no la mira nadie."
            ),
            admin_console_url=CONSOLE_URL,
            cis_control=CIS,
            scope_label="reglas de alerta del tenant",
            scope_type=ORG_SCOPE,
            i18n_variant="" if status != "pass" else "clean",
            i18n_params={
                "total": len(rules),
                "active": activas,
                "off": len(apagadas),
                "silent": len(mudas),
            },
            details={
                "total_rules": len(rules),
                "active": activas,
                "inactive": len(apagadas),
                "active_without_recipients": len(mudas),
                "security_rules_off": len(apagadas_seguridad),
            },
        )
    ]
