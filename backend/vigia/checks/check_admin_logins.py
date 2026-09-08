"""Where the super admins sign in from, and what is new about it.

The Admin console draws a location column next to every sign-in, so it looks
like the audit log carries one. It does not — the login activity events give
`ipAddress`, `is_suspicious`, `login_type` and `login_challenge_method`, and
nothing geographic. The country here comes from an offline database (see
`vigia.geoip`), so no address ever leaves this server.

What this check is for: a super admin's account is the whole tenant. The
single cheapest signal that one has been taken over is that it started signing
in from somewhere it never had. Not "a risky country" — that is a stereotype,
not a control, and a Spanish company with a developer in Argentina would light
up every week for nothing. **New** is the signal. A country that appears for
the first time in the recent window, on an account that has months of history
somewhere else, is worth a phone call.

Three honesty rules:

* With no geo database installed the check still runs and still spots new
  *networks*; it just says "unknown" instead of inventing a country.
* A tenant whose whole history fits inside the recent window has no baseline
  to compare against, so nothing can be "new" and the check says so rather
  than flagging everything.
* The addresses and countries are personal data about the admins, so they are
  covered by the 24-hour purge like any other.
"""
from __future__ import annotations

from ..wording import con_numero

from collections import defaultdict
from datetime import timedelta

from .. import geoip
from .finding import Finding
from .roles import super_admins
from .util import cap_items, is_active, parse_google_time, utcnow

#: The data sources this module's findings rest on. `collect_findings`
#: demotes every verdict here to «no verificado» when any of them was read
#: incompletely — inherited, not remembered per check.
SOURCES = ('users', 'login')


CHECK_ID = "admin-logins"

CONSOLE_URL = "https://admin.google.com/ac/reporting/audit/login"
CIS = "CIS GWS §1 — Vigilar los inicios de sesión de las cuentas privilegiadas"

#: A country seen for the first time inside this window, on an account with
#: history before it, is what gets reported.
RECENT_DAYS = 14
#: Below this, the log is too short to tell "new" from "the only thing there".
MIN_BASELINE_DAYS = 21

SUCCESS_EVENTS = ("login_success", "login_verification", "login_challenge")


def _events_for(items: list[dict], addresses: set[str]) -> list[dict]:
    """Successful sign-ins by the accounts we care about, newest first."""
    out = []
    for item in items or []:
        actor = ((item.get("actor") or {}).get("email") or "").lower()
        if actor not in addresses:
            continue
        when = parse_google_time((item.get("id") or {}).get("time"))
        ip = (item.get("ipAddress") or "").strip()
        if when is None or not ip:
            continue
        names = {(e.get("name") or "").lower() for e in item.get("events") or []}
        if not any(n in names for n in SUCCESS_EVENTS):
            continue
        suspicious = any(
            (p.get("name") == "is_suspicious" and p.get("boolValue") is True)
            for e in item.get("events") or []
            for p in e.get("parameters") or []
        )
        login_type = next(
            (
                str(p.get("value"))
                for e in item.get("events") or []
                for p in e.get("parameters") or []
                if p.get("name") == "login_type"
            ),
            "",
        )
        out.append(
            {"actor": actor, "ip": ip, "when": when,
             "suspicious": suspicious, "login_type": login_type}
        )
    out.sort(key=lambda e: e["when"], reverse=True)
    return out


def _summarize(events: list[dict], cutoff) -> dict:
    """Per account: which countries, since when, and which are only recent."""
    by_actor: dict[str, dict] = defaultdict(
        lambda: {"countries": defaultdict(lambda: {"first": None, "last": None, "count": 0}),
                 "unknown_ips": set(), "suspicious": 0, "password_logins": 0, "total": 0}
    )
    for event in events:
        entry = by_actor[event["actor"]]
        entry["total"] += 1
        entry["suspicious"] += 1 if event["suspicious"] else 0
        if event["login_type"] == "google_password":
            entry["password_logins"] += 1

        code = geoip.country(event["ip"])
        if code is None:
            entry["unknown_ips"].add(event["ip"])
            continue
        seen = entry["countries"][code]
        seen["count"] += 1
        if seen["first"] is None or event["when"] < seen["first"]:
            seen["first"] = event["when"]
        if seen["last"] is None or event["when"] > seen["last"]:
            seen["last"] = event["when"]

    for entry in by_actor.values():
        entry["new_countries"] = sorted(
            code for code, seen in entry["countries"].items()
            if seen["first"] is not None and seen["first"] >= cutoff
        )
    return by_actor


def _label(code: str) -> str:
    return f"{geoip.country_name(code)} ({code})"


def run(ctx) -> list[Finding]:
    users = [u for u in ctx.users() if is_active(u)]
    admins = {u["primaryEmail"].lower() for u in super_admins(users) if u.get("primaryEmail")}
    if not admins:
        return []

    try:
        activities = ctx.login_events()
    except Exception:  # noqa: BLE001 — the scan must survive one API hiccup
        activities = None

    if not activities:
        return [
            Finding(
                id="admin-login-countries",
                title="Países desde los que entran los superadministradores",
                severity="info",
                status="undetermined",
                description=(
                    "No se ha podido leer el registro de inicios de sesión, así que no se "
                    "puede decir desde dónde entran las cuentas con más privilegios."
                ),
                remediation="Comprueba que la cuenta conectada tiene privilegios de Informes.",
                admin_console_url=CONSOLE_URL,
                cis_control=CIS,
                scope_label="superadministradores",
                # Sin variante, el catálogo pisaría este texto con el del caso
                # normal y diría «3 de 3 superadministradores tienen accesos»
                # justo cuando no se ha podido leer ni uno.
                i18n_variant="undetermined",
            )
        ]

    events = _events_for(activities, admins)
    now = utcnow()
    cutoff = now - timedelta(days=RECENT_DAYS)
    summary = _summarize(events, cutoff)

    has_geoip = geoip.available()
    oldest = min((e["when"] for e in events), default=None)
    baseline_days = (now - oldest).days if oldest else 0
    has_baseline = baseline_days >= MIN_BASELINE_DAYS

    lines: list[str] = []
    flagged: list[str] = []
    unknown_only: list[str] = []
    for actor in sorted(summary):
        entry = summary[actor]
        países = sorted(entry["countries"], key=lambda c: -entry["countries"][c]["count"])
        if países:
            detalle = ", ".join(
                f"{_label(c)}×{entry['countries'][c]['count']}" for c in países[:6]
            )
        else:
            detalle = "sin país determinable"
            unknown_only.append(actor)
        marca = ""
        if has_baseline and entry["new_countries"]:
            marca = "  ← NUEVO: " + ", ".join(_label(c) for c in entry["new_countries"])
            flagged.append(actor)
        if entry["unknown_ips"] and países:
            detalle += f", {con_numero(len(entry['unknown_ips']), "IP")} sin ubicar"
        lines.append(f"{actor}: {detalle}{marca}")

    findings = [
        Finding(
            id="admin-login-countries",
            title="Países desde los que entran los superadministradores",
            severity="info",
            status="pass",
            description=(
                f"{len(summary)} de {len(admins)} superadministradores tienen accesos en el "
                f"registro, sobre una ventana de {con_numero(baseline_days, 'día')}.\n\nEs un inventario, "
                "no un fallo: sirve para que reconozcas de un vistazo desde dónde se entra "
                "normalmente a las cuentas que controlan todo el tenant. El país sale de una "
                "base de datos local; ninguna dirección IP sale de este servidor."
                if has_geoip else
                f"{len(summary)} de {len(admins)} superadministradores tienen accesos en el "
                f"registro, sobre una ventana de {con_numero(baseline_days, 'día')}.\n\nNo hay base de datos "
                "de países instalada, así que se listan las direcciones IP sin traducir a país. "
                "El inventario sigue sirviendo para reconocer desde qué redes se entra "
                "normalmente. Ejecuta scripts/fetch_geoip.py para añadir los países."
            ),
            affected_items=cap_items(lines),
            remediation=(
                "Repasa la lista con quien corresponda: lo que importa no es el país en sí, "
                "sino que cuadre con dónde trabaja de verdad esa persona."
            ),
            admin_console_url=CONSOLE_URL,
            cis_control=CIS,
            scope_label="superadministradores",
            i18n_variant="" if has_geoip else "no-geodb",
            i18n_params={
                "admins": len(admins), "days": baseline_days, "seen": len(summary),
            },
            details={
                "window_days": baseline_days,
                "geoip_available": has_geoip,
                "admins_with_logins": len(summary),
                "admins_total": len(admins),
            },
        )
    ]

    if not has_baseline:
        findings.append(
            Finding(
                id="admin-login-new-country",
                title="Accesos de superadministrador desde un país nuevo",
                severity="high",
                status="undetermined",
                description=(
                    f"El registro solo cubre {con_numero(baseline_days, 'día')}, menos de los "
                    f"{MIN_BASELINE_DAYS} que hacen falta para distinguir «un país nuevo» de "
                    "«el único país que hay». Sin línea base, marcar algo como nuevo sería "
                    "inventárselo."
                ),
                remediation=(
                    "Vuelve a revisarlo cuando el registro tenga más recorrido. Google conserva "
                    "los eventos de acceso unos 180 días; de esa ventana se han leído "
                    f"{con_numero(baseline_days, 'día')}."
                ),
                admin_console_url=CONSOLE_URL,
                cis_control=CIS,
                scope_label="superadministradores",
                i18n_variant="no-baseline",
                i18n_params={"days": baseline_days, "needed": MIN_BASELINE_DAYS},
                details={"window_days": baseline_days, "baseline_required": MIN_BASELINE_DAYS},
            )
        )
        return findings

    nuevos = [
        f"{actor}: {', '.join(_label(c) for c in summary[actor]['new_countries'])}"
        for actor in flagged
    ]
    findings.append(
        Finding(
            id="admin-login-new-country",
            title="Accesos de superadministrador desde un país nuevo",
            severity="high",
            status="fail" if flagged else "pass",
            description=(
                (
                    f"{len(flagged)} superadministrador(es) han entrado en los últimos "
                    f"{RECENT_DAYS} días desde un país en el que no constaba ningún acceso "
                    f"suyo antes, en {baseline_days} días de registro.\n\nNo es que el país sea "
                    "peligroso: lo que llama la atención es el cambio. Una cuenta con meses de "
                    "historial en un sitio que de pronto entra desde otro es el indicio más "
                    "barato que existe de que alguien más la está usando, y en un "
                    "superadministrador eso es el tenant entero.\n\nAntes de alarmarte: un "
                    "viaje, una VPN nueva o un móvil en itinerancia dan exactamente la misma "
                    "señal. Se confirma con una llamada, no con el informe."
                )
                if flagged
                else (
                    f"Ningún superadministrador ha entrado desde un país nuevo en los últimos "
                    f"{RECENT_DAYS} días, sobre {baseline_days} días de registro."
                )
            ),
            affected_items=cap_items(nuevos),
            remediation=(
                "Pregunta a esa persona si el acceso es suyo. Si no lo reconoce: cierra sus "
                "sesiones (Directorio > Usuarios > la cuenta > Seguridad > Cerrar sesión), "
                "restablece la contraseña, revisa las aplicaciones con acceso a su cuenta y "
                "mira el registro de administración por si tocó algún ajuste."
            ),
            admin_console_url=CONSOLE_URL,
            cis_control=CIS,
            scope_label="superadministradores",
            accounts=sorted(flagged),
            i18n_variant="" if flagged else "clean",
            i18n_params={"count": len(flagged), "days": RECENT_DAYS, "window": baseline_days},
            details={
                "window_days": baseline_days,
                "recent_days": RECENT_DAYS,
                "flagged": len(flagged),
                "unresolved_accounts": sorted(unknown_only),
            },
        )
    )
    return findings
