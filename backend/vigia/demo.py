"""Anonymised demo tenant for sales material.

Design rules, in order of importance:

1. **It can never touch a real tenant.** Nothing here reads the database or
   an OAuth token; the whole dataset is built in memory from the constants
   below and served on its own unauthenticated routes.
2. **It goes through the real engine.** The findings come from running the
   actual checks over fake clients and a fake DNS resolver, so the demo
   cannot drift away from what production does. Hand-written report JSON
   would rot the first time a check changed.
3. **Deterministic.** No randomness anywhere. Account ages are expressed as
   offsets from today, so the report content (findings, score, counts) is
   identical on every run while the dates never look stale.

The domain, the people and the DNS records are invented. The DNS records
are syntactically valid so they read correctly to a technical audience.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

from .delta import detect_regressions, gated_summary
from .dns_email_auth import DnsUnavailable

DEMO_DOMAIN = "agencia-exemplo.gal"
DEMO_NEWSLETTER_DOMAIN = f"boletin.{DEMO_DOMAIN}"
DEMO_ADMIN_EMAIL = f"brais.otero@{DEMO_DOMAIN}"
DEMO_ORG = {"id": 0, "primary_domain": DEMO_DOMAIN, "admin_email": DEMO_ADMIN_EMAIL}

# Weekly cadence for the synthetic history.
HISTORY_WEEKS = 8


def _iso(days_ago: float) -> str:
    when = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return when.strftime("%Y-%m-%dT%H:%M:%S.000Z")


# --------------------------------------------------------------- accounts


def _user(
    local: str,
    full_name: str,
    *,
    admin: bool = False,
    delegated: bool = False,
    enrolled_2sv: bool = True,
    enforced_2sv: bool = False,
    last_login_days: float | None = 3,
    created_days: float = 500,
    suspended: bool = False,
    recovery_phone: str = "+34 986 000 000",
    recovery_email: str = "",
) -> dict:
    account = {
        "primaryEmail": f"{local}@{DEMO_DOMAIN}",
        "name": {"fullName": full_name},
        "isAdmin": admin,
        "isDelegatedAdmin": delegated,
        "isEnrolledIn2Sv": enrolled_2sv,
        "isEnforcedIn2Sv": enforced_2sv,
        "lastLoginTime": _iso(last_login_days)
        if last_login_days is not None
        else "1970-01-01T00:00:00.000Z",
        "creationTime": _iso(created_days),
        "suspended": suspended,
        "archived": False,
        "orgUnitPath": "/",
    }
    # Google omits empty fields, so the demo omits them too: that absence is
    # exactly what check_recovery reads as "not configured".
    if recovery_phone:
        account["recoveryPhone"] = recovery_phone
    if recovery_email:
        account["recoveryEmail"] = recovery_email
    return account


DEMO_USERS: list[dict] = [
    # The administrator who does it right — so the report is not all red.
    _user("brais.otero", "Brais Otero Landeira", admin=True, enforced_2sv=True),
    # Left over from the migration: super admin, no 2FA, never used. This is
    # the flagship critical composite.
    _user(
        "uxia.ferreiro",
        "Uxía Ferreiro Nogueira",
        admin=True,
        enrolled_2sv=False,
        last_login_days=None,
        created_days=430,
        # No recovery phone and a personal mailbox: whoever owns that inbox
        # can reset a super admin, and there is no way back for the tenant.
        recovery_phone="",
        recovery_email="uxia.ferreiro.persoal@gmail.com",
    ),
    # Shared integrations mailbox, no second factor.
    _user("integraciones", "Integracións (conta funcional)", enrolled_2sv=False),
    # Delegated admin without 2FA — its own finding now that super admins
    # are handled separately.
    _user("anton.carballo", "Antón Carballo Rei", delegated=True, enrolled_2sv=False),
    _user("sabela.rivas", "Sabela Rivas Pombo", enforced_2sv=True),
    _user("carme.souto", "Carme Souto Vilariño", enforced_2sv=True),
    _user("roi.pardo", "Roi Pardo Estévez"),
    _user("iago.mendez", "Iago Méndez Barreiro", enrolled_2sv=False),
    _user("nerea.figueroa", "Nerea Figueroa Caamaño"),
    # Dormant: still enabled, no sign-in for seven months.
    _user("noa.lourido", "Noa Lourido Seoane", last_login_days=214),
    # Created for someone who never started.
    _user("xurxo.vilar", "Xurxo Vilar Amoedo", last_login_days=None, created_days=120),
    # Left the company; suspended but never removed.
    _user("becaria.2025", "Bolseira 2025", suspended=True, last_login_days=260),
]


def demo_domains() -> list[dict]:
    return [
        {"domainName": DEMO_DOMAIN, "isPrimary": True, "verified": True},
        {"domainName": DEMO_NEWSLETTER_DOMAIN, "isPrimary": False, "verified": True},
    ]


# ------------------------------------------------------------------- DNS
# A fake zone, syntactically valid. The failures are the ones we see most
# often in real audits: an SPF that quietly exceeds the RFC 7208 lookup
# limit, DMARC parked at p=none with reports going to an agency, a
# 1024-bit DKIM key, and a sending subdomain with nothing at all.

_A_1024 = "A" * 216  # decodes to ~162 bytes → 1024-bit
_A_2048 = "A" * 392

DEMO_ZONE_TXT: dict[str, list[str]] = {
    DEMO_DOMAIN: [
        "v=spf1 include:_spf.google.com include:sendgrid.net "
        "include:spf.mailjet.com include:_spf.crm-exemplo.com ~all"
    ],
    # Nested includes push the recursive count over 10 → permerror.
    "_spf.google.com": [
        "v=spf1 include:_netblocks.google.com include:_netblocks2.google.com "
        "include:_netblocks3.google.com ~all"
    ],
    "_netblocks.google.com": ["v=spf1 ip4:35.190.247.0/24 ~all"],
    "_netblocks2.google.com": ["v=spf1 ip6:2001:4860:4000::/36 ~all"],
    "_netblocks3.google.com": ["v=spf1 ip4:172.217.0.0/19 ~all"],
    "sendgrid.net": ["v=spf1 include:sendgrid.info mx a ~all"],
    "sendgrid.info": ["v=spf1 ip4:167.89.0.0/17 ~all"],
    "spf.mailjet.com": ["v=spf1 ip4:87.253.232.0/21 ~all"],
    "_spf.crm-exemplo.com": ["v=spf1 a mx ip4:203.0.113.0/24 ~all"],
    # DKIM present but on a legacy 1024-bit key.
    f"google._domainkey.{DEMO_DOMAIN}": [f"v=DKIM1; k=rsa; p={_A_1024}"],
    # Parked at p=none, and the reports only reach the agency.
    f"_dmarc.{DEMO_DOMAIN}": [
        "v=DMARC1; p=none; rua=mailto:informes@axencia-marketing-exemplo.com; adkim=r; aspf=r"
    ],
    # The sending subdomain has no protection at all.
    f"_dmarc.{DEMO_NEWSLETTER_DOMAIN}": [],
    DEMO_NEWSLETTER_DOMAIN: [],
}

DEMO_ZONE_MX: dict[str, list[str]] = {
    DEMO_DOMAIN: ["aspmx.l.google.com", "alt1.aspmx.l.google.com"],
    DEMO_NEWSLETTER_DOMAIN: ["mx.sendgrid.net"],
}

# DS only on the apex: DNSSEC on, but not on the subdomain.
DEMO_ZONE_DS: dict[str, list[str]] = {
    DEMO_DOMAIN: ["12345 13 2 9F1A2B3C4D5E6F70819202A2B3C4D5E6F708192A2B3C4D5E6F70819202A2B3C"],
    DEMO_NEWSLETTER_DOMAIN: [],
}


class DemoResolver:
    """Answers only from the fake zone above. Anything it does not know
    returns empty (NXDOMAIN-equivalent), never a live DNS query — the demo
    must not depend on the network or leak a real lookup."""

    def txt(self, name: str) -> list[str]:
        return list(DEMO_ZONE_TXT.get(name, []))

    def mx(self, name: str) -> list[str]:
        return list(DEMO_ZONE_MX.get(name, []))

    def ds(self, name: str) -> list[str]:
        return list(DEMO_ZONE_DS.get(name, []))


# ------------------------------------------------------------ audit events


def _token_item(local: str, days_ago: float, client_id: str, app: str, scopes: list[str]) -> dict:
    return {
        "id": {"time": _iso(days_ago)},
        "actor": {"email": f"{local}@{DEMO_DOMAIN}"},
        "events": [
            {
                "name": "authorize",
                "parameters": [
                    {"name": "client_id", "value": client_id},
                    {"name": "app_name", "value": app},
                    {"name": "scope", "multiValue": scopes},
                ],
            }
        ],
    }


def demo_token_events() -> list[dict]:
    gmail_full = ["https://mail.google.com/", "openid", "email"]
    drive_full = ["https://www.googleapis.com/auth/drive", "openid"]
    calendar = ["https://www.googleapis.com/auth/calendar", "openid"]
    harmless = ["openid", "email", "profile"]

    items = [
        _token_item("iago.mendez", 11, "901-mailmerge", "MailMerge Studio", gmail_full),
        _token_item("nerea.figueroa", 34, "901-mailmerge", "MailMerge Studio", gmail_full),
        _token_item("roi.pardo", 7, "902-filesync", "FileSync Cloud", drive_full),
        _token_item("carme.souto", 52, "903-agenda", "AgendaPlus", calendar),
    ]
    # One harmless tool that most of the team authorised → "widely granted".
    for index, user in enumerate(DEMO_USERS[:10]):
        local = user["primaryEmail"].split("@")[0]
        items.append(_token_item(local, 4 + index, "904-chat", "EquipoChat", harmless))
    return items


def demo_admin_events() -> list[dict]:
    return [
        {
            "id": {"time": _iso(2)},
            "actor": {"email": DEMO_ADMIN_EMAIL},
            "events": [
                {
                    "name": "CHANGE_DOCS_SHARING_SETTING",
                    "parameters": [{"name": "NEW_VALUE", "value": "SHARING_ALLOWED"}],
                }
            ],
        },
        {
            "id": {"time": _iso(12)},
            "actor": {"email": f"anton.carballo@{DEMO_DOMAIN}"},
            "events": [
                {
                    "name": "AUTHORIZE_API_CLIENT_ACCESS",
                    "parameters": [
                        {
                            "name": "API_CLIENT_NAME",
                            "value": "sync-antiga@proxecto-exemplo.iam.gserviceaccount.com",
                        },
                        {
                            "name": "API_SCOPES",
                            "multiValue": [
                                "https://mail.google.com/",
                                "https://www.googleapis.com/auth/admin.directory.user",
                            ],
                        },
                    ],
                }
            ],
        },
        {
            "id": {"time": _iso(23)},
            "actor": {"email": DEMO_ADMIN_EMAIL},
            "events": [{"name": "ASSIGN_ROLE", "parameters": [{"name": "ROLE_NAME", "value": "Soporte"}]}],
        },
    ]


def demo_login_events() -> list[dict]:
    """Sign-ins for the demo tenant, with addresses.

    The dates span more than `MIN_BASELINE_DAYS` on purpose: with a shorter
    log the location check would correctly refuse to call any country new, and
    the demo would show an "undetermined" card instead of the thing it exists
    to show.

    The addresses are real public allocations — they have to be, or the
    offline database could not resolve them — but they belong to no customer:
    the tenant, the people and the events are all invented.
    """
    OFICINA = "81.45.30.11"       # España, la oficina
    CASA = "88.20.140.7"          # España, teletrabajo
    VIAJE = "197.230.4.10"        # Marruecos: el país nuevo de la demo
    VPN = "5.2.72.14"             # Países Bajos, salida de VPN

    def item(local: str, days: float, name: str, ip: str = "") -> dict:
        entry = {
            "id": {"time": _iso(days)},
            "actor": {"email": f"{local}@{DEMO_DOMAIN}"},
            "events": [{"name": name, "type": "login"}],
        }
        if ip:
            entry["ipAddress"] = ip
        return entry

    items = [
        item("nerea.figueroa", 5, "account_disabled_password_leak"),
        item("iago.mendez", 9, "suspicious_login"),
    ]
    items += [item("integraciones", 3 + i * 0.05, "login_failure") for i in range(14)]

    # brais.otero: superadministrador con rutina estable. No se marca.
    items += [
        item("brais.otero", d, "login_success", OFICINA)
        for d in (0.5, 2, 4, 7, 11, 18, 25, 33, 41, 52, 63, 74)
    ]
    items += [item("brais.otero", d, "login_success", CASA) for d in (1, 9, 21, 46, 68)]

    # uxia.ferreiro: misma rutina durante meses y, la semana pasada, un país
    # donde nunca había constado un acceso suyo. Es la tarjeta que la demo
    # existe para mostrar — y también el caso que se explica con un viaje.
    items += [
        item("uxia.ferreiro", d, "login_success", OFICINA)
        for d in (3, 6, 13, 20, 29, 38, 49, 58, 71)
    ]
    items += [item("uxia.ferreiro", d, "login_success", VPN) for d in (16, 44)]
    items += [item("uxia.ferreiro", d, "login_success", VIAJE) for d in (2, 4)]
    return items


def demo_policies() -> list[dict]:
    def policy(setting: str, value: dict, target: str | None = None) -> dict:
        return {
            "name": f"policies/demo-{setting}",
            "policyQuery": ({"orgUnit": target} if target else {}),
            "setting": {"type": f"settings/{setting}", "value": value},
        }

    # A realistic mix: some set (and wrong), some never configured — which
    # leaves the corresponding manual cards in place.
    return [
        policy("drive_and_docs.external_sharing", {"externalSharingMode": "ALLOWED"}),
        policy("security.password", {"minimumLength": 8, "allowReuse": True}),
        policy("groups_for_business.groups_sharing", {"collaborationCapability": "DOMAIN_USERS_ONLY"}),
    ]


# ------------------------------------------------------------ fake clients


class DemoDirectoryClient:
    def list_users(self) -> tuple[list[dict], bool]:
        return copy.deepcopy(DEMO_USERS), False

    def list_domains(self) -> list[dict]:
        return demo_domains()


class DemoReportsClient:
    def token_activities(self, max_pages: int = 5) -> list[dict]:
        return demo_token_events()

    def admin_activities(self, max_results: int = 1000, max_pages: int = 3) -> list[dict]:
        return demo_admin_events()

    def login_activities(self, max_pages: int = 5) -> list[dict]:
        return demo_login_events()


class DemoPolicyClient:
    def list_policies(self) -> list[dict]:
        return demo_policies()


__all__ = [
    "DEMO_DOMAIN",
    "DEMO_NEWSLETTER_DOMAIN",
    "DEMO_ORG",
    "DemoDirectoryClient",
    "DemoPolicyClient",
    "DemoReportsClient",
    "DemoResolver",
    "DnsUnavailable",
    "HISTORY_WEEKS",
    "gated_summary",
    "detect_regressions",
    "build_demo_payload",
    "demo_domain_rows",
    "demo_history",
]


# ------------------------------------------------------- the demo payload


def demo_domain_rows() -> list[dict]:
    return [
        {"domain": DEMO_DOMAIN, "source": "google", "added_at": _iso(60)},
        {"domain": DEMO_NEWSLETTER_DOMAIN, "source": "google", "added_at": _iso(60)},
    ]


def demo_history(current_score: int) -> list[dict]:
    """Eight weekly points, oldest first, ending at today's real score.

    The shape tells a story a prospect recognises: a slow improvement, one
    fix that did not stick (the dip at week 6) and recovery afterwards.
    """
    scores = [41, 44, 44, 52, 57, 49, 58]
    history = []
    for index, score in enumerate(scores):
        days_ago = (HISTORY_WEEKS - 1 - index) * 7
        history.append(
            {
                "id": index + 1,
                "created_at": _iso(days_ago),
                "score": score,
                "counts": {
                    "critical": 2 if score < 50 else 1,
                    "high": 6 if score < 50 else 4,
                    "medium": 3,
                    "low": 2,
                    "info": 0,
                },
            }
        )
    history.append(
        {"id": HISTORY_WEEKS, "created_at": _iso(0), "score": current_score, "counts": {}}
    )
    return history


def _previous_findings(findings: list[dict]) -> list[dict]:
    """A plausible previous scan: one issue since fixed, one since appeared,
    and one that had been resolved and has come back (the regression).

    Built by flipping states on a copy of the current findings, so the delta
    the UI shows is produced by the same code that runs in production.
    """
    previous = copy.deepcopy(findings)
    for finding in previous:
        # Was passing last week, fails now → shows up as a NEW issue.
        if finding["id"] == "login-compromised":
            finding["status"] = "pass"
            finding["accounts"] = []
        # Was failing last week, passes now → shows up as RESOLVED.
        elif finding["id"] == "policy-groups-sharing":
            finding["status"] = "fail"
        # Passing last week and failing now, and it had already failed
        # before → detect_regressions escalates it.
        elif finding["id"] == "email-dmarc":
            finding["status"] = "pass"
    return previous


def _older_findings(findings: list[dict]) -> list[dict]:
    """An even earlier scan where the DMARC finding was already open, which
    is what makes the current failure a regression rather than news."""
    older = copy.deepcopy(findings)
    for finding in older:
        if finding["id"] == "email-dmarc":
            finding["status"] = "fail"
        # Anything meant to read as NEW must never have been open before, or
        # the regression detector would (correctly) escalate it instead.
        elif finding["id"] == "login-compromised":
            finding["status"] = "pass"
            finding["accounts"] = []
    return older


def build_demo_payload(settings) -> dict:
    """The whole demo report, produced by the real engine over fake inputs.

    Returns the same shape the dashboard already consumes, so the demo needs
    no special-case rendering — only a banner and a different endpoint.
    """
    from .remediation import rank_actions
    from .scan import ScanContext, collect_findings, remaining_manual_checks
    from .engine_version import engine_version
    from .scoring import compute_score, people_at_risk, score_breakdown, severity_counts

    ctx = ScanContext(
        DemoDirectoryClient(),
        DemoReportsClient(),
        settings,
        policy=DemoPolicyClient(),
        resolver=DemoResolver(),
    )
    findings = collect_findings(ctx, label="demo")

    # Synthesise the two prior scans BEFORE escalation, then run the real
    # regression detector so the demo exercises production code paths.
    baseline = [f.to_dict() for f in findings]
    previous = _previous_findings(baseline)
    older = _older_findings(baseline)
    detect_regressions(findings, previous, [older])

    score = compute_score(findings)
    counts = severity_counts(findings)
    finding_dicts = [f.to_dict() for f in findings]

    history = demo_history(score if score is not None else 0)
    history[-1]["counts"] = counts

    scan = {
        "id": HISTORY_WEEKS,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "counts": counts,
        "findings": finding_dicts,
        "manual_checks": remaining_manual_checks(findings),
        # The demo runs the real engine, so it carries the real fingerprint.
        # Without it the demo report footer reads "engine: unknown", which is
        # a strange thing for a shop window to say about itself.
        "engine_version": engine_version(),
        "result": {"breakdown": score_breakdown(finding_dicts)},
    }

    # Through the gate, like every other caller. This used to call
    # `annotate_changes` directly, which is the same shortcut that let the
    # scheduled e-mail announce a delta the dashboard was refusing to compute.
    # The demo is a shop window, so a demo that labels changes by a different
    # rule than the product is a demo of a product we do not sell.
    previous_scan = {
        "score": history[-2]["score"] if len(history) > 1 else None,
        "engine_version": scan["engine_version"],
        "findings": previous,
        "result": {"breakdown": score_breakdown(previous)},
    }
    _, summary = gated_summary(scan, previous_scan)

    return {
        "org": {"domain": DEMO_DOMAIN, "admin_email": DEMO_ADMIN_EMAIL},
        "scan": scan,
        "previous_score": history[-2]["score"] if len(history) > 1 else None,
        "delta": summary,
        "actions": rank_actions(finding_dicts, limit=3),
        "breakdown": score_breakdown(finding_dicts),
        "people_at_risk": people_at_risk(finding_dicts),
        "demo": True,
        "history": history,
        "domains": demo_domain_rows(),
    }
