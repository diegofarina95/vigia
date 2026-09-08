"""Seeded data for MOCK_MODE: develop the full UI with zero Google setup.

The dataset is crafted so every check produces a mix of pass/fail/warn:
an admin without 2SV (critical), dormant users, a risky OAuth app and a
domain-wide delegation event. Email-auth (SPF/DKIM/DMARC) is NEVER
mocked — it always runs real DNS against the user-configured domains.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

MOCK_DOMAIN = "acme-demo.example"
MOCK_ADMIN_EMAIL = "dana.admin@acme-demo.example"


def _iso(days_ago: float) -> str:
    when = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return when.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _user(
    email: str,
    full_name: str,
    *,
    admin: bool = False,
    delegated: bool = False,
    enrolled_2sv: bool = True,
    enforced_2sv: bool = False,
    last_login_days: float | None = 2,
    created_days: float = 400,
    suspended: bool = False,
) -> dict:
    return {
        "primaryEmail": email,
        "name": {"fullName": full_name},
        "isAdmin": admin,
        "isDelegatedAdmin": delegated,
        "isEnrolledIn2Sv": enrolled_2sv,
        "isEnforcedIn2Sv": enforced_2sv,
        "lastLoginTime": _iso(last_login_days) if last_login_days is not None
        else "1970-01-01T00:00:00.000Z",
        "creationTime": _iso(created_days),
        "suspended": suspended,
        "archived": False,
        "orgUnitPath": "/",
    }


def mock_users() -> list[dict]:
    d = MOCK_DOMAIN
    return [
        _user(f"dana.admin@{d}", "Dana Admin", admin=True, enforced_2sv=True),
        _user(f"victor.ops@{d}", "Víctor Sistemas", admin=True, enrolled_2sv=False),  # critical
        _user(f"sam.it@{d}", "Samuel Informática", delegated=True),
        _user(f"maria.sales@{d}", "María Ventas"),
        _user(f"leo.eng@{d}", "Leo Ingeniería", enforced_2sv=True),
        _user(f"nina.hr@{d}", "Nina RRHH", enrolled_2sv=False),
        _user(f"pablo.mkt@{d}", "Pablo Marketing", enrolled_2sv=False, last_login_days=120),
        _user(f"emma.fin@{d}", "Emma Finanzas", last_login_days=200),  # dormant
        _user(f"contractor.old@{d}", "Contrato antiguo", last_login_days=310),  # dormant
        _user(f"kiosk@{d}", "Kiosco de recepción", last_login_days=None, created_days=90),
        _user(f"intern.summer@{d}", "Becario de verano", last_login_days=None, created_days=5),
        _user(f"ex.employee@{d}", "Extrabajador", suspended=True, last_login_days=250),
        _user(f"ex.temp@{d}", "Temporal antiguo", suspended=True, last_login_days=400),
        _user(f"ana.legal@{d}", "Ana Legal"),
        _user(f"tom.support@{d}", "Tomás Soporte"),
        # Leftovers from setup and migrations: super admin, no second factor,
        # never signed in. Individually each looks minor; together they are the
        # flagship composite finding (a permanent, unwatched back door).
        _user(f"admin@{d}", "Admin de instalación", admin=True, enrolled_2sv=False, last_login_days=None),
        _user(
            f"migration.admin@{d}", "Admin de migración",
            admin=True, enrolled_2sv=False, last_login_days=None,
        ),
        _user(
            f"integrations@{d}", "Servicio de integraciones",
            admin=True, enrolled_2sv=False, last_login_days=None,
        ),
    ]


def mock_domains() -> list[dict]:
    return [
        {"domainName": MOCK_DOMAIN, "isPrimary": True, "verified": True},
        {"domainName": f"mail.{MOCK_DOMAIN}", "isPrimary": False, "verified": True},
    ]


def _token_item(email: str, days_ago: float, client_id: str, app_name: str, scopes: list[str]) -> dict:
    return {
        "id": {"time": _iso(days_ago)},
        "actor": {"email": email},
        "events": [
            {
                "name": "authorize",
                "parameters": [
                    {"name": "client_id", "value": client_id},
                    {"name": "app_name", "value": app_name},
                    {"name": "client_type", "value": "WEB"},
                    {"name": "scope", "multiValue": scopes},
                ],
            }
        ],
    }


def mock_token_events() -> list[dict]:
    d = MOCK_DOMAIN
    gmail_full = ["https://mail.google.com/", "openid", "email"]
    drive_full = ["https://www.googleapis.com/auth/drive", "openid"]
    safe = ["openid", "email", "profile"]
    calendar = ["https://www.googleapis.com/auth/calendar", "openid"]

    items = [
        _token_item(f"maria.sales@{d}", 12, "111-mailflow", "MailFlow Pro", gmail_full),
        _token_item(f"nina.hr@{d}", 30, "111-mailflow", "MailFlow Pro", gmail_full),
        _token_item(f"pablo.mkt@{d}", 45, "111-mailflow", "MailFlow Pro", gmail_full),
        _token_item(f"leo.eng@{d}", 8, "222-drivesync", "DriveSyncer", drive_full),
        _token_item(f"tom.support@{d}", 60, "222-drivesync", "DriveSyncer", drive_full),
        _token_item(f"ana.legal@{d}", 3, "444-scheduler", "MeetPlanner", calendar),
    ]
    # a harmless app authorized by many users → "widely granted"
    for index, user in enumerate(mock_users()[:12]):
        items.append(
            _token_item(user["primaryEmail"], 5 + index, "333-slackish", "TeamChat", safe)
        )
    return items


def mock_admin_events() -> list[dict]:
    d = MOCK_DOMAIN
    return [
        {
            "id": {"time": _iso(1)},
            "actor": {"email": f"dana.admin@{d}"},
            "events": [
                {
                    "name": "CHANGE_APPLICATION_SETTING",
                    "parameters": [
                        {"name": "APPLICATION_NAME", "value": "Gmail"},
                        {"name": "SETTING_NAME", "value": "SPAM_OVERRIDE"},
                    ],
                }
            ],
        },
        {
            "id": {"time": _iso(9)},
            "actor": {"email": f"victor.ops@{d}"},
            "events": [
                {
                    "name": "AUTHORIZE_API_CLIENT_ACCESS",
                    "parameters": [
                        {"name": "API_CLIENT_NAME", "value": "legacy-sync@dusty-project.iam.gserviceaccount.com"},
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
            "id": {"time": _iso(15)},
            "actor": {"email": f"dana.admin@{d}"},
            "events": [{"name": "CREATE_ROLE", "parameters": [{"name": "ROLE_NAME", "value": "Helpdesk"}]}],
        },
    ]


def _policy(setting_type: str, value: dict, target: str | None = None) -> dict:
    query = {"orgUnit": target} if target else {}
    return {
        "name": f"policies/mock-{setting_type}",
        "policyQuery": query,
        "setting": {"type": f"settings/{setting_type}", "value": value},
    }


def mock_policies() -> list[dict]:
    """Admin console settings for the demo tenant — deliberately a mix, so
    every policy check shows a different verdict.

    Note 'security.session_controls' is intentionally absent: it exercises
    the 'no explicit policy → undetermined' path."""
    return [
        # Wide open: the worst realistic default.
        _policy("drive_and_docs.external_sharing", {"externalSharingMode": "ALLOWED"}),
        # Forwarding left on org-wide, disabled for one sensitive OU.
        _policy("gmail.auto_forwarding", {"enableAutoForwarding": True}),
        _policy("gmail.auto_forwarding", {"enableAutoForwarding": False}, "/Finance"),
        # Weak password policy: short and reusable.
        _policy(
            "security.password",
            {"minimumLength": 8, "allowReuse": True, "expirationDuration": "7776000s"},
        ),
        # Groups reachable by anyone.
        _policy(
            "groups_for_business.groups_sharing",
            {"collaborationCapability": "ANYONE_CAN_ACCESS"},
        ),
        # A Marketplace allowlist is configured — the good case.
        _policy(
            "workspace_marketplace.apps_allowlist",
            {
                "apps": [
                    {"applicationId": "111", "access": "ALLOWED"},
                    {"applicationId": "222", "access": "BLOCKED"},
                ]
            },
        ),
    ]


def _login_item(email: str, days_ago: float, event_name: str) -> dict:
    return {
        "id": {"time": _iso(days_ago)},
        "actor": {"email": email},
        "events": [{"name": event_name, "type": "login"}],
    }


def mock_login_events() -> list[dict]:
    d = MOCK_DOMAIN
    items = [
        _login_item(f"nina.hr@{d}", 4, "account_disabled_password_leak"),  # critical
        _login_item(f"pablo.mkt@{d}", 6, "suspicious_login"),
        _login_item(f"maria.sales@{d}", 11, "suspicious_login"),
    ]
    # A burst of failures against one account (looks like guessing).
    items += [_login_item(f"emma.fin@{d}", 3 + i * 0.1, "login_failure") for i in range(12)]
    items += [_login_item(f"leo.eng@{d}", 1, "login_success")]
    return items
