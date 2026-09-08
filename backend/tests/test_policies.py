"""Admin-console settings, now judged against Google's documented defaults.

This file changed meaning. It used to assert that an absent policy produced
`undetermined`, on the grounds that "we cannot tell whether the tenant is on
Google's default". Google publishes that default, and for five of these
settings it is the permissive one — external Drive sharing defaults to
ALLOWED, Gmail auto-forwarding to true, the 2SV factor set to ALL. Reporting
those as "check it by hand" hid the most common real exposure there is, so
absence is now evaluated against the documented default.

The old rule survives exactly where it still applies: settings Google
documents no default for, and any value this code cannot interpret.
"""
import pytest

from vigia.checks import check_policies as mod
from vigia.checks.finding import Finding
from vigia.google_client.base import GoogleApiError
from vigia.google_client.policy import PolicyClient, PolicyUnavailable
from vigia.scan import remaining_manual_checks

ROOT = "/"


def policy(setting_type, value, target=None, order=0):
    raw = {"setting": {"type": f"settings/{setting_type}", "value": value}}
    query = {}
    if target:
        query["orgUnit"] = target
    if order:
        query["sortOrder"] = order
    if query:
        raw["policyQuery"] = query
    return raw


def user(email, ou=ROOT):
    return {"primaryEmail": email, "orgUnitPath": ou, "suspended": False, "archived": False}


PLANTILLA = [user("ana@x.com"), user("luis@x.com"), user("dir@x.com", "/Direccion")]


class Ctx:
    def __init__(self, policies=None, error=None, users=None):
        self._policies = policies or []
        self._error = error
        self._users = PLANTILLA if users is None else users

    def policies(self):
        if self._error:
            raise self._error
        return self._policies

    def users(self):
        return self._users

    def complete(self, source):
        return getattr(self, "_completo", {}).get(source, True)

    def measured(self, source):
        return True

def find(findings, fid):
    return next(f for f in findings if f.id == fid)


def run(policies=None, users=None):
    return mod.run(Ctx(policies, users=users))


# ------------------------------------------------- absence is now a verdict

@pytest.mark.parametrize("finding_id,reason", [
    ("policy-drive-sharing", "el uso compartido externo viene en ALLOWED"),
    ("policy-gmail-forwarding", "el reenvío automático viene activado"),
    ("policy-2sv-methods", "el conjunto de factores viene en ALL, con SMS"),
    ("policy-marketplace", "el Marketplace viene en ALLOW_ALL"),
    ("policy-password", "la longitud mínima viene en 8"),
])
def test_a_tenant_with_no_policies_fails_the_permissive_defaults(finding_id, reason):
    """Not touching a setting is not a neutral position."""
    found = find(run([]), finding_id)
    assert found.status == "fail", reason
    assert found.details["from_default"] is True
    assert found.details["exposed"] == 3 and found.accounts == []
    assert "valor por defecto de Google" in found.description


@pytest.mark.parametrize("finding_id", [
    "policy-less-secure-apps",     # allow_less_secure_apps defaults to false
    "policy-2sv-grace",            # enrollment_grace_period defaults to 0s
    "policy-drive-link-default",   # defaults to LINK_SHARING_PRIVATE
    "policy-groups-sharing",       # defaults to DOMAIN_USERS_ONLY
])
def test_the_defaults_that_are_safe_pass_without_any_policy(finding_id):
    found = find(run([]), finding_id)
    assert found.status == "pass"
    assert found.accounts == []


@pytest.mark.parametrize("finding_id", ["policy-imap", "policy-pop", "policy-session"])
def test_settings_google_documents_no_default_for_stay_undetermined(finding_id):
    """The old honesty rule, kept where it still applies."""
    found = find(run([]), finding_id)
    assert found.status == "undetermined"
    assert found.accounts == []


# --------------------------------------------------- explicit policies win

def test_an_explicit_safe_policy_passes():
    found = find(run([policy("drive_and_docs.external_sharing",
                             {"externalSharingMode": "DISALLOWED"})]),
                 "policy-drive-sharing")
    assert found.status == "pass" and found.accounts == []
    assert found.details["from_default"] is False


def test_an_explicit_unsafe_policy_fails():
    found = find(run([policy("drive_and_docs.external_sharing",
                             {"externalSharingMode": "ALLOWED"})]),
                 "policy-drive-sharing")
    assert found.status == "fail"
    # A tenant setting is not three personal failures: the count lives in
    # `details`, the payroll does not live in `accounts`.
    assert found.accounts == []
    assert found.details["exposed"] == 3
    assert found.scope_type == "organization"


def test_snake_case_field_names_also_work():
    found = find(run([policy("gmail.auto_forwarding", {"enable_auto_forwarding": False})]),
                 "policy-gmail-forwarding")
    assert found.status == "pass"


def test_a_value_this_code_cannot_read_is_never_a_pass():
    found = find(run([policy("drive_and_docs.external_sharing",
                             {"externalSharingMode": "MODO_FUTURO"})]),
                 "policy-drive-sharing")
    assert found.status == "undetermined"
    assert found.details["unresolved"] == 3


def test_imap_and_pop_are_judged_once_a_policy_exists():
    findings = run([
        policy("gmail.imap_access", {"enableImapAccess": True}),
        policy("gmail.pop_access", {"enablePopAccess": False}),
    ])
    assert find(findings, "policy-imap").status == "fail"
    assert find(findings, "policy-pop").status == "pass"


# ------------------------------------------- the per-OU finding, the point

def test_a_setting_locked_down_in_one_ou_says_how_many_are_left_out():
    """The headline: "applied only in /Direccion, 2 of 3 accounts are outside"
    instead of a flat verdict. It is the answer to a report that said "2SV is
    not enforced for everyone: Pass" next to eight unenrolled users.

    It counts the people it leaves exposed without naming them: the exposure
    belongs to the setting, and the names belong to the findings that are
    actually about those people."""
    found = find(
        run([policy("drive_and_docs.external_sharing",
                    {"externalSharingMode": "DISALLOWED"}, target="/Direccion")]),
        "policy-drive-sharing",
    )
    assert found.status == "fail"
    assert found.accounts == []
    assert found.details["exposed"] == 2
    assert found.details["partial_coverage"] is True
    assert "Aplicado solo en /Direccion" in found.description
    assert "2 de 3 cuentas quedan fuera" in found.description


def test_a_policy_at_the_root_covers_everyone_and_says_so():
    found = find(run([policy("gmail.auto_forwarding",
                             {"enableAutoForwarding": False}, target=ROOT)]),
                 "policy-gmail-forwarding")
    assert found.status == "pass"
    assert found.details["partial_coverage"] is False
    assert "Cubre las 3 cuentas activas" in found.description


def test_the_highest_sort_order_wins_when_two_policies_apply():
    found = find(
        run([
            policy("gmail.auto_forwarding", {"enableAutoForwarding": False}, order=1),
            policy("gmail.auto_forwarding", {"enableAutoForwarding": True}, order=9),
        ]),
        "policy-gmail-forwarding",
    )
    assert found.status == "fail"


def test_a_group_scoped_policy_keeps_accounts_out_of_pass():
    """Membership is unreadable, so a group-steered setting is never green."""
    raw = policy("gmail.auto_forwarding", {"enableAutoForwarding": False})
    raw["policyQuery"] = {"group": "direccion@x.com"}
    found = find(run([raw]), "policy-gmail-forwarding")
    assert found.status == "undetermined"
    assert found.details["group_policies"] == ["direccion@x.com"]
    assert "pertenencia a grupos" in found.description


def test_suspended_accounts_are_not_counted_as_exposed():
    plantilla = PLANTILLA + [
        {"primaryEmail": "ex@x.com", "orgUnitPath": ROOT,
         "suspended": True, "archived": False}
    ]
    found = find(run([], users=plantilla), "policy-drive-sharing")
    assert "ex@x.com" not in found.accounts


def test_with_no_active_accounts_nothing_is_reported():
    assert mod.run(Ctx([], users=[])) == []


# ------------------------------------------------ when the API is not there

def test_a_delegated_admin_gets_an_explanation_not_a_wall_of_undetermined():
    """Useful information for the customer, not an error."""
    problem = PolicyUnavailable("not_super_admin", "Vuelve a conectar con superadmin.")
    [found] = mod.run(Ctx(error=problem))
    assert found.id == "policy-automation"
    assert "superadministrador" in found.title
    assert "administrador delegado" in found.description
    assert found.i18n_variant == "not_super_admin"


def test_a_missing_scope_asks_for_a_reconnect_in_plain_words():
    problem = PolicyUnavailable("scope_missing", "Desconecta y vuelve a conectar.")
    [found] = mod.run(Ctx(error=problem))
    assert "Reconecta" in found.title
    assert found.details["needs_reconnect"] is True


def test_a_disabled_api_says_which_switch_to_flip():
    problem = PolicyUnavailable("api_disabled", "Activa la API de Cloud Identity.")
    [found] = mod.run(Ctx(error=problem))
    assert found.details["reason"] == "api_disabled"
    assert found.details["needs_reconnect"] is False


def test_the_manual_cards_come_back_when_the_api_is_unavailable():
    """Degradation, not disappearance: if the automatic check cannot run, the
    human instructions have to still be there."""
    problem = PolicyUnavailable("api_disabled", "Activa la API.")
    remaining = {m["id"] for m in remaining_manual_checks(mod.run(Ctx(error=problem)))}
    assert {"manual-drive-sharing", "manual-gmail-forwarding",
            "manual-password-policy"} <= remaining


def test_the_manual_cards_disappear_once_the_automatic_ones_are_conclusive():
    remaining = {m["id"] for m in remaining_manual_checks(run([]))}
    assert "manual-drive-sharing" not in remaining
    assert "manual-password-policy" not in remaining


def _f(fid, status):
    return Finding(id=fid, title=fid, severity="high", status=status)


def test_an_undetermined_automatic_check_keeps_its_manual_card():
    kept = remaining_manual_checks([_f("policy-drive-sharing", "undetermined")])
    assert any(c.get("automated_by") == "policy-drive-sharing" for c in kept)


# ---------------------------------------------------- the client classifier

class FakeSession:
    def __init__(self, exc):
        self._exc = exc

    def get(self, url, params=None):
        raise self._exc


@pytest.mark.parametrize("status,message,expected", [
    (403, "Request had insufficient authentication scopes.", "scope_missing"),
    (403, "Cloud Identity API has not been used in project 123 before", "api_disabled"),
    (403, "The caller does not have permission", "not_super_admin"),
    (500, "backend error", "error"),
])
def test_the_google_error_is_turned_into_an_actionable_reason(status, message, expected):
    client = PolicyClient(FakeSession(GoogleApiError(status, message)))
    with pytest.raises(PolicyUnavailable) as caught:
        client.list_policies()
    assert caught.value.reason == expected


def test_a_404_falls_through_the_api_versions_then_reports_unavailable():
    client = PolicyClient(FakeSession(GoogleApiError(404, "not found")))
    with pytest.raises(PolicyUnavailable) as caught:
        client.list_policies()
    assert caught.value.reason == "not_available"


# ------------------------------------- the link that unblocks the customer

DISABLED_BODY = {
    "error": {
        "code": 403,
        "message": (
            "Cloud Identity API has not been used in project 1085112005140 before or it "
            "is disabled. Enable it by visiting "
            "https://console.developers.google.com/apis/api/cloudidentity.googleapis.com/"
            "overview?project=1085112005140 then retry."
        ),
        "status": "PERMISSION_DENIED",
        "details": [{
            "@type": "type.googleapis.com/google.rpc.ErrorInfo",
            "reason": "SERVICE_DISABLED",
            "metadata": {
                "activationUrl": (
                    "https://console.developers.google.com/apis/api/"
                    "cloudidentity.googleapis.com/overview?project=1085112005140"
                ),
                "service": "cloudidentity.googleapis.com",
            },
        }],
    }
}


def test_a_disabled_api_yields_the_activation_link_for_the_right_project():
    """A generic link to the API library opens whichever project the admin
    last used. Enabling the API there changes nothing and the report keeps
    saying the same thing — so the link has to carry the project number
    Google itself named."""
    from vigia.google_client.base import GoogleApiError
    from vigia.google_client.policy import _classify

    problem = _classify(GoogleApiError(403, DISABLED_BODY["error"]["message"], DISABLED_BODY))
    assert problem.reason == "api_disabled"
    assert "project=1085112005140" in problem.url
    assert problem.url in problem.hint


def test_the_link_survives_a_body_without_structured_details():
    from vigia.google_client.base import GoogleApiError
    from vigia.google_client.policy import _classify

    problem = _classify(GoogleApiError(403, DISABLED_BODY["error"]["message"], {}))
    assert "project=1085112005140" in problem.url


def test_with_no_link_at_all_the_card_still_warns_about_the_wrong_project():
    from vigia.google_client.base import GoogleApiError
    from vigia.google_client.policy import _classify

    problem = _classify(GoogleApiError(403, "the api is disabled", {}))
    assert problem.url == ""
    assert "no el que tengas abierto" in problem.hint


def test_the_card_points_at_the_activation_link():
    from vigia.checks.check_policies import _setup_finding
    from vigia.google_client.policy import PolicyUnavailable

    card = _setup_finding(PolicyUnavailable("api_disabled", "activa la api", "https://x/y?project=9"))
    assert card.admin_console_url == "https://x/y?project=9"
    assert card.details["activation_url"] == "https://x/y?project=9"


def test_without_a_link_the_card_falls_back_to_the_api_library():
    from vigia.checks.check_policies import _setup_finding
    from vigia.google_client.policy import PolicyUnavailable

    card = _setup_finding(PolicyUnavailable("scope_missing", "reconecta"))
    assert "cloudidentity.googleapis.com" in card.admin_console_url


# ------------------------------------------- a rate limit is not a failure

def test_a_rate_limit_is_told_apart_from_a_real_problem():
    """429 used to fall through to "unknown Policy API error", which reads as
    "we could not determine your settings" — a claim about the customer's
    configuration made on the strength of a temporary quota."""
    from vigia.google_client.base import GoogleApiError
    from vigia.google_client.policy import _classify

    for exc in (
        GoogleApiError(429, "Resource has been exhausted (e.g. check quota)."),
        GoogleApiError(429, "quota exceeded"),
    ):
        problem = _classify(exc)
        assert problem.reason == "rate_limited"
        assert "no es un problema de tu configuración" in problem.hint.lower()


def test_the_pages_are_retried_before_giving_up():
    from vigia.google_client.base import GoogleApiError
    from vigia.google_client import policy as mod

    calls = {"n": 0}

    class Session:
        def get(self, url, params=None):
            calls["n"] += 1
            if calls["n"] < 3:
                raise GoogleApiError(429, "Resource has been exhausted")
            return {"policies": [{"setting": {"type": "settings/x", "value": {}}}]}

    mod.RETRY_WAITS = (0, 0, 0)          # no real waiting inside a test
    politicas, cobertura = mod.PolicyClient(Session()).list_policies()
    assert len(politicas) == 1
    assert cobertura.complete is True
    assert calls["n"] == 3


def test_a_permanent_rate_limit_surfaces_rather_than_looping():
    from vigia.google_client.base import GoogleApiError
    from vigia.google_client import policy as mod
    from vigia.google_client.policy import PolicyUnavailable
    import pytest as _pytest

    class Session:
        def get(self, url, params=None):
            raise GoogleApiError(429, "Resource has been exhausted")

    mod.RETRY_WAITS = (0, 0)
    with _pytest.raises(PolicyUnavailable) as caught:
        mod.PolicyClient(Session()).list_policies()
    assert caught.value.reason == "rate_limited"


def test_the_waiting_is_bounded_for_the_whole_listing_not_per_page():
    """22 seconds of backoff per page across 20 pages is over seven minutes.
    Gunicorn cuts the request at 120s and Cloudflare sooner, so the customer
    would not get the rate-limit card the retry exists to avoid — they would
    get "Failed to fetch" and no explanation."""
    from vigia.google_client.base import GoogleApiError
    from vigia.google_client import policy as mod
    from vigia.google_client.policy import PolicyUnavailable
    import pytest as _pytest

    dormido = []

    class Session:
        def get(self, url, params=None):
            raise GoogleApiError(429, "Resource has been exhausted")

    original_sleep, original_budget = mod.time.sleep, mod.RETRY_BUDGET_SECONDS
    mod.time.sleep = dormido.append
    mod.RETRY_BUDGET_SECONDS = 10
    try:
        with _pytest.raises(PolicyUnavailable) as caught:
            mod.PolicyClient(Session()).list_policies()
    finally:
        mod.time.sleep, mod.RETRY_BUDGET_SECONDS = original_sleep, original_budget

    assert caught.value.reason == "rate_limited"
    assert sum(dormido) <= 10, f"se ha pasado del presupuesto: {dormido}"


# ---------------- an absence is only a default when nothing was hidden

def test_a_truncated_listing_returns_its_incompleteness():
    """This loop used to `return policies` with the page token still set — the
    same shape as the token-events defect and worse in consequence, because the
    reduction engine reads an absence as Google's documented default."""
    from vigia.google_client import policy as mod

    class Session:
        def __init__(self):
            self.n = 0

        def get(self, url, params=None):
            self.n += 1
            return {"policies": [{"setting": {"type": "settings/x", "value": {}}}],
                    "nextPageToken": "siempre-hay-mas"}

    original = mod.MAX_PAGES
    mod.MAX_PAGES = 3
    try:
        politicas, cobertura = mod.PolicyClient(Session()).list_policies()
    finally:
        mod.MAX_PAGES = original

    assert len(politicas) == 3
    assert cobertura.complete is False
    assert cobertura.pages == 3
    assert "valor por defecto" in cobertura.reason


def test_a_truncated_listing_never_invents_a_default_verdict():
    """The exact inversion: the customer loosened a setting, the page carrying
    it was dropped, and the tool printed "Google's default value, which nobody
    has changed" — a positive claim about their configuration manufactured by a
    page cap."""
    from vigia.checks import policy_engine as pe

    vacio = pe.parse([])
    completo = pe.reduce_for(vacio, "drive_and_docs.general_access_default", "/", True)
    truncado = pe.reduce_for(vacio, "drive_and_docs.general_access_default", "/", False)

    assert completo.source == "default" and completo.resolved
    assert truncado.source == "unresolved" and not truncado.resolved


def test_the_policy_checks_go_undetermined_on_a_truncated_listing():
    from tests.fakes import FakeContext
    from vigia.checks import check_policies

    limpio = FakeContext(users=[{"primaryEmail": "a@x.com", "orgUnitPath": "/"}])
    cortado = FakeContext(
        users=[{"primaryEmail": "a@x.com", "orgUnitPath": "/"}],
        complete={"policies": False},
    )
    con = {f.id: f.status for f in check_policies.run(limpio)}
    sin = {f.id: f.status for f in check_policies.run(cortado)}

    # With a complete listing the documented defaults produce real verdicts…
    assert any(v in ("fail", "warn", "pass") for v in con.values())
    # …and with a truncated one, none of them may.
    assert set(sin.values()) == {"undetermined"}, sin
