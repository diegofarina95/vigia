"""The ways in that do not go through the second factor.

Every other 2SV check in the suite asks "is this account enrolled". These ask
the harder question: enrolled or not, **what else still opens the door** — a
weak factor, a grace period, a legacy protocol, password-only app access, or a
recovery path that hands the account to whoever owns a personal mailbox.

The invariant these tests defend is the one this codebase has been bitten by
twice today: a value the code cannot interpret must never read as `pass`.
"""
from dataclasses import dataclass

import pytest

from vigia.checks import check_policies, check_recovery, composite

EPOCH = "1970-01-01T00:00:00.000Z"
RECENT = "2026-07-28T09:00:00.000Z"


@dataclass
class Settings:
    dormant_days: int = 90
    super_admin_threshold: int = 4


def user(email, *, admin=False, delegated=False, enrolled_2sv=True,
         phone="+34600111222", recovery="", last_login=RECENT, suspended=False):
    account = {
        "primaryEmail": email,
        "isAdmin": admin,
        "isDelegatedAdmin": delegated,
        "isEnrolledIn2Sv": enrolled_2sv,
        "isEnforcedIn2Sv": enrolled_2sv,
        "lastLoginTime": last_login,
        "suspended": suspended,
        "archived": False,
    }
    # Google omits empty fields, so the fixtures omit them too.
    if phone:
        account["recoveryPhone"] = phone
    if recovery:
        account["recoveryEmail"] = recovery
    return account


class Ctx:
    def __init__(self, users, policies=None):
        self._users = users
        self._policies = policies or []
        self.settings = Settings()

    def users(self):
        return self._users

    def policies(self):
        return self._policies

    def complete(self, source):
        return getattr(self, "_completo", {}).get(source, True)

    def measured(self, source):
        return True

def entry(setting, value, target=""):
    """Same shape the Policy API returns: the target comes from policyQuery,
    and its absence means the policy applies to the whole organization."""
    policy = {"setting": {"type": f"settings/{setting}", "value": value}}
    if target:
        policy["policyQuery"] = {"orgUnit": target}
    return policy


# The policy checks now reduce per account, so a population is required: the
# verdict is "who is exposed", not "what does the flag say".
POLICY_USERS = [
    {"primaryEmail": "a@cliente.com", "orgUnitPath": "/", "suspended": False,
     "archived": False},
    {"primaryEmail": "b@cliente.com", "orgUnitPath": "/Ventas", "suspended": False,
     "archived": False},
]


def policy_findings(setting, value, target=""):
    ctx = Ctx(POLICY_USERS, [entry(setting, value, target)])
    return {f.id: f for f in check_policies.run(ctx)}


# ============================================================ 1 · grace period
# These now go through policy_engine: the verdict is per account, and absence
# of a policy is judged against Google's documented default instead of being
# shrugged off.

GRACE = "security.two_step_verification_grace_period"


@pytest.mark.parametrize("seconds,expected", [
    (0, "pass"),
    (7 * 86400, "pass"),
    (14 * 86400, "pass"),
    (15 * 86400, "warn"),      # over a fortnight: worth flagging
    (30 * 86400, "warn"),
    (31 * 86400, "fail"),      # over a month: a permanent hole
    (90 * 86400, "fail"),
])
def test_the_grace_period_has_two_tiers(seconds, expected):
    found = policy_findings(GRACE, {"enrollmentGracePeriod": f"{seconds}s"})["policy-2sv-grace"]
    assert found.status == expected


def test_a_plain_number_is_accepted_as_well_as_a_duration_string():
    assert policy_findings(GRACE, {"enrollment_grace_period": 2592000})[
        "policy-2sv-grace"].status == "warn"


def test_an_unreadable_grace_period_is_not_a_pass():
    found = policy_findings(GRACE, {"enrollmentGracePeriod": "para siempre"})["policy-2sv-grace"]
    assert found.status == "undetermined"
    assert found.details["unresolved"] == len(POLICY_USERS)


def test_with_no_policy_the_documented_default_of_zero_passes():
    ctx = Ctx(POLICY_USERS, [])
    found = {f.id: f for f in check_policies.run(ctx)}["policy-2sv-grace"]
    assert found.status == "pass"


# ========================================================== 2 · allowed methods

FACTOR = "security.two_step_verification_enforcement_factor"


@pytest.mark.parametrize("factor_set,expected", [
    ("ALL", "fail"),                                   # SMS and voice allowed
    ("NO_TELEPHONY", "pass"),
    ("PASSKEY_ONLY", "pass"),
    ("PASSKEY_PLUS_SECURITY_CODE", "pass"),
    ("PASSKEY_PLUS_IP_BOUND_SECURITY_CODE", "pass"),
])
def test_telephony_is_the_line_between_fail_and_pass(factor_set, expected):
    found = policy_findings(FACTOR, {"allowedSignInFactorSet": factor_set})["policy-2sv-methods"]
    assert found.status == expected


def test_the_default_factor_set_is_the_permissive_one_so_no_policy_fails():
    """Google ships ALL, which admits SMS. Doing nothing is not neutral."""
    found = {f.id: f for f in check_policies.run(Ctx(POLICY_USERS, []))}["policy-2sv-methods"]
    assert found.status == "fail"
    assert found.details["from_default"] is True


def test_a_factor_set_google_adds_later_is_flagged_not_assumed_safe():
    found = policy_findings(FACTOR, {"allowedSignInFactorSet": "QUANTUM_ONLY"})["policy-2sv-methods"]
    assert found.status == "undetermined"


def test_a_missing_factor_field_is_flagged_too():
    assert policy_findings(FACTOR, {})["policy-2sv-methods"].status == "undetermined"


def test_the_weak_methods_text_says_why_sms_is_not_a_second_factor():
    found = policy_findings(FACTOR, {"allowedSignInFactorSet": "ALL"})["policy-2sv-methods"]
    assert "SMS" in found.description and "phishing" in found.description


# ================================================ 3 & 4 · legacy and password-only

SIDE_DOORS = [
    ("gmail.imap_access", "policy-imap", "enableImapAccess"),
    ("gmail.pop_access", "policy-pop", "enablePopAccess"),
    ("security.less_secure_apps", "policy-less-secure-apps", "allowLessSecureApps"),
]


@pytest.mark.parametrize("setting,finding_id,field", SIDE_DOORS)
def test_a_side_door_that_is_open_fails(setting, finding_id, field):
    assert policy_findings(setting, {field: True})[finding_id].status == "fail"


@pytest.mark.parametrize("setting,finding_id,field", SIDE_DOORS)
def test_a_side_door_that_is_closed_passes(setting, finding_id, field):
    assert policy_findings(setting, {field: False})[finding_id].status == "pass"


@pytest.mark.parametrize("setting,finding_id,_", SIDE_DOORS)
@pytest.mark.parametrize("value", [{}, {"otroCampo": True}, {"enableImapAccess": "sí"}])
def test_an_unreadable_side_door_is_never_a_pass(setting, finding_id, _, value):
    """The exact failure this codebase shipped twice: a renamed field reading
    as "everything fine"."""
    assert policy_findings(setting, value)[finding_id].status == "undetermined"


def test_snake_case_spellings_work_too():
    """Google's own docs mix the two conventions for these settings."""
    assert policy_findings(
        "gmail.imap_access", {"enable_imap_access": True}
    )["policy-imap"].status == "fail"


def test_the_less_secure_apps_text_explains_why_enforced_2sv_makes_it_worse():
    found = policy_findings(
        "security.less_secure_apps", {"allowLessSecureApps": True}
    )["policy-less-secure-apps"]
    assert "obligatoria" in found.description


def test_one_permissive_org_unit_names_the_accounts_it_leaves_open():
    """IMAP off at the root but on under /Ventas: the finding says who."""
    ctx = Ctx(POLICY_USERS, [
        entry("gmail.imap_access", {"enableImapAccess": False}),
        entry("gmail.imap_access", {"enableImapAccess": True}, "/Ventas"),
    ])
    found = {f.id: f for f in check_policies.run(ctx)}["policy-imap"]
    assert found.status == "fail"
    assert found.accounts == []                     # a setting names no people
    assert found.details["exposed"] == 1            # but still counts them
    assert "b@cliente.com" not in repr(found.to_dict())
    assert found.details["partial_coverage"] is True


# ============================================================== 5 · recovery

SUPER_NO_PHONE = user("ceo@cliente.com", admin=True, phone="")
SUPER_GMAIL = user("cto@cliente.com", admin=True, recovery="cto.personal@gmail.com")
SUPER_OK = user("cio@cliente.com", admin=True, recovery="cio@cliente.com")
NORMAL_NO_PHONE = user("ana@cliente.com", phone="")


def recovery_finding(users):
    found = check_recovery.run(Ctx(users))
    return found[0] if found else None


def test_a_consumer_recovery_mailbox_is_detected():
    for domain in ("gmail.com", "hotmail.com", "yahoo.es", "icloud.com", "outlook.com"):
        assert check_recovery.is_consumer_mailbox(f"alguien@{domain}"), domain


def test_a_corporate_recovery_mailbox_is_not_flagged():
    for address in ("admin@cliente.com", "it@empresa.co.uk", "soporte@sub.cliente.com"):
        assert not check_recovery.is_consumer_mailbox(address), address


def test_a_super_admin_without_a_recovery_phone_fails():
    found = recovery_finding([SUPER_NO_PHONE, SUPER_OK])
    assert found.status == "fail" and found.severity == "critical"
    assert found.accounts == ["ceo@cliente.com"]
    assert "sin teléfono de recuperación" in " ".join(found.affected_items)


def test_a_super_admin_with_a_personal_recovery_mailbox_fails():
    found = recovery_finding([SUPER_GMAIL, SUPER_OK])
    assert found.status == "fail"
    assert found.accounts == ["cto@cliente.com"]
    assert "dominio personal" in " ".join(found.affected_items)
    assert found.details["consumer_recovery_email"] == 1


def test_a_well_configured_super_admin_passes():
    found = recovery_finding([SUPER_OK])
    assert found.status == "pass"
    assert found.accounts == []


def test_only_super_admins_are_judged_here():
    """A normal user without a recovery phone is not this finding's business."""
    found = recovery_finding([SUPER_OK, NORMAL_NO_PHONE])
    assert found.status == "pass"
    assert "ana@cliente.com" not in repr(found.to_dict())


def test_a_suspended_super_admin_is_ignored():
    suspended = user("ex@cliente.com", admin=True, phone="", suspended=True)
    assert recovery_finding([SUPER_OK, suspended]).status == "pass"


def test_a_tenant_with_no_super_admins_produces_nothing():
    assert check_recovery.run(Ctx([NORMAL_NO_PHONE])) == []


def test_the_check_refuses_to_accuse_everyone_when_the_api_returns_no_fields():
    """If the field stopped being returned, "every admin lacks a recovery
    phone" would be a spectacular false positive. It reports undetermined."""
    blind = [
        {"primaryEmail": "a@cliente.com", "isAdmin": True, "suspended": False, "archived": False},
        {"primaryEmail": "b@cliente.com", "isAdmin": True, "suspended": False, "archived": False},
    ]
    found = recovery_finding(blind)
    assert found.status == "undetermined"
    assert found.details["recovery_fields_returned"] is False
    assert "no se puede distinguir" in found.description


def test_one_account_with_the_field_is_enough_to_trust_the_signal():
    blind = {"primaryEmail": "b@cliente.com", "isAdmin": True, "suspended": False, "archived": False}
    found = recovery_finding([SUPER_OK, blind])
    assert found.status == "fail"
    assert found.accounts == ["b@cliente.com"]


def test_the_directory_client_actually_asks_for_the_recovery_fields():
    """The client uses an explicit field mask, so a check that reads a field
    nobody requested would silently see nothing."""
    from vigia.google_client.directory import USER_FIELDS

    assert "recoveryEmail" in USER_FIELDS
    assert "recoveryPhone" in USER_FIELDS


# -------------------------------------------- the composite the user asked for

def test_no_2sv_plus_bad_recovery_is_its_own_critical_finding():
    ghost = user("ghost@cliente.com", admin=True, enrolled_2sv=False,
                 phone="", recovery="ghost@gmail.com")
    findings = {f.id: f for f in composite.run(Ctx([ghost, SUPER_OK]))}
    combined = findings["composite-superadmin-no-2sv-no-recovery"]
    assert combined.status == "fail" and combined.severity == "critical"
    assert combined.accounts == ["ghost@cliente.com"]


def test_the_combined_finding_explains_why_it_is_worse_than_its_parts():
    ghost = user("ghost@cliente.com", admin=True, enrolled_2sv=False, phone="")
    # SUPER_OK carries a phone, so the recovery signal is trustworthy here.
    combined = {f.id: f for f in composite.run(Ctx([ghost, SUPER_OK]))}[
        "composite-superadmin-no-2sv-no-recovery"
    ]
    assert "permanente" in combined.description
    assert "días" in combined.description


def test_a_super_admin_with_2sv_does_not_reach_the_combined_finding():
    weak_recovery_only = user("x@cliente.com", admin=True, recovery="x@gmail.com")
    findings = {f.id: f for f in composite.run(Ctx([weak_recovery_only]))}
    assert findings["composite-superadmin-no-2sv-no-recovery"].status == "pass"


def test_the_signal_is_dropped_when_the_api_returns_no_recovery_fields():
    """The bug this guard exists for: "no recovery phone" is inferred from an
    absent field, so if the field stopped being returned the signal would fire
    for every account and light up the harshest composite for the whole tenant.
    Here nobody has the field, so the signal is not trusted at all."""
    blind = [
        {"primaryEmail": "a@cliente.com", "isAdmin": True, "isEnrolledIn2Sv": False,
         "suspended": False, "archived": False, "lastLoginTime": RECENT},
        {"primaryEmail": "b@cliente.com", "isAdmin": True, "isEnrolledIn2Sv": False,
         "suspended": False, "archived": False, "lastLoginTime": RECENT},
    ]
    findings = {f.id: f for f in composite.run(Ctx(blind))}
    assert findings["composite-superadmin-no-2sv-no-recovery"].status == "pass"
    # The plain 2SV composite still reports them: only the recovery part is
    # withheld, not the finding it was combined with.
    assert set(findings["composite-superadmin-no-2sv"].accounts) == {
        "a@cliente.com", "b@cliente.com"
    }


def test_the_combined_accounts_are_a_subset_of_the_broader_2sv_finding():
    """Same invariant as the rest of the composite engine: the specific
    finding can never name someone the broader one does not."""
    ghost = user("ghost@cliente.com", admin=True, enrolled_2sv=False, phone="")
    findings = {f.id: f for f in composite.run(Ctx([ghost, SUPER_OK]))}
    specific = set(findings["composite-superadmin-no-2sv-no-recovery"].accounts)
    broader = set(findings["composite-superadmin-no-2sv"].accounts)
    assert specific <= broader


def test_the_new_signal_is_declared_in_the_engine():
    assert "insecure_recovery" in composite.SIGNALS
