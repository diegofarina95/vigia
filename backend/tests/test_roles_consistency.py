"""Administrative roles: one definition, disjoint sets, no contradictions.

This file exists because of a real production report that said, about the
same tenant and the same scan:

    "Super admin with no 2FA that has never signed in" ......... FAIL
    "Super admin without 2-Step Verification" .................. PASS

and listed one account, simultaneously, as a delegated admin, as a super
admin without 2FA, and inside the super-admin count. Both statements can't
be true, and the reader has no way to tell which one to believe.

The fixture population below is the minimum needed to reproduce every case,
and the tests assert the two invariants that make the contradiction
impossible: the role predicates are the single definition, and no report may
leave `check_consistency` with a violation.
"""
from dataclasses import dataclass

import pytest

from vigia.checks import check_2sv, check_super_admins, composite
from vigia.checks.consistency import check_consistency
from vigia.checks.roles import (
    delegated_admins,
    is_admin,
    is_delegated_admin,
    is_super_admin,
    super_admins,
)

EPOCH = "1970-01-01T00:00:00.000Z"  # Google's "never signed in"
RECENT = "2026-07-28T09:00:00.000Z"


@dataclass
class Settings:
    dormant_days: int = 90
    super_admin_threshold: int = 4


def user(email, *, admin=False, delegated=False, enrolled_2sv=True,
         last_login=RECENT, suspended=False):
    return {
        "primaryEmail": email,
        "isAdmin": admin,
        "isDelegatedAdmin": delegated,
        "isEnrolledIn2Sv": enrolled_2sv,
        "isEnforcedIn2Sv": enrolled_2sv,
        "lastLoginTime": last_login,
        "suspended": suspended,
        "archived": False,
    }


# The five cases asked for, plus the one that actually caused the bug:
# an account with BOTH flags set, which Google does return.
GHOST = user("ghost@example.com", admin=True, enrolled_2sv=False, last_login=EPOCH)
SAFE_SUPER = user("cto@example.com", admin=True)
DELEGATED = user("helpdesk@example.com", delegated=True, enrolled_2sv=False)
NORMAL = user("ana@example.com", enrolled_2sv=False)
SUSPENDED_ADMIN = user("exadmin@example.com", admin=True, enrolled_2sv=False, suspended=True)
BOTH_FLAGS = user("bart@example.com", admin=True, delegated=True, enrolled_2sv=False)

POPULATION = [GHOST, SAFE_SUPER, DELEGATED, NORMAL, SUSPENDED_ADMIN, BOTH_FLAGS]


class Ctx:
    def __init__(self, users, settings=None):
        self._users = users
        self.settings = settings or Settings()

    def users(self):
        return self._users

    def complete(self, source):
        return getattr(self, "_completo", {}).get(source, True)

    def measured(self, source):
        return True

def findings_for(users):
    """Every finding the admin-role checks produce for a population."""
    ctx = Ctx(users)
    return check_2sv.run(ctx) + check_super_admins.run(ctx) + composite.run(ctx)


def by_id(findings):
    return {f.id: f for f in findings}


# ----------------------------------------------------- the predicates alone

def test_the_two_sets_are_disjoint_even_when_google_sets_both_flags():
    """`isAdmin` and `isDelegatedAdmin` are independent fields and an account
    can come back with both. Whoever holds super-admin power is a super admin;
    counting them as delegated too is what produced the contradiction."""
    assert is_super_admin(BOTH_FLAGS)
    assert not is_delegated_admin(BOTH_FLAGS)
    assert is_admin(BOTH_FLAGS)


def test_a_delegated_admin_is_not_a_super_admin():
    assert is_delegated_admin(DELEGATED)
    assert not is_super_admin(DELEGATED)


def test_a_normal_user_is_neither():
    assert not is_admin(NORMAL)


def test_the_role_survives_suspension():
    """Suspension is not a role change: the account still holds the privilege,
    and `is_active` is what filters it out of the findings."""
    assert is_super_admin(SUSPENDED_ADMIN)


def test_the_string_true_counts_as_true():
    """Missing a super admin is far worse than being strict about types."""
    assert is_super_admin({"primaryEmail": "x@y.com", "isAdmin": "true"})
    assert not is_super_admin({"primaryEmail": "x@y.com", "isAdmin": "false"})
    assert not is_super_admin({"primaryEmail": "x@y.com"})


def test_every_admin_is_in_exactly_one_set():
    supers = {u["primaryEmail"] for u in super_admins(POPULATION)}
    delegated = {u["primaryEmail"] for u in delegated_admins(POPULATION)}
    assert not supers & delegated
    assert supers == {"ghost@example.com", "cto@example.com",
                      "exadmin@example.com", "bart@example.com"}
    assert delegated == {"helpdesk@example.com"}


def test_no_check_reads_the_raw_directory_fields():
    """The predicates are only a single definition if nothing bypasses them."""
    import pathlib

    checks = pathlib.Path(__file__).resolve().parents[1] / "vigia" / "checks"
    offenders = [
        path.name
        for path in checks.glob("*.py")
        if path.name != "roles.py" and (
            "isAdmin" in path.read_text() or "isDelegatedAdmin" in path.read_text()
        )
    ]
    assert offenders == [], f"deben usar roles.py: {offenders}"


# ------------------------------------------- the reported contradiction, gone

def test_the_atomic_super_admin_finding_fails_when_a_super_admin_has_no_2sv():
    """The one the user saw pass while the composite failed."""
    found = by_id(findings_for(POPULATION))
    atomic = found["composite-superadmin-no-2sv"]
    assert atomic.status == "fail"
    assert set(atomic.accounts) == {"ghost@example.com", "bart@example.com"}


def test_the_specific_composite_fails_too_and_they_agree():
    found = by_id(findings_for(POPULATION))
    specific = found["composite-superadmin-dormant-no-2sv"]
    broader = found["composite-superadmin-no-2sv"]
    assert specific.status == "fail"
    # The specific finding's accounts are a subset of the broader one's, so
    # the broader one can never be the cleaner of the two.
    assert set(specific.accounts) <= set(broader.accounts)


def test_a_super_admin_is_never_reported_as_a_delegated_admin():
    found = by_id(findings_for(POPULATION))
    delegated = set(found["2sv-delegated-admins"].accounts)
    delegated |= set(found["delegated-admins"].affected_items)
    supers = set(found["super-admin-count"].accounts)
    assert not delegated & supers
    assert "bart@example.com" not in delegated


def test_the_suspended_admin_is_not_reported_at_all():
    """Suspended accounts hold no live risk and would inflate every count."""
    blob = repr([f.to_dict() for f in findings_for(POPULATION)])
    assert "exadmin@example.com" not in blob


# --------------------------------------------------- the safety net, point 5

def test_the_fixture_population_produces_a_coherent_report():
    assert check_consistency(findings_for(POPULATION)) == []


@pytest.mark.parametrize("users", [
    POPULATION,
    [GHOST],
    [SAFE_SUPER, NORMAL],
    [DELEGATED, NORMAL],
    [BOTH_FLAGS],
    [SUSPENDED_ADMIN],
    [],
])
def test_no_population_can_produce_a_contradiction(users):
    assert check_consistency(findings_for(users)) == []


def test_the_whole_scan_engine_runs_the_check():
    """Wired into `collect_findings`, not `run_scan`, so the demo route and
    any future caller are covered too."""
    import inspect

    from vigia import scan

    assert "consistency_diagnostic" in inspect.getsource(scan.collect_findings)


def test_stored_scans_are_verified_again_on_the_way_out():
    """Scans produced before the check existed are still in the database and
    still contain the contradiction, so the payload the reader receives is
    verified too — the archive must not be a way around the safety net."""
    import inspect

    from vigia.api import routes

    source = inspect.getsource(routes._latest_payload)
    assert "consistency_diagnostic" in source
    assert "internal-consistency" in source  # never added twice


# A checker that always returned [] would pass everything above, so the two
# contradictions the user described are injected here and must be caught.

def test_it_catches_an_account_reported_as_both_kinds_of_admin():
    found = findings_for(POPULATION)
    data = [f.to_dict() for f in found]
    for finding in data:
        if finding["id"] == "2sv-delegated-admins":
            finding["accounts"].append("bart@example.com")
    violations = check_consistency(data)
    assert violations and "bart@example.com" in violations[0]
    assert "disjuntos" in violations[0]


def test_it_catches_the_overlap_even_when_only_the_printed_list_shows_it():
    """`delegated-admins` prints accounts through `affected_items` only, which
    is exactly where the overlap was visible in production."""
    data = [f.to_dict() for f in findings_for(POPULATION)]
    for finding in data:
        if finding["id"] == "delegated-admins":
            finding["affected_items"].append("ghost@example.com")
    assert any("ghost@example.com" in v for v in check_consistency(data))


def test_it_catches_a_composite_failing_while_its_broader_check_passes():
    data = [f.to_dict() for f in findings_for(POPULATION)]
    for finding in data:
        if finding["id"] == "composite-superadmin-no-2sv":
            finding["status"] = "pass"  # the false statement the user saw
    violations = check_consistency(data)
    assert any(
        "composite-superadmin-dormant-no-2sv" in v and "composite-superadmin-no-2sv" in v
        for v in violations
    ), violations


def test_it_catches_an_atomic_check_passing_while_a_composite_fails():
    data = [f.to_dict() for f in findings_for(POPULATION)]
    for finding in data:
        if finding["id"] == "2sv-users":
            finding["status"], finding["accounts"] = "pass", []
    assert any("2sv-users" in v for v in check_consistency(data))


def test_a_violation_becomes_a_visible_finding_instead_of_a_crash():
    from vigia.scan import consistency_diagnostic

    data = [f.to_dict() for f in findings_for(POPULATION)]
    for finding in data:
        if finding["id"] == "composite-superadmin-no-2sv":
            finding["status"] = "pass"
    diagnostic = consistency_diagnostic(data, label="test")
    assert len(diagnostic) == 1
    assert diagnostic[0].id == "internal-consistency"
    assert diagnostic[0].status == "undetermined"
    assert "contradicen" in diagnostic[0].description
    assert consistency_diagnostic([f.to_dict() for f in findings_for(POPULATION)]) == []
