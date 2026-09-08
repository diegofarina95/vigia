"""Policy reduction: the three states, and the per-OU picture.

Everything downstream reads a boolean out of this module, so a mistake here is
not one wrong check — it is twelve. The fixtures cover the five states the
brief asked for: explicit-safe, explicit-unsafe, no policy (Google's default),
a policy that only covers one organizational unit, and a caller who cannot
resolve the answer at all.
"""
import pytest

from vigia.checks import policy_engine as pe
from vigia.checks.policy_engine import ROOT, Effective, coverage, parse, reduce_for


def policy(setting, value, *, ou="", group="", order=0.0, system=False):
    """The shape the Policy API actually returns."""
    raw = {"setting": {"type": f"settings/{setting}", "value": value}}
    query = {}
    if ou:
        query["orgUnit"] = ou
    if group:
        query["group"] = group
    if order:
        query["sortOrder"] = order
    if query:
        raw["policyQuery"] = query
    if system:
        raw["type"] = "SYSTEM"
    return raw


def user(email, ou=ROOT):
    return {"primaryEmail": email, "orgUnitPath": ou}


SHARING = "drive_and_docs.external_sharing"
FACTOR = "security.two_step_verification_enforcement_factor"
IMAP = "gmail.imap_access"


# ------------------------------------------------------------- parsing

def test_the_setting_prefix_and_both_spellings_are_handled():
    [p] = parse([policy(SHARING, {"externalSharingMode": "DISALLOWED"}, ou="/Ventas")])
    assert p.setting_type == SHARING          # "settings/" stripped
    assert p.value == {"external_sharing_mode": "DISALLOWED"}  # camel → snake
    assert p.org_unit == "/Ventas"


def test_a_policy_without_a_setting_type_is_dropped_not_guessed():
    assert parse([{"policyQuery": {"orgUnit": "/x"}}]) == []


def test_a_malformed_sort_order_does_not_crash_the_reduction():
    [p] = parse([{"setting": {"type": f"settings/{SHARING}", "value": {}},
                  "policyQuery": {"sortOrder": "no soy un número"}}])
    assert p.sort_order == 0.0


# ------------------------------------------------- the three states

def test_explicitly_safe_reads_as_explicit():
    policies = parse([policy(SHARING, {"external_sharing_mode": "DISALLOWED"})])
    effective = reduce_for(policies, SHARING)
    assert effective.source == "explicit"
    assert effective.value["external_sharing_mode"] == "DISALLOWED"


def test_explicitly_unsafe_reads_as_explicit_too():
    policies = parse([policy(SHARING, {"external_sharing_mode": "ALLOWED"})])
    assert reduce_for(policies, SHARING).source == "explicit"


def test_no_policy_falls_back_to_googles_documented_default():
    """The change that turns five "check it by hand" cards into real findings:
    with no policy the tenant is on Google's default, and for Drive sharing
    that default is ALLOWED."""
    effective = reduce_for([], SHARING)
    assert effective.source == "default"
    assert effective.value["external_sharing_mode"] == "ALLOWED"
    assert effective.from_default


@pytest.mark.parametrize("setting,field,default", [
    (SHARING, "external_sharing_mode", "ALLOWED"),
    ("gmail.auto_forwarding", "enable_auto_forwarding", True),
    (FACTOR, "allowed_sign_in_factor_set", "ALL"),
    ("workspace_marketplace.apps_access_options", "access_level", "ALLOW_ALL"),
    ("security.password", "minimum_length", 8),
    ("security.less_secure_apps", "allow_less_secure_apps", False),
    ("security.two_step_verification_grace_period", "enrollment_grace_period", "0s"),
    ("groups_for_business.groups_sharing", "collaboration_capability", "DOMAIN_USERS_ONLY"),
])
def test_the_documented_defaults_are_transcribed_exactly(setting, field, default):
    assert reduce_for([], setting).value[field] == default


@pytest.mark.parametrize("setting", [IMAP, "gmail.pop_access",
                                     "security.session_controls"])
def test_a_setting_google_documents_no_default_for_stays_unresolved(setting):
    """Absence is only a verdict when Google publishes what absence means."""
    effective = reduce_for([], setting)
    assert effective.source == "unresolved"
    assert not effective.resolved


def test_an_unknown_setting_is_unresolved_rather_than_empty_pass():
    assert reduce_for([], "gmail.setting_que_no_existe").source == "unresolved"


# ------------------------------------------------------------- scoping

def test_a_policy_on_an_ou_reaches_its_children():
    policies = parse([policy(SHARING, {"external_sharing_mode": "DISALLOWED"},
                             ou="/Ventas")])
    assert reduce_for(policies, SHARING, "/Ventas").source == "explicit"
    assert reduce_for(policies, SHARING, "/Ventas/Interno").source == "explicit"


def test_a_policy_on_an_ou_does_not_reach_a_sibling():
    policies = parse([policy(SHARING, {"external_sharing_mode": "DISALLOWED"},
                             ou="/Ventas")])
    outside = reduce_for(policies, SHARING, "/Ingenieria")
    assert outside.source == "default"
    assert outside.value["external_sharing_mode"] == "ALLOWED"


def test_a_prefix_that_is_not_a_real_ancestor_does_not_match():
    """"/Vent" must not swallow "/Ventas"."""
    policies = parse([policy(SHARING, {"external_sharing_mode": "DISALLOWED"},
                             ou="/Vent")])
    assert reduce_for(policies, SHARING, "/Ventas").source == "default"


def test_the_root_policy_reaches_everyone():
    policies = parse([policy(SHARING, {"external_sharing_mode": "DISALLOWED"}, ou=ROOT)])
    assert reduce_for(policies, SHARING, "/Cualquiera/Cosa").source == "explicit"


# ------------------------------------------------------------ reducers

def test_max_takes_the_value_with_the_greatest_sort_order():
    policies = parse([
        policy(SHARING, {"external_sharing_mode": "DISALLOWED"}, order=1),
        policy(SHARING, {"external_sharing_mode": "ALLOWED"}, order=9),
    ])
    assert reduce_for(policies, SHARING).value["external_sharing_mode"] == "ALLOWED"


def test_order_is_relative_so_googles_september_renumbering_cannot_flip_it():
    """On 2026-09-01 Google shifts the integer part of SYSTEM sortOrder by one.
    Only the ordering is ever compared, so the same pair reduces the same way
    before and after."""
    before = parse([
        policy(SHARING, {"external_sharing_mode": "DISALLOWED"}, order=101.00049),
        policy(SHARING, {"external_sharing_mode": "ALLOWED"}, order=102.00049),
    ])
    after = parse([
        policy(SHARING, {"external_sharing_mode": "DISALLOWED"}, order=100.00049),
        policy(SHARING, {"external_sharing_mode": "ALLOWED"}, order=101.00049),
    ])
    assert (reduce_for(before, SHARING).value
            == reduce_for(after, SHARING).value)


def test_max_fills_each_field_from_the_policy_that_sets_it():
    policies = parse([
        policy("security.password", {"minimum_length": 14}, order=1),
        policy("security.password", {"allow_reuse": True}, order=2),
    ])
    value = reduce_for(policies, "security.password").value
    assert value["minimum_length"] == 14 and value["allow_reuse"] is True


def test_maxmap_deduplicates_the_allowlist_by_application_id():
    policies = parse([
        policy("workspace_marketplace.apps_allowlist",
               {"apps": [{"application_id": "a", "access": "ALLOWED"},
                         {"application_id": "b", "access": "ALLOWED"}]}, order=1),
        policy("workspace_marketplace.apps_allowlist",
               {"apps": [{"application_id": "a", "access": "BLOCKED"}]}, order=5),
    ])
    apps = {a["application_id"]: a["access"]
            for a in reduce_for(policies, "workspace_marketplace.apps_allowlist").value["apps"]}
    assert apps == {"a": "BLOCKED", "b": "ALLOWED"}


# ------------------------------------------- what cannot be resolved

def test_a_group_scoped_policy_is_flagged_because_membership_is_unknown():
    """Vigía does not read group membership. A setting steered by group could
    be anything for whoever is in it, so it never counts as safe."""
    policies = parse([policy(SHARING, {"external_sharing_mode": "DISALLOWED"},
                             group="grupo-direccion")])
    effective = reduce_for(policies, SHARING)
    assert effective.group_policies == ("grupo-direccion",)
    # the group policy is not applied to the OU reduction
    assert effective.source == "default"


# --------------------------------------------- the per-account picture

def unsafe_sharing(effective: Effective):
    mode = str(effective.value.get("external_sharing_mode") or "").upper()
    if mode not in ("ALLOWED", "ALLOWLISTED_DOMAINS", "DISALLOWED"):
        return None  # an enum Google added later: do not invent a verdict
    return mode == "ALLOWED"


PLANTILLA = [
    user("dir1@x.com", "/Direccion"),
    user("dir2@x.com", "/Direccion"),
    user("ven1@x.com", "/Ventas"),
    user("ven2@x.com", "/Ventas"),
    user("raiz@x.com", ROOT),
]


def test_a_setting_locked_down_only_in_one_ou_names_who_is_left_out():
    """The finding the product is sold on: not "sharing is on", but "sharing
    is off only under /Direccion; three accounts are outside it"."""
    policies = parse([policy(SHARING, {"external_sharing_mode": "DISALLOWED"},
                             ou="/Direccion")])
    result = coverage(policies, SHARING, PLANTILLA, unsafe_sharing)

    assert result.partial
    assert result.exposed == ["raiz@x.com", "ven1@x.com", "ven2@x.com"]
    assert result.total_accounts == 5
    assert "/Direccion" in result.safe_org_units


def test_locked_down_at_the_root_leaves_nobody_exposed():
    policies = parse([policy(SHARING, {"external_sharing_mode": "DISALLOWED"}, ou=ROOT)])
    result = coverage(policies, SHARING, PLANTILLA, unsafe_sharing)
    assert result.exposed == [] and not result.partial


def test_with_no_policy_at_all_everyone_is_exposed_by_default():
    result = coverage([], SHARING, PLANTILLA, unsafe_sharing)
    assert len(result.exposed) == 5
    assert not result.partial, "todos expuestos no es cobertura parcial"
    assert all(e.from_default for e in result.by_ou.values())


def test_an_unknown_enum_puts_accounts_in_unresolved_not_in_safe():
    policies = parse([policy(SHARING, {"external_sharing_mode": "MODO_NUEVO"}, ou=ROOT)])
    result = coverage(policies, SHARING, PLANTILLA, unsafe_sharing)
    assert result.exposed == []
    assert len(result.unresolved) == 5


def test_a_group_policy_moves_accounts_to_unresolved_not_to_safe():
    policies = parse([
        policy(SHARING, {"external_sharing_mode": "DISALLOWED"}, ou=ROOT),
        policy(SHARING, {"external_sharing_mode": "ALLOWED"}, group="ventas@x.com"),
    ])
    result = coverage(policies, SHARING, PLANTILLA, unsafe_sharing)
    assert result.exposed == []
    assert len(result.unresolved) == 5
    assert result.group_policies == ("ventas@x.com",)


def test_a_setting_with_no_documented_default_leaves_everyone_unresolved():
    result = coverage([], IMAP, PLANTILLA, lambda e: bool(e.value.get("enable_imap_access")))
    assert result.exposed == []
    assert len(result.unresolved) == 5


def test_an_account_with_no_org_unit_is_treated_as_the_root():
    result = coverage([], SHARING, [{"primaryEmail": "sin-ou@x.com"}], unsafe_sharing)
    assert result.exposed == ["sin-ou@x.com"]
    assert ROOT in result.by_ou


def test_every_declared_setting_has_a_reducer_and_a_stated_default_policy():
    """A setting with no reducer would silently reduce wrong, and one whose
    `defaults` were forgotten would fabricate a pass. Both are caught here."""
    for name, setting in pe.SETTINGS.items():
        assert setting.reducer in (pe.MAX, pe.MERGE, pe.MAXMAP), name
        assert setting.defaults is None or isinstance(setting.defaults, dict), name
        if setting.reducer == pe.MAXMAP:
            assert setting.key_field, f"{name}: MAXMAP necesita clave primaria"
