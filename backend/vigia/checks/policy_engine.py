"""Turn raw Cloud Identity policies into an effective value per account.

The Policy API does **not** hand you the value the Admin console shows. It
returns the policies whose value was set explicitly, each with the scope it
applies to, and documents the algorithm the caller has to run:

    "To reduce a given setting for a given user:
     1. Filter out all policies that don't apply to the user.
     2. Apply the Reducer of the given Setting."

Reading one boolean out of that list and believing it is how a scanner ends up
reporting the opposite of the truth. So this module does the reduction, and it
answers three questions instead of two:

* the setting is explicitly set to something unsafe   → fail
* the setting is explicitly set to something safe     → pass
* **no policy at all**                                → the tenant is on
  Google's documented default, so the default is evaluated. For five of these
  settings the default is the permissive one — external Drive sharing defaults
  to ALLOWED, Gmail auto-forwarding to true, the 2SV factor set to ALL — and
  calling that "not verified" would hide the most common real exposure there
  is.

The payoff is the finding nobody else produces: because policies are scoped to
organizational units, and the directory tells us each account's `orgUnitPath`,
the reduction can be run **per account** and say "enforced only under
/Dirección — 8 accounts are outside it" instead of a flat yes/no.

Two limits are declared rather than papered over:

* **Group- and licence-targeted policies cannot be resolved.** Vigía does not
  read group membership, so a setting steered by group is reported as
  unresolvable for the accounts it might touch, never as a pass.
* **Google does not publish which reducer each setting uses.** It defines Max,
  Merge and MaxMap but ships no per-setting mapping. The table below states a
  reducer per setting explicitly; anything not stated does not get to produce a
  pass. From 2026-09-01 Google renumbers the `sortOrder` of SYSTEM policies, so
  only relative order is ever compared, never an absolute value.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace

# ---------------------------------------------------------------- reducers

MAX = "max"        # highest sortOrder wins, field by field
MERGE = "merge"    # highest sortOrder per field; arrays concatenate
MAXMAP = "maxmap"  # arrays keyed by a primary field; Max on the rest


@dataclass(frozen=True)
class Setting:
    """One policy setting, with everything needed to reduce and judge it.

    `defaults` holds Google's documented default field values. `None` means
    Google does not document a default for this setting, which is not the same
    as "there is no default" — it means we cannot state one, so absence stays
    unresolved instead of becoming a verdict.
    """

    type: str
    reducer: str
    defaults: dict | None = None
    key_field: str | None = None  # MAXMAP only
    aliases: tuple[str, ...] = ()  # enum spellings Google mixes across pages


# Defaults transcribed from the "Default field values" table in the Policy API
# concepts page. The permissive ones are the whole reason this module exists.
SETTINGS: dict[str, Setting] = {
    "drive_and_docs.external_sharing": Setting(
        type="drive_and_docs.external_sharing",
        reducer=MAX,
        defaults={
            "external_sharing_mode": "ALLOWED",  # permissive by default
            "warn_for_external_sharing": True,
            "allow_receiving_external_files": True,
            "allow_publishing_files": True,
        },
    ),
    # Calendar: Google documents both defaults, and the secondary one is the
    # permissive surprise — a calendar nobody thinks about is readable in full
    # from outside by default, event titles included.
    "calendar.primary_calendar_max_allowed_external_sharing": Setting(
        type="calendar.primary_calendar_max_allowed_external_sharing",
        reducer=MAX,
        defaults={"max_allowed_external_sharing": "EXTERNAL_FREE_BUSY_ONLY"},
    ),
    "calendar.secondary_calendar_max_allowed_external_sharing": Setting(
        type="calendar.secondary_calendar_max_allowed_external_sharing",
        reducer=MAX,
        defaults={"max_allowed_external_sharing": "EXTERNAL_ALL_INFO_READ_ONLY"},
    ),
    "drive_and_docs.general_access_default": Setting(
        type="drive_and_docs.general_access_default",
        reducer=MAX,
        # Google spells this enum two different ways across its own pages:
        # PRIVATE_TO_OWNER in the settings table, LINK_SHARING_PRIVATE in the
        # defaults table. Both mean the same thing and both are accepted.
        defaults={"default_file_access": "LINK_SHARING_PRIVATE"},
        aliases=("PRIVATE_TO_OWNER", "LINK_SHARING_PRIVATE"),
    ),
    "gmail.auto_forwarding": Setting(
        type="gmail.auto_forwarding",
        reducer=MAX,
        defaults={"enable_auto_forwarding": True},  # permissive by default
    ),
    "gmail.imap_access": Setting(
        type="gmail.imap_access",
        reducer=MAX,
        defaults=None,  # Google documents no default for this one
    ),
    "gmail.pop_access": Setting(
        type="gmail.pop_access",
        reducer=MAX,
        defaults=None,  # Google documents no default for this one
    ),
    "security.password": Setting(
        type="security.password",
        reducer=MAX,
        defaults={
            "minimum_length": 8,  # below the 12 this product asks for
            "allow_reuse": False,
            "expiration_duration": 0,
        },
    ),
    "security.session_controls": Setting(
        type="security.session_controls",
        reducer=MAX,
        defaults=None,
    ),
    "security.less_secure_apps": Setting(
        type="security.less_secure_apps",
        reducer=MAX,
        defaults={"allow_less_secure_apps": False},
    ),
    "security.two_step_verification_enforcement": Setting(
        type="security.two_step_verification_enforcement",
        reducer=MAX,
        defaults=None,  # no enforcement date documented as a default
    ),
    "security.two_step_verification_grace_period": Setting(
        type="security.two_step_verification_grace_period",
        reducer=MAX,
        defaults={"enrollment_grace_period": "0s"},
    ),
    "security.two_step_verification_enforcement_factor": Setting(
        type="security.two_step_verification_enforcement_factor",
        reducer=MAX,
        defaults={"allowed_sign_in_factor_set": "ALL"},  # telephony allowed
    ),
    "security.two_step_verification_device_trust": Setting(
        type="security.two_step_verification_device_trust",
        reducer=MAX,
        defaults=None,
    ),
    "workspace_marketplace.apps_access_options": Setting(
        type="workspace_marketplace.apps_access_options",
        reducer=MAX,
        # "For K12 customers: ALLOW_NONE. Otherwise: ALLOW_ALL." Vigía cannot
        # tell whether a tenant is K12, so it assumes the general case and
        # says so in the finding.
        defaults={"access_level": "ALLOW_ALL", "allow_all_internal_apps": False},
    ),
    "workspace_marketplace.apps_allowlist": Setting(
        type="workspace_marketplace.apps_allowlist",
        reducer=MAXMAP,
        key_field="application_id",
        defaults={"apps": []},
    ),
    "groups_for_business.groups_sharing": Setting(
        type="groups_for_business.groups_sharing",
        reducer=MAX,
        defaults={
            "collaboration_capability": "DOMAIN_USERS_ONLY",
            "owners_can_allow_external_members": False,
        },
    ),
}

ROOT = "/"


# ------------------------------------------------------------- parsing

def _camel_to_snake(name: str) -> str:
    out = []
    for char in name:
        if char.isupper():
            out.append("_")
            out.append(char.lower())
        else:
            out.append(char)
    return "".join(out).lstrip("_")


def normalize_value(value: dict) -> dict:
    """Google mixes camelCase and snake_case for the same fields across its
    own documentation and responses, so everything is read in one spelling."""
    if not isinstance(value, dict):
        return {}
    return {_camel_to_snake(str(k)): v for k, v in value.items()}


@dataclass
class Policy:
    """One policy as the API returned it, in the shape reduction needs."""

    setting_type: str
    value: dict
    org_unit: str = ""
    group: str = ""
    sort_order: float = 0.0
    system: bool = False

    @property
    def scoped_to_group(self) -> bool:
        return bool(self.group)

    @property
    def opaque_ou(self) -> bool:
        """The API names organizational units by ID (`orgUnits/03ph8a…`) while
        the directory names them by path (`/Ventas`). An ID we could not map
        to a path is not "does not apply" — it is "cannot tell", and the two
        must never be confused: treating it as inapplicable makes the setting
        fall back to Google's documented default and report a value the
        customer does not have."""
        return self.org_unit.startswith(OU_ID_PREFIX)

    @property
    def target(self) -> str:
        if self.group:
            return f"grupo {self.group}"
        return self.org_unit or ROOT


OU_ID_PREFIX = "orgUnits/"


def _root_id(parsed: list[Policy]) -> str:
    """Which organizational-unit ID is the root, if it can be told.

    Google returns its own defaults as policies of type SYSTEM, and those are
    customer-wide, so they sit on the root. When every SYSTEM policy shares one
    ID, that ID is the root and can be mapped to `/`.

    Deliberately conservative: with zero or several candidates nothing is
    mapped, and the affected accounts come back as unresolved. An inference
    that silently picked the wrong unit would apply one team's settings to the
    whole company.
    """
    candidates = {p.org_unit for p in parsed if p.system and p.org_unit}
    return candidates.pop() if len(candidates) == 1 else ""


def parse(policies: list[dict]) -> list[Policy]:
    """Read the API payload. Anything without a setting type is dropped."""
    parsed: list[Policy] = []
    for raw in policies or []:
        setting = raw.get("setting") or {}
        setting_type = str(setting.get("type") or "").removeprefix("settings/")
        if not setting_type:
            continue
        query = raw.get("policyQuery") or raw.get("policy_query") or {}
        try:
            sort_order = float(query.get("sortOrder", query.get("sort_order", 0)) or 0)
        except (TypeError, ValueError):
            sort_order = 0.0
        parsed.append(
            Policy(
                setting_type=setting_type,
                value=normalize_value(setting.get("value") or {}),
                org_unit=str(query.get("orgUnit") or query.get("org_unit") or ""),
                group=str(query.get("group") or ""),
                sort_order=sort_order,
                system=str(raw.get("type") or "").upper() == "SYSTEM",
            )
        )
    root = _root_id(parsed)
    if root:
        for index, policy in enumerate(parsed):
            if policy.org_unit == root:
                parsed[index] = replace(policy, org_unit=ROOT)
    return parsed


# ------------------------------------------------------------ reduction

def applies_to_ou(policy: Policy, ou_path: str) -> bool:
    """An OU policy applies to that OU and everything under it."""
    if policy.scoped_to_group:
        return False  # membership is unknown; handled separately
    scope = policy.org_unit or ROOT
    if scope == ROOT:
        return True
    target = ou_path or ROOT
    return target == scope or target.startswith(scope.rstrip("/") + "/")


def _apply(reducer: str, applicable: list[Policy], setting: Setting) -> dict:
    """Combine the policies that apply, in ascending sortOrder so the highest
    wins. Only relative order is used: Google renumbers SYSTEM sortOrder on
    2026-09-01, so absolute values are not comparable across time."""
    ordered = sorted(applicable, key=lambda p: p.sort_order)
    if reducer == MAXMAP and setting.key_field:
        merged: dict = {}
        by_key: dict[str, dict] = {}
        for policy in ordered:
            for name, value in policy.value.items():
                if not isinstance(value, list):
                    merged[name] = value
                    continue
                for entry in value:
                    if not isinstance(entry, dict):
                        continue
                    key = str(entry.get(setting.key_field, ""))
                    by_key.setdefault(key, {}).update(entry)
        if by_key:
            merged["apps"] = list(by_key.values())
        return merged

    merged = {}
    for policy in ordered:
        for name, value in policy.value.items():
            if reducer == MERGE and isinstance(value, list):
                merged[name] = list(merged.get(name, [])) + list(value)
            else:
                merged[name] = value
    return merged


@dataclass
class Effective:
    """The reduced value for one scope, and where it came from."""

    value: dict
    source: str  # "explicit" | "default" | "unresolved"
    target: str = ROOT
    reducer: str = MAX
    #: Group-scoped policies exist for this setting, so the answer may be
    #: wrong for whoever belongs to those groups.
    group_policies: tuple[str, ...] = ()
    contributing: int = 0

    @property
    def resolved(self) -> bool:
        return self.source in ("explicit", "default")

    @property
    def from_default(self) -> bool:
        return self.source == "default"


def reduce_for(
    policies: list[Policy],
    setting_type: str,
    ou_path: str = ROOT,
    listing_complete: bool = True,
) -> Effective:
    """The effective value of one setting for one organizational unit.

    `listing_complete=False` means the policy listing itself was truncated, and
    that changes what an ABSENCE is allowed to mean. Normally a setting with no
    explicit policy is Google's documented default, and saying so is true and
    useful. If pages were dropped, absence might simply be a page we never
    fetched — so the same code path would print "Google's default value, which
    nobody has changed" about a setting the customer deliberately loosened.

    With an incomplete listing, absence is unresolved. A default is only a
    verdict when we know nothing was hidden from us.
    """

    setting = SETTINGS.get(setting_type)
    if setting is None:
        return Effective(value={}, source="unresolved", target=ou_path or ROOT)

    mine = [p for p in policies if p.setting_type == setting_type]
    groups = tuple(sorted({p.group for p in mine if p.scoped_to_group}))
    applicable = [p for p in mine if applies_to_ou(p, ou_path)]

    # A policy on an organizational unit we could not place might be the one
    # that governs this account — unless the account sits at the root, which
    # no child unit can override.
    target_path = ou_path or ROOT
    if target_path != ROOT and any(p.opaque_ou for p in mine):
        return Effective(
            value={}, source="unresolved", target=target_path,
            reducer=setting.reducer, group_policies=groups,
        )

    if applicable:
        return Effective(
            value=_apply(setting.reducer, applicable, setting),
            source="explicit",
            target=ou_path or ROOT,
            reducer=setting.reducer,
            group_policies=groups,
            contributing=len(applicable),
        )

    if setting.defaults is None or not listing_complete:
        # Either Google publishes no default, or we cannot tell an absence from
        # a page we did not read. Both are "cannot say".
        return Effective(
            value={}, source="unresolved", target=ou_path or ROOT,
            reducer=setting.reducer, group_policies=groups,
        )

    return Effective(
        value=dict(setting.defaults),
        source="default",
        target=ou_path or ROOT,
        reducer=setting.reducer,
        group_policies=groups,
    )


# ------------------------------------------------- the per-account picture

@dataclass
class Coverage:
    """How one setting lands across the whole organization."""

    setting_type: str
    #: effective value keyed by organizational unit path
    by_ou: dict[str, Effective] = field(default_factory=dict)
    #: accounts whose effective value is the unsafe one
    exposed: list[str] = field(default_factory=list)
    #: accounts on a value that is not good but is not a failure either —
    #: a 20-day 2SV grace period and a 90-day one are not the same finding
    warned: list[str] = field(default_factory=list)
    #: accounts in an OU steered by a group policy we cannot resolve
    unresolved: list[str] = field(default_factory=list)
    total_accounts: int = 0
    group_policies: tuple[str, ...] = ()

    @property
    def partial(self) -> bool:
        """True when some accounts are protected and others are not — the
        finding worth selling: "enforced only under /Dirección"."""
        flagged = len(self.exposed) + len(self.warned)
        return bool(flagged) and flagged < self.total_accounts

    @property
    def safe_org_units(self) -> list[str]:
        exposed_ous = {
            ou for ou, eff in self.by_ou.items() if ou in self._exposed_ous
        }
        return sorted(set(self.by_ou) - exposed_ous)

    _exposed_ous: set = field(default_factory=set)


def coverage(
    policies: list[Policy],
    setting_type: str,
    users: list[dict],
    is_unsafe,
    listing_complete: bool = True,
) -> Coverage:
    """Run the reduction once per account and group the answer by OU.

    `is_unsafe(effective)` decides the verdict for a reduced value:

        True     → exposed
        "warn"   → worth flagging, not a failure
        False    → safe
        None     → cannot tell, which keeps those accounts out of the exposed
                   list and into the unresolved one. Never a pass.
    """
    result = Coverage(setting_type=setting_type, total_accounts=len(users))
    cache: dict[str, Effective] = {}

    for user in users:
        ou = str(user.get("orgUnitPath") or ROOT)
        if ou not in cache:
            cache[ou] = reduce_for(policies, setting_type, ou, listing_complete)
        effective = cache[ou]
        email = user.get("primaryEmail", "")

        if effective.group_policies:
            # A group policy could override this account and we cannot see
            # membership, so it is not counted as safe.
            result.unresolved.append(email)
            continue
        if not effective.resolved:
            result.unresolved.append(email)
            continue

        verdict = is_unsafe(effective)
        if verdict is None:
            result.unresolved.append(email)
        elif verdict == "warn":
            result.warned.append(email)
            result._exposed_ous.add(ou)
        elif verdict:
            result.exposed.append(email)
            result._exposed_ous.add(ou)

    result.by_ou = cache
    result.group_policies = tuple(
        sorted({g for eff in cache.values() for g in eff.group_policies})
    )
    result.exposed.sort()
    result.warned.sort()
    result.unresolved.sort()
    return result
