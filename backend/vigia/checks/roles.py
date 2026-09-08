"""The only place allowed to read `isAdmin` / `isDelegatedAdmin`.

Google's Directory API exposes two independent fields:

    isAdmin           → super administrator
    isDelegatedAdmin  → holds admin roles without being a super admin

They are *not* mutually exclusive in the payload: an account can come back
with both set. Every check used to apply its own inline condition, and one
of them (`isAdmin or isDelegatedAdmin`) merged the two populations — which
is how the same account ended up reported as a super admin and as a
delegated admin in the same scan.

So the two sets are defined once, here, and made disjoint by construction:
a super admin is never also counted as delegated. No check reads the raw
fields; they all go through these predicates.
"""
from __future__ import annotations

# Directory API returns JSON booleans today. Older Google endpoints have
# been known to return the *string* "true", and in a security tool a false
# negative (missing a super admin) is far worse than being strict, so both
# spellings are accepted and everything else is false.
_TRUE = (True, "true", "True", "TRUE")


def _flag(user: dict, field: str) -> bool:
    return user.get(field) in _TRUE


def is_super_admin(user: dict) -> bool:
    """Super administrator: full control of the tenant."""
    return _flag(user, "isAdmin")


def is_delegated_admin(user: dict) -> bool:
    """Admin roles without being a super admin.

    Excludes super admins on purpose: the two sets must be disjoint so no
    account can be reported under both populations.
    """
    return _flag(user, "isDelegatedAdmin") and not is_super_admin(user)


def is_admin(user: dict) -> bool:
    """Holds administrative privileges of any kind."""
    return is_super_admin(user) or is_delegated_admin(user)


def super_admins(users: list[dict]) -> list[dict]:
    return [u for u in users if is_super_admin(u)]


def delegated_admins(users: list[dict]) -> list[dict]:
    return [u for u in users if is_delegated_admin(u)]


def emails(users: list[dict]) -> list[str]:
    return sorted(u["primaryEmail"] for u in users if u.get("primaryEmail"))
