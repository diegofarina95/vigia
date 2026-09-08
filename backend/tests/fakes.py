"""Shared fake scan context.

There were nine hand-rolled `Ctx` classes across the test suite and each one
implemented whichever accessors its own module happened to call. That is fine
until the contract grows a method — `complete(source)` — whose DEFAULT is
"no, that source was not measured". Nine fakes then silently disagreed with the
real context in nine different ways, and 61 tests failed for a reason that had
nothing to do with what they were testing.

One fake, one contract. It declares full coverage by default because a test
fixture IS the whole tenant: the fixture author decided what exists. Tests that
care about partial reads pass `complete={"token": False}` and say so.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from vigia.google_client.grants import Coverage

#: Every source the real ScanContext can record.
SOURCES = ("users", "domains", "token", "admin", "login", "policies")


@dataclass
class Settings:
    dormant_days: int = 90
    super_admin_threshold: int = 4
    widely_granted_threshold: int = 10
    dkim_selectors: tuple = ()


class FakeContext:
    """Implements the accessors checks are allowed to call, and nothing else."""

    def __init__(
        self,
        users=None,
        domains=None,
        token_events=None,
        admin_events=None,
        login_events=None,
        policies=None,
        grants=None,
        settings=None,
        complete: dict | None = None,
        raises: dict | None = None,
    ) -> None:
        self._users = list(users or [])
        self._domains = list(domains or [])
        self._token_events = list(token_events or [])
        self._admin_events = list(admin_events or [])
        self._login_events = list(login_events or [])
        self._policies = list(policies or [])
        self._grants = grants
        self.settings = settings or Settings()
        self._raises = raises or {}
        completo = complete or {}
        self.coverage = {
            source: Coverage(
                source=source,
                pages=1,
                records=0,
                complete=completo.get(source, True),
                reason="" if completo.get(source, True) else "tope de páginas alcanzado",
            )
            for source in SOURCES
        }
        self.include_directory_domains = True

    # --- the contract ------------------------------------------------------

    def complete(self, source: str) -> bool:
        cobertura = self.coverage.get(source)
        return bool(cobertura.complete) if cobertura is not None else False

    def measured(self, source: str) -> bool:
        return source in self.coverage

    def _maybe_raise(self, source: str) -> None:
        exc = self._raises.get(source)
        if exc is not None:
            raise exc

    def users(self):
        self._maybe_raise("users")
        return self._users

    def domains(self):
        self._maybe_raise("domains")
        return self._domains

    def token_events(self):
        self._maybe_raise("token")
        return self._token_events

    def token_grants(self):
        self._maybe_raise("token")
        if self._grants is not None:
            return self._grants
        from vigia.google_client.grants import fold

        return fold(self._token_events)

    def admin_events(self):
        self._maybe_raise("admin")
        return self._admin_events

    def login_events(self):
        self._maybe_raise("login")
        return self._login_events

    def policies(self):
        self._maybe_raise("policies")
        return self._policies

    def email_domains(self):
        return [d["domainName"] for d in self._domains if d.get("domainName")]

    def email_auth_reports(self):
        """DNS is not a tenant API: an empty list means "no domains to check",
        which is what a fixture with no domains genuinely says."""
        from vigia import dns_email_auth

        return [
            dns_email_auth.check_domain(d, resolver=_sin_dns, selectors=())
            for d in self.email_domains()
        ]

    def now(self):
        from vigia.checks.util import utcnow

        return utcnow()


def _sin_dns(name, rdtype):
    """A resolver that answers nothing, so DNS checks are exercised without
    reaching the network from a unit test."""
    return []
