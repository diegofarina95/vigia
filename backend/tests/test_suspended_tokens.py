"""Access that a suspension does not necessarily take away.

The claim this check is allowed to make is narrow on purpose: Google documents
that a password change revokes OAuth tokens and says nothing about what a
suspension does, so "these tokens are still live" would be the invented part.
What is on the record — granted, never revoked — is enough to act on.
"""
from datetime import timedelta

from vigia.checks import check_suspended_tokens as mod
from vigia.checks.util import utcnow

NOW = utcnow()


def user(email, suspended=False):
    return {"primaryEmail": email, "suspended": suspended, "archived": False,
            "isAdmin": False, "isDelegatedAdmin": False}


def token(email, name, client_id, days_ago, app_name="CRM Acme"):
    when = (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return {
        "id": {"time": when, "applicationName": "token"},
        "actor": {"email": email},
        "events": [{"name": name, "parameters": [
            {"name": "client_id", "value": client_id},
            {"name": "app_name", "value": app_name},
        ]}],
    }


class Ctx:
    """Mirrors the real ScanContext contract: folded grants plus coverage."""

    def __init__(self, users, events=None, boom=False, complete=True):
        self._users, self._events, self._boom = users, events or [], boom
        from vigia.google_client.grants import Coverage

        self.coverage = {
            "token": Coverage(source="token", pages=1, records=len(self._events),
                              complete=complete,
                              reason="" if complete else "se alcanzó el tope de páginas")
        }

    def users(self):
        return self._users

    def token_grants(self):
        if self._boom:
            raise RuntimeError("informes no disponible")
        from vigia.google_client.grants import fold

        return fold(self._events)

    def complete(self, source):
        cobertura = self.coverage.get(source)
        return True if cobertura is None else cobertura.complete


def test_a_suspended_account_with_an_unrevoked_app_is_critical():
    found = mod.run(Ctx(
        [user("ex@x.com", suspended=True), user("ana@x.com")],
        [token("ex@x.com", "authorize", "111", 60)],
    ))[0]
    assert found.status == "fail" and found.severity == "critical"
    assert found.accounts == ["ex@x.com"]
    assert "CRM Acme" in " ".join(found.affected_items)


def test_a_revocation_after_the_grant_clears_it():
    found = mod.run(Ctx(
        [user("ex@x.com", suspended=True)],
        [token("ex@x.com", "authorize", "111", 60),
         token("ex@x.com", "revoke", "111", 10)],
    ))[0]
    assert found.status == "pass"


def test_a_revocation_BEFORE_a_later_grant_does_not_clear_it():
    """Revoked in March, connected again in June: that is connected."""
    found = mod.run(Ctx(
        [user("ex@x.com", suspended=True)],
        [token("ex@x.com", "authorize", "111", 120),
         token("ex@x.com", "revoke", "111", 90),
         token("ex@x.com", "authorize", "111", 30)],
    ))[0]
    assert found.status == "fail"


def test_apps_of_accounts_that_are_still_active_are_not_this_check():
    found = mod.run(Ctx(
        [user("ana@x.com")],
        [token("ana@x.com", "authorize", "111", 10)],
    ))[0]
    assert found.status == "pass"
    assert "No hay ninguna cuenta suspendida" in found.description


def test_an_unreadable_token_log_is_undetermined_not_a_pass():
    """A suspended account plus no visibility is not "nothing to see": it is
    the one combination where a false pass hides a live door."""
    found = mod.run(Ctx([user("ex@x.com", suspended=True)], boom=True))[0]
    assert found.status == "undetermined"


def test_the_finding_does_not_claim_the_tokens_still_work():
    """Google does not document what a suspension does to a token, and this
    product cannot see inside. Overstating it here would be the one sentence
    a knowledgeable reader could catch us on."""
    found = mod.run(Ctx(
        [user("ex@x.com", suspended=True)],
        [token("ex@x.com", "authorize", "111", 60)],
    ))[0]
    texto = found.description.lower()
    # The hedge has to be present…
    assert "no puede mirar dentro de google" in texto
    assert "no documenta" in texto
    assert "no hay ninguna revocación posterior" in texto
    # …and the claim has to be about the record, not about the credential.
    # (Checking for the bare phrase is not enough: it appears inside the
    # negation, "cannot confirm whether these still work".)
    for afirmacion in ("los tokens siguen activos", "el acceso sigue vivo",
                       "las credenciales siguen siendo válidas"):
        assert afirmacion not in texto


def test_several_apps_are_summarised_rather_than_dumped():
    eventos = [token("ex@x.com", "authorize", str(i), 30, f"App {i}") for i in range(7)]
    found = mod.run(Ctx([user("ex@x.com", suspended=True)], eventos))[0]
    linea = found.affected_items[0]
    assert "7 aplicación(es)" in linea and "+3" in linea


# ------------------------- an incomplete window is not "nothing to see"

def test_a_truncated_window_is_partial_not_a_pass():
    """The events arrive newest-first, so what falls off the end is the past —
    exactly the old grant made by somebody who has since left. A pass over a
    cut window would be the worst false negative in the report."""
    found = mod.run(Ctx(
        [user("ex@x.com", suspended=True)],
        [token("ex@x.com", "authorize", "111", 60)],
        complete=False,
    ))[0]
    assert found.status == "undetermined"
    assert "no se ha podido leer completa" in found.description
    assert found.details["coverage_complete"] is False


def test_a_complete_window_still_reaches_a_verdict():
    found = mod.run(Ctx(
        [user("ex@x.com", suspended=True)],
        [token("ex@x.com", "authorize", "111", 60)],
        complete=True,
    ))[0]
    assert found.status == "fail"
