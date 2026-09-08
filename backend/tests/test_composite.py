"""Composite findings: the rules, the precedence, and the epoch edge case."""
from dataclasses import dataclass

from vigia.checks import composite
from vigia.checks.composite import RULES, SIGNALS, match_rules, signals_for

EPOCH = "1970-01-01T00:00:00.000Z"  # what Google returns for "never signed in"


@dataclass
class Settings:
    dormant_days: int = 90


def user(
    email="a@example.com",
    *,
    admin=False,
    delegated=False,
    enrolled_2sv=True,
    last_login="2026-07-20T10:00:00.000Z",
    suspended=False,
    archived=False,
):
    return {
        "primaryEmail": email,
        "isAdmin": admin,
        "isDelegatedAdmin": delegated,
        "isEnrolledIn2Sv": enrolled_2sv,
        "lastLoginTime": last_login,
        "suspended": suspended,
        "archived": archived,
    }


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

def finding(findings, rule_id):
    fid = f"composite-{rule_id.lower().replace('_', '-')}"
    return next(f for f in findings if f.id == fid)


# ------------------------------------------------------------ the epoch case

def test_epoch_last_login_counts_as_never_signed_in():
    """Google reports the Unix epoch, not null, for unused accounts."""
    signals = signals_for(user(last_login=EPOCH), Settings())
    assert "never_signed_in" in signals


def test_missing_last_login_counts_as_never_signed_in():
    assert "never_signed_in" in signals_for(user(last_login=None), Settings())


def test_recent_login_is_not_never_signed_in():
    signals = signals_for(user(), Settings())
    assert "never_signed_in" not in signals
    assert "inactive" not in signals


# ----------------------------------------------------------- one rule each

def test_superadmin_dormant_no_2sv_is_critical():
    findings = composite.run(
        Ctx([user("ghost@example.com", admin=True, enrolled_2sv=False, last_login=EPOCH)])
    )
    hit = finding(findings, "SUPERADMIN_DORMANT_NO_2SV")
    assert hit.severity == "critical" and hit.status == "fail"
    assert hit.accounts == ["ghost@example.com"]
    # It must justify why the combination is worse than the parts.
    assert "puerta trasera permanente" in hit.description
    assert "línea base" in hit.description
    assert hit.cis_control


def test_superadmin_no_2sv_is_critical():
    hit = finding(
        composite.run(Ctx([user("boss@example.com", admin=True, enrolled_2sv=False)])),
        "SUPERADMIN_NO_2SV",
    )
    assert hit.severity == "critical" and hit.accounts == ["boss@example.com"]


def test_superadmin_dormant_is_high():
    hit = finding(
        composite.run(
            Ctx([user("old@example.com", admin=True, last_login="2026-01-01T00:00:00.000Z")])
        ),
        "SUPERADMIN_DORMANT",
    )
    assert hit.severity == "high" and hit.accounts == ["old@example.com"]


def test_dormant_no_2sv_is_high():
    hit = finding(
        composite.run(Ctx([user("new@example.com", enrolled_2sv=False, last_login=EPOCH)])),
        "DORMANT_NO_2SV",
    )
    assert hit.severity == "high" and hit.accounts == ["new@example.com"]


def test_service_account_no_2sv_is_high():
    hit = finding(
        composite.run(Ctx([user("integrations@example.com", enrolled_2sv=False)])),
        "SERVICE_ACCOUNT_NO_2SV",
    )
    assert hit.severity == "high" and hit.accounts == ["integrations@example.com"]


def test_functional_account_names_recognised():
    for local in ("admin", "noreply", "info", "integrations"):
        signals = signals_for(user(f"{local}@example.com", enrolled_2sv=False), Settings())
        assert "functional_account" in signals, local
    assert "functional_account" not in signals_for(
        user("maria.lopez@example.com", enrolled_2sv=False), Settings()
    )


# -------------------------------------------------------------- precedence

def test_an_account_appears_in_every_rule_it_matches():
    """A super admin with no 2SV who never signed in matches three rules. All
    three must report it: if the broader rule dropped the account it would
    claim PASS while the account exists, which is a false statement."""
    ghost = user("ghost@example.com", admin=True, enrolled_2sv=False, last_login=EPOCH)
    con_telefono = {**user("otra@example.com"), "recoveryPhone": "+34600000000"}
    matches = match_rules([ghost, con_telefono], Settings())
    # Every rule whose signals it holds: the specific one plus each broader
    # one. "never signed in" also implies "inactive", and the no-2SV+unused
    # rule applies regardless of the admin role.
    assert set(matches) == {
        "SUPERADMIN_DORMANT_NO_2SV",
        "SUPERADMIN_NO_2SV",
        "SUPERADMIN_DORMANT",
        "DORMANT_NO_2SV",
        # This fixture carries no recoveryPhone, and another account in the
        # population does, so the recovery signal is trustworthy and holds.
        "SUPERADMIN_NO_2SV_NO_RECOVERY",
    }


def test_the_broader_finding_cannot_pass_while_the_specific_one_fails():
    """This is the exact contradiction reported from production."""
    ghost = user("ghost@example.com", admin=True, enrolled_2sv=False, last_login=EPOCH)
    findings = composite.run(Ctx([ghost]))
    specific = finding(findings, "SUPERADMIN_DORMANT_NO_2SV")
    broader = finding(findings, "SUPERADMIN_NO_2SV")
    assert specific.status == "fail"
    assert broader.status == "fail", "a super admin without 2SV exists — this cannot pass"
    assert "ghost@example.com" in broader.accounts


def test_overlapping_findings_do_not_double_count_in_the_score():
    """Overlap is safe because scoring counts each account once, at its worst
    severity — that is what makes non-exclusive attribution correct."""
    from vigia.scoring import score_breakdown

    ghost = user("ghost@example.com", admin=True, enrolled_2sv=False, last_login=EPOCH)
    findings = [f.to_dict() for f in composite.run(Ctx([ghost]))]
    breakdown = score_breakdown(findings)
    rows = [row for row in breakdown["accounts"] if row["account"] == "ghost@example.com"]
    # One row for the person, at the worst severity they appear under —
    # not one row per finding that named them.
    assert len(rows) == 1
    assert rows[0]["severity"] == "critical"
    assert rows[0]["weight"] == 10
    # The four failing composites contribute this person once, so the account
    # side of the score is a single critical weight rather than 10+10+6+6.
    assert sum(row["weight"] for row in breakdown["accounts"]) == 10


def test_rules_are_ordered_most_specific_first():
    """Precedence is data, not code: more signals must come first."""
    lengths = [len(rule.signals) for rule in RULES]
    assert lengths == sorted(lengths, reverse=True) or lengths[0] == max(lengths)


def test_every_rule_signal_exists():
    for rule in RULES:
        for signal in rule.signals:
            assert signal in SIGNALS, f"{rule.id} references unknown signal {signal}"


def test_every_rule_has_explanation_remediation_and_cis():
    for rule in RULES:
        assert len(rule.why_worse) > 80, rule.id
        assert rule.remediation and rule.admin_console_url and rule.cis_control, rule.id
        assert rule.remediation_actions, rule.id


# ------------------------------------------------------------ clean tenants

def test_clean_tenant_passes_every_rule():
    findings = composite.run(Ctx([user("safe@example.com"), user("also@example.com")]))
    assert all(f.status == "pass" for f in findings)
    assert all(f.accounts == [] for f in findings)


def test_suspended_and_archived_accounts_are_ignored():
    users = [
        user("gone@example.com", admin=True, enrolled_2sv=False, last_login=EPOCH, suspended=True),
        user("filed@example.com", admin=True, enrolled_2sv=False, last_login=EPOCH, archived=True),
    ]
    assert match_rules(users, Settings()) == {}


def test_dormant_threshold_follows_settings():
    old = user("x@example.com", admin=True, last_login="2026-06-01T00:00:00.000Z")
    # With a 90-day window that login is recent; with 7 days it is inactive.
    assert "inactive" not in signals_for(old, Settings(dormant_days=90))
    assert "inactive" in signals_for(old, Settings(dormant_days=7))
