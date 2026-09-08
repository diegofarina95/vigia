from vigia.checks import check_login_security as mod


class Ctx:
    def __init__(self, items):
        self._items = items

    def login_events(self):
        return self._items

    def complete(self, source):
        return getattr(self, "_completo", {}).get(source, True)

    def measured(self, source):
        return True

def _ev(email, name):
    return {"actor": {"email": email}, "events": [{"name": name}]}


def find(findings, fid):
    return next(f for f in findings if f.id == fid)


def test_clean_login_log_all_pass():
    findings = mod.run(Ctx([_ev("a@x.com", "login_success")]))
    assert all(f.status == "pass" for f in findings)


def test_password_leak_is_critical_fail():
    findings = mod.run(Ctx([_ev("victim@x.com", "account_disabled_password_leak")]))
    comp = find(findings, "login-compromised")
    assert comp.severity == "critical" and comp.status == "fail"
    assert any("victim@x.com" in item for item in comp.affected_items)


def test_hijack_and_gov_attack_flagged():
    for name in ("account_disabled_hijacked", "gov_attack_warning"):
        findings = mod.run(Ctx([_ev("t@x.com", name)]))
        assert find(findings, "login-compromised").status == "fail"


def test_suspicious_login_warns():
    findings = mod.run(Ctx([_ev("u@x.com", "suspicious_login")]))
    assert find(findings, "login-suspicious").status == "warn"
    assert find(findings, "login-compromised").status == "pass"


def test_brute_force_threshold():
    nine = [_ev("u@x.com", "login_failure") for _ in range(9)]
    assert find(mod.run(Ctx(nine)), "login-brute-force").status == "pass"
    ten = [_ev("u@x.com", "login_failure") for _ in range(10)]
    assert find(mod.run(Ctx(ten)), "login-brute-force").status == "warn"


def test_api_error_is_undetermined_not_crash():
    from vigia.google_client.base import GoogleApiError

    class Boom:
        def login_events(self):
            raise GoogleApiError(403, "no access")

    findings = mod.run(Boom())
    assert len(findings) == 1 and findings[0].status == "undetermined"
