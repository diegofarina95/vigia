from vigia.checks.finding import Finding
from vigia.scoring import SEVERITY_WEIGHTS, compute_score, severity_counts


def make(severity: str, status: str, manual: bool = False, i: int = 0) -> Finding:
    return Finding(
        id=f"f-{severity}-{status}-{i}", title="t", severity=severity, status=status, manual=manual
    )


def test_all_pass_is_100():
    findings = [make("critical", "pass"), make("high", "pass"), make("low", "pass")]
    assert compute_score(findings) == 100


def test_all_fail_is_0():
    findings = [make("critical", "fail"), make("medium", "fail")]
    assert compute_score(findings) == 0


def test_no_scorable_findings_is_none_not_100():
    assert compute_score([]) is None
    assert compute_score([make("info", "pass"), make("high", "undetermined")]) is None


def test_weighted_by_severity():
    # critical fail (0/10), high pass (6/6), medium warn (1.5/3)
    findings = [make("critical", "fail"), make("high", "pass"), make("medium", "warn")]
    expected = round(100 * (0 + 6 + 1.5) / (10 + 6 + 3))  # 39
    assert compute_score(findings) == expected == 39


def test_warn_earns_half_credit():
    assert compute_score([make("high", "warn")]) == 50


def test_undetermined_and_info_and_manual_are_excluded():
    base = [make("high", "pass")]
    with_excluded = base + [
        make("critical", "undetermined"),
        make("info", "fail"),
        make("critical", "fail", manual=True),
    ]
    assert compute_score(with_excluded) == compute_score(base) == 100


def test_score_is_bounded():
    findings = [make(sev, status, i=i) for i, (sev, status) in enumerate([
        ("critical", "fail"), ("critical", "pass"), ("high", "warn"),
        ("medium", "fail"), ("low", "pass"),
    ])]
    score = compute_score(findings)
    assert score is not None and 0 <= score <= 100


def test_severity_counts_only_open_issues():
    findings = [
        make("critical", "fail"),
        make("critical", "pass"),
        make("high", "warn"),
        make("high", "undetermined"),
        make("medium", "fail", manual=True),  # manual excluded
    ]
    counts = severity_counts(findings)
    assert counts["critical"] == 1
    assert counts["high"] == 1
    assert counts["medium"] == 0


def test_every_severity_has_a_weight():
    for severity in ("critical", "high", "medium", "low", "info"):
        assert severity in SEVERITY_WEIGHTS
