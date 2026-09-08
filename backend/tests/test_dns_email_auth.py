from vigia.dns_email_auth import (
    DnsUnavailable,
    check_dkim,
    check_domain,
    dkim_verdict,
    dmarc_verdict,
    normalize_domain,
    parse_dmarc,
    parse_spf,
    spf_verdict,
)


class FakeResolver:
    """name -> list[str] (TXT), or the DnsUnavailable class to simulate
    an infrastructure failure."""

    def __init__(self, txt_map: dict | None = None, mx_map: dict | None = None):
        self.txt_map = txt_map or {}
        self.mx_map = mx_map or {}

    def txt(self, name):
        value = self.txt_map.get(name, [])
        if value is DnsUnavailable:
            raise DnsUnavailable("timeout")
        return value

    def mx(self, name):
        value = self.mx_map.get(name, [])
        if value is DnsUnavailable:
            raise DnsUnavailable("timeout")
        return value


# ------------------------------------------------------------------ SPF

def test_spf_missing_is_conclusive_fail():
    result = parse_spf(["some-verification=abc"])
    assert result.found is False
    assert spf_verdict(result)[0] == "fail"


def test_spf_strict_all_passes():
    result = parse_spf(["v=spf1 include:_spf.google.com -all"])
    assert result.found and result.all_qualifier == "-" and not result.issues
    assert spf_verdict(result)[0] == "pass"


def test_spf_softfail_passes():
    result = parse_spf(["v=spf1 include:_spf.google.com ~all"])
    assert spf_verdict(result)[0] == "pass"


def test_spf_plus_all_fails():
    result = parse_spf(["v=spf1 +all"])
    assert result.all_qualifier == "+"
    assert spf_verdict(result)[0] == "fail"


def test_spf_neutral_or_missing_all_warns():
    assert spf_verdict(parse_spf(["v=spf1 include:x.com ?all"]))[0] == "warn"
    assert spf_verdict(parse_spf(["v=spf1 include:x.com"]))[0] == "warn"


def test_spf_multiple_records_invalid():
    result = parse_spf(["v=spf1 -all", "v=spf1 include:a.com ~all"])
    assert any("inválido" in issue for issue in result.issues)
    assert spf_verdict(result)[0] == "fail"


def test_spf_redirect_needs_no_all():
    result = parse_spf(["v=spf1 redirect=_spf.example.com"])
    assert not any("no 'all'" in i.lower() for i in result.issues)


def test_spf_counts_lookup_terms():
    record = "v=spf1 " + " ".join(f"include:s{i}.example.com" for i in range(12)) + " -all"
    result = parse_spf([record])
    assert result.lookup_terms == 12
    assert spf_verdict(result)[0] == "warn"


def test_spf_timeout_is_undetermined_never_fail():
    resolver = FakeResolver({"example.com": DnsUnavailable})
    from vigia.dns_email_auth import check_spf

    result = check_spf("example.com", resolver)
    assert result.found is None and result.error
    assert spf_verdict(result)[0] == "undetermined"


# ---------------------------------------------------------------- DMARC

def test_dmarc_missing_fails():
    result = parse_dmarc([])
    assert result.found is False
    assert dmarc_verdict(result)[0] == "fail"


def test_dmarc_p_none_fails_high():
    result = parse_dmarc(["v=DMARC1; p=none; rua=mailto:d@x.com"])
    assert result.policy == "none"
    assert dmarc_verdict(result)[0] == "fail"


def test_dmarc_quarantine_warns():
    result = parse_dmarc(["v=DMARC1; p=quarantine; rua=mailto:d@x.com"])
    assert dmarc_verdict(result)[0] == "warn"


def test_dmarc_reject_passes():
    result = parse_dmarc(["v=DMARC1; p=reject; rua=mailto:d@x.com"])
    assert dmarc_verdict(result)[0] == "pass"


def test_dmarc_reject_partial_pct_warns():
    result = parse_dmarc(["v=DMARC1; p=reject; pct=50; rua=mailto:d@x.com"])
    assert result.pct == 50
    assert dmarc_verdict(result)[0] == "warn"


def test_dmarc_missing_p_tag_fails():
    result = parse_dmarc(["v=DMARC1; rua=mailto:d@x.com"])
    assert result.policy is None
    assert dmarc_verdict(result)[0] == "fail"


def test_dmarc_multiple_records_fail():
    result = parse_dmarc(["v=DMARC1; p=reject", "v=DMARC1; p=none"])
    assert dmarc_verdict(result)[0] == "fail"


def test_dmarc_parses_rua_and_sp():
    result = parse_dmarc(["v=DMARC1; p=reject; sp=quarantine; rua=mailto:a@x.com,mailto:b@x.com"])
    assert result.subdomain_policy == "quarantine"
    assert result.rua == ["mailto:a@x.com", "mailto:b@x.com"]


# ----------------------------------------------------------------- DKIM

def test_dkim_found_at_google_selector():
    resolver = FakeResolver({"google._domainkey.example.com": ["v=DKIM1; k=rsa; p=MIIB"]})
    result = check_dkim("example.com", resolver, ["google", "default"])
    assert result.found is True and result.selector == "google"
    assert dkim_verdict(result)[0] == "pass"


def test_dkim_unknown_selector_is_undetermined_never_fail():
    resolver = FakeResolver({})
    result = check_dkim("example.com", resolver, ["google", "default"])
    assert result.found is None
    status, summary = dkim_verdict(result)
    assert status == "undetermined"
    # La redacción cambió al fijar el escaneo al selector «google»: sigue
    # teniendo que decir que un selector propio no se encuentra, y sigue sin
    # poder ser `fail`.
    assert "selector propio" in summary and "no significa que no firmes" in summary


def test_dkim_timeout_is_undetermined():
    resolver = FakeResolver({
        "google._domainkey.example.com": DnsUnavailable,
        "default._domainkey.example.com": DnsUnavailable,
    })
    result = check_dkim("example.com", resolver, ["google", "default"])
    assert dkim_verdict(result)[0] == "undetermined"


def test_dkim_revoked_empty_key_warns():
    resolver = FakeResolver({"google._domainkey.example.com": ["v=DKIM1; k=rsa; p="]})
    result = check_dkim("example.com", resolver, ["google"])
    assert result.found is True and result.issues
    assert dkim_verdict(result)[0] == "warn"


# ------------------------------------------------------------- combined

def test_check_domain_full_report():
    resolver = FakeResolver(
        txt_map={
            "example.com": ["v=spf1 include:_spf.google.com ~all"],
            "google._domainkey.example.com": ["v=DKIM1; k=rsa; p=MIIB"],
            "_dmarc.example.com": ["v=DMARC1; p=none"],
        },
        mx_map={"example.com": ["aspmx.l.google.com"]},
    )
    report = check_domain("example.com", resolver=resolver, selectors=["google"])
    assert report["spf"]["status"] == "pass"
    assert report["dkim"]["status"] == "pass"
    assert report["dmarc"]["status"] == "fail"  # p=none
    assert report["mx"]["google_workspace"] is True
    # everything must be JSON-serializable
    import json

    json.dumps(report)


# -------------------------------------------------------------- domains

def test_normalize_domain():
    assert normalize_domain("Example.COM") == "example.com"
    assert normalize_domain("https://www.example.co.uk/path") == "example.co.uk"
    assert normalize_domain("example.com.") == "example.com"
    assert normalize_domain("münchen.de") == "xn--mnchen-3ya.de"
    assert normalize_domain("not a domain") is None
    assert normalize_domain("nodots") is None
    assert normalize_domain("") is None
