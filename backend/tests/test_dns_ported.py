"""Point 4: logic ported from prospector.py — recursive SPF lookup count,
DKIM key size, MX provider, DMARC report destination."""
from vigia.dns_email_auth import (
    SPF_LOOKUP_LIMIT,
    DnsUnavailable,
    check_dkim,
    check_dmarc,
    check_spf,
    classify_rua,
    count_spf_lookups,
    dkim_key_bits,
    mail_provider,
    parse_dmarc,
    spf_verdict,
)


class FakeResolver:
    def __init__(self, txt_map=None):
        self.txt_map = txt_map or {}

    def txt(self, name):
        value = self.txt_map.get(name, [])
        if value is DnsUnavailable:
            raise DnsUnavailable("timeout")
        return value


# ------------------------------------------------- recursive lookup counting

def test_counts_top_level_lookup_mechanisms():
    resolver = FakeResolver({"x.com": ["v=spf1 include:a.com mx a:h.com -all"]})
    # include: + mx + a: = 3 (the include target has no record)
    assert count_spf_lookups("x.com", resolver) == 3


def test_recurses_into_include():
    resolver = FakeResolver(
        {
            "x.com": ["v=spf1 include:a.com -all"],
            "a.com": ["v=spf1 include:b.com include:c.com -all"],
            "b.com": ["v=spf1 mx -all"],
        }
    )
    # x: include(1) → a: include+include(2) → b: mx(1) = 4
    assert count_spf_lookups("x.com", resolver) == 4


def test_follows_redirect():
    resolver = FakeResolver(
        {"x.com": ["v=spf1 redirect=r.com"], "r.com": ["v=spf1 include:i.com ~all"]}
    )
    assert count_spf_lookups("x.com", resolver) == 2


def test_include_loop_does_not_hang():
    resolver = FakeResolver(
        {"a.com": ["v=spf1 include:b.com -all"], "b.com": ["v=spf1 include:a.com -all"]}
    )
    assert count_spf_lookups("a.com", resolver) == 2  # each visited once


def test_self_include_loop_is_safe():
    resolver = FakeResolver({"a.com": ["v=spf1 include:a.com -all"]})
    assert count_spf_lookups("a.com", resolver) == 1


def test_deep_chain_is_cut_off():
    # 20 chained includes: the depth guard must stop it, not recurse forever.
    txt_map = {f"d{i}.com": [f"v=spf1 include:d{i + 1}.com -all"] for i in range(20)}
    total = count_spf_lookups("d0.com", FakeResolver(txt_map))
    assert 0 < total <= 20


def test_timeout_during_recursion_returns_partial_count_not_error():
    resolver = FakeResolver(
        {"x.com": ["v=spf1 include:a.com -all"], "a.com": DnsUnavailable}
    )
    assert count_spf_lookups("x.com", resolver) == 1


def test_over_the_limit_is_a_hard_fail_permerror():
    includes = " ".join(f"include:s{i}.com" for i in range(12))
    resolver = FakeResolver({"x.com": [f"v=spf1 {includes} -all"]})
    result = check_spf("x.com", resolver)
    assert result.dns_lookups == 12 > SPF_LOOKUP_LIMIT
    status, summary = spf_verdict(result)
    assert status == "fail"
    assert "permerror" in summary
    assert any("permerror" in issue for issue in result.issues)


def test_within_the_limit_passes():
    resolver = FakeResolver({"x.com": ["v=spf1 include:_spf.google.com -all"]})
    result = check_spf("x.com", resolver)
    assert result.dns_lookups == 1
    assert spf_verdict(result)[0] == "pass"


# --------------------------------------------------------- DKIM key strength

def test_key_bits_classification():
    assert dkim_key_bits("A" * 216) == 1024  # ~162 bytes decoded
    assert dkim_key_bits("A" * 392) == 2048  # ~294 bytes
    assert dkim_key_bits("A" * 800) == 4096
    assert dkim_key_bits("!!!not base64!!!") is None
    assert dkim_key_bits("") is None


def test_weak_1024_bit_key_warns_but_is_still_verified():
    resolver = FakeResolver(
        {"google._domainkey.x.com": ["v=DKIM1; k=rsa; p=" + "A" * 216]}
    )
    result = check_dkim("x.com", resolver, ["google"])
    assert result.found is True and result.key_bits == 1024
    from vigia.dns_email_auth import dkim_verdict

    status, summary = dkim_verdict(result)
    assert status == "warn"
    assert "1024 bits" in summary


def test_strong_key_passes_and_reports_size():
    resolver = FakeResolver(
        {"google._domainkey.x.com": ["v=DKIM1; k=rsa; p=" + "A" * 392]}
    )
    result = check_dkim("x.com", resolver, ["google"])
    from vigia.dns_email_auth import dkim_verdict

    status, summary = dkim_verdict(result)
    assert status == "pass" and "2048 bits" in summary


# ------------------------------------------------------------- MX provider

def test_provider_detection():
    assert mail_provider(["aspmx.l.google.com"]) == "google"
    assert mail_provider(["x-com.mail.protection.outlook.com"]) == "microsoft"
    assert mail_provider(["mx.zoho.eu"]) == "zoho"
    assert mail_provider(["something.unknown.tld"]) == "other"
    assert mail_provider([]) == "none"


# -------------------------------------------------- DMARC report destination

def test_rua_at_own_domain():
    assert classify_rua("acme.com", ["mailto:dmarc@acme.com"]) == "own"
    assert classify_rua("acme.com", ["mailto:d@reports.acme.com"]) == "own"


def test_rua_at_a_third_party_is_flagged():
    assert classify_rua("acme.com", ["mailto:acme@dmarc-vendor.io"]) == "third_party"


def test_rua_missing():
    assert classify_rua("acme.com", []) == "none"


def test_mixed_rua_counts_as_own_because_the_client_sees_the_data():
    destinations = ["mailto:acme@vendor.io", "mailto:dmarc@acme.com"]
    assert classify_rua("acme.com", destinations) == "own"


def test_third_party_only_rua_produces_an_issue():
    resolver = FakeResolver(
        {"_dmarc.acme.com": ["v=DMARC1; p=reject; rua=mailto:acme@vendor.io"]}
    )
    result = check_dmarc("acme.com", resolver)
    assert result.rua_destination == "third_party"
    assert any("nunca ves tu" in issue for issue in result.issues)


def test_alignment_tags_are_parsed():
    result = parse_dmarc(["v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:a@acme.com"])
    assert result.adkim == "s" and result.aspf == "s"


def test_alignment_defaults_to_relaxed():
    result = parse_dmarc(["v=DMARC1; p=reject; rua=mailto:a@acme.com"])
    assert result.adkim == "r" and result.aspf == "r"
