from vigia.dns_email_auth import (
    DnsUnavailable,
    check_transport,
    dnssec_verdict,
    mta_sts_verdict,
    tls_rpt_verdict,
)


class TxtOnlyResolver:
    """A resolver that predates DS support — used to prove we degrade to
    'undetermined' instead of crashing."""

    def __init__(self, txt_map=None):
        self.txt_map = txt_map or {}

    def txt(self, name):
        value = self.txt_map.get(name, [])
        if value is DnsUnavailable:
            raise DnsUnavailable("timeout")
        return value


class FakeResolver(TxtOnlyResolver):
    def __init__(self, txt_map=None, ds_map=None):
        super().__init__(txt_map)
        self.ds_map = ds_map or {}

    def ds(self, name):
        value = self.ds_map.get(name, [])
        if value is DnsUnavailable:
            raise DnsUnavailable("timeout")
        return value


def test_all_present_passes():
    resolver = FakeResolver(
        txt_map={
            "_mta-sts.example.com": ["v=STSv1; id=20260721T000000;"],
            "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:t@example.com"],
        },
        ds_map={"example.com": ["12345 13 2 ABCD"]},
    )
    result = check_transport("example.com", resolver)
    assert result.mta_sts is True and result.mta_sts_id == "20260721T000000"
    assert result.tls_rpt is True
    assert result.dnssec is True
    assert mta_sts_verdict(result)[0] == "pass"
    assert tls_rpt_verdict(result)[0] == "pass"
    assert dnssec_verdict(result)[0] == "pass"


def test_all_absent_warns_never_fails():
    result = check_transport("example.com", FakeResolver())
    assert result.mta_sts is False and result.tls_rpt is False and result.dnssec is False
    # These are hardening gaps, not broken configs → warn, not fail.
    assert mta_sts_verdict(result)[0] == "warn"
    assert tls_rpt_verdict(result)[0] == "warn"
    assert dnssec_verdict(result)[0] == "warn"


def test_dns_timeout_is_undetermined():
    resolver = FakeResolver(
        txt_map={
            "_mta-sts.example.com": DnsUnavailable,
            "_smtp._tls.example.com": DnsUnavailable,
        },
        ds_map={"example.com": DnsUnavailable},
    )
    result = check_transport("example.com", resolver)
    assert mta_sts_verdict(result)[0] == "undetermined"
    assert tls_rpt_verdict(result)[0] == "undetermined"
    assert dnssec_verdict(result)[0] == "undetermined"


def test_resolver_without_ds_support_is_undetermined_not_crash():
    result = check_transport("example.com", TxtOnlyResolver())
    assert result.dnssec is None
    assert dnssec_verdict(result)[0] == "undetermined"


def test_unrelated_txt_records_are_ignored():
    resolver = FakeResolver(
        txt_map={"_mta-sts.example.com": ["some-other-verification=abc"]},
    )
    result = check_transport("example.com", resolver)
    assert result.mta_sts is False
