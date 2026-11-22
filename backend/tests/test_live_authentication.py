"""
Tests for live (online) SPF / DKIM / DMARC verification.

All DNS is served by an in-memory FakeResolver: no network is used, results are deterministic.
"""
import base64
import hashlib
from datetime import datetime, timezone
from types import SimpleNamespace

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.services.dkim_crypto_verifier import (
    DKIMCryptoStatus,
    LocalKeyStore,
    _canon_body,
    _canon_header,
    _split_raw,
    verify_dkim_signatures,
)
from app.services.dns_resolver import DnsResolver, DnsTempError
from app.services.live_auth_verifier import run_live_authentication
from app.services.live_dkim import DNSKeyStore, summarize_dkim
from app.services.live_dmarc import evaluate_dmarc, organizational_domain
from app.services.live_spf import check_spf


class FakeResolver(DnsResolver):
    def __init__(self, txt=None, a=None, aaaa=None, mx=None, ptr=None, fail=()):
        self._txt, self._a, self._aaaa = txt or {}, a or {}, aaaa or {}
        self._mx, self._ptr, self.fail = mx or {}, ptr or {}, set(fail)
        self.queries = []

    def _get(self, table, name):
        name = name.lower().rstrip(".")
        self.queries.append(name)
        if name in self.fail:
            raise DnsTempError(f"simulated SERVFAIL for {name}")
        return list(table.get(name, []))

    def txt(self, n): return self._get(self._txt, n)
    def a(self, n): return self._get(self._a, n)
    def aaaa(self, n): return self._get(self._aaaa, n)
    def mx(self, n): return self._get(self._mx, n)
    def ptr(self, ip): return self._get(self._ptr, ip)


# =========================================================================== #
# SPF
# =========================================================================== #
def test_spf_ip4_pass_and_fail():
    r = FakeResolver(txt={"example.com": ["v=spf1 ip4:203.0.113.0/24 -all"]})
    assert check_spf("203.0.113.5", "a@example.com", "h", r).result == "pass"
    res = check_spf("198.51.100.9", "a@example.com", "h", r)
    assert res.result == "fail" and res.mechanism == "-all"


def test_spf_softfail_and_neutral():
    r = FakeResolver(txt={"s.com": ["v=spf1 ip4:1.2.3.4 ~all"], "n.com": ["v=spf1 ip4:1.2.3.4 ?all"], "d.com": ["v=spf1 ip4:1.2.3.4"]})
    assert check_spf("9.9.9.9", "x@s.com", "", r).result == "softfail"
    assert check_spf("9.9.9.9", "x@n.com", "", r).result == "neutral"
    assert check_spf("9.9.9.9", "x@d.com", "", r).result == "neutral"  # no match, no all


def test_spf_no_record_is_none():
    assert check_spf("1.2.3.4", "x@nospf.com", "", FakeResolver()).result == "none"


def test_spf_multiple_records_permerror():
    r = FakeResolver(txt={"m.com": ["v=spf1 -all", "v=spf1 +all"]})
    assert check_spf("1.2.3.4", "x@m.com", "", r).result == "permerror"


def test_spf_include_pass_and_nonmatch():
    r = FakeResolver(txt={
        "corp.com": ["v=spf1 include:_spf.mailer.net -all"],
        "_spf.mailer.net": ["v=spf1 ip4:209.85.128.0/17 -all"],
    })
    assert check_spf("209.85.220.41", "u@corp.com", "", r).result == "pass"
    assert check_spf("8.8.8.8", "u@corp.com", "", r).result == "fail"


def test_spf_include_missing_target_is_permerror():
    r = FakeResolver(txt={"corp.com": ["v=spf1 include:gone.example -all"]})
    assert check_spf("1.1.1.1", "u@corp.com", "", r).result == "permerror"


def test_spf_a_and_mx_mechanisms_with_cidr():
    r = FakeResolver(
        txt={"corp.com": ["v=spf1 a mx:mail.corp.com/24 -all"]},
        a={"corp.com": ["192.0.2.10"], "mail.corp.com": ["198.51.100.7"]},
        mx={"mail.corp.com": ["mail.corp.com"]},
    )
    assert check_spf("192.0.2.10", "u@corp.com", "", r).result == "pass"       # a
    assert check_spf("198.51.100.200", "u@corp.com", "", r).result == "pass"   # mx /24
    assert check_spf("203.0.113.1", "u@corp.com", "", r).result == "fail"


def test_spf_redirect():
    r = FakeResolver(txt={
        "brand.com": ["v=spf1 redirect=_spf.brand.net"],
        "_spf.brand.net": ["v=spf1 ip4:10.1.1.1 -all"],
    })
    assert check_spf("10.1.1.1", "u@brand.com", "", r).result == "pass"
    assert check_spf("10.9.9.9", "u@brand.com", "", r).result == "fail"


def test_spf_ipv6():
    r = FakeResolver(txt={"v6.com": ["v=spf1 ip6:2001:db8::/32 -all"]})
    assert check_spf("2001:db8::1", "u@v6.com", "", r).result == "pass"
    assert check_spf("2001:dead::1", "u@v6.com", "", r).result == "fail"


def test_spf_exists_with_macro():
    r = FakeResolver(
        txt={"mac.com": ["v=spf1 exists:%{i}._allow.mac.com -all"]},
        a={"1.2.3.4._allow.mac.com": ["127.0.0.2"]},
    )
    assert check_spf("1.2.3.4", "u@mac.com", "", r).result == "pass"
    assert check_spf("1.2.3.5", "u@mac.com", "", r).result == "fail"


def test_spf_ptr_mechanism():
    r = FakeResolver(
        txt={"p.com": ["v=spf1 ptr -all"]},
        ptr={"1.2.3.4": ["mx1.p.com"]},
        a={"mx1.p.com": ["1.2.3.4"]},
    )
    assert check_spf("1.2.3.4", "u@p.com", "", r).result == "pass"


def test_spf_ten_lookup_limit_is_permerror():
    includes = " ".join(f"include:i{n}.com" for n in range(11))
    txt = {"big.com": [f"v=spf1 {includes} -all"]}
    for n in range(11):
        txt[f"i{n}.com"] = ["v=spf1 ip4:10.0.0.1 -all"]
    res = check_spf("1.2.3.4", "u@big.com", "", FakeResolver(txt=txt))
    assert res.result == "permerror" and "limit" in res.explanation.lower()


def test_spf_dns_failure_is_temperror():
    r = FakeResolver(txt={"x.com": ["v=spf1 -all"]}, fail=["x.com"])
    assert check_spf("1.2.3.4", "u@x.com", "", r).result == "temperror"


def test_spf_null_sender_uses_helo():
    r = FakeResolver(txt={"mta.example.org": ["v=spf1 ip4:1.2.3.4 -all"]})
    res = check_spf("1.2.3.4", "<>", "mta.example.org", r)
    assert res.result == "pass" and res.sender == "postmaster@mta.example.org"


def test_spf_ipv4_mapped_ipv6_client():
    r = FakeResolver(txt={"e.com": ["v=spf1 ip4:1.2.3.4 -all"]})
    assert check_spf("::ffff:1.2.3.4", "u@e.com", "", r).result == "pass"


# =========================================================================== #
# DKIM (live key from DNS)
# =========================================================================== #
def _make_signed(domain="example.com", selector="sel1", from_addr="alice@example.com"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    record = "v=DKIM1; k=rsa; p=" + base64.b64encode(der).decode()
    hdrs = (f"From: Alice <{from_addr}>\r\nTo: bob@test.org\r\nSubject: Hello   world\r\n"
            "Date: Sun, 15 Nov 2026 10:00:00 +0000\r\n").encode()
    body = b"Hi Bob,\r\nPlease review.  \r\n\r\nThanks\r\n"
    bh = base64.b64encode(hashlib.sha256(_canon_body(body, "relaxed")).digest()).decode()
    tmpl = (f"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d={domain}; s={selector}; "
            f"h=from:to:subject:date; bh={bh}; b=")
    fields, _ = _split_raw(hdrs + b"\r\n")
    data = b"".join(_canon_header(f, "relaxed") for f in fields) + _canon_header(tmpl.encode(), "relaxed").rstrip(b"\r\n")
    sig = base64.b64encode(key.sign(data, padding.PKCS1v15(), hashes.SHA256())).decode()
    return (tmpl + sig).encode() + b"\r\n" + hdrs + b"\r\n" + body, record, key


def _other_key_record():
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return "v=DKIM1; k=rsa; p=" + base64.b64encode(der).decode()


def test_dkim_live_key_verifies():
    msg, record, _ = _make_signed()
    r = FakeResolver(txt={"sel1._domainkey.example.com": [record]})
    store = DNSKeyStore(r)
    res = verify_dkim_signatures(msg, store)
    assert res[0].status == DKIMCryptoStatus.VERIFIED and res[0].key_source == "dns"
    assert summarize_dkim(res, store)["result"] == "pass"


def test_dkim_split_txt_record_is_joined_by_resolver_contract():
    # Resolver contract: multi-string TXT already concatenated; verify with a long 2048-bit key
    msg, record, _ = _make_signed()
    store = DNSKeyStore(FakeResolver(txt={"sel1._domainkey.example.com": [record]}))
    assert verify_dkim_signatures(msg, store)[0].signature_valid is True


def test_dkim_tampered_body_fails():
    msg, record, _ = _make_signed()
    store = DNSKeyStore(FakeResolver(txt={"sel1._domainkey.example.com": [record]}))
    res = verify_dkim_signatures(msg.replace(b"Please review", b"Click here"), store)
    assert res[0].status == DKIMCryptoStatus.BODY_MODIFIED
    assert summarize_dkim(res, store)["result"] == "fail"


def test_dkim_forged_header_fails_signature():
    msg, record, _ = _make_signed()
    store = DNSKeyStore(FakeResolver(txt={"sel1._domainkey.example.com": [record]}))
    res = verify_dkim_signatures(msg.replace(b"Subject: Hello   world", b"Subject: URGENT"), store)
    assert res[0].status == DKIMCryptoStatus.SIGNATURE_INVALID


def test_dkim_key_not_in_dns_is_permerror():
    msg, _, _ = _make_signed()
    store = DNSKeyStore(FakeResolver())
    res = verify_dkim_signatures(msg, store)
    assert res[0].status == DKIMCryptoStatus.BODY_HASH_ONLY and "NXDOMAIN" in " ".join(res[0].notes)
    assert summarize_dkim(res, store)["result"] == "permerror"


def test_dkim_revoked_key():
    msg, _, _ = _make_signed()
    store = DNSKeyStore(FakeResolver(txt={"sel1._domainkey.example.com": ["v=DKIM1; k=rsa; p="]}))
    res = verify_dkim_signatures(msg, store)
    assert "revoked" in " ".join(res[0].notes)
    assert summarize_dkim(res, store)["result"] == "permerror"


def test_dkim_dns_down_without_fallback_is_temperror():
    msg, _, _ = _make_signed()
    store = DNSKeyStore(FakeResolver(fail=["sel1._domainkey.example.com"]))
    res = verify_dkim_signatures(msg, store)
    assert summarize_dkim(res, store)["result"] == "temperror"


def test_dkim_dns_down_uses_pinned_fallback():
    msg, record, _ = _make_signed()
    pinned = LocalKeyStore(records={"sel1._domainkey.example.com": record})
    store = DNSKeyStore(FakeResolver(fail=["sel1._domainkey.example.com"]), fallback=pinned)
    res = verify_dkim_signatures(msg, store)
    assert res[0].status == DKIMCryptoStatus.VERIFIED and res[0].key_source == "local_keystore_dns_fallback"


def test_dkim_rotated_key_not_masked_by_stale_pin():
    msg, old_record, _ = _make_signed()
    pinned = LocalKeyStore(records={"sel1._domainkey.example.com": old_record})
    # DNS now publishes a different key: pinned (stale) key must NOT be used
    store = DNSKeyStore(FakeResolver(txt={"sel1._domainkey.example.com": [_other_key_record()]}), fallback=pinned)
    assert verify_dkim_signatures(msg, store)[0].status == DKIMCryptoStatus.SIGNATURE_INVALID


def test_dkim_no_signature():
    store = DNSKeyStore(FakeResolver())
    res = verify_dkim_signatures(b"From: a@b.com\r\n\r\nhi\r\n", store)
    assert summarize_dkim(res, store)["result"] == "none"


def test_offline_keystore_behaviour_unchanged():
    msg, record, _ = _make_signed()
    store = LocalKeyStore(records={"sel1._domainkey.example.com": record})
    res = verify_dkim_signatures(msg, store)[0]
    assert res.status == DKIMCryptoStatus.VERIFIED and res.key_source == "local_keystore"
    assert verify_dkim_signatures(msg, LocalKeyStore())[0].status == DKIMCryptoStatus.BODY_HASH_ONLY


# =========================================================================== #
# DMARC
# =========================================================================== #
def test_organizational_domain():
    assert organizational_domain("mail.sub.example.com") == "example.com"
    assert organizational_domain("a.b.example.co.uk") == "example.co.uk"
    assert organizational_domain("x.bank.co.in") == "bank.co.in"


def test_dmarc_pass_via_aligned_dkim():
    r = FakeResolver(txt={"_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:r@example.com"]})
    d = evaluate_dmarc(r, "example.com", "fail", "other.net", True, ["mail.example.com"])
    assert d.result == "pass" and d.dkim_aligned and not d.spf_aligned


def test_dmarc_pass_via_aligned_spf():
    r = FakeResolver(txt={"_dmarc.example.com": ["v=DMARC1; p=quarantine"]})
    d = evaluate_dmarc(r, "example.com", "pass", "bounce.example.com", True, [])
    assert d.result == "pass" and d.spf_aligned


def test_dmarc_fail_reject_when_unaligned():
    r = FakeResolver(txt={"_dmarc.bank.com": ["v=DMARC1; p=reject"]})
    d = evaluate_dmarc(r, "bank.com", "pass", "attacker.ru", True, ["attacker.ru"])
    assert d.result == "fail" and d.disposition == "reject"


def test_dmarc_strict_alignment_rejects_subdomain():
    r = FakeResolver(txt={"_dmarc.example.com": ["v=DMARC1; p=reject; adkim=s; aspf=s"]})
    d = evaluate_dmarc(r, "example.com", "pass", "mail.example.com", True, ["mail.example.com"])
    assert d.result == "fail"


def test_dmarc_subdomain_falls_back_to_org_and_uses_sp():
    r = FakeResolver(txt={"_dmarc.example.com": ["v=DMARC1; p=none; sp=reject"]})
    d = evaluate_dmarc(r, "news.example.com", "none", None, False, [])
    assert d.policy_domain == "example.com" and d.applied_policy == "reject" and d.result == "fail"


def test_dmarc_no_record_is_none():
    d = evaluate_dmarc(FakeResolver(), "nodmarc.com", "pass", "nodmarc.com", True, [])
    assert d.result == "none"


def test_dmarc_helo_spf_gets_no_alignment_credit():
    r = FakeResolver(txt={"_dmarc.example.com": ["v=DMARC1; p=reject"]})
    d = evaluate_dmarc(r, "example.com", "pass", "example.com", False, [])
    assert d.result == "fail"


def test_dmarc_multiple_records_ignored():
    r = FakeResolver(txt={"_dmarc.x.com": ["v=DMARC1; p=reject", "v=DMARC1; p=none"]})
    assert evaluate_dmarc(r, "x.com", "fail", None, True, []).result == "none"


def test_dmarc_dns_failure_is_temperror():
    r = FakeResolver(fail=["_dmarc.x.com"])
    assert evaluate_dmarc(r, "x.com", "pass", "x.com", True, []).result == "temperror"


# =========================================================================== #
# Orchestrator
# =========================================================================== #
def _header_info(msg_from="alice@example.com", return_path="<bounce@example.com>", date="Sun, 15 Nov 2026 10:00:00 +0000"):
    return SimpleNamespace(
        from_header=f"Alice <{msg_from}>", return_path=return_path, date=date,
        received_headers=["from mail.example.com (mail.example.com [203.0.113.5]) by mx.me.org with ESMTPS"],
    )


def _ips(ip="203.0.113.5", cls="Public", hop=0):
    return [SimpleNamespace(ip=ip, classification=cls, hop_index=hop)]


def test_orchestrator_all_pass():
    msg, record, _ = _make_signed()
    r = FakeResolver(txt={
        "example.com": ["v=spf1 ip4:203.0.113.0/24 -all"],
        "sel1._domainkey.example.com": [record],
        "_dmarc.example.com": ["v=DMARC1; p=reject"],
    })
    out = run_live_authentication(msg, _header_info(), _ips(), resolver=r,
                                  now=datetime(2026, 11, 16, tzinfo=timezone.utc))
    assert out["mode"] == "LIVE_DNS" and out["available"]
    assert out["summary"] == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    assert out["spf"]["client_ip_source"] == "Received[0]"


def test_orchestrator_spoofed_sender_detected():
    # Attacker sends "From: alice@example.com" from their own server, unsigned
    msg = b"From: Alice <alice@example.com>\r\nSubject: wire money\r\n\r\nnow\r\n"
    r = FakeResolver(txt={
        "example.com": ["v=spf1 ip4:203.0.113.0/24 -all"],
        "_dmarc.example.com": ["v=DMARC1; p=reject"],
    })
    out = run_live_authentication(msg, _header_info(), _ips("198.51.100.66"), resolver=r)
    assert out["summary"] == {"spf": "fail", "dkim": "none", "dmarc": "fail"}
    assert out["dmarc"]["disposition"] == "reject"


def test_orchestrator_no_public_ip_skips_spf():
    msg, record, _ = _make_signed()
    r = FakeResolver(txt={"sel1._domainkey.example.com": [record], "_dmarc.example.com": ["v=DMARC1; p=none"]})
    out = run_live_authentication(msg, _header_info(), _ips("10.0.0.5", "Private"), resolver=r)
    assert out["spf"]["evaluated"] is False
    assert out["dkim"]["result"] == "pass" and out["dmarc"]["result"] == "pass"


def test_orchestrator_dns_unreachable_reports_unavailable():
    msg, _, _ = _make_signed()
    r = FakeResolver(fail=["example.com", "sel1._domainkey.example.com", "_dmarc.example.com"])
    out = run_live_authentication(msg, _header_info(), _ips(), resolver=r)
    assert out["available"] is False and out["dns_errors"]


def test_orchestrator_old_message_gets_staleness_caveat():
    msg, record, _ = _make_signed()
    r = FakeResolver(txt={"example.com": ["v=spf1 -all"], "sel1._domainkey.example.com": [record]})
    out = run_live_authentication(msg, _header_info(), _ips(), resolver=r,
                                  now=datetime(2026, 11, 21, tzinfo=timezone.utc))
    assert any("days old" in c for c in out["caveats"])


def test_orchestrator_forwarding_caveat():
    msg, record, _ = _make_signed()
    r = FakeResolver(txt={"example.com": ["v=spf1 ip4:192.0.2.1 -all"], "sel1._domainkey.example.com": [record],
                          "_dmarc.example.com": ["v=DMARC1; p=reject"]})
    out = run_live_authentication(msg, _header_info(), _ips(), resolver=r)
    assert out["summary"]["spf"] == "fail" and out["summary"]["dkim"] == "pass" and out["summary"]["dmarc"] == "pass"
    assert any("forwarded" in c for c in out["caveats"])
