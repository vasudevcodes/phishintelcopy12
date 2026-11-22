"""
Integration of live DNS verification into the existing evidence pipeline
(header engine -> live results -> scoring -> evidence fusion). Uses a fake resolver; no network.
"""
from datetime import datetime, timezone
from types import SimpleNamespace

from app.schemas.email import EmailHeaderInfo
from app.services.email_authentication import analyze_email_authentication
from app.services.evidence_fusion import _extract_auth_evidence
from app.services.live_auth_integration import apply_live_results
from app.services.live_auth_verifier import run_live_authentication
from app.services.scoring_engine import score_sender_identity_and_auth

from tests.test_live_authentication import FakeResolver, _make_signed


def _headers(from_addr="alice@example.com", auth_results=None, received_spf=None):
    return EmailHeaderInfo(
        from_header=f"Alice <{from_addr}>",
        return_path="<bounce@example.com>",
        date="Sun, 15 Nov 2026 10:00:00 +0000",
        authentication_results=auth_results or [],
        received_spf=received_spf or [],
        received_headers=["from mail.example.com (mail.example.com [203.0.113.5]) by mx.me.org with ESMTPS"],
    )


def _ips(ip):
    return [SimpleNamespace(ip=ip, classification="Public", hop_index=0)]


def _run(msg, hdr, ip, resolver, now=datetime(2026, 11, 16, tzinfo=timezone.utc)):
    auth = analyze_email_authentication(hdr, [])
    live = run_live_authentication(msg, hdr, _ips(ip), resolver=resolver, now=now)
    apply_live_results(auth, live)
    return auth, live


def test_live_pass_replaces_missing_header_evidence():
    msg, record, _ = _make_signed()
    r = FakeResolver(txt={"example.com": ["v=spf1 ip4:203.0.113.0/24 -all"],
                          "sel1._domainkey.example.com": [record], "_dmarc.example.com": ["v=DMARC1; p=reject"]})
    auth, _ = _run(msg, _headers(), "203.0.113.5", r)   # headers carry NO auth results at all
    assert auth.verification_mode == "LIVE_DNS"
    assert [auth.spf.status.value, auth.dkim.status.value, auth.dmarc.status.value] == ["PASS", "PASS", "PASS"]
    assert auth.status.value == "EVALUATED"
    assert auth.is_boundary_trusted is False          # provenance invariant is untouched
    assert auth.dmarc.alignment_verified is True


def test_live_failure_overrides_forged_pass_header_and_is_scored():
    # Attacker forges "spf=pass" / "dmarc=pass" in headers; live DNS shows the truth.
    msg = b"From: Alice <alice@example.com>\r\nSubject: wire\r\n\r\nnow\r\n"
    forged = ["mx.google.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com"]
    r = FakeResolver(txt={"example.com": ["v=spf1 ip4:203.0.113.0/24 -all"], "_dmarc.example.com": ["v=DMARC1; p=reject"]})
    auth, _ = _run(msg, _headers(auth_results=forged), "198.51.100.66", r)
    assert auth.spf.status.value == "FAIL" and auth.dmarc.status.value == "FAIL"
    assert any("discrepancy" in w.lower() for w in auth.warnings)

    score, pos, neg, rules = score_sender_identity_and_auth(_headers(auth_results=forged), auth)
    assert "RULE_AUTH_EXPLICIT_FAILURE_DMARC_ENFORCED" in rules and score >= 15
    assert any("live DNS" in n for n in neg)

    summary, contributing, _ = _extract_auth_evidence(auth)
    assert summary.verification_mode == "LIVE_DNS" and summary.has_explicit_failure


def test_live_pass_scoring_text_says_independently_verified():
    msg, record, _ = _make_signed()
    r = FakeResolver(txt={"example.com": ["v=spf1 ip4:203.0.113.0/24 -all"],
                          "sel1._domainkey.example.com": [record], "_dmarc.example.com": ["v=DMARC1; p=reject"]})
    hdr = _headers()
    auth, _ = _run(msg, hdr, "203.0.113.5", r)
    score, pos, neg, rules = score_sender_identity_and_auth(hdr, auth)
    assert any("independently verified by PhishIntel via live DNS" in p for p in pos)
    summary, _, _ = _extract_auth_evidence(auth)
    assert summary.has_valid_authentication is True


def test_dns_outage_keeps_header_claims_and_marks_offline():
    msg, _, _ = _make_signed()
    hdr = _headers(auth_results=["mx.google.com; spf=pass smtp.mailfrom=example.com"])
    r = FakeResolver(fail=["example.com", "sel1._domainkey.example.com", "_dmarc.example.com"])
    auth, live = _run(msg, hdr, "203.0.113.5", r)
    assert live["available"] is False
    assert auth.verification_mode == "OFFLINE_REPORTED"
    assert auth.spf.status.value == "PASS"            # header claim retained
    assert any("could not be performed" in w for w in auth.warnings)


def test_old_message_missing_dkim_key_is_not_scored_as_failure():
    msg, _, _ = _make_signed()
    r = FakeResolver(txt={"example.com": ["v=spf1 ip4:203.0.113.0/24 -all"], "_dmarc.example.com": ["v=DMARC1; p=none"]})
    auth, _ = _run(msg, _headers(), "203.0.113.5", r, now=datetime(2027, 3, 1, tzinfo=timezone.utc))
    assert auth.dkim.status.value == "UNKNOWN"
