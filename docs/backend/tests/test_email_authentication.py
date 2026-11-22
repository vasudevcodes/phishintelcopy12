"""
Tests for Phase 5A Email Authentication Evidence Engine (PhishIntel).
Covers 15 scenarios:
1. SPF pass
2. SPF fail
3. SPF softfail and neutral
4. DKIM pass and fail
5. DMARC pass and fail
6. Missing authentication evidence
7. Multiple Authentication-Results headers
8. Conflicting results
9. Malformed header values
10. Unrelated or misleading header content
11. DKIM-Signature header without explicit verification result
12. Missing optional headers
13. API integration with existing URL analysis
14. Regression tests for Phase 1 and Phase 4B
15. Network isolation test (zero DNS / outbound network calls)
"""

import io
from pathlib import Path
import socket
from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.schemas.email import EmailHeaderInfo
from app.schemas.email_authentication import (
    AuthResultStatus,
    OverallAuthStatus,
)
from app.services.email_authentication import analyze_email_authentication
from app.services.email_parser import parse_email_message

client = TestClient(app)
FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def guard_no_network(monkeypatch):
    """
    Enforces zero network access during authentication tests.
    Outbound socket connections and non-local DNS resolutions raise RuntimeError.
    """
    orig_connect = socket.socket.connect
    orig_getaddrinfo = socket.getaddrinfo
    orig_gethostbyname = socket.gethostbyname

    def fail_connect(self, addr):
        host = addr[0] if isinstance(addr, tuple) else addr
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise RuntimeError(f"Network connect attempted during test: {addr}")
        return orig_connect(self, addr)

    def fail_dns(host, *args, **kwargs):
        if host not in ("127.0.0.1", "localhost", "::1", "testserver", None, ""):
            raise RuntimeError(f"DNS resolution attempted during test: {host}")
        return orig_getaddrinfo(host, *args, **kwargs)

    def fail_gethostbyname(host):
        if host not in ("127.0.0.1", "localhost", "::1", "testserver"):
            raise RuntimeError(f"DNS resolution attempted during test: {host}")
        return orig_gethostbyname(host)

    monkeypatch.setattr(socket.socket, "connect", fail_connect)
    monkeypatch.setattr(socket, "getaddrinfo", fail_dns)
    monkeypatch.setattr(socket, "gethostbyname", fail_gethostbyname)


# 1. SPF Pass
def test_01_spf_pass():
    header_info = EmailHeaderInfo(
        authentication_results=[
            "mx.google.com; spf=pass (google.com: domain of sender@example.com designates 192.0.2.1 as permitted sender) smtp.mailfrom=sender@example.com"
        ],
        received_spf=[
            "pass (google.com: domain of sender@example.com designates 192.0.2.1 as permitted sender) client-ip=192.0.2.1;"
        ],
    )
    analysis = analyze_email_authentication(header_info)
    assert analysis.spf.status == AuthResultStatus.PASS
    assert analysis.spf.domain == "sender@example.com"
    assert analysis.spf.client_ip == "192.0.2.1"
    assert "mx.google.com" in analysis.authserv_ids
    assert len(analysis.spf.findings) == 2


# 2. SPF Fail
def test_02_spf_fail():
    header_info = EmailHeaderInfo(
        authentication_results=[
            "mx.google.com; spf=fail (google.com: domain of bad@spoofed.com does not designate 198.51.100.1) smtp.mailfrom=bad@spoofed.com"
        ]
    )
    analysis = analyze_email_authentication(header_info)
    assert analysis.spf.status == AuthResultStatus.FAIL
    assert analysis.spf.domain == "bad@spoofed.com"
    assert analysis.status in [OverallAuthStatus.EVALUATED, OverallAuthStatus.PARTIAL_EVIDENCE]


# 3. SPF Softfail and Neutral
def test_03_spf_softfail_and_neutral():
    # Softfail
    h_soft = EmailHeaderInfo(
        authentication_results=["mx.example.org; spf=softfail smtp.mailfrom=test@example.org"]
    )
    res_soft = analyze_email_authentication(h_soft)
    assert res_soft.spf.status == AuthResultStatus.SOFTFAIL

    # Neutral via Received-SPF
    h_neu = EmailHeaderInfo(
        received_spf=["neutral (domain of neu@example.org: 192.0.2.1 is neither permitted nor denied)"]
    )
    res_neu = analyze_email_authentication(h_neu)
    assert res_neu.spf.status == AuthResultStatus.NEUTRAL


# 4. DKIM Pass and Fail
def test_04_dkim_pass_and_fail():
    # Pass
    h_pass = EmailHeaderInfo(
        authentication_results=[
            "mx.google.com; dkim=pass header.i=@legit.com header.s=s2026 header.d=legit.com"
        ]
    )
    res_pass = analyze_email_authentication(h_pass)
    assert res_pass.dkim.status == AuthResultStatus.PASS
    assert res_pass.dkim.domain == "legit.com"
    assert res_pass.dkim.selector == "s2026"

    # Fail
    h_fail = EmailHeaderInfo(
        authentication_results=[
            "mx.google.com; dkim=fail (body hash mismatch) header.d=legit.com"
        ]
    )
    res_fail = analyze_email_authentication(h_fail)
    assert res_fail.dkim.status == AuthResultStatus.FAIL
    assert res_fail.dkim.domain == "legit.com"


# 5. DMARC Pass and Fail
def test_05_dmarc_pass_and_fail():
    # Pass with policy and disposition
    h_pass = EmailHeaderInfo(
        authentication_results=[
            "mx.google.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=corporate.com"
        ]
    )
    res_pass = analyze_email_authentication(h_pass)
    assert res_pass.dmarc.status == AuthResultStatus.PASS
    assert res_pass.dmarc.policy is not None
    assert res_pass.dmarc.policy.lower() == "reject"
    assert res_pass.dmarc.disposition is not None
    assert res_pass.dmarc.disposition.lower() == "none"
    assert res_pass.dmarc.header_from == "corporate.com"

    # Fail
    h_fail = EmailHeaderInfo(
        authentication_results=[
            "mx.google.com; dmarc=fail (p=REJECT dis=REJECT) header.from=spoof.com"
        ]
    )
    res_fail = analyze_email_authentication(h_fail)
    assert res_fail.dmarc.status == AuthResultStatus.FAIL
    assert res_fail.dmarc.header_from == "spoof.com"


# 6. Missing Authentication Evidence
def test_06_missing_authentication_evidence():
    header_info = EmailHeaderInfo()
    analysis = analyze_email_authentication(header_info)
    assert analysis.status == OverallAuthStatus.NO_EVIDENCE
    assert analysis.spf.status == AuthResultStatus.NOT_PRESENT
    assert analysis.dkim.status == AuthResultStatus.NOT_PRESENT
    assert analysis.dmarc.status == AuthResultStatus.NOT_PRESENT
    assert analysis.has_conflicts is False


# 7. Multiple Authentication-Results Headers (Consistent)
def test_07_multiple_authentication_results_consistent():
    header_info = EmailHeaderInfo(
        authentication_results=[
            "edge-gateway.internal; spf=pass smtp.mailfrom=user@company.com; dkim=pass header.d=company.com",
            "internal-relay.corp; spf=pass; dkim=pass",
        ]
    )
    analysis = analyze_email_authentication(header_info)
    assert analysis.spf.status == AuthResultStatus.PASS
    assert analysis.dkim.status == AuthResultStatus.PASS
    assert len(analysis.spf.findings) == 2
    assert len(analysis.dkim.findings) == 2
    assert analysis.has_conflicts is False


# 8. Conflicting Results
def test_08_conflicting_results():
    header_info = EmailHeaderInfo(
        authentication_results=[
            "mta1.corp.com; spf=pass smtp.mailfrom=user@company.com",
            "mta2.corp.com; spf=fail smtp.mailfrom=user@company.com",
        ]
    )
    analysis = analyze_email_authentication(header_info)
    assert analysis.spf.status == AuthResultStatus.CONFLICTING_EVIDENCE
    assert analysis.status == OverallAuthStatus.CONFLICTING_EVIDENCE
    assert analysis.has_conflicts is True
    assert "Conflicting SPF results" in analysis.spf.explanation


# 9. Malformed Header Values
def test_09_malformed_header_values():
    header_info = EmailHeaderInfo(
        authentication_results=[
            "mx.bad.com; spf=invalid_unrecognized_token; dkim=@@corrupted_token"
        ]
    )
    analysis = analyze_email_authentication(header_info)
    assert analysis.spf.status == AuthResultStatus.UNKNOWN
    assert analysis.dkim.status == AuthResultStatus.UNKNOWN


# 10. Misleading or Unrelated Content
def test_10_unrelated_or_misleading_content():
    header_info = EmailHeaderInfo(
        authentication_results=[
            'mx.test.com; note="spf=pass was fake"; something_else=hello; custom_tag="dkim=pass"'
        ]
    )
    analysis = analyze_email_authentication(header_info)
    # The header has no valid spf= or dkim= method clauses
    assert analysis.spf.status == AuthResultStatus.NOT_PRESENT
    assert analysis.dkim.status == AuthResultStatus.NOT_PRESENT


# 11. DKIM-Signature Header Present Without Explicit Verification Result
def test_11_dkim_signature_without_verification():
    raw_dkim_sig = [
        "v=1; a=rsa-sha256; c=relaxed/relaxed; d=sender.com; s=s1; bh=abc...; b=xyz..."
    ]
    header_info = EmailHeaderInfo(
        dkim_signatures=raw_dkim_sig,
        authentication_results=[],  # No MTA verified it
    )
    analysis = analyze_email_authentication(header_info, raw_dkim_signatures=raw_dkim_sig)
    assert analysis.dkim.has_dkim_signature_header is True
    assert analysis.dkim.dkim_signature_count == 1
    # MUST NOT be PASS! It is unverified
    assert analysis.dkim.status == AuthResultStatus.UNKNOWN
    assert analysis.dkim.status != AuthResultStatus.PASS
    assert "no receiving mta recorded a verification result" in analysis.dkim.explanation.lower()


# 12. Missing Optional Headers
def test_12_missing_optional_headers():
    eml_minimal = (
        b"From: test@domain.com\n"
        b"Subject: Minimal Email\n\n"
        b"Body content only.\n"
    )
    res = parse_email_message(eml_minimal, "minimal.eml")
    assert res.parsing_status == "success"
    assert res.authentication_analysis is not None
    assert res.authentication_analysis.status == OverallAuthStatus.NO_EVIDENCE


# 13. API Integration with Existing URL Analysis
def test_13_api_integration_with_url_analysis():
    eml_with_both = (
        b"From: billing@domain.com\n"
        b"To: client@domain.com\n"
        b"Subject: Invoices\n"
        b"Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=domain.com; dkim=pass header.d=domain.com; dmarc=pass header.from=domain.com\n"
        b"Content-Type: text/html\n\n"
        b'<p>Click <a href="https://billing.domain.com/pay">here</a></p>\n'
    )
    response = client.post(
        "/api/v1/email/analyze",
        files={"file": ("both.eml", io.BytesIO(eml_with_both), "message/rfc822")},
    )
    assert response.status_code == 200
    data = response.json()

    # 1. URL Analysis intact
    assert "url_analysis" in data
    assert data["url_analysis"] is not None
    assert data["url_analysis"]["total_urls"] == 1
    assert data["url_analysis"]["url_results"][0]["normalized_hostname"] == "billing.domain.com"

    # 2. Authentication Analysis intact
    assert "authentication_analysis" in data
    auth = data["authentication_analysis"]
    assert auth is not None
    assert auth["spf"]["status"] == "PASS"
    assert auth["dkim"]["status"] == "PASS"
    assert auth["dmarc"]["status"] == "PASS"
    assert auth["status"] in ["EVALUATED", "PARTIAL_EVIDENCE"]

    # 3. Existing Phase 1 parser fields intact
    assert data["filename"] == "both.eml"
    assert "headers" in data
    assert "body" in data


# 14. Regression Test for Phase 1 & Phase 4B Fixtures
def test_14_regression_fixtures():
    # Test fixture 06: has 4 received hops, IP candidates, and full auth results
    fixture_path = FIXTURES_DIR / "06_multiple_received_hops.eml"
    with open(fixture_path, "rb") as f:
        response = client.post(
            "/api/v1/email/analyze",
            files={"file": ("06_multiple_received_hops.eml", f, "message/rfc822")},
        )
    assert response.status_code == 200
    data = response.json()

    # Check headers
    assert len(data["headers"]["received_headers"]) == 4
    assert len(data["ip_candidates"]) >= 3
    assert len(data["headers"]["authentication_results"]) == 1
    assert len(data["headers"]["received_spf"]) == 1

    # Check Phase 5A authentication results
    auth = data["authentication_analysis"]
    assert auth is not None
    assert auth["spf"]["status"] == "PASS"
    assert auth["dkim"]["status"] == "PASS"
    assert auth["dmarc"]["status"] == "PASS"
    assert "mx.google.com" in auth["authserv_ids"]


# 15. Network Isolation
def test_15_network_isolation(monkeypatch):
    """
    Explicitly verifies that email authentication interpretation
    operates 100% offline and raises immediately if any outbound connection or DNS is attempted.
    """
    def block_all(*args, **kwargs):
        raise RuntimeError("Network activity strictly forbidden in Phase 5A!")

    monkeypatch.setattr(socket, "getaddrinfo", block_all)
    monkeypatch.setattr(socket, "gethostbyname", block_all)

    # Analyze an email with full auth headers
    h = EmailHeaderInfo(
        authentication_results=[
            "mx.example.com; spf=pass smtp.mailfrom=test.org; dkim=pass header.d=test.org; dmarc=pass header.from=test.org"
        ],
        received_spf=["pass client-ip=192.0.2.1"],
    )
    res = analyze_email_authentication(h)
    assert res.spf.status == AuthResultStatus.PASS
    assert res.dkim.status == AuthResultStatus.PASS
    assert res.dmarc.status == AuthResultStatus.PASS
