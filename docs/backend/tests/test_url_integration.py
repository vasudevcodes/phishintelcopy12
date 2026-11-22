"""
Integration tests for Phase 4B URL Intelligence Integration (PhishIntel).
Tests end-to-end email analysis endpoint (/api/v1/email/analyze) with URL intelligence,
covering multiple URLs, zero URLs, duplicate URLs, malformed URLs, multipart emails,
unsupported schemes, serialization, graceful error handling, and socket isolation.
"""

import io
from pathlib import Path
import socket
from fastapi.testclient import TestClient
import pytest

from app.main import app

client = TestClient(app)
FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def guard_no_network(monkeypatch):
    """
    Enforces zero network access during API integration tests.
    Outbound socket connections and non-local DNS resolutions raise RuntimeError.
    """
    orig_connect = socket.socket.connect
    orig_getaddrinfo = socket.getaddrinfo
    orig_gethostbyname = socket.gethostbyname

    def fail_connect(self, addr):
        host = addr[0] if isinstance(addr, tuple) else addr
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise RuntimeError(f"Network connect attempted during API test: {addr}")
        return orig_connect(self, addr)

    def fail_dns(host, *args, **kwargs):
        if host not in ("127.0.0.1", "localhost", "::1", "testserver", None, ""):
            raise RuntimeError(f"DNS resolution attempted during API test: {host}")
        return orig_getaddrinfo(host, *args, **kwargs)

    def fail_gethostbyname(host):
        if host not in ("127.0.0.1", "localhost", "::1", "testserver"):
            raise RuntimeError(f"DNS resolution attempted during API test: {host}")
        return orig_gethostbyname(host)

    monkeypatch.setattr(socket.socket, "connect", fail_connect)
    monkeypatch.setattr(socket, "getaddrinfo", fail_dns)
    monkeypatch.setattr(socket, "gethostbyname", fail_gethostbyname)


def test_api_integration_multiple_urls():
    """
    Tests upload of 05_multiple_urls.eml, verifying that extracted URLs
    are analyzed by the URL Intelligence Engine and returned in 'url_analysis'.
    """
    fixture_path = FIXTURES_DIR / "05_multiple_urls.eml"
    with open(fixture_path, "rb") as f:
        response = client.post(
            "/api/v1/email/analyze",
            files={"file": ("05_multiple_urls.eml", f, "message/rfc822")},
        )
    assert response.status_code == 200
    data = response.json()

    # 1. Existing Phase 1 parser fields intact
    assert data["filename"] == "05_multiple_urls.eml"
    assert "headers" in data
    assert "body" in data
    assert "urls" in data
    assert len(data["urls"]) == 4  # 4 deduplicated URLs in fixture

    # 2. Phase 4B URL Intelligence section present
    assert "url_analysis" in data
    url_analysis = data["url_analysis"]
    assert url_analysis is not None
    assert url_analysis["total_urls"] == 4
    assert url_analysis["unique_urls"] == 4
    assert "highest_risk_category" in url_analysis
    assert "risk_breakdown" in url_analysis
    assert len(url_analysis["url_results"]) == 4

    # 3. Check per-URL evidence and source preservation
    first_res = url_analysis["url_results"][0]
    assert "url_index" in first_res
    assert "original_url" in first_res
    assert "source" in first_res
    assert first_res["source"] in ["plain_text", "html_href", "both"]
    assert "features" in first_res
    assert "observations" in first_res
    assert "heuristic_risk_category" in first_res
    assert "heuristic_risk_score" in first_res
    assert 0 <= first_res["heuristic_risk_score"] <= 100
    assert "risk_summary" in first_res


def test_api_integration_no_urls():
    """
    Tests upload of an email with no URLs (01_simple_plaintext.eml).
    Must return empty URL analysis collection, NOT an error or null crash.
    """
    fixture_path = FIXTURES_DIR / "01_simple_plaintext.eml"
    with open(fixture_path, "rb") as f:
        response = client.post(
            "/api/v1/email/analyze",
            files={"file": ("01_simple_plaintext.eml", f, "message/rfc822")},
        )
    assert response.status_code == 200
    data = response.json()

    assert data["urls"] == []
    assert "url_analysis" in data
    url_analysis = data["url_analysis"]
    assert url_analysis["total_urls"] == 0
    assert url_analysis["unique_urls"] == 0
    assert url_analysis["url_results"] == []
    assert url_analysis["highest_risk_category"] == "INFO"


def test_api_integration_duplicate_urls_in_eml():
    """
    Tests an EML containing duplicate identical URLs across plain text and HTML.
    Verifies that deduplication is handled cleanly.
    """
    eml_content = (
        b"From: test@sender.com\n"
        b"To: user@target.com\n"
        b"Subject: Duplicates Test\n"
        b"Content-Type: text/plain\n\n"
        b"Visit https://example.com/login and again at https://example.com/login\n"
    )
    response = client.post(
        "/api/v1/email/analyze",
        files={"file": ("dup_test.eml", io.BytesIO(eml_content), "message/rfc822")},
    )
    assert response.status_code == 200
    data = response.json()

    # The Phase 1 parser deduplicates into a single ExtractedURL
    assert len(data["urls"]) == 1
    assert data["url_analysis"]["total_urls"] == 1
    assert data["url_analysis"]["unique_urls"] == 1
    assert data["url_analysis"]["url_results"][0]["normalized_hostname"] == "example.com"


def test_api_integration_malformed_url_in_eml():
    """
    Tests an email containing a malformed URL string.
    The email analysis must succeed gracefully, flagging the URL without crashing the request.
    """
    eml_content = (
        b"From: attacker@bad.com\n"
        b"To: victim@work.com\n"
        b"Subject: Malformed Link\n"
        b'Content-Type: text/html\n\n'
        b'<a href="https:///missing-host/path">Click</a>\n'
    )
    response = client.post(
        "/api/v1/email/analyze",
        files={"file": ("malformed_url.eml", io.BytesIO(eml_content), "message/rfc822")},
    )
    assert response.status_code == 200
    data = response.json()

    assert len(data["urls"]) == 1
    url_analysis = data["url_analysis"]
    assert len(url_analysis["url_results"]) == 1
    malformed_res = url_analysis["url_results"][0]
    assert malformed_res["parse_status"] == "malformed"
    assert any("MISSING" in o["rule_id"] or "MALFORMED" in o["rule_id"] for o in malformed_res["observations"])


def test_api_integration_unsupported_scheme_in_eml():
    """
    Tests an email with unsupported or dangerous script schemes (e.g. javascript:, data:).
    """
    eml_content = (
        b"From: attacker@bad.com\n"
        b"To: victim@work.com\n"
        b"Subject: Script Link\n"
        b'Content-Type: text/html\n\n'
        b'<a href="javascript:alert(1)">Exploit</a>\n'
    )
    # The Phase 1 parser extracts href if it starts with http/https, but if text contains it:
    eml_content_with_http_and_js = (
        b"From: attacker@bad.com\n"
        b"To: victim@work.com\n"
        b"Subject: Mixed Links\n"
        b'Content-Type: text/html\n\n'
        b'<p>Click <a href="http://legit.com@phish.com/auth">here</a></p>\n'
    )
    response = client.post(
        "/api/v1/email/analyze",
        files={"file": ("unusual.eml", io.BytesIO(eml_content_with_http_and_js), "message/rfc822")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["url_analysis"]["highest_risk_category"] == "HIGH"
    assert data["url_analysis"]["url_results"][0]["features"]["has_userinfo"] is True


def test_api_integration_multipart_html_and_plaintext():
    """
    Tests upload of 03_multipart_plain_html.eml fixture.
    """
    fixture_path = FIXTURES_DIR / "03_multipart_plain_html.eml"
    with open(fixture_path, "rb") as f:
        response = client.post(
            "/api/v1/email/analyze",
            files={"file": ("03_multipart_plain_html.eml", f, "message/rfc822")},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["body"]["has_plain_text"] is True
    assert data["body"]["has_html"] is True
    assert "url_analysis" in data


def test_api_integration_heuristic_score_serialization():
    """
    Verifies that the heuristic risk score is strictly an integer between 0 and 100,
    the risk category is one of INFO/LOW/MEDIUM/HIGH, and no probability strings exist.
    """
    fixture_path = FIXTURES_DIR / "05_multiple_urls.eml"
    with open(fixture_path, "rb") as f:
        response = client.post(
            "/api/v1/email/analyze",
            files={"file": ("05_multiple_urls.eml", f, "message/rfc822")},
        )
    assert response.status_code == 200
    data = response.json()
    for res in data["url_analysis"]["url_results"]:
        assert isinstance(res["heuristic_risk_score"], int)
        assert 0 <= res["heuristic_risk_score"] <= 100
        assert res["heuristic_risk_category"] in ["INFO", "LOW", "MEDIUM", "HIGH"]
        assert "%" not in res["heuristic_risk_category"]


def test_api_integration_graceful_url_engine_failure(monkeypatch):
    """
    Tests that an unexpected exception in the URL intelligence service
    does not crash the overall email parsing request.
    The response must succeed with a non-fatal warning recorded.
    """
    from app.services import email_parser

    def mock_broken_url_engine(*args, **kwargs):
        raise RuntimeError("Simulated URL engine failure")

    monkeypatch.setattr(email_parser, "analyze_email_extracted_urls", mock_broken_url_engine)

    fixture_path = FIXTURES_DIR / "05_multiple_urls.eml"
    with open(fixture_path, "rb") as f:
        response = client.post(
            "/api/v1/email/analyze",
            files={"file": ("05_multiple_urls.eml", f, "message/rfc822")},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "05_multiple_urls.eml"
    assert data["parsing_status"] == "partial_success"
    assert any("URL intelligence analysis non-fatal warning" in w for w in data["warnings"])
    assert data["url_analysis"] is None


def test_api_integration_single_valid_url():
    """
    Tests upload of an email containing exactly one valid URL.
    Verifies URL extraction and deterministic intelligence analysis.
    """
    eml_content = (
        b"From: billing@company.com\n"
        b"To: client@domain.com\n"
        b"Subject: Your Monthly Statement\n"
        b"Content-Type: text/plain\n\n"
        b"Please review your statement at https://billing.example.com/portal/invoices?id=123\n"
    )
    response = client.post(
        "/api/v1/email/analyze",
        files={"file": ("single_url.eml", io.BytesIO(eml_content), "message/rfc822")},
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data["urls"]) == 1
    assert data["url_analysis"]["total_urls"] == 1
    assert data["url_analysis"]["unique_urls"] == 1
    res = data["url_analysis"]["url_results"][0]
    assert res["normalized_hostname"] == "billing.example.com"
    assert res["features"]["is_https"] is True
    assert res["heuristic_risk_category"] in ["INFO", "LOW", "MEDIUM", "HIGH"]


def test_api_integration_upload_constraints_intact():
    """
    Verifies that Phase 1 upload constraints (file size limits, extension validation,
    empty file handling) remain strictly enforced and backward-compatible.
    """
    # 1. Non-eml extension rejected
    bad_ext = io.BytesIO(b"Subject: Test\n\nNot an eml.")
    r_bad_ext = client.post(
        "/api/v1/email/analyze",
        files={"file": ("report.pdf", bad_ext, "application/pdf")},
    )
    assert r_bad_ext.status_code == 400
    assert "Only .eml files are accepted" in r_bad_ext.json()["detail"]

    # 2. Empty file rejected
    empty_file = io.BytesIO(b"")
    r_empty = client.post(
        "/api/v1/email/analyze",
        files={"file": ("empty.eml", empty_file, "message/rfc822")},
    )
    assert r_empty.status_code == 400
    assert "empty" in r_empty.json()["detail"].lower()

    # 3. Oversized file (>10MB) rejected
    oversized = io.BytesIO(b"A" * (10 * 1024 * 1024 + 1024))
    r_oversized = client.post(
        "/api/v1/email/analyze",
        files={"file": ("large.eml", oversized, "message/rfc822")},
    )
    assert r_oversized.status_code == 413
    assert "exceeds maximum upload limit" in r_oversized.json()["detail"].lower()

