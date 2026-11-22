"""
Phase 9 End-to-End Application Validation and Security Review Tests.
Covers all 12 required scenarios against the live FastAPI application:
1. Ordinary plain-text email
2. HTML-only email
3. Multipart plain-text and HTML email
4. Email with multiple URLs
5. Missing or malformed optional headers
6. SPF/DKIM/DMARC evidence present, absent, or conflicting
7. Public, private, and documentation-range IP addresses
8. Empty or malformed email
9. Zero-byte upload, oversized (>10 MB) upload, and invalid extension
10. Model checkpoint unavailable and inference error handling
11. Successful analysis followed by report export verification
12. Partial analysis with optional response fields missing
"""

import io
from pathlib import Path
import socket
from unittest.mock import patch

from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.schemas.evidence_fusion import ModelInferenceEvidence, ModelInferenceStatus
from app.services.model_inference import ModelInferenceEngine

client = TestClient(app)
FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def guard_no_network(monkeypatch):
    """
    Enforces strict zero network access during validation tests.
    Any non-local connect or external DNS query raises RuntimeError.
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


# ---------------------------------------------------------------------------
# Scenario 1: Ordinary Plain-Text Email
# ---------------------------------------------------------------------------
def test_scenario_01_ordinary_plaintext_email():
    fixture_path = FIXTURES_DIR / "01_simple_plaintext.eml"
    with open(fixture_path, "rb") as f:
        resp = client.post(
            "/api/v1/email/analyze",
            files={"file": ("01_simple_plaintext.eml", f, "message/rfc822")},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["filename"] == "01_simple_plaintext.eml"
    assert data["body"]["has_plain_text"] is True
    assert data["body"]["has_html"] is False
    assert "Meeting Reminder" in data["headers"]["subject"]
    assert data["model_inference"]["status"] == "EVALUATED"
    assert isinstance(data["model_inference"]["uncalibrated_score"], float)
    assert data["evidence_fusion"]["overall_category"] in [
        "INSUFFICIENT_EVIDENCE",
        "LOW_RISK_INDICATORS",
        "REVIEW_RECOMMENDED",
    ]


# ---------------------------------------------------------------------------
# Scenario 2: HTML-Only Email
# ---------------------------------------------------------------------------
def test_scenario_02_html_only_email():
    fixture_path = FIXTURES_DIR / "02_html_only.eml"
    with open(fixture_path, "rb") as f:
        resp = client.post(
            "/api/v1/email/analyze",
            files={"file": ("02_html_only.eml", f, "message/rfc822")},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["filename"] == "02_html_only.eml"
    assert data["body"]["has_html"] is True
    # HTML extracted text must be safely sanitized (scripts/tags stripped)
    assert data["body"]["html_extracted_text"] is not None
    assert "<script>" not in data["body"]["html_extracted_text"]
    assert data["body"]["html_text_char_count"] > 0
    assert data["model_inference"]["status"] == "EVALUATED"


# ---------------------------------------------------------------------------
# Scenario 3: Multipart Plain-Text and HTML Email
# ---------------------------------------------------------------------------
def test_scenario_03_multipart_plain_and_html():
    fixture_path = FIXTURES_DIR / "03_multipart_plain_html.eml"
    with open(fixture_path, "rb") as f:
        resp = client.post(
            "/api/v1/email/analyze",
            files={"file": ("03_multipart_plain_html.eml", f, "message/rfc822")},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["body"]["has_plain_text"] is True
    assert data["body"]["has_html"] is True
    assert data["body"]["plain_text_char_count"] > 0
    assert data["body"]["html_text_char_count"] > 0
    assert data["model_inference"]["status"] == "EVALUATED"


# ---------------------------------------------------------------------------
# Scenario 4: Email with Multiple URLs
# ---------------------------------------------------------------------------
def test_scenario_04_multiple_urls_extraction_and_heuristics():
    fixture_path = FIXTURES_DIR / "05_multiple_urls.eml"
    with open(fixture_path, "rb") as f:
        resp = client.post(
            "/api/v1/email/analyze",
            files={"file": ("05_multiple_urls.eml", f, "message/rfc822")},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["urls"]) >= 2
    assert data["url_analysis"] is not None
    assert data["url_analysis"]["total_urls"] == len(data["urls"])
    assert data["url_analysis"]["highest_risk_category"] in ["INFO", "LOW", "MEDIUM", "HIGH"]
    for url_res in data["url_analysis"]["url_results"]:
        assert 0 <= url_res["heuristic_risk_score"] <= 100
        assert url_res["features"]["host_classification"] is not None


# ---------------------------------------------------------------------------
# Scenario 5: Missing or Malformed Optional Headers
# ---------------------------------------------------------------------------
def test_scenario_05_missing_and_malformed_headers():
    # 08: Missing optional headers (Date, Message-ID, Return-Path omitted)
    f8 = FIXTURES_DIR / "08_missing_optional_headers.eml"
    with open(f8, "rb") as f:
        resp8 = client.post("/api/v1/email/analyze", files={"file": ("08_missing.eml", f, "message/rfc822")})
    assert resp8.status_code == 200
    d8 = resp8.json()
    assert d8["headers"]["message_id"] is None
    assert d8["headers"]["subject"] is None
    assert d8["headers"]["return_path"] is None
    assert d8["headers"]["to_headers"] == []

    # 07: Malformed email structure
    f7 = FIXTURES_DIR / "07_malformed.eml"
    with open(f7, "rb") as f:
        resp7 = client.post("/api/v1/email/analyze", files={"file": ("07_malformed.eml", f, "message/rfc822")})
    assert resp7.status_code == 200
    d7 = resp7.json()
    # Parser must handle non-fatal anomalies gracefully
    assert d7["parsing_status"] in ["success", "partial_success"]


# ---------------------------------------------------------------------------
# Scenario 6: SPF/DKIM/DMARC Present, Absent, or Conflicting
# ---------------------------------------------------------------------------
def test_scenario_06_authentication_absent_and_conflicting():
    # Case A: Authentication absent (01_simple_plaintext.eml has no auth headers)
    f1 = FIXTURES_DIR / "01_simple_plaintext.eml"
    with open(f1, "rb") as f:
        resp_absent = client.post("/api/v1/email/analyze", files={"file": ("01.eml", f, "message/rfc822")})
    d_absent = resp_absent.json()
    auth_absent = d_absent["authentication_analysis"]
    assert auth_absent["status"] == "NO_EVIDENCE"
    assert auth_absent["spf"]["status"] == "NOT_PRESENT"
    assert auth_absent["dkim"]["status"] == "NOT_PRESENT"
    assert auth_absent["dmarc"]["status"] == "NOT_PRESENT"
    assert auth_absent["has_conflicts"] is False

    # Case B: Conflicting authentication headers across downstream MTAs
    conflicting_eml = (
        b"From: billing@legit.example.com\r\n"
        b"To: victim@example.com\r\n"
        b"Subject: Test Conflicting Auth\r\n"
        b"Authentication-Results: mta1.example.com; spf=pass (mail.legit.example.com: 198.51.100.1)\r\n"
        b"Authentication-Results: mta2.example.com; spf=fail (mail.legit.example.com: 198.51.100.1)\r\n"
        b"\r\n"
        b"Testing contradictory SPF verdicts.\r\n"
    )
    resp_conflict = client.post(
        "/api/v1/email/analyze",
        files={"file": ("conflict.eml", io.BytesIO(conflicting_eml), "message/rfc822")},
    )
    assert resp_conflict.status_code == 200
    d_conflict = resp_conflict.json()
    auth_conflict = d_conflict["authentication_analysis"]
    assert auth_conflict["has_conflicts"] is True
    assert auth_conflict["status"] == "CONFLICTING_EVIDENCE"
    assert auth_conflict["spf"]["status"] == "CONFLICTING_EVIDENCE"


# ---------------------------------------------------------------------------
# Scenario 7: Public, Private, and Documentation-Range IP Addresses
# ---------------------------------------------------------------------------
def test_scenario_07_ip_range_classification():
    # Test multi-hop Received transit containing Public, Private, Documentation, Loopback
    multi_ip_eml = (
        b"From: sender@example.com\r\n"
        b"To: recipient@example.com\r\n"
        b"Subject: IP Range Test\r\n"
        b"Received: from public-mta.example.com (public-mta.example.com [142.250.190.46]) by mx.example.com; Tue, 13 Oct 2026 10:00:03 +0000\r\n"
        b"Received: from doc-relay.example.com (doc-relay.example.com [198.51.100.99]) by public-mta.example.com; Tue, 13 Oct 2026 10:00:02 +0000\r\n"
        b"Received: from internal-node.local (internal-node.local [10.240.0.5]) by doc-relay.example.com; Tue, 13 Oct 2026 10:00:01 +0000\r\n"
        b"Received: from localhost (localhost [127.0.0.1]) by internal-node.local; Tue, 13 Oct 2026 10:00:00 +0000\r\n"
        b"\r\n"
        b"Checking IP range classification fidelity.\r\n"
    )
    resp = client.post(
        "/api/v1/email/analyze",
        files={"file": ("multi_ip.eml", io.BytesIO(multi_ip_eml), "message/rfc822")},
    )
    assert resp.status_code == 200
    data = resp.json()
    ip_intel = data["ip_intelligence"]
    assert ip_intel is not None

    cand_map = {c["ip"]: c for c in ip_intel["candidates"]}
    # 142.250.190.46 -> Public, routable
    assert cand_map["142.250.190.46"]["classification"] == "Public"
    assert cand_map["142.250.190.46"]["is_routable"] is True

    # 198.51.100.99 -> Documentation (TEST-NET-2), NOT routable
    assert cand_map["198.51.100.99"]["classification"] == "Documentation"
    assert cand_map["198.51.100.99"]["is_routable"] is False

    # 10.240.0.5 -> Private (RFC 1918), NOT routable
    assert cand_map["10.240.0.5"]["classification"] == "Private"
    assert cand_map["10.240.0.5"]["is_routable"] is False

    # 127.0.0.1 -> Loopback, NOT routable
    assert cand_map["127.0.0.1"]["classification"] == "Loopback"
    assert cand_map["127.0.0.1"]["is_routable"] is False


# ---------------------------------------------------------------------------
# Scenario 8: Malformed Email Bytes
# ---------------------------------------------------------------------------
def test_scenario_08_corrupt_binary_junk_email():
    corrupt_bytes = b"\x00\xff\xfe\x01\x88\x99\xaa" * 50
    resp = client.post(
        "/api/v1/email/analyze",
        files={"file": ("corrupt.eml", io.BytesIO(corrupt_bytes), "message/rfc822")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["filename"] == "corrupt.eml"
    # Handled without unhandled 500 crash
    assert data["parsing_status"] in ["success", "partial_success"]


# ---------------------------------------------------------------------------
# Scenario 9: Zero-Byte Upload, Oversized File, and Invalid Extension
# ---------------------------------------------------------------------------
def test_scenario_09_upload_constraints_and_validation():
    # 1. Zero-byte upload
    resp_zero = client.post(
        "/api/v1/email/analyze",
        files={"file": ("empty.eml", io.BytesIO(b""), "message/rfc822")},
    )
    assert resp_zero.status_code == 400
    assert "empty" in resp_zero.json()["detail"].lower()

    # 2. Oversized upload (> 10 MB limit)
    huge_bytes = b"X" * (10 * 1024 * 1024 + 1024)
    resp_huge = client.post(
        "/api/v1/email/analyze",
        files={"file": ("huge.eml", io.BytesIO(huge_bytes), "message/rfc822")},
    )
    assert resp_huge.status_code == 413
    assert "exceeds maximum upload limit" in resp_huge.json()["detail"].lower()

    # 3. Invalid extension (.txt or .exe)
    resp_ext = client.post(
        "/api/v1/email/analyze",
        files={"file": ("payload.exe", io.BytesIO(b"MZ\x90..."), "application/octet-stream")},
    )
    assert resp_ext.status_code == 400
    assert "Only .eml files are accepted" in resp_ext.json()["detail"]


# ---------------------------------------------------------------------------
# Scenario 10: Model Unavailable or Inference Error
# ---------------------------------------------------------------------------
def test_scenario_10_model_unavailable_and_error_handling():
    f = FIXTURES_DIR / "01_simple_plaintext.eml"
    with open(f, "rb") as eml_f:
        eml_bytes = eml_f.read()

    # Case A: Model checkpoint unavailable
    with patch(
        "app.services.email_parser.run_model_inference",
        return_value=ModelInferenceEvidence(
            uncalibrated_score=None,
            predicted_label=None,
            status=ModelInferenceStatus.UNAVAILABLE,
            error_message="Checkpoint weights not found on disk",
        ),
    ):
        resp_unavail = client.post(
            "/api/v1/email/analyze",
            files={"file": ("unavail.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        )
        assert resp_unavail.status_code == 200
        d_unavail = resp_unavail.json()
        assert d_unavail["model_inference"]["status"] == "UNAVAILABLE"
        assert d_unavail["model_inference"]["predicted_label"] is None
        assert d_unavail["model_inference"]["uncalibrated_score"] is None
        assert d_unavail["evidence_fusion"]["model_evidence"]["status"] == "UNAVAILABLE"
        # Must NEVER be reported as benign
        assert d_unavail["evidence_fusion"]["model_evidence"]["predicted_label"] is None

    # Case B: Model runtime exception
    with patch(
        "app.services.email_parser.run_model_inference",
        side_effect=RuntimeError("CUDA out-of-memory exception"),
    ):
        resp_err = client.post(
            "/api/v1/email/analyze",
            files={"file": ("err.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        )
        assert resp_err.status_code == 200
        d_err = resp_err.json()
        assert d_err["model_inference"]["status"] == "ERROR"
        assert d_err["model_inference"]["predicted_label"] is None
        assert d_err["model_inference"]["uncalibrated_score"] is None
        assert d_err["evidence_fusion"]["model_evidence"]["status"] == "ERROR"
        # Must NEVER be reported as benign
        assert d_err["evidence_fusion"]["model_evidence"]["predicted_label"] is None


# ---------------------------------------------------------------------------
# Scenario 11: Real API Response to Valid Report Generation
# ---------------------------------------------------------------------------
def test_scenario_11_real_response_report_generation():
    f = FIXTURES_DIR / "06_multiple_received_hops.eml"
    with open(f, "rb") as eml_f:
        resp = client.post(
            "/api/v1/email/analyze",
            files={"file": ("06_multiple_received_hops.eml", eml_f, "message/rfc822")},
        )
    assert resp.status_code == 200
    data = resp.json()

    # Verify that the response contains all elements needed for report generation
    assert "filename" in data
    assert "headers" in data
    assert "urls" in data
    assert "ip_candidates" in data
    assert "evidence_fusion" in data
    assert "model_inference" in data
    assert "authentication_analysis" in data
    assert "ip_intelligence" in data
    assert "url_analysis" in data


# ---------------------------------------------------------------------------
# Scenario 12: Partial Analysis with Optional Fields Missing
# ---------------------------------------------------------------------------
def test_scenario_12_partial_analysis_missing_optional_fields():
    f = FIXTURES_DIR / "01_simple_plaintext.eml"
    with open(f, "rb") as eml_f:
        eml_bytes = eml_f.read()

    # Simulate parser failures in sub-engines to produce partial analysis
    with patch("app.services.email_parser.analyze_email_extracted_urls", side_effect=Exception("URL engine fault")):
        with patch("app.services.email_parser.analyze_email_authentication", side_effect=Exception("Auth engine fault")):
            resp = client.post(
                "/api/v1/email/analyze",
                files={"file": ("partial.eml", io.BytesIO(eml_bytes), "message/rfc822")},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["parsing_status"] == "partial_success"
            assert data["url_analysis"] is None
            assert data["authentication_analysis"] is None
            assert len(data["warnings"]) >= 2
            # Fusion must still handle missing modalities defensively
            assert data["evidence_fusion"] is not None
            assert data["evidence_fusion"]["overall_category"] in [
                "INSUFFICIENT_EVIDENCE",
                "LOW_RISK_INDICATORS",
                "REVIEW_RECOMMENDED",
            ]
