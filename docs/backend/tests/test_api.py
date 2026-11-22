"""
API Integration tests for PhishIntel backend endpoints (Phase 1).
"""

import io
from pathlib import Path
from fastapi.testclient import TestClient
import pytest

from app.main import app

client = TestClient(app)
FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "PhishIntel"


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "PhishIntel" in data["message"]


def test_upload_valid_eml_fixture():
    fixture_path = FIXTURES_DIR / "01_simple_plaintext.eml"
    with open(fixture_path, "rb") as f:
        response = client.post(
            "/api/v1/email/analyze",
            files={"file": ("01_simple_plaintext.eml", f, "message/rfc822")},
        )
    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "01_simple_plaintext.eml"
    assert data["headers"]["from_header"] == "alice@sender.com"
    assert data["headers"]["subject"] == "Meeting Reminder"
    assert data["body"]["has_plain_text"] is True
    assert "Meeting Reminder" in data["headers"]["subject"]
    assert "parsed_at" in data
    assert data["parsing_status"] == "success"


def test_upload_invalid_extension():
    # Attempting to upload a .txt file
    dummy_txt = io.BytesIO(b"Subject: Test\n\nThis is not an .eml extension.")
    response = client.post(
        "/api/v1/email/analyze",
        files={"file": ("malicious.txt", dummy_txt, "text/plain")},
    )
    assert response.status_code == 400
    data = response.json()
    assert "Only .eml files are accepted" in data["detail"]


def test_upload_empty_file():
    empty_file = io.BytesIO(b"")
    response = client.post(
        "/api/v1/email/analyze",
        files={"file": ("empty.eml", empty_file, "message/rfc822")},
    )
    assert response.status_code == 400
    data = response.json()
    assert "empty" in data["detail"].lower()


def test_upload_oversized_file():
    # 10 MB + 1 KB = 10,486,784 bytes
    oversized_bytes = b"X" * (10 * 1024 * 1024 + 1024)
    oversized_file = io.BytesIO(oversized_bytes)
    response = client.post(
        "/api/v1/email/analyze",
        files={"file": ("huge_sample.eml", oversized_file, "message/rfc822")},
    )
    # Exceeds max upload limit
    assert response.status_code == 413
    data = response.json()
    assert "exceeds maximum upload limit" in data["detail"].lower()


def test_api_received_hops_and_ip_candidates():
    fixture_path = FIXTURES_DIR / "06_multiple_received_hops.eml"
    with open(fixture_path, "rb") as f:
        response = client.post(
            "/api/v1/email/analyze",
            files={"file": ("06_multiple_received_hops.eml", f, "message/rfc822")},
        )
    assert response.status_code == 200
    data = response.json()

    # Check received hops structure
    assert len(data["headers"]["received_headers"]) == 4
    assert len(data["ip_candidates"]) >= 3

    # Check IP candidate properties
    ip_list = [c["ip"] for c in data["ip_candidates"]]
    assert "198.51.100.25" in ip_list
    assert "10.240.0.5" in ip_list
    cand_by_ip = {c["ip"]: c for c in data["ip_candidates"]}
    assert cand_by_ip["198.51.100.25"]["classification"] == "Documentation"
    assert cand_by_ip["198.51.100.25"]["hop_index"] == 0
    assert cand_by_ip["10.240.0.5"]["classification"] == "Private"
    assert cand_by_ip["10.240.0.5"]["hop_index"] == 1
    assert cand_by_ip["127.0.0.1"]["classification"] == "Loopback"
    assert cand_by_ip["127.0.0.1"]["hop_index"] == 2

    for cand in data["ip_candidates"]:
        assert "ip" in cand
        assert "version" in cand
        assert "classification" in cand
        assert "hop_index" in cand
        assert "source_header" in cand


def test_api_attachment_metadata_and_hashes():
    fixture_path = FIXTURES_DIR / "04_attachments.eml"
    with open(fixture_path, "rb") as f:
        response = client.post(
            "/api/v1/email/analyze",
            files={"file": ("04_attachments.eml", f, "message/rfc822")},
        )
    assert response.status_code == 200
    data = response.json()
    assert len(data["attachments"]) == 2

    for att in data["attachments"]:
        assert att["filename"] in ["invoice_october.pdf", "payment_instructions.txt"]
        assert att["size_bytes"] > 0
        assert len(att["sha256"]) == 64
