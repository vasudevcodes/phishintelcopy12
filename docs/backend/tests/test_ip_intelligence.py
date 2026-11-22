"""
Tests for Phase 6A IP Intelligence Engine (PhishIntel).
Covers:
1. Public IPv4 and IPv6
2. Private IPv4 (RFC 1918) and IPv6 Unique Local Addresses (RFC 4193)
3. Loopback and link-local addresses
4. Multicast, reserved, unspecified, and invalid values
5. Provider gateway and internal IP provenance
6. Missing origin IP (no candidates)
7. Geolocation database unavailable
8. Valid local database lookup with mock reader
9. Network isolation (zero DNS or outbound socket calls)
10. Full API integration with URL analysis and authentication evidence
11. Regression tests for existing fixtures
"""

import io
from pathlib import Path
import socket
from unittest.mock import MagicMock
from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.schemas.email import IPCandidate
from app.schemas.ip_intelligence import (
    GeolocationStatus,
    IPClassification,
    IPGeolocationData,
)
from app.services.ip_intelligence import (
    LocalGeoIPReader,
    analyze_candidate_ip,
    analyze_ip_candidates,
    classify_ip_string,
)
from app.services.email_parser import parse_email_message

client = TestClient(app)
FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def guard_no_network(monkeypatch):
    """
    Enforces zero network access during IP intelligence tests.
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


# 1. Public IPv4 and IPv6
def test_public_ipv4_and_ipv6():
    # Public IPv4
    c_v4, obj_v4 = classify_ip_string("8.8.8.8")
    assert c_v4 == IPClassification.PUBLIC
    assert obj_v4 is not None
    assert obj_v4.version == 4

    res_v4 = analyze_candidate_ip("8.8.8.8", hop_index=0)
    assert res_v4.classification == IPClassification.PUBLIC
    assert res_v4.is_routable is True
    assert res_v4.version == 4

    # Public IPv6
    c_v6, obj_v6 = classify_ip_string("2607:f8b0:4005:805::200e")
    assert c_v6 == IPClassification.PUBLIC
    assert obj_v6 is not None
    assert obj_v6.version == 6

    res_v6 = analyze_candidate_ip("2607:f8b0:4005:805::200e", hop_index=1)
    assert res_v6.classification == IPClassification.PUBLIC
    assert res_v6.is_routable is True
    assert res_v6.version == 6


# 2. Private IPv4 and IPv6 ULA
def test_private_ipv4_and_ipv6_unique_local():
    # RFC 1918 ranges
    for ip in ["10.0.1.5", "172.16.20.1", "192.168.1.254"]:
        c, obj = classify_ip_string(ip)
        assert c == IPClassification.PRIVATE
        assert obj is not None
        assert obj.version == 4
        res = analyze_candidate_ip(ip)
        assert res.classification == IPClassification.PRIVATE
        assert res.is_routable is False
        assert res.geolocation_status == GeolocationStatus.NOT_ROUTABLE

    # RFC 4193 Unique Local IPv6 (fc00::/7)
    c_ula, obj_ula = classify_ip_string("fd12:3456:789a:1::1")
    assert c_ula == IPClassification.PRIVATE
    assert obj_ula is not None
    assert obj_ula.version == 6
    res_ula = analyze_candidate_ip("fd12:3456:789a:1::1")
    assert res_ula.classification == IPClassification.PRIVATE
    assert res_ula.is_routable is False


# 3. Loopback and Link-Local
def test_loopback_and_link_local():
    # Loopback
    c_lb4, _ = classify_ip_string("127.0.0.1")
    assert c_lb4 == IPClassification.LOOPBACK
    c_lb6, _ = classify_ip_string("::1")
    assert c_lb6 == IPClassification.LOOPBACK

    # Link-Local
    c_ll4, _ = classify_ip_string("169.254.10.20")
    assert c_ll4 == IPClassification.LINK_LOCAL
    c_ll6, _ = classify_ip_string("fe80::1")
    assert c_ll6 == IPClassification.LINK_LOCAL


# 4. Multicast, Reserved, Unspecified, and Invalid
def test_multicast_reserved_unspecified_and_invalid():
    # Multicast
    c_mc4, _ = classify_ip_string("224.0.0.1")
    assert c_mc4 == IPClassification.MULTICAST
    c_mc6, _ = classify_ip_string("ff02::1")
    assert c_mc6 == IPClassification.MULTICAST

    # Reserved
    c_res, _ = classify_ip_string("240.0.0.1")
    assert c_res == IPClassification.RESERVED

    # Unspecified
    c_uns4, _ = classify_ip_string("0.0.0.0")
    assert c_uns4 == IPClassification.UNSPECIFIED
    c_uns6, _ = classify_ip_string("::")
    assert c_uns6 == IPClassification.UNSPECIFIED

    # Invalid
    c_inv, obj_inv = classify_ip_string("999.999.999.999")
    assert c_inv == IPClassification.INVALID
    assert obj_inv is None
    res_inv = analyze_candidate_ip("not-an-ip")
    assert res_inv.classification == IPClassification.INVALID
    assert res_inv.is_routable is False


# 5. Documentation Addresses (RFC 5737 and RFC 3849)
def test_documentation_addresses():
    for doc_ip in ["192.0.2.1", "198.51.100.1", "203.0.113.1", "2001:db8::1"]:
        c, _ = classify_ip_string(doc_ip)
        assert c == IPClassification.DOCUMENTATION


# 6. Provider Gateway and Internal IP Provenance
def test_provider_gateway_and_internal_provenance():
    candidates = [
        IPCandidate(
            ip="198.51.100.25",
            version=4,
            classification="Documentation",
            hop_index=0,
            source_header="Received: from mail.relay by mx.google.com",
        ),
        IPCandidate(
            ip="10.240.0.5",
            version=4,
            classification="Private",
            hop_index=1,
            source_header="Received: from internal by mail.relay",
        ),
        IPCandidate(
            ip="127.0.0.1",
            version=4,
            classification="Loopback",
            hop_index=2,
            source_header="Received: from app-srv ([127.0.0.1])",
        ),
    ]

    result = analyze_ip_candidates(candidates)
    assert result.total_candidates == 3
    assert result.private_count == 1
    assert result.other_count == 2  # Documentation + Loopback

    # Origin candidate is highest hop index (Hop 2: 127.0.0.1)
    assert result.origin_candidate is not None
    assert result.origin_candidate.hop_index == 2
    assert result.origin_candidate.ip == "127.0.0.1"
    assert result.origin_candidate.classification == IPClassification.LOOPBACK
    assert "Loopback" in result.origin_assessment


# 7. Missing Origin IP / Empty Candidates
def test_missing_origin_ip_empty():
    result = analyze_ip_candidates([])
    assert result.total_candidates == 0
    assert result.candidates == []
    assert result.origin_candidate is None
    assert "No IP candidates" in result.origin_assessment


# 8. Geolocation Database Unavailable (Default State)
def test_geolocation_database_unavailable():
    # Public IP evaluated without configured database
    cand = IPCandidate(
        ip="93.184.216.34",
        version=4,
        classification="Public",
        hop_index=0,
        source_header="Received: by edge.mta",
    )
    result = analyze_ip_candidates([cand])
    assert result.database_available is False
    c_intel = result.candidates[0]
    assert c_intel.is_routable is True
    assert c_intel.geolocation_status == GeolocationStatus.DATABASE_UNAVAILABLE
    assert c_intel.geolocation is None


# 9. Valid Local Database Lookup (Mocked GeoIP Reader)
def test_valid_local_database_lookup_mocked():
    mock_reader = MagicMock(spec=LocalGeoIPReader)
    mock_reader.is_available.return_value = True

    mock_geo = IPGeolocationData(
        country_name="United States",
        country_code="US",
        city_name="Norwell",
        latitude=42.1596,
        longitude=-70.8217,
        asn=15133,
        as_org="EDGECAST",
    )
    mock_reader.lookup.return_value = (GeolocationStatus.LOOKUP_SUCCESS, mock_geo)

    cand = IPCandidate(
        ip="93.184.216.34",
        version=4,
        classification="Public",
        hop_index=0,
        source_header="Received: by edge",
    )
    result = analyze_ip_candidates([cand], geoip_reader=mock_reader)
    assert result.database_available is True
    c_intel = result.candidates[0]
    assert c_intel.geolocation_status == GeolocationStatus.LOOKUP_SUCCESS
    assert c_intel.geolocation is not None
    assert c_intel.geolocation.country_name == "United States"
    assert c_intel.geolocation.country_code == "US"
    assert c_intel.geolocation.city_name == "Norwell"
    assert c_intel.geolocation.asn == 15133


# 10. API Integration: URL, Authentication, and IP Intelligence Combined
def test_api_integration_all_engines():
    eml_complete = (
        b"Received: from mail.sender.example (mail.sender.example [198.51.100.25])\n"
        b" by mx.receiver.example with ESMTPS id 12345;\n"
        b" Mon, 12 Oct 2026 10:00:00 +0000\n"
        b"Authentication-Results: mx.receiver.example; spf=pass smtp.mailfrom=sender.example; dkim=pass header.d=sender.example\n"
        b"From: Billing <billing@sender.example>\n"
        b"To: Client <client@receiver.example>\n"
        b"Subject: Invoice #888\n"
        b"Content-Type: text/html\n\n"
        b'<p>View invoice: <a href="https://billing.sender.example/invoice/888">Click Here</a></p>\n'
    )
    response = client.post(
        "/api/v1/email/analyze",
        files={"file": ("complete.eml", io.BytesIO(eml_complete), "message/rfc822")},
    )
    assert response.status_code == 200
    data = response.json()

    # 1. Phase 1 Parser fields
    assert data["filename"] == "complete.eml"
    assert len(data["headers"]["received_headers"]) == 1
    assert len(data["ip_candidates"]) == 1

    # 2. Phase 4B URL Intelligence
    assert "url_analysis" in data
    assert data["url_analysis"] is not None
    assert data["url_analysis"]["total_urls"] == 1

    # 3. Phase 5A Authentication Analysis
    assert "authentication_analysis" in data
    assert data["authentication_analysis"] is not None
    assert data["authentication_analysis"]["spf"]["status"] == "PASS"
    assert data["authentication_analysis"]["dkim"]["status"] == "PASS"

    # 4. Phase 6A IP Intelligence
    assert "ip_intelligence" in data
    assert data["ip_intelligence"] is not None
    ip_intel = data["ip_intelligence"]
    assert ip_intel["total_candidates"] == 1
    assert ip_intel["candidates"][0]["ip"] == "198.51.100.25"
    assert ip_intel["candidates"][0]["classification"] == "Documentation"
    assert ip_intel["origin_candidate"] is not None


# 11. Regression Test: Multi-Hop Fixture 06
def test_regression_multi_hop_fixture():
    fixture_path = FIXTURES_DIR / "06_multiple_received_hops.eml"
    with open(fixture_path, "rb") as f:
        response = client.post(
            "/api/v1/email/analyze",
            files={"file": ("06_multiple_received_hops.eml", f, "message/rfc822")},
        )
    assert response.status_code == 200
    data = response.json()

    assert "ip_intelligence" in data
    ip_intel = data["ip_intelligence"]
    assert ip_intel["total_candidates"] >= 3
    # Check that candidate IPs from the 4 hops are present
    ips = [c["ip"] for c in ip_intel["candidates"]]
    assert "198.51.100.25" in ips
    assert "10.240.0.5" in ips
    assert "127.0.0.1" in ips

    # Check origin hop identification
    origin = ip_intel["origin_candidate"]
    assert origin is not None
    # Highest hop is hop 3 (IPv6 origin or hop 2 loopback)
    assert origin["hop_index"] >= 2


# ==============================================================================
# Phase 10B Regression Tests: Origin Attribution Remediation
# ==============================================================================

# 12. Google Shared MTA with No Client IP in Earlier Hop (Nazario Defect Pattern)
def test_origin_attribution_google_shared_mta_missing_client_ip():
    """
    Verifies that when an email passes through Google Workspace outbound infrastructure
    and earlier upstream transit hops lack usable IP literals, the boundary Google MTA
    is NOT falsely attributed as the sender's origin IP.
    """
    raw_headers = [
        "Received: from mail-pj1-f41.google.com (mail-pj1-f41.google.com [209.85.216.41]) by mx.receiver.example with ESMTPS;",
        "Received: by mail-pj1-f41.google.com with SMTP id abc123xyz for <target@example.com>;",
    ]
    cand = IPCandidate(
        ip="209.85.216.41",
        version=4,
        classification="Public",
        hop_index=0,
        source_header=raw_headers[0],
    )
    result = analyze_ip_candidates(
        [cand],
        total_received_headers=len(raw_headers),
        raw_received_headers=raw_headers,
    )

    # 1. Extraction and subnet classification are preserved
    assert result.total_candidates == 1
    assert result.candidates[0].ip == "209.85.216.41"
    assert result.candidates[0].classification == IPClassification.PUBLIC
    assert "Provider" in result.candidates[0].role_hint
    assert "Google Mail / Workspace" in result.candidates[0].role_hint

    # 2. Origin candidate is conservatively marked UNAVAILABLE (None)
    assert result.origin_candidate is None
    assert "Originating IP is UNAVAILABLE" in result.origin_assessment
    assert "Google Mail / Workspace" in result.origin_assessment
    assert any("earlier Received transit hop" in w for w in result.warnings)


# 13. SendGrid Shared MTA with No Client IP in Earlier Hop
def test_origin_attribution_sendgrid_shared_mta_missing_client_ip():
    """
    Verifies that SendGrid outbound shared relays are identified as provider gateways
    and not misattributed as client origin when earlier hops have no extractable IPs.
    """
    raw_headers = [
        "Received: from o1.outbound-mail.sendgrid.net (o1.outbound-mail.sendgrid.net [167.89.77.213]) by mx.receiver.example with ESMTPS;",
        "Received: by filter-internal.relay with SMTP id sg99;",
        "Received: by api.sendgrid.net with HTTP; Wed, 14 Feb 2026 12:00:00 +0000",
    ]
    cand = IPCandidate(
        ip="167.89.77.213",
        version=4,
        classification="Public",
        hop_index=0,
        source_header=raw_headers[0],
    )
    result = analyze_ip_candidates(
        [cand],
        total_received_headers=len(raw_headers),
        raw_received_headers=raw_headers,
    )

    assert result.total_candidates == 1
    assert result.candidates[0].classification == IPClassification.PUBLIC
    assert "SendGrid" in result.candidates[0].role_hint
    assert result.origin_candidate is None
    assert "Originating IP is UNAVAILABLE" in result.origin_assessment
    assert "SendGrid" in result.origin_assessment


# 14. Genuine Public IP in an Earlier Usable Hop
def test_origin_attribution_genuine_public_ip_earliest_hop():
    """
    Verifies that when a public IP is present at the earliest recorded hop,
    it is attributed as EXTRACTED_PUBLIC with unverified provenance caveat.
    """
    raw_headers = [
        "Received: from perimeter.isp.net ([198.51.100.10]) by mx.receiver.example with ESMTPS;",
        "Received: from client.egress.org ([93.184.216.34]) by perimeter.isp.net with ESMTP;",
    ]
    cands = [
        IPCandidate(ip="198.51.100.10", version=4, classification="Documentation", hop_index=0, source_header=raw_headers[0]),
        IPCandidate(ip="93.184.216.34", version=4, classification="Public", hop_index=1, source_header=raw_headers[1]),
    ]
    result = analyze_ip_candidates(
        cands,
        total_received_headers=len(raw_headers),
        raw_received_headers=raw_headers,
    )

    assert result.total_candidates == 2
    assert result.origin_candidate is not None
    assert result.origin_candidate.ip == "93.184.216.34"
    assert result.origin_candidate.hop_index == 1
    assert result.origin_candidate.classification == IPClassification.PUBLIC
    assert "EXTRACTED_PUBLIC" in result.origin_assessment
    assert "forged or manipulated" in result.origin_assessment


# 15. Private IP in an Earlier Hop
def test_origin_attribution_private_ip_earliest_hop():
    """
    Verifies that RFC 1918 private IPs at the earliest hop are classified as INTERNAL_PRIVATE,
    origin is reported UNAVAILABLE, and the earliest public ingress candidate in the chain is noted.
    """
    raw_headers = [
        "Received: from edge.mta ([93.184.216.34]) by mx.receiver.example;",
        "Received: from workstation-10 ([10.50.1.20]) by edge.mta;",
    ]
    cands = [
        IPCandidate(ip="93.184.216.34", version=4, classification="Public", hop_index=0, source_header=raw_headers[0]),
        IPCandidate(ip="10.50.1.20", version=4, classification="Private", hop_index=1, source_header=raw_headers[1]),
    ]
    result = analyze_ip_candidates(
        cands,
        total_received_headers=len(raw_headers),
        raw_received_headers=raw_headers,
    )

    assert result.origin_candidate is not None
    assert result.origin_candidate.ip == "10.50.1.20"
    assert result.origin_candidate.classification == IPClassification.PRIVATE
    assert "INTERNAL_PRIVATE" in result.origin_assessment
    assert "UNAVAILABLE" in result.origin_assessment
    assert "93.184.216.34" in result.origin_assessment


# 16. Loopback and Link-Local Addresses at Earliest Hop (No Local Submission Inference)
def test_origin_attribution_loopback_and_link_local():
    """
    Verifies appropriate handling for loopback (127.0.0.1) and link-local (169.254.x.x).
    Crucially does NOT infer direct local sender submission merely from the address type.
    Reports origin as UNAVAILABLE while preserving the evidence.
    """
    # Loopback
    cand_loopback = IPCandidate(ip="127.0.0.1", version=4, classification="Loopback", hop_index=0, source_header="Received: from localhost ([127.0.0.1])")
    res_lb = analyze_ip_candidates([cand_loopback], total_received_headers=1)
    assert res_lb.origin_candidate is not None
    assert res_lb.origin_candidate.classification == IPClassification.LOOPBACK
    assert "Loopback" in res_lb.origin_assessment
    assert "UNAVAILABLE" in res_lb.origin_assessment
    # Verify no ungrounded inference of direct local submission
    assert "indicating direct local submission" not in res_lb.origin_assessment

    # Link-Local
    cand_ll = IPCandidate(ip="169.254.100.5", version=4, classification="Link-Local", hop_index=0, source_header="Received: from host ([169.254.100.5])")
    res_ll = analyze_ip_candidates([cand_ll], total_received_headers=1)
    assert res_ll.origin_candidate is not None
    assert res_ll.origin_candidate.classification == IPClassification.LINK_LOCAL
    assert "Link-Local" in res_ll.origin_assessment
    assert "UNAVAILABLE" in res_ll.origin_assessment


# 17. Multiple Received Headers with Different IP Candidates
def test_origin_attribution_multiple_hops_distinct_candidates():
    """
    Verifies that in a multi-hop chain with multiple public and private IPs,
    the highest hop candidate is selected, preserving all candidates for forensic inspection.
    """
    raw_headers = [
        "Received: from mta1.example.com ([198.51.100.1]) by mx.receiver.com;",
        "Received: from relay2.example.com ([198.51.100.2]) by mta1.example.com;",
        "Received: from client.egress.org ([93.184.216.34]) by relay2.example.com;",
    ]
    cands = [
        IPCandidate(ip="198.51.100.1", version=4, classification="Documentation", hop_index=0, source_header=raw_headers[0]),
        IPCandidate(ip="198.51.100.2", version=4, classification="Documentation", hop_index=1, source_header=raw_headers[1]),
        IPCandidate(ip="93.184.216.34", version=4, classification="Public", hop_index=2, source_header=raw_headers[2]),
    ]
    result = analyze_ip_candidates(cands, total_received_headers=len(raw_headers))

    assert result.total_candidates == 3
    assert result.origin_candidate is not None
    assert result.origin_candidate.ip == "93.184.216.34"
    assert result.origin_candidate.hop_index == 2
    # Verify all candidates are retained
    assert len(result.candidates) == 3


# 18. Missing or Malformed Received Headers
def test_origin_attribution_missing_or_malformed():
    """
    Verifies conservative handling when no Received headers or no valid IPs exist.
    """
    res_empty = analyze_ip_candidates([], total_received_headers=0)
    assert res_empty.origin_candidate is None
    assert "UNAVAILABLE" in res_empty.origin_assessment
    assert res_empty.total_candidates == 0

    res_missing_ips = analyze_ip_candidates([], total_received_headers=2)
    assert res_missing_ips.origin_candidate is None
    assert "UNAVAILABLE" in res_missing_ips.origin_assessment


# 19. Forged / Untrusted Upstream Received Headers Provenance Caveat
def test_origin_attribution_untrusted_upstream_caveat():
    """
    Verifies that when an IP is attributed from an upstream hop (hop_index > 0),
    an explicit warning regarding unverified provenance and potential forgery is attached.
    """
    raw_headers = [
        "Received: from edge.mta ([198.51.100.1]) by mx.receiver.com;",
        "Received: from suspicious.upstream ([203.0.113.99]) by edge.mta;",
    ]
    cands = [
        IPCandidate(ip="198.51.100.1", version=4, classification="Documentation", hop_index=0, source_header=raw_headers[0]),
        IPCandidate(ip="203.0.113.99", version=4, classification="Documentation", hop_index=1, source_header=raw_headers[1]),
    ]
    result = analyze_ip_candidates(cands, total_received_headers=len(raw_headers))

    assert result.origin_candidate is not None
    assert result.origin_candidate.hop_index == 1
    assert any("upstream Received header" in w for w in result.warnings)
    assert any("provenance cannot be independently verified" in w for w in result.warnings)


# 20. End-to-End API Integration with Nazario Google Pattern
def test_e2e_api_provider_gateway_nazario_pattern():
    """
    Verifies that an email matching the Nazario Google delivery pattern
    returns origin_candidate=None and UNAVAILABLE via the full HTTP API.
    """
    eml_content = (
        b"Received: from mail-pj1-f41.google.com (mail-pj1-f41.google.com [209.85.216.41])\n"
        b" by mx.receiver.example with ESMTPS id 12345;\n"
        b" Mon, 12 Oct 2026 10:00:00 +0000\n"
        b"Received: by mail-pj1-f41.google.com with SMTP id abc123def;\n"
        b" Mon, 12 Oct 2026 09:59:58 +0000\n"
        b"From: Service <service@google.internal>\n"
        b"To: User <user@example.com>\n"
        b"Subject: Security Notification\n"
        b"Content-Type: text/plain; charset=utf-8\n\n"
        b"Please review your account settings.\n"
    )
    response = client.post(
        "/api/v1/email/analyze",
        files={"file": ("nazario_google.eml", io.BytesIO(eml_content), "message/rfc822")},
    )
    assert response.status_code == 200
    data = response.json()

    assert "ip_intelligence" in data
    ip_intel = data["ip_intelligence"]
    assert ip_intel["total_candidates"] == 1
    assert ip_intel["candidates"][0]["ip"] == "209.85.216.41"
    assert ip_intel["candidates"][0]["classification"] == "Public"
    assert "Provider" in ip_intel["candidates"][0]["role_hint"]

    # Origin candidate must be None and assessment UNAVAILABLE
    assert ip_intel["origin_candidate"] is None
    assert "UNAVAILABLE" in ip_intel["origin_assessment"]
    assert "Google Mail / Workspace" in ip_intel["origin_assessment"]


# 21. Specific Review Test: Provider CIDR Match with Unrelated Hostname
def test_provider_cidr_match_with_unrelated_hostname():
    """
    Verifies that an IP within a known provider CIDR (e.g., 209.85.216.41 in Google)
    is identified as likely shared provider infrastructure even if the Received header
    contains an unrelated, deceptive, or attacker-chosen hostname.
    """
    raw_headers = [
        "Received: from evil.phishing.attacker.com ([209.85.216.41]) by mx.victim.example with ESMTP;",
        "Received: by upstream.hidden.mta; Wed, 14 Feb 2026 10:00:00 +0000",
    ]
    cand = IPCandidate(
        ip="209.85.216.41",
        version=4,
        classification="Public",
        hop_index=0,
        source_header=raw_headers[0],
    )
    result = analyze_ip_candidates(
        [cand],
        total_received_headers=len(raw_headers),
        raw_received_headers=raw_headers,
    )
    # CIDR match succeeds regardless of hostname
    assert "Google Mail / Workspace" in result.candidates[0].role_hint
    assert result.origin_candidate is None
    assert "UNAVAILABLE" in result.origin_assessment


# 22. Specific Review Test: Provider Hostname Pattern with Untrusted Upstream Header
def test_provider_hostname_pattern_with_untrusted_upstream_header():
    """
    Verifies that when an upstream pre-boundary header claims a provider hostname
    with an untrusted IP, the system identifies the hostname pattern as likely shared
    provider infrastructure, does not attribute it as client origin, and reports UNAVAILABLE.
    """
    raw_headers = [
        "Received: from edge.receiver.com ([198.51.100.1]) by mx.local with ESMTPS;",
        "Received: from mail-pj1-f41.google.com ([192.0.2.77]) by edge.receiver.com with ESMTP;",
    ]
    cands = [
        IPCandidate(ip="198.51.100.1", version=4, classification="Documentation", hop_index=0, source_header=raw_headers[0]),
        IPCandidate(ip="192.0.2.77", version=4, classification="Documentation", hop_index=1, source_header=raw_headers[1]),
    ]
    result = analyze_ip_candidates(cands, total_received_headers=len(raw_headers))
    # Provider pattern was recognized in candidate 1
    assert "Google Mail / Workspace" in result.candidates[1].role_hint
    # Earliest hop matches provider infrastructure -> origin is safely marked UNAVAILABLE
    assert result.origin_candidate is None
    assert "UNAVAILABLE" in result.origin_assessment
    assert "Google Mail / Workspace" in result.origin_assessment
    assert any("earliest recorded hop matches likely shared provider infrastructure" in w for w in result.warnings)


# 23. Specific Review Test: Attacker-Controlled Upstream Received Header
def test_attacker_controlled_upstream_received_header():
    """
    Verifies that an attacker-injected Received header pretending to originate
    from an authoritative banking relay is not blindly trusted.
    """
    raw_headers = [
        "Received: from perimeter.corp ([198.51.100.1]) by mx.corp.com;",
        "Received: from secure.bank.example ([93.184.216.34]) by fake.upstream.relay.net with ESMTP;",
    ]
    cands = [
        IPCandidate(ip="198.51.100.1", version=4, classification="Documentation", hop_index=0, source_header=raw_headers[0]),
        IPCandidate(ip="93.184.216.34", version=4, classification="Public", hop_index=1, source_header=raw_headers[1]),
    ]
    result = analyze_ip_candidates(cands, total_received_headers=len(raw_headers))
    assert result.origin_candidate is not None
    assert result.origin_candidate.ip == "93.184.216.34"
    assert "EXTRACTED_PUBLIC" in result.origin_assessment
    assert "forged or manipulated" in result.origin_assessment
    assert any("provenance cannot be independently verified" in w for w in result.warnings)


# 24. Specific Review Test: Public IP Candidate with Unknown Provenance
def test_public_ip_candidate_unknown_provenance():
    """
    Verifies that a public IP candidate extracted without independent cryptographic
    provenance is described as an apparent network egress candidate with unverified provenance,
    not as verified origin proof.
    """
    raw_headers = [
        "Received: from egress.mailer.com ([203.0.113.88]) by mx.example.com;",
    ]
    cand = IPCandidate(
        ip="203.0.113.88",
        version=4,
        classification="Documentation",
        hop_index=0,
        source_header=raw_headers[0],
    )
    result = analyze_ip_candidates([cand], total_received_headers=1)
    assert result.origin_candidate is not None
    assert result.origin_candidate.ip == "203.0.113.88"
    assert "Documentation" in result.origin_assessment


# 25. Specific Review Test: Missing Earlier-Hop IP Evidence (Non-Provider Relay)
def test_missing_earlier_hop_ip_evidence_generic():
    """
    Verifies that when a generic non-provider relay is at Hop 0, and an upstream Hop 1
    contains no IP literal, Hop 0 is NOT falsely attributed as the sender origin.
    """
    raw_headers = [
        "Received: from relay.partner.com ([198.51.100.50]) by mx.receiver.com with ESMTP;",
        "Received: by internal-routing-daemon with ID 999 id abc-xyz;",
    ]
    cand = IPCandidate(
        ip="198.51.100.50",
        version=4,
        classification="Documentation",
        hop_index=0,
        source_header=raw_headers[0],
    )
    result = analyze_ip_candidates(
        [cand],
        total_received_headers=len(raw_headers),
        raw_received_headers=raw_headers,
    )
    assert result.origin_candidate is None
    assert "Originating IP is UNAVAILABLE" in result.origin_assessment
    assert "Earlier transit hop(s)" in result.origin_assessment
    assert any("earliest recorded transit hop" in w for w in result.warnings)


# ==============================================================================
# Phase 10B Regression Tests
# ==============================================================================

# Test 1: Public routable provider candidate with unavailable origin
def test_phase10b_public_routable_provider_candidate_unavailable_origin():
    """
    Test 1: Public routable provider candidate with unavailable origin.
    Verifies that for a public Google gateway candidate at Hop 0 where earlier hops lack IPs:
    - origin_candidate is None
    - origin_attribution_status == "UNAVAILABLE"
    - candidate_ip_classification == "Public"
    - is_candidate_routable is True
    - provider_infrastructure_match == "Likely Google infrastructure"
    - sender_identity_status == "Not established"
    """
    raw_headers = [
        "Received: from mail-pj1-f41.google.com (mail-pj1-f41.google.com [209.85.216.41]) by mx.receiver.example with ESMTPS;",
        "Received: by mail-pj1-f41.google.com with SMTP id abc123xyz for <target@example.com>;",
    ]
    cand = IPCandidate(
        ip="209.85.216.41",
        version=4,
        classification="Public",
        hop_index=0,
        source_header=raw_headers[0],
    )
    result = analyze_ip_candidates(
        [cand],
        total_received_headers=len(raw_headers),
        raw_received_headers=raw_headers,
    )
    assert result.origin_candidate is None
    assert result.origin_attribution_status == "UNAVAILABLE"
    assert result.candidate_ip_classification == "Public"
    assert result.is_candidate_routable is True
    assert result.provider_infrastructure_match == "Likely Google infrastructure"
    assert result.sender_identity_status == "Not established"
    assert "Google Mail / Workspace" in result.candidates[0].role_hint
    assert result.candidates[0].provider_match_category == "Confirmed Email-Delivery Network Range"
    assert result.candidates[0].provider_confidence == "High (Confirmed Mail Range)"
    assert result.candidates[0].provider_source_url == "https://support.google.com/a/answer/60764"


# Test 2: Spoofed provider hostname in an untrusted upstream header
def test_phase10b_spoofed_provider_hostname_in_untrusted_upstream_header():
    """
    Test 2: Spoofed provider hostname in an untrusted upstream header.
    Verifies that a hostname matching Google/SendGrid in an attacker-controlled
    upstream header (hop_index > 0) with a non-provider IP:
    - does NOT establish trusted provider identity
    - sets provider_match_category to 'Unverified Upstream Hostname Indicator (Untrusted)'
    - sets provider_confidence to 'UNKNOWN'
    - retains conservative UNAVAILABLE sender-origin behavior (origin_candidate is None)
    - sets sender_identity_status to 'Not established (Untrusted upstream hostname)'
    """
    raw_headers = [
        "Received: from perimeter.isp.net ([198.51.100.1]) by mx.receiver.example with ESMTPS;",
        "Received: from mail-pj1-f41.google.com ([192.0.2.99]) by perimeter.isp.net with ESMTP;",
    ]
    cands = [
        IPCandidate(ip="198.51.100.1", version=4, classification="Documentation", hop_index=0, source_header=raw_headers[0]),
        IPCandidate(ip="192.0.2.99", version=4, classification="Documentation", hop_index=1, source_header=raw_headers[1]),
    ]
    result = analyze_ip_candidates(cands, total_received_headers=len(raw_headers))
    cand_1 = result.candidates[1]
    assert cand_1.provider_match_category == "Unverified Upstream Hostname Indicator (Untrusted)"
    assert cand_1.provider_confidence == "UNKNOWN"
    assert cand_1.provider_indicator is not None
    assert "Unverified Google Mail / Workspace hostname indicator" in cand_1.provider_indicator

    # Origin attribution is conservatively UNAVAILABLE
    assert result.origin_candidate is None
    assert result.origin_attribution_status == "UNAVAILABLE"
    assert result.sender_identity_status == "Not established (Untrusted upstream hostname)"
    assert any("upstream header cannot establish trusted provider identity" in w for w in result.warnings)


# Test 3: Broad provider-owned CIDR without confirmed mail-service provenance
def test_phase10b_broad_provider_owned_cidr_without_confirmed_mail_provenance():
    """
    Test 3: Broad provider-owned CIDR without confirmed mail-service provenance.
    Verifies that IPs in broad general cloud netblocks or historical retired SPF ranges
    (e.g., Google 142.250.0.0/15 or historical 64.233.160.0/19):
    - are categorized as 'General Provider-Owned Network Range'
    - have downgraded confidence 'Low (Broad Provider Range)'
    - are NOT presented as confirmed email-delivery ranges
    """
    # 1. Broad Google Cloud datacenter range (goog.json)
    c_intel_google = analyze_candidate_ip("142.250.180.1", hop_index=0)
    assert c_intel_google.provider_match_category == "General Provider-Owned Network Range"
    assert c_intel_google.provider_confidence == "Low (Broad Provider Range)"
    assert c_intel_google.provider_source_url == "https://www.gstatic.com/ipranges/goog.json"
    assert c_intel_google.provider_indicator is not None
    assert "unconfirmed mail provenance" in c_intel_google.provider_indicator

    # 2. Historical retired Google SPF netblock
    c_intel_hist_google = analyze_candidate_ip("64.233.160.1", hop_index=0)
    assert c_intel_hist_google.provider_match_category == "General Provider-Owned Network Range"
    assert c_intel_hist_google.provider_confidence == "Low (Broad Provider Range)"
    assert c_intel_hist_google.provider_indicator is not None
    assert "unconfirmed mail provenance" in c_intel_hist_google.provider_indicator

    # 3. Google IPv6: broad ARIN allocation outside current /36 SPF netblock
    c_intel_hist_v6 = analyze_candidate_ip("2607:f8b0:1000::1", hop_index=0)
    assert c_intel_hist_v6.provider_match_category == "General Provider-Owned Network Range"
    assert c_intel_hist_v6.provider_confidence == "Low (Broad Provider Range)"
    assert c_intel_hist_v6.provider_indicator is not None
    assert "unconfirmed mail provenance" in c_intel_hist_v6.provider_indicator


# Test 3B: Microsoft 365 52.100.0.0/14 Exchange Online Mail Protection Verification
def test_phase10b_m365_exchange_online_mail_protection_reclassification():
    """
    Verifies that 52.100.0.0/14 is correctly classified as a documented Exchange Online
    mail-protection range from M365 Endpoint IDs 9 & 10 with High confidence.
    """
    c_intel_m365 = analyze_candidate_ip("52.100.50.1", hop_index=0)
    assert c_intel_m365.provider_match_category == "Confirmed Email-Delivery Network Range"
    assert c_intel_m365.provider_confidence == "High (Confirmed Mail Range)"
    assert c_intel_m365.provider_source_url is not None
    assert "learn.microsoft.com" in c_intel_m365.provider_source_url
    assert c_intel_m365.provider_indicator is not None
    assert "Exchange" in c_intel_m365.provider_indicator


# Test 3C: SendGrid 167.89.0.0/17 Precision Verification (Not Broadened to /16)
def test_phase10b_sendgrid_cidr_precision_17_not_16():
    """
    Verifies SendGrid CIDR precision:
    - 167.89.77.213 (in 167.89.0.0/17) matches SendGrid confirmed mail range
    - 167.89.200.1 (outside 167.89.0.0/17, would match /16) is NOT classified as SendGrid confirmed mail range
    """
    # Inside documented /17
    c_sg_in = analyze_candidate_ip("167.89.77.213", hop_index=0)
    assert c_sg_in.provider_match_category == "Confirmed Email-Delivery Network Range"
    assert c_sg_in.provider_confidence == "High (Confirmed Mail Range)"
    assert c_sg_in.provider_indicator == "Likely SendGrid infrastructure"

    # Outside documented /17 (in upper half 167.89.128.0/17)
    c_sg_out = analyze_candidate_ip("167.89.200.1", hop_index=0)
    assert c_sg_out.provider_match_category is None
    assert c_sg_out.provider_indicator is None


# Test 3D: Google Workspace Current SPF Netblocks Verification (IPv4 & IPv6)
def test_phase10b_google_workspace_current_spf_netblocks_verification():
    """
    Verifies that current SPF netblocks in _netblocks.google.com and _netblocks2.google.com
    match as Confirmed Email-Delivery Network Ranges with High confidence:
    - 209.85.128.0/17 (IPv4)
    - 74.125.0.0/16 (IPv4)
    - 2607:f8b0:4000::/36 (IPv6)
    """
    c_v4 = analyze_candidate_ip("209.85.216.41", hop_index=0)
    assert c_v4.provider_match_category == "Confirmed Email-Delivery Network Range"
    assert c_v4.provider_confidence == "High (Confirmed Mail Range)"

    c_v6 = analyze_candidate_ip("2607:f8b0:4000::1", hop_index=0)
    assert c_v6.provider_match_category == "Confirmed Email-Delivery Network Range"
    assert c_v6.provider_confidence == "High (Confirmed Mail Range)"


# Test 4: Non-routable evidence retained with unavailable sender attribution
def test_phase10b_non_routable_evidence_retained_with_unavailable_sender_attribution():
    """
    Test 4: Non-routable evidence retained with unavailable sender attribution.
    Verifies that for private (10.0.0.1), loopback (127.0.0.1), and link-local (169.254.1.1):
    - candidate evidence is retained in origin_candidate
    - origin_attribution_status == "UNAVAILABLE"
    - candidate_ip_classification preserves the true type ('Private', 'Loopback', 'Link-Local')
    - is_candidate_routable is False
    - sender_identity_status clearly indicates 'Not established'
    """
    # Private IP
    c_priv = IPCandidate(ip="10.20.30.40", version=4, classification="Private", hop_index=0, source_header="Received: from internal ([10.20.30.40])")
    res_priv = analyze_ip_candidates([c_priv], total_received_headers=1)
    assert res_priv.origin_candidate is not None
    assert res_priv.origin_candidate.ip == "10.20.30.40"
    assert res_priv.origin_attribution_status == "UNAVAILABLE"
    assert res_priv.candidate_ip_classification == "Private"
    assert res_priv.is_candidate_routable is False
    assert res_priv.sender_identity_status == "Not established (Non-routable internal address)"

    # Loopback IP
    c_loop = IPCandidate(ip="127.0.0.1", version=4, classification="Loopback", hop_index=0, source_header="Received: from localhost ([127.0.0.1])")
    res_loop = analyze_ip_candidates([c_loop], total_received_headers=1)
    assert res_loop.origin_candidate is not None
    assert res_loop.origin_candidate.ip == "127.0.0.1"
    assert res_loop.origin_attribution_status == "UNAVAILABLE"
    assert res_loop.candidate_ip_classification == "Loopback"
    assert res_loop.is_candidate_routable is False
    assert res_loop.sender_identity_status == "Not established (Non-routable loopback address)"

    # Link-Local IP
    c_ll = IPCandidate(ip="169.254.10.20", version=4, classification="Link-Local", hop_index=0, source_header="Received: from link ([169.254.10.20])")
    res_ll = analyze_ip_candidates([c_ll], total_received_headers=1)
    assert res_ll.origin_candidate is not None
    assert res_ll.origin_candidate.ip == "169.254.10.20"
    assert res_ll.origin_attribution_status == "UNAVAILABLE"
    assert res_ll.candidate_ip_classification == "Link-Local"
    assert res_ll.is_candidate_routable is False
    assert res_ll.sender_identity_status == "Not established (Non-routable link-local address)"


# =============================================================================
# Action 3 Tests: Phase 2.5 Revised IP Catalogue Verification
# =============================================================================

def test_action3_microsoft_52_100_documented_association():
    """
    1. Microsoft 52.100.0.0/14 documented Exchange Online association.
    Verifies that 52.100.50.1 matches Confirmed Email-Delivery Network Range with High confidence
    referencing Microsoft's official M365 Endpoint URLs and IP ranges.
    """
    c = analyze_candidate_ip("52.100.50.1", hop_index=0)
    assert c.provider_match_category == "Confirmed Email-Delivery Network Range"
    assert c.provider_confidence == "High (Confirmed Mail Range)"
    assert c.provider_source_url == "https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges"
    assert "Microsoft 365 / Exchange Online" in c.role_hint


def test_action3_microsoft_ip_matching_does_not_prove_sender_identity():
    """
    2. Microsoft IP matching must not prove actual sender identity.
    Matching 52.100.0.0/14 indicates shared provider mail-protection connectivity,
    NOT proof of actual sender identity or authorization.
    """
    c = IPCandidate(
        ip="52.100.50.1",
        version=4,
        classification="Public",
        hop_index=0,
        source_header="Received: from mail-protection.outlook.com ([52.100.50.1]) by recipient.com"
    )
    res = analyze_ip_candidates([c], total_received_headers=1)
    # Sole hop matching shared infrastructure must not declare originating sender proven
    assert res.origin_attribution_status == "UNAVAILABLE"
    assert res.sender_identity_status == "Not established"
    assert res.candidates[0].provider_indicator is not None
    assert "not proof of actual sender authorization" in res.candidates[0].provider_indicator
    assert "Shared multi-tenant infrastructure cannot prove individual sender-origin attribution" in res.origin_assessment


def test_action3_microsoft_service_scope_and_confidence():
    """
    3. Microsoft service scope and confidence must be accurate.
    Verifies that service scope reflects M365 Endpoints ID 9 & 10 mail-protection connectivity.
    """
    c = analyze_candidate_ip("52.100.0.1", hop_index=0)
    assert c.provider_confidence == "High (Confirmed Mail Range)"
    assert c.provider_indicator is not None
    assert "mail-protection connectivity" in c.provider_indicator


def test_action3_sendgrid_17_matching():
    """
    4. SendGrid 167.89.0.0/17 matching.
    Verifies that 167.89.77.213 (inside 167.89.0.0/17) matches SendGrid confirmed mail range with High confidence.
    """
    c = analyze_candidate_ip("167.89.77.213", hop_index=0)
    assert c.provider_match_category == "Confirmed Email-Delivery Network Range"
    assert c.provider_confidence == "High (Confirmed Mail Range)"
    assert c.provider_source_url == "https://docs.sendgrid.com/ui/account-and-settings/ip-addresses"
    assert "SendGrid" in c.role_hint


def test_action3_sendgrid_200_1_not_matching_17():
    """
    5. SendGrid 167.89.200.1 not matching the /17.
    Verifies that 167.89.200.1 (outside 167.89.0.0/17) does NOT match any SendGrid confirmed mail range.
    """
    c = analyze_candidate_ip("167.89.200.1", hop_index=0)
    assert c.provider_match_category is None
    assert c.provider_confidence is None
    assert c.provider_indicator is None


def test_action3_no_overlapping_obsolete_16_entry():
    """
    6. No overlapping obsolete /16 entry.
    Verifies that PROVIDER_GATEWAY_NETWORKS does not contain 167.89.0.0/16.
    """
    import ipaddress
    from app.services.ip_intelligence import PROVIDER_GATEWAY_NETWORKS
    
    obsolete_net = ipaddress.IPv4Network("167.89.0.0/16")
    exact_net = ipaddress.IPv4Network("167.89.0.0/17")
    
    networks = [e.network for e in PROVIDER_GATEWAY_NETWORKS]
    assert obsolete_net not in networks, "Obsolete 167.89.0.0/16 must not be present in PROVIDER_GATEWAY_NETWORKS"
    assert exact_net in networks, "Documented 167.89.0.0/17 must be present in PROVIDER_GATEWAY_NETWORKS"


def test_action3_unknown_ips_remain_unknown():
    """
    7. Unknown IPs remain UNKNOWN.
    Verifies that arbitrary uncatalogued public IPs without matching provider patterns
    produce no provider match and maintain unverified attribution status.
    """
    c = analyze_candidate_ip("93.184.216.34", hop_index=0)
    assert c.provider_match_category is None
    assert c.provider_confidence is None
    assert c.provider_indicator is None

    cand = IPCandidate(
        ip="93.184.216.34",
        version=4,
        classification="Public",
        hop_index=0,
        source_header="Received: from example.com ([93.184.216.34])"
    )
    res = analyze_ip_candidates([cand], total_received_headers=1)
    assert res.origin_attribution_status == "AVAILABLE_UNVERIFIED"
    assert "Unverified" in res.sender_identity_status




