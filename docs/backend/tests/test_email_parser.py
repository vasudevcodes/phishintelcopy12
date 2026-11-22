"""
Unit tests for Email Forensic Parser (Phase 1).
Validates RFC 5322 parsing against 8 synthetic fixtures.
"""

import hashlib
from pathlib import Path
from unittest.mock import patch
import pytest

from app.schemas.email import AttachmentInfo, EmailBodyInfo, EmailHeaderInfo
from app.services.email_parser import parse_email_message
from app.services.ip_extractor import classify_ip_address, extract_ip_candidates_from_received_headers
import ipaddress

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def read_fixture(filename: str) -> bytes:
    filepath = FIXTURES_DIR / filename
    assert filepath.exists(), f"Fixture file not found: {filepath}"
    return filepath.read_bytes()


def test_01_simple_plaintext():
    content = read_fixture("01_simple_plaintext.eml")
    result = parse_email_message(content, "01_simple_plaintext.eml")

    assert result.filename == "01_simple_plaintext.eml"
    assert result.file_size_bytes == len(content)
    assert result.headers.from_header == "alice@sender.com"
    assert result.headers.to_headers == ["bob@receiver.com"]
    assert result.headers.subject == "Meeting Reminder"
    assert result.headers.message_id == "<simple123@sender.com>"
    assert result.body.has_plain_text is True
    assert result.body.plain_text is not None
    assert "project sync meeting" in result.body.plain_text
    assert result.body.has_html is False
    assert len(result.attachments) == 0
    assert result.parsing_status == "success"


def test_02_html_only():
    content = read_fixture("02_html_only.eml")
    result = parse_email_message(content, "02_html_only.eml")

    assert result.headers.subject == "Weekly Threat Summary Report"
    assert result.body.has_html is True
    assert result.body.html_extracted_text is not None
    # Script content should NOT be in extracted clean text
    assert "Untrusted script should never execute" not in result.body.html_extracted_text
    assert "Access Threat Report" in result.body.html_extracted_text

    # URL in href should be extracted
    assert len(result.urls) == 1
    assert result.urls[0].url == "https://portal.security-alerts.org/reports/weekly-40"
    assert result.urls[0].domain == "portal.security-alerts.org"
    assert result.urls[0].source == "html_href"


def test_03_multipart_plain_and_html():
    content = read_fixture("03_multipart_plain_html.eml")
    result = parse_email_message(content, "03_multipart_plain_html.eml")

    assert result.headers.subject == "Tech Digest #89"
    assert result.headers.cc_headers == ["archive@workplace.com"]
    assert result.body.has_plain_text is True
    assert result.body.has_html is True
    assert "Welcome to Tech Digest #89" in (result.body.plain_text or "")
    assert "AI Security Review" in (result.body.html_extracted_text or "")

    # URLs extracted from both plain and html href
    extracted_urls_map = {u.url: u for u in result.urls}
    assert "https://updates.tech/articles/ai-security" in extracted_urls_map
    assert "https://updates.tech/unsubscribe?id=sub123" in extracted_urls_map
    # Since it appeared in both text and html, source should be 'both'
    assert extracted_urls_map["https://updates.tech/articles/ai-security"].source == "both"


def test_04_attachments_metadata_and_hashes():
    content = read_fixture("04_attachments.eml")
    result = parse_email_message(content, "04_attachments.eml")

    assert len(result.attachments) == 2
    att_map = {a.filename: a for a in result.attachments}

    assert "invoice_october.pdf" in att_map
    pdf_att = att_map["invoice_october.pdf"]
    assert pdf_att.content_type == "application/pdf"
    assert pdf_att.size_bytes > 0
    assert pdf_att.sha256 is not None
    assert len(pdf_att.sha256) == 64  # valid SHA-256 length

    assert "payment_instructions.txt" in att_map
    txt_att = att_map["payment_instructions.txt"]
    assert "text" in txt_att.content_type
    assert txt_att.size_bytes > 0
    # Expected SHA256 of payment_instructions content
    expected_content = b"Wire Transfer Instructions:\nBank: Global Trust Bank\nRouting: 123456789\nAccount: 9876543210"
    assert txt_att.sha256 == hashlib.sha256(expected_content).hexdigest()


def test_05_multiple_urls_deduplication():
    content = read_fixture("05_multiple_urls.eml")
    result = parse_email_message(content, "05_multiple_urls.eml")

    # Should contain deduplicated URLs
    url_strings = [u.url for u in result.urls]
    assert len(url_strings) == len(set(url_strings))  # Unique!

    assert "https://secure-account-verify.net/login?token=abc123xyz" in url_strings
    assert "http://docs.secure-account-verify.net/faq" in url_strings
    assert "https://helpdesk.corporate-safety.com/tickets" in url_strings
    assert "https://portal.external-partner.org/sso" in url_strings

    # Verify domain and scheme parsing
    for u in result.urls:
        if u.url == "http://docs.secure-account-verify.net/faq":
            assert u.scheme == "http"
            assert u.domain == "docs.secure-account-verify.net"


def test_06_received_headers_and_ip_candidates():
    content = read_fixture("06_multiple_received_hops.eml")
    result = parse_email_message(content, "06_multiple_received_hops.eml")

    # 4 Received headers in original order
    assert len(result.headers.received_headers) == 4

    # Authentication headers preserved
    assert len(result.headers.authentication_results) >= 1
    assert "dkim=pass" in result.headers.authentication_results[0]
    assert len(result.headers.received_spf) >= 1
    assert "198.51.100.25" in result.headers.received_spf[0]
    assert result.headers.return_path == "<sender@partner.com>"

    # IP candidates extracted and classified
    ip_map = {c.ip: c for c in result.ip_candidates}

    # RFC 5737 TEST-NET-2 documentation address (Hop #0, newest hop)
    assert "198.51.100.25" in ip_map
    assert ip_map["198.51.100.25"].classification == "Documentation"
    assert ip_map["198.51.100.25"].hop_index == 0

    # RFC 1918 Private IPv4 (10.240.0.5, Hop #1)
    assert "10.240.0.5" in ip_map
    assert ip_map["10.240.0.5"].classification == "Private"
    assert ip_map["10.240.0.5"].hop_index == 1

    # Loopback IPv4 (127.0.0.1, Hop #2)
    assert "127.0.0.1" in ip_map
    assert ip_map["127.0.0.1"].classification == "Loopback"
    assert ip_map["127.0.0.1"].hop_index == 2

    # RFC 3849 Documentation IPv6 (2001:db8:85a3::8a2e:370:7334, Hop #3, oldest hop)
    ipv6_str = "2001:db8:85a3::8a2e:370:7334"
    assert ipv6_str in ip_map
    assert ip_map[ipv6_str].version == 6
    assert ip_map[ipv6_str].classification == "Documentation"
    assert ip_map[ipv6_str].hop_index == 3


def test_07_malformed_email_resilience():
    content = read_fixture("07_malformed.eml")
    result = parse_email_message(content, "07_malformed.eml")

    # Parser should not crash, returns result with extracted components
    assert result.headers.from_header == "corrupt-sender@broken.domain"
    assert result.headers.subject == "Malformed Email Sample"
    assert result.filename == "07_malformed.eml"
    assert len(result.attachments) >= 1


def test_08_missing_optional_headers():
    content = read_fixture("08_missing_optional_headers.eml")
    result = parse_email_message(content, "08_missing_optional_headers.eml")

    assert result.headers.from_header == "anonymous@minimal-headers.com"
    assert result.headers.subject is None
    assert result.headers.to_headers == []
    assert result.headers.cc_headers == []
    assert result.headers.bcc_headers == []
    assert result.headers.message_id is None
    assert result.headers.received_headers == []
    assert result.headers.authentication_results == []
    assert result.headers.received_spf == []
    assert result.parsing_status == "success"


def test_ip_classification_helper():
    """
    Focused tests verifying:
    1. RFC 1918 Private addresses vs Documentation, Reserved, Loopback, Link-Local, Multicast, Special-Purpose.
    2. Python ipaddress.is_private is NOT used as blanket label for Private.
    3. TEST-NET documentation addresses are classified as 'Documentation', NOT 'Private'.
    """
    # 1. RFC 1918 Private IPv4
    assert classify_ip_address(ipaddress.ip_address("10.0.0.1")) == "Private"
    assert classify_ip_address(ipaddress.ip_address("10.255.255.255")) == "Private"
    assert classify_ip_address(ipaddress.ip_address("172.16.0.1")) == "Private"
    assert classify_ip_address(ipaddress.ip_address("172.31.255.254")) == "Private"
    assert classify_ip_address(ipaddress.ip_address("192.168.0.1")) == "Private"
    assert classify_ip_address(ipaddress.ip_address("192.168.254.254")) == "Private"

    # 2. RFC 4193 Unique Local IPv6 (ULA Private)
    assert classify_ip_address(ipaddress.ip_address("fc00::1")) == "Private"
    assert classify_ip_address(ipaddress.ip_address("fd12:3456:789a::1")) == "Private"

    # 3. Documentation Ranges (TEST-NET-1, TEST-NET-2, TEST-NET-3, RFC 3849 IPv6)
    # MUST NOT be labelled Private despite ipaddress.is_private returning True in Python!
    assert ipaddress.ip_address("192.0.2.1").is_private is True
    assert classify_ip_address(ipaddress.ip_address("192.0.2.1")) == "Documentation"
    assert classify_ip_address(ipaddress.ip_address("198.51.100.25")) == "Documentation"
    assert classify_ip_address(ipaddress.ip_address("203.0.113.199")) == "Documentation"
    assert classify_ip_address(ipaddress.ip_address("2001:db8::1")) == "Documentation"
    assert classify_ip_address(ipaddress.ip_address("2001:db8:ffff::1")) == "Documentation"

    # 4. Loopback
    assert classify_ip_address(ipaddress.ip_address("127.0.0.1")) == "Loopback"
    assert classify_ip_address(ipaddress.ip_address("127.255.255.254")) == "Loopback"
    assert classify_ip_address(ipaddress.ip_address("::1")) == "Loopback"

    # 5. Link-Local (MUST NOT be labelled Private)
    assert ipaddress.ip_address("169.254.1.1").is_private is True
    assert classify_ip_address(ipaddress.ip_address("169.254.1.1")) == "Link-Local"
    assert classify_ip_address(ipaddress.ip_address("fe80::1")) == "Link-Local"

    # 6. Multicast
    assert classify_ip_address(ipaddress.ip_address("224.0.0.1")) == "Multicast"
    assert classify_ip_address(ipaddress.ip_address("239.255.255.250")) == "Multicast"
    assert classify_ip_address(ipaddress.ip_address("ff02::1")) == "Multicast"

    # 7. Reserved (RFC 1112 future use, broadcast, current network)
    assert classify_ip_address(ipaddress.ip_address("240.0.0.1")) == "Reserved"
    assert classify_ip_address(ipaddress.ip_address("255.255.255.255")) == "Reserved"
    assert classify_ip_address(ipaddress.ip_address("0.0.0.0")) == "Reserved"
    assert classify_ip_address(ipaddress.ip_address("::")) == "Reserved"

    # 8. Special-Purpose (CGNAT, Benchmarking, IETF Protocol Assignments)
    # MUST NOT be labelled Private
    assert classify_ip_address(ipaddress.ip_address("100.64.0.1")) == "Special-Purpose"
    assert classify_ip_address(ipaddress.ip_address("198.18.0.1")) == "Special-Purpose"
    assert classify_ip_address(ipaddress.ip_address("192.0.0.1")) == "Special-Purpose"

    # 9. Public Globally Routable
    assert classify_ip_address(ipaddress.ip_address("8.8.8.8")) == "Public"
    assert classify_ip_address(ipaddress.ip_address("1.1.1.1")) == "Public"
    assert classify_ip_address(ipaddress.ip_address("93.184.216.34")) == "Public"
    assert classify_ip_address(ipaddress.ip_address("2607:f8b0:4005:805::200e")) == "Public"


def test_evidence_fusion_integration_receives_headers_body_and_attachments():
    """
    Regression test: Verifies that parse_email_message forwards header_info,
    body_info, and attachments to fuse_evidence.
    """
    import app.services.email_parser as parser_module

    content = read_fixture("04_attachments.eml")

    with patch.object(parser_module, "fuse_evidence", wraps=parser_module.fuse_evidence) as mock_fuse:
        result = parser_module.parse_email_message(content, "04_attachments.eml")

        assert mock_fuse.called, "fuse_evidence was not invoked by parse_email_message"
        call_kwargs = mock_fuse.call_args.kwargs

        # 1. header_info forwarded and populated
        assert "header_info" in call_kwargs, "header_info missing from fuse_evidence call"
        header_arg = call_kwargs["header_info"]
        assert isinstance(header_arg, EmailHeaderInfo)
        assert header_arg.from_header == "billing@vendor-services.com"
        assert header_arg.subject == "Invoice INV-2026-9081 Attached"

        # 2. body_info forwarded and populated
        assert "body_info" in call_kwargs, "body_info missing from fuse_evidence call"
        body_arg = call_kwargs["body_info"]
        assert isinstance(body_arg, EmailBodyInfo)
        assert body_arg.plain_text is not None
        assert "INV-2026-9081" in body_arg.plain_text

        # 3. attachments forwarded and populated
        assert "attachments" in call_kwargs, "attachments missing from fuse_evidence call"
        att_arg = call_kwargs["attachments"]
        assert isinstance(att_arg, list)
        assert len(att_arg) == 2
        assert any(att.filename == "invoice_october.pdf" for att in att_arg)
        assert any(att.filename == "payment_instructions.txt" for att in att_arg)

        # 4. Result integrity
        assert result.evidence_fusion is not None
