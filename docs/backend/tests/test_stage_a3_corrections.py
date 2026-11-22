"""
Stage A.3 Regression Tests — Final Authentication and IP Classification Audit.

Tests verify:
1. Authentication Boolean Safety:
   - `validate_authserv_id_trust()` returns `AuthservTrustResult` (NamedTuple).
   - `is_trusted` is ALWAYS False for offline .eml uploads (including REPORTED).
   - `domain_matches_policy` is True for REPORTED, False for UNTRUSTED/MISSING/SUSPICIOUS.
   - Unpacking as 3-tuple `is_trusted, status, explanation = validate_authserv_id_trust(...)`
     guarantees that `if is_trusted:` is NEVER taken for reported authentication.
   - Caller audit: `parse_auth_results_header` and `analyze_email_authentication`
     do not interpret the return value as independently established provenance.

2. Special-Purpose IP Classification:
   - Special-purpose networks are classified as RESERVED before the generic `is_private` check.
   - RFC 1918 IPv4 private -> PRIVATE.
   - RFC 4193 IPv6 ULA -> PRIVATE.
   - RFC 6598 Shared Address Space -> RESERVED.
   - RFC 2544 Benchmarking -> RESERVED (NOT private!).
   - RFC 1112 Reserved -> RESERVED (NOT private!).
   - Unspecified (0.0.0.0, 0.0.0.1, ::) -> RESERVED.
   - Documentation ranges (RFC 5737 / RFC 3849) -> DOCUMENTATION.
   - Loopback (127.0.0.0/8, ::1) -> LOOPBACK.
   - Link-local (169.254.0.0/16, fe80::/10) -> LINK_LOCAL.
   - Multicast (224.0.0.0/4, ff00::/8) -> RESERVED.
   - Public IPv4 and IPv6 -> PUBLIC.

Zero network access: all logic is 100% offline and deterministic.
"""

import pytest

from app.schemas.email import EmailHeaderInfo
from app.schemas.email_authentication import (
    AuthResultStatus,
    AuthservTrustResult,
    AuthservTrustStatus,
    EmailAuthenticationAnalysis,
    ProvenanceStatus,
)
from app.schemas.url_intelligence import HostClassification
from app.services.email_authentication import (
    analyze_email_authentication,
    parse_auth_results_header,
    validate_authserv_id_trust,
)
from app.services.url_intelligence import is_valid_ipv4_or_ipv6


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_header_info(
    authentication_results=None,
    received_spf=None,
    received_headers=None,
) -> EmailHeaderInfo:
    return EmailHeaderInfo(
        from_header=None,
        to_headers=[],
        cc_headers=[],
        bcc_headers=[],
        subject=None,
        date=None,
        message_id=None,
        reply_to=None,
        return_path=None,
        mime_version=None,
        content_type=None,
        authentication_results=authentication_results or [],
        received_spf=received_spf or [],
        dkim_signatures=[],
        received_headers=received_headers or [],
    )


# ===========================================================================
# 1. Authentication Boolean Safety Tests
# ===========================================================================

class TestAuthservBooleanSafety:
    """
    Verifies that validate_authserv_id_trust() return contract cannot be
    mistaken for independently established authentication provenance.
    """

    def test_return_type_is_authserv_trust_result(self):
        """Must return AuthservTrustResult namedtuple."""
        res = validate_authserv_id_trust("mx.google.com")
        assert isinstance(res, AuthservTrustResult)
        assert isinstance(res, tuple)
        assert len(res) == 3

    def test_reported_domain_is_trusted_is_false(self):
        """
        Critical safety test: For recognized gateway domains (e.g. mx.google.com),
        is_trusted MUST be False. Domain matching is not provenance proof.
        """
        for domain in ["mx.google.com", "protection.outlook.com", "mx0a-001.pphosted.com"]:
            res = validate_authserv_id_trust(domain)
            assert res.is_trusted is False, f"is_trusted was True for {domain}; must be False!"
            assert res.status == AuthservTrustStatus.REPORTED
            assert res.domain_matches_policy is True

    def test_untrusted_domain_is_trusted_is_false(self):
        """Unrecognized domains must have is_trusted=False and domain_matches_policy=False."""
        res = validate_authserv_id_trust("mail.attacker.com")
        assert res.is_trusted is False
        assert res.status == AuthservTrustStatus.UNTRUSTED
        assert res.domain_matches_policy is False

    def test_missing_authserv_id_is_trusted_is_false(self):
        """Missing authserv-id must have is_trusted=False and domain_matches_policy=False."""
        res = validate_authserv_id_trust(None)
        assert res.is_trusted is False
        assert res.status == AuthservTrustStatus.MISSING
        assert res.domain_matches_policy is False

        res_empty = validate_authserv_id_trust("")
        assert res_empty.is_trusted is False
        assert res_empty.status == AuthservTrustStatus.MISSING

    def test_suspicious_authserv_id_is_trusted_is_false(self):
        """Malformed/suspicious authserv-id must have is_trusted=False and domain_matches_policy=False."""
        for malformed in ["mx google.com", "admin@evil.com", "mx/google.com", "mx;google.com"]:
            res = validate_authserv_id_trust(malformed)
            assert res.is_trusted is False
            assert res.status == AuthservTrustStatus.SUSPICIOUS
            assert res.domain_matches_policy is False

    def test_three_tuple_unpacking_safety(self):
        """
        When unpacked as a traditional 3-tuple (is_trusted, status, explanation):
        `if is_trusted:` must evaluate to False for reported authentication.
        """
        is_trusted, status, explanation = validate_authserv_id_trust("mx.google.com")
        assert is_trusted is False
        assert status == AuthservTrustStatus.REPORTED
        assert "provenance is NOT independently established" in explanation

        # A naive caller checking `if is_trusted:` must NOT enter the trusted block
        trusted_branch_taken = False
        if is_trusted:
            trusted_branch_taken = True
        assert trusted_branch_taken is False

    def test_custom_trust_policy_returns_reported_with_false_is_trusted(self):
        """Custom configured trust policy must still return is_trusted=False for offline uploads."""
        custom_domains = ["mail.internal-corp.enterprise"]
        res = validate_authserv_id_trust("mail.internal-corp.enterprise", trusted_domains=custom_domains)
        assert res.is_trusted is False
        assert res.domain_matches_policy is True
        assert res.status == AuthservTrustStatus.REPORTED


class TestCallerSafetyAudit:
    """
    Inspects internal callers of validate_authserv_id_trust to ensure
    none of them grant trusted boundary status based on reported headers.
    """

    def test_parse_auth_results_header_sets_reported_trust(self):
        """parse_auth_results_header sets authserv_trust to REPORTED, never TRUSTED."""
        header = "mx.google.com; spf=pass smtp.mailfrom=example.com"
        aid, findings, warnings = parse_auth_results_header(header, 0)
        assert aid == "mx.google.com"
        assert len(findings) == 1
        assert findings[0].authserv_trust == AuthservTrustStatus.REPORTED

    def test_analyze_email_authentication_sets_boundary_trusted_false(self):
        """analyze_email_authentication guarantees is_boundary_trusted=False for reported headers."""
        hdr = _make_header_info(
            authentication_results=[
                "mx.google.com; spf=pass smtp.mailfrom=example.com; dkim=pass; dmarc=pass"
            ]
        )
        res = analyze_email_authentication(hdr)
        assert res.is_boundary_trusted is False
        assert res.boundary_authserv_trust == AuthservTrustStatus.REPORTED
        assert res.provenance_status == ProvenanceStatus.REPORTED_AUTHENTICATION


# ===========================================================================
# 2. Special-Purpose IP Classification Tests
# ===========================================================================

class TestSpecialPurposeIPClassification:
    """
    Verifies the corrected classification order in url_intelligence.py:
    Special-purpose networks must be classified as RESERVED before the
    generic `ip_obj.is_private` check, preventing Python 3.13 from
    misclassifying benchmarking, reserved, and unspecified ranges as PRIVATE.
    """

    # --- RFC 1918 Private IPv4 ---
    @pytest.mark.parametrize("addr", [
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.1.100",
        "192.168.255.255",
    ])
    def test_rfc1918_private(self, addr):
        is_ip, ver, classification = is_valid_ipv4_or_ipv6(addr)
        assert is_ip is True
        assert ver == 4
        assert classification == HostClassification.PRIVATE

    # --- RFC 4193 IPv6 ULA ---
    @pytest.mark.parametrize("addr", [
        "fc00::1",
        "fd00::1",
        "fd12:3456:789a::1",
        "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    ])
    def test_rfc4193_ipv6_ula(self, addr):
        is_ip, ver, classification = is_valid_ipv4_or_ipv6(addr)
        assert is_ip is True
        assert ver == 6
        assert classification == HostClassification.PRIVATE

    # --- RFC 6598 Shared Address Space ---
    @pytest.mark.parametrize("addr", [
        "100.64.0.1",
        "100.64.100.50",
        "100.127.255.255",
    ])
    def test_rfc6598_shared_address_space(self, addr):
        is_ip, ver, classification = is_valid_ipv4_or_ipv6(addr)
        assert is_ip is True
        assert ver == 4
        assert classification == HostClassification.RESERVED

    # --- RFC 2544 Benchmarking (Must NOT be PRIVATE) ---
    @pytest.mark.parametrize("addr", [
        "198.18.0.1",
        "198.18.50.1",
        "198.19.255.255",
    ])
    def test_rfc2544_benchmarking_is_reserved_not_private(self, addr):
        """
        Critical Stage A.3 test: Benchmarking addresses must be classified as RESERVED,
        NOT as PRIVATE (even though Python 3.13 sets is_private=True).
        """
        is_ip, ver, classification = is_valid_ipv4_or_ipv6(addr)
        assert is_ip is True
        assert ver == 4
        assert classification == HostClassification.RESERVED
        assert classification != HostClassification.PRIVATE

    # --- RFC 1112 Reserved / Class E (Must NOT be PRIVATE) ---
    @pytest.mark.parametrize("addr", [
        "240.0.0.1",
        "250.1.2.3",
        "255.255.255.254",
    ])
    def test_rfc1112_reserved_is_reserved_not_private(self, addr):
        """
        Critical Stage A.3 test: Class E reserved addresses must be classified as RESERVED,
        NOT as PRIVATE (even though Python 3.13 sets is_private=True).
        """
        is_ip, ver, classification = is_valid_ipv4_or_ipv6(addr)
        assert is_ip is True
        assert ver == 4
        assert classification == HostClassification.RESERVED
        assert classification != HostClassification.PRIVATE

    # --- Unspecified Addresses (Must NOT be PRIVATE) ---
    @pytest.mark.parametrize("addr", [
        "0.0.0.0",
        "0.0.0.1",
        "0.255.255.255",
        "::",
    ])
    def test_unspecified_addresses_are_reserved(self, addr):
        is_ip, ver, classification = is_valid_ipv4_or_ipv6(addr)
        assert is_ip is True
        assert classification == HostClassification.RESERVED
        assert classification != HostClassification.PRIVATE
        assert classification != HostClassification.PUBLIC

    # --- Documentation Ranges (RFC 5737 / RFC 3849) ---
    @pytest.mark.parametrize("addr", [
        "192.0.2.1",       # TEST-NET-1
        "198.51.100.1",    # TEST-NET-2
        "203.0.113.1",     # TEST-NET-3
        "2001:db8::1",     # IPv6 Documentation
    ])
    def test_documentation_ranges(self, addr):
        is_ip, ver, classification = is_valid_ipv4_or_ipv6(addr)
        assert is_ip is True
        assert classification == HostClassification.DOCUMENTATION

    # --- Loopback Addresses ---
    @pytest.mark.parametrize("addr", [
        "127.0.0.1",
        "127.0.0.2",
        "127.255.255.254",
        "::1",
    ])
    def test_loopback_addresses(self, addr):
        is_ip, ver, classification = is_valid_ipv4_or_ipv6(addr)
        assert is_ip is True
        assert classification == HostClassification.LOOPBACK

    # --- Link-Local Addresses ---
    @pytest.mark.parametrize("addr", [
        "169.254.1.1",
        "169.254.254.254",
        "fe80::1",
        "fe80::dead:beef",
    ])
    def test_link_local_addresses(self, addr):
        is_ip, ver, classification = is_valid_ipv4_or_ipv6(addr)
        assert is_ip is True
        assert classification == HostClassification.LINK_LOCAL

    # --- Multicast Addresses ---
    @pytest.mark.parametrize("addr", [
        "224.0.0.1",
        "239.255.255.255",
        "ff02::1",
        "ff05::2",
    ])
    def test_multicast_addresses(self, addr):
        is_ip, ver, classification = is_valid_ipv4_or_ipv6(addr)
        assert is_ip is True
        assert classification == HostClassification.RESERVED

    # --- Public IPv4 and IPv6 ---
    @pytest.mark.parametrize("addr,ver_expected", [
        ("8.8.8.8", 4),
        ("1.1.1.1", 4),
        ("93.184.216.34", 4),
        ("2001:4860:4860::8888", 6),
        ("2606:4700:4700::1111", 6),
    ])
    def test_public_addresses(self, addr, ver_expected):
        is_ip, ver, classification = is_valid_ipv4_or_ipv6(addr)
        assert is_ip is True
        assert ver == ver_expected
        assert classification == HostClassification.PUBLIC

