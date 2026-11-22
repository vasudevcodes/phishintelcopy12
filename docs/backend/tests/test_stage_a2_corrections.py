"""
Stage A.2 Regression Tests — Authentication Provenance and IP Classification Fallback Correction.

Tests verify:
1. Forged Authentication-Results headers with recognized authserv-id domains do NOT produce
   is_boundary_trusted=True or provenance TRUSTED_RECEIVER_EVIDENCE.
2. Header position (index 0) does NOT establish provenance.
3. Reported PASS is distinct from trusted evidence in has_valid_authentication.
4. Missing authentication produces provenance MISSING_AUTHENTICATION.
5. Non-global IP addresses cannot fall through to PUBLIC classification.
6. Comprehensive IP range classification coverage.

NO network calls are made.  Socket is not monkeypatched because all code
under test already guarantees zero network access (pure parsing / classification).
"""

import pytest

from app.schemas.email import EmailHeaderInfo
from app.schemas.email_authentication import (
    AuthResultStatus,
    AuthservTrustStatus,
    EmailAuthenticationAnalysis,
    ProvenanceStatus,
)
from app.schemas.url_intelligence import HostClassification
from app.services.email_authentication import (
    analyze_email_authentication,
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
    """Construct a minimal EmailHeaderInfo for authentication analysis."""
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


# ---------------------------------------------------------------------------
# Issue 1 — Authentication Provenance
# ---------------------------------------------------------------------------

class TestForgedGoogleAuthservId:
    """
    Forged header: Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass

    This is the canonical forged-header attack.  The authserv-id string 'mx.google.com'
    matches a known mail gateway name.  For offline .eml uploads, the application MUST NOT
    treat this as independently established trusted evidence.
    """

    def _result(self) -> EmailAuthenticationAnalysis:
        hdr = _make_header_info(
            authentication_results=[
                "mx.google.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass"
            ]
        )
        return analyze_email_authentication(hdr)

    def test_is_boundary_trusted_is_false(self):
        """is_boundary_trusted must be False — authserv-id match is not provenance proof."""
        result = self._result()
        assert result.is_boundary_trusted is False, (
            "is_boundary_trusted must stay False for offline .eml upload regardless of authserv-id match"
        )

    def test_boundary_authserv_trust_is_reported_not_trusted(self):
        """boundary_authserv_trust should be REPORTED (domain matched but not verified)."""
        result = self._result()
        assert result.boundary_authserv_trust in (
            AuthservTrustStatus.REPORTED, AuthservTrustStatus.UNTRUSTED
        ), (
            f"Expected REPORTED or UNTRUSTED, got {result.boundary_authserv_trust}. "
            "TRUSTED must not be assigned based on authserv-id domain match alone."
        )

    def test_provenance_status_is_reported_not_trusted(self):
        """provenance_status must be REPORTED_AUTHENTICATION, not TRUSTED_RECEIVER_EVIDENCE."""
        result = self._result()
        assert result.provenance_status != ProvenanceStatus.TRUSTED_RECEIVER_EVIDENCE, (
            f"provenance_status is {result.provenance_status} — must not be TRUSTED_RECEIVER_EVIDENCE "
            "for an offline .eml upload with forged authserv-id."
        )
        assert result.provenance_status == ProvenanceStatus.REPORTED_AUTHENTICATION, (
            f"Expected REPORTED_AUTHENTICATION, got {result.provenance_status}"
        )

    def test_spf_pass_is_present_but_not_verified(self):
        """SPF PASS should be recorded as PASS status (the claim exists) but is not independently verified."""
        result = self._result()
        assert result.spf.status == AuthResultStatus.PASS


class TestForgedMicrosoftAuthservId:
    """Same attack with protection.outlook.com as authserv-id."""

    def _result(self) -> EmailAuthenticationAnalysis:
        hdr = _make_header_info(
            authentication_results=[
                "protection.outlook.com; spf=pass; dkim=pass; dmarc=pass"
            ]
        )
        return analyze_email_authentication(hdr)

    def test_is_boundary_trusted_is_false(self):
        result = self._result()
        assert result.is_boundary_trusted is False

    def test_boundary_authserv_trust_not_trusted(self):
        result = self._result()
        assert result.boundary_authserv_trust not in (AuthservTrustStatus.TRUSTED,), (
            "TRUSTED must not be assigned for offline .eml with Microsoft authserv-id"
        )

    def test_provenance_is_reported(self):
        result = self._result()
        assert result.provenance_status == ProvenanceStatus.REPORTED_AUTHENTICATION


class TestHeaderPositionDoesNotEstablishProvenance:
    """
    Stage A.2 core invariant: header_index == 0 does NOT establish provenance.
    The outermost Authentication-Results header in an uploaded .eml is as forgeable
    as any other.
    """

    def test_index_zero_known_domain_still_reported(self):
        """
        Header at index 0 with known gateway authserv-id must still be REPORTED.
        """
        hdr = _make_header_info(
            authentication_results=[
                # This is at index 0 — still cannot establish provenance for offline upload
                "mx.google.com; spf=pass; dkim=pass; dmarc=pass"
            ]
        )
        result = analyze_email_authentication(hdr)
        assert result.is_boundary_trusted is False
        assert result.provenance_status == ProvenanceStatus.REPORTED_AUTHENTICATION

    def test_multiple_headers_index_zero_still_reported(self):
        """
        Even with multiple headers, index 0 with known authserv-id stays REPORTED.
        """
        hdr = _make_header_info(
            authentication_results=[
                "mx.google.com; spf=pass; dkim=pass; dmarc=pass",
                "mx.google.com; spf=pass",
            ]
        )
        result = analyze_email_authentication(hdr)
        assert result.is_boundary_trusted is False
        assert result.provenance_status == ProvenanceStatus.REPORTED_AUTHENTICATION


class TestReportedPassDistinctFromTrustedEvidence:
    """
    has_valid_authentication must reflect provenance, not just reported result.
    For offline uploads, all PASS assertions are REPORTED — has_valid_authentication
    must therefore be False even when SPF/DKIM/DMARC all report PASS.
    """

    def test_all_pass_offline_upload_has_valid_auth_is_false(self):
        """
        SPF=PASS, DKIM=PASS, DMARC=PASS in offline upload → has_valid_authentication=False.
        The PASS assertions are present but their provenance is not independently established.
        """
        from app.services.evidence_fusion import _extract_auth_evidence

        hdr = _make_header_info(
            authentication_results=[
                "mx.google.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass"
            ]
        )
        auth_result = analyze_email_authentication(hdr)
        # Confirm provenance
        assert auth_result.provenance_status == ProvenanceStatus.REPORTED_AUTHENTICATION
        assert auth_result.is_boundary_trusted is False

        # Evidence fusion must reflect this
        auth_summary, contributing, missing = _extract_auth_evidence(auth_result)
        assert auth_summary.has_valid_authentication is False, (
            "has_valid_authentication must be False when provenance is REPORTED_AUTHENTICATION"
        )

    def test_no_auth_headers_has_valid_auth_is_false(self):
        """No headers → has_valid_authentication=False and provenance=MISSING."""
        from app.services.evidence_fusion import _extract_auth_evidence

        hdr = _make_header_info()
        auth_result = analyze_email_authentication(hdr)
        auth_summary, _, _ = _extract_auth_evidence(auth_result)
        assert auth_summary.has_valid_authentication is False


class TestMissingProvenanceExplicit:
    """No authentication headers → provenance MISSING_AUTHENTICATION."""

    def test_no_auth_headers_gives_missing_authentication(self):
        hdr = _make_header_info()
        result = analyze_email_authentication(hdr)
        assert result.provenance_status == ProvenanceStatus.MISSING_AUTHENTICATION

    def test_no_auth_results_no_received_spf_missing(self):
        hdr = _make_header_info(
            authentication_results=[],
            received_spf=[],
        )
        result = analyze_email_authentication(hdr)
        assert result.provenance_status == ProvenanceStatus.MISSING_AUTHENTICATION


class TestValidateAuthservIdReturnedReported:
    """
    Stage A.3: validate_authserv_id_trust() returns `AuthservTrustResult`.
    Guarantees that `is_trusted` is False for recognized domains in offline .eml uploads,
    while `.domain_matches_policy` confirms policy domain recognition.
    """

    def test_google_domain_returns_reported(self):
        res = validate_authserv_id_trust("mx.google.com")
        assert res.is_trusted is False, "is_trusted must be False (safety guarantee)"
        assert res.domain_matches_policy is True
        assert res.status == AuthservTrustStatus.REPORTED

    def test_outlook_domain_returns_reported(self):
        res = validate_authserv_id_trust("protection.outlook.com")
        assert res.is_trusted is False, "is_trusted must be False (safety guarantee)"
        assert res.domain_matches_policy is True
        assert res.status == AuthservTrustStatus.REPORTED

    def test_unknown_domain_returns_untrusted(self):
        res = validate_authserv_id_trust("mail.attacker.example")
        assert res.is_trusted is False
        assert res.domain_matches_policy is False
        assert res.status == AuthservTrustStatus.UNTRUSTED

    def test_missing_id_returns_missing(self):
        res = validate_authserv_id_trust(None)
        assert res.is_trusted is False
        assert res.domain_matches_policy is False
        assert res.status == AuthservTrustStatus.MISSING

    def test_malformed_id_returns_suspicious(self):
        res = validate_authserv_id_trust("mx google.com")
        assert res.is_trusted is False
        assert res.domain_matches_policy is False
        assert res.status == AuthservTrustStatus.SUSPICIOUS


# ---------------------------------------------------------------------------
# Issue 2 — IP Classification Fallback
# ---------------------------------------------------------------------------

class TestNonGlobalIPsCannotFallThroughToPublic:
    """
    Stage A.2: Non-global IP addresses must not fall through to PUBLIC classification.
    Addresses from shared address space, benchmarking, unspecified, reserved ranges
    must be classified as RESERVED (or another non-PUBLIC classification).
    """

    @pytest.mark.parametrize("addr,expected_not", [
        # RFC 6598 Shared Address Space
        ("100.64.0.1", HostClassification.PUBLIC),
        ("100.127.255.255", HostClassification.PUBLIC),
        # Benchmarking (RFC 2544)
        ("198.18.0.1", HostClassification.PUBLIC),
        ("198.19.255.255", HostClassification.PUBLIC),
        # Reserved (RFC 1112) — class E
        ("240.0.0.1", HostClassification.PUBLIC),
        ("255.255.255.254", HostClassification.PUBLIC),
        # Unspecified / "this" network (RFC 1122)
        ("0.0.0.1", HostClassification.PUBLIC),
        # IPv6 unspecified
        ("::", HostClassification.PUBLIC),
    ])
    def test_non_global_not_public(self, addr, expected_not):
        is_ip, version, classification = is_valid_ipv4_or_ipv6(addr)
        assert is_ip is True, f"{addr} should be recognized as an IP address"
        assert classification != expected_not, (
            f"{addr} was classified as {classification.value} but must NOT be {expected_not.value}"
        )


class TestCompleteIPRangeClassification:
    """
    Comprehensive IP classification coverage for all major address ranges.
    """

    @pytest.mark.parametrize("addr,expected_classification", [
        # RFC 1918 — Private
        ("10.0.0.1", HostClassification.PRIVATE),
        ("172.16.0.1", HostClassification.PRIVATE),
        ("172.31.255.255", HostClassification.PRIVATE),
        ("192.168.1.100", HostClassification.PRIVATE),
        # Loopback
        ("127.0.0.1", HostClassification.LOOPBACK),
        ("127.255.255.254", HostClassification.LOOPBACK),
        ("::1", HostClassification.LOOPBACK),
        # Link-local
        ("169.254.1.1", HostClassification.LINK_LOCAL),
        ("fe80::1", HostClassification.LINK_LOCAL),
        # RFC 5737 Documentation
        ("192.0.2.1", HostClassification.DOCUMENTATION),
        ("198.51.100.1", HostClassification.DOCUMENTATION),
        ("203.0.113.1", HostClassification.DOCUMENTATION),
        # RFC 3849 IPv6 Documentation
        ("2001:db8::1", HostClassification.DOCUMENTATION),
        # RFC 4193 IPv6 ULA
        ("fc00::1", HostClassification.PRIVATE),
        ("fd12:3456:789a::1", HostClassification.PRIVATE),
        # Public IPv4
        ("8.8.8.8", HostClassification.PUBLIC),
        ("1.1.1.1", HostClassification.PUBLIC),
        ("93.184.216.34", HostClassification.PUBLIC),
        # Public IPv6
        ("2001:4860:4860::8888", HostClassification.PUBLIC),
        # Multicast
        ("224.0.0.1", HostClassification.RESERVED),
        ("239.255.255.255", HostClassification.RESERVED),
        # Reserved — special-purpose ranges
        ("100.64.0.1", HostClassification.RESERVED),   # RFC 6598 Shared
        ("198.18.0.1", HostClassification.RESERVED),   # RFC 2544 Benchmarking (Stage A.3: RESERVED, not PRIVATE)
        ("240.0.0.1", HostClassification.RESERVED),    # RFC 1112 Reserved (Stage A.3: RESERVED, not PRIVATE)
    ])
    def test_ip_classification(self, addr, expected_classification):
        is_ip, version, classification = is_valid_ipv4_or_ipv6(addr)
        assert is_ip is True, f"{addr} should be recognized as a valid IP"
        assert classification == expected_classification, (
            f"{addr}: expected {expected_classification.value}, got {classification.value}"
        )

    def test_invalid_host_returns_unknown(self):
        is_ip, version, classification = is_valid_ipv4_or_ipv6("not-an-ip.example.com")
        assert is_ip is False
        assert classification == HostClassification.UNKNOWN

    def test_ipv6_bracketed_literal(self):
        """IPv6 addresses in bracket notation (URL host format) should be classified correctly."""
        is_ip, version, classification = is_valid_ipv4_or_ipv6("[::1]")
        assert is_ip is True
        assert version == 6
        assert classification == HostClassification.LOOPBACK

    def test_ipv4_unspecified_not_public(self):
        """0.0.0.0 (unspecified) must not be PUBLIC."""
        is_ip, version, classification = is_valid_ipv4_or_ipv6("0.0.0.0")
        assert is_ip is True
        assert classification != HostClassification.PUBLIC

    def test_ipv6_unspecified_not_public(self):
        """:: (IPv6 unspecified) must not be PUBLIC."""
        is_ip, version, classification = is_valid_ipv4_or_ipv6("::")
        assert is_ip is True
        assert classification != HostClassification.PUBLIC
