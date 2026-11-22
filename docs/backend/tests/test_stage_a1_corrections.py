"""
Stage A.1 Security and Forensic Correctness Regression Test Suite.
Validates:
1. Forged Authentication-Results headers.
2. Trusted and untrusted authserv-id validation against trust policy.
3. Reordered authentication headers and upstream boundary detection.
4. Schema safety: trust-related Booleans must NOT default to True.
5. RFC 1918 Private IP URLs (not automatically classified as malicious).
6. Loopback IP URLs (RFC 1122 / RFC 4291).
7. Link-local IP URLs (RFC 3927 / RFC 4291).
8. RFC 5737 Documentation IP URLs (TEST-NET-1/2/3, not claims of real malicious destinations).
9. Public IP literal URLs (evasion indicators).
10. Symmetrical IPv4 and IPv6 classification.
11. Nested documentation IP redirects (INFO severity).
12. Legitimate external tracking redirects (LOW severity, distinguishable from attacks).
13. Suspicious nested redirects (public IP literals and credential @ syntax -> HIGH severity).
"""

import socket
import pytest

from app.schemas.email import EmailHeaderInfo
from app.schemas.email_authentication import (
    AuthResultStatus,
    AuthservTrustStatus,
    EmailAuthenticationAnalysis,
    HeaderFinding,
    OverallAuthStatus,
)
from app.schemas.evidence_fusion import (
    AssessmentCategory,
    AuthEvidenceSummary,
)
from app.schemas.url_intelligence import (
    HeuristicRiskCategory,
    HostClassification,
    HostType,
    ObservationSeverity,
    ParseStatus,
)
from app.services.email_authentication import (
    DEFAULT_TRUSTED_AUTHSERV_DOMAINS,
    analyze_email_authentication,
    validate_authserv_id_trust,
)
from app.services.evidence_fusion import fuse_evidence
from app.services.url_intelligence import analyze_url, is_valid_ipv4_or_ipv6


@pytest.fixture(autouse=True)
def guard_no_network(monkeypatch):
    """
    Enforces absolute offline isolation during regression tests.
    Zero outbound socket connections or external DNS lookups are permitted.
    """
    orig_connect = socket.socket.connect
    orig_getaddrinfo = socket.getaddrinfo
    orig_gethostbyname = socket.gethostbyname

    def fail_connect(self, addr):
        host = addr[0] if isinstance(addr, tuple) else addr
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise RuntimeError(f"Network connect forbidden during test: {addr}")
        return orig_connect(self, addr)

    def fail_dns(host, *args, **kwargs):
        if host not in ("127.0.0.1", "localhost", "::1", "testserver", None, ""):
            raise RuntimeError(f"DNS resolution forbidden during test: {host}")
        return orig_getaddrinfo(host, *args, **kwargs)

    def fail_gethostbyname(host):
        if host not in ("127.0.0.1", "localhost", "::1", "testserver"):
            raise RuntimeError(f"DNS resolution forbidden during test: {host}")
        return orig_gethostbyname(host)

    monkeypatch.setattr(socket.socket, "connect", fail_connect)
    monkeypatch.setattr(socket, "getaddrinfo", fail_dns)
    monkeypatch.setattr(socket, "gethostbyname", fail_gethostbyname)


# ---------------------------------------------------------------------------
# 1. Forged Authentication-Results Headers
# ---------------------------------------------------------------------------
def test_case_01_forged_authentication_results():
    """
    An attacker injects a forged Authentication-Results header at index 0 claiming
    SPF and DKIM pass with an untrusted or forged authserv-id.
    Downstream trust validation must treat this as untrusted, is_boundary_trusted=False,
    and must not grant valid authentication pass.

    Stage A.2 update: warning text changed to match new message wording.
    """
    header_info = EmailHeaderInfo(
        authentication_results=[
            "forged-mta.attacker-domain.com; spf=pass smtp.mailfrom=attacker.com; dkim=pass header.d=attacker.com",
            "mx.google.com; spf=fail smtp.mailfrom=attacker.com; dkim=fail",
        ]
    )
    auth_res = analyze_email_authentication(header_info)

    assert auth_res.boundary_authserv_id == "forged-mta.attacker-domain.com"
    assert auth_res.boundary_authserv_trust == AuthservTrustStatus.UNTRUSTED
    assert auth_res.is_boundary_trusted is False
    # Stage A.2: warning message updated — check for unrecognized authserv-id text
    assert any(
        ("untrusted" in w.lower() or "unrecognized" in w.lower())
        for w in auth_res.warnings
    ), f"Expected untrusted/unrecognized warning in: {auth_res.warnings}"

    # In evidence fusion: untrusted boundary must NOT be treated as valid authentication
    fusion = fuse_evidence(authentication_analysis=auth_res)
    assert fusion.auth_evidence.is_boundary_trusted is False
    assert fusion.auth_evidence.has_valid_authentication is False
    assert any("untrusted" in c.lower() or "unrecognized" in c.lower() for c in fusion.contributing_factors)


# ---------------------------------------------------------------------------
# 2. Trusted and Untrusted authserv-id Values
# ---------------------------------------------------------------------------
def test_case_02_trusted_and_untrusted_authserv_id_values():
    """
    Validates authserv-id against trust policy.

    Stage A.3 update: validate_authserv_id_trust() returns `AuthservTrustResult`.
    The `is_trusted` boolean is guaranteed to be False for offline .eml uploads,
    preventing any caller from mistaking a recognized domain name for established trust.
    Policy matching is checked via `.domain_matches_policy`.

    - Known provider domains (Google, Microsoft, Proofpoint) -> is_trusted=False, domain_matches_policy=True, status=REPORTED
    - Unrecognized or spoofed domains -> is_trusted=False, domain_matches_policy=False, status=UNTRUSTED
    - Malformed tokens containing spaces or @ -> is_trusted=False, domain_matches_policy=False, status=SUSPICIOUS
    - Explicitly custom configured trust policy returns is_trusted=False, domain_matches_policy=True, status=REPORTED
    """
    # Google MTA — Stage A.3: is_trusted=False, domain_matches_policy=True, status=REPORTED
    res_google = validate_authserv_id_trust("mx.google.com")
    assert res_google.is_trusted is False
    assert res_google.domain_matches_policy is True
    assert res_google.status == AuthservTrustStatus.REPORTED

    # Microsoft 365 MTA — Stage A.3: is_trusted=False, domain_matches_policy=True, status=REPORTED
    res_ms = validate_authserv_id_trust("mail-eop.protection.outlook.com")
    assert res_ms.is_trusted is False
    assert res_ms.domain_matches_policy is True
    assert res_ms.status == AuthservTrustStatus.REPORTED

    # Proofpoint gateway — Stage A.3: is_trusted=False, domain_matches_policy=True, status=REPORTED
    res_pp = validate_authserv_id_trust("mx0a-001.pphosted.com")
    assert res_pp.is_trusted is False
    assert res_pp.domain_matches_policy is True
    assert res_pp.status == AuthservTrustStatus.REPORTED

    # Unrecognized attacker domain
    res_untrusted = validate_authserv_id_trust("mail.unknown-mta.org")
    assert res_untrusted.is_trusted is False
    assert res_untrusted.domain_matches_policy is False
    assert res_untrusted.status == AuthservTrustStatus.UNTRUSTED

    # Subdomain spoofing attempt (suffix does not match)
    res_spoof = validate_authserv_id_trust("mx.google.com.attacker.com")
    assert res_spoof.is_trusted is False
    assert res_spoof.domain_matches_policy is False
    assert res_spoof.status == AuthservTrustStatus.UNTRUSTED

    # Malformed / suspicious authserv-id tokens
    res_mal = validate_authserv_id_trust("mx.google.com; admin@evil.com")
    assert res_mal.is_trusted is False
    assert res_mal.domain_matches_policy is False
    assert res_mal.status == AuthservTrustStatus.SUSPICIOUS

    # Custom organization trust policy — Stage A.3: domain_matches_policy=True, is_trusted=False
    custom_policy = ["mail.internal-corp.enterprise", "gateway.bank.secure"]
    res_custom = validate_authserv_id_trust("edge01.mail.internal-corp.enterprise", custom_policy)
    assert res_custom.is_trusted is False
    assert res_custom.domain_matches_policy is True
    assert res_custom.status == AuthservTrustStatus.REPORTED


# ---------------------------------------------------------------------------
# 3. Reordered Authentication Headers
# ---------------------------------------------------------------------------
def test_case_03_reordered_authentication_headers():
    """
    When an email has reordered headers where the genuine boundary MTA is at index 1
    (upstream hop) while index 0 is an untrusted hop, the PASS at index 1 cannot be
    trusted as the recipient boundary assertion.
    """
    header_info = EmailHeaderInfo(
        authentication_results=[
            "internal-relay.corp; spf=none",
            "mx.google.com; spf=pass smtp.mailfrom=company.com; dkim=pass header.d=company.com",
        ]
    )
    auth_res = analyze_email_authentication(header_info)

    assert auth_res.boundary_authserv_id == "internal-relay.corp"
    assert auth_res.boundary_authserv_trust == AuthservTrustStatus.UNTRUSTED
    # The PASS finding was at index 1, not index 0
    assert auth_res.is_boundary_trusted is False
    assert any("upstream/lower headers (index > 0)" in w for w in auth_res.warnings)


# ---------------------------------------------------------------------------
# 4. Schema Safety: Missing Trust Information Must Not Default to True
# ---------------------------------------------------------------------------
def test_case_04_missing_trust_information():
    """
    Inspects all trust-related Boolean fields in models to verify that:
    - Missing trust information defaults to False, never True.
    - An empty email with no headers produces is_boundary_trusted=False.
    - Explicit unknown/untrusted states are preserved.
    """
    # 1. Pydantic model defaults
    hf_default = HeaderFinding(
        method="spf",
        result=AuthResultStatus.NONE,
        raw_result="none",
        source_header="Authentication-Results",
    )
    assert hf_default.is_boundary_mta is False
    assert hf_default.authserv_trust == AuthservTrustStatus.UNTRUSTED

    auth_summary_default = AuthEvidenceSummary(explanation="No auth")
    assert auth_summary_default.is_boundary_trusted is False
    assert auth_summary_default.boundary_authserv_trust == "UNTRUSTED"

    # 2. Analysis of empty header info
    empty_header = EmailHeaderInfo()
    auth_analysis = analyze_email_authentication(empty_header)
    assert auth_analysis.is_boundary_trusted is False
    assert auth_analysis.boundary_authserv_trust == AuthservTrustStatus.MISSING

    # 3. Fusion of empty analysis
    fusion = fuse_evidence(authentication_analysis=auth_analysis)
    assert fusion.auth_evidence.is_boundary_trusted is False
    assert fusion.auth_evidence.has_valid_authentication is False


# ---------------------------------------------------------------------------
# 5. Private IP URL (RFC 1918)
# ---------------------------------------------------------------------------
def test_case_05_private_ip_url():
    """
    Private IP addresses belong to local network infrastructure.
    They must NOT automatically be classified as malicious or HIGH risk.
    """
    for private_ip in ["10.0.0.1", "172.16.50.2", "192.168.1.254"]:
        url = f"http://{private_ip}/intranet/login"
        res = analyze_url(url)

        assert res.parse_status == ParseStatus.PARSED
        assert res.features.is_ip_literal is True
        assert res.features.ip_version == 4
        assert res.features.host_classification == HostClassification.PRIVATE
        assert any(o.rule_id == "RULE_PRIVATE_IP_HOST" for o in res.observations)
        assert any(o.severity == ObservationSeverity.LOW for o in res.observations if o.rule_id == "RULE_PRIVATE_IP_HOST")
        # Must NOT automatically be HIGH (malicious):
        assert res.heuristic_risk_category in (HeuristicRiskCategory.LOW, HeuristicRiskCategory.INFO)
        assert res.heuristic_risk_category != HeuristicRiskCategory.HIGH


# ---------------------------------------------------------------------------
# 6. Loopback IP URL (RFC 1122)
# ---------------------------------------------------------------------------
def test_case_06_loopback_url():
    """
    Loopback addresses target local host interface.
    Must be distinguished from private, public, and reserved space, and not labeled malicious.
    """
    for loop_ip in ["127.0.0.1", "127.0.0.53"]:
        url = f"http://{loop_ip}:8080/portal"
        res = analyze_url(url)

        assert res.features.is_ip_literal is True
        assert res.features.host_classification == HostClassification.LOOPBACK
        assert any(o.rule_id == "RULE_LOOPBACK_IP_HOST" for o in res.observations)
        assert any(o.severity == ObservationSeverity.LOW for o in res.observations if o.rule_id == "RULE_LOOPBACK_IP_HOST")


# ---------------------------------------------------------------------------
# 7. Link-Local IP URL (RFC 3927)
# ---------------------------------------------------------------------------
def test_case_07_link_local_url():
    """
    Link-local addresses (169.254.0.0/16) are valid only on local segment.
    Must be classified as LINK_LOCAL with LOW severity.
    """
    url = "http://169.254.169.254/latest/meta-data"
    res = analyze_url(url)

    assert res.features.is_ip_literal is True
    assert res.features.host_classification == HostClassification.LINK_LOCAL
    assert any(o.rule_id == "RULE_LINK_LOCAL_IP_HOST" for o in res.observations)
    assert any(o.severity == ObservationSeverity.LOW for o in res.observations if o.rule_id == "RULE_LINK_LOCAL_IP_HOST")


# ---------------------------------------------------------------------------
# 8. Documentation IP URL (RFC 5737 TEST-NET-1, TEST-NET-2, TEST-NET-3)
# ---------------------------------------------------------------------------
def test_case_08_documentation_ip_url():
    """
    Documentation IP addresses (TEST-NET-1: 192.0.2.0/24, TEST-NET-2: 198.51.100.0/24,
    TEST-NET-3: 203.0.113.0/24) are reserved for documentation and examples.
    They must NOT produce claims of real malicious destinations.
    """
    doc_ips = ["192.0.2.10", "198.51.100.99", "203.0.113.4"]
    for doc_ip in doc_ips:
        url = f"https://{doc_ip}/sample/path"
        res = analyze_url(url)

        assert res.features.is_ip_literal is True
        assert res.features.host_classification == HostClassification.DOCUMENTATION
        assert any(o.rule_id == "RULE_DOCUMENTATION_IP_HOST" for o in res.observations)
        # Severity must be INFO:
        doc_obs = [o for o in res.observations if o.rule_id == "RULE_DOCUMENTATION_IP_HOST"][0]
        assert doc_obs.severity == ObservationSeverity.INFO
        assert "not represent real malicious destinations" in doc_obs.description
        assert res.heuristic_risk_category == HeuristicRiskCategory.INFO


# ---------------------------------------------------------------------------
# 9. Public IP Literal URL
# ---------------------------------------------------------------------------
def test_case_09_public_ip_url():
    """
    Public IP literals are commonly used in phishing attacks to bypass domain reputation.
    Must be classified as PUBLIC with MEDIUM severity.
    """
    url = "http://93.184.216.34/login.html"
    res = analyze_url(url)

    assert res.features.is_ip_literal is True
    assert res.features.host_classification == HostClassification.PUBLIC
    assert any(o.rule_id == "RULE_PUBLIC_IP_HOST" for o in res.observations)
    pub_obs = [o for o in res.observations if o.rule_id == "RULE_PUBLIC_IP_HOST"][0]
    assert pub_obs.severity == ObservationSeverity.MEDIUM
    assert res.heuristic_risk_category in (HeuristicRiskCategory.MEDIUM, HeuristicRiskCategory.HIGH)


# ---------------------------------------------------------------------------
# 10. IPv6 URL Symmetry
# ---------------------------------------------------------------------------
def test_case_10_ipv6_url_symmetry():
    """
    Ensures IPv4 and IPv6 are handled completely consistently across:
    - Loopback (::1)
    - Link-local (fe80::1)
    - Documentation (2001:db8::1)
    - Private / Unique Local Address (fc00::1)
    - Public Global Unicast (2606:4700:4700::1111)
    """
    # 1. Loopback IPv6
    is_ip, ver, cls_loop = is_valid_ipv4_or_ipv6("::1")
    assert is_ip and ver == 6 and cls_loop == HostClassification.LOOPBACK
    res_loop = analyze_url("http://[::1]/status")
    assert any(o.rule_id == "RULE_LOOPBACK_IP_HOST" for o in res_loop.observations)

    # 2. Link-local IPv6
    is_ip, ver, cls_ll = is_valid_ipv4_or_ipv6("fe80::1ff:fe00:1")
    assert is_ip and ver == 6 and cls_ll == HostClassification.LINK_LOCAL
    res_ll = analyze_url("http://[fe80::1ff:fe00:1]/config")
    assert any(o.rule_id == "RULE_LINK_LOCAL_IP_HOST" for o in res_ll.observations)

    # 3. Documentation IPv6 (RFC 3849)
    is_ip, ver, cls_doc = is_valid_ipv4_or_ipv6("2001:db8::dead:beef")
    assert is_ip and ver == 6 and cls_doc == HostClassification.DOCUMENTATION
    res_doc = analyze_url("http://[2001:db8::dead:beef]/doc")
    assert any(o.rule_id == "RULE_DOCUMENTATION_IP_HOST" for o in res_doc.observations)

    # 4. Private IPv6 (RFC 4193 ULA)
    is_ip, ver, cls_priv = is_valid_ipv4_or_ipv6("fc00:1234:5678::1")
    assert is_ip and ver == 6 and cls_priv == HostClassification.PRIVATE
    res_priv = analyze_url("http://[fc00:1234:5678::1]/admin")
    assert any(o.rule_id == "RULE_PRIVATE_IP_HOST" for o in res_priv.observations)

    # 5. Public IPv6
    is_ip, ver, cls_pub = is_valid_ipv4_or_ipv6("2606:4700:4700::1111")
    assert is_ip and ver == 6 and cls_pub == HostClassification.PUBLIC
    res_pub = analyze_url("http://[2606:4700:4700::1111]/login")
    assert any(o.rule_id == "RULE_PUBLIC_IP_HOST" for o in res_pub.observations)


# ---------------------------------------------------------------------------
# 11. Nested Documentation IP Redirect
# ---------------------------------------------------------------------------
def test_case_11_nested_documentation_ip_redirect():
    """
    A URL containing an embedded redirect parameter pointing to a documentation IP
    must trigger RULE_NESTED_REDIRECT_DOCUMENTATION with INFO severity,
    and must NOT claim real malicious destinations.
    """
    url = "https://gateway.example.com/redirect?url=http://198.51.100.44/test"
    res = analyze_url(url)

    assert any(o.rule_id == "RULE_NESTED_REDIRECT_DOCUMENTATION" for o in res.observations)
    doc_redir_obs = [o for o in res.observations if o.rule_id == "RULE_NESTED_REDIRECT_DOCUMENTATION"][0]
    assert doc_redir_obs.severity == ObservationSeverity.INFO
    assert "Documentation IPs do not represent real malicious destinations" in doc_redir_obs.description
    assert not any(o.rule_id == "RULE_NESTED_REDIRECT_IP_LITERAL" for o in res.observations)


# ---------------------------------------------------------------------------
# 12. Legitimate External Tracking Redirect
# ---------------------------------------------------------------------------
def test_case_12_legitimate_external_tracking_redirect():
    """
    Ordinary email marketing or newsletter redirect links contain an external destination
    in query parameters (e.g. url=https://partner.com/article).
    This must NOT be classified as high risk or malicious; it is recorded with LOW severity
    and distinguished from suspicious attacks.
    """
    url = "https://newsletter-service.com/click?dest=https://legitimate-store.com/promo&user_id=123"
    res = analyze_url(url)

    assert any(o.rule_id == "RULE_NESTED_REDIRECT_URL" for o in res.observations)
    track_obs = [o for o in res.observations if o.rule_id == "RULE_NESTED_REDIRECT_URL"][0]
    assert track_obs.severity == ObservationSeverity.LOW
    assert "not inherently malicious" in track_obs.description
    assert res.heuristic_risk_category in (HeuristicRiskCategory.LOW, HeuristicRiskCategory.INFO)
    assert res.heuristic_risk_category != HeuristicRiskCategory.HIGH


# ---------------------------------------------------------------------------
# 13. Suspicious Nested Redirect
# ---------------------------------------------------------------------------
def test_case_13_suspicious_nested_redirect():
    """
    Structural indicators that increase risk on nested redirects:
    1. Redirect to a raw public IP literal -> RULE_NESTED_REDIRECT_IP_LITERAL (HIGH)
    2. Redirect containing userinfo credential syntax (@) -> RULE_NESTED_REDIRECT_CREDENTIAL_TRICK (HIGH)
    Both must produce HIGH severity observations.
    """
    # 1. Nested redirect to raw public IP literal
    url_ip = "https://portal.company.com/bounce?url=http://93.184.216.34/harvest"
    res_ip = analyze_url(url_ip)
    assert any(o.rule_id == "RULE_NESTED_REDIRECT_IP_LITERAL" for o in res_ip.observations)
    ip_obs = [o for o in res_ip.observations if o.rule_id == "RULE_NESTED_REDIRECT_IP_LITERAL"][0]
    assert ip_obs.severity == ObservationSeverity.HIGH
    assert res_ip.heuristic_risk_category == HeuristicRiskCategory.HIGH

    # 2. Nested redirect with credential deception syntax (@)
    url_at = "https://portal.company.com/bounce?target=https://trusted-brand.com@evil-phish.net/login"
    res_at = analyze_url(url_at)
    assert any(o.rule_id == "RULE_NESTED_REDIRECT_CREDENTIAL_TRICK" for o in res_at.observations)
    at_obs = [o for o in res_at.observations if o.rule_id == "RULE_NESTED_REDIRECT_CREDENTIAL_TRICK"][0]
    assert at_obs.severity == ObservationSeverity.HIGH
    assert res_at.heuristic_risk_category == HeuristicRiskCategory.HIGH
