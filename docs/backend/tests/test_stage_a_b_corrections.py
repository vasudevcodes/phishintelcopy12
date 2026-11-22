"""
Regression and verification test suite for Stage A and Stage B corrections.
Covers all 15 scenarios specified in Stage C:
1. The original LinkedIn email fixture.
2. Long legitimate tracking URLs.
3. Short suspicious URLs.
4. IP-literal URLs (public, private, reserved).
5. Punycode / IDN homograph URLs.
6. URLs containing credential-like (@) syntax in authority.
7. Nested redirect URLs in query parameters.
8. Long suspicious URL paths.
9. Valid trusted authentication evidence at boundary MTA.
10. Untrusted Authentication-Results headers (upstream-only PASS).
11. Explicit SPF/DKIM/DMARC failures.
12. Missing authentication evidence (NOT_PRESENT != FAIL).
13. High model score without independent evidence.
14. High model score combined with meaningful independent evidence.
15. Dynamic explanation accuracy and absence of invented findings.
"""

from pathlib import Path
import socket
import pytest

from app.schemas.email import EmailHeaderInfo
from app.schemas.evidence_fusion import (
    AssessmentCategory,
    ModelInferenceEvidence,
)
from app.schemas.email_authentication import (
    AuthResultStatus,
    OverallAuthStatus,
)
from app.schemas.url_intelligence import (
    HeuristicRiskCategory,
    ObservationSeverity,
)
from app.services.email_parser import parse_email_message
from app.services.email_authentication import analyze_email_authentication
from app.services.evidence_fusion import fuse_evidence
from app.services.url_intelligence import analyze_url, analyze_urls


FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def guard_no_network(monkeypatch):
    """
    Enforces strict zero network access during testing.
    Any attempt to connect to external IPs or perform DNS lookups raises RuntimeError.
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
            raise RuntimeError(f"DNS lookup forbidden during test: {host}")
        return orig_getaddrinfo(host, *args, **kwargs)

    def fail_gethostbyname(host):
        if host not in ("127.0.0.1", "localhost", "::1", "testserver"):
            raise RuntimeError(f"DNS resolution forbidden during test: {host}")
        return orig_gethostbyname(host)

    monkeypatch.setattr(socket.socket, "connect", fail_connect)
    monkeypatch.setattr(socket, "getaddrinfo", fail_dns)
    monkeypatch.setattr(socket, "gethostbyname", fail_gethostbyname)


# 1. Original LinkedIn email
def test_case_01_original_linkedin_email():
    fixture_path = FIXTURES_DIR / "linkedin_complete_profile.eml"
    with open(fixture_path, "rb") as f:
        content = f.read()

    resp = parse_email_message(content, "Complete your profile.eml")
    fusion = resp.evidence_fusion
    assert fusion is not None

    # Must NOT be HIGH_RISK_INDICATORS_PRESENT
    assert fusion.overall_category in (
        AssessmentCategory.LOW_RISK_INDICATORS,
        AssessmentCategory.REVIEW_RECOMMENDED,
    )
    assert fusion.overall_category != AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT
    # URL highest heuristic risk must be LOW (long queries alone do not produce MEDIUM/HIGH)
    assert fusion.url_evidence.highest_heuristic_risk == "LOW"
    # Stage A.2: For offline .eml uploads, is_boundary_trusted is always False even when
    # SPF/DKIM/DMARC all pass — authserv-id domain matching is not provenance proof.
    assert fusion.auth_evidence.is_boundary_trusted is False
    assert fusion.auth_evidence.spf_status == "PASS"
    assert fusion.auth_evidence.dkim_status == "PASS"
    assert fusion.auth_evidence.dmarc_status == "PASS"
    # Reasoning must not fabricate conflicting authentication headers
    assert "conflicting authentication headers" not in fusion.reasoning


# 2. Long legitimate tracking URLs
def test_case_02_long_legitimate_tracking_urls():
    # Long query string (600 characters) with HMAC token
    query_param = "a" * 600
    url = f"https://tracking.newsletter.example.com/click?token={query_param}&campaign=202610"
    res = analyze_url(url)

    # Must NOT produce MEDIUM or HIGH risk on query length alone
    assert res.heuristic_risk_category in (HeuristicRiskCategory.INFO, HeuristicRiskCategory.LOW)
    assert any(o.rule_id == "RULE_LONG_QUERY_STRING" for o in res.observations)
    assert not any(o.rule_id == "RULE_EXCESSIVE_URL_LENGTH" for o in res.observations)


# 3. Short suspicious URLs
def test_case_03_short_suspicious_urls():
    # Short URL targeting raw public IP literal host
    url = "http://93.184.216.34/login"
    res = analyze_url(url)

    assert res.heuristic_risk_category in (HeuristicRiskCategory.MEDIUM, HeuristicRiskCategory.HIGH)
    assert any(o.rule_id == "RULE_PUBLIC_IP_HOST" for o in res.observations)


# 4. IP-literal URLs
def test_case_04_ip_literal_urls():
    # Private IP literal host
    url_priv = "http://10.0.0.1/admin"
    res_priv = analyze_url(url_priv)
    assert res_priv.heuristic_risk_category in (HeuristicRiskCategory.LOW, HeuristicRiskCategory.MEDIUM)
    assert res_priv.heuristic_risk_category != HeuristicRiskCategory.HIGH
    assert any(o.rule_id == "RULE_PRIVATE_IP_HOST" for o in res_priv.observations)

    # Loopback IP host
    url_loop = "http://127.0.0.1:8080/portal"
    res_loop = analyze_url(url_loop)
    assert any(o.rule_id == "RULE_LOOPBACK_IP_HOST" for o in res_loop.observations)


# 5. Punycode URLs
def test_case_05_punycode_urls():
    url = "https://xn--pypal-4ve.com/signin"
    res = analyze_url(url)
    assert res.heuristic_risk_category in (HeuristicRiskCategory.MEDIUM, HeuristicRiskCategory.HIGH)
    assert any(o.rule_id == "RULE_PUNYCODE_HOST" for o in res.observations)


# 6. URLs containing credential-like syntax
def test_case_06_credential_like_syntax():
    url = "https://secure.chase.com@phish-login.com/auth"
    res = analyze_url(url)
    assert res.heuristic_risk_category == HeuristicRiskCategory.HIGH
    assert any(o.rule_id == "RULE_USERINFO_AUTH" for o in res.observations)


# 7. Nested redirect URLs
def test_case_07_nested_redirect_urls():
    # Nested redirect to external domain (standard tracking/redirection: LOW risk)
    url_ext = "https://portal.example.com/redirect?url=https://attacker-harvest.com/login"
    res_ext = analyze_url(url_ext)
    assert any(o.rule_id == "RULE_NESTED_REDIRECT_URL" for o in res_ext.observations)
    assert res_ext.heuristic_risk_category in (HeuristicRiskCategory.LOW, HeuristicRiskCategory.INFO)

    # Nested redirect targeting raw public IP literal (HIGH risk)
    url_ip = "https://portal.example.com/redirect?dest=http://93.184.216.34/drop"
    res_ip = analyze_url(url_ip)
    assert any(o.rule_id == "RULE_NESTED_REDIRECT_IP_LITERAL" for o in res_ip.observations)
    assert res_ip.heuristic_risk_category == HeuristicRiskCategory.HIGH


# 8. Long suspicious paths
def test_case_08_long_suspicious_paths():
    # URL path > 200 characters without query
    deep_path = "/wp-content/plugins/revslider/temp/upload/sess_" + ("x" * 160) + "/login.php"
    url = f"https://compromised-site.com{deep_path}"
    res = analyze_url(url)
    assert any(o.rule_id == "RULE_EXCESSIVE_PATH_LENGTH" for o in res.observations)
    assert res.heuristic_risk_category == HeuristicRiskCategory.MEDIUM


# 9. Valid trusted authentication evidence
def test_case_09_valid_trusted_authentication_evidence():
    """
    Stage A.2 update: For offline .eml uploads, is_boundary_trusted is always False
    regardless of authserv-id domain match.  SPF/DKIM/DMARC PASS are recorded as PASS
    but their provenance is REPORTED_AUTHENTICATION, not TRUSTED_RECEIVER_EVIDENCE.
    """
    header_info = EmailHeaderInfo(
        authentication_results=["mx.google.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com"],
        received_spf=["pass (google.com: domain of sender@example.com designates 198.51.100.1 as permitted sender) client-ip=198.51.100.1;"],
    )
    auth_res = analyze_email_authentication(header_info)
    # Stage A.2: is_boundary_trusted is always False for offline uploads
    assert auth_res.is_boundary_trusted is False
    assert auth_res.boundary_authserv_id == "mx.google.com"
    # The PASS assertions are present (they are REPORTED claims)
    assert auth_res.spf.status == AuthResultStatus.PASS
    assert auth_res.dkim.status == AuthResultStatus.PASS
    assert auth_res.dmarc.status == AuthResultStatus.PASS
    # Provenance must be REPORTED, not TRUSTED
    from app.schemas.email_authentication import ProvenanceStatus
    assert auth_res.provenance_status == ProvenanceStatus.REPORTED_AUTHENTICATION


# 10. Untrusted Authentication-Results headers
def test_case_10_untrusted_authentication_results_headers():
    # Boundary MTA (index 0) has NO pass results; only upstream internal hop (index 1) has PASS
    header_info = EmailHeaderInfo(
        authentication_results=[
            "mx.google.com; dmarc=fail (p=NONE) header.from=spoofed.com",
            "untrusted.internal.relay; spf=pass smtp.mailfrom=spoofed.com; dkim=pass header.d=spoofed.com",
        ]
    )
    auth_res = analyze_email_authentication(header_info)
    assert auth_res.is_boundary_trusted is False

    fusion = fuse_evidence(authentication_analysis=auth_res)
    assert fusion.auth_evidence.is_boundary_trusted is False
    assert fusion.overall_category == AssessmentCategory.REVIEW_RECOMMENDED
    # Stage A.2: contributing factor text updated — check for "upstream" or "untrusted" in factors
    assert any(
        "upstream" in f.lower() or "untrusted" in f.lower() or "reported" in f.lower()
        for f in fusion.contributing_factors
    ), f"Expected upstream/untrusted/reported in contributing factors: {fusion.contributing_factors}"


# 11. Explicit SPF/DKIM/DMARC failures
def test_case_11_explicit_auth_failures():
    header_info = EmailHeaderInfo(
        authentication_results=["mx.google.com; spf=fail smtp.mailfrom=bank.com; dkim=fail header.d=bank.com; dmarc=fail (p=REJECT) header.from=bank.com"]
    )
    auth_res = analyze_email_authentication(header_info)
    assert auth_res.spf.status == AuthResultStatus.FAIL
    assert auth_res.dmarc.status == AuthResultStatus.FAIL

    # Isolated auth failure without URL or text indicators -> REVIEW_RECOMMENDED
    fusion_isolated = fuse_evidence(authentication_analysis=auth_res)
    assert fusion_isolated.overall_category == AssessmentCategory.REVIEW_RECOMMENDED
    assert fusion_isolated.auth_evidence.has_explicit_failure is True

    # Auth failure corroborated by elevated text model score -> HIGH_RISK_INDICATORS_PRESENT
    model_inf = ModelInferenceEvidence(uncalibrated_score=0.88, predicted_label=1)
    fusion_corrob = fuse_evidence(authentication_analysis=auth_res, model_inference=model_inf)
    assert fusion_corrob.overall_category == AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT
    assert "explicit domain authentication failure" in fusion_corrob.reasoning


# 12. Missing authentication evidence
def test_case_12_missing_authentication_evidence():
    # Empty headers with no SPF, DKIM, or DMARC
    header_info = EmailHeaderInfo()
    auth_res = analyze_email_authentication(header_info)
    assert auth_res.status == OverallAuthStatus.NO_EVIDENCE
    assert auth_res.spf.status == AuthResultStatus.NOT_PRESENT

    fusion = fuse_evidence(authentication_analysis=auth_res)
    # Missing auth alone must NOT be treated as explicit failure
    assert fusion.auth_evidence.has_explicit_failure is False
    assert fusion.auth_evidence.has_valid_authentication is False
    assert fusion.overall_category in (
        AssessmentCategory.LOW_RISK_INDICATORS,
        AssessmentCategory.INSUFFICIENT_EVIDENCE,
    )


# 13. High model score without independent evidence
def test_case_13_high_model_score_without_independent_evidence():
    # Model indicates elevated phishing similarity (0.92), but URLs are clean and auth is PASS
    url_batch = analyze_urls(["https://legit-portal.example.com/welcome"])
    header_info = EmailHeaderInfo(
        authentication_results=["mx.google.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass"],
    )
    auth_res = analyze_email_authentication(header_info)
    model_inf = ModelInferenceEvidence(uncalibrated_score=0.92, predicted_label=1)

    fusion = fuse_evidence(
        url_analysis=url_batch,
        authentication_analysis=auth_res,
        model_inference=model_inf,
    )
    # Must NOT produce HIGH_RISK without independent corroboration
    assert fusion.overall_category in (
        AssessmentCategory.LOW_RISK_INDICATORS,
        AssessmentCategory.REVIEW_RECOMMENDED,
    )
    assert fusion.overall_category != AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT


# 14. High model score combined with meaningful independent evidence
def test_case_14_high_model_score_with_meaningful_independent_evidence():
    # High model score (0.90) + severe URL risk (credential syntax @)
    url_batch_severe = analyze_urls(["https://bank.com@phish-harvest.net/login"])
    model_inf = ModelInferenceEvidence(uncalibrated_score=0.90, predicted_label=1)

    fusion_severe = fuse_evidence(
        url_analysis=url_batch_severe,
        model_inference=model_inf,
    )
    assert fusion_severe.overall_category == AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT

    # High model score (0.90) + moderate URL anomaly (explicit non-default port) on unauthenticated email
    url_batch_med = analyze_urls(["https://portal.com:8080/login"])
    fusion_unauth = fuse_evidence(
        url_analysis=url_batch_med,
        model_inference=model_inf,
    )
    assert fusion_unauth.overall_category == AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT


# 15. Dynamic explanation accuracy
def test_case_15_dynamic_explanation_accuracy():
    """
    Stage A.2 update: For offline .eml uploads, authentication cannot be verified as
    boundary-trusted (is_boundary_trusted=False, has_valid_authentication=False).

    Clean email with low model score 0.12 and PASS auth — the application correctly
    produces INSUFFICIENT_EVIDENCE because authentication provenance is REPORTED,
    not independently established.  This is the correct and accurate outcome.

    The reasoning must still accurately describe the available evidence.
    """
    # Clean email with PASS authentication and low model score
    url_batch = analyze_urls(["https://example.com/home"])
    header_info = EmailHeaderInfo(
        authentication_results=["mx.google.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass"],
    )
    auth_res = analyze_email_authentication(header_info)
    model_inf = ModelInferenceEvidence(uncalibrated_score=0.12, predicted_label=0)

    fusion = fuse_evidence(
        url_analysis=url_batch,
        authentication_analysis=auth_res,
        model_inference=model_inf,
    )
    # Stage A.2: has_trusted_auth_pass=False for offline uploads → INSUFFICIENT_EVIDENCE (correct)
    assert fusion.overall_category in (
        AssessmentCategory.LOW_RISK_INDICATORS,
        AssessmentCategory.INSUFFICIENT_EVIDENCE,
    )
    assert "conflicting authentication headers" not in fusion.reasoning
    assert "Model evidence: DistilBERT NLP uncalibrated phishing score 0.120" in fusion.reasoning
    # Authentication evidence in the reasoning: reported, not boundary-verified
    assert "Authentication evidence:" in fusion.reasoning
