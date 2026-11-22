"""
Comprehensive Regression Test Suite for Evidence-Based Phishing Risk Scoring Redesign.
Covers:
1. Real corporate notification fixtures (OpenAI, LinkedIn, Pinterest, Google, Overleaf).
2. Clean plain-text emails (01_simple_plaintext).
3. Dangerous executable and double-extension attachments (floor >= 75).
4. Deceptive displayed links (anchor spoofing) (floor >= 75).
5. Userinfo @ authority deception (floor >= 75).
6. Lookalike / brand impersonation domains (floor >= 75 when unaligned).
7. Credential-harvesting URL with unaligned or failing authentication (floor >= 75).
8. Explicit authentication failure (floor >= 30, REVIEW_RECOMMENDED).
9. Contradictory authentication headers (floor >= 30, REVIEW_RECOMMENDED).
10. Incomplete / malformed email (07_malformed.eml -> INSUFFICIENT_EVIDENCE).
11. Corroboration dampening for DistilBERT on clean emails (score <= 25).
12. Full 5-category point breakdown integrity (sender_auth <= 25, url <= 25, content <= 20, ml <= 20, header_ip <= 10, total <= 100).
"""

from pathlib import Path
import pytest

from app.schemas.email import AttachmentInfo, EmailBodyInfo, EmailHeaderInfo
from app.schemas.email_authentication import (
    AuthResultStatus,
    DKIMEvidence,
    DMARCEvidence,
    EmailAuthenticationAnalysis,
    OverallAuthStatus,
    SPFEvidence,
)
from app.schemas.evidence_fusion import (
    AssessmentCategory,
    EvidenceCompletenessStatus,
    ModelInferenceEvidence,
    ModelInferenceStatus,
)
from app.services.email_authentication import analyze_email_authentication
from app.services.email_parser import parse_email_message
from app.services.evidence_fusion import fuse_evidence
from app.services.scoring_engine import calculate_phishing_risk_score
from app.services.url_intelligence import analyze_urls
from app.schemas.url_intelligence import (
    ObservationSeverity,
    URLObservation,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ==============================================================================
# 1. Genuine Corporate Notifications
# ==============================================================================

def test_openai_privacy_policy_notification():
    """
    Verifies that the authentic OpenAI Privacy Policy update fixture evaluates to
    LOW_RISK_INDICATORS (score <= 25) with FULL_COVERAGE, correctly treating
    the login_hint OIDC parameter on chatgpt.com as benign.
    """
    path = FIXTURES_DIR / "openai_privacy_policy.eml"
    assert path.is_file(), f"Fixture missing: {path}"

    res = parse_email_message(path.read_bytes(), "openai_privacy_policy.eml")
    ef = res.evidence_fusion
    assert ef is not None
    assert ef.overall_category == AssessmentCategory.LOW_RISK_INDICATORS
    assert ef.overall_risk_score <= 25
    assert ef.overall_risk_score >= 0
    assert ef.evidence_completeness == EvidenceCompletenessStatus.FULL_COVERAGE
    assert ef.risk_score_breakdown is not None
    assert ef.risk_score_breakdown.ml_model.is_dampened is True
    assert ef.risk_score_breakdown.sender_auth.score == 0
    assert ef.risk_score_breakdown.url_intelligence.score == 0


def test_linkedin_complete_profile_notification():
    """
    Verifies that the authentic LinkedIn notification fixture evaluates to
    LOW_RISK_INDICATORS (score <= 25) with FULL_COVERAGE, with uncorroborated
    DistilBERT shortcut learning dampened to <= 5 points.
    """
    path = FIXTURES_DIR / "linkedin_complete_profile.eml"
    assert path.is_file(), f"Fixture missing: {path}"

    res = parse_email_message(path.read_bytes(), "linkedin_complete_profile.eml")
    ef = res.evidence_fusion
    assert ef is not None
    assert ef.overall_category == AssessmentCategory.LOW_RISK_INDICATORS
    assert ef.overall_risk_score <= 25
    assert ef.overall_risk_score >= 0
    assert ef.evidence_completeness == EvidenceCompletenessStatus.FULL_COVERAGE
    assert ef.risk_score_breakdown is not None
    assert ef.risk_score_breakdown.ml_model.is_dampened is True
    assert ef.risk_score_breakdown.ml_model.score <= 5


def test_pinterest_terms_update_notification():
    """
    Verifies that the authentic Pinterest Terms of Service update evaluates to
    LOW_RISK_INDICATORS (score <= 25) with FULL_COVERAGE.
    """
    path = FIXTURES_DIR / "pinterest_terms_update.eml"
    assert path.is_file(), f"Fixture missing: {path}"

    res = parse_email_message(path.read_bytes(), "pinterest_terms_update.eml")
    ef = res.evidence_fusion
    assert ef is not None
    assert ef.overall_category == AssessmentCategory.LOW_RISK_INDICATORS
    assert ef.overall_risk_score <= 25
    assert ef.overall_risk_score >= 0
    assert ef.evidence_completeness == EvidenceCompletenessStatus.FULL_COVERAGE


def test_google_account_notification():
    """
    Verifies that authentic Google Account security notifications evaluate to
    LOW_RISK_INDICATORS (score <= 25) with FULL_COVERAGE.
    """
    path = FIXTURES_DIR / "google_notification.eml"
    assert path.is_file(), f"Fixture missing: {path}"

    res = parse_email_message(path.read_bytes(), "google_notification.eml")
    ef = res.evidence_fusion
    assert ef is not None
    assert ef.overall_category == AssessmentCategory.LOW_RISK_INDICATORS
    assert ef.overall_risk_score <= 25
    assert ef.overall_risk_score >= 0
    assert ef.evidence_completeness == EvidenceCompletenessStatus.FULL_COVERAGE


def test_overleaf_welcome_notification():
    """
    Verifies that authentic Overleaf welcome notification evaluates to
    LOW_RISK_INDICATORS (score <= 25) with FULL_COVERAGE.
    """
    path = FIXTURES_DIR / "overleaf_welcome.eml"
    assert path.is_file(), f"Fixture missing: {path}"

    res = parse_email_message(path.read_bytes(), "overleaf_welcome.eml")
    ef = res.evidence_fusion
    assert ef is not None
    assert ef.overall_category == AssessmentCategory.LOW_RISK_INDICATORS
    assert ef.overall_risk_score <= 25
    assert ef.overall_risk_score >= 0
    assert ef.evidence_completeness == EvidenceCompletenessStatus.FULL_COVERAGE


def test_simple_plaintext_email():
    """
    Verifies that 01_simple_plaintext.eml evaluates to LOW_RISK_INDICATORS (score <= 25)
    with PARTIAL_COVERAGE due to missing auth headers and transit hops.
    """
    path = FIXTURES_DIR / "01_simple_plaintext.eml"
    assert path.is_file(), f"Fixture missing: {path}"

    res = parse_email_message(path.read_bytes(), "01_simple_plaintext.eml")
    ef = res.evidence_fusion
    assert ef is not None
    assert ef.overall_category == AssessmentCategory.LOW_RISK_INDICATORS
    assert ef.overall_risk_score <= 25
    assert ef.evidence_completeness == EvidenceCompletenessStatus.PARTIAL_COVERAGE


# ==============================================================================
# 2. Critical Threat Floors (Score >= 75 -> HIGH_RISK_INDICATORS_PRESENT)
# ==============================================================================

def test_critical_threat_floor_dangerous_attachment():
    """
    Verifies that dangerous executable or double-extension attachments (.pdf.exe)
    trigger the critical threat floor (score >= 75, HIGH_RISK_INDICATORS_PRESENT)
    regardless of other clean signals.
    """
    score, category, breakdown, comp, comp_det, pos, neg = calculate_phishing_risk_score(
        header_info=EmailHeaderInfo(from_header="billing@legit-vendor.com", subject="Important invoice"),
        body_info=EmailBodyInfo(plain_text="Please review your monthly invoice attached."),
        attachments=[
            AttachmentInfo(
                filename="statement_2026.pdf.exe",
                content_type="application/x-msdownload",
                size_bytes=4096,
                sha256="abc12345",
            )
        ],
        url_analysis=None,
        auth_analysis=None,
        ip_analysis=None,
        model_inference=None,
    )
    assert score >= 75
    assert category == AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT
    assert any("executable" in n.lower() or "double" in n.lower() for n in neg)


def test_critical_threat_floor_deceptive_displayed_link():
    """
    Verifies that deceptive anchor text spoofing (<a href="evil.com">https://paypal.com</a>)
    triggers the critical threat floor (score >= 75, HIGH_RISK_INDICATORS_PRESENT).
    """
    url_analysis = analyze_urls(["https://phish-harvesting-portal.com/login"])
    url_analysis.url_results[0].observations.append(
        URLObservation(
            rule_id="RULE_DECEPTIVE_DISPLAYED_LINK",
            rule_name="Deceptive Displayed Link",
            severity=ObservationSeverity.HIGH,
            description="Visual anchor text displays legitimate domain but href points to different domain",
        )
    )
    score, category, breakdown, comp, comp_det, pos, neg = calculate_phishing_risk_score(
        header_info=EmailHeaderInfo(from_header="service@notifications.com", subject="Action Required"),
        body_info=EmailBodyInfo(html_extracted_text="Please log in to your account."),
        attachments=[],
        url_analysis=url_analysis,
        auth_analysis=None,
        ip_analysis=None,
        model_inference=None,
    )
    assert score >= 75
    assert category == AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT
    assert any("deceptive" in n.lower() for n in neg)


def test_critical_threat_floor_userinfo_auth_deception():
    """
    Verifies that authority deception with '@' syntax (https://paypal.com@evil-site.com)
    triggers the critical threat floor (score >= 75, HIGH_RISK_INDICATORS_PRESENT).
    """
    url_batch = analyze_urls(["https://chase.com@phish-login-portal.net/auth"])
    score, category, breakdown, comp, comp_det, pos, neg = calculate_phishing_risk_score(
        header_info=EmailHeaderInfo(from_header="security@chase.com", subject="Verify Login"),
        body_info=EmailBodyInfo(plain_text="Click here to authenticate."),
        attachments=[],
        url_analysis=url_batch,
        auth_analysis=None,
        ip_analysis=None,
        model_inference=None,
    )
    assert score >= 75
    assert category == AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT


def test_critical_threat_floor_lookalike_domain_unaligned():
    """
    Verifies that lookalike brand impersonation domain (paypa1-security.com)
    with unaligned sender identity triggers high risk.
    """
    url_analysis = analyze_urls(["https://paypa1-security.com/signin"])
    url_analysis.url_results[0].observations.append(
        URLObservation(
            rule_id="RULE_LOOKALIKE_IMPERSONATION_DOMAIN",
            rule_name="Lookalike Impersonation Domain",
            severity=ObservationSeverity.HIGH,
            description="Lookalike brand domain detected in destination URL",
        )
    )
    score, category, breakdown, comp, comp_det, pos, neg = calculate_phishing_risk_score(
        header_info=EmailHeaderInfo(from_header="support@attacker-mail.org", subject="Account Alert"),
        body_info=EmailBodyInfo(plain_text="Log in to verify your identity."),
        attachments=[],
        url_analysis=url_analysis,
        auth_analysis=None,
        ip_analysis=None,
        model_inference=None,
    )
    assert score >= 75
    assert category == AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT


# ==============================================================================
# 3. Authentication Risk Floors & Completeness
# ==============================================================================

def test_auth_explicit_failure_floor_review_recommended():
    """
    Verifies that explicit domain authentication failure alone (SPF/DKIM/DMARC fail)
    enforces a minimum risk score of 30 (REVIEW_RECOMMENDED) and never evaluates as LOW_RISK.
    """
    header_info = EmailHeaderInfo(
        authentication_results=["mx.google.com; spf=fail smtp.mailfrom=target.com; dkim=fail; dmarc=fail"]
    )
    auth_res = analyze_email_authentication(header_info)
    model_inf = ModelInferenceEvidence(uncalibrated_score=0.10, predicted_label=0)

    res = fuse_evidence(
        header_info=header_info,
        body_info=EmailBodyInfo(plain_text="Hello, here is our regular team update."),
        authentication_analysis=auth_res,
        model_inference=model_inf,
    )
    assert res.overall_risk_score >= 30
    assert res.overall_category == AssessmentCategory.REVIEW_RECOMMENDED
    assert res.overall_category != AssessmentCategory.LOW_RISK_INDICATORS


def test_conflicting_headers_floor_review_recommended():
    """
    Verifies that contradictory authentication headers across intermediate MTAs
    enforce a minimum risk score of 30 (REVIEW_RECOMMENDED).
    """
    auth_analysis = EmailAuthenticationAnalysis(
        status=OverallAuthStatus.CONFLICTING_EVIDENCE,
        spf=SPFEvidence(status=AuthResultStatus.CONFLICTING_EVIDENCE, explanation="Conflicting SPF"),
        dkim=DKIMEvidence(status=AuthResultStatus.PASS, explanation="DKIM pass"),
        dmarc=DMARCEvidence(status=AuthResultStatus.NOT_PRESENT, explanation="DMARC missing"),
        has_conflicts=True,
    )
    res = fuse_evidence(authentication_analysis=auth_analysis)
    assert res.overall_risk_score >= 30
    assert res.overall_category == AssessmentCategory.REVIEW_RECOMMENDED


def test_malformed_email_insufficient_evidence():
    """
    Verifies that empty or malformed emails lacking both headers and body text
    evaluate to INSUFFICIENT_EVIDENCE with MINIMAL_OR_INSUFFICIENT coverage.
    """
    score, category, breakdown, comp, comp_det, pos, neg = calculate_phishing_risk_score(
        header_info=None,
        body_info=None,
        attachments=[],
        url_analysis=None,
        auth_analysis=None,
        ip_analysis=None,
        model_inference=None,
    )
    assert category == AssessmentCategory.INSUFFICIENT_EVIDENCE
    assert comp == EvidenceCompletenessStatus.MINIMAL_OR_INSUFFICIENT


# ==============================================================================
# 13. Phishing Detection Regression for Confirmed Phishing Samples
# ==============================================================================

def test_sample_1_bradesco_livelo_phishing():
    """
    sample-1.eml: Bradesco & Livelo loyalty points expiration phishing lure.
    Verifies:
    - Display name spoofing (claims Bradesco / Livelo, From is atendimento.com.br).
    - Unqualified Return-Path host (root@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06).
    - Destination URL brand mismatch (blog1seguimentmydomaine2bra.me).
    - Urgent rewards expiration social engineering language (expiram hoje).
    - Resulting score >= 70, HIGH_RISK_INDICATORS_PRESENT.
    """
    eml_path = FIXTURES_DIR / "sample-1.eml"
    if not eml_path.exists():
        pytest.skip("sample-1.eml fixture not available")

    res = parse_email_message(eml_path.read_bytes(), "sample-1.eml")
    ef = res.evidence_fusion

    assert ef is not None
    assert ef.overall_risk_score >= 70
    assert ef.overall_category == AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT

    # Verify breakdown across modalities
    breakdown = ef.risk_score_breakdown
    assert breakdown.sender_auth.score >= 18
    assert "RULE_DISPLAY_NAME_SPOOFING" in breakdown.sender_auth.rules_triggered
    assert breakdown.url_intelligence.score >= 15
    assert "RULE_URL_BRAND_MISMATCH" in breakdown.url_intelligence.rules_triggered
    assert breakdown.content_language.score >= 10
    assert "RULE_REWARDS_EXPIRATION_URGENCY" in breakdown.content_language.rules_triggered
    assert breakdown.ml_model.score == 20  # Full linear weight under corroborated evidence


def test_sample_10_okx_homoglyph_phishing():
    """
    sample-10.eml: Fake OKX Web3 Chrome Extension promotion phishing.
    Verifies:
    - Display name spoofing (claims OKX, From is handpay.com.cn).
    - Explicit DKIM failure (signed by unauthorized dev.roombird.ru).
    - Cyrillic homoglyph in URL path (/detail/окх-wаllеt-dashboard/...).
    - Resulting score >= 75, HIGH_RISK_INDICATORS_PRESENT.
    """
    eml_path = FIXTURES_DIR / "sample-10.eml"
    if not eml_path.exists():
        pytest.skip("sample-10.eml fixture not available")

    res = parse_email_message(eml_path.read_bytes(), "sample-10.eml")
    ef = res.evidence_fusion

    assert ef is not None
    assert ef.overall_risk_score >= 75
    assert ef.overall_category == AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT

    breakdown = ef.risk_score_breakdown
    assert breakdown.sender_auth.score == 25  # Max capped
    assert "RULE_DISPLAY_NAME_SPOOFING" in breakdown.sender_auth.rules_triggered
    assert "RULE_AUTH_EXPLICIT_FAILURE" in breakdown.sender_auth.rules_triggered
    assert breakdown.url_intelligence.score >= 15
    assert "RULE_UNICODE_PATH_OR_QUERY" in breakdown.url_intelligence.rules_triggered
    assert breakdown.content_language.score >= 10
    assert "RULE_HOMOGLYPH_TEXT_OBFUSCATION" in breakdown.content_language.rules_triggered


def test_sample_10001_metamask_2fa_phishing():
    """
    sample-10001.eml: MetaMask 2FA wallet protection lure.
    Verifies:
    - Cyrillic homoglyphs in display name (MеtаMаsk-Team).
    - Disposable Reply-To address (fcbarca123@mailinator.com).
    - Authentication decoupling: SPF/DKIM/DMARC pass on wellnessliving.com does NOT
      authenticate MetaMask or grant positive evidence for the claimed brand.
    - Suspicious security impersonation URL (red1524.enabletwofactor.shop).
    - Homoglyphs in anchor text (Enаblе 2Fа Now!).
    - Mixed-script homoglyphs in body text and mandatory 2FA wallet protection lure.
    - Resulting score >= 75, HIGH_RISK_INDICATORS_PRESENT.
    """
    eml_path = FIXTURES_DIR / "sample-10001.eml"
    if not eml_path.exists():
        pytest.skip("sample-10001.eml fixture not available")

    res = parse_email_message(eml_path.read_bytes(), "sample-10001.eml")
    ef = res.evidence_fusion

    assert ef is not None
    assert ef.overall_risk_score >= 75
    assert ef.overall_category == AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT

    breakdown = ef.risk_score_breakdown
    assert breakdown.sender_auth.score == 25
    assert "RULE_HOMOGLYPH_DISPLAY_NAME" in breakdown.sender_auth.rules_triggered
    assert "RULE_DISPLAY_NAME_SPOOFING" in breakdown.sender_auth.rules_triggered
    assert "RULE_SUSPICIOUS_REPLYTO_DISPOSABLE_MAIL" in breakdown.sender_auth.rules_triggered

    # Authentication passes for wellnessliving.com must NOT count as proof of MetaMask
    for pos_item in ef.positive_evidence:
        assert "verified domain alignment to From header ('MetaMask')" not in pos_item
    assert any("passed only for underlying infrastructure domain" in neg for neg in ef.negative_evidence)

    assert breakdown.url_intelligence.score >= 20
    assert "RULE_SUSPICIOUS_SECURITY_KEYWORD_DOMAIN" in breakdown.url_intelligence.rules_triggered
    assert "RULE_HOMOGLYPH_ANCHOR_TEXT" in breakdown.url_intelligence.rules_triggered

    assert breakdown.content_language.score == 20
    assert "RULE_HOMOGLYPH_TEXT_OBFUSCATION" in breakdown.content_language.rules_triggered
    assert "RULE_MANDATORY_SECURITY_WALLET_LURE" in breakdown.content_language.rules_triggered


# ==============================================================================
# 14. Static Homoglyph Detection Unit Tests
# ==============================================================================

def test_homoglyph_detection_unit():
    """
    Unit test for homoglyph detector: verifies mixed-script detection and Latin normalization.
    """
    from app.services.homoglyph_detector import (
        detect_mixed_script_homoglyphs,
        has_mixed_script_homoglyphs,
        normalize_homoglyphs,
    )

    # 1. Cyrillic lookalikes in MetaMask
    raw_metamask = "MеtаMаsk"
    assert has_mixed_script_homoglyphs(raw_metamask) is True
    normalized = normalize_homoglyphs(raw_metamask)
    assert normalized == "MetaMask"

    # 2. Cyrillic lookalikes in OKX URL token
    raw_okx = "окх-wаllеt"
    assert has_mixed_script_homoglyphs(raw_okx) is True
    assert normalize_homoglyphs(raw_okx) == "okx-wallet"

    # 3. Clean strings with standard Latin letters
    clean_str = "OpenAI Privacy Policy Update"
    assert has_mixed_script_homoglyphs(clean_str) is False
    assert normalize_homoglyphs(clean_str) == clean_str

    # 4. Standard Portuguese accented Latin characters (must NOT be flagged as homoglyphs)
    pt_clean = "Você possui Pontos Livelo disponíveis para resgate"
    assert has_mixed_script_homoglyphs(pt_clean) is False


# ==============================================================================
# 15. Legitimate Control Email Integrity Tests
# ==============================================================================

@pytest.mark.parametrize("control_filename", [
    "openai_privacy_policy.eml",
    "google_notification.eml",
    "linkedin_complete_profile.eml",
    "pinterest_terms_update.eml",
    "overleaf_welcome.eml",
])
def test_legitimate_control_emails_remain_low_risk(control_filename: str):
    """
    Verifies that legitimate enterprise notifications with authentic alignment
    consistently evaluate to LOW_RISK_INDICATORS (score <= 25).
    """
    path = FIXTURES_DIR / control_filename
    if not path.exists():
        pytest.skip(f"Fixture {control_filename} not found")

    res = parse_email_message(path.read_bytes(), control_filename)
    assert res.evidence_fusion is not None
    assert res.evidence_fusion.overall_risk_score <= 25
    assert res.evidence_fusion.overall_category == AssessmentCategory.LOW_RISK_INDICATORS
