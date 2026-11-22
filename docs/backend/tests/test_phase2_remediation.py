"""
Comprehensive Phase 2 Regression Test Suite for PhishIntel.
Verifies safe false-positive remediation and detection preservation across 12 distinct scenarios:

1. Genuine LinkedIn "Complete your profile" email.
2. Legitimate long tracking URLs (>250 chars).
3. Clean plain-text business emails.
4. Legitimate newsletters.
5. Forged Authentication-Results PASS headers.
6. Forged Authentication-Results FAIL headers.
7. Credential-harvesting URLs.
8. Userinfo @ authority deception.
9. Public IP-literal URLs.
10. Punycode and nested redirect attacks.
11. Legitimate emails with unusual but harmless URL structures.
12. Genuine phishing emails with valid authentication claims.
"""

from pathlib import Path
import pytest

from app.schemas.email import EmailHeaderInfo, ExtractedURL
from app.schemas.email_authentication import (
    AuthResultStatus,
    EmailAuthenticationAnalysis,
    OverallAuthStatus,
    ProvenanceStatus,
)
from app.schemas.evidence_fusion import (
    AssessmentCategory,
    ModelInferenceEvidence,
    ModelInferenceStatus,
)
from app.schemas.url_intelligence import HeuristicRiskCategory
from app.services.email_authentication import (
    analyze_email_authentication,
)
from app.services.email_parser import parse_email_message
from app.services.evidence_fusion import fuse_evidence
from app.services.url_intelligence import (
    analyze_email_extracted_urls,
    analyze_url,
    analyze_urls,
)


# ==============================================================================
# Scenario 1: Genuine LinkedIn Complete your profile email
# ==============================================================================
def test_01_genuine_linkedin_complete_profile_eml():
    """
    Verifies that the authentic LinkedIn notification fixture evaluates to LOW_RISK_INDICATORS
    (never HIGH_RISK_INDICATORS_PRESENT), accurately reporting unverified offline pass
    without falsely alleging contradictory/conflicting headers.
    """
    fixture_path = Path("backend/tests/fixtures/linkedin_complete_profile.eml")
    if not fixture_path.is_file():
        fixture_path = Path("tests/fixtures/linkedin_complete_profile.eml")
    assert fixture_path.is_file(), f"Fixture missing at {fixture_path}"

    with open(fixture_path, "rb") as f:
        raw_bytes = f.read()

    res = parse_email_message(raw_bytes, "linkedin_complete_profile.eml")
    assert res.url_analysis is not None
    assert res.evidence_fusion is not None

    # URL inspection: tracking links must not exceed LOW severity
    assert res.url_analysis.highest_risk_category in (
        HeuristicRiskCategory.INFO,
        HeuristicRiskCategory.LOW,
    ), f"Expected URL risk <= LOW, got {res.url_analysis.highest_risk_category}"

    # Model inference: uncalibrated score is high due to phrase shortcut learning
    assert res.model_inference is not None
    assert res.model_inference.uncalibrated_score is not None
    assert res.model_inference.uncalibrated_score > 0.90

    # Overall fusion verdict: In evidence-based scoring, evaluates to LOW_RISK_INDICATORS (score <= 25)
    assert (
        res.evidence_fusion.overall_category == AssessmentCategory.LOW_RISK_INDICATORS
    ), f"Expected LOW_RISK_INDICATORS, got {res.evidence_fusion.overall_category}"

    # Reasoning verification: strictly evidence-grounded
    reasoning = res.evidence_fusion.reasoning
    assert "conflicting" not in reasoning.lower(), "Reasoning must not claim false conflicts"
    assert "contradictory" not in reasoning.lower()
    assert "Receiver-reported domain authentication passed" in reasoning
    assert "cannot be independently verified" in reasoning


# ==============================================================================
# Scenario 2: Legitimate long tracking URLs (>250 chars)
# ==============================================================================
def test_02_legitimate_long_tracking_urls():
    """
    Verifies that URL length alone (>250 characters non-query) triggers RULE_EXCESSIVE_URL_LENGTH
    with severity LOW, never elevating the URL to MEDIUM or HIGH.
    """
    hostname = "https://email-delivery-tracking-subdomain.corporate-enterprise-service.com"
    long_path = "/track/v2/routing_identifier_without_exceeding_path_limit_token_" + ("a" * 115)
    url = f"{hostname}{long_path}"
    assert len(url) > 250

    res = analyze_url(url)
    assert any(o.rule_id == "RULE_EXCESSIVE_URL_LENGTH" for o in res.observations)
    excessive_obs = next(o for o in res.observations if o.rule_id == "RULE_EXCESSIVE_URL_LENGTH")
    assert excessive_obs.severity.value == "LOW"
    assert res.heuristic_risk_category == HeuristicRiskCategory.LOW


# ==============================================================================
# Scenario 3: Clean plain-text business emails
# ==============================================================================
def test_03_clean_plain_text_business_email():
    """
    Verifies that a clean email with low model score and reported PASS produces
    INSUFFICIENT_EVIDENCE in offline mode (preserving the trusted boundary requirement),
    without claiming 'No authentication results present'.
    """
    url_batch = analyze_urls(["https://company.example.com/portal"])
    header_info = EmailHeaderInfo(
        authentication_results=[
            "mx.google.com; spf=pass smtp.mailfrom=company.example.com; dkim=pass header.d=company.example.com; dmarc=pass"
        ]
    )
    auth_res = analyze_email_authentication(header_info)
    model_inf = ModelInferenceEvidence(uncalibrated_score=0.08, predicted_label=0)

    fusion = fuse_evidence(
        url_analysis=url_batch,
        authentication_analysis=auth_res,
        model_inference=model_inf,
    )

    assert fusion.overall_category in (
        AssessmentCategory.LOW_RISK_INDICATORS,
        AssessmentCategory.INSUFFICIENT_EVIDENCE,
    )
    assert "Receiver-reported domain authentication passed" in fusion.reasoning
    assert "No authentication results present" not in fusion.reasoning


# ==============================================================================
# Scenario 4: Legitimate newsletters
# ==============================================================================
def test_04_legitimate_newsletters():
    """
    Verifies that newsletters with multiple signed links and unsubscribe URLs
    do not escalate to HIGH_RISK_INDICATORS_PRESENT.
    """
    urls = [
        "https://newsletter.techdigest.com/issues/2026-w44",
        "https://newsletter.techdigest.com/track/click?user=vasudev&article=42&sig=d83f81",
        "https://newsletter.techdigest.com/preferences/manage?token=92847291047294",
        "https://newsletter.techdigest.com/unsubscribe?list=weekly_ai&user=vasudev",
    ]
    url_batch = analyze_urls(urls)
    header_info = EmailHeaderInfo(
        authentication_results=[
            "mx.google.com; spf=pass smtp.mailfrom=newsletter.techdigest.com; dkim=pass header.d=newsletter.techdigest.com; dmarc=pass"
        ]
    )
    auth_res = analyze_email_authentication(header_info)
    # Even if DistilBERT flags slight marketing similarity (0.65)
    model_inf = ModelInferenceEvidence(uncalibrated_score=0.65, predicted_label=1)

    fusion = fuse_evidence(
        url_analysis=url_batch,
        authentication_analysis=auth_res,
        model_inference=model_inf,
    )

    assert fusion.overall_category in (
        AssessmentCategory.LOW_RISK_INDICATORS,
        AssessmentCategory.REVIEW_RECOMMENDED,
    )
    assert fusion.overall_category != AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT


# ==============================================================================
# Scenario 5: Forged Authentication-Results PASS headers
# ==============================================================================
def test_05_forged_authentication_results_pass_header():
    """
    Verifies that an injected/forged Authentication-Results header claiming PASS
    cannot override structural URL deception (e.g. userinfo @ deception).
    """
    url_batch = analyze_urls(["http://trusted-bank.com@malicious-phish.net/login.html"])  # Userinfo deception -> HIGH
    header_info = EmailHeaderInfo(
        authentication_results=[
            "mx.google.com; spf=pass smtp.mailfrom=trusted-bank.com; dkim=pass header.d=trusted-bank.com; dmarc=pass"
        ]
    )
    auth_res = analyze_email_authentication(header_info)
    model_inf = ModelInferenceEvidence(uncalibrated_score=0.95, predicted_label=1)

    fusion = fuse_evidence(
        url_analysis=url_batch,
        authentication_analysis=auth_res,
        model_inference=model_inf,
    )

    # Malicious structural link deception MUST remain HIGH_RISK
    assert fusion.overall_category == AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT
    assert fusion.url_evidence.highest_heuristic_risk == "HIGH"


# ==============================================================================
# Scenario 6: Forged Authentication-Results FAIL headers
# ==============================================================================
def test_06_forged_authentication_results_fail_header():
    """
    Verifies that reported auth failure alone (without corroborating URL deception or text)
    is treated as an unverified reported assertion and evaluates to REVIEW_RECOMMENDED,
    not HIGH_RISK.
    """
    url_batch = analyze_urls(["https://reputable-portal.com/help"])
    header_info = EmailHeaderInfo(
        authentication_results=[
            "mx.google.com; spf=fail smtp.mailfrom=spoofed.com; dkim=fail header.d=spoofed.com; dmarc=fail"
        ]
    )
    auth_res = analyze_email_authentication(header_info)
    # Neutral text score
    model_inf = ModelInferenceEvidence(uncalibrated_score=0.25, predicted_label=0)

    fusion = fuse_evidence(
        url_analysis=url_batch,
        authentication_analysis=auth_res,
        model_inference=model_inf,
    )

    # Isolated reported failure without independent corroboration must be REVIEW_RECOMMENDED
    assert fusion.overall_category == AssessmentCategory.REVIEW_RECOMMENDED
    assert "reported authentication failure" in fusion.reasoning


# ==============================================================================
# Scenario 7: Credential-harvesting URLs
# ==============================================================================
def test_07_credential_harvesting_urls():
    """
    Verifies that credential harvesting links with pre-populated email addresses
    trigger RULE_EMAIL_IN_QUERY (MEDIUM severity). When corroborated by failing auth
    or elevated text model score, evaluates to HIGH_RISK_INDICATORS_PRESENT.
    """
    url = "https://secure-login-update.com/login?email=victim@target.com&source=reminder"
    res = analyze_url(url)
    assert any(o.rule_id == "RULE_EMAIL_IN_QUERY" for o in res.observations)
    assert res.heuristic_risk_category == HeuristicRiskCategory.MEDIUM

    url_batch = analyze_urls([url])
    header_info = EmailHeaderInfo(
        authentication_results=["mx.google.com; spf=fail smtp.mailfrom=bad.com; dmarc=fail"]
    )
    auth_res = analyze_email_authentication(header_info)
    model_inf = ModelInferenceEvidence(uncalibrated_score=0.88, predicted_label=1)

    fusion = fuse_evidence(
        url_analysis=url_batch,
        authentication_analysis=auth_res,
        model_inference=model_inf,
    )
    assert fusion.overall_category == AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT


# ==============================================================================
# Scenario 8: Userinfo @ authority deception
# ==============================================================================
def test_08_userinfo_at_symbol_deception():
    """
    Verifies that authority deception using '@' triggers RULE_USERINFO_AUTH with HIGH severity
    and forces the fusion outcome to HIGH_RISK_INDICATORS_PRESENT.
    """
    url = "https://accounts.google.com@phishing-landing-zone.net/login"
    res = analyze_url(url)
    assert any(o.rule_id == "RULE_USERINFO_AUTH" for o in res.observations)
    assert res.heuristic_risk_category == HeuristicRiskCategory.HIGH

    url_batch = analyze_urls([url])
    fusion = fuse_evidence(url_analysis=url_batch)
    assert fusion.overall_category == AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT


# ==============================================================================
# Scenario 9: Public IP-literal URLs
# ==============================================================================
def test_09_public_ip_literal_urls():
    """
    Verifies that raw public IP literal hostnames trigger RULE_PUBLIC_IP_HOST (MEDIUM severity)
    and, when corroborated by elevated text model score on unauthenticated mail, evaluate to HIGH_RISK.
    """
    url = "http://93.184.216.34/update_account.php"
    res = analyze_url(url)
    assert any(o.rule_id == "RULE_PUBLIC_IP_HOST" for o in res.observations)
    assert res.heuristic_risk_category == HeuristicRiskCategory.MEDIUM

    url_batch = analyze_urls([url])
    model_inf = ModelInferenceEvidence(uncalibrated_score=0.92, predicted_label=1)
    fusion = fuse_evidence(url_analysis=url_batch, model_inference=model_inf)
    assert fusion.overall_category == AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT


# ==============================================================================
# Scenario 10: Punycode and nested redirect attacks
# ==============================================================================
def test_10_punycode_and_nested_redirect_attacks():
    """
    Verifies detection of Punycode homograph spoofing (MEDIUM) and
    nested redirects pointing to external IP literals (HIGH).
    """
    # 1. Punycode spoofing
    puny_url = "https://xn--pple-43d.com/store"
    res_puny = analyze_url(puny_url)
    assert any(o.rule_id == "RULE_PUNYCODE_HOST" for o in res_puny.observations)
    assert res_puny.heuristic_risk_category == HeuristicRiskCategory.MEDIUM

    # 2. Nested redirect to public IP
    nested_url = "https://trustworthy.org/redirect?dest=http://93.184.216.34/steal"
    res_nested = analyze_url(nested_url)
    assert any(o.rule_id == "RULE_NESTED_REDIRECT_IP_LITERAL" for o in res_nested.observations)
    assert res_nested.heuristic_risk_category == HeuristicRiskCategory.HIGH


# ==============================================================================
# Scenario 11: Legitimate emails with unusual but harmless URL structures
# ==============================================================================
def test_11_legitimate_emails_with_unusual_harmless_url_structures():
    """
    Verifies that multiple deep harmless subdomains or long query strings on HTTPS
    domains do not produce false HIGH_RISK verdicts.
    """
    url = "https://support.internal.cloud.service.provider.corp.example.com/kb/article?id=849201&session=active#section-2"
    res = analyze_url(url)
    # May trigger deep subdomains or query params, but not HIGH
    assert res.heuristic_risk_category in (
        HeuristicRiskCategory.LOW,
        HeuristicRiskCategory.MEDIUM,
    )

    url_batch = analyze_urls([url])
    header_info = EmailHeaderInfo(
        authentication_results=[
            "mx.google.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass"
        ]
    )
    auth_res = analyze_email_authentication(header_info)
    model_inf = ModelInferenceEvidence(uncalibrated_score=0.45, predicted_label=0)

    fusion = fuse_evidence(
        url_analysis=url_batch,
        authentication_analysis=auth_res,
        model_inference=model_inf,
    )
    assert fusion.overall_category in (
        AssessmentCategory.LOW_RISK_INDICATORS,
        AssessmentCategory.REVIEW_RECOMMENDED,
    )
    assert fusion.overall_category != AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT


# ==============================================================================
# Scenario 12: Genuine phishing emails with valid authentication claims
# ==============================================================================
def test_12_genuine_phishing_with_valid_authentication_claims():
    """
    Verifies that an attacker sending phishing from an authenticated domain they own
    (SPF=PASS, DKIM=PASS, DMARC=PASS for attacker-owned domain) CANNOT evade detection
    if the email contains structural link deception or credential harvesting lures.
    """
    # Attacker controls 'attacker-hosted-phish.net' with valid SPF/DKIM/DMARC
    header_info = EmailHeaderInfo(
        authentication_results=[
            "mx.google.com; spf=pass smtp.mailfrom=attacker-hosted-phish.net; dkim=pass header.d=attacker-hosted-phish.net; dmarc=pass header.from=attacker-hosted-phish.net"
        ]
    )
    auth_res = analyze_email_authentication(header_info)

    # But email body directs user to credential harvesting with userinfo deception
    url_batch = analyze_urls(["https://microsoft.com@attacker-hosted-phish.net/owa/login.php"])
    model_inf = ModelInferenceEvidence(uncalibrated_score=0.98, predicted_label=1)

    fusion = fuse_evidence(
        url_analysis=url_batch,
        authentication_analysis=auth_res,
        model_inference=model_inf,
    )

    # Valid domain authentication MUST NOT override severe structural phishing indicators!
    assert fusion.overall_category == AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT
    assert fusion.url_evidence.highest_heuristic_risk == "HIGH"
