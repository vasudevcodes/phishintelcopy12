"""
Tests for Phase 7A Evidence Fusion Engine (PhishIntel).
Covers:
1. All evidence sources present (corroborated)
2. Missing URL evidence
3. Missing authentication results
4. No usable public IP (internal transit only)
5. Contradictory authentication evidence
6. High URL heuristic score without model support
7. High model score without corroborating evidence
8. Multiple suspicious URLs without double-counting
9. Multiple related authentication headers (correlated SPF/DMARC)
10. Malformed component output handled gracefully
11. No calibrated overall probability emitted
12. API integration preserving all existing response fields
13. Regression on existing fixtures
"""

import io
from pathlib import Path
import socket
from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.schemas.email import AttachmentInfo, EmailBodyInfo, EmailHeaderInfo
from app.services.email_authentication import analyze_email_authentication
from app.services.url_intelligence import analyze_urls
from app.schemas.evidence_fusion import (
    AssessmentCategory,
    EvidenceFusionResult,
    ModelInferenceEvidence,
    ModelInferenceStatus,
)
from app.schemas.email_authentication import (
    AuthResultStatus,
    DKIMEvidence,
    DMARCEvidence,
    EmailAuthenticationAnalysis,
    OverallAuthStatus,
    SPFEvidence,
)
from app.schemas.ip_intelligence import (
    CandidateIPIntelligence,
    GeolocationStatus,
    IPClassification,
    IPIntelligenceResult,
)
from app.schemas.url_intelligence import (
    HeuristicRiskCategory,
    ObservationSeverity,
    ParseStatus,
    URLAnalysisResult,
    URLBatchAnalysisResult,
    URLFeatures,
    URLObservation,
)
from app.services.evidence_fusion import fuse_evidence

client = TestClient(app)
FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def guard_no_network(monkeypatch):
    """
    Enforces zero network access during evidence fusion tests.
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


def _make_dummy_url_features(host="example.com"):
    return URLFeatures(
        scheme="https",
        is_https=True,
        hostname=host,
        port=None,
        has_non_standard_port=False,
        is_ip_literal=False,
        ip_version=None,
        ip_classification=None,
        is_punycode=False,
        is_fqdn_valid=True,
        has_userinfo=False,
        subdomain_count=0,
        path_depth=1,
        query_param_count=0,
        has_fragment=False,
        url_length=len(host) + 10,
        hostname_length=len(host),
        path_length=5,
        query_length=0,
        hex_encoded_char_count=0,
        hyphen_count_hostname=0,
        at_symbol_count=0,
        double_slash_in_path=False,
    )


# 1. All Evidence Sources Present (Corroborated)
def test_all_evidence_sources_present():
    url_res = URLAnalysisResult(
        url_index=0,
        original_url="http://192.168.1.50/login",
        normalized_hostname="192.168.1.50",
        parse_status=ParseStatus.PARSED,
        features=_make_dummy_url_features("192.168.1.50"),
        observations=[
            URLObservation(
                rule_id="RULE_IP_LITERAL_HOST",
                rule_name="IP Literal Host",
                severity=ObservationSeverity.HIGH,
                description="Destination is IPv4 literal",
            )
        ],
        heuristic_risk_score=70,
        heuristic_risk_category=HeuristicRiskCategory.HIGH,
        risk_summary="High risk",
    )
    url_batch = URLBatchAnalysisResult(
        total_urls=1,
        unique_urls=1,
        highest_risk_category=HeuristicRiskCategory.HIGH,
        risk_breakdown={HeuristicRiskCategory.HIGH: 1},
        url_results=[url_res],
        analyzed_at="2026-10-12T00:00:00Z",
    )

    auth_analysis = EmailAuthenticationAnalysis(
        status=OverallAuthStatus.EVALUATED,
        spf=SPFEvidence(status=AuthResultStatus.FAIL, explanation="SPF failed"),
        dkim=DKIMEvidence(status=AuthResultStatus.FAIL, explanation="DKIM failed"),
        dmarc=DMARCEvidence(status=AuthResultStatus.FAIL, explanation="DMARC failed"),
        has_conflicts=False,
    )

    ip_intel = IPIntelligenceResult(
        total_candidates=1,
        candidates=[
            CandidateIPIntelligence(
                ip="198.51.100.25",
                version=4,
                classification=IPClassification.PUBLIC,
                is_routable=True,
                geolocation_status=GeolocationStatus.DATABASE_UNAVAILABLE,
                role_hint="Edge Gateway",
                explanation="Public IP",
            )
        ],
        origin_candidate=CandidateIPIntelligence(
            ip="198.51.100.25",
            version=4,
            classification=IPClassification.PUBLIC,
            is_routable=True,
            geolocation_status=GeolocationStatus.DATABASE_UNAVAILABLE,
            role_hint="Origin",
            explanation="Origin",
        ),
        origin_assessment="Public origin",
        public_count=1,
    )

    model_inf = ModelInferenceEvidence(uncalibrated_score=0.88, predicted_label=1)

    result = fuse_evidence(
        url_analysis=url_batch,
        authentication_analysis=auth_analysis,
        ip_intelligence=ip_intel,
        model_inference=model_inf,
    )

    assert result.overall_category == AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT
    assert result.model_evidence.status == ModelInferenceStatus.EVALUATED
    assert result.model_evidence.uncalibrated_score == 0.88
    assert result.url_evidence.highest_heuristic_risk == "HIGH"
    assert result.auth_evidence.has_explicit_failure is True
    assert len(result.contributing_factors) >= 2


# 2. Missing URL Evidence
def test_missing_url_evidence():
    result = fuse_evidence(url_analysis=None)
    assert result.url_evidence.total_urls == 0
    assert result.url_evidence.highest_heuristic_risk == "NONE"
    assert any("No extracted URLs present" in f for f in result.inconclusive_or_missing_factors)


# 3. Missing Authentication Results
def test_missing_authentication_results():
    result = fuse_evidence(authentication_analysis=None)
    assert result.auth_evidence.spf_status == "NOT_PRESENT"
    assert result.auth_evidence.has_valid_authentication is False
    assert any("No SPF, DKIM, or DMARC" in f for f in result.inconclusive_or_missing_factors)


# 4. No Usable Public IP (Internal Transit Only)
def test_no_usable_public_ip():
    ip_intel = IPIntelligenceResult(
        total_candidates=2,
        candidates=[
            CandidateIPIntelligence(
                ip="10.0.0.1",
                version=4,
                classification=IPClassification.PRIVATE,
                is_routable=False,
                geolocation_status=GeolocationStatus.NOT_ROUTABLE,
                role_hint="Gateway",
                explanation="Private",
            ),
            CandidateIPIntelligence(
                ip="127.0.0.1",
                version=4,
                classification=IPClassification.LOOPBACK,
                is_routable=False,
                geolocation_status=GeolocationStatus.NOT_ROUTABLE,
                role_hint="Origin",
                explanation="Loopback",
            ),
        ],
        origin_candidate=CandidateIPIntelligence(
            ip="127.0.0.1",
            version=4,
            classification=IPClassification.LOOPBACK,
            is_routable=False,
            geolocation_status=GeolocationStatus.NOT_ROUTABLE,
            role_hint="Origin",
            explanation="Loopback",
        ),
        origin_assessment="Loopback submission",
        public_count=0,
        private_count=1,
        other_count=1,
    )
    result = fuse_evidence(ip_intelligence=ip_intel)
    assert result.ip_evidence.is_routable is False
    assert result.ip_evidence.origin_classification == "Loopback"
    # Internal submission is not marked high risk solely due to private/loopback IP
    assert result.overall_category in [AssessmentCategory.INSUFFICIENT_EVIDENCE, AssessmentCategory.LOW_RISK_INDICATORS]


# 5. Contradictory Authentication Evidence
def test_contradictory_authentication_evidence():
    auth_analysis = EmailAuthenticationAnalysis(
        status=OverallAuthStatus.CONFLICTING_EVIDENCE,
        spf=SPFEvidence(status=AuthResultStatus.CONFLICTING_EVIDENCE, explanation="Conflicting SPF"),
        dkim=DKIMEvidence(status=AuthResultStatus.PASS, explanation="DKIM pass"),
        dmarc=DMARCEvidence(status=AuthResultStatus.NOT_PRESENT, explanation="DMARC missing"),
        has_conflicts=True,
    )
    result = fuse_evidence(authentication_analysis=auth_analysis)
    assert result.auth_evidence.has_conflicts is True
    assert result.overall_category == AssessmentCategory.REVIEW_RECOMMENDED
    assert any("Contradictory authentication evidence" in f for f in result.contributing_factors)


# 6. High URL Heuristic Score Without Model Support
def test_high_url_heuristic_without_model_support():
    url_res = URLAnalysisResult(
        url_index=0,
        original_url="http://legit.com@phish-site.com/auth",
        normalized_hostname="phish-site.com",
        parse_status=ParseStatus.PARSED,
        features=_make_dummy_url_features("phish-site.com"),
        observations=[
            URLObservation(
                rule_id="RULE_USERINFO_AUTH_TRICK",
                rule_name="Userinfo Auth Trick",
                severity=ObservationSeverity.HIGH,
                description="Credentials trick",
            )
        ],
        heuristic_risk_score=75,
        heuristic_risk_category=HeuristicRiskCategory.HIGH,
        risk_summary="High risk",
    )
    url_batch = URLBatchAnalysisResult(
        total_urls=1,
        unique_urls=1,
        highest_risk_category=HeuristicRiskCategory.HIGH,
        risk_breakdown={HeuristicRiskCategory.HIGH: 1},
        url_results=[url_res],
        analyzed_at="2026-10-12T00:00:00Z",
    )
    # Model indicates benign text (0.15)
    model_inf = ModelInferenceEvidence(uncalibrated_score=0.15, predicted_label=0)

    result = fuse_evidence(url_analysis=url_batch, model_inference=model_inf)
    assert result.overall_category == AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT
    assert result.url_evidence.highest_heuristic_risk == "HIGH"
    assert result.model_evidence.uncalibrated_score == 0.15
    assert "severe structural URL heuristics" in result.reasoning


# 7. High Model Score Without Corroborating Evidence
def test_high_model_score_without_corroborating_evidence():
    # Model score is high (0.85), but URL is clean INFO, and auth is PASS
    url_res = URLAnalysisResult(
        url_index=0,
        original_url="https://legit-portal.example.com/welcome",
        normalized_hostname="legit-portal.example.com",
        parse_status=ParseStatus.PARSED,
        features=_make_dummy_url_features("legit-portal.example.com"),
        observations=[],
        heuristic_risk_score=0,
        heuristic_risk_category=HeuristicRiskCategory.INFO,
        risk_summary="Negligible risk",
    )
    url_batch = URLBatchAnalysisResult(
        total_urls=1,
        unique_urls=1,
        highest_risk_category=HeuristicRiskCategory.INFO,
        risk_breakdown={HeuristicRiskCategory.INFO: 1},
        url_results=[url_res],
        analyzed_at="2026-10-12T00:00:00Z",
    )
    auth_analysis = EmailAuthenticationAnalysis(
        status=OverallAuthStatus.EVALUATED,
        spf=SPFEvidence(status=AuthResultStatus.PASS, explanation="SPF pass"),
        dkim=DKIMEvidence(status=AuthResultStatus.PASS, explanation="DKIM pass"),
        dmarc=DMARCEvidence(status=AuthResultStatus.PASS, explanation="DMARC pass"),
        has_conflicts=False,
    )
    model_inf = ModelInferenceEvidence(uncalibrated_score=0.85, predicted_label=1)

    result = fuse_evidence(
        url_analysis=url_batch,
        authentication_analysis=auth_analysis,
        model_inference=model_inf,
    )
    # Must NOT jump to definitive malicious verdict without corroboration; dampened when clean
    assert result.overall_category in (AssessmentCategory.LOW_RISK_INDICATORS, AssessmentCategory.REVIEW_RECOMMENDED)
    assert "DistilBERT" in result.reasoning


# 8. Multiple Suspicious URLs Without Double-Counting
def test_multiple_suspicious_urls_without_double_counting():
    # 3 identical host links
    obs = [
        URLObservation(
            rule_id="RULE_IP_LITERAL_HOST",
            rule_name="IP Literal Host",
            severity=ObservationSeverity.HIGH,
            description="IP literal host",
        )
    ]
    url_results = [
        URLAnalysisResult(
            url_index=i,
            original_url=f"http://192.168.1.100/page{i}",
            normalized_hostname="192.168.1.100",
            parse_status=ParseStatus.PARSED,
            features=_make_dummy_url_features("192.168.1.100"),
            observations=obs,
            heuristic_risk_score=70,
            heuristic_risk_category=HeuristicRiskCategory.HIGH,
            risk_summary="High risk",
        )
        for i in range(3)
    ]
    url_batch = URLBatchAnalysisResult(
        total_urls=3,
        unique_urls=3,
        highest_risk_category=HeuristicRiskCategory.HIGH,
        risk_breakdown={HeuristicRiskCategory.HIGH: 3},
        url_results=url_results,
        analyzed_at="2026-10-12T00:00:00Z",
    )

    result = fuse_evidence(url_analysis=url_batch)
    assert result.url_evidence.total_urls == 3
    assert result.url_evidence.unique_domains == 1
    assert result.url_evidence.deduplication_applied is True
    # The IP literal indicator should appear only once in suspicious_indicators
    assert len(result.url_evidence.suspicious_indicators) == 1


# 9. Multiple Related Authentication Headers (Correlated SPF/DMARC)
def test_multiple_related_authentication_headers():
    auth_analysis = EmailAuthenticationAnalysis(
        status=OverallAuthStatus.EVALUATED,
        spf=SPFEvidence(status=AuthResultStatus.FAIL, explanation="SPF fail"),
        dkim=DKIMEvidence(status=AuthResultStatus.NOT_PRESENT, explanation="DKIM not present"),
        dmarc=DMARCEvidence(status=AuthResultStatus.FAIL, explanation="DMARC fail"),
        has_conflicts=False,
    )
    result = fuse_evidence(authentication_analysis=auth_analysis)
    assert result.auth_evidence.has_explicit_failure is True
    assert result.auth_evidence.correlated_failure_noted is True
    assert "correlated downstream DMARC" in result.contributing_factors[0]


# 10. Malformed Component Output Handled Gracefully
def test_malformed_component_output_graceful():
    # Pass empty / invalid dictionaries or None values
    result = fuse_evidence(
        url_analysis=None,
        authentication_analysis=None,
        ip_intelligence=None,
        model_inference={},
    )
    assert isinstance(result, EvidenceFusionResult)
    assert result.overall_category == AssessmentCategory.INSUFFICIENT_EVIDENCE
    assert result.model_evidence.status == ModelInferenceStatus.UNAVAILABLE


# 11. No Calibrated Overall Probability Emitted
def test_no_calibrated_overall_probability_emitted():
    result = fuse_evidence()
    data = result.model_dump()
    # Ensure NO top-level probability or percentage exists
    assert "overall_probability" not in data
    assert "probability" not in data
    assert "phishing_score" not in data
    assert "calibrated_score" not in data
    assert result.overall_category in [
        AssessmentCategory.INSUFFICIENT_EVIDENCE,
        AssessmentCategory.LOW_RISK_INDICATORS,
        AssessmentCategory.REVIEW_RECOMMENDED,
        AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT,
    ]
    # Model score explicitly labeled uncalibrated
    assert "uncalibrated_score" in data["model_evidence"]


# 12. API Integration Preserves All Response Fields
def test_api_integration_preserves_all_fields():
    eml_sample = (
        b"From: test@sender.com\n"
        b"To: user@target.com\n"
        b"Subject: Statement\n"
        b"Received: from [198.51.100.25] by mx.target.com; Mon, 12 Oct 2026 10:00:00 +0000\n"
        b"Authentication-Results: mx.target.com; spf=pass smtp.mailfrom=sender.com; dkim=pass header.d=sender.com\n"
        b"Content-Type: text/html\n\n"
        b'<p>Click <a href="https://billing.sender.com/statement">here</a></p>\n'
    )
    response = client.post(
        "/api/v1/email/analyze",
        files={"file": ("fusion_sample.eml", io.BytesIO(eml_sample), "message/rfc822")},
    )
    assert response.status_code == 200
    data = response.json()

    # 1. Existing Phase 1 parser fields
    assert data["filename"] == "fusion_sample.eml"
    assert "headers" in data
    assert "body" in data
    assert "urls" in data
    assert "attachments" in data
    assert "ip_candidates" in data

    # 2. Phase 4B URL Intelligence
    assert "url_analysis" in data
    assert data["url_analysis"] is not None

    # 3. Phase 5A Authentication Analysis
    assert "authentication_analysis" in data
    assert data["authentication_analysis"] is not None

    # 4. Phase 6A IP Intelligence
    assert "ip_intelligence" in data
    assert data["ip_intelligence"] is not None

    # 5. Phase 7A Evidence Fusion
    assert "evidence_fusion" in data
    fusion = data["evidence_fusion"]
    assert fusion is not None
    assert "overall_category" in fusion
    assert fusion["overall_category"] in [
        "INSUFFICIENT_EVIDENCE",
        "LOW_RISK_INDICATORS",
        "REVIEW_RECOMMENDED",
        "HIGH_RISK_INDICATORS_PRESENT",
    ]
    assert "overall_risk_score" in fusion
    assert isinstance(fusion["overall_risk_score"], int)
    assert "risk_score_breakdown" in fusion
    assert "evidence_completeness" in fusion
    assert "evidence_completeness_detail" in fusion
    assert "positive_evidence" in fusion
    assert "negative_evidence" in fusion
    assert "model_evidence" in fusion
    assert "url_evidence" in fusion
    assert "auth_evidence" in fusion
    assert "ip_evidence" in fusion
    assert "contributing_factors" in fusion
    assert "inconclusive_or_missing_factors" in fusion
    assert "reasoning" in fusion
    assert "disclaimer" in fusion


# 13. Regression on Existing Multi-Hop Fixture 06
def test_regression_existing_fixtures():
    fixture_path = FIXTURES_DIR / "06_multiple_received_hops.eml"
    with open(fixture_path, "rb") as f:
        response = client.post(
            "/api/v1/email/analyze",
            files={"file": ("06_multiple_received_hops.eml", f, "message/rfc822")},
        )
    assert response.status_code == 200
    data = response.json()
    assert "evidence_fusion" in data
    fusion = data["evidence_fusion"]
    assert fusion["overall_category"] in [
        "INSUFFICIENT_EVIDENCE",
        "LOW_RISK_INDICATORS",
        "REVIEW_RECOMMENDED",
        "HIGH_RISK_INDICATORS_PRESENT",
    ]
    assert fusion["auth_evidence"]["spf_status"] == "PASS"
    assert fusion["auth_evidence"]["dkim_status"] == "PASS"
    assert fusion["auth_evidence"]["dmarc_status"] == "PASS"


# 14. Forwarding & Reception of Header, Body, and Attachment Arguments
def test_fuse_evidence_accepts_header_body_and_attachment_arguments():
    """
    Regression test: Verifies that fuse_evidence accepts header_info, body_info,
    and attachments without error and retains backward-compatible optional invocation.
    """
    header_info = EmailHeaderInfo(
        from_header="alice@sender.com",
        subject="Integration Verification",
        to_headers=["bob@receiver.com"],
    )
    body_info = EmailBodyInfo(
        plain_text="Sample plain text body for fusion testing.",
        extracted_urls=[],
    )
    attachments = [
        AttachmentInfo(
            filename="document.pdf",
            content_type="application/pdf",
            size_bytes=1024,
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
    ]

    result = fuse_evidence(
        header_info=header_info,
        body_info=body_info,
        attachments=attachments,
    )
    assert isinstance(result, EvidenceFusionResult)
    assert result.overall_category is not None


# 15. Semantic Separation of Positive, Negative, Contributing, and Missing Evidence
def test_evidence_mapping_semantics_positive_not_in_missing():
    """
    Regression test: Verifies that positive/mitigating evidence is strictly kept in
    positive_evidence (and contributing_factors for LOW_RISK_INDICATORS), and is
    NEVER classified into inconclusive_or_missing_factors.
    """
    header_info = EmailHeaderInfo(
        from_header="newsletter@legitimate-service.com",
        subject="Monthly Digest",
        authentication_results=[
            "mx.google.com; spf=pass smtp.mailfrom=legitimate-service.com; dkim=pass header.d=legitimate-service.com; dmarc=pass"
        ],
    )
    auth_analysis = analyze_email_authentication(header_info)
    url_batch = analyze_urls(["https://legitimate-service.com/digest/nov-2026"])
    model_inf = ModelInferenceEvidence(uncalibrated_score=0.05, predicted_label=0)

    result = fuse_evidence(
        url_analysis=url_batch,
        authentication_analysis=auth_analysis,
        model_inference=model_inf,
        header_info=header_info,
        body_info=EmailBodyInfo(plain_text="Enjoy our monthly digest."),
    )

    assert result.overall_category == AssessmentCategory.LOW_RISK_INDICATORS
    assert len(result.positive_evidence) > 0

    # Critical invariant: Positive evidence must NEVER be in inconclusive_or_missing_factors
    for pos_item in result.positive_evidence:
        assert pos_item not in result.inconclusive_or_missing_factors, (
            f"Semantic violation: Positive evidence '{pos_item}' was classified as missing factor!"
        )

    # For LOW_RISK_INDICATORS, positive evidence appropriately contributes to the verdict
    assert any(pos in result.contributing_factors for pos in result.positive_evidence)


def test_evidence_mapping_semantics_negative_and_missing_isolation():
    """
    Regression test: Verifies that negative evidence is captured in negative_evidence
    and drives contributing_factors for elevated risk, without polluting missing factors.
    """
    header_info = EmailHeaderInfo(
        from_header="security@spoofed-bank.com",
        subject="Account Suspended",
        authentication_results=[
            "mx.google.com; spf=fail smtp.mailfrom=spoofed-bank.com; dkim=fail; dmarc=fail (p=REJECT)"
        ],
    )
    auth_analysis = analyze_email_authentication(header_info)
    model_inf = ModelInferenceEvidence(uncalibrated_score=0.92, predicted_label=1)

    result = fuse_evidence(
        url_analysis=None,
        authentication_analysis=auth_analysis,
        model_inference=model_inf,
        header_info=header_info,
        body_info=EmailBodyInfo(plain_text="Your account has been suspended. Urgent action required."),
    )

    assert result.overall_category in (
        AssessmentCategory.REVIEW_RECOMMENDED,
        AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT,
    )
    assert len(result.negative_evidence) > 0

    # Risk indicators should be in contributing_factors
    assert any("fail" in f.lower() for f in result.contributing_factors)

    # Missing factors only reflect genuinely absent modalities (e.g. no URLs)
    assert any("no extracted urls" in f.lower() for f in result.inconclusive_or_missing_factors)
    # Missing factors must NOT contain any negative risk findings
    assert not any("fail" in f.lower() for f in result.inconclusive_or_missing_factors)


# 16. Parser-to-Fusion End-to-End Five-Category Scoring Integration
def test_parser_to_fusion_end_to_end_scoring():
    """
    Regression test: Verifies that parse_email_message forwards all 7 modalities,
    and produces a fully structured 0-100 EvidenceFusionResult with breakdown.
    """
    from app.services.email_parser import parse_email_message

    fixture_path = FIXTURES_DIR / "04_attachments.eml"
    result = parse_email_message(fixture_path.read_bytes(), "04_attachments.eml")

    assert result.evidence_fusion is not None
    ef = result.evidence_fusion

    # Overall score and category consistency
    assert 0 <= ef.overall_risk_score <= 100
    assert ef.overall_category is not None

    # Five-category breakdown completeness
    bd = ef.risk_score_breakdown
    assert bd is not None
    assert 0 <= bd.sender_auth.score <= 25
    assert 0 <= bd.url_intelligence.score <= 25
    assert 0 <= bd.content_language.score <= 20
    assert 0 <= bd.ml_model.score <= 20
    assert 0 <= bd.header_ip.score <= 10
    assert (
        bd.sender_auth.score
        + bd.url_intelligence.score
        + bd.content_language.score
        + bd.ml_model.score
        + bd.header_ip.score
    ) <= 100
