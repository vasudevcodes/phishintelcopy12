"""
Pydantic schemas for Evidence Fusion Engine (Phase 7A).
Synthesizes evidence from DistilBERT, URL intelligence, email authentication, and IP intelligence.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class AssessmentCategory(str, Enum):
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    LOW_RISK_INDICATORS = "LOW_RISK_INDICATORS"
    REVIEW_RECOMMENDED = "REVIEW_RECOMMENDED"
    HIGH_RISK_INDICATORS_PRESENT = "HIGH_RISK_INDICATORS_PRESENT"


class ModelInferenceStatus(str, Enum):
    UNAVAILABLE = "UNAVAILABLE"
    EVALUATED = "EVALUATED"
    ERROR = "ERROR"


class ModelInferenceEvidence(BaseModel):
    """
    Input schema for DistilBERT model inference results when available.
    """
    uncalibrated_score: Optional[float] = Field(None, description="Raw model output (0.0 to 1.0)")
    predicted_label: Optional[int] = Field(None, description="Predicted class index: 0 (benign), 1 (phishing)")
    status: Optional[ModelInferenceStatus] = Field(None, description="Inference execution status")
    error_message: Optional[str] = Field(None, description="Error message if inference failed or was unavailable")


class ModelEvidenceInterpretation(BaseModel):
    """
    Interpreted DistilBERT model evidence with explicit calibration caveats.
    """
    status: ModelInferenceStatus = Field(..., description="Availability status of Transformer model inference")
    uncalibrated_score: Optional[float] = Field(None, description="Uncalibrated model output score (0.0 to 1.0)")
    predicted_label: Optional[int] = Field(None, description="Predicted class index: 0 (benign) or 1 (phishing)")
    interpretation: str = Field(..., description="Explanation of model output and its forensic meaning")
    caveat: str = Field(
        default="Score is an uncalibrated DistilBERT output trained on the PhishMMF dataset. "
                "Due to dataset source-label collinearity and synthetic token shortcuts (<USER>), "
                "this score represents a text-similarity heuristic and NOT a validated real-world probability.",
        description="Explicit limitation regarding model calibration and dataset shortcuts"
    )


class URLEvidenceSummary(BaseModel):
    """
    Consolidated URL intelligence findings for evidence fusion.
    """
    total_urls: int = Field(0, description="Total URLs extracted from email")
    unique_domains: int = Field(0, description="Count of distinct destination domains or hostnames")
    highest_heuristic_risk: str = Field("NONE", description="Highest heuristic risk tier: NONE, INFO, LOW, MEDIUM, or HIGH")
    suspicious_indicators: List[str] = Field(default_factory=list, description="Unique structural risk indicators detected")
    deduplication_applied: bool = Field(True, description="Whether duplicate destination URLs were collapsed to prevent double-counting")
    explanation: str = Field(..., description="Summary explanation of URL evidence")
    heuristic_disclaimer: str = Field(
        default="URL risk scores are rule-based heuristic indicators (0-100) reflecting structural and lexical patterns, "
                "not statistical probabilities.",
        description="Disclaimer on heuristic nature of URL scores"
    )


class AuthEvidenceSummary(BaseModel):
    """
    Consolidated email authentication findings for evidence fusion.
    """
    spf_status: str = Field("NOT_PRESENT", description="Normalized SPF result status")
    dkim_status: str = Field("NOT_PRESENT", description="Normalized DKIM result status")
    dmarc_status: str = Field("NOT_PRESENT", description="Normalized DMARC result status")
    has_conflicts: bool = Field(False, description="Whether contradictory authentication evidence was recorded across headers")
    has_valid_authentication: bool = Field(False, description="Whether one or more mechanisms explicitly passed")
    has_explicit_failure: bool = Field(False, description="Whether explicit failure was recorded (FAIL)")
    correlated_failure_noted: bool = Field(False, description="Whether DMARC failure was correlated with SPF/DKIM to avoid double-counting")
    boundary_authserv_trust: str = Field("UNTRUSTED", description="Trust status of the boundary MTA authserv-id")
    is_boundary_trusted: bool = Field(False, description="Whether authentication was recorded by a trusted recipient boundary MTA")
    verification_mode: str = Field("OFFLINE_REPORTED", description="LIVE_DNS when statuses were re-verified against live DNS, else OFFLINE_REPORTED")
    explanation: str = Field(..., description="Summary explanation of authentication evidence")
    trust_limitation: str = Field(
        default="Authentication results reflect downstream MTA assertions (RFC 8601/RFC 7208). "
                "PASS does not guarantee benign intent (e.g. attacker-owned domain), and FAIL does not guarantee "
                "malice (e.g. forwarding breakage).",
        description="Trust boundary limitation"
    )


class IPEvidenceSummary(BaseModel):
    """
    Consolidated IP transit and origin findings for evidence fusion.
    """
    apparent_origin_ip: Optional[str] = Field(None, description="IP address identified at earliest recorded transit hop")
    origin_classification: str = Field("Unavailable", description="Classification of apparent origin IP")
    is_routable: bool = Field(False, description="Whether apparent origin IP is globally routable on public Internet")
    hop_count: int = Field(0, description="Total Received hops analyzed")
    explanation: str = Field(..., description="Summary explanation of IP intelligence evidence")
    provenance_limitation: str = Field(
        default="Received headers prior to the recipient boundary MTA can be spoofed or omitted by untrusted relays. "
                "IP egress reflects network routing, not a person's physical location. Private IPs, proxies, and cloud "
                "hosts are not proof of maliciousness.",
        description="Provenance and forensic limitations"
    )


class EvidenceCompletenessStatus(str, Enum):
    FULL_COVERAGE = "FULL_COVERAGE"
    PARTIAL_COVERAGE = "PARTIAL_COVERAGE"
    MINIMAL_OR_INSUFFICIENT = "MINIMAL_OR_INSUFFICIENT"


class CategoryScoreDetail(BaseModel):
    """
    Detailed numerical contribution and explanation for an individual evidence category.
    """
    category_name: str = Field(..., description="Human-readable category title")
    score: int = Field(..., ge=0, description="Heuristic risk points accrued")
    max_score: int = Field(..., ge=1, description="Maximum possible risk points in this category")
    weight_percentage: int = Field(..., ge=1, le=100, description="Target architecture weight percentage")
    explanation: str = Field(..., description="Explainable rationale for points assigned")
    rules_triggered: List[str] = Field(default_factory=list, description="IDs of rules that contributed points")
    is_dampened: bool = Field(False, description="Whether corroboration dampening was applied (ML model category)")


class CategoryScoresBreakdown(BaseModel):
    """
    Structured breakdown of risk points across the 5 evidence categories.
    Total maximum sum = 100 points.
    """
    sender_auth: CategoryScoreDetail = Field(..., description="Sender identity and authentication (max 25 pts)")
    url_intelligence: CategoryScoreDetail = Field(..., description="URL and link intelligence (max 25 pts)")
    content_language: CategoryScoreDetail = Field(..., description="Content and language analysis (max 20 pts)")
    ml_model: CategoryScoreDetail = Field(..., description="ML model analysis (max 20 pts)")
    header_ip: CategoryScoreDetail = Field(..., description="Header, IP and infrastructure intelligence (max 10 pts)")
    category_sum: int = Field(0, ge=0, description="Sum of the five category scores before any safety floor")
    floor_adjustment: int = Field(
        0, ge=0,
        description="Points added by a safety floor so that category_sum + floor_adjustment == overall_risk_score",
    )
    floor_adjustment_reason: Optional[str] = Field(None, description="Why the safety floor raised the score, if it did")


class EvidenceFusionResult(BaseModel):
    """
    Structured multi-modal evidence fusion assessment for an analyzed email.
    """
    overall_category: AssessmentCategory = Field(
        ...,
        description="Overall forensic assessment category with explicit uncertainty"
    )
    overall_risk_score: int = Field(
        0,
        ge=0,
        le=100,
        description="Transparent 0-100 overall phishing risk score based on weighted evidence categories. Not a statistical probability."
    )
    risk_score_breakdown: Optional[CategoryScoresBreakdown] = Field(
        None,
        description="Detailed point contributions across the 5 evidence categories"
    )
    evidence_completeness: EvidenceCompletenessStatus = Field(
        EvidenceCompletenessStatus.FULL_COVERAGE,
        description="Assessment of evidence completeness and coverage"
    )
    evidence_completeness_detail: str = Field(
        default="Complete forensic evidence available across headers, body, authentication, and transit chain.",
        description="Explanation of evidence coverage and missing modalities"
    )
    positive_evidence: List[str] = Field(
        default_factory=list,
        description="Observed mitigating or authenticating evidence factors"
    )
    negative_evidence: List[str] = Field(
        default_factory=list,
        description="Observed risk-elevating or suspicious evidence factors"
    )
    model_evidence: ModelEvidenceInterpretation = Field(..., description="DistilBERT NLP evidence interpretation")
    url_evidence: URLEvidenceSummary = Field(..., description="URL intelligence evidence summary")
    auth_evidence: AuthEvidenceSummary = Field(..., description="Email authentication evidence summary")
    ip_evidence: IPEvidenceSummary = Field(..., description="IP transit and origin evidence summary")
    contributing_factors: List[str] = Field(default_factory=list, description="Specific observed findings that influenced the category")
    inconclusive_or_missing_factors: List[str] = Field(default_factory=list, description="Evidence components that were missing, unverified, or indeterminate")
    reasoning: str = Field(..., description="Detailed natural-language justification for the assessment category")
    disclaimer: str = Field(
        default="This assessment is an investigation support aid combining local forensic observations and model scores. "
                "It does NOT emit a calibrated probability or a definitive phishing verdict. Findings must be validated by security analysts.",
        description="Mandatory disclaimer on non-probabilistic, non-verdict nature"
    )
