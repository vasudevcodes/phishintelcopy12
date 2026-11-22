"""
Pydantic schemas for PhishIntel URL Intelligence Engine (Phase 4A).
Defines structured, explainable models for local URL parsing, feature extraction,
rule-based observations, and heuristic risk assessment.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class ParseStatus(str, Enum):
    PARSED = "parsed"
    MALFORMED = "malformed"
    UNSUPPORTED_SCHEME = "unsupported_scheme"
    MISSING_SCHEME = "missing_scheme"


class HostType(str, Enum):
    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    LOCALHOST = "localhost"
    INVALID = "invalid"


class HostClassification(str, Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    RESERVED = "reserved"
    DOCUMENTATION = "documentation"
    UNKNOWN = "unknown"


class ObservationSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class HeuristicRiskCategory(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class URLFeatures(BaseModel):
    """
    Deterministically extracted structural and lexical features of a URL.
    All features are derived locally without any network resolution.
    """
    # Scheme & validation
    scheme: Optional[str] = Field(None, description="URL protocol scheme (e.g. http, https)")
    is_https: bool = Field(False, description="Whether URL uses HTTPS protocol")
    is_http: bool = Field(False, description="Whether URL uses HTTP protocol")
    is_unusual_scheme: bool = Field(False, description="Whether URL uses an unusual/unsupported scheme (e.g. data, javascript, file)")
    
    # Host & IP features
    raw_host: Optional[str] = Field(None, description="Raw extracted host string")
    normalized_host: Optional[str] = Field(None, description="Cleaned, lowercase, normalized hostname without trailing dot")
    host_type: HostType = Field(HostType.DOMAIN, description="Host classification: domain, ipv4, ipv6, localhost, invalid")
    is_ip_literal: bool = Field(False, description="Whether hostname is an IP address literal")
    ip_version: Optional[int] = Field(None, description="IP version (4 or 6) if host is an IP literal")
    host_classification: HostClassification = Field(HostClassification.UNKNOWN, description="IP or domain scope (public, private, loopback, reserved)")
    has_trailing_dot: bool = Field(False, description="Whether hostname had a trailing root dot (e.g. example.com.)")
    
    # Lengths & counts
    url_length: int = Field(0, description="Total character length of the URL")
    host_length: int = Field(0, description="Character length of the hostname")
    subdomain_count: int = Field(0, description="Estimated number of subdomains before registrable domain")
    dots_in_host: int = Field(0, description="Total count of '.' characters in the hostname")
    hyphens_in_host: int = Field(0, description="Total count of '-' characters in the hostname")
    dots_in_url: int = Field(0, description="Total count of '.' characters in the entire URL")
    hyphens_in_url: int = Field(0, description="Total count of '-' characters in the entire URL")
    
    # Authority & Port
    has_userinfo: bool = Field(False, description="Whether user-info or '@' is present in the authority component")
    port: Optional[int] = Field(None, description="Explicit port number if specified")
    is_non_default_port: bool = Field(False, description="Whether URL specifies a non-standard port (e.g. not 80 for http or 443 for https)")
    
    # Encodings & Internationalization
    percent_encoding_count: int = Field(0, description="Number of percent-encoded (%XX) sequences in URL")
    is_punycode: bool = Field(False, description="Whether hostname contains Punycode labels (xn--)")
    has_unicode: bool = Field(False, description="Whether hostname or URL contains non-ASCII Unicode characters")
    
    # Path, Query, Fragment
    has_path: bool = Field(False, description="Whether URL contains a non-empty, non-root path")
    path_length: int = Field(0, description="Character length of path component")
    has_query: bool = Field(False, description="Whether URL contains query parameters (?key=val)")
    query_length: int = Field(0, description="Character length of query component")
    query_param_count: int = Field(0, description="Number of query parameters")
    has_fragment: bool = Field(False, description="Whether URL contains a fragment identifier (#section)")


class URLObservation(BaseModel):
    """
    Explainable, rule-based observation generated for an individual URL.
    """
    rule_id: str = Field(..., description="Unique rule identifier (e.g. RULE_IP_LITERAL, RULE_USERINFO_AUTH)")
    rule_name: str = Field(..., description="Human-readable rule name")
    severity: ObservationSeverity = Field(..., description="Severity category: INFO, LOW, MEDIUM, HIGH")
    description: str = Field(..., description="Clear explanation of the observed indicator and its security rationale")


class URLAnalysisResult(BaseModel):
    """
    Comprehensive structured analysis result for a single URL.
    """
    url_index: int = Field(0, description="0-based index of URL within the email or batch")
    original_url: str = Field(..., description="Original extracted URL string")
    source: Optional[str] = Field(None, description="Origin location of URL in email: 'plain_text', 'html_href', or 'both'")
    normalized_url: Optional[str] = Field(None, description="Normalized, safely canonicalized URL representation")
    parse_status: ParseStatus = Field(..., description="Parse status: parsed, malformed, unsupported_scheme, missing_scheme")
    normalized_hostname: Optional[str] = Field(None, description="Normalized hostname safely extracted without sensitive query/userinfo")
    features: URLFeatures = Field(..., description="Extracted structural and lexical features")
    observations: List[URLObservation] = Field(default_factory=list, description="Rule-based explainable observations")
    heuristic_risk_category: HeuristicRiskCategory = Field(
        HeuristicRiskCategory.INFO,
        description="Overall heuristic risk tier (INFO, LOW, MEDIUM, HIGH). Not a calibrated probability."
    )
    heuristic_risk_score: int = Field(
        0,
        ge=0,
        le=100,
        description="Explainable heuristic risk score (0-100) based on weighted rule observations. Not a probability."
    )
    risk_summary: str = Field(..., description="Summary explanation of the risk assessment")


class URLBatchAnalysisResult(BaseModel):
    """
    Summary and per-URL results for a collection of URLs (e.g. from an analyzed email).
    """
    total_urls: int = Field(0, description="Total count of URLs analyzed")
    unique_urls: int = Field(0, description="Count of distinct normalized URLs")
    risk_breakdown: dict = Field(
        default_factory=lambda: {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0},
        description="Count of URLs in each risk category"
    )
    highest_risk_category: HeuristicRiskCategory = Field(
        HeuristicRiskCategory.INFO,
        description="Highest risk tier observed across all analyzed URLs"
    )
    url_results: List[URLAnalysisResult] = Field(
        default_factory=list,
        description="Individual per-URL analysis results"
    )
    analyzed_at: str = Field(..., description="ISO 8601 UTC timestamp of URL analysis pass")
