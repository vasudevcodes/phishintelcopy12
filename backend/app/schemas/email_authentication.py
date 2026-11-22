"""
Pydantic schemas for Email Authentication Evidence Engine (Phase 5A).
Interprets reported SPF, DKIM, and DMARC evidence from email headers.
"""

from enum import Enum
from typing import Any, Dict, List, NamedTuple, Optional
from pydantic import BaseModel, Field

# Re-export so callers can import ProvenanceStatus and AuthservTrustResult from this module
__all__ = [
    "AuthResultStatus",
    "OverallAuthStatus",
    "AuthservTrustStatus",
    "AuthservTrustResult",
    "ProvenanceStatus",
    "HeaderFinding",
    "SPFEvidence",
    "DKIMEvidence",
    "DMARCEvidence",
    "EmailAuthenticationAnalysis",
]


class AuthResultStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SOFTFAIL = "SOFTFAIL"
    NEUTRAL = "NEUTRAL"
    NONE = "NONE"
    TEMPERROR = "TEMPERROR"
    PERMERROR = "PERMERROR"
    UNKNOWN = "UNKNOWN"
    NOT_PRESENT = "NOT_PRESENT"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"


class OverallAuthStatus(str, Enum):
    EVALUATED = "EVALUATED"
    NO_EVIDENCE = "NO_EVIDENCE"
    PARTIAL_EVIDENCE = "PARTIAL_EVIDENCE"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"


class AuthservTrustStatus(str, Enum):
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    MISSING = "MISSING"
    SUSPICIOUS = "SUSPICIOUS"
    # Stage A.2: added to represent authserv-id domain match in an offline .eml upload context.
    # Domain matching is not provenance proof — REPORTED means the assertion came from the email
    # file itself, not from an independently established trusted ingestion mechanism.
    REPORTED = "REPORTED"


class AuthservTrustResult(NamedTuple):
    """
    Stage A.3: Structured, immutable return contract for authserv-id trust validation.

    Safety Guarantee:
    `is_trusted` is False whenever authentication provenance is not independently
    established (e.g., for all offline .eml uploads). It is True ONLY for TRUSTED.

    Preserves 3-element tuple unpacking compatibility:
        is_trusted, status, explanation = validate_authserv_id_trust(...)

    Also provides `.domain_matches_policy` for callers needing to know whether the
    authserv-id matched a configured gateway policy domain without mistaking that match
    for established trust.
    """
    is_trusted: bool
    status: AuthservTrustStatus
    explanation: str

    @property
    def domain_matches_policy(self) -> bool:
        """Returns True if the authserv-id matched a known gateway policy domain."""
        return self.status in (AuthservTrustStatus.TRUSTED, AuthservTrustStatus.REPORTED)


class ProvenanceStatus(str, Enum):
    """
    Stage A.2: Explicit provenance classification for authentication assertions.

    For offline .eml upload workflows, all authentication assertions found in
    email headers are REPORTED — they reflect claims made within the uploaded
    file and cannot be independently verified as originating from the alleged MTA.

    TRUSTED_RECEIVER_EVIDENCE is reserved for future infrastructure-level
    integration where the ingestion mechanism itself establishes provenance
    (e.g., direct API call to a trusted mail gateway).  It MUST NOT be set
    for any offline .eml upload regardless of authserv-id domain matching.
    """
    TRUSTED_RECEIVER_EVIDENCE = "TRUSTED_RECEIVER_EVIDENCE"
    REPORTED_AUTHENTICATION = "REPORTED_AUTHENTICATION"
    UNTRUSTED_AUTHENTICATION = "UNTRUSTED_AUTHENTICATION"
    MISSING_AUTHENTICATION = "MISSING_AUTHENTICATION"


class HeaderFinding(BaseModel):
    """
    Represents a single authentication finding extracted from a specific header.
    """
    method: str = Field(..., description="Authentication protocol: 'spf', 'dkim', or 'dmarc'")
    result: AuthResultStatus = Field(..., description="Normalized result status")
    raw_result: str = Field(..., description="Original raw token from header, e.g. 'pass', 'fail'")
    source_header: str = Field(..., description="Header where finding was discovered: 'Authentication-Results' or 'Received-SPF'")
    header_index: int = Field(0, description="0-based index of the source header in the email's header list")
    authserv_id: Optional[str] = Field(None, description="Reported authserv-id (MTA hostname/identifier) for Authentication-Results")
    authserv_trust: AuthservTrustStatus = Field(AuthservTrustStatus.UNTRUSTED, description="Trust verification status of the recording MTA")
    properties: Dict[str, str] = Field(default_factory=dict, description="Extracted key-value properties (e.g. header.i, header.d, header.s, client-ip)")
    reason: Optional[str] = Field(None, description="Reported human-readable reason or comment text")
    raw_snippet: Optional[str] = Field(None, description="Sanitized snippet of the method clause")
    is_boundary_mta: bool = Field(False, description="Whether this finding was recorded by the outermost recipient boundary MTA (index 0)")


class SPFEvidence(BaseModel):
    """
    Interpreted SPF authentication evidence.
    """
    status: AuthResultStatus = Field(..., description="Consolidated SPF result status")
    findings: List[HeaderFinding] = Field(default_factory=list, description="All individual SPF findings from inspected headers")
    domain: Optional[str] = Field(None, description="Sender domain evaluated for SPF (from smtp.mailfrom or Received-SPF identity)")
    client_ip: Optional[str] = Field(None, description="Client IP evaluated for SPF")
    explanation: str = Field(..., description="Concise explanation of the SPF evidence")
    trust_limitation: Optional[str] = Field(None, description="Trust boundary warning or caveat")


class DKIMEvidence(BaseModel):
    """
    Interpreted DKIM authentication evidence.
    """
    status: AuthResultStatus = Field(..., description="Consolidated DKIM result status")
    findings: List[HeaderFinding] = Field(default_factory=list, description="All individual DKIM findings from inspected headers")
    has_dkim_signature_header: bool = Field(False, description="Whether one or more raw DKIM-Signature headers exist on the email")
    dkim_signature_count: int = Field(0, description="Count of raw DKIM-Signature headers present")
    domain: Optional[str] = Field(None, description="Signing domain (header.d or header.i)")
    selector: Optional[str] = Field(None, description="DKIM key selector (header.s)")
    explanation: str = Field(..., description="Concise explanation of the DKIM evidence")
    trust_limitation: Optional[str] = Field(None, description="Trust boundary warning or caveat")


class DMARCEvidence(BaseModel):
    """
    Interpreted DMARC authentication evidence.
    """
    status: AuthResultStatus = Field(..., description="Consolidated DMARC result status")
    findings: List[HeaderFinding] = Field(default_factory=list, description="All individual DMARC findings from inspected headers")
    policy: Optional[str] = Field(None, description="Reported domain DMARC policy (p=none, p=quarantine, p=reject)")
    subdomain_policy: Optional[str] = Field(None, description="Reported subdomain policy (sp=...)")
    disposition: Optional[str] = Field(None, description="Reported receiver action/disposition (dis=none, dis=reject, etc.)")
    header_from: Optional[str] = Field(None, description="From header domain evaluated for DMARC (header.from)")
    alignment_verified: bool = Field(False, description="Whether available evidence explicitly confirms SPF/DKIM alignment")
    explanation: str = Field(..., description="Concise explanation of the DMARC evidence")
    trust_limitation: Optional[str] = Field(None, description="Trust boundary warning or caveat")


class EmailAuthenticationAnalysis(BaseModel):
    """
    Complete structured evidence report for reported email authentication headers.
    """
    status: OverallAuthStatus = Field(..., description="Overall analysis status across all three protocols")
    spf: SPFEvidence = Field(..., description="SPF authentication evidence")
    dkim: DKIMEvidence = Field(..., description="DKIM authentication evidence")
    dmarc: DMARCEvidence = Field(..., description="DMARC authentication evidence")
    headers_inspected: List[str] = Field(default_factory=list, description="List of header types inspected")
    authserv_ids: List[str] = Field(default_factory=list, description="List of unique authserv-id identifiers found in Authentication-Results")
    boundary_authserv_id: Optional[str] = Field(None, description="Reported authserv-id of outermost recipient boundary MTA (index 0)")
    boundary_authserv_trust: AuthservTrustStatus = Field(AuthservTrustStatus.UNTRUSTED, description="Trust status of the boundary MTA authserv-id")
    is_boundary_trusted: bool = Field(False, description="Whether authentication evidence originated from a verified trusted boundary MTA")
    has_conflicts: bool = Field(False, description="Whether contradictory results were found across headers")
    warnings: List[str] = Field(default_factory=list, description="Non-fatal ambiguities, malformed entries, or trust warnings")
    # Stage A.2: Explicit provenance classification for all authentication assertions found in this email.
    # For offline .eml uploads this is always REPORTED_AUTHENTICATION or weaker — never TRUSTED_RECEIVER_EVIDENCE.
    provenance_status: "ProvenanceStatus" = Field(
        default=ProvenanceStatus.REPORTED_AUTHENTICATION,
        description=(
            "Stage A.2 provenance classification. REPORTED_AUTHENTICATION means assertions were found "
            "in the uploaded .eml file; provenance is NOT independently established. "
            "TRUSTED_RECEIVER_EVIDENCE is reserved for future infrastructure-level integration only."
        ),
    )
    dkim_crypto: Optional[List[Dict[str, Any]]] = Field(
        None,
        description="Cryptographic DKIM verification (RFC 6376): body-hash recomputation and signature verification. In live mode the public key is fetched from DNS; in offline mode it comes from locally pinned keys.",
    )
    verification_mode: str = Field(
        default="OFFLINE_REPORTED",
        description="'LIVE_DNS' when SPF/DKIM/DMARC were re-computed by PhishIntel against live DNS; 'OFFLINE_REPORTED' when statuses only reflect claims inside the uploaded headers.",
    )
    live_verification: Optional[Dict[str, Any]] = Field(
        None,
        description="Full live DNS verification report (SPF check_host, DKIM key lookup + signature check, DMARC policy + alignment), including caveats and DNS errors.",
    )
    disclaimer: str = Field(
        default=(
            "Authentication evidence reflects downstream MTA header assertions (RFC 8601/RFC 7208). "
            "Phase 5A does not perform live DNS queries or fetch public keys; DKIM signatures are verified offline only against locally pinned keys (see dkim_crypto). "
            "For offline .eml uploads, all authentication assertions are REPORTED — their origin cannot be independently "
            "established. An authserv-id matching a known mail gateway (e.g. mx.google.com) does NOT prove the header "
            "originated from that gateway; the string can be trivially forged by any sender."
        ),
        description="Explicit limitation regarding offline header interpretation vs cryptographic verification",
    )
