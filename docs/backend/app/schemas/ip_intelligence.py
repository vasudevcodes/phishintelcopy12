"""
Pydantic schemas for IP Intelligence Engine (Phase 6A).
Classifies and evaluates IP candidates extracted from RFC 5322 Received headers.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class IPClassification(str, Enum):
    PUBLIC = "Public"
    PRIVATE = "Private"
    LOOPBACK = "Loopback"
    LINK_LOCAL = "Link-Local"
    MULTICAST = "Multicast"
    DOCUMENTATION = "Documentation"
    SPECIAL_PURPOSE = "Special-Purpose"
    RESERVED = "Reserved"
    UNSPECIFIED = "Unspecified"
    INVALID = "Invalid"
    UNAVAILABLE = "Unavailable"


class GeolocationStatus(str, Enum):
    DATABASE_UNAVAILABLE = "DATABASE_UNAVAILABLE"
    NOT_ROUTABLE = "NOT_ROUTABLE"
    LOOKUP_SUCCESS = "LOOKUP_SUCCESS"
    NOT_FOUND = "NOT_FOUND"


class IPGeolocationData(BaseModel):
    """
    Database-derived geolocation information. Only populated when an offline
    GeoLite2-compatible database is locally available and matched.
    """
    country_name: Optional[str] = Field(None, description="Country name derived from local database")
    country_code: Optional[str] = Field(None, description="Two-letter ISO 3166-1 country code")
    city_name: Optional[str] = Field(None, description="City name derived from local database")
    latitude: Optional[float] = Field(None, description="Approximate latitude of network egress")
    longitude: Optional[float] = Field(None, description="Approximate longitude of network egress")
    asn: Optional[int] = Field(None, description="Autonomous System Number (ASN)")
    as_org: Optional[str] = Field(None, description="Autonomous System organization name / ISP")


class CandidateIPIntelligence(BaseModel):
    """
    Analysis and forensic classification for a single extracted IP candidate.
    """
    ip: str = Field(..., description="Original extracted IP string or token")
    version: Optional[int] = Field(None, description="IP version: 4, 6, or None if invalid")
    classification: IPClassification = Field(..., description="Forensic IP classification")
    hop_index: Optional[int] = Field(None, description="Hop index in Received headers (0 is newest/recipient gateway)")
    source_header: Optional[str] = Field(None, description="Header snippet where IP was discovered")
    is_routable: bool = Field(False, description="Whether this IP is globally routable on the public Internet")
    geolocation_status: GeolocationStatus = Field(..., description="Offline geolocation lookup status")
    geolocation: Optional[IPGeolocationData] = Field(None, description="Offline database geolocation data if available")
    role_hint: str = Field(..., description="Forensic role hint (e.g. Ingress Gateway, Internal Relay, Apparent Origin)")
    explanation: str = Field(..., description="Concise explanation of the classification and provenance")
    provider_indicator: Optional[str] = Field(None, description="Short indicator label for matched provider infrastructure")
    provider_match_category: Optional[str] = Field(None, description="Service category of the provider match")
    provider_confidence: Optional[str] = Field(None, description="Confidence rating for provider infrastructure match")
    provider_source_url: Optional[str] = Field(None, description="Authoritative documentation URL for the matched netblock")


class IPIntelligenceResult(BaseModel):
    """
    Overall structured IP intelligence response for all candidates in an email.
    """
    total_candidates: int = Field(0, description="Total IP candidates analyzed")
    candidates: List[CandidateIPIntelligence] = Field(default_factory=list, description="Per-candidate intelligence records")
    origin_candidate: Optional[CandidateIPIntelligence] = Field(
        None, description="Candidate identified as closest to email origin in the transit path"
    )
    origin_assessment: str = Field(..., description="Forensic summary regarding originating IP identification")
    origin_attribution_status: str = Field(
        default="UNAVAILABLE", description="Availability status: 'UNAVAILABLE', 'AVAILABLE_UNVERIFIED'"
    )
    sender_identity_status: str = Field(
        default="Not established", description="Sender identity confidence: 'Not established', 'Unverified candidate (pre-boundary)', etc."
    )
    provider_infrastructure_match: Optional[str] = Field(
        default=None, description="Provider infrastructure match (e.g. 'Likely Google infrastructure')"
    )
    candidate_ip_classification: str = Field(
        default="Unavailable", description="Address classification of primary candidate ('Public', 'Private', etc.)"
    )
    is_candidate_routable: Optional[bool] = Field(
        default=None, description="Routability of primary candidate IP, independent of origin availability"
    )
    public_count: int = Field(0, description="Count of public IP candidates")
    private_count: int = Field(0, description="Count of private IP candidates")
    other_count: int = Field(0, description="Count of loopback, special-purpose, or non-routable candidates")
    database_available: bool = Field(False, description="Whether a valid local offline GeoLite2 database was loaded")
    warnings: List[str] = Field(default_factory=list, description="Forensic warnings regarding IP hops or anomalies")
    disclaimer: str = Field(
        default="IP analysis is strictly offline and deterministic. Geolocation reflects approximate network registration "
                "or egress routing, NOT a person's physical location. Received transit headers prior to the receiving "
                "boundary MTA may be forged or manipulated by untrusted relays.",
        description="Explicit limitation disclaimer"
    )
