"""
Pydantic schemas for PhishIntel Email Analysis (Phase 1).
"""

from typing import List, Optional
from pydantic import BaseModel, Field

from app.schemas.email_authentication import EmailAuthenticationAnalysis
from app.schemas.evidence_fusion import EvidenceFusionResult, ModelInferenceEvidence
from app.schemas.ip_intelligence import IPIntelligenceResult
from app.schemas.url_intelligence import URLBatchAnalysisResult


class EmailHeaderInfo(BaseModel):
    from_header: Optional[str] = Field(None, description="Sender header (From)")
    to_headers: List[str] = Field(default_factory=list, description="Recipient headers (To)")
    cc_headers: List[str] = Field(default_factory=list, description="Carbon copy headers (Cc)")
    bcc_headers: List[str] = Field(default_factory=list, description="Blind carbon copy headers (Bcc, if present)")
    subject: Optional[str] = Field(None, description="Email subject line")
    date: Optional[str] = Field(None, description="Date header string as reported in email")
    message_id: Optional[str] = Field(None, description="Message-ID header")
    reply_to: Optional[str] = Field(None, description="Reply-To header")
    return_path: Optional[str] = Field(None, description="Return-Path header")
    mime_version: Optional[str] = Field(None, description="MIME-Version header")
    content_type: Optional[str] = Field(None, description="Top-level Content-Type header")
    authentication_results: List[str] = Field(default_factory=list, description="Authentication-Results headers in order")
    received_spf: List[str] = Field(default_factory=list, description="Received-SPF headers in order")
    dkim_signatures: List[str] = Field(default_factory=list, description="DKIM-Signature headers in order")
    received_headers: List[str] = Field(
        default_factory=list,
        description="All Received headers preserved in original extracted order (index 0 is typically the newest hop; last is typically the oldest hop)"
    )


class EmailBodyInfo(BaseModel):
    has_plain_text: bool = Field(False, description="Whether text/plain part is present")
    plain_text: Optional[str] = Field(None, description="Extracted text/plain content")
    has_html: bool = Field(False, description="Whether text/html part is present")
    html_extracted_text: Optional[str] = Field(None, description="Safely extracted readable text from HTML body")
    plain_text_char_count: int = Field(0, description="Character count of plain text")
    html_text_char_count: int = Field(0, description="Character count of extracted HTML text")


class ExtractedURL(BaseModel):
    url: str = Field(..., description="Preserved original URL string")
    scheme: Optional[str] = Field(None, description="URL protocol scheme (e.g. http, https)")
    domain: Optional[str] = Field(None, description="Parsed domain / hostname")
    source: str = Field(..., description="Origin of URL: 'plain_text', 'html_href', or 'both'")
    anchor_text: Optional[str] = Field(None, description="Anchor text / link label if extracted from HTML <a> tag")


class AttachmentInfo(BaseModel):
    filename: str = Field(..., description="Sanitized attachment filename")
    content_type: str = Field(..., description="MIME type of attachment")
    size_bytes: int = Field(..., description="Attachment size in bytes")
    sha256: Optional[str] = Field(None, description="SHA-256 hexadecimal digest of payload")


class IPCandidate(BaseModel):
    ip: str = Field(..., description="Candidate IP address string (IPv4 or IPv6)")
    version: int = Field(..., description="IP version: 4 or 6")
    classification: str = Field(
        ...,
        description="Classification: 'Public', 'Private', 'Loopback', 'Link-Local', 'Multicast', 'Documentation', 'Reserved', or 'Special-Purpose'"
    )
    hop_index: int = Field(..., description="0-based index of Received header in extracted order (index 0 is typically the newest hop, last is typically the oldest)")
    source_header: str = Field(..., description="Truncated or complete Received header snippet containing this IP")


class EmailAnalysisResponse(BaseModel):
    filename: str = Field(..., description="Name of uploaded .eml file")
    file_size_bytes: int = Field(..., description="File size in bytes")
    headers: EmailHeaderInfo = Field(..., description="Parsed email headers")
    body: EmailBodyInfo = Field(..., description="Email body forensic info")
    urls: List[ExtractedURL] = Field(default_factory=list, description="Extracted and deduplicated URLs")
    attachments: List[AttachmentInfo] = Field(default_factory=list, description="Attachment metadata and hashes")
    ip_candidates: List[IPCandidate] = Field(default_factory=list, description="Candidate IPs extracted from Received headers")
    url_analysis: Optional[URLBatchAnalysisResult] = Field(
        None,
        description="Structured deterministic URL intelligence analysis for extracted URLs (Phase 4A)"
    )
    authentication_analysis: Optional[EmailAuthenticationAnalysis] = Field(
        None,
        description="Reported email authentication evidence (SPF, DKIM, DMARC) interpreted from headers (Phase 5A)"
    )
    ip_intelligence: Optional[IPIntelligenceResult] = Field(
        None,
        description="Structured IP intelligence and forensic classification for Received header IP candidates (Phase 6A)"
    )
    evidence_fusion: Optional[EvidenceFusionResult] = Field(
        None,
        description="Transparent multi-modal evidence fusion assessment combining URL, auth, IP, and model signals (Phase 7A)"
    )
    model_inference: Optional[ModelInferenceEvidence] = Field(
        None,
        description="Direct DistilBERT text inference evidence (Phase 8A)"
    )
    parsing_status: str = Field("success", description="Status of parsing: 'success' or 'partial_success'")
    warnings: List[str] = Field(default_factory=list, description="Non-fatal warnings encountered during parsing")
    parsed_at: str = Field(..., description="ISO 8601 UTC timestamp of analysis")


class ErrorResponse(BaseModel):
    detail: str = Field(..., description="Error message description")
