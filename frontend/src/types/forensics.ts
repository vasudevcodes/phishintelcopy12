/**
 * TypeScript forensic schemas for PhishIntel frontend.
 * Accurately mirrors backend Pydantic models from Phases 1 through 8A.
 */

// --- Phase 1: Header, Body, URLs, Attachments, IPs ---

export interface EmailHeaderInfo {
  from_header: string | null;
  to_headers: string[];
  cc_headers: string[];
  bcc_headers: string[];
  subject: string | null;
  date: string | null;
  message_id: string | null;
  reply_to: string | null;
  return_path: string | null;
  mime_version: string | null;
  content_type: string | null;
  authentication_results: string[];
  received_spf: string[];
  dkim_signatures?: string[];
  received_headers: string[];
}

export interface EmailBodyInfo {
  has_plain_text: boolean;
  plain_text: string | null;
  has_html: boolean;
  html_extracted_text: string | null;
  plain_text_char_count: number;
  html_text_char_count: number;
}

export interface ExtractedURL {
  url: string;
  scheme: string | null;
  domain: string | null;
  source: 'plain_text' | 'html_href' | 'both';
  anchor_text?: string | null;
}

export interface AttachmentInfo {
  filename: string;
  content_type: string;
  size_bytes: number;
  sha256: string | null;
}

export type IPClassification =
  | 'Public'
  | 'Private'
  | 'Loopback'
  | 'Link-Local'
  | 'Multicast'
  | 'Documentation'
  | 'Special-Purpose'
  | 'Reserved'
  | 'Unspecified'
  | 'Invalid'
  | 'Unavailable';

export interface IPCandidate {
  ip: string;
  version: number;
  classification: IPClassification;
  hop_index: number;
  source_header: string;
}

// --- Phase 4A / 4B: URL Intelligence ---

export type ParseStatus = 'parsed' | 'malformed' | 'unsupported_scheme' | 'missing_scheme';
export type HostType = 'domain' | 'ipv4' | 'ipv6' | 'localhost' | 'invalid';
export type HostClassification = 'public' | 'private' | 'loopback' | 'link_local' | 'reserved' | 'documentation' | 'unknown';
export type ObservationSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH';
export type HeuristicRiskCategory = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH';

export interface URLFeatures {
  scheme: string | null;
  is_https: boolean;
  is_http: boolean;
  is_unusual_scheme: boolean;
  raw_host: string | null;
  normalized_host: string | null;
  host_type: HostType;
  is_ip_literal: boolean;
  ip_version: number | null;
  host_classification: HostClassification;
  has_trailing_dot: boolean;
  url_length: number;
  host_length: number;
  subdomain_count: number;
  dots_in_host: number;
  hyphens_in_host: number;
  dots_in_url: number;
  hyphens_in_url: number;
  has_userinfo: boolean;
  port: number | null;
  is_non_default_port: boolean;
  percent_encoding_count: number;
  is_punycode: boolean;
  has_unicode: boolean;
  has_path: boolean;
  path_length: number;
  has_query: boolean;
  query_param_count: number;
  has_fragment: boolean;
}

export interface URLObservation {
  rule_id: string;
  rule_name: string;
  severity: ObservationSeverity;
  description: string;
}

export interface URLAnalysisResult {
  url_index: number;
  original_url: string;
  source?: string | null;
  normalized_url?: string | null;
  parse_status: ParseStatus;
  normalized_hostname?: string | null;
  features: URLFeatures;
  observations: URLObservation[];
  heuristic_risk_category: HeuristicRiskCategory;
  heuristic_risk_score: number;
  risk_summary: string;
}

export interface URLBatchAnalysisResult {
  total_urls: number;
  unique_urls: number;
  risk_breakdown: Record<string, number>;
  highest_risk_category: HeuristicRiskCategory;
  url_results: URLAnalysisResult[];
  analyzed_at: string;
}

// --- Phase 5A: Email Authentication ---

export type AuthResultStatus =
  | 'PASS'
  | 'FAIL'
  | 'SOFTFAIL'
  | 'NEUTRAL'
  | 'NONE'
  | 'TEMPERROR'
  | 'PERMERROR'
  | 'UNKNOWN'
  | 'NOT_PRESENT'
  | 'CONFLICTING_EVIDENCE';

export type AuthservTrustStatus = 'TRUSTED' | 'UNTRUSTED' | 'MISSING' | 'SUSPICIOUS' | 'REPORTED';

/**
 * Stage A.2: Explicit provenance classification for authentication assertions.
 * For offline .eml upload workflows, all authentication assertions found in
 * email headers are REPORTED_AUTHENTICATION — their origin cannot be independently
 * established. TRUSTED_RECEIVER_EVIDENCE is reserved for future infrastructure-level
 * integration only.
 */
export type ProvenanceStatus =
  | 'TRUSTED_RECEIVER_EVIDENCE'
  | 'REPORTED_AUTHENTICATION'
  | 'UNTRUSTED_AUTHENTICATION'
  | 'MISSING_AUTHENTICATION';
export type OverallAuthStatus =
  | 'EVALUATED'
  | 'NO_EVIDENCE'
  | 'PARTIAL_EVIDENCE'
  | 'CONFLICTING_EVIDENCE';

export interface HeaderFinding {
  method: string;
  result: AuthResultStatus;
  raw_result: string;
  source_header: string;
  header_index: number;
  authserv_id?: string | null;
  authserv_trust?: AuthservTrustStatus;
  is_boundary_mta?: boolean;
  properties: Record<string, string>;
  reason?: string | null;
  raw_snippet?: string | null;
}

export interface SPFEvidence {
  status: AuthResultStatus;
  findings: HeaderFinding[];
  domain?: string | null;
  client_ip?: string | null;
  explanation: string;
  trust_limitation?: string | null;
}

export interface DKIMEvidence {
  status: AuthResultStatus;
  findings: HeaderFinding[];
  has_dkim_signature_header: boolean;
  dkim_signature_count: number;
  domain?: string | null;
  selector?: string | null;
  explanation: string;
  trust_limitation?: string | null;
}

export interface DMARCEvidence {
  status: AuthResultStatus;
  findings: HeaderFinding[];
  policy?: string | null;
  subdomain_policy?: string | null;
  disposition?: string | null;
  header_from?: string | null;
  alignment_verified: boolean;
  explanation: string;
  trust_limitation?: string | null;
}

export interface DKIMCryptoResult {
  status: string;
  domain?: string | null;
  selector?: string | null;
  algorithm?: string | null;
  canonicalization?: string | null;
  body_hash_valid?: boolean | null;
  signature_valid?: boolean | null;
  key_source?: string | null;
  key_bits?: number | null;
  aligned_with_from?: boolean | null;
  covers_from_header?: boolean | null;
  weak_algorithm?: boolean;
  notes?: string[];
  /** Live mode: outcome of the DNS lookup for the signer's public key. */
  key_lookup?: {
    outcome?: string;
    record?: string;
    testing_mode?: boolean;
    key_type?: string;
    detail?: string;
  } | null;
}

// --- Live (online) DNS verification of SPF / DKIM / DMARC ---
export interface LiveSPFResult {
  evaluated?: boolean;
  result: string;
  domain?: string;
  sender?: string;
  client_ip?: string;
  client_ip_source?: string;
  helo?: string;
  identity?: string;
  mechanism?: string | null;
  record?: string | null;
  dns_lookups?: number;
  explanation?: string;
  trace?: string[];
  other_hops?: { client_ip: string; hop_index: number; result: string; explanation: string }[];
}

export interface LiveDKIMResult {
  result: string;
  domain?: string | null;
  selector?: string | null;
  explanation?: string;
  signatures?: DKIMCryptoResult[];
}

export interface LiveDMARCResult {
  result: string;
  from_domain?: string;
  policy_domain?: string | null;
  record?: string | null;
  policy?: string | null;
  subdomain_policy?: string | null;
  applied_policy?: string | null;
  pct?: number;
  adkim?: string;
  aspf?: string;
  spf_aligned?: boolean;
  dkim_aligned?: boolean;
  disposition?: string;
  explanation?: string;
  notes?: string[];
}

export interface LiveVerification {
  mode: string;
  available: boolean;
  error?: string;
  performed_at: string;
  message_age_days?: number | null;
  from_domain?: string;
  spf?: LiveSPFResult;
  dkim?: LiveDKIMResult;
  dmarc?: LiveDMARCResult;
  summary?: { spf?: string; dkim?: string; dmarc?: string };
  dns_errors: string[];
  caveats: string[];
  duration_ms?: number;
}

export interface EmailAuthenticationAnalysis {
  dkim_crypto?: DKIMCryptoResult[] | null;
  /** 'LIVE_DNS' when SPF/DKIM/DMARC were re-computed against live DNS; 'OFFLINE_REPORTED' otherwise. */
  verification_mode?: string;
  live_verification?: LiveVerification | null;
  status: OverallAuthStatus;
  spf: SPFEvidence;
  dkim: DKIMEvidence;
  dmarc: DMARCEvidence;
  headers_inspected: string[];
  authserv_ids: string[];
  boundary_authserv_id?: string | null;
  boundary_authserv_trust?: AuthservTrustStatus;
  is_boundary_trusted?: boolean;
  has_conflicts: boolean;
  warnings: string[];
  disclaimer: string;
  /**
   * Stage A.2: Explicit provenance classification for all authentication assertions.
   * For offline .eml uploads this is always REPORTED_AUTHENTICATION or weaker.
   * Never TRUSTED_RECEIVER_EVIDENCE for uploaded email files.
   */
  provenance_status?: ProvenanceStatus;
}

// --- Phase 6A: IP Intelligence ---

export type GeolocationStatus =
  | 'DATABASE_UNAVAILABLE'
  | 'NOT_ROUTABLE'
  | 'LOOKUP_SUCCESS'
  | 'NOT_FOUND';

export interface IPGeolocationData {
  country_name?: string | null;
  country_code?: string | null;
  city_name?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  asn?: number | null;
  as_org?: string | null;
}

export interface CandidateIPIntelligence {
  ip: string;
  version?: number | null;
  classification: IPClassification;
  hop_index?: number | null;
  source_header?: string | null;
  is_routable: boolean;
  geolocation_status: GeolocationStatus;
  geolocation?: IPGeolocationData | null;
  role_hint: string;
  explanation: string;
  provider_indicator?: string | null;
  provider_match_category?: string | null;
  provider_confidence?: string | null;
  provider_source_url?: string | null;
}

export interface IPIntelligenceResult {
  total_candidates: number;
  candidates: CandidateIPIntelligence[];
  origin_candidate?: CandidateIPIntelligence | null;
  origin_assessment: string;
  origin_attribution_status?: string;
  sender_identity_status?: string;
  provider_infrastructure_match?: string | null;
  candidate_ip_classification?: string;
  is_candidate_routable?: boolean | null;
  public_count: number;
  private_count: number;
  other_count: number;
  database_available: boolean;
  warnings: string[];
  disclaimer: string;
}

// --- Phase 7A / 8A: Evidence Fusion & DistilBERT Model Inference ---

export type AssessmentCategory =
  | 'INSUFFICIENT_EVIDENCE'
  | 'LOW_RISK_INDICATORS'
  | 'REVIEW_RECOMMENDED'
  | 'HIGH_RISK_INDICATORS_PRESENT';

export type ModelInferenceStatus = 'UNAVAILABLE' | 'EVALUATED' | 'ERROR';

export interface ModelInferenceEvidence {
  uncalibrated_score?: number | null;
  predicted_label?: number | null;
  status?: ModelInferenceStatus | null;
  error_message?: string | null;
}

export interface ModelEvidenceInterpretation {
  status: ModelInferenceStatus;
  uncalibrated_score: number | null;
  predicted_label: number | null;
  interpretation: string;
  caveat: string;
}

export interface URLEvidenceSummary {
  total_urls: number;
  unique_domains: number;
  highest_heuristic_risk: string;
  suspicious_indicators: string[];
  deduplication_applied: boolean;
  explanation: string;
  heuristic_disclaimer: string;
}

export interface AuthEvidenceSummary {
  spf_status: string;
  dkim_status: string;
  dmarc_status: string;
  has_conflicts: boolean;
  has_valid_authentication: boolean;
  has_explicit_failure: boolean;
  correlated_failure_noted: boolean;
  boundary_authserv_trust?: string;
  is_boundary_trusted?: boolean;
  explanation: string;
  trust_limitation: string;
}

export interface IPEvidenceSummary {
  apparent_origin_ip?: string | null;
  origin_classification: string;
  is_routable: boolean;
  hop_count: number;
  explanation: string;
  provenance_limitation: string;
}

export type EvidenceCompletenessStatus =
  | 'FULL_COVERAGE'
  | 'PARTIAL_COVERAGE'
  | 'MINIMAL_OR_INSUFFICIENT';

export interface CategoryScoreDetail {
  category_name: string;
  score: number;
  max_score: number;
  weight_percentage: number;
  explanation: string;
  rules_triggered: string[];
  is_dampened?: boolean;
}

export interface CategoryScoresBreakdown {
  sender_auth: CategoryScoreDetail;
  url_intelligence: CategoryScoreDetail;
  content_language: CategoryScoreDetail;
  ml_model: CategoryScoreDetail;
  header_ip: CategoryScoreDetail;
}

export interface EvidenceFusionResult {
  overall_category: AssessmentCategory;
  overall_risk_score?: number;
  risk_score_breakdown?: CategoryScoresBreakdown | null;
  evidence_completeness?: EvidenceCompletenessStatus;
  evidence_completeness_detail?: string;
  positive_evidence?: string[];
  negative_evidence?: string[];
  model_evidence: ModelEvidenceInterpretation;
  url_evidence: URLEvidenceSummary;
  auth_evidence: AuthEvidenceSummary;
  ip_evidence: IPEvidenceSummary;
  contributing_factors: string[];
  inconclusive_or_missing_factors: string[];
  reasoning: string;
  disclaimer: string;
}

// --- Top-Level Response ---

export interface EmailAnalysisResponse {
  filename: string;
  file_size_bytes: number;
  headers: EmailHeaderInfo;
  body: EmailBodyInfo;
  urls: ExtractedURL[];
  attachments: AttachmentInfo[];
  ip_candidates: IPCandidate[];
  url_analysis?: URLBatchAnalysisResult | null;
  authentication_analysis?: EmailAuthenticationAnalysis | null;
  ip_intelligence?: IPIntelligenceResult | null;
  evidence_fusion?: EvidenceFusionResult | null;
  model_inference?: ModelInferenceEvidence | null;
  parsing_status: 'success' | 'partial_success';
  warnings: string[];
  parsed_at: string;
}
