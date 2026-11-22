import { test, describe } from 'node:test';
import assert from 'node:assert';
import { generateForensicReportHtml } from '../utils/reportGenerator.ts';
import type { EmailAnalysisResponse } from '../types/forensics.ts';

const baseMockData: EmailAnalysisResponse = {
  filename: 'test_targeted_cleanup.eml',
  file_size_bytes: 4096,
  parsing_status: 'success',
  warnings: [],
  parsed_at: '2026-11-14T14:00:00Z',
  headers: {
    from_header: 'Security Team <security@example.com>',
    to_headers: ['analyst@company.org'],
    cc_headers: [],
    bcc_headers: [],
    subject: 'Targeted UI and Report Cleanup Verification',
    date: 'Wed, 14 Nov 2026 14:00:00 +0000',
    message_id: '<msg-cleanup-123@example.com>',
    reply_to: null,
    return_path: '<security@example.com>',
    mime_version: '1.0',
    content_type: 'multipart/alternative',
    authentication_results: [],
    received_spf: [],
    dkim_signatures: [],
    received_headers: ['from relay.net by mta.org; Wed, 14 Nov 2026 14:00:00 +0000'],
  },
  body: {
    has_plain_text: true,
    plain_text: 'Please visit https://portal.example.com/verify to complete verification.',
    has_html: true,
    html_extracted_text: 'Please visit portal to verify.',
    plain_text_char_count: 70,
    html_text_char_count: 30,
  },
  attachments: [],
  urls: [
    {
      url: 'https://portal.example.com/verify',
      scheme: 'https',
      domain: 'portal.example.com',
      source: 'both',
    },
  ],
  ip_candidates: [
    {
      ip: '198.51.100.42',
      version: 4,
      classification: 'Public',
      hop_index: 0,
      source_header: 'from relay.net by mta.org',
    },
  ],
  url_analysis: {
    total_urls: 1,
    unique_urls: 1,
    risk_breakdown: { INFO: 1, LOW: 0, MEDIUM: 0, HIGH: 0 },
    highest_risk_category: 'INFO',
    url_results: [
      {
        url_index: 0,
        original_url: 'https://portal.example.com/verify',
        source: 'both',
        normalized_url: 'https://portal.example.com/verify',
        parse_status: 'parsed',
        normalized_hostname: 'portal.example.com',
        features: {
          scheme: 'https',
          is_https: true,
          is_http: false,
          is_unusual_scheme: false,
          raw_host: 'portal.example.com',
          normalized_host: 'portal.example.com',
          host_type: 'domain',
          is_ip_literal: false,
          ip_version: null,
          host_classification: 'public',
          has_trailing_dot: false,
          url_length: 33,
          host_length: 18,
          subdomain_count: 1,
          dots_in_host: 2,
          hyphens_in_host: 0,
          dots_in_url: 2,
          hyphens_in_url: 0,
          has_userinfo: false,
          port: null,
          is_non_default_port: false,
          percent_encoding_count: 0,
          is_punycode: false,
          has_unicode: false,
          has_path: true,
          path_length: 7,
          has_query: false,
          query_param_count: 0,
          has_fragment: false,
        },
        observations: [],
        heuristic_risk_category: 'INFO',
        heuristic_risk_score: 5,
        risk_summary: 'Standard HTTPS link.',
      },
    ],
    analyzed_at: '2026-11-14T14:00:00Z',
  },
  model_inference: {
    status: 'EVALUATED',
    predicted_label: 0,
    uncalibrated_score: 0.0412,
    error_message: null,
  },
  authentication_analysis: null,
  ip_intelligence: {
    total_candidates: 1,
    public_count: 1,
    private_count: 0,
    other_count: 0,
    origin_candidate: {
      ip: '198.51.100.42',
      version: 4,
      classification: 'Public',
      hop_index: 0,
      source_header: 'from relay.net by mta.org',
      is_routable: true,
      geolocation_status: 'DATABASE_UNAVAILABLE',
      role_hint: 'Boundary Ingress Hop',
      explanation: 'Egress candidate',
    },
    origin_assessment: 'Apparent egress relay candidate at Hop 0.',
    origin_attribution_status: 'AVAILABLE_UNVERIFIED',
    candidate_ip_classification: 'Public',
    is_candidate_routable: true,
    provider_infrastructure_match: null,
    sender_identity_status: 'Unverified',
    database_available: false,
    warnings: ['Hop 0 is unverified public egress'],
    disclaimer: 'IP egress reflects routing, not identity.',
    candidates: [
      {
        ip: '198.51.100.42',
        version: 4,
        classification: 'Public',
        hop_index: 0,
        source_header: 'from relay.net by mta.org',
        is_routable: true,
        geolocation_status: 'DATABASE_UNAVAILABLE',
        role_hint: 'Boundary Ingress Hop',
        explanation: 'Egress candidate',
      },
    ],
  },
  evidence_fusion: {
    overall_category: 'LOW_RISK_INDICATORS',
    overall_risk_score: 5,
    reasoning: 'Minimal risk indicators detected.',
    disclaimer: 'Heuristic assessment disclaimer.',
    contributing_factors: [],
    inconclusive_or_missing_factors: [],
    model_evidence: {
      status: 'EVALUATED',
      uncalibrated_score: 0.0412,
      predicted_label: 0,
      interpretation: 'Text exhibits standard organizational communication patterns.',
      caveat: 'Score is uncalibrated output.',
    },
    url_evidence: {
      total_urls: 1,
      unique_domains: 1,
      highest_heuristic_risk: 'INFO',
      suspicious_indicators: [],
      deduplication_applied: false,
      explanation: 'All links benign',
      heuristic_disclaimer: 'Zero touch static',
    },
    auth_evidence: {
      spf_status: 'NONE',
      dkim_status: 'NONE',
      dmarc_status: 'NONE',
      has_conflicts: false,
      has_valid_authentication: false,
      has_explicit_failure: false,
      correlated_failure_noted: false,
      explanation: 'No auth headers present',
      trust_limitation: 'Offline limitation',
    },
    ip_evidence: {
      origin_classification: 'Public',
      is_routable: true,
      hop_count: 1,
      explanation: 'Hop 0 recorded',
      provenance_limitation: 'Provenance unverified',
    },
  },
};

describe('Targeted UI and Report Cleanup Verification', () => {
  test('Task 2: Yellow DistilBERT caveat box is absent from report', () => {
    const html = generateForensicReportHtml(baseMockData);
    assert.ok(!html.includes('Prominent Calibration Caveat:'), 'Must not contain Prominent Calibration Caveat');
    assert.ok(!html.includes('caveat-box'), 'Must not contain caveat-box class');
    assert.ok(html.includes('Forensic Interpretation:'), 'Forensic interpretation must be preserved');
    assert.ok(html.includes('0.0412'), 'Raw uncalibrated score must be preserved');
    assert.ok(html.includes('0 (Benign Pattern)'), 'Predicted label must be preserved');
  });

  test('Task 3: IP Transit Anomalies / Transit Reconstruction title is absent from report', () => {
    const html = generateForensicReportHtml(baseMockData);
    assert.ok(!html.includes('Transit Reconstruction'), 'Must not contain Transit Reconstruction in title');
    assert.ok(!html.includes('IP Transit Anomalies:'), 'Must not contain IP Transit Anomalies box');
    assert.ok(html.includes('5. IP Intelligence'), 'Section 5 must be titled 5. IP Intelligence');
    assert.ok(html.includes('198.51.100.42'), 'IP candidate table must be preserved');
    assert.ok(html.includes('Origin Transit Evaluation'), 'Origin evaluation must be preserved');
  });

  test('Task 1: URL Intelligence displays authoritative URLs and consistent counts', () => {
    const html = generateForensicReportHtml(baseMockData);
    assert.ok(html.includes('3. URL Intelligence &amp; Lexical Heuristics'));
    assert.ok(html.includes('https://portal.example.com/verify'));
    assert.ok(html.includes('Total URLs</div>\n          <div class="card-val">1</div>'));
    assert.ok(html.includes('Unique URLs</div>\n          <div class="card-val">1</div>'));
  });

  test('URL Intelligence empty state renders clean message when no URLs exist', () => {
    const noUrlsData: EmailAnalysisResponse = {
      ...baseMockData,
      urls: [],
      url_analysis: {
        total_urls: 0,
        unique_urls: 0,
        risk_breakdown: { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0 },
        highest_risk_category: 'INFO',
        url_results: [],
        analyzed_at: '2026-11-14T14:00:00Z',
      },
    };
    const html = generateForensicReportHtml(noUrlsData);
    assert.ok(html.includes('No URLs extracted from email text or HTML parts.'));
    assert.ok(!html.includes('https://portal.example.com/verify'));
  });

  test('Consecutive report generation maintains strict email isolation', () => {
    const emailA: EmailAnalysisResponse = {
      ...baseMockData,
      filename: 'newsletter_email.eml',
      urls: [
        { url: 'https://updates.tech/articles/ai', scheme: 'https', domain: 'updates.tech', source: 'both', anchor_text: 'Tech Update' },
      ],
      url_analysis: {
        total_urls: 1,
        unique_urls: 1,
        risk_breakdown: { INFO: 1, LOW: 0, MEDIUM: 0, HIGH: 0 },
        highest_risk_category: 'INFO',
        url_results: [],
        analyzed_at: '2026-11-14T14:00:00Z',
      },
    };

    const emailB: EmailAnalysisResponse = {
      ...baseMockData,
      filename: 'clean_email.eml',
      urls: [],
      url_analysis: {
        total_urls: 0,
        unique_urls: 0,
        risk_breakdown: { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0 },
        highest_risk_category: 'INFO',
        url_results: [],
        analyzed_at: '2026-11-14T14:05:00Z',
      },
    };

    const htmlA = generateForensicReportHtml(emailA);
    const htmlB = generateForensicReportHtml(emailB);

    assert.ok(htmlA.includes('https://updates.tech/articles/ai'));
    assert.ok(htmlA.includes('Label: &ldquo;Tech Update&rdquo;'));
    assert.ok(!htmlB.includes('https://updates.tech/articles/ai'));
    assert.ok(!htmlB.includes('Tech Update'));
    assert.ok(htmlB.includes('No URLs extracted from email text or HTML parts.'));
  });

  test('Task 4: Report retains offline W3C CSP Level 3 policy', () => {
    const html = generateForensicReportHtml(baseMockData);
    assert.ok(html.includes("default-src 'none'"));
    assert.ok(html.includes("script-src 'none'"));
    assert.ok(html.includes("style-src 'unsafe-inline'"));
    assert.ok(html.includes("img-src data:"));
  });
});
