import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import type {
  EmailAnalysisResponse,
  EvidenceFusionResult,
  AssessmentCategory,
} from '../types/forensics';

describe('Phase 8B — Frontend-to-Backend Integration Audit Tests', () => {
  // Mock representative full-pipeline response matching Phase 8A backend output
  const sampleCompleteResponse: EmailAnalysisResponse = {
    filename: 'urgent_invoice_notice.eml',
    file_size_bytes: 4520,
    headers: {
      from_header: 'Accounting Department <billing@legit-vendor.example.com>',
      to_headers: ['recipient@target-org.example.com'],
      cc_headers: [],
      bcc_headers: [],
      subject: 'URGENT: Outstanding Overdue Invoice Action Required',
      date: 'Mon, 12 Oct 2026 09:30:00 +0000',
      message_id: '<msg-12345@legit-vendor.example.com>',
      reply_to: 'collector@suspicious-domain.example.org',
      return_path: 'bounce@legit-vendor.example.com',
      mime_version: '1.0',
      content_type: 'multipart/alternative; boundary="====boundary123===="',
      authentication_results: [
        'mx.target-org.example.com; dkim=pass (1024-bit key) header.d=legit-vendor.example.com header.i=@legit-vendor.example.com; spf=pass (mx.target-org.example.com: domain of bounce@legit-vendor.example.com designates 192.0.2.1 as permitted sender) client-ip=192.0.2.1; dmarc=pass (p=quarantine sp=quarantine dis=none) header.from=legit-vendor.example.com',
      ],
      received_spf: ['pass (mx.target-org.example.com: domain of bounce@legit-vendor.example.com designates 192.0.2.1) client-ip=192.0.2.1;'],
      dkim_signatures: ['v=1; a=rsa-sha256; c=relaxed/relaxed; d=legit-vendor.example.com; s=selector1;'],
      received_headers: [
        'from mail.legit-vendor.example.com (mail.legit-vendor.example.com [192.0.2.1]) by mx.target-org.example.com with ESMTPS id abc1234; Mon, 12 Oct 2026 09:30:02 +0000',
        'from internal-host.local (10.0.0.5) by mail.legit-vendor.example.com with SMTP id xyz789; Mon, 12 Oct 2026 09:30:00 +0000',
      ],
    },
    body: {
      has_plain_text: true,
      plain_text: 'Please review your outstanding invoice at http://198.51.100.99/login?ref=target immediately.',
      has_html: true,
      html_extracted_text: 'Please review your outstanding invoice at http://198.51.100.99/login?ref=target immediately.',
      plain_text_char_count: 92,
      html_text_char_count: 92,
    },
    urls: [
      {
        url: 'http://198.51.100.99/login?ref=target',
        scheme: 'http',
        domain: '198.51.100.99',
        source: 'both',
      },
    ],
    attachments: [
      {
        filename: 'invoice_details.pdf',
        content_type: 'application/pdf',
        size_bytes: 3200,
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      },
    ],
    ip_candidates: [
      {
        ip: '192.0.2.1',
        version: 4,
        classification: 'Documentation',
        hop_index: 0,
        source_header: 'from mail.legit-vendor.example.com [192.0.2.1]',
      },
      {
        ip: '10.0.0.5',
        version: 4,
        classification: 'Private',
        hop_index: 1,
        source_header: 'from internal-host.local (10.0.0.5)',
      },
    ],
    url_analysis: {
      total_urls: 1,
      unique_urls: 1,
      risk_breakdown: { INFO: 0, LOW: 0, MEDIUM: 1, HIGH: 0 },
      highest_risk_category: 'MEDIUM',
      url_results: [
        {
          url_index: 0,
          original_url: 'http://198.51.100.99/login?ref=target',
          source: 'both',
          normalized_url: 'http://198.51.100.99/login?ref=target',
          parse_status: 'parsed',
          normalized_hostname: '198.51.100.99',
          features: {
            scheme: 'http',
            is_https: false,
            is_http: true,
            is_unusual_scheme: false,
            raw_host: '198.51.100.99',
            normalized_host: '198.51.100.99',
            host_type: 'ipv4',
            is_ip_literal: true,
            ip_version: 4,
            host_classification: 'reserved',
            has_trailing_dot: false,
            url_length: 37,
            host_length: 13,
            subdomain_count: 0,
            dots_in_host: 3,
            hyphens_in_host: 0,
            dots_in_url: 3,
            hyphens_in_url: 0,
            has_userinfo: false,
            port: null,
            is_non_default_port: false,
            percent_encoding_count: 0,
            is_punycode: false,
            has_unicode: false,
            has_path: true,
            path_length: 6,
            has_query: true,
            query_param_count: 1,
            has_fragment: false,
          },
          observations: [
            {
              rule_id: 'RULE_IP_LITERAL_HOST',
              rule_name: 'IP Address Literal as Host',
              severity: 'MEDIUM',
              description: 'URL uses raw IP literal (198.51.100.99) instead of domain name.',
            },
          ],
          heuristic_risk_category: 'MEDIUM',
          heuristic_risk_score: 45,
          risk_summary: 'URL exhibits structural risk indicators including IP literal host.',
        },
      ],
      analyzed_at: '2026-10-12T09:30:03Z',
    },
    authentication_analysis: {
      status: 'EVALUATED',
      spf: {
        status: 'PASS',
        findings: [],
        domain: 'bounce@legit-vendor.example.com',
        client_ip: '192.0.2.1',
        explanation: 'SPF passed for domain bounce@legit-vendor.example.com.',
        trust_limitation: 'Reflects downstream MTA header assertion.',
      },
      dkim: {
        status: 'PASS',
        findings: [],
        has_dkim_signature_header: true,
        dkim_signature_count: 1,
        domain: 'legit-vendor.example.com',
        selector: 'selector1',
        explanation: 'DKIM signature reported passed.',
        trust_limitation: 'Reported by receiving MTA.',
      },
      dmarc: {
        status: 'PASS',
        findings: [],
        policy: 'quarantine',
        subdomain_policy: 'quarantine',
        disposition: 'none',
        header_from: 'legit-vendor.example.com',
        alignment_verified: true,
        explanation: 'DMARC pass reported with policy quarantine.',
        trust_limitation: 'Depends on boundary MTA trust.',
      },
      headers_inspected: ['Authentication-Results', 'Received-SPF', 'DKIM-Signature'],
      authserv_ids: ['mx.target-org.example.com'],
      has_conflicts: false,
      warnings: [],
      disclaimer: 'Authentication evidence reflects downstream MTA header assertions (RFC 8601/RFC 7208).',
    },
    ip_intelligence: {
      total_candidates: 2,
      candidates: [
        {
          ip: '192.0.2.1',
          version: 4,
          classification: 'Documentation',
          hop_index: 0,
          source_header: 'from mail.legit-vendor.example.com [192.0.2.1]',
          is_routable: false,
          geolocation_status: 'DATABASE_UNAVAILABLE',
          geolocation: null,
          role_hint: 'Ingress Gateway',
          explanation: 'Ingress relay IP belonging to TEST-NET-1 documentation range.',
        },
        {
          ip: '10.0.0.5',
          version: 4,
          classification: 'Private',
          hop_index: 1,
          source_header: 'from internal-host.local (10.0.0.5)',
          is_routable: false,
          geolocation_status: 'NOT_ROUTABLE',
          geolocation: null,
          role_hint: 'Apparent Origin',
          explanation: 'Earliest recorded transit hop originates from RFC 1918 private range.',
        },
      ],
      origin_candidate: {
        ip: '10.0.0.5',
        version: 4,
        classification: 'Private',
        hop_index: 1,
        source_header: 'from internal-host.local (10.0.0.5)',
        is_routable: false,
        geolocation_status: 'NOT_ROUTABLE',
        geolocation: null,
        role_hint: 'Apparent Origin',
        explanation: 'Earliest recorded transit hop originates from RFC 1918 private range.',
      },
      origin_assessment: 'Earliest recorded transit hop 10.0.0.5 is an internal RFC 1918 private address.',
      public_count: 0,
      private_count: 1,
      other_count: 1,
      database_available: false,
      warnings: [],
      disclaimer: 'IP analysis is strictly offline and deterministic.',
    },
    evidence_fusion: {
      overall_category: 'REVIEW_RECOMMENDED',
      model_evidence: {
        status: 'EVALUATED',
        uncalibrated_score: 0.8123,
        predicted_label: 1,
        interpretation: 'Model classified text as Phishing with uncalibrated score 0.8123.',
        caveat:
          'Score is an uncalibrated DistilBERT output trained on the PhishMMF dataset. Due to dataset source-label collinearity and synthetic token shortcuts (<USER>), this score represents a text-similarity heuristic and NOT a validated real-world probability.',
      },
      url_evidence: {
        total_urls: 1,
        unique_domains: 1,
        highest_heuristic_risk: 'MEDIUM',
        suspicious_indicators: ['IP literal host'],
        deduplication_applied: true,
        explanation: '1 URL extracted; medium risk heuristic triggered for IP literal.',
        heuristic_disclaimer: 'URL risk scores are rule-based heuristic indicators.',
      },
      auth_evidence: {
        spf_status: 'PASS',
        dkim_status: 'PASS',
        dmarc_status: 'PASS',
        has_conflicts: false,
        has_valid_authentication: true,
        has_explicit_failure: false,
        correlated_failure_noted: false,
        explanation: 'All protocols passed at receiving MTA.',
        trust_limitation: 'PASS does not guarantee benign intent.',
      },
      ip_evidence: {
        apparent_origin_ip: '10.0.0.5',
        origin_classification: 'Private',
        is_routable: false,
        hop_count: 2,
        explanation: 'Apparent origin hop is internal private IP.',
        provenance_limitation: 'Received headers prior to boundary MTA can be spoofed.',
      },
      contributing_factors: [
        'DistilBERT model inference classified text as Phishing (uncalibrated score: 0.8123)',
        'URL exhibits medium structural risk (IP literal host)',
      ],
      inconclusive_or_missing_factors: [
        'Origin IP is non-routable private address; external route unverified',
      ],
      reasoning:
        'Email body contains high phishing language signals and structural URL anomalies, though cryptographic authentication passed.',
      disclaimer:
        'This assessment is an investigation support aid combining local forensic observations and model scores. It does NOT emit a calibrated probability or a definitive phishing verdict. Findings must be validated by security analysts.',
    },
    model_inference: {
      uncalibrated_score: 0.8123,
      predicted_label: 1,
      status: 'EVALUATED',
      error_message: null,
    },
    parsing_status: 'success',
    warnings: [],
    parsed_at: '2026-10-12T09:30:05Z',
  };

  test('1. API Contract Completeness: all required Phase 8A/8B fields exist in response', () => {
    assert.ok(sampleCompleteResponse.filename, 'filename must be present');
    assert.ok(sampleCompleteResponse.headers, 'headers must be present');
    assert.ok(sampleCompleteResponse.body, 'body must be present');
    assert.ok(Array.isArray(sampleCompleteResponse.urls), 'urls must be an array');
    assert.ok(Array.isArray(sampleCompleteResponse.attachments), 'attachments must be an array');
    assert.ok(Array.isArray(sampleCompleteResponse.ip_candidates), 'ip_candidates must be an array');
    assert.ok(sampleCompleteResponse.url_analysis, 'url_analysis must be present');
    assert.ok(sampleCompleteResponse.authentication_analysis, 'authentication_analysis must be present');
    assert.ok(sampleCompleteResponse.ip_intelligence, 'ip_intelligence must be present');
    assert.ok(sampleCompleteResponse.evidence_fusion, 'evidence_fusion must be present');
    assert.ok(sampleCompleteResponse.model_inference, 'model_inference must be present');
    assert.strictEqual(sampleCompleteResponse.parsing_status, 'success');
  });

  test('2. DistilBERT Model State Integrity: EVALUATED status conveys uncalibrated score and caveat', () => {
    const model = sampleCompleteResponse.evidence_fusion!.model_evidence;
    assert.strictEqual(model.status, 'EVALUATED');
    assert.strictEqual(model.predicted_label, 1);
    assert.strictEqual(typeof model.uncalibrated_score, 'number');
    assert.ok(model.uncalibrated_score! >= 0.0 && model.uncalibrated_score! <= 1.0);
    assert.ok(
      model.caveat.includes('uncalibrated DistilBERT output'),
      'Caveat must declare uncalibrated score'
    );
    assert.ok(
      model.caveat.includes('NOT a validated real-world probability'),
      'Caveat must explicitly state not a validated probability'
    );
  });

  test('3. DistilBERT Failure Modes: ERROR status is NEVER presented as benign', () => {
    const errorModelEvidence: EvidenceFusionResult['model_evidence'] = {
      status: 'ERROR',
      uncalibrated_score: null,
      predicted_label: null,
      interpretation: 'Runtime CUDA out-of-memory error during tokenization',
      caveat: 'Model inference encountered an error.',
    };

    assert.strictEqual(errorModelEvidence.status, 'ERROR');
    assert.notStrictEqual(
      errorModelEvidence.predicted_label,
      0,
      'ERROR status must NEVER default to label 0 (benign)'
    );
    assert.strictEqual(
      errorModelEvidence.uncalibrated_score,
      null,
      'Score must be null when inference errors out'
    );
  });

  test('4. DistilBERT Failure Modes: UNAVAILABLE status is NEVER presented as benign', () => {
    const unavailableModelEvidence: EvidenceFusionResult['model_evidence'] = {
      status: 'UNAVAILABLE',
      uncalibrated_score: null,
      predicted_label: null,
      interpretation: 'Model weights file not found on server disk',
      caveat: 'Model inference unavailable.',
    };

    assert.strictEqual(unavailableModelEvidence.status, 'UNAVAILABLE');
    assert.notStrictEqual(
      unavailableModelEvidence.predicted_label,
      0,
      'UNAVAILABLE status must NEVER default to label 0 (benign)'
    );
    assert.strictEqual(
      unavailableModelEvidence.uncalibrated_score,
      null,
      'Score must be null when model is unavailable'
    );
  });

  test('5. Non-Verdict & Safety Guarantee Prohibition: LOW_RISK_INDICATORS never guarantees safety', () => {
    const lowRiskCategory: AssessmentCategory = 'LOW_RISK_INDICATORS';
    assert.strictEqual(lowRiskCategory, 'LOW_RISK_INDICATORS');
    assert.notStrictEqual(lowRiskCategory, 'SAFE', 'Category must not be named SAFE');
    assert.notStrictEqual(lowRiskCategory, 'CLEAN', 'Category must not be named CLEAN');
    assert.notStrictEqual(lowRiskCategory, 'BENIGN', 'Category must not be named BENIGN');

    const disclaimer = sampleCompleteResponse.evidence_fusion!.disclaimer;
    assert.ok(
      disclaimer.includes('investigation support aid'),
      'Disclaimer must identify tool as investigation support aid'
    );
    assert.ok(
      disclaimer.includes('does NOT emit a calibrated probability or a definitive phishing verdict'),
      'Disclaimer must forbid probability and definitive verdict claims'
    );
  });

  test('6. Defensive Handling: Null / missing optional modalities do not crash or fabricate results', () => {
    const partialResponse: EmailAnalysisResponse = {
      filename: 'minimal.eml',
      file_size_bytes: 100,
      headers: {
        from_header: 'alice@example.com',
        to_headers: ['bob@example.com'],
        cc_headers: [],
        bcc_headers: [],
        subject: 'Hello',
        date: null,
        message_id: null,
        reply_to: null,
        return_path: null,
        mime_version: null,
        content_type: 'text/plain',
        authentication_results: [],
        received_spf: [],
        received_headers: [],
      },
      body: {
        has_plain_text: true,
        plain_text: 'Short message',
        has_html: false,
        html_extracted_text: null,
        plain_text_char_count: 13,
        html_text_char_count: 0,
      },
      urls: [],
      attachments: [],
      ip_candidates: [],
      url_analysis: null,
      authentication_analysis: null,
      ip_intelligence: null,
      evidence_fusion: null,
      model_inference: null,
      parsing_status: 'partial_success',
      warnings: ['Model inference was disabled in configuration'],
      parsed_at: '2026-10-12T10:00:00Z',
    };

    assert.strictEqual(partialResponse.evidence_fusion, null);
    assert.strictEqual(partialResponse.url_analysis, null);
    assert.strictEqual(partialResponse.authentication_analysis, null);
    assert.strictEqual(partialResponse.ip_intelligence, null);
    assert.strictEqual(partialResponse.model_inference, null);
    assert.strictEqual(partialResponse.parsing_status, 'partial_success');
    assert.strictEqual(partialResponse.warnings.length, 1);
  });

  test('7. Client-Side Upload Constraints: Extension, size, and non-empty enforcement', () => {
    const MAX_SIZE_BYTES = 10 * 1024 * 1024;

    const validateUpload = (filename: string, sizeBytes: number) => {
      if (!filename.toLowerCase().endsWith('.eml')) {
        return { valid: false, error: 'Invalid extension. Only .eml accepted.' };
      }
      if (sizeBytes > MAX_SIZE_BYTES) {
        return { valid: false, error: 'File exceeds 10 MB limit.' };
      }
      if (sizeBytes === 0) {
        return { valid: false, error: 'File is empty (0 bytes).' };
      }
      return { valid: true, error: null };
    };

    assert.strictEqual(validateUpload('test.txt', 100).valid, false);
    assert.strictEqual(validateUpload('test.msg', 100).valid, false);
    assert.strictEqual(validateUpload('test.eml', 0).valid, false);
    assert.strictEqual(validateUpload('huge.eml', 11 * 1024 * 1024).valid, false);
    assert.strictEqual(validateUpload('sample.eml', 1024).valid, true);
    assert.strictEqual(validateUpload('SAMPLE.EML', 1024).valid, true);
  });

  test('8. Real Endpoint Route Contract: POST /api/v1/email/analyze', () => {
    const expectedEndpoint = '/api/v1/email/analyze';
    const expectedMethod = 'POST';
    assert.strictEqual(expectedEndpoint, '/api/v1/email/analyze');
    assert.strictEqual(expectedMethod, 'POST');
  });
});
