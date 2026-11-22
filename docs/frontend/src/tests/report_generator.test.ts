import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  escapeHtml,
  formatBytes,
  generateReportFilename,
  generateForensicReportHtml,
} from '../utils/reportGenerator.ts';
import type { EmailAnalysisResponse, IPClassification } from '../types/forensics';

describe('Phase 8C — Downloadable Forensic Report Tests', () => {
  const completeMockData: EmailAnalysisResponse = {
    filename: 'suspicious_payroll_update.eml',
    file_size_bytes: 5240,
    headers: {
      from_header: 'Human Resources <hr@payroll-service.example.com>',
      to_headers: ['employee@company.example.com'],
      cc_headers: [],
      bcc_headers: [],
      subject: 'ACTION REQUIRED: Direct Deposit Verification Notice',
      date: 'Tue, 13 Oct 2026 14:00:00 +0000',
      message_id: '<msg-pay-999@payroll-service.example.com>',
      reply_to: 'support@external-phish.example.net',
      return_path: 'bounce@payroll-service.example.com',
      mime_version: '1.0',
      content_type: 'multipart/alternative',
      authentication_results: [
        'mx.company.example.com; dkim=pass header.d=payroll-service.example.com header.s=hr2026; spf=pass client-ip=198.51.100.25; dmarc=pass p=reject header.from=payroll-service.example.com',
      ],
      received_spf: ['pass (mx.company.example.com: domain of bounce@payroll-service.example.com designates 198.51.100.25) client-ip=198.51.100.25;'],
      dkim_signatures: ['v=1; a=rsa-sha256; d=payroll-service.example.com; s=hr2026;'],
      received_headers: [
        'from mail.payroll-service.example.com ([198.51.100.25]) by mx.company.example.com with ESMTPS id p887; Tue, 13 Oct 2026 14:00:02 +0000',
      ],
    },
    body: {
      has_plain_text: true,
      plain_text: 'Please verify your banking details here: http://198.51.100.99/login?id=user1',
      has_html: true,
      html_extracted_text: 'Please verify your banking details here: http://198.51.100.99/login?id=user1',
      plain_text_char_count: 76,
      html_text_char_count: 76,
    },
    urls: [
      {
        url: 'http://198.51.100.99/login?id=user1',
        scheme: 'http',
        domain: '198.51.100.99',
        source: 'both',
      },
    ],
    attachments: [
      {
        filename: 'DirectDepositForm.pdf',
        content_type: 'application/pdf',
        size_bytes: 4096,
        sha256: 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0',
      },
    ],
    ip_candidates: [
      {
        ip: '198.51.100.25',
        version: 4,
        classification: 'Documentation',
        hop_index: 0,
        source_header: 'from mail.payroll-service.example.com ([198.51.100.25])',
      },
    ],
    url_analysis: {
      total_urls: 1,
      unique_urls: 1,
      risk_breakdown: { HIGH: 0, MEDIUM: 1, LOW: 0, INFO: 0 },
      highest_risk_category: 'MEDIUM',
      url_results: [
        {
          url_index: 0,
          original_url: 'http://198.51.100.99/login?id=user1',
          source: 'both',
          normalized_url: 'http://198.51.100.99/login?id=user1',
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
              rule_name: 'IP Address Literal Host',
              severity: 'MEDIUM',
              description: 'URL target uses raw numeric IP literal instead of verified domain.',
            },
          ],
          heuristic_risk_category: 'MEDIUM',
          heuristic_risk_score: 55,
          risk_summary: 'Medium heuristic risk due to numeric IP host.',
        },
      ],
      analyzed_at: '2026-10-13T14:00:03Z',
    },
    authentication_analysis: {
      status: 'EVALUATED',
      spf: {
        status: 'PASS',
        findings: [],
        domain: 'bounce@payroll-service.example.com',
        client_ip: '198.51.100.25',
        explanation: 'SPF passed for domain bounce@payroll-service.example.com.',
        trust_limitation: 'Reported by receiving boundary MTA.',
      },
      dkim: {
        status: 'PASS',
        findings: [],
        has_dkim_signature_header: true,
        dkim_signature_count: 1,
        domain: 'payroll-service.example.com',
        selector: 'hr2026',
        explanation: 'DKIM signature present and validated by boundary MTA.',
        trust_limitation: 'Reflects receiving MTA assertion.',
      },
      dmarc: {
        status: 'PASS',
        findings: [],
        policy: 'reject',
        subdomain_policy: null,
        disposition: 'none',
        header_from: 'payroll-service.example.com',
        alignment_verified: true,
        explanation: 'DMARC passed with reject policy.',
        trust_limitation: 'Receiver policy alignment assertion.',
      },
      headers_inspected: ['Authentication-Results', 'Received-SPF', 'DKIM-Signature'],
      authserv_ids: ['mx.company.example.com'],
      has_conflicts: false,
      warnings: [],
      disclaimer: 'Authentication evidence reflects downstream MTA header assertions (RFC 8601/RFC 7208).',
    },
    ip_intelligence: {
      total_candidates: 1,
      candidates: [
        {
          ip: '198.51.100.25',
          version: 4,
          classification: 'Documentation',
          hop_index: 0,
          source_header: 'from mail.payroll-service.example.com ([198.51.100.25])',
          is_routable: false,
          geolocation_status: 'DATABASE_UNAVAILABLE',
          geolocation: null,
          role_hint: 'Apparent Origin',
          explanation: 'Transit origin in TEST-NET-2 documentation range.',
        },
      ],
      origin_candidate: {
        ip: '198.51.100.25',
        version: 4,
        classification: 'Documentation',
        hop_index: 0,
        source_header: 'from mail.payroll-service.example.com ([198.51.100.25])',
        is_routable: false,
        geolocation_status: 'DATABASE_UNAVAILABLE',
        geolocation: null,
        role_hint: 'Apparent Origin',
        explanation: 'Transit origin in TEST-NET-2 documentation range.',
      },
      origin_assessment: 'Apparent origin hop is 198.51.100.25 (TEST-NET-2 documentation block).',
      public_count: 0,
      private_count: 0,
      other_count: 1,
      database_available: false,
      warnings: [],
      disclaimer: 'IP analysis is strictly offline and deterministic.',
    },
    evidence_fusion: {
      overall_category: 'REVIEW_RECOMMENDED',
      model_evidence: {
        status: 'EVALUATED',
        uncalibrated_score: 0.8841,
        predicted_label: 1,
        interpretation: 'DistilBERT text model classified content as Phishing with uncalibrated score 0.8841.',
        caveat:
          'Score is an uncalibrated DistilBERT output trained on the PhishMMF dataset. Due to dataset source-label collinearity and synthetic token shortcuts (<USER>), this score represents a text-similarity heuristic and NOT a validated real-world probability.',
      },
      url_evidence: {
        total_urls: 1,
        unique_domains: 1,
        highest_heuristic_risk: 'MEDIUM',
        suspicious_indicators: ['IP Address Literal Host'],
        deduplication_applied: true,
        explanation: '1 URL extracted with medium structural heuristic risk.',
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
        explanation: 'SPF, DKIM, and DMARC reported passed.',
        trust_limitation: 'Reflects downstream MTA assertions.',
      },
      ip_evidence: {
        apparent_origin_ip: '198.51.100.25',
        origin_classification: 'Documentation',
        is_routable: false,
        hop_count: 1,
        explanation: 'Transit hop 198.51.100.25.',
        provenance_limitation: 'Transit headers can be manipulated.',
      },
      contributing_factors: [
        'DistilBERT model inference classified text as Phishing (uncalibrated score: 0.8841)',
        'URL exhibits medium structural risk (IP literal host)',
      ],
      inconclusive_or_missing_factors: [
        'Origin IP in documentation range; public egress route indeterminate',
      ],
      reasoning:
        'Elevated phishing text patterns and raw IP destination combined with authenticated sender identity indicate review required.',
      disclaimer:
        'This assessment is an investigation support aid combining local forensic observations and model scores. It does NOT emit a calibrated probability or a definitive phishing verdict. Findings must be validated by security analysts.',
    },
    model_inference: {
      uncalibrated_score: 0.8841,
      predicted_label: 1,
      status: 'EVALUATED',
      error_message: null,
    },
    parsing_status: 'success',
    warnings: [],
    parsed_at: '2026-10-13T14:00:04Z',
  };

  test('1. Filename Generation: produces standard phishintel-report-YYYYMMDD-HHmmss.html', () => {
    const fixedDate = new Date(Date.UTC(2026, 9, 26, 16, 15, 30)); // 2026-10-26 16:15:30 UTC
    const filename = generateReportFilename(completeMockData, fixedDate);
    assert.strictEqual(filename, 'phishintel-report-20261026-161530.html');
  });

  test('2. HTML Escaping: neutralizes script injection, tags, and quotes', () => {
    assert.strictEqual(escapeHtml('<script>alert("xss")</script>'), '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;');
    assert.strictEqual(escapeHtml("Tom & 'Jerry'"), 'Tom &amp; &#039;Jerry&#039;');
    assert.strictEqual(escapeHtml('"><img src=x onerror=alert(1)>'), '&quot;&gt;&lt;img src=x onerror=alert(1)&gt;');
    assert.strictEqual(escapeHtml(null), '');
    assert.strictEqual(escapeHtml(undefined), '');
  });

  test('3. Byte Formatting Utility: accurately formats 0 B, KB, and MB', () => {
    assert.strictEqual(formatBytes(0), '0 B');
    assert.strictEqual(formatBytes(1024), '1 KB');
    assert.strictEqual(formatBytes(5240), '5.12 KB');
    assert.strictEqual(formatBytes(10485760), '10 MB');
  });

  test('4. Complete Report Generation: contains all required sections, branding, and metadata', () => {
    const fixedDate = new Date(Date.UTC(2026, 9, 26, 16, 20, 0));
    const html = generateForensicReportHtml(completeMockData, fixedDate);

    // Document & Security Headers
    assert.ok(html.includes('<!DOCTYPE html>'));
    assert.ok(html.includes('<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'none\'; style-src \'unsafe-inline\'; img-src data:; connect-src \'none\'; object-src \'none\'; frame-src \'none\'; media-src \'none\'; font-src \'none\'; form-action \'none\'; base-uri \'none\';">'));
    assert.ok(html.includes('PhishIntel Forensic Engine'));
    assert.ok(html.includes('suspicious_payroll_update.eml'));

    // Section 1: Executive Summary & Evidence Fusion
    assert.ok(html.includes('1. Executive Summary &amp; Evidence Fusion'));
    assert.ok(html.includes('REVIEW_RECOMMENDED'));
    assert.ok(html.includes('Review Recommended'));
    assert.ok(html.includes('Elevated phishing text patterns and raw IP destination'));
    assert.ok(html.includes('Mandatory Non-Verdict Disclaimer:'));

    // Section 2: DistilBERT Inference (Caveat box removed per Task 2)
    assert.ok(html.includes('2. DistilBERT Transformer Text Inference'));
    assert.ok(html.includes('EVALUATED'));
    assert.ok(html.includes('1 (Phishing Indicator)'));
    assert.ok(html.includes('0.8841'));
    assert.ok(!html.includes('Prominent Calibration Caveat:'));
    assert.ok(!html.includes('caveat-box'));

    // Section 3: URL Intelligence
    assert.ok(html.includes('3. URL Intelligence &amp; Lexical Heuristics'));
    assert.ok(html.includes('http://198.51.100.99/login?id=user1'));
    assert.ok(html.includes('RULE_IP_LITERAL_HOST'));
    assert.ok(html.includes('IP Address Literal Host'));
    assert.ok(html.includes('55/100'));

    // Section 4: Cryptographic Authentication
    assert.ok(html.includes('4. Cryptographic Authentication Evidence (SPF / DKIM / DMARC)'));
    assert.ok(html.includes('payroll-service.example.com'));
    assert.ok(html.includes('hr2026'));
    assert.ok(html.includes('p=reject'));
    assert.ok(html.includes('Trust Boundary Limitation:'));

    // Section 5: IP Intelligence (Transit reconstruction presentation removed per Task 3)
    assert.ok(html.includes('5. IP Intelligence'));
    assert.ok(!html.includes('Transit Reconstruction'));
    assert.ok(html.includes('198.51.100.25'));
    assert.ok(html.includes('Apparent Origin'));
    assert.ok(html.includes('Forensic IP Limitation:'));

    // Section 6: RFC 5322 Standard Headers & Attachments
    assert.ok(html.includes('6. RFC 5322 Standard Headers &amp; Attachments'));
    assert.ok(html.includes('ACTION REQUIRED: Direct Deposit Verification Notice'));
    assert.ok(html.includes('DirectDepositForm.pdf'));

    // Section 7: Warnings & Footer
    assert.ok(html.includes('7. Forensic Parser Notices &amp; Operational Warnings'));
    assert.ok(html.includes('No parser anomalies or non-fatal warnings were recorded'));
    assert.ok(html.includes('This forensic report does not guarantee that an email is safe'));
  });

  test('5. DistilBERT Error State: exports error details without fabricating score or label', () => {
    const errorData: EmailAnalysisResponse = {
      ...completeMockData,
      model_inference: {
        status: 'ERROR',
        predicted_label: null,
        uncalibrated_score: null,
        error_message: 'CUDA device error during forward pass',
      },
      evidence_fusion: {
        ...completeMockData.evidence_fusion!,
        model_evidence: {
          status: 'ERROR',
          uncalibrated_score: null,
          predicted_label: null,
          interpretation: 'Model execution failed due to runtime error.',
          caveat: 'Model inference encountered an error.',
        },
      },
    };

    const html = generateForensicReportHtml(errorData);
    assert.ok(html.includes('ERROR'));
    assert.ok(html.includes('N/A (ERROR)'), 'Predicted label must be N/A when model errored');
    assert.ok(!html.includes('1 (Phishing Indicator)'), 'Must not report Phishing when errored');
    assert.ok(!html.includes('0 (Benign Pattern)'), 'Must not report Benign when errored');
    assert.ok(!html.includes('Prominent Calibration Caveat:'));
  });

  test('6. DistilBERT Unavailable State: exports unavailable status without fabricating score or label', () => {
    const unavailData: EmailAnalysisResponse = {
      ...completeMockData,
      model_inference: {
        status: 'UNAVAILABLE',
        predicted_label: null,
        uncalibrated_score: null,
        error_message: null,
      },
      evidence_fusion: {
        ...completeMockData.evidence_fusion!,
        model_evidence: {
          status: 'UNAVAILABLE',
          uncalibrated_score: null,
          predicted_label: null,
          interpretation: 'Model was not loaded.',
          caveat: 'Model inference unavailable.',
        },
      },
    };

    const html = generateForensicReportHtml(unavailData);
    assert.ok(html.includes('UNAVAILABLE'));
    assert.ok(html.includes('N/A (UNAVAILABLE)'));
    assert.ok(!html.includes('1 (Phishing Indicator)'));
    assert.ok(!html.includes('0 (Benign Pattern)'));
  });

  test('7. Safety Guarantee Prohibition: LOW_RISK_INDICATORS explicitly states no guarantee of safety', () => {
    const lowRiskData: EmailAnalysisResponse = {
      ...completeMockData,
      evidence_fusion: {
        ...completeMockData.evidence_fusion!,
        overall_category: 'LOW_RISK_INDICATORS',
      },
    };

    const html = generateForensicReportHtml(lowRiskData);
    assert.ok(html.includes('Low Risk Indicators Observed (No Guarantee of Safety)'));
    assert.ok(!html.includes('Safe Email'));
    assert.ok(!html.includes('Clean Email'));
    assert.ok(!html.includes('Guaranteed Benign'));
  });

  test('8. Defensive Handling: Null optional modalities render safely without crashing', () => {
    const minimalData: EmailAnalysisResponse = {
      filename: 'plain_test.eml',
      file_size_bytes: 350,
      headers: {
        from_header: 'test@example.com',
        to_headers: ['recipient@example.com'],
        cc_headers: [],
        bcc_headers: [],
        subject: 'Test Subject',
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
        plain_text: 'Just a simple test',
        has_html: false,
        html_extracted_text: null,
        plain_text_char_count: 18,
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
      warnings: ['Model inference disabled', 'No Received headers found'],
      parsed_at: '2026-10-26T16:00:00Z',
    };

    const html = generateForensicReportHtml(minimalData);
    assert.ok(html.includes('plain_test.eml'));
    assert.ok(html.includes('Partial Parse'));
    assert.ok(html.includes('INSUFFICIENT_EVIDENCE'));
    assert.ok(html.includes('No URLs extracted from email text or HTML parts.'));
    assert.ok(html.includes('No IP candidates detected in Received headers.'));
    assert.ok(html.includes('Non-Fatal Warnings Detected (2)'));
    assert.ok(html.includes('Model inference disabled'));
    assert.ok(html.includes('No Received headers found'));
  });

  test('9. Script Injection Neutralization in Email Artifacts', () => {
    const maliciousData: EmailAnalysisResponse = {
      ...completeMockData,
      filename: '"><script>alert(1)</script>.eml',
      headers: {
        ...completeMockData.headers,
        subject: '<img src=x onerror="fetch(\'http://attacker.com\')">',
        from_header: 'Evil <attacker@evil.com" onmouseover="alert(\'pwn\')">',
      },
      urls: [
        {
          url: 'javascript:alert(1)',
          scheme: 'javascript',
          domain: 'alert(1)',
          source: 'plain_text',
        },
      ],
      warnings: ['<script>evil()</script> warning message'],
    };

    const html = generateForensicReportHtml(maliciousData);
    // Verifies that literal <script> tags and quotes were escaped
    assert.ok(!html.includes('<script>alert(1)</script>'));
    assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
    assert.ok(!html.includes('<img src=x onerror='));
    assert.ok(html.includes('&lt;img src=x onerror=&quot;fetch'));
    assert.ok(!html.includes('<script>evil()</script>'));
    assert.ok(html.includes('&lt;script&gt;evil()&lt;/script&gt;'));
  });

  test('10. Focused Content Security Policy Directive Audit (W3C Meta Spec Compliance)', () => {
    const fixedDate = new Date(Date.UTC(2026, 9, 26, 16, 20, 0));
    const html = generateForensicReportHtml(completeMockData, fixedDate);

    // Extract meta CSP content
    const cspMatch = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)">/);
    assert.ok(cspMatch, 'Meta CSP tag must be present in HTML document');
    const cspContent = cspMatch[1];

    // Verify critical blocking directives
    assert.ok(cspContent.includes("default-src 'none'"), "Must enforce default-src 'none'");
    assert.ok(cspContent.includes("script-src 'none'"), "Must explicitly block script execution via script-src 'none'");
    assert.ok(cspContent.includes("object-src 'none'"), "Must explicitly block plugins and objects via object-src 'none'");
    assert.ok(cspContent.includes("connect-src 'none'"), "Must explicitly block network calls (fetch/XHR/WS) via connect-src 'none'");
    assert.ok(cspContent.includes("form-action 'none'"), "Must explicitly block form submission via form-action 'none'");
    assert.ok(cspContent.includes("base-uri 'none'"), "Must explicitly block base-href hijacking via base-uri 'none'");
    assert.ok(cspContent.includes("frame-src 'none'"), "Must explicitly block iframes via frame-src 'none'");

    // Verify allowed presentation styling
    assert.ok(cspContent.includes("style-src 'unsafe-inline'"), "Must preserve internal embedded style block");
    assert.ok(cspContent.includes("img-src data:"), "Must permit data: URI images if needed");

    // Compliance check: W3C CSP Level 2/3 mandates user agents ignore sandbox in meta elements.
    // Assert that 'sandbox' is NOT present in the meta CSP.
    assert.ok(!cspContent.includes('sandbox'), "Must NOT specify 'sandbox' in meta-delivered CSP per W3C specification");
  });

  test('11. Comprehensive Script-Injection Payload Neutralization Across All Email Artifacts', () => {
    const multiVectorAttackData: EmailAnalysisResponse = {
      filename: '"><svg onload=alert("pwn-file")>.eml',
      file_size_bytes: 4096,
      headers: {
        from_header: 'Attacker <"user@evil.com\'><script>alert(\'from\')</script>">',
        to_headers: ['victim@company.com<iframe src="javascript:alert(\'to\')"></iframe>'],
        cc_headers: ['cc@company.com"><script>alert(\'cc\')</script>'],
        bcc_headers: ['bcc@company.com"><script>alert(\'bcc\')</script>'],
        subject: '<marquee onstart=alert("sub")>URGENT: Click here <script>steal()</script></marquee>',
        date: '2026-10-31"><script>alert("date")</script>',
        message_id: '<msg123"><script>alert("msgid")</script>@evil.com>',
        reply_to: 'reply@evil.com"><script>alert("replyto")</script>',
        return_path: 'bounce@evil.com"><script>alert("returnpath")</script>',
        mime_version: '1.0',
        content_type: 'multipart/mixed; boundary="--<script>alert(1)</script>"',
        authentication_results: [],
        received_spf: [],
        received_headers: [],
      },
      body: {
        has_plain_text: true,
        plain_text: 'Body content',
        has_html: false,
        html_extracted_text: null,
        plain_text_char_count: 12,
        html_text_char_count: 0,
      },
      urls: [
        {
          url: 'http://evil.com/path?param="><script>alert(\'url\')</script>',
          scheme: 'http"><script>alert(\'scheme\')</script>',
          domain: 'evil.com"><script>alert(\'domain\')</script>',
          source: 'both',
        },
      ],
      attachments: [
        {
          filename: 'payload"><script>alert(\'filename\')</script>.exe',
          content_type: 'application/x-msdownload"><script>alert(\'content-type\')</script>',
          size_bytes: 1024,
          sha256: 'deadbeef"><script>alert(\'sha256\')</script>',
        },
      ],
      ip_candidates: [
        {
          ip: '198.51.100.1"><script>alert(\'ip\')</script>',
          version: 4,
          classification: 'Documentation' as IPClassification,
          hop_index: 0,
          source_header: 'from evil.com ([198.51.100.1])',
        },
      ],
      url_analysis: {
        total_urls: 1,
        unique_urls: 1,
        risk_breakdown: { HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
        highest_risk_category: 'HIGH',
        url_results: [
          {
            url_index: 0,
            original_url: 'http://evil.com/path?param="><script>alert(\'url\')</script>',
            source: 'both',
            normalized_url: 'http://evil.com/path',
            parse_status: 'parsed',
            normalized_hostname: 'evil.com',
            features: {
              scheme: 'http',
              is_https: false,
              is_http: true,
              is_unusual_scheme: false,
              raw_host: 'evil.com',
              normalized_host: 'evil.com',
              host_type: 'domain',
              is_ip_literal: false,
              ip_version: null,
              host_classification: 'public',
              has_trailing_dot: false,
              url_length: 50,
              host_length: 8,
              subdomain_count: 1,
              dots_in_host: 1,
              hyphens_in_host: 0,
              dots_in_url: 1,
              hyphens_in_url: 0,
              has_userinfo: false,
              port: null,
              is_non_default_port: false,
              percent_encoding_count: 0,
              is_punycode: false,
              has_unicode: false,
              has_path: true,
              path_length: 5,
              has_query: true,
              query_param_count: 1,
              has_fragment: false,
            },
            heuristic_risk_score: 90,
            heuristic_risk_category: 'HIGH',
            risk_summary: 'High risk URL pattern',
            observations: [
              {
                rule_id: 'RULE_EVIL"><script>alert(1)</script>',
                rule_name: 'Evil Rule"><script>alert(2)</script>',
                severity: 'HIGH',
                description: 'Description with <script>alert("obs")</script>',
              },
            ],
          },
        ],
        analyzed_at: '2026-10-31T12:00:00Z',
      },
      authentication_analysis: {
        status: 'EVALUATED',
        headers_inspected: ['Authentication-Results'],
        authserv_ids: ['mx.example.com'],
        has_conflicts: false,
        spf: {
          status: 'FAIL',
          domain: 'evil.com"><script>alert(\'spf-domain\')</script>',
          client_ip: '198.51.100.1',
          explanation: 'SPF check failed with <script>alert("spf")</script>',
          findings: [],
        },
        dkim: {
          status: 'FAIL',
          domain: 'evil.com"><script>alert(\'dkim-domain\')</script>',
          selector: 'default"><script>alert(\'dkim-sel\')</script>',
          has_dkim_signature_header: true,
          dkim_signature_count: 1,
          explanation: 'DKIM failed with <script>alert("dkim")</script>',
          findings: [],
        },
        dmarc: {
          status: 'FAIL',
          header_from: 'evil.com"><script>alert(\'dmarc-from\')</script>',
          policy: 'reject"><script>alert(\'dmarc-policy\')</script>',
          alignment_verified: false,
          explanation: 'DMARC failed with <script>alert("dmarc")</script>',
          findings: [],
        },
        warnings: ['Auth warning <script>alert("warn")</script>'],
        disclaimer: 'Auth disclaimer with <script>alert("disclaimer")</script>',
      },
      ip_intelligence: {
        total_candidates: 1,
        candidates: [],
        origin_candidate: null,
        origin_assessment: 'Assessment with <script>alert("ip-assessment")</script>',
        public_count: 0,
        private_count: 0,
        other_count: 1,
        database_available: false,
        warnings: ['IP Warning <script>alert("ip-warn")</script>'],
        disclaimer: 'IP Disclaimer <script>alert("ip-disc")</script>',
      },
      evidence_fusion: {
        overall_category: 'HIGH_RISK_INDICATORS_PRESENT',
        model_evidence: {
          status: 'EVALUATED',
          uncalibrated_score: 0.99,
          predicted_label: 1,
          interpretation: 'Phishing <script>alert("fusion-interp")</script>',
          caveat: 'Model caveat <script>alert("fusion-caveat")</script>',
        },
        url_evidence: {
          total_urls: 1,
          unique_domains: 1,
          highest_heuristic_risk: 'HIGH',
          suspicious_indicators: ['Indicator <script>alert("url-ind")</script>'],
          deduplication_applied: true,
          explanation: 'URL evidence <script>alert("url-ev")</script>',
          heuristic_disclaimer: 'URL disclaimer <script>alert("url-disc")</script>',
        },
        auth_evidence: {
          spf_status: 'FAIL',
          dkim_status: 'FAIL',
          dmarc_status: 'FAIL',
          has_conflicts: false,
          has_valid_authentication: false,
          has_explicit_failure: true,
          correlated_failure_noted: true,
          explanation: 'Auth expl <script>alert("auth-expl")</script>',
          trust_limitation: 'Auth limitation <script>alert("auth-lim")</script>',
        },
        ip_evidence: {
          apparent_origin_ip: null,
          origin_classification: 'Documentation',
          is_routable: false,
          hop_count: 1,
          explanation: 'IP expl <script>alert("ip-expl")</script>',
          provenance_limitation: 'IP limitation <script>alert("ip-lim")</script>',
        },
        contributing_factors: [
          'Contributing factor <script>alert("factor")</script>',
        ],
        inconclusive_or_missing_factors: [
          'Missing factor <script>alert("missing")</script>',
        ],
        reasoning: 'Synthesized reasoning with <script>alert("reasoning")</script>',
        disclaimer: 'Fusion disclaimer with <script>alert("fusion-disc")</script>',
      },
      model_inference: {
        uncalibrated_score: 0.99,
        predicted_label: 1,
        status: 'EVALUATED',
        error_message: null,
      },
      parsing_status: 'partial_success',
      warnings: ['Parser warning with <script>alert("parser-warn")</script>'],
      parsed_at: '2026-10-31T12:00:00Z',
    };

    const html = generateForensicReportHtml(multiVectorAttackData);

    // Verify that NO executable HTML tags from payloads exist anywhere except encoded entities
    assert.strictEqual(html.includes('<script'), false, 'Document must not contain any raw unescaped <script tag');
    assert.strictEqual(html.includes('</script>'), false, 'Document must not contain any raw unescaped </script> tag');
    assert.strictEqual(html.includes('<iframe'), false, 'Document must not contain any raw unescaped <iframe> tag');
    assert.strictEqual(html.includes('<marquee'), false, 'Document must not contain any raw unescaped <marquee> tag');
    assert.strictEqual(html.includes('<svg'), false, 'Document must not contain any raw unescaped <svg> tag');
    assert.strictEqual(html.includes('<img'), false, 'Document must not contain any raw unescaped <img> tag');

    // Confirm that escaped entities ARE present
    assert.ok(html.includes('&lt;script&gt;alert('), 'Payloads must be safely entity-encoded');
    assert.ok(html.includes('&lt;svg onload='), 'SVG tag must be safely entity-encoded');
  });

  test('12. Phase 10B: UI/report rendering for unavailable origin with a public candidate', () => {
    const dataWithUnavailablePublicOrigin: EmailAnalysisResponse = {
      ...completeMockData,
      ip_candidates: [
        {
          ip: '209.85.216.41',
          version: 4,
          classification: 'Public',
          hop_index: 0,
          source_header: 'from mail-pj1-f41.google.com ([209.85.216.41]) by mx.victim.com',
        },
      ],
      ip_intelligence: {
        total_candidates: 1,
        candidates: [
          {
            ip: '209.85.216.41',
            version: 4,
            classification: 'Public',
            hop_index: 0,
            source_header: 'from mail-pj1-f41.google.com ([209.85.216.41]) by mx.victim.com',
            is_routable: true,
            geolocation_status: 'DATABASE_UNAVAILABLE',
            geolocation: null,
            role_hint: 'Likely Shared Provider Infrastructure (Google Mail / Workspace) (Recipient Ingress / Perimeter Gateway)',
            explanation: 'Public IPv4 address. Database unavailable.',
            provider_indicator: 'Likely Google infrastructure',
            provider_match_category: 'Confirmed Email-Delivery Network Range',
            provider_confidence: 'High (Confirmed Mail Range)',
            provider_source_url: 'https://support.google.com/a/answer/60764',
          },
        ],
        origin_candidate: null,
        origin_assessment: 'Originating IP is UNAVAILABLE. Earlier transit hops contain no extractable IP address. Boundary relay matches likely shared provider infrastructure (Google Mail / Workspace).',
        origin_attribution_status: 'UNAVAILABLE',
        sender_identity_status: 'Not established',
        provider_infrastructure_match: 'Likely Google infrastructure',
        candidate_ip_classification: 'Public',
        is_candidate_routable: true,
        public_count: 1,
        private_count: 0,
        other_count: 0,
        database_available: false,
        warnings: ['Originating IP is unavailable: earlier Received transit hop lacks IP evidence.'],
        disclaimer: 'IP analysis is strictly offline and deterministic.',
      },
    };

    const html = generateForensicReportHtml(dataWithUnavailablePublicOrigin);

    // Verify Phase 10B UI/Report requirements:
    // 1. Origin attribution is UNAVAILABLE
    assert.ok(html.includes('Origin Attribution: <strong style="color: var(--amber, #f59e0b);">UNAVAILABLE</strong>'));
    // 2. Candidate IP is Public
    assert.ok(html.includes('Candidate IP: <strong>Public</strong>'));
    // 3. Provider indicator is Likely Google infrastructure
    assert.ok(html.includes('Provider Indicator: <strong>Likely Google infrastructure</strong>'));
    // 4. Sender identity is Not established
    assert.ok(html.includes('Sender Identity: <strong>Not established</strong>'));
    // 5. Candidate Routability is Public (NOT Non-routable merely because origin_candidate is null!)
    assert.ok(html.includes('Candidate Routability: <strong>Public</strong>'));
    assert.strictEqual(html.includes('Candidate Routability: <strong>Non-routable</strong>'), false);
  });

  test('13. Phase 10B: UI/report rendering for an unverified public origin candidate', () => {
    const dataWithUnverifiedPublicOrigin: EmailAnalysisResponse = {
      ...completeMockData,
      ip_candidates: [
        {
          ip: '198.51.100.10',
          version: 4,
          classification: 'Documentation',
          hop_index: 0,
          source_header: 'from perimeter.isp.net ([198.51.100.10])',
        },
        {
          ip: '93.184.216.34',
          version: 4,
          classification: 'Public',
          hop_index: 1,
          source_header: 'from client.egress.org ([93.184.216.34])',
        },
      ],
      ip_intelligence: {
        total_candidates: 2,
        candidates: [
          {
            ip: '198.51.100.10',
            version: 4,
            classification: 'Documentation',
            hop_index: 0,
            source_header: 'from perimeter.isp.net ([198.51.100.10])',
            is_routable: false,
            geolocation_status: 'DATABASE_UNAVAILABLE',
            geolocation: null,
            role_hint: 'Recipient Ingress / Perimeter Gateway (Newest Hop)',
            explanation: 'Documentation IP.',
          },
          {
            ip: '93.184.216.34',
            version: 4,
            classification: 'Public',
            hop_index: 1,
            source_header: 'from client.egress.org ([93.184.216.34])',
            is_routable: true,
            geolocation_status: 'DATABASE_UNAVAILABLE',
            geolocation: null,
            role_hint: 'Apparent Earliest Relay / Origin Candidate (Oldest Hop)',
            explanation: 'Public IPv4 address.',
          },
        ],
        origin_candidate: {
          ip: '93.184.216.34',
          version: 4,
          classification: 'Public',
          hop_index: 1,
          source_header: 'from client.egress.org ([93.184.216.34])',
          is_routable: true,
          geolocation_status: 'DATABASE_UNAVAILABLE',
          geolocation: null,
          role_hint: 'Apparent Earliest Relay / Origin Candidate (Oldest Hop)',
          explanation: 'Public IPv4 address.',
        },
        origin_assessment: 'Candidate 93.184.216.34 at earliest recorded hop (Hop 1) is an EXTRACTED_PUBLIC IP candidate representing the apparent network egress with unverified provenance.',
        origin_attribution_status: 'AVAILABLE_UNVERIFIED',
        sender_identity_status: 'Unverified candidate (Pre-boundary / No cryptographic proof)',
        provider_infrastructure_match: null,
        candidate_ip_classification: 'Public',
        is_candidate_routable: true,
        public_count: 1,
        private_count: 0,
        other_count: 1,
        database_available: false,
        warnings: ['Candidate 93.184.216.34 was extracted from an upstream Received header prior to receiving boundary; provenance cannot be independently verified.'],
        disclaimer: 'IP analysis is strictly offline and deterministic.',
      },
    };

    const html = generateForensicReportHtml(dataWithUnverifiedPublicOrigin);

    // Verify Phase 10B UI/Report requirements:
    // 1. Origin attribution is AVAILABLE_UNVERIFIED
    assert.ok(html.includes('Origin Attribution: <strong style="color: var(--cyan-light, #38bdf8);">AVAILABLE_UNVERIFIED</strong>'));
    // 2. Sender Identity explicitly indicates unverified candidate without cryptographic proof
    assert.ok(html.includes('Sender Identity: <strong>Unverified candidate (Pre-boundary / No cryptographic proof)</strong>'));
    // 3. Table badge indicates unverified provenance (NOT a verified origin proof!)
    assert.ok(html.includes('Earliest Public Candidate (Unverified)'));
    // 4. Must NOT claim verified origin or verified sender proof
    assert.strictEqual(html.includes('Verified Sender Proof'), false);
  });
});
