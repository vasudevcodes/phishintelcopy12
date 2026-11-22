import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import type { EmailAnalysisResponse } from '../types/forensics';

describe('Real Frontend-to-Backend Contract Verification (8 Real Fixtures)', () => {
  const fixturesPath = path.resolve(import.meta.dirname, 'fixtures/real_backend_responses.json');
  const rawData = fs.readFileSync(fixturesPath, 'utf-8');
  const realResponses: Record<string, EmailAnalysisResponse> = JSON.parse(rawData);

  const fixtureNames = Object.keys(realResponses);

  test('All 8 fixture emails were processed by the live backend', () => {
    assert.strictEqual(fixtureNames.length, 8);
  });

  for (const fname of fixtureNames) {
    describe(`Fixture Contract: ${fname}`, () => {
      const resp = realResponses[fname];

      test('Headers and body structure match schema', () => {
        assert.ok(resp.filename);
        assert.ok(typeof resp.file_size_bytes === 'number');
        assert.ok(resp.headers);
        assert.ok(Array.isArray(resp.headers.to_headers));
        assert.ok(Array.isArray(resp.headers.cc_headers));
        assert.ok(Array.isArray(resp.headers.bcc_headers));
        assert.ok(Array.isArray(resp.headers.received_headers));
        assert.ok(resp.body);
        assert.ok(typeof resp.body.has_plain_text === 'boolean');
        assert.ok(typeof resp.body.has_html === 'boolean');
        assert.ok(typeof resp.body.plain_text_char_count === 'number');
        assert.ok(typeof resp.body.html_text_char_count === 'number');
      });

      test('Parsing status and warnings are valid', () => {
        assert.ok(resp.parsing_status === 'success' || resp.parsing_status === 'partial_success');
        assert.ok(Array.isArray(resp.warnings));
        assert.ok(resp.parsed_at);
      });

      test('DistilBERT model inference is EVALUATED with uncalibrated score', () => {
        assert.ok(resp.model_inference, 'model_inference must exist');
        assert.strictEqual(resp.model_inference.status, 'EVALUATED');
        assert.ok(
          resp.model_inference.predicted_label === 0 || resp.model_inference.predicted_label === 1,
          'predicted_label must be 0 or 1'
        );
        assert.ok(
          typeof resp.model_inference.uncalibrated_score === 'number',
          'uncalibrated_score must be a float'
        );
        assert.ok(
          resp.model_inference.uncalibrated_score >= 0.0 &&
            resp.model_inference.uncalibrated_score <= 1.0,
          'uncalibrated_score must be in [0.0, 1.0]'
        );
      });

      test('Evidence fusion synthesis is structured and includes caveats', () => {
        assert.ok(resp.evidence_fusion, 'evidence_fusion must exist');
        const ef = resp.evidence_fusion;
        assert.ok(
          [
            'INSUFFICIENT_EVIDENCE',
            'LOW_RISK_INDICATORS',
            'REVIEW_RECOMMENDED',
            'HIGH_RISK_INDICATORS_PRESENT',
          ].includes(ef.overall_category),
          `Invalid overall category: ${ef.overall_category}`
        );

        // Verify Phase 10 numerical risk score and 5-category breakdown
        assert.ok(typeof ef.overall_risk_score === 'number', 'overall_risk_score must be a number');
        assert.ok(
          ef.overall_risk_score >= 0 && ef.overall_risk_score <= 100,
          `overall_risk_score must be in [0, 100], got ${ef.overall_risk_score}`
        );

        assert.ok(ef.risk_score_breakdown, 'risk_score_breakdown must be present');
        assert.ok(typeof ef.risk_score_breakdown.sender_auth.score === 'number');
        assert.strictEqual(ef.risk_score_breakdown.sender_auth.max_score, 25);
        assert.ok(typeof ef.risk_score_breakdown.url_intelligence.score === 'number');
        assert.strictEqual(ef.risk_score_breakdown.url_intelligence.max_score, 25);
        assert.ok(typeof ef.risk_score_breakdown.content_language.score === 'number');
        assert.strictEqual(ef.risk_score_breakdown.content_language.max_score, 20);
        assert.ok(typeof ef.risk_score_breakdown.ml_model.score === 'number');
        assert.strictEqual(ef.risk_score_breakdown.ml_model.max_score, 20);
        assert.ok(typeof ef.risk_score_breakdown.header_ip.score === 'number');
        assert.strictEqual(ef.risk_score_breakdown.header_ip.max_score, 10);

        assert.ok(
          [
            'FULL_COVERAGE',
            'PARTIAL_COVERAGE',
            'MINIMAL_OR_INSUFFICIENT',
          ].includes(ef.evidence_completeness || ''),
          `Invalid evidence completeness: ${ef.evidence_completeness}`
        );

        assert.ok(Array.isArray(ef.positive_evidence), 'positive_evidence must be an array');
        assert.ok(Array.isArray(ef.negative_evidence), 'negative_evidence must be an array');

        assert.ok(ef.reasoning && ef.reasoning.length > 0, 'Reasoning must be present');
        assert.ok(Array.isArray(ef.contributing_factors), 'contributing_factors must be array');
        assert.ok(
          Array.isArray(ef.inconclusive_or_missing_factors),
          'inconclusive_or_missing_factors must be array'
        );

        // Verify model evidence in fusion
        assert.strictEqual(ef.model_evidence.status, 'EVALUATED');
        assert.ok(
          ef.model_evidence.caveat.includes('uncalibrated DistilBERT output'),
          'Model caveat must specify uncalibrated output'
        );

        // Verify URL evidence summary
        assert.ok(typeof ef.url_evidence.total_urls === 'number');
        assert.ok(typeof ef.url_evidence.unique_domains === 'number');
        assert.ok(ef.url_evidence.heuristic_disclaimer);

        // Verify Auth evidence summary
        assert.ok(ef.auth_evidence.spf_status);
        assert.ok(ef.auth_evidence.dkim_status);
        assert.ok(ef.auth_evidence.dmarc_status);
        assert.ok(ef.auth_evidence.trust_limitation);

        // Verify IP evidence summary
        assert.ok(ef.ip_evidence.origin_classification);
        assert.ok(typeof ef.ip_evidence.is_routable === 'boolean');
        assert.ok(ef.ip_evidence.provenance_limitation);

        // Verify Non-verdict disclaimer
        assert.ok(
          ef.disclaimer.includes('investigation support aid'),
          'Disclaimer must specify investigation support aid'
        );
      });

      test('URL intelligence matches structure when URLs present', () => {
        assert.ok(resp.url_analysis, 'url_analysis must exist');
        assert.strictEqual(resp.url_analysis.total_urls, resp.urls.length);
        assert.ok(resp.url_analysis.risk_breakdown);
        assert.ok(resp.url_analysis.highest_risk_category);
        for (const urlRes of resp.url_analysis.url_results) {
          assert.ok(urlRes.original_url);
          assert.ok(urlRes.features);
          assert.ok(Array.isArray(urlRes.observations));
          assert.ok(typeof urlRes.heuristic_risk_score === 'number');
          assert.ok(
            urlRes.heuristic_risk_score >= 0 && urlRes.heuristic_risk_score <= 100,
            'heuristic score in [0, 100]'
          );
        }
      });

      test('Authentication analysis contains SPF, DKIM, DMARC sections', () => {
        assert.ok(resp.authentication_analysis, 'authentication_analysis must exist');
        const auth = resp.authentication_analysis;
        assert.ok(auth.status);
        assert.ok(auth.spf && auth.spf.status);
        assert.ok(auth.dkim && auth.dkim.status);
        assert.ok(auth.dmarc && auth.dmarc.status);
        assert.ok(Array.isArray(auth.authserv_ids));
        assert.ok(auth.disclaimer);
      });

      test('IP intelligence contains origin assessment and classification', () => {
        assert.ok(resp.ip_intelligence, 'ip_intelligence must exist');
        const ipIntel = resp.ip_intelligence;
        assert.strictEqual(ipIntel.total_candidates, resp.ip_candidates.length);
        assert.ok(ipIntel.origin_assessment);
        assert.ok(typeof ipIntel.database_available === 'boolean');
        assert.ok(ipIntel.disclaimer);
      });
    });
  }
});
