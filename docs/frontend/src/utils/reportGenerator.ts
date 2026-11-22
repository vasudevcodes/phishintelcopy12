/**
 * Forensic Report Generator for PhishIntel (Phase 8C).
 * Produces a self-contained, standalone HTML forensic report from in-memory API responses.
 *
 * Security & Integrity Guarantees:
 * - 100% offline generation; zero external network requests or CDN dependencies.
 * - Restrictive Content Security Policy:
 *     default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data:;
 *     connect-src 'none'; object-src 'none'; frame-src 'none'; media-src 'none';
 *     font-src 'none'; form-action 'none'; base-uri 'none';
 *   (Note: 'sandbox' is omitted as W3C CSP spec mandates user agents ignore sandbox in meta elements).
 * - Full HTML entity escaping on all email-derived artifacts to prevent script injection.
 * - Strict non-verdict disclaimers; no probability claims or safety guarantees.
 * - Zero persistence in localStorage, IndexedDB, or cookies.
 */

import type { EmailAnalysisResponse } from '../types/forensics';

/**
 * Escapes characters to prevent HTML/script injection when rendering untrusted email artifacts.
 */
export function escapeHtml(str: string | null | undefined): string {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Formats byte counts into human-readable strings.
 */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

/**
 * Generates standard timestamped report filenames: phishintel-report-YYYYMMDD-HHmmss.html
 */
export function generateReportFilename(_data?: EmailAnalysisResponse, date: Date = new Date()): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  const year = date.getUTCFullYear();
  const month = pad(date.getUTCMonth() + 1);
  const day = pad(date.getUTCDate());
  const hours = pad(date.getUTCHours());
  const minutes = pad(date.getUTCMinutes());
  const seconds = pad(date.getUTCSeconds());
  return `phishintel-report-${year}${month}${day}-${hours}${minutes}${seconds}.html`;
}

/**
 * Generates the complete, standalone HTML forensic report.
 */
export function generateForensicReportHtml(data: EmailAnalysisResponse, generatedAt: Date = new Date()): string {
  const fusion = data.evidence_fusion;
  const model = data.model_inference;
  const urlAnalysis = data.url_analysis;
  const auth = data.authentication_analysis;
  const ipIntel = data.ip_intelligence;

  const generatedIso = generatedAt.toISOString();

  // Category styling
  const category = fusion?.overall_category || 'INSUFFICIENT_EVIDENCE';
  let categoryColor = '#94a3b8'; // slate
  let categoryBg = '#1e293b';
  let categoryTitle = 'Insufficient Evidence';
  let categorySub = 'Key evidence components were missing, unverified, or indeterminate.';

  if (category === 'HIGH_RISK_INDICATORS_PRESENT') {
    categoryColor = '#f43f5e'; // rose
    categoryBg = '#4c0519';
    categoryTitle = 'High Risk Indicators Present';
    categorySub = 'Explicit structural, authentication, or model risk indicators were identified.';
  } else if (category === 'REVIEW_RECOMMENDED') {
    categoryColor = '#f59e0b'; // amber
    categoryBg = '#451a03';
    categoryTitle = 'Review Recommended';
    categorySub = 'Elevated or ambiguous indicators require manual analyst inspection.';
  } else if (category === 'LOW_RISK_INDICATORS') {
    categoryColor = '#38bdf8'; // sky
    categoryBg = '#082f49';
    categoryTitle = 'Low Risk Indicators Observed (No Guarantee of Safety)';
    categorySub = 'No prominent structural risk flags observed. Absence of flags does not guarantee benign intent.';
  }

  // Model details
  const modelStatus = model?.status || fusion?.model_evidence?.status || 'UNAVAILABLE';
  const isModelEvaluated = modelStatus === 'EVALUATED';
  const rawScore = model?.uncalibrated_score ?? fusion?.model_evidence?.uncalibrated_score;
  const predictedLabel = model?.predicted_label ?? fusion?.model_evidence?.predicted_label;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; object-src 'none'; frame-src 'none'; media-src 'none'; font-src 'none'; form-action 'none'; base-uri 'none';">
  <title>PhishIntel Forensic Report - ${escapeHtml(data.filename)}</title>
  <style>
    :root {
      --bg-primary: #0b0f19;
      --bg-card: #111827;
      --bg-subtle: #1f2937;
      --text-main: #e2e8f0;
      --text-muted: #94a3b8;
      --border: #334155;
      --cyan: #06b6d4;
      --cyan-light: #67e8f9;
      --rose: #f43f5e;
      --amber: #f59e0b;
      --emerald: #10b981;
      --sky: #38bdf8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg-primary);
      color: var(--text-main);
      line-height: 1.5;
      padding: 32px 20px;
    }
    .container {
      max-width: 1040px;
      margin: 0 auto;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
    }
    .header {
      padding: 24px 32px;
      background: linear-gradient(180deg, #162032 0%, #111827 100%);
      border-bottom: 1px solid var(--border);
    }
    .brand {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 4px 12px;
      border-radius: 9999px;
      background: rgba(6, 182, 212, 0.15);
      border: 1px solid rgba(6, 182, 212, 0.4);
      color: var(--cyan-light);
      font-size: 11px;
      font-family: monospace;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 12px;
    }
    h1 { font-size: 24px; font-weight: 800; color: #ffffff; letter-spacing: -0.02em; }
    .meta-bar {
      display: flex;
      flex-wrap: wrap;
      gap: 16px;
      margin-top: 12px;
      font-size: 12px;
      color: var(--text-muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    .meta-bar span strong { color: #f1f5f9; }
    .section {
      padding: 24px 32px;
      border-bottom: 1px solid var(--border);
    }
    .section:last-child { border-bottom: none; }
    .section-title {
      font-size: 14px;
      font-weight: 700;
      color: var(--cyan-light);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 14px;
      font-family: ui-monospace, monospace;
    }
    .banner {
      padding: 16px 20px;
      border-radius: 8px;
      margin-bottom: 16px;
      border: 1px solid;
    }
    .badge {
      display: inline-block;
      padding: 3px 10px;
      border-radius: 6px;
      font-size: 11px;
      font-family: ui-monospace, monospace;
      font-weight: 700;
      border: 1px solid;
    }
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; }
    .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
    @media (max-width: 768px) {
      .grid-2, .grid-3, .grid-4 { grid-template-columns: 1fr; }
      body { padding: 12px 8px; }
      .header, .section { padding: 16px 18px; }
    }
    .card {
      background: rgba(15, 23, 42, 0.6);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px 16px;
    }
    .card-title {
      font-size: 11px;
      text-transform: uppercase;
      color: var(--text-muted);
      font-family: ui-monospace, monospace;
      letter-spacing: 0.05em;
      margin-bottom: 4px;
    }
    .card-val { font-size: 15px; font-weight: 700; color: #ffffff; }
    .card-sub { font-size: 11px; color: var(--text-muted); margin-top: 4px; }
    .table-container { overflow-x: auto; margin-top: 10px; border: 1px solid var(--border); border-radius: 6px; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; font-family: ui-monospace, monospace; }
    th {
      background: #0f172a;
      color: var(--text-muted);
      font-weight: 600;
      text-align: left;
      padding: 8px 12px;
      border-bottom: 1px solid var(--border);
      text-transform: uppercase;
      font-size: 10px;
      letter-spacing: 0.05em;
    }
    td { padding: 9px 12px; border-bottom: 1px solid rgba(51, 65, 85, 0.6); color: var(--text-main); vertical-align: top; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(30, 41, 59, 0.4); }
    .disclaimer-box {
      background: rgba(15, 23, 42, 0.9);
      border: 1px solid rgba(6, 182, 212, 0.3);
      border-radius: 8px;
      padding: 12px 16px;
      font-size: 11px;
      color: #94a3b8;
      line-height: 1.6;
    }
    .disclaimer-box strong { color: var(--cyan-light); }
    .url-string { word-break: break-all; color: #cbd5e1; font-size: 11px; }
    ul.factors-list { list-style: none; padding-left: 0; }
    ul.factors-list li {
      font-size: 12px;
      padding: 4px 0;
      display: flex;
      gap: 8px;
      color: #cbd5e1;
    }
    ul.factors-list li::before {
      content: "•";
      color: var(--cyan);
      font-weight: bold;
    }
    .footer {
      padding: 24px 32px;
      background: #090d16;
      text-align: center;
      font-size: 11px;
      color: #64748b;
      font-family: ui-monospace, monospace;
      line-height: 1.6;
    }
    @media print {
      body { background: #ffffff; color: #0f172a; padding: 0; }
      .container { border: none; box-shadow: none; max-width: 100%; }
      .header, .section, .footer { background: #ffffff !important; color: #0f172a !important; }
      h1, .card-val { color: #000000 !important; }
      th { background: #f1f5f9 !important; color: #334155 !important; }
      td { color: #0f172a !important; }
      .card { background: #f8fafc !important; border-color: #cbd5e1 !important; }
      .banner { border-color: #000000 !important; }
    }
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <div class="header">
      <div class="brand">PhishIntel Forensic Engine</div>
      <h1>Email Forensic Analysis Report</h1>
      <div class="meta-bar">
        <span>Target File: <strong>${escapeHtml(data.filename)}</strong></span>
        <span>Size: <strong>${formatBytes(data.file_size_bytes)}</strong></span>
        <span>Parsing: <strong style="color: ${data.parsing_status === 'success' ? 'var(--emerald)' : 'var(--amber)'};">${escapeHtml(data.parsing_status === 'success' ? 'RFC 5322 Parsed' : 'Partial Parse')}</strong></span>
        <span>Generated: <strong>${escapeHtml(generatedIso)} UTC</strong></span>
        <span>Format: <strong>v1.0 Standalone</strong></span>
      </div>
    </div>

    <!-- Executive Summary -->
    <div class="section">
      <div class="section-title">1. Executive Summary &amp; Evidence Fusion</div>
      
      <div class="banner" style="background: ${categoryBg}; border-color: ${categoryColor};">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
          <div>
            <span class="badge" style="background: ${categoryBg}; color: ${categoryColor}; border-color: ${categoryColor}; font-size: 12px;">
              ${escapeHtml(categoryTitle)}
            </span>
            ${fusion?.overall_risk_score !== undefined ? `
            <span class="badge" style="background: rgba(15, 23, 42, 0.7); color: #ffffff; border-color: rgba(255,255,255,0.2); font-size: 13px; margin-left: 8px;">
              Score: <strong>${fusion.overall_risk_score}</strong> / 100
            </span>` : ''}
            <div style="font-size: 13px; color: #f1f5f9; margin-top: 6px;">
              ${escapeHtml(categorySub)}
            </div>
          </div>
          <div style="font-family: ui-monospace, monospace; font-size: 12px; color: #94a3b8; text-align: right;">
            Overall Risk Score: <strong style="font-size: 18px; color: ${categoryColor};">${fusion?.overall_risk_score !== undefined ? `${fusion.overall_risk_score}/100` : 'N/A'}</strong><br/>
            Category: <strong>${escapeHtml(category)}</strong>
          </div>
        </div>
      </div>

      ${fusion?.risk_score_breakdown ? `
      <div style="margin-bottom: 16px;">
        <div class="card-title">Five-Category Risk Point Contributions (Max 100 Points)</div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; margin-top: 8px;">
          <div class="card" style="padding: 10px;">
            <div style="font-size: 11px; font-weight: bold; color: var(--cyan);">Sender &amp; Auth (25%)</div>
            <div style="font-size: 16px; font-weight: bold; font-family: monospace; color: #fff; margin: 4px 0;">${fusion.risk_score_breakdown.sender_auth.score} / ${fusion.risk_score_breakdown.sender_auth.max_score}</div>
            <div style="font-size: 10px; color: #94a3b8;">${escapeHtml(fusion.risk_score_breakdown.sender_auth.explanation)}</div>
          </div>
          <div class="card" style="padding: 10px;">
            <div style="font-size: 11px; font-weight: bold; color: var(--cyan);">URLs &amp; Links (25%)</div>
            <div style="font-size: 16px; font-weight: bold; font-family: monospace; color: #fff; margin: 4px 0;">${fusion.risk_score_breakdown.url_intelligence.score} / ${fusion.risk_score_breakdown.url_intelligence.max_score}</div>
            <div style="font-size: 10px; color: #94a3b8;">${escapeHtml(fusion.risk_score_breakdown.url_intelligence.explanation)}</div>
          </div>
          <div class="card" style="padding: 10px;">
            <div style="font-size: 11px; font-weight: bold; color: var(--cyan);">Content &amp; Language (20%)</div>
            <div style="font-size: 16px; font-weight: bold; font-family: monospace; color: #fff; margin: 4px 0;">${fusion.risk_score_breakdown.content_language.score} / ${fusion.risk_score_breakdown.content_language.max_score}</div>
            <div style="font-size: 10px; color: #94a3b8;">${escapeHtml(fusion.risk_score_breakdown.content_language.explanation)}</div>
          </div>
          <div class="card" style="padding: 10px;">
            <div style="font-size: 11px; font-weight: bold; color: var(--cyan);">ML DistilBERT (20%)</div>
            <div style="font-size: 16px; font-weight: bold; font-family: monospace; color: #fff; margin: 4px 0;">${fusion.risk_score_breakdown.ml_model.score} / ${fusion.risk_score_breakdown.ml_model.max_score}</div>
            <div style="font-size: 10px; color: #94a3b8;">${escapeHtml(fusion.risk_score_breakdown.ml_model.explanation)}</div>
          </div>
          <div class="card" style="padding: 10px;">
            <div style="font-size: 11px; font-weight: bold; color: var(--cyan);">Header &amp; IP (10%)</div>
            <div style="font-size: 16px; font-weight: bold; font-family: monospace; color: #fff; margin: 4px 0;">${fusion.risk_score_breakdown.header_ip.score} / ${fusion.risk_score_breakdown.header_ip.max_score}</div>
            <div style="font-size: 10px; color: #94a3b8;">${escapeHtml(fusion.risk_score_breakdown.header_ip.explanation)}</div>
          </div>
        </div>
      </div>` : ''}

      ${(fusion?.risk_score_breakdown?.floor_adjustment ?? 0) > 0 ? `
      <div class="card" style="margin-bottom: 16px; border-color: rgba(239, 68, 68, 0.4);">
        <div class="card-title" style="color: #f87171;">Safety-Floor Adjustment: +${fusion?.risk_score_breakdown?.floor_adjustment}</div>
        <div class="card-sub">${escapeHtml(fusion?.risk_score_breakdown?.floor_adjustment_reason ?? 'A minimum-risk floor was applied because of a severe indicator.')}</div>
        <div class="card-sub">${fusion?.risk_score_breakdown?.category_sum ?? 0} (category points) + ${fusion?.risk_score_breakdown?.floor_adjustment} (floor) = ${fusion?.overall_risk_score}/100</div>
      </div>` : ''}

      ${(fusion?.positive_evidence?.length || fusion?.negative_evidence?.length) ? `
      <div class="grid-2" style="margin-bottom: 16px;">
        <div class="card" style="border-color: rgba(16, 185, 129, 0.4);">
          <div class="card-title" style="color: var(--emerald);">Mitigating Observations (${fusion?.positive_evidence?.length ?? 0})</div>
          ${fusion?.positive_evidence && fusion.positive_evidence.length > 0 ? `
            <ul class="factors-list">
              ${fusion.positive_evidence.map((p) => `<li style="color: #6ee7b7;"><span style="color: var(--emerald); font-weight: bold;">[PASS]</span> ${escapeHtml(p)}</li>`).join('')}
            </ul>
          ` : '<p style="font-size: 12px; color: #64748b; font-style: italic;">No specific mitigating observations recorded.</p>'}
        </div>

        <div class="card" style="border-color: rgba(244, 63, 94, 0.4);">
          <div class="card-title" style="color: var(--rose);">Risk Indicators Present (${fusion?.negative_evidence?.length ?? 0})</div>
          ${fusion?.negative_evidence && fusion.negative_evidence.length > 0 ? `
            <ul class="factors-list">
              ${fusion.negative_evidence.map((n) => `<li style="color: #fca5a5;"><span style="color: var(--rose); font-weight: bold;">[RISK]</span> ${escapeHtml(n)}</li>`).join('')}
            </ul>
          ` : '<p style="font-size: 12px; color: #6ee7b7; font-style: italic;">Zero prominent risk indicators detected.</p>'}
        </div>
      </div>` : ''}

      ${fusion?.reasoning ? `
      <div style="margin-bottom: 16px;">
        <div class="card-title">Synthesized Forensic Reasoning</div>
        <p style="font-size: 13px; color: #cbd5e1; line-height: 1.6; background: rgba(15, 23, 42, 0.4); padding: 12px 14px; border-radius: 6px; border: 1px solid var(--border);">
          ${escapeHtml(fusion.reasoning)}
        </p>
      </div>` : ''}

      <div class="grid-2" style="margin-bottom: 16px;">
        <div class="card">
          <div class="card-title" style="color: var(--rose);">Observed Contributing Factors (${fusion?.contributing_factors?.length ?? 0})</div>
          ${fusion?.contributing_factors && fusion.contributing_factors.length > 0 ? `
            <ul class="factors-list">
              ${fusion.contributing_factors.map((f) => `<li>${escapeHtml(f)}</li>`).join('')}
            </ul>
          ` : '<p style="font-size: 12px; color: #64748b; font-style: italic;">No elevated risk factors recorded.</p>'}
        </div>

        <div class="card">
          <div class="card-title" style="color: var(--text-muted);">Inconclusive or Missing Factors (${fusion?.inconclusive_or_missing_factors?.length ?? 0})</div>
          ${fusion?.inconclusive_or_missing_factors && fusion.inconclusive_or_missing_factors.length > 0 ? `
            <ul class="factors-list">
              ${fusion.inconclusive_or_missing_factors.map((m) => `<li>${escapeHtml(m)}</li>`).join('')}
            </ul>
          ` : '<p style="font-size: 12px; color: #64748b; font-style: italic;">All expected signals were evaluable.</p>'}
        </div>
      </div>

      <div class="disclaimer-box">
        <strong>Mandatory Non-Verdict Disclaimer: </strong>
        ${escapeHtml(fusion?.disclaimer || 'This assessment is an investigation support aid combining local forensic observations and model scores. It does NOT emit a calibrated probability or a definitive phishing verdict. Findings must be validated by security analysts.')}
      </div>
    </div>

    <!-- DistilBERT Transformer Inference -->
    <div class="section">
      <div class="section-title">2. DistilBERT Transformer Text Inference</div>
      
      <div class="grid-3" style="margin-bottom: 14px;">
        <div class="card">
          <div class="card-title">Model Execution Status</div>
          <div class="card-val" style="color: ${modelStatus === 'EVALUATED' ? 'var(--emerald)' : modelStatus === 'ERROR' ? 'var(--rose)' : 'var(--amber)'};">
            ${escapeHtml(modelStatus)}
          </div>
          <div class="card-sub">Fine-tuned baseline model</div>
        </div>

        <div class="card">
          <div class="card-title">Predicted Classification Label</div>
          <div class="card-val">
            ${isModelEvaluated ? (
      predictedLabel === 1
        ? '<span style="color: var(--rose);">1 (Phishing Indicator)</span>'
        : '<span style="color: var(--sky);">0 (Benign Pattern)</span>'
    ) : `<span style="color: var(--text-muted);">N/A (${escapeHtml(modelStatus)})</span>`}
          </div>
          <div class="card-sub">${isModelEvaluated ? 'Decision boundary: 0.5000' : 'Inference not performed'}</div>
        </div>

        <div class="card">
          <div class="card-title">Uncalibrated Phishing Score</div>
          <div class="card-val" style="color: var(--cyan-light);">
            ${isModelEvaluated && typeof rawScore === 'number' ? rawScore.toFixed(4) : 'N/A'}
          </div>
          <div class="card-sub">Raw model output (0.0 to 1.0)</div>
        </div>
      </div>

      ${fusion?.model_evidence?.interpretation ? `
      <div style="font-size: 12px; color: #cbd5e1; margin-bottom: 12px;">
        <strong>Forensic Interpretation: </strong>${escapeHtml(fusion.model_evidence.interpretation)}
      </div>` : ''}
    </div>

    <!-- URL Intelligence -->
    <div class="section">
      <div class="section-title">3. URL Intelligence &amp; Lexical Heuristics</div>

      ${urlAnalysis ? `
      <div class="grid-4" style="margin-bottom: 16px;">
        <div class="card">
          <div class="card-title">Total URLs</div>
          <div class="card-val">${urlAnalysis.total_urls}</div>
        </div>
        <div class="card">
          <div class="card-title">Unique URLs</div>
          <div class="card-val">${urlAnalysis.unique_urls}</div>
        </div>
        <div class="card">
          <div class="card-title">Highest Risk Tier</div>
          <div class="card-val" style="color: ${urlAnalysis.highest_risk_category === 'HIGH' ? 'var(--rose)' : urlAnalysis.highest_risk_category === 'MEDIUM' ? 'var(--amber)' : 'var(--text-main)'};">
            ${escapeHtml(urlAnalysis.highest_risk_category)}
          </div>
        </div>
        <div class="card">
          <div class="card-title">Risk Breakdown</div>
          <div style="font-size: 11px; font-family: ui-monospace, monospace; margin-top: 4px; color: #cbd5e1;">
            H: ${urlAnalysis.risk_breakdown['HIGH'] ?? 0} | M: ${urlAnalysis.risk_breakdown['MEDIUM'] ?? 0} | L: ${urlAnalysis.risk_breakdown['LOW'] ?? 0} | I: ${urlAnalysis.risk_breakdown['INFO'] ?? 0}
          </div>
        </div>
      </div>` : ''}

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Protocol</th>
              <th>Host / Domain</th>
              <th>Classification</th>
              <th>Risk Tier & Score</th>
              <th>Triggered Heuristic Observations</th>
            </tr>
          </thead>
          <tbody>
            ${data.urls.length === 0 ? `
              <tr><td colspan="6" style="text-align: center; color: #64748b; font-style: italic;">No URLs extracted from email text or HTML parts.</td></tr>
            ` : data.urls.map((u, idx) => {
      const uRes = urlAnalysis?.url_results?.find((r) => r.original_url === u.url || r.url_index === idx);
      const hostClass = uRes?.features?.host_classification || 'unknown';
      const riskTier = uRes?.heuristic_risk_category || 'INFO';
      const riskScore = uRes?.heuristic_risk_score !== undefined ? `${uRes.heuristic_risk_score}/100` : 'N/A';
      const obs = uRes?.observations || [];

      return `
              <tr>
                <td>#${idx}</td>
                <td><strong>${escapeHtml(u.scheme ? u.scheme.toUpperCase() : 'RAW')}</strong></td>
                <td>
                  <strong>${escapeHtml(u.domain || '(Unknown)')}</strong>
                  ${u.anchor_text && u.anchor_text.trim() !== u.url.trim() ? `<div style="font-size: 10px; color: #94a3b8; margin-top: 2px;">Label: &ldquo;${escapeHtml(u.anchor_text)}&rdquo;</div>` : ''}
                  <div class="url-string">${escapeHtml(u.url)}</div>
                </td>
                <td>${escapeHtml(hostClass)}</td>
                <td>
                  <span class="badge" style="border-color: ${riskTier === 'HIGH' ? 'var(--rose)' : riskTier === 'MEDIUM' ? 'var(--amber)' : 'var(--border)'}; color: ${riskTier === 'HIGH' ? 'var(--rose)' : riskTier === 'MEDIUM' ? 'var(--amber)' : '#ffffff'};">
                    ${escapeHtml(riskTier)} (${escapeHtml(riskScore)})
                  </span>
                </td>
                <td>
                  ${obs.length > 0 ? `
                    <div style="display: flex; flex-direction: column; gap: 4px;">
                      ${obs.map((o) => `
                        <div style="font-size: 11px; background: rgba(0,0,0,0.3); padding: 4px 6px; border-radius: 4px; border: 1px solid var(--border);">
                          <strong style="color: ${o.severity === 'HIGH' ? 'var(--rose)' : o.severity === 'MEDIUM' ? 'var(--amber)' : 'var(--cyan-light)'};">[${escapeHtml(o.severity)}] ${escapeHtml(o.rule_name)} (${escapeHtml(o.rule_id)}):</strong>
                          <span style="color: #cbd5e1;">${escapeHtml(o.description)}</span>
                        </div>
                      `).join('')}
                    </div>
                  ` : '<span style="color: #64748b; font-style: italic;">No structural anomalies detected.</span>'}
                </td>
              </tr>`;
    }).join('')}
          </tbody>
        </table>
      </div>

      <div style="font-size: 11px; color: #94a3b8; margin-top: 10px; font-family: ui-monospace, monospace;">
        * Note: URL risk scores are rule-based heuristic indicators (0–100) reflecting structural and lexical patterns, not statistical probabilities. Strict zero-touch guarantee: PhishIntel never visits or resolves external links.
      </div>
    </div>

    <!-- Cryptographic Authentication -->
    <div class="section">
      <div class="section-title">4. Cryptographic Authentication Evidence (SPF / DKIM / DMARC)</div>

      <div class="grid-3" style="margin-bottom: 14px;">
        <!-- SPF -->
        <div class="card">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
            <div class="card-title">SPF Evidence</div>
            <span class="badge" style="border-color: ${auth?.spf?.status === 'PASS' ? 'var(--emerald)' : auth?.spf?.status === 'FAIL' ? 'var(--rose)' : 'var(--border)'};">
              ${escapeHtml(auth?.spf?.status || 'NOT_PRESENT')}
            </span>
          </div>
          <div style="font-size: 11px; font-family: ui-monospace, monospace; color: #cbd5e1;">
            <div>Domain: <strong>${escapeHtml(auth?.spf?.domain || '(None)')}</strong></div>
            <div>Client IP: <strong>${escapeHtml(auth?.spf?.client_ip || '(None)')}</strong></div>
          </div>
          <div class="card-sub">${escapeHtml(auth?.spf?.explanation || 'No SPF analysis available.')}</div>
        </div>

        <!-- DKIM -->
        <div class="card">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
            <div class="card-title">DKIM Evidence</div>
            <span class="badge" style="border-color: ${auth?.dkim?.status === 'PASS' ? 'var(--emerald)' : auth?.dkim?.status === 'FAIL' ? 'var(--rose)' : 'var(--border)'};">
              ${escapeHtml(auth?.dkim?.status || 'NOT_PRESENT')}
            </span>
          </div>
          <div style="font-size: 11px; font-family: ui-monospace, monospace; color: #cbd5e1;">
            <div>Signing Domain (d=): <strong>${escapeHtml(auth?.dkim?.domain || '(None)')}</strong></div>
            <div>Selector (s=): <strong>${escapeHtml(auth?.dkim?.selector || '(None)')}</strong></div>
            <div>Raw Signatures: <strong>${auth?.dkim?.dkim_signature_count ?? 0} header(s)</strong></div>
          </div>
          <div class="card-sub">${escapeHtml(auth?.dkim?.explanation || 'No DKIM analysis available.')}</div>
        </div>

        <!-- DMARC -->
        <div class="card">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
            <div class="card-title">DMARC Evidence</div>
            <span class="badge" style="border-color: ${auth?.dmarc?.status === 'PASS' ? 'var(--emerald)' : auth?.dmarc?.status === 'FAIL' ? 'var(--rose)' : 'var(--border)'};">
              ${escapeHtml(auth?.dmarc?.status || 'NOT_PRESENT')}
            </span>
          </div>
          <div style="font-size: 11px; font-family: ui-monospace, monospace; color: #cbd5e1;">
            <div>From Domain: <strong>${escapeHtml(auth?.dmarc?.header_from || '(None)')}</strong></div>
            <div>Published Policy: <strong>${auth?.dmarc?.policy ? `p=${escapeHtml(auth.dmarc.policy)}` : '(None)'}</strong></div>
            <div>Alignment Verified: <strong>${auth?.dmarc?.alignment_verified ? 'Yes (Explicit)' : 'No'}</strong></div>
          </div>
          <div class="card-sub">${escapeHtml(auth?.dmarc?.explanation || 'No DMARC analysis available.')}</div>
        </div>
      </div>

      <div class="disclaimer-box">
        <strong>Trust Boundary Limitation: </strong>
        ${escapeHtml(auth?.disclaimer || 'Authentication evidence reflects downstream MTA header assertions (RFC 8601/RFC 7208). DKIM signature presence indicates a signature was attached, but full cryptographic verification depends on gateway trust boundaries and live key lookups.')}
      </div>
    </div>

    <!-- IP Intelligence -->
    <div class="section">
      <div class="section-title">5. IP Intelligence</div>

      ${ipIntel ? `
      <div class="card" style="margin-bottom: 14px;">
        <div class="card-title">Origin Transit Evaluation</div>
        <div style="font-size: 13px; color: #cbd5e1; margin-bottom: 8px;">
          ${escapeHtml(ipIntel.origin_assessment)}
        </div>
        <div style="display: flex; gap: 16px; flex-wrap: wrap; font-size: 11px; font-family: ui-monospace, monospace; color: var(--text-muted); border-top: 1px solid var(--border); padding-top: 8px;">
          <span>Origin Attribution: <strong style="color: ${ipIntel.origin_attribution_status === 'UNAVAILABLE' ? 'var(--amber, #f59e0b)' : 'var(--cyan-light, #38bdf8)'};">${escapeHtml(ipIntel.origin_attribution_status || (ipIntel.origin_candidate ? 'AVAILABLE_UNVERIFIED' : 'UNAVAILABLE'))}</strong></span>
          <span>Apparent Origin: <strong style="color: var(--cyan-light);">${escapeHtml(ipIntel.origin_candidate?.ip || '(Unavailable)')}</strong></span>
          <span>Candidate IP: <strong>${escapeHtml(ipIntel.candidate_ip_classification || ipIntel.origin_candidate?.classification || 'Unavailable')}</strong></span>
          <span>Provider Indicator: <strong>${escapeHtml(ipIntel.provider_infrastructure_match || 'None detected')}</strong></span>
          <span>Sender Identity: <strong>${escapeHtml(ipIntel.sender_identity_status || 'Not established')}</strong></span>
          <span>Candidate Routability: <strong>${ipIntel.is_candidate_routable !== undefined && ipIntel.is_candidate_routable !== null ? (ipIntel.is_candidate_routable ? 'Public' : 'Non-routable') : (ipIntel.origin_candidate?.is_routable ? 'Public' : 'Non-routable')}</strong></span>
          <span>Offline DB: <strong>${ipIntel.database_available ? 'GeoLite2 Active' : 'Not Loaded'}</strong></span>
        </div>
      </div>` : ''}

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Hop</th>
              <th>Candidate IP</th>
              <th>Role Hint</th>
              <th>Classification</th>
              <th>Routability</th>
              <th>Offline Geolocation</th>
            </tr>
          </thead>
          <tbody>
            ${data.ip_candidates.length === 0 ? `
              <tr><td colspan="6" style="text-align: center; color: #64748b; font-style: italic;">No IP candidates detected in Received headers.</td></tr>
            ` : data.ip_candidates.map((cand) => {
      const cIntel = ipIntel?.candidates?.find((c) => c.ip === cand.ip && (c.hop_index === cand.hop_index || c.hop_index === null));
      const isOrigin = ipIntel?.origin_candidate && ipIntel.origin_candidate.ip === cand.ip && ipIntel.origin_candidate.hop_index === cand.hop_index;
      const geo = cIntel?.geolocation;
      const geoStr = geo
        ? [geo.city_name, geo.country_name || geo.country_code].filter(Boolean).join(', ')
        : cIntel?.geolocation_status === 'NOT_ROUTABLE'
          ? 'Non-routable'
          : 'DB Unavailable';

      return `
              <tr>
                <td>#${cand.hop_index}</td>
                <td><strong>${escapeHtml(cand.ip)}</strong></td>
                <td>${isOrigin ? `<span class="badge" style="border-color: var(--cyan); color: var(--cyan-light);">${cIntel?.classification === 'Public' ? 'Earliest Public Candidate (Unverified)' : 'Earliest Recorded Hop (Origin Unavailable)'}</span>` : escapeHtml(cIntel?.role_hint || 'Relay')}</td>
                <td>${escapeHtml(cand.classification)}</td>
                <td>${cIntel?.is_routable ? '<span style="color: var(--sky);">Public Internet</span>' : '<span style="color: var(--text-muted);">Non-Routable</span>'}</td>
                <td>${escapeHtml(geoStr)}</td>
              </tr>`;
    }).join('')}
          </tbody>
        </table>
      </div>

      <div class="disclaimer-box" style="margin-top: 10px;">
        <strong>Forensic IP Limitation: </strong>
        ${escapeHtml(ipIntel?.disclaimer || 'Received headers prior to the recipient boundary MTA can be spoofed or omitted by untrusted relays. IP egress reflects network routing, not a person\'s physical location. Private IPs, proxies, and cloud hosts are not proof of maliciousness.')}
      </div>
    </div>

    <!-- RFC 5322 Standard Headers & Attachments -->
    <div class="section">
      <div class="section-title">6. RFC 5322 Standard Headers &amp; Attachments</div>

      <div class="table-container" style="margin-bottom: 16px;">
        <table>
          <thead>
            <tr>
              <th style="width: 180px;">Header Field</th>
              <th>Extracted Value</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>Subject</strong></td>
              <td>${escapeHtml(data.headers.subject || '(None)')}</td>
            </tr>
            <tr>
              <td><strong>From</strong></td>
              <td>${escapeHtml(data.headers.from_header || '(Not Specified)')}</td>
            </tr>
            <tr>
              <td><strong>To</strong></td>
              <td>${escapeHtml(data.headers.to_headers.join(', ') || '(Not Specified)')}</td>
            </tr>
            ${data.headers.cc_headers.length > 0 ? `
            <tr>
              <td><strong>Cc</strong></td>
              <td>${escapeHtml(data.headers.cc_headers.join(', '))}</td>
            </tr>` : ''}
            ${data.headers.bcc_headers.length > 0 ? `
            <tr>
              <td><strong>Bcc</strong></td>
              <td>${escapeHtml(data.headers.bcc_headers.join(', '))}</td>
            </tr>` : ''}
            <tr>
              <td><strong>Date</strong></td>
              <td>${escapeHtml(data.headers.date || '(Not Specified)')}</td>
            </tr>
            <tr>
              <td><strong>Message-ID</strong></td>
              <td>${escapeHtml(data.headers.message_id || '(None)')}</td>
            </tr>
            <tr>
              <td><strong>Return-Path</strong></td>
              <td>${escapeHtml(data.headers.return_path || '(None)')}</td>
            </tr>
            <tr>
              <td><strong>Reply-To</strong></td>
              <td>${escapeHtml(data.headers.reply_to || '(None)')}</td>
            </tr>
            <tr>
              <td><strong>Content-Type</strong></td>
              <td>${escapeHtml(data.headers.content_type || '(None)')}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="card-title">Attachment Artifacts (${data.attachments.length})</div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Filename</th>
              <th>MIME Content-Type</th>
              <th>Size</th>
              <th>Cryptographic SHA-256 Checksum</th>
            </tr>
          </thead>
          <tbody>
            ${data.attachments.length === 0 ? `
              <tr><td colspan="4" style="text-align: center; color: #64748b; font-style: italic;">No attachments detected in email.</td></tr>
            ` : data.attachments.map((att) => `
              <tr>
                <td><strong>${escapeHtml(att.filename)}</strong></td>
                <td>${escapeHtml(att.content_type)}</td>
                <td>${formatBytes(att.size_bytes)}</td>
                <td style="font-size: 11px; color: var(--cyan-light); word-break: break-all;">${escapeHtml(att.sha256 || 'Unavailable')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Forensic Warnings & Limitations -->
    <div class="section">
      <div class="section-title">7. Forensic Parser Notices &amp; Operational Warnings</div>

      ${data.warnings && data.warnings.length > 0 ? `
        <div class="banner" style="background: rgba(69, 26, 3, 0.4); border-color: rgba(245, 158, 11, 0.5);">
          <div style="font-weight: 700; color: #f59e0b; margin-bottom: 6px; font-size: 12px;">Non-Fatal Warnings Detected (${data.warnings.length}):</div>
          <ul class="factors-list">
            ${data.warnings.map((w) => `<li style="color: #fde68a;">${escapeHtml(w)}</li>`).join('')}
          </ul>
        </div>
      ` : `
        <div style="font-size: 12px; color: #64748b; font-style: italic;">
          No parser anomalies or non-fatal warnings were recorded during this analysis pass.
        </div>
      `}
    </div>

    <!-- Footer -->
    <div class="footer">
      <div>PhishIntel Forensic Analysis Platform — Local In-Memory Evidence Synthesis</div>
      <div style="margin-top: 4px;">Strict Zero-Touch Protocol: Zero external API lookups, zero live URL fetching, zero scan retention.</div>
      <div style="margin-top: 4px; color: #94a3b8;">This forensic report does not guarantee that an email is safe and makes no definitive phishing verdict claim.</div>
    </div>
  </div>
</body>
</html>`;
}

/**
 * Triggers a browser file download of the forensic report without making network requests
 * or storing data in persistent browser storage.
 */
export function downloadForensicReport(data: EmailAnalysisResponse): void {
  if (!data) return;
  const htmlContent = generateForensicReportHtml(data);
  const filename = generateReportFilename(data);

  const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}
