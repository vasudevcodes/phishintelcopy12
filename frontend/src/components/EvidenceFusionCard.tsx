import type { FC } from 'react';
import React from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  AlertCircle,
  HelpCircle,
  Cpu,
  Globe,
  Lock,
  Network,
  Info,
  CheckCircle2,
  ArrowRight,
  ShieldCheck,
  Layers,
} from 'lucide-react';
import type {
  EvidenceFusionResult,
  AssessmentCategory,
  ModelInferenceStatus,
  CategoryScoreDetail,
} from '../types/forensics';

interface EvidenceFusionCardProps {
  fusion?: EvidenceFusionResult | null;
}

export const EvidenceFusionCard: FC<EvidenceFusionCardProps> = ({ fusion }) => {
  if (!fusion) {
    return (
      <div className="rounded-2xl border border-surface-border bg-white p-6 shadow-card">
        <div className="flex items-center space-x-2 text-slate-500">
          <HelpCircle className="w-5 h-5" />
          <h3 className="text-base font-semibold text-navy-900 tracking-tight">
            Multi-Modal Evidence Fusion Assessment
          </h3>
        </div>
        <p className="mt-3 text-xs font-mono text-slate-500">
          Evidence fusion assessment data is not available for this email analysis.
        </p>
      </div>
    );
  }

  const getCategoryConfig = (category: AssessmentCategory) => {
    switch (category) {
      case 'HIGH_RISK_INDICATORS_PRESENT':
        return {
          title: 'High Risk Indicators Present',
          badgeClass: 'bg-red-50 text-red-700 border-red-200',
          scoreBadgeClass: 'bg-red-50 text-red-700 border-red-200',
          scoreBandLabel: 'High Risk (75–100)',
          scoreBoxClass: 'bg-red-50/70 border-red-200 text-red-700',
          progressClass: 'bg-red-600',
          icon: <ShieldAlert className="w-6 h-6 text-red-600 flex-shrink-0" />,
          cardBorder: 'border-red-200',
          bgHeader: 'bg-red-50/50',
          subtitle: 'Explicit structural, authentication, or model risk indicators were identified.',
          actionText: 'Quarantine message immediately. Investigate origin relay and block reported destination URLs.',
        };
      case 'REVIEW_RECOMMENDED':
        return {
          title: 'Review Recommended',
          badgeClass: 'bg-amber-50 text-amber-800 border-amber-200',
          scoreBadgeClass: 'bg-amber-50 text-amber-800 border-amber-200',
          scoreBandLabel: 'Review Recommended (26–74)',
          scoreBoxClass: 'bg-amber-50/70 border-amber-200 text-amber-800',
          progressClass: 'bg-amber-500',
          icon: <AlertTriangle className="w-6 h-6 text-amber-600 flex-shrink-0" />,
          cardBorder: 'border-amber-200',
          bgHeader: 'bg-amber-50/50',
          subtitle: 'Elevated or ambiguous indicators require manual forensic analyst inspection.',
          actionText: 'Inspect message headers and candidate IP provenance. Do not engage with embedded hyperlinks.',
        };
      case 'LOW_RISK_INDICATORS':
        return {
          title: 'Low Risk Indicators Observed',
          badgeClass: 'bg-emerald-50 text-emerald-800 border-emerald-200',
          scoreBadgeClass: 'bg-emerald-50 text-emerald-800 border-emerald-200',
          scoreBandLabel: 'Low Risk Observed (0–25)',
          scoreBoxClass: 'bg-emerald-50/70 border-emerald-200 text-emerald-800',
          progressClass: 'bg-emerald-500',
          icon: <CheckCircle2 className="w-6 h-6 text-emerald-600 flex-shrink-0" />,
          cardBorder: 'border-emerald-200',
          bgHeader: 'bg-emerald-50/50',
          subtitle: 'No prominent structural risk flags observed. (Note: does NOT guarantee safety).',
          actionText: 'Routine delivery permissible. Continue adhering to standard organizational security awareness.',
        };
      case 'INSUFFICIENT_EVIDENCE':
      default:
        return {
          title: 'Insufficient Evidence',
          badgeClass: 'bg-slate-100 text-slate-700 border-slate-200',
          scoreBadgeClass: 'bg-slate-100 text-slate-700 border-slate-200',
          scoreBandLabel: 'Insufficient Evidence',
          scoreBoxClass: 'bg-slate-100 border-slate-200 text-slate-700',
          progressClass: 'bg-slate-400',
          icon: <HelpCircle className="w-6 h-6 text-slate-500 flex-shrink-0" />,
          cardBorder: 'border-surface-border',
          bgHeader: 'bg-slate-50',
          subtitle: 'Key evidence components were missing, unverified, or indeterminate.',
          actionText: 'Gather original raw transit headers or resubmit complete RFC 5322 payload.',
        };
    }
  };

  const catConfig = getCategoryConfig(fusion.overall_category);
  const model = fusion.model_evidence;

  // Build reassuring factors fallback if positive_evidence is not directly populated
  const reassuringFactors: string[] = [];
  if (fusion.positive_evidence && fusion.positive_evidence.length > 0) {
    reassuringFactors.push(...fusion.positive_evidence);
  } else {
    if (fusion.auth_evidence.has_valid_authentication && !fusion.auth_evidence.has_explicit_failure) {
      const passed = [
        fusion.auth_evidence.spf_status === 'PASS' ? 'SPF' : null,
        fusion.auth_evidence.dkim_status === 'PASS' ? 'DKIM' : null,
        fusion.auth_evidence.dmarc_status === 'PASS' ? 'DMARC' : null,
      ].filter(Boolean).join(', ');
      reassuringFactors.push(`Reported cryptographic authentication passed (${passed || 'Valid'})`);
    }
    if (model.status === 'EVALUATED' && model.predicted_label === 0) {
      reassuringFactors.push('DistilBERT model observed benign language patterns');
    }
    if (fusion.url_evidence.total_urls > 0 && (fusion.url_evidence.highest_heuristic_risk === 'LOW' || fusion.url_evidence.highest_heuristic_risk === 'INFO')) {
      reassuringFactors.push('All extracted URLs are within low structural risk thresholds');
    }
    if (fusion.url_evidence.total_urls === 0) {
      reassuringFactors.push('Zero external URLs embedded in message body');
    }
  }

  // Build negative factors fallback
  const negativeFactors: string[] = [];
  if (fusion.negative_evidence && fusion.negative_evidence.length > 0) {
    negativeFactors.push(...fusion.negative_evidence);
  } else if (fusion.contributing_factors && fusion.contributing_factors.length > 0) {
    negativeFactors.push(...fusion.contributing_factors);
  }

  const renderModelStatusBadge = (status: ModelInferenceStatus) => {
    switch (status) {
      case 'EVALUATED':
        return (
          <span className="px-2.5 py-0.5 rounded-md text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
            EVALUATED
          </span>
        );
      case 'ERROR':
        return (
          <span className="px-2.5 py-0.5 rounded-md text-xs font-semibold bg-red-50 text-red-700 border border-red-200">
            ERROR (Unavailable)
          </span>
        );
      case 'UNAVAILABLE':
      default:
        return (
          <span className="px-2.5 py-0.5 rounded-md text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200">
            UNAVAILABLE
          </span>
        );
    }
  };

  const renderCategoryCard = (
    cat: CategoryScoreDetail,
    icon: React.ReactNode
  ) => {
    const percentage = Math.round((cat.score / cat.max_score) * 100);
    const isElevated = cat.score > 0;
    return (
      <div
        key={cat.category_name}
        className={`p-4 rounded-xl border transition-all ${
          isElevated
            ? 'bg-amber-50/30 border-amber-200 shadow-subtle'
            : 'bg-surface-subtle border-surface-border'
        }`}
      >
        <div className="flex items-start justify-between gap-2 pb-2.5 border-b border-slate-200/60">
          <div className="flex items-center space-x-2">
            <div className="p-1.5 rounded-lg bg-white border border-slate-200 shadow-subtle flex-shrink-0">
              {icon}
            </div>
            <div>
              <span className="text-xs font-bold text-navy-900 block leading-tight">
                {cat.category_name}
              </span>
              <span className="text-[10px] text-slate-500 font-mono">
                Weight: {cat.weight_percentage}%
              </span>
            </div>
          </div>
          <div className="text-right flex-shrink-0">
            <span
              className={`text-base font-black font-mono ${
                isElevated ? 'text-amber-800' : 'text-emerald-700'
              }`}
            >
              {cat.score}
            </span>
            <span className="text-xs font-mono text-slate-400">/{cat.max_score}</span>
          </div>
        </div>

        {/* Mini progress bar */}
        <div className="w-full h-1.5 bg-slate-200 rounded-full overflow-hidden my-2.5">
          <div
            className={`h-full transition-all duration-300 ${
              isElevated
                ? cat.score >= cat.max_score * 0.7
                  ? 'bg-red-500'
                  : 'bg-amber-500'
                : 'bg-emerald-500'
            }`}
            style={{ width: `${Math.max(percentage, isElevated ? 6 : 0)}%` }}
          />
        </div>

        <p className="text-xs text-slate-600 leading-relaxed">
          {cat.explanation}
        </p>

        {cat.is_dampened && (
          <div className="mt-2.5 inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold bg-blue-50 text-blue-700 border border-blue-200">
            Corroboration Dampening Applied
          </div>
        )}

        {cat.rules_triggered && cat.rules_triggered.length > 0 && (
          <div className="mt-2.5 flex flex-wrap gap-1">
            {cat.rules_triggered.map((rule) => (
              <span
                key={rule}
                className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-white text-slate-700 border border-slate-200 shadow-subtle"
              >
                {rule}
              </span>
            ))}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className={`rounded-2xl border ${catConfig.cardBorder} bg-white shadow-card overflow-hidden`}>
      {/* Assessment Header Banner */}
      <div className={`p-5 sm:p-6 ${catConfig.bgHeader} border-b border-surface-border`}>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start space-x-3.5">
            <div className="p-2.5 rounded-xl bg-white border border-surface-border flex items-center justify-center shadow-subtle">
              {catConfig.icon}
            </div>
            <div>
              <div className="flex items-center space-x-2.5 flex-wrap gap-y-1">
                <span className="text-xs font-mono uppercase tracking-wider text-slate-500 font-semibold">
                  Evidence Fusion Synthesis
                </span>
                <span
                  className={`px-3 py-0.5 rounded-full text-xs font-bold border ${catConfig.badgeClass}`}
                >
                  {catConfig.title}
                </span>
              </div>
              <p className="text-xs sm:text-sm text-navy-900 mt-1 leading-relaxed">
                {catConfig.subtitle}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3.5 self-start md:self-center">
            {fusion.overall_risk_score !== undefined && (
              <div className={`px-4 py-2 rounded-xl border text-center ${catConfig.scoreBoxClass}`}>
                <div className="text-[10px] font-mono uppercase tracking-wider font-semibold opacity-75">
                  Risk Score
                </div>
                <div className="text-2xl font-black font-mono tracking-tight leading-none mt-0.5">
                  {fusion.overall_risk_score}
                  <span className="text-xs font-normal opacity-60">/100</span>
                </div>
              </div>
            )}
            <div className="text-left md:text-right text-xs">
              <span className="block text-[11px] font-medium text-slate-500 uppercase tracking-wider">
                Assessment Code
              </span>
              <span className="font-mono font-semibold text-navy-900">{fusion.overall_category}</span>
            </div>
          </div>
        </div>

        {/* Recommended Action Pill */}
        <div className="mt-4 pt-3.5 border-t border-slate-200/60 flex items-start sm:items-center space-x-2 text-xs">
          <span className="font-semibold text-navy-900 flex-shrink-0 flex items-center gap-1">
            <span>Recommended Action:</span>
            <ArrowRight className="w-3.5 h-3.5 text-slate-400" />
          </span>
          <span className="text-slate-700">{catConfig.actionText}</span>
        </div>
      </div>

      <div className="p-5 sm:p-6 space-y-6">
        {/* Numerical Phishing Risk Score & Five-Category Breakdown Section */}
        <div className="rounded-xl border border-surface-border bg-white p-5 shadow-subtle space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-surface-border">
            <div>
              <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                <ShieldCheck className="w-5 h-5 text-brand-600" />
                <h4 className="text-base font-bold text-navy-900 tracking-tight">
                  Evidence-Based Phishing Risk Score
                </h4>
                {fusion.evidence_completeness && (
                  <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-brand-50 text-brand-700 border border-brand-200">
                    {fusion.evidence_completeness.replace('_', ' ')}
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-500 mt-1">
                Transparent 0–100 heuristic risk index based on 5 weighted evidence categories. Not a statistical probability or guarantee of safety.
              </p>
            </div>

            {/* Score Highlight Metric */}
            <div className="flex items-center space-x-3 self-start sm:self-center">
              <div className="text-right">
                <div className="text-xs text-slate-500 font-medium">Risk Tier</div>
                <div className="text-xs font-semibold text-navy-900">
                  {catConfig.scoreBandLabel}
                </div>
              </div>
              <div className={`px-4 py-2 rounded-xl border font-mono font-black text-2xl sm:text-3xl ${catConfig.scoreBadgeClass}`}>
                {fusion.overall_risk_score !== undefined ? `${fusion.overall_risk_score}` : 'N/A'}
                <span className="text-xs font-normal text-slate-500 font-sans">/100</span>
              </div>
            </div>
          </div>

          {/* Overall Score Progress Bar with 3 Risk Bands */}
          <div className="space-y-1.5">
            <div className="flex justify-between text-[11px] font-medium text-slate-500">
              <span className="text-emerald-700 font-semibold">Low Risk (0–25)</span>
              <span className="text-amber-700 font-semibold">Review Recommended (26–74)</span>
              <span className="text-red-700 font-semibold">High Risk Present (75–100)</span>
            </div>
            <div className="w-full h-3 bg-slate-100 rounded-full overflow-hidden border border-slate-200 relative">
              {/* Reference markers for 25 and 75 */}
              <div className="absolute left-[25%] top-0 bottom-0 w-0.5 bg-slate-300 z-10" />
              <div className="absolute left-[75%] top-0 bottom-0 w-0.5 bg-slate-300 z-10" />
              <div
                className={`h-full transition-all duration-500 ${catConfig.progressClass}`}
                style={{ width: `${Math.min(100, Math.max(0, fusion.overall_risk_score ?? 0))}%` }}
              />
            </div>
            {fusion.evidence_completeness_detail && (
              <p className="text-[11px] text-slate-500 italic mt-1">
                Evidence coverage: {fusion.evidence_completeness_detail}
              </p>
            )}
          </div>

          {/* 5-Category Breakdown Grid */}
          {fusion.risk_score_breakdown && (
            <div className="space-y-3 pt-2">
              <div className="flex items-center justify-between">
                <h5 className="text-xs font-semibold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
                  <Layers className="w-3.5 h-3.5 text-brand-600" />
                  <span>Five-Category Risk Contributions (Max 100 Points)</span>
                </h5>
                <span className="text-xs font-mono text-slate-500 font-medium">
                  Total Points Accrued: <strong className="text-navy-900">{fusion.overall_risk_score ?? 0}</strong>/100
                  {(fusion.risk_score_breakdown.floor_adjustment ?? 0) > 0 && (
                    <span className="text-slate-400">
                      {' '}
                      ({fusion.risk_score_breakdown.category_sum ?? 0} + {fusion.risk_score_breakdown.floor_adjustment} floor)
                    </span>
                  )}
                </span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
                {/* 1. Sender Identity & Authentication (25 pts) */}
                {renderCategoryCard(
                  fusion.risk_score_breakdown.sender_auth,
                  <Lock className="w-4 h-4 text-brand-600" />
                )}
                {/* 2. URL & Link Intelligence (25 pts) */}
                {renderCategoryCard(
                  fusion.risk_score_breakdown.url_intelligence,
                  <Globe className="w-4 h-4 text-blue-600" />
                )}
                {/* 3. Content & Language Analysis (20 pts) */}
                {renderCategoryCard(
                  fusion.risk_score_breakdown.content_language,
                  <AlertCircle className="w-4 h-4 text-amber-600" />
                )}
                {/* 4. DistilBERT ML Model Analysis (20 pts) */}
                {renderCategoryCard(
                  fusion.risk_score_breakdown.ml_model,
                  <Cpu className="w-4 h-4 text-purple-600" />
                )}
                {/* 5. Header, IP & Infrastructure (10 pts) */}
                {renderCategoryCard(
                  fusion.risk_score_breakdown.header_ip,
                  <Network className="w-4 h-4 text-indigo-600" />
                )}
              </div>
              {(fusion.risk_score_breakdown.floor_adjustment ?? 0) > 0 && (
                <div className="p-4 rounded-xl border border-red-200 bg-red-50/40">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <span className="text-xs font-bold text-navy-900 block leading-tight">
                        Safety-Floor Adjustment
                      </span>
                      <p className="text-xs text-slate-600 leading-relaxed mt-1">
                        {fusion.risk_score_breakdown.floor_adjustment_reason ||
                          'A minimum-risk floor was applied because of a severe indicator.'}
                      </p>
                    </div>
                    <span className="text-base font-black font-mono text-red-700 flex-shrink-0">
                      +{fusion.risk_score_breakdown.floor_adjustment}
                    </span>
                  </div>
                  <p className="text-[11px] font-mono text-slate-500 mt-2 pt-2 border-t border-red-100">
                    {fusion.risk_score_breakdown.category_sum ?? 0} (category points) +{' '}
                    {fusion.risk_score_breakdown.floor_adjustment} (floor) = {fusion.overall_risk_score ?? 0}/100
                  </p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Synthesized Forensic Reasoning */}
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-2">
            Forensic Reasoning &amp; Context
          </h4>
          <div className="p-4 rounded-xl bg-surface-subtle border border-surface-border text-xs sm:text-sm text-navy-900 leading-relaxed font-sans">
            {fusion.reasoning}
          </div>
        </div>

        {/* DistilBERT Model Evidence Section */}
        <div className="rounded-xl border border-surface-border bg-white p-5 shadow-subtle">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3.5 border-b border-surface-border">
            <div className="flex items-center space-x-2 text-navy-900">
              <Cpu className="w-4 h-4 text-brand-600" />
              <h4 className="text-sm font-semibold tracking-tight">
                DistilBERT Transformer Text Inference
              </h4>
            </div>
            <div className="flex items-center space-x-2">
              <span className="text-xs text-slate-500">Inference Status:</span>
              {renderModelStatusBadge(model.status)}
            </div>
          </div>

          {model.status === 'EVALUATED' ? (
            <div className="mt-4 space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
                <div className="p-3.5 rounded-xl bg-surface-subtle border border-surface-border">
                  <div className="text-slate-500 text-[11px] font-medium uppercase tracking-wider">
                    Classification Output
                  </div>
                  <div className="text-base font-bold mt-1">
                    {model.predicted_label === 1 ? (
                      <span className="text-red-700 flex items-center gap-1.5">
                        <AlertCircle className="w-4 h-4 text-red-600" />
                        1 (Phishing Indicator)
                      </span>
                    ) : (
                      <span className="text-emerald-700 flex items-center gap-1.5">
                        <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                        0 (Benign / Non-Phishing Pattern)
                      </span>
                    )}
                  </div>
                  <div className="text-[11px] text-slate-500 mt-1 font-mono">
                    Binary decision threshold: 0.5000
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-surface-subtle border border-surface-border">
                  <div className="text-slate-500 text-[11px] font-medium uppercase tracking-wider">
                    Model Confidence Indicator
                  </div>
                  <div className="text-base font-bold font-mono text-navy-900 mt-1">
                    {model.uncalibrated_score !== null
                      ? model.uncalibrated_score.toFixed(4)
                      : 'N/A'}
                  </div>
                  <div className="text-[11px] text-amber-700 mt-1">
                    * Raw heuristic model score (not a calibrated real-world probability)
                  </div>
                </div>
              </div>

              <div className="text-xs text-slate-700 leading-relaxed">
                <strong className="text-navy-900">Interpretation: </strong>
                {model.interpretation}
              </div>
            </div>
          ) : (
            <div className="mt-4 p-4 rounded-xl bg-amber-50 border border-amber-200 text-xs space-y-2">
              <div className="flex items-center space-x-2 text-amber-800 font-semibold">
                <AlertTriangle className="w-4 h-4 text-amber-600" />
                <span>
                  Model Inference {model.status === 'ERROR' ? 'Failed with Error' : 'Unavailable'}
                </span>
              </div>
              <p className="text-amber-800 leading-relaxed">
                {model.interpretation ||
                  'The DistilBERT model was not executed or encountered an inference fault. The system does not fall back to a default benign assumption.'}
              </p>
              <div className="p-2 rounded bg-white border border-amber-200 font-mono text-slate-600 text-[11px]">
                Predicted Label: <span className="text-red-700 font-semibold">N/A ({model.status})</span> | Model Score:{' '}
                <span className="text-red-700 font-semibold">N/A</span>
              </div>
            </div>
          )}
        </div>

        {/* Key Findings: Suspicious, Reassuring & Inconclusive Groups */}
        <div className="space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500">
            Key Findings &amp; Forensic Indicators
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
            {/* 1. Suspicious / Risk Indicators */}
            <div className="rounded-xl border border-red-200 bg-red-50/20 p-4">
              <h5 className="text-xs font-semibold uppercase tracking-wider text-red-800 mb-2.5 flex items-center gap-1.5">
                <AlertCircle className="w-4 h-4 text-red-600 flex-shrink-0" />
                <span>Risk Indicators ({negativeFactors.length})</span>
              </h5>
              {negativeFactors.length === 0 ? (
                <p className="text-xs text-slate-500 italic">
                  No explicit suspicious factors flagged.
                </p>
              ) : (
                <ul className="space-y-2 text-xs text-navy-900">
                  {negativeFactors.map((factor, idx) => (
                    <li key={idx} className="flex items-start space-x-2">
                      <span className="text-red-500 font-bold mt-0.5">•</span>
                      <span className="leading-relaxed">{factor}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* 2. Reassuring / Mitigating Indicators */}
            <div className="rounded-xl border border-emerald-200 bg-emerald-50/20 p-4">
              <h5 className="text-xs font-semibold uppercase tracking-wider text-emerald-800 mb-2.5 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0" />
                <span>Mitigating Observations ({reassuringFactors.length})</span>
              </h5>
              {reassuringFactors.length === 0 ? (
                <p className="text-xs text-slate-500 italic">
                  No positive authentication or benign signals observed.
                </p>
              ) : (
                <ul className="space-y-2 text-xs text-navy-900">
                  {reassuringFactors.map((r, idx) => (
                    <li key={idx} className="flex items-start space-x-2">
                      <span className="text-emerald-500 font-bold mt-0.5">•</span>
                      <span className="leading-relaxed">{r}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* 3. Inconclusive or Missing Factors */}
            <div className="rounded-xl border border-slate-200 bg-slate-50/60 p-4">
              <h5 className="text-xs font-semibold uppercase tracking-wider text-slate-600 mb-2.5 flex items-center gap-1.5">
                <HelpCircle className="w-4 h-4 text-slate-500 flex-shrink-0" />
                <span>Inconclusive Signals ({fusion.inconclusive_or_missing_factors.length})</span>
              </h5>
              {fusion.inconclusive_or_missing_factors.length === 0 ? (
                <p className="text-xs text-slate-500 italic">
                  All expected forensic signals were present and evaluable.
                </p>
              ) : (
                <ul className="space-y-2 text-xs text-slate-700">
                  {fusion.inconclusive_or_missing_factors.map((factor, idx) => (
                    <li key={idx} className="flex items-start space-x-2">
                      <span className="text-slate-400 font-bold mt-0.5">•</span>
                      <span className="leading-relaxed">{factor}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>

        {/* Modality Summaries Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
          {/* URL Intelligence Summary */}
          <div className="p-4 rounded-xl bg-surface-subtle border border-surface-border space-y-2 shadow-subtle">
            <div className="flex items-center justify-between text-xs">
              <span className="flex items-center gap-1.5 text-blue-700 font-semibold">
                <Globe className="w-4 h-4" />
                <span>URL Intelligence</span>
              </span>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                  fusion.url_evidence.highest_heuristic_risk === 'HIGH'
                    ? 'bg-red-50 text-red-700 border-red-200'
                    : fusion.url_evidence.highest_heuristic_risk === 'MEDIUM'
                    ? 'bg-amber-50 text-amber-800 border-amber-200'
                    : 'bg-slate-100 text-slate-700 border-slate-200'
                }`}
              >
                {fusion.url_evidence.highest_heuristic_risk} RISK
              </span>
            </div>
            <p className="text-xs text-slate-700 leading-relaxed">
              {fusion.url_evidence.explanation}
            </p>
            <div className="text-[11px] font-mono text-slate-500 pt-1.5 border-t border-slate-200">
              URLs: {fusion.url_evidence.total_urls} | Domains: {fusion.url_evidence.unique_domains}
            </div>
          </div>

          {/* Authentication Summary */}
          <div className="p-4 rounded-xl bg-surface-subtle border border-surface-border space-y-2 shadow-subtle">
            <div className="flex items-center justify-between text-xs">
              <span className="flex items-center gap-1.5 text-brand-700 font-semibold">
                <Lock className="w-4 h-4" />
                <span>Authentication</span>
              </span>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                  fusion.auth_evidence.has_explicit_failure
                    ? 'bg-red-50 text-red-700 border-red-200'
                    : fusion.auth_evidence.has_valid_authentication
                    ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                    : 'bg-slate-100 text-slate-700 border-slate-200'
                }`}
              >
                {fusion.auth_evidence.has_explicit_failure
                  ? 'FAIL DETECTED'
                  : fusion.auth_evidence.has_valid_authentication
                  ? 'VALID AUTH'
                  : 'INDETERMINATE'}
              </span>
            </div>
            <p className="text-xs text-slate-700 leading-relaxed">
              {fusion.auth_evidence.explanation}
            </p>
            <div className="text-[11px] font-mono text-slate-500 pt-1.5 border-t border-slate-200 flex justify-between">
              <span>SPF: {fusion.auth_evidence.spf_status}</span>
              <span>DKIM: {fusion.auth_evidence.dkim_status}</span>
              <span>DMARC: {fusion.auth_evidence.dmarc_status}</span>
            </div>
          </div>

          {/* IP Transit Summary */}
          <div className="p-4 rounded-xl bg-surface-subtle border border-surface-border space-y-2 shadow-subtle">
            <div className="flex items-center justify-between text-xs">
              <span className="flex items-center gap-1.5 text-purple-700 font-semibold">
                <Network className="w-4 h-4" />
                <span>IP Transit</span>
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-50 text-purple-700 border border-purple-200 font-mono">
                {fusion.ip_evidence.hop_count} HOPS
              </span>
            </div>
            <p className="text-xs text-slate-700 leading-relaxed">
              {fusion.ip_evidence.explanation}
            </p>
            <div className="text-[11px] font-mono text-slate-500 pt-1.5 border-t border-slate-200 truncate">
              Origin: {fusion.ip_evidence.apparent_origin_ip || '(Undetermined)'} (
              {fusion.ip_evidence.origin_classification})
            </div>
          </div>
        </div>

        {/* Mandatory Research / Analyst Disclaimer */}
        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-600 space-y-1">
          <div className="flex items-center space-x-1.5 text-navy-900 font-semibold">
            <Info className="w-4 h-4 text-brand-600 flex-shrink-0" />
            <span>Forensic Synthesis Disclaimer</span>
          </div>
          <p className="leading-relaxed">
            {fusion.disclaimer}
          </p>
        </div>
      </div>
    </div>
  );
};
