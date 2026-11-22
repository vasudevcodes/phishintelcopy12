import { useState } from 'react';
import type { FC } from 'react';
import {
  Globe,
  Copy,
  Check,
  ShieldAlert,
  ChevronDown,
  ChevronUp,
  Info,
} from 'lucide-react';
import type {
  ExtractedURL,
  URLBatchAnalysisResult,
  HeuristicRiskCategory,
  ObservationSeverity,
} from '../types/forensics';

interface ExtractedURLsCardProps {
  urls: ExtractedURL[];
  urlAnalysis?: URLBatchAnalysisResult | null;
}

export const ExtractedURLsCard: FC<ExtractedURLsCardProps> = ({ urls, urlAnalysis }) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [expandedObservations, setExpandedObservations] = useState<Record<number, boolean>>({});

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const toggleObservations = (index: number) => {
    setExpandedObservations((prev) => ({
      ...prev,
      [index]: !prev[index],
    }));
  };

  const getRiskBadgeClass = (category: HeuristicRiskCategory) => {
    switch (category) {
      case 'HIGH':
        return 'bg-red-50 text-red-700 border-red-200';
      case 'MEDIUM':
        return 'bg-amber-50 text-amber-800 border-amber-200';
      case 'LOW':
        return 'bg-blue-50 text-blue-700 border-blue-200';
      case 'INFO':
      default:
        return 'bg-slate-100 text-slate-700 border-slate-200';
    }
  };

  const getSeverityBadgeClass = (sev: ObservationSeverity) => {
    switch (sev) {
      case 'HIGH':
        return 'bg-red-50 text-red-700 border-red-200';
      case 'MEDIUM':
        return 'bg-amber-50 text-amber-800 border-amber-200';
      case 'LOW':
        return 'bg-blue-50 text-blue-700 border-blue-200';
      case 'INFO':
      default:
        return 'bg-slate-100 text-slate-700 border-slate-200';
    }
  };

  return (
    <div className="rounded-2xl border border-surface-border bg-white p-5 sm:p-6 shadow-card space-y-6">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-surface-border">
        <div className="flex items-center space-x-2.5 text-navy-900">
          <Globe className="w-5 h-5 text-blue-600" />
          <h3 className="text-base font-semibold tracking-tight">
            URL Intelligence &amp; Lexical Heuristics ({urls.length})
          </h3>
        </div>

        {urlAnalysis && (
          <div className="flex items-center space-x-2">
            <span className="text-xs text-slate-500 font-medium">Highest Heuristic Risk:</span>
            <span
              className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${getRiskBadgeClass(
                urlAnalysis.highest_risk_category
              )}`}
            >
              {urlAnalysis.highest_risk_category}
            </span>
          </div>
        )}
      </div>

      {/* Strict Security Protocol Banner */}
      <div className="p-4 rounded-xl bg-blue-50/60 border border-blue-200 text-xs text-blue-900 space-y-1">
        <div className="flex items-center space-x-1.5 font-semibold text-blue-900">
          <ShieldAlert className="w-4 h-4 text-blue-600 flex-shrink-0" />
          <span>Strict Zero-Touch Static URL Analysis</span>
        </div>
        <p className="leading-relaxed text-blue-800">
          All extracted URLs are parsed and evaluated locally through deterministic lexical and structural heuristics.
          <strong className="text-blue-950 font-semibold"> PhishIntel never visits, pre-fetches, resolves DNS, or connects to external destination hosts.</strong>
          {' '}Links are strictly non-clickable to prevent accidental navigation.
        </p>
      </div>

      {/* Batch Overview if urlAnalysis is present */}
      {urlAnalysis && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-4 rounded-xl bg-surface-subtle border border-surface-border text-xs">
          <div>
            <div className="text-slate-500 font-medium uppercase tracking-wider text-[11px]">Total Extracted</div>
            <div className="text-navy-900 font-bold text-base mt-0.5">{urlAnalysis.total_urls}</div>
          </div>
          <div>
            <div className="text-slate-500 font-medium uppercase tracking-wider text-[11px]">Unique URLs</div>
            <div className="text-navy-900 font-bold text-base mt-0.5">{urlAnalysis.unique_urls}</div>
          </div>
          <div className="col-span-2 flex items-center justify-end gap-2 flex-wrap">
            <span className="px-2.5 py-0.5 rounded-md text-[11px] font-bold bg-red-50 text-red-700 border border-red-200">
              HIGH: {urlAnalysis.risk_breakdown['HIGH'] ?? 0}
            </span>
            <span className="px-2.5 py-0.5 rounded-md text-[11px] font-bold bg-amber-50 text-amber-800 border border-amber-200">
              MEDIUM: {urlAnalysis.risk_breakdown['MEDIUM'] ?? 0}
            </span>
            <span className="px-2.5 py-0.5 rounded-md text-[11px] font-bold bg-blue-50 text-blue-700 border border-blue-200">
              LOW: {urlAnalysis.risk_breakdown['LOW'] ?? 0}
            </span>
            <span className="px-2.5 py-0.5 rounded-md text-[11px] font-bold bg-slate-100 text-slate-700 border border-slate-200">
              INFO: {urlAnalysis.risk_breakdown['INFO'] ?? 0}
            </span>
          </div>
        </div>
      )}

      {urls.length === 0 ? (
        <div className="text-center py-8 text-slate-500 font-mono text-xs">
          No URLs were detected in plain-text or HTML parts.
        </div>
      ) : (
        <div className="space-y-3.5">
          {urls.map((item, idx) => {
            const analysis = urlAnalysis?.url_results?.find(
              (r) => r.original_url === item.url || r.url_index === idx
            );
            const isExpanded = !!expandedObservations[idx];
            const observations = analysis?.observations || [];

            return (
              <div
                key={idx}
                className="rounded-xl border border-surface-border bg-white p-4 sm:p-5 space-y-3 shadow-subtle hover:border-slate-300 transition-colors"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2.5 border-b border-surface-border">
                  <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                    <span
                      className={`px-2 py-0.5 rounded text-[11px] font-mono font-semibold border ${
                        item.scheme === 'https'
                          ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                          : 'bg-amber-50 text-amber-800 border-amber-200'
                      }`}
                    >
                      {item.scheme ? item.scheme.toUpperCase() : 'RAW'}
                    </span>

                    <span className="font-mono font-semibold text-navy-900 text-xs">
                      {item.domain || '(Unknown Host)'}
                    </span>

                    <span
                      className={`px-2 py-0.5 rounded text-[10px] border font-mono ${
                        item.source === 'both'
                          ? 'bg-purple-50 text-purple-700 border-purple-200'
                          : item.source === 'html_href'
                          ? 'bg-blue-50 text-blue-700 border-blue-200'
                          : 'bg-slate-100 text-slate-700 border-slate-200'
                      }`}
                    >
                      {item.source === 'both'
                        ? 'Plain + HTML'
                        : item.source === 'html_href'
                        ? 'HTML href'
                        : 'Plain text'}
                    </span>

                    {analysis?.features?.host_classification && (
                      <span className="px-2 py-0.5 rounded text-[10px] bg-slate-100 border border-slate-200 font-mono text-slate-600">
                        {analysis.features.host_classification}
                      </span>
                    )}
                  </div>

                  <div className="flex items-center space-x-2.5">
                    {analysis && (
                      <div className="flex items-center space-x-2">
                        <span
                          className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-bold border ${getRiskBadgeClass(
                            analysis.heuristic_risk_category
                          )}`}
                        >
                          {analysis.heuristic_risk_category}
                        </span>
                        <span className="text-xs text-slate-500">
                          Score: <strong className="font-mono text-navy-900">{analysis.heuristic_risk_score}</strong>/100
                        </span>
                      </div>
                    )}

                    <button
                      onClick={() => handleCopy(item.url, `url_${idx}`)}
                      className="inline-flex items-center px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-600 hover:text-navy-900 transition-colors text-xs font-mono"
                      title="Copy URL"
                    >
                      {copiedKey === `url_${idx}` ? (
                        <Check className="w-3.5 h-3.5 text-emerald-600" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </div>

                {/* URL String and Anchor Text */}
                <div className="space-y-1.5">
                  {item.anchor_text && item.anchor_text.trim() !== item.url.trim() && (
                    <div className="text-xs text-slate-600 flex items-center space-x-1.5">
                      <span className="text-slate-400 font-medium text-[11px]">Anchor Text:</span>
                      <span className="font-medium text-navy-900 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
                        &ldquo;{item.anchor_text}&rdquo;
                      </span>
                    </div>
                  )}
                  <div className="font-mono text-xs text-slate-800 break-all bg-surface-subtle p-3 rounded-lg border border-surface-border select-all">
                    {item.url}
                  </div>
                </div>

                {/* Heuristic Findings / Observations */}
                {analysis && (
                  <div>
                    {observations.length > 0 ? (
                      <div className="space-y-2">
                        <button
                          onClick={() => toggleObservations(idx)}
                          className="flex items-center space-x-1.5 text-xs font-medium text-brand-600 hover:text-brand-700"
                        >
                          {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                          <span>
                            {observations.length} Heuristic Observation{observations.length === 1 ? '' : 's'} Detected
                          </span>
                        </button>

                        {isExpanded && (
                          <div className="space-y-2 pt-1 pl-2 border-l-2 border-brand-200">
                            {observations.map((obs, oIdx) => (
                              <div
                                key={oIdx}
                                className="p-3 rounded-lg bg-surface-subtle border border-surface-border space-y-1 text-xs"
                              >
                                <div className="flex items-center justify-between">
                                  <span className="font-semibold text-navy-900">{obs.rule_name}</span>
                                  <span
                                    className={`px-1.5 py-0.2 rounded text-[10px] font-bold border ${getSeverityBadgeClass(
                                      obs.severity
                                    )}`}
                                  >
                                    {obs.severity}
                                  </span>
                                </div>
                                <p className="text-slate-600 text-xs leading-relaxed">
                                  {obs.description}
                                </p>
                                <div className="text-[10px] font-mono text-slate-400">
                                  Rule ID: {obs.rule_id}
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="text-[11px] text-slate-400 italic">
                        No structural risk rules triggered for this URL.
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Heuristic Disclaimer */}
      <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-600 space-y-1">
        <div className="flex items-center space-x-1.5 text-navy-900 font-semibold">
          <Info className="w-4 h-4 text-brand-600 flex-shrink-0" />
          <span>Heuristic Scoring Limitation</span>
        </div>
        <p className="leading-relaxed">
          URL risk scores are rule-based heuristic indicators (0–100) reflecting structural and lexical patterns,
          not calibrated statistical probabilities.
        </p>
      </div>
    </div>
  );
};
