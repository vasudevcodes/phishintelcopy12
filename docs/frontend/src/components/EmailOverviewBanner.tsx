import type { FC } from 'react';
import {
  FileCheck2,
  RefreshCw,
  Download,
  Route,
  Globe,
  Paperclip,
  Network,
  AlertTriangle,
  Clock,
  HardDrive,
  Cpu,
  Mail,
  User,
  Calendar,
  AlertCircle,
  CheckCircle2,
  HelpCircle,
} from 'lucide-react';
import type { EmailAnalysisResponse } from '../types/forensics';
import { downloadForensicReport } from '../utils/reportGenerator';

interface EmailOverviewBannerProps {
  data: EmailAnalysisResponse;
  onReset: () => void;
}

export const EmailOverviewBanner: FC<EmailOverviewBannerProps> = ({ data, onReset }) => {
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
  };

  const formattedDate = new Date(data.parsed_at).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });

  const fusion = data.evidence_fusion;
  const model = data.model_inference;

  const getCategoryBadge = (category: string) => {
    switch (category) {
      case 'HIGH_RISK_INDICATORS_PRESENT':
        return {
          label: 'High Risk Indicators Present',
          badgeClass: 'bg-red-50 text-red-700 border-red-200',
          icon: <AlertCircle className="w-3.5 h-3.5 text-red-600 mr-1.5" />,
        };
      case 'REVIEW_RECOMMENDED':
        return {
          label: 'Review Recommended',
          badgeClass: 'bg-amber-50 text-amber-800 border-amber-200',
          icon: <AlertTriangle className="w-3.5 h-3.5 text-amber-600 mr-1.5" />,
        };
      case 'LOW_RISK_INDICATORS':
        return {
          label: 'Low Risk Indicators Observed',
          badgeClass: 'bg-emerald-50 text-emerald-800 border-emerald-200',
          icon: <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 mr-1.5" />,
        };
      case 'INSUFFICIENT_EVIDENCE':
      default:
        return {
          label: 'Insufficient Evidence',
          badgeClass: 'bg-slate-100 text-slate-700 border-slate-200',
          icon: <HelpCircle className="w-3.5 h-3.5 text-slate-500 mr-1.5" />,
        };
    }
  };

  const catBadge = fusion ? getCategoryBadge(fusion.overall_category) : null;

  return (
    <div className="w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mb-6">
      <div className="rounded-2xl border border-surface-border bg-white p-5 sm:p-6 shadow-card space-y-5">
        {/* Top File and Actions Bar */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-5 border-b border-surface-border">
          <div className="flex items-start space-x-3.5">
            <div className="w-11 h-11 rounded-xl bg-brand-50 border border-brand-200 flex items-center justify-center text-brand-600 flex-shrink-0 mt-0.5">
              <FileCheck2 className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2.5 flex-wrap gap-y-1.5">
                <h2 className="text-base sm:text-lg font-bold text-navy-900 font-mono break-all">
                  {data.filename}
                </h2>

                {/* Parsing Status Badge */}
                <span
                  className={`inline-flex items-center text-xs px-2.5 py-0.5 rounded-full font-medium border ${data.parsing_status === 'success'
                    ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                    : 'bg-amber-50 text-amber-700 border-amber-200'
                    }`}
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 mr-1.5" />
                  {data.parsing_status === 'success' ? 'RFC 5322 Parsed' : 'Partial Parse'}
                </span>

                {/* Evidence Fusion Category & Numerical Score Badge */}
                {catBadge && (
                  <span
                    className={`inline-flex items-center text-xs px-3 py-0.5 rounded-full font-semibold border ${catBadge.badgeClass}`}
                  >
                    {catBadge.icon}
                    {catBadge.label}
                    {fusion?.overall_risk_score !== undefined && (
                      <span className="ml-1.5 font-mono font-bold bg-white/70 px-1.5 py-0.2 rounded border border-current/20">
                        {fusion.overall_risk_score}/100
                      </span>
                    )}
                  </span>
                )}

                {/* Evidence Completeness Badge */}
                {fusion?.evidence_completeness && (
                  <span
                    className={`inline-flex items-center text-xs px-2.5 py-0.5 rounded-full font-medium border ${fusion.evidence_completeness === 'FULL_COVERAGE'
                      ? 'bg-blue-50 text-blue-700 border-blue-200'
                      : fusion.evidence_completeness === 'PARTIAL_COVERAGE'
                        ? 'bg-amber-50 text-amber-700 border-amber-200'
                        : 'bg-slate-100 text-slate-700 border-slate-200'
                      }`}
                    title={fusion.evidence_completeness_detail || 'Evidence coverage assessment'}
                  >
                    <span
                      className={`w-1.5 h-1.5 rounded-full mr-1.5 ${fusion.evidence_completeness === 'FULL_COVERAGE'
                        ? 'bg-blue-500'
                        : fusion.evidence_completeness === 'PARTIAL_COVERAGE'
                          ? 'bg-amber-500'
                          : 'bg-slate-400'
                        }`}
                    />
                    {fusion.evidence_completeness === 'FULL_COVERAGE'
                      ? 'Full Coverage'
                      : fusion.evidence_completeness === 'PARTIAL_COVERAGE'
                        ? 'Partial Coverage'
                        : 'Minimal Evidence'}
                  </span>
                )}
              </div>

              <div className="flex items-center space-x-4 text-xs text-slate-500 mt-1.5 flex-wrap gap-y-1">
                <span className="flex items-center space-x-1">
                  <HardDrive className="w-3.5 h-3.5 text-slate-400" />
                  <span>{formatBytes(data.file_size_bytes)}</span>
                </span>
                <span className="text-slate-300">•</span>
                <span className="flex items-center space-x-1">
                  <Clock className="w-3.5 h-3.5 text-slate-400" />
                  <span>Parsed at {formattedDate} UTC</span>
                </span>
              </div>
            </div>
          </div>

          {/* Risk gauge */}
          {fusion && fusion.overall_risk_score !== undefined && (
            <div
              className="flex items-center gap-3 lg:ml-auto lg:mr-4 self-start lg:self-center"
              role="img"
              aria-label={`Overall risk score ${fusion.overall_risk_score} out of 100`}
            >
              <svg viewBox="0 0 44 44" className="w-14 h-14 -rotate-90">
                <circle cx="22" cy="22" r="18" fill="none" strokeWidth="4" className="stroke-slate-100" />
                <circle
                  cx="22"
                  cy="22"
                  r="18"
                  fill="none"
                  strokeWidth="4"
                  strokeLinecap="round"
                  strokeDasharray={`${(Math.min(Math.max(fusion.overall_risk_score, 0), 100) / 100) * 113.1} 113.1`}
                  className={
                    fusion.overall_category === 'HIGH_RISK_INDICATORS_PRESENT'
                      ? 'stroke-red-500'
                      : fusion.overall_category === 'REVIEW_RECOMMENDED'
                        ? 'stroke-amber-500'
                        : fusion.overall_category === 'LOW_RISK_INDICATORS'
                          ? 'stroke-emerald-500'
                          : 'stroke-slate-400'
                  }
                />
              </svg>
              <div className="leading-tight">
                <div className="text-2xl font-semibold font-mono text-navy-900">
                  {fusion.overall_risk_score}
                  <span className="text-sm text-slate-400">/100</span>
                </div>
                <div className="text-[11px] text-slate-500">Fused risk score</div>
              </div>
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex items-center space-x-2.5 self-start lg:self-center flex-wrap gap-y-2">
            <button
              id="download-report-btn"
              onClick={() => downloadForensicReport(data)}
              className="inline-flex items-center px-4 py-2 rounded-lg bg-brand-500 hover:bg-brand-600 text-white text-xs font-semibold transition-colors shadow-subtle hover:shadow"
              title="Download standalone forensic HTML report"
            >
              <Download className="w-4 h-4 mr-2" />
              Download Forensic Report
            </button>
            <button
              id="analyze-another-btn"
              onClick={onReset}
              className="inline-flex items-center px-3.5 py-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-300 text-xs font-medium text-slate-700 transition-colors shadow-subtle"
            >
              <RefreshCw className="w-3.5 h-3.5 mr-2 text-slate-500" />
              New Investigation
            </button>
          </div>
        </div>

        {/* Email Metadata Summary Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 bg-surface-subtle p-3.5 rounded-xl border border-surface-border text-xs">
          <div className="space-y-1">
            <div className="flex items-center space-x-1.5 text-slate-500 font-medium">
              <Mail className="w-3.5 h-3.5 text-slate-400" />
              <span>Subject</span>
            </div>
            <div className="font-semibold text-navy-900 truncate" title={data.headers.subject || '(No Subject)'}>
              {data.headers.subject || '(No Subject Provided)'}
            </div>
          </div>

          <div className="space-y-1">
            <div className="flex items-center space-x-1.5 text-slate-500 font-medium">
              <User className="w-3.5 h-3.5 text-slate-400" />
              <span>From (Sender)</span>
            </div>
            <div className="font-mono text-navy-900 truncate text-[11px]" title={data.headers.from_header || '(Not specified)'}>
              {data.headers.from_header || '(Not Specified)'}
            </div>
          </div>

          <div className="space-y-1">
            <div className="flex items-center space-x-1.5 text-slate-500 font-medium">
              <User className="w-3.5 h-3.5 text-slate-400" />
              <span>To (Recipient)</span>
            </div>
            <div className="font-mono text-navy-900 truncate text-[11px]" title={data.headers.to_headers.join(', ') || '(Not specified)'}>
              {data.headers.to_headers.length > 0 ? data.headers.to_headers.join(', ') : '(Not Specified)'}
            </div>
          </div>

          <div className="space-y-1">
            <div className="flex items-center space-x-1.5 text-slate-500 font-medium">
              <Calendar className="w-3.5 h-3.5 text-slate-400" />
              <span>Message Date</span>
            </div>
            <div className="font-mono text-navy-900 truncate text-[11px]" title={data.headers.date || '(Not specified)'}>
              {data.headers.date || '(Not Specified)'}
            </div>
          </div>
        </div>

        {/* DistilBERT Model Integration Banner in Overview */}
        {model && (
          <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 text-xs">
            <div className="flex items-center space-x-2 text-slate-700">
              <Cpu className="w-4 h-4 text-brand-600 flex-shrink-0" />
              <span className="font-semibold text-navy-900">DistilBERT Model Inference:</span>
              {model.status === 'EVALUATED' ? (
                <span className="font-semibold text-emerald-700 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded text-[11px]">
                  EVALUATED
                </span>
              ) : model.status === 'ERROR' ? (
                <span className="font-semibold text-red-700 bg-red-50 border border-red-200 px-2 py-0.5 rounded text-[11px]">
                  ERROR (Execution Failed)
                </span>
              ) : (
                <span className="font-semibold text-amber-700 bg-amber-50 border border-amber-200 px-2 py-0.5 rounded text-[11px]">
                  UNAVAILABLE
                </span>
              )}
            </div>

            {model.status === 'EVALUATED' ? (
              <div className="flex items-center space-x-4 text-slate-600 flex-wrap gap-y-1">
                <span>
                  Classification Output:{' '}
                  <strong
                    className={`font-semibold ${model.predicted_label === 1 ? 'text-red-700' : 'text-blue-700'
                      }`}
                  >
                    {model.predicted_label === 1 ? '1 (Phishing Indicator)' : '0 (Benign Pattern)'}
                  </strong>
                </span>
                <span className="text-slate-300">•</span>
                <span>
                  Model Score:{' '}
                  <strong className="font-mono text-navy-900 font-semibold">
                    {model.uncalibrated_score !== null && model.uncalibrated_score !== undefined
                      ? model.uncalibrated_score.toFixed(4)
                      : 'N/A'}
                  </strong>
                  <span className="text-[10px] text-slate-500 ml-1">(uncalibrated)</span>
                </span>
              </div>
            ) : (
              <div className="text-slate-500 italic text-[11px]">
                {model.error_message || 'Model inference is not available; never defaulting to benign.'}
              </div>
            )}
          </div>
        )}

        {/* Forensic metrics bar */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
          <div className="bg-white border border-surface-border rounded-xl p-3.5 flex items-center space-x-3 shadow-subtle">
            <div className="w-10 h-10 rounded-lg bg-teal-50 border border-teal-100 flex items-center justify-center text-teal-700 flex-shrink-0">
              <Route className="w-5 h-5" />
            </div>
            <div>
              <div className="text-[11px] text-slate-500 font-medium uppercase tracking-wider">Transit Hops</div>
              <div className="text-xl font-bold font-mono text-navy-900">
                {data.headers.received_headers.length}
              </div>
            </div>
          </div>

          <div className="bg-white border border-surface-border rounded-xl p-3.5 flex items-center space-x-3 shadow-subtle">
            <div className="w-10 h-10 rounded-lg bg-purple-50 border border-purple-100 flex items-center justify-center text-purple-700 flex-shrink-0">
              <Network className="w-5 h-5" />
            </div>
            <div>
              <div className="text-[11px] text-slate-500 font-medium uppercase tracking-wider">Candidate IPs</div>
              <div className="text-xl font-bold font-mono text-navy-900">
                {data.ip_candidates.length}
              </div>
            </div>
          </div>

          <div className="bg-white border border-surface-border rounded-xl p-3.5 flex items-center space-x-3 shadow-subtle">
            <div className="w-10 h-10 rounded-lg bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-700 flex-shrink-0">
              <Globe className="w-5 h-5" />
            </div>
            <div>
              <div className="text-[11px] text-slate-500 font-medium uppercase tracking-wider">Extracted URLs</div>
              <div className="text-xl font-bold font-mono text-navy-900">
                {data.urls.length}
              </div>
            </div>
          </div>

          <div className="bg-white border border-surface-border rounded-xl p-3.5 flex items-center space-x-3 shadow-subtle">
            <div className="w-10 h-10 rounded-lg bg-emerald-50 border border-emerald-100 flex items-center justify-center text-emerald-700 flex-shrink-0">
              <Paperclip className="w-5 h-5" />
            </div>
            <div>
              <div className="text-[11px] text-slate-500 font-medium uppercase tracking-wider">Attachments</div>
              <div className="text-xl font-bold font-mono text-navy-900">
                {data.attachments.length}
              </div>
            </div>
          </div>
        </div>

        {/* Warnings notice if any */}
        {data.warnings && data.warnings.length > 0 && (
          <div className="p-3.5 rounded-xl bg-amber-50 border border-amber-200 text-amber-900 text-xs flex items-start space-x-2.5">
            <AlertTriangle className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
            <div>
              <span className="font-semibold text-amber-800">Forensic parser notices ({data.warnings.length}):</span>
              <ul className="list-disc list-inside mt-1 space-y-0.5 text-amber-700 font-mono">
                {data.warnings.map((w, idx) => (
                  <li key={idx}>{w}</li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
