import { useState } from 'react';
import type { FC } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Info,
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
  Lock,
  Globe,
} from 'lucide-react';
import type {
  EmailAuthenticationAnalysis,
  AuthResultStatus,
  OverallAuthStatus,
  HeaderFinding,
} from '../types/forensics';

interface AuthenticationCardProps {
  auth?: EmailAuthenticationAnalysis | null;
}

export const AuthenticationCard: FC<AuthenticationCardProps> = ({ auth }) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [showFindings, setShowFindings] = useState<boolean>(false);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  if (!auth) {
    return (
      <div className="rounded-2xl border border-surface-border bg-white p-6 shadow-card">
        <div className="flex items-center space-x-2 text-slate-500">
          <Lock className="w-5 h-5 text-brand-600" />
          <h3 className="text-base font-semibold text-navy-900 tracking-tight">
            Cryptographic Authentication Evidence (SPF / DKIM / DMARC)
          </h3>
        </div>
        <p className="mt-3 text-xs font-mono text-slate-500">
          Authentication analysis is not available for this email.
        </p>
      </div>
    );
  }

  const getStatusBadge = (status: AuthResultStatus) => {
    switch (status) {
      case 'PASS':
        return 'bg-emerald-50 text-emerald-800 border-emerald-200';
      case 'FAIL':
        return 'bg-red-50 text-red-800 border-red-200';
      case 'SOFTFAIL':
      case 'NEUTRAL':
      case 'NONE':
        return 'bg-amber-50 text-amber-800 border-amber-200';
      case 'TEMPERROR':
      case 'PERMERROR':
      case 'CONFLICTING_EVIDENCE':
        return 'bg-purple-50 text-purple-800 border-purple-200';
      case 'NOT_PRESENT':
      case 'UNKNOWN':
      default:
        return 'bg-slate-100 text-slate-700 border-slate-200';
    }
  };

  const getOverallBadge = (status: OverallAuthStatus) => {
    switch (status) {
      case 'EVALUATED':
        return 'bg-emerald-50 text-emerald-800 border-emerald-200';
      case 'CONFLICTING_EVIDENCE':
        return 'bg-red-50 text-red-800 border-red-200';
      case 'PARTIAL_EVIDENCE':
        return 'bg-amber-50 text-amber-800 border-amber-200';
      case 'NO_EVIDENCE':
      default:
        return 'bg-slate-100 text-slate-700 border-slate-200';
    }
  };

  const allFindings: HeaderFinding[] = [
    ...auth.spf.findings,
    ...auth.dkim.findings,
    ...auth.dmarc.findings,
  ];

  return (
    <div className="rounded-2xl border border-surface-border bg-white p-5 sm:p-6 shadow-card space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-surface-border">
        <div className="flex items-center space-x-2.5 text-navy-900">
          <ShieldCheck className="w-5 h-5 text-brand-600" />
          <h3 className="text-base font-semibold tracking-tight">
            Cryptographic Authentication Evidence (SPF / DKIM / DMARC)
          </h3>
        </div>
        <div className="flex items-center space-x-2">
          <span className="text-xs text-slate-500 font-medium">Overall Status:</span>
          <span
            className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border ${getOverallBadge(
              auth.status
            )}`}
          >
            {auth.status}
          </span>
        </div>
      </div>

      {/* Conflicting Evidence Notice if any */}
      {auth.has_conflicts && (
        <div className="p-4 rounded-xl bg-red-50 border border-red-200 text-red-900 text-xs flex items-start space-x-2.5">
          <ShieldAlert className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold text-red-800">Conflicting Evidence Detected: </span>
            Different headers reported contradictory authentication outcomes across downstream MTAs.
          </div>
        </div>
      )}

      {/* Three Modality Cards: SPF, DKIM, DMARC (Consistent 3-column desktop / stacked mobile) */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* SPF Card */}
        <div className="p-4 rounded-xl bg-surface-subtle border border-surface-border space-y-3.5 flex flex-col justify-between shadow-subtle">
          <div>
            <div className="flex items-center justify-between pb-2.5 border-b border-slate-200">
              <span className="text-xs font-semibold uppercase tracking-wider text-navy-900">
                SPF (Sender Policy)
              </span>
              <span
                className={`px-2.5 py-0.5 rounded-md text-[11px] font-bold border ${getStatusBadge(
                  auth.spf.status
                )}`}
              >
                {auth.spf.status}
              </span>
            </div>

            <div className="space-y-1.5 text-xs mt-3 text-slate-700">
              <div>
                <span className="text-slate-500 font-medium">Evaluated Domain: </span>
                <span className="font-mono text-navy-900 break-all">{auth.spf.domain || '(None)'}</span>
              </div>
              <div>
                <span className="text-slate-500 font-medium">Sender Client IP: </span>
                <span className="font-mono text-navy-900 break-all">{auth.spf.client_ip || '(None)'}</span>
              </div>
            </div>

            <p className="text-xs text-slate-600 mt-2.5 leading-relaxed">
              {auth.spf.explanation}
            </p>
          </div>

          {auth.spf.trust_limitation && (
            <div className="text-[11px] text-amber-800 font-medium pt-2 border-t border-slate-200">
              {auth.spf.trust_limitation}
            </div>
          )}
        </div>

        {/* DKIM Card */}
        <div className="p-4 rounded-xl bg-surface-subtle border border-surface-border space-y-3.5 flex flex-col justify-between shadow-subtle">
          <div>
            <div className="flex items-center justify-between pb-2.5 border-b border-slate-200">
              <span className="text-xs font-semibold uppercase tracking-wider text-navy-900">
                DKIM (Signature)
              </span>
              <span
                className={`px-2.5 py-0.5 rounded-md text-[11px] font-bold border ${getStatusBadge(
                  auth.dkim.status
                )}`}
              >
                {auth.dkim.status}
              </span>
            </div>

            <div className="space-y-1.5 text-xs mt-3 text-slate-700">
              <div>
                <span className="text-slate-500 font-medium">Signing Domain: </span>
                <span className="font-mono text-navy-900 break-all">{auth.dkim.domain || '(None)'}</span>
              </div>
              <div>
                <span className="text-slate-500 font-medium">Selector (s=): </span>
                <span className="font-mono text-navy-900">{auth.dkim.selector || '(None)'}</span>
              </div>
              <div>
                <span className="text-slate-500 font-medium">Raw Signatures: </span>
                <span className="font-mono text-navy-900">{auth.dkim.dkim_signature_count} header(s)</span>
              </div>
            </div>

            <p className="text-xs text-slate-600 mt-2.5 leading-relaxed">
              {auth.dkim.explanation}
            </p>

            {auth.dkim_crypto && auth.dkim_crypto.length > 0 && (
              <div className="mt-3 pt-3 border-t border-slate-200 space-y-2">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-navy-900">
                  {auth.verification_mode === 'LIVE_DNS'
                    ? 'Live Cryptographic Verification (public key fetched from DNS)'
                    : 'Offline Cryptographic Verification'}
                </div>
                {auth.dkim_crypto.map((c, i) => (
                  <div key={i} className="text-xs text-slate-700 space-y-0.5">
                    <div>
                      <span
                        className={`px-2 py-0.5 rounded-md text-[11px] font-bold border ${
                          c.status === 'VERIFIED'
                            ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                            : c.status === 'BODY_MODIFIED' || c.status === 'SIGNATURE_INVALID'
                              ? 'bg-red-50 text-red-800 border-red-200'
                              : 'bg-slate-100 text-slate-700 border-slate-200'
                        }`}
                      >
                        {c.status}
                      </span>
                      <span className="ml-2 font-mono break-all">{c.domain || ''}</span>
                    </div>
                    <div>
                      Body hash (bh=):{' '}
                      <span className="font-mono">
                        {c.body_hash_valid === true ? 'match' : c.body_hash_valid === false ? 'MISMATCH' : 'n/a'}
                      </span>
                      {' | '}Signature (b=):{' '}
                      <span className="font-mono">
                        {c.signature_valid === true ? 'valid' : c.signature_valid === false ? 'INVALID' : 'not checked (no public key available)'}
                      </span>
                    </div>
                    {c.notes && c.notes.length > 0 && (
                      <div className="text-[11px] text-slate-500">{c.notes.join(' ')}</div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {auth.dkim.trust_limitation && (
            <div className="text-[11px] text-amber-800 font-medium pt-2 border-t border-slate-200">
              {auth.dkim.trust_limitation}
            </div>
          )}
        </div>

        {/* DMARC Card */}
        <div className="p-4 rounded-xl bg-surface-subtle border border-surface-border space-y-3.5 flex flex-col justify-between shadow-subtle">
          <div>
            <div className="flex items-center justify-between pb-2.5 border-b border-slate-200">
              <span className="text-xs font-semibold uppercase tracking-wider text-navy-900">
                DMARC (Policy Alignment)
              </span>
              <span
                className={`px-2.5 py-0.5 rounded-md text-[11px] font-bold border ${getStatusBadge(
                  auth.dmarc.status
                )}`}
              >
                {auth.dmarc.status}
              </span>
            </div>

            <div className="space-y-1.5 text-xs mt-3 text-slate-700">
              <div>
                <span className="text-slate-500 font-medium">From Domain: </span>
                <span className="font-mono text-navy-900 break-all">{auth.dmarc.header_from || '(None)'}</span>
              </div>
              <div>
                <span className="text-slate-500 font-medium">Published Policy: </span>
                <span className="font-mono text-navy-900">
                  {auth.dmarc.policy ? `p=${auth.dmarc.policy}` : '(None)'}
                </span>
              </div>
              <div>
                <span className="text-slate-500 font-medium">Alignment Verified: </span>
                <span className={`font-semibold ${auth.dmarc.alignment_verified ? 'text-emerald-700' : 'text-slate-600'}`}>
                  {auth.dmarc.alignment_verified ? 'Yes (Explicit)' : 'No'}
                </span>
              </div>
            </div>

            <p className="text-xs text-slate-600 mt-2.5 leading-relaxed">
              {auth.dmarc.explanation}
            </p>
          </div>

          {auth.dmarc.trust_limitation && (
            <div className="text-[11px] text-amber-800 font-medium pt-2 border-t border-slate-200">
              {auth.dmarc.trust_limitation}
            </div>
          )}
        </div>
      </div>

      {/* Downstream Authserv IDs */}
      {auth.authserv_ids.length > 0 && (
        <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-600">
          <span className="font-semibold text-navy-900">Reporting Authserv MTA Identifiers: </span>
          <span className="font-mono text-slate-800">{auth.authserv_ids.join(', ')}</span>
        </div>
      )}

      {/* Collapsible Individual Header Findings */}
      {allFindings.length > 0 && (
        <div className="border border-surface-border rounded-xl overflow-hidden bg-white shadow-subtle">
          <button
            onClick={() => setShowFindings(!showFindings)}
            className="w-full px-4 py-3 flex items-center justify-between text-xs font-medium text-navy-900 bg-surface-subtle hover:bg-surface-hover transition-colors"
          >
            <span>
              Detailed Header Authentication Clauses ({allFindings.length} Finding{allFindings.length === 1 ? '' : 's'})
            </span>
            <div className="p-1 rounded bg-white border border-surface-border text-slate-500">
              {showFindings ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            </div>
          </button>

          {showFindings && (
            <div className="p-4 border-t border-surface-border space-y-2.5 text-xs">
              {allFindings.map((finding, idx) => (
                <div
                  key={idx}
                  className="p-3.5 rounded-lg bg-surface-subtle border border-surface-border space-y-2"
                >
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <div className="flex items-center space-x-2">
                      <span className="px-2 py-0.5 rounded bg-white border border-slate-200 text-navy-900 font-bold uppercase text-[10px] font-mono">
                        {finding.method}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded font-bold text-[10px] border ${getStatusBadge(
                          finding.result
                        )}`}
                      >
                        {finding.result} (raw: {finding.raw_result})
                      </span>
                    </div>
                    <span className="text-[11px] text-slate-500 font-mono">
                      Header: {finding.source_header} #{finding.header_index}
                    </span>
                  </div>

                  {finding.raw_snippet && (
                    <div className="text-[11px] text-slate-800 font-mono break-all bg-white p-2.5 rounded border border-slate-200 flex justify-between items-start gap-2">
                      <span className="leading-relaxed">{finding.raw_snippet}</span>
                      <button
                        onClick={() => handleCopy(finding.raw_snippet!, `snippet_${idx}`)}
                        className="p-1 hover:bg-slate-100 rounded text-slate-500 hover:text-navy-900 flex-shrink-0"
                        title="Copy snippet"
                      >
                        {copiedKey === `snippet_${idx}` ? (
                          <Check className="w-3.5 h-3.5 text-emerald-600" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                  )}

                  {finding.reason && (
                    <div className="text-[11px] text-amber-800 font-sans">
                      Reason: {finding.reason}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Live DNS Verification (online SPF / DKIM / DMARC) */}
      {auth.live_verification && (
        <div className="p-4 rounded-xl bg-surface-subtle border border-surface-border space-y-3 shadow-subtle">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-1.5 text-navy-900 font-semibold text-xs uppercase tracking-wider">
              <Globe className="w-4 h-4 text-brand-600 flex-shrink-0" />
              <span>Live DNS Verification</span>
            </div>
            <span
              className={`px-2.5 py-0.5 rounded-md text-[11px] font-bold border ${
                auth.live_verification.available
                  ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                  : 'bg-amber-50 text-amber-800 border-amber-200'
              }`}
            >
              {auth.live_verification.available ? 'ONLINE' : 'UNAVAILABLE'}
            </span>
          </div>

          {!auth.live_verification.available && (
            <p className="text-xs text-amber-800">
              {auth.live_verification.error || 'Live DNS verification could not be performed.'} Statuses above fall back
              to header claims and pinned keys.
            </p>
          )}

          {auth.live_verification.available &&
            (
              [
                ['SPF', auth.live_verification.spf?.result, auth.live_verification.spf?.explanation, auth.live_verification.spf?.record],
                ['DKIM', auth.live_verification.dkim?.result, auth.live_verification.dkim?.explanation, null],
                ['DMARC', auth.live_verification.dmarc?.result, auth.live_verification.dmarc?.explanation, auth.live_verification.dmarc?.record],
              ] as [string, string | undefined, string | undefined, string | null | undefined][]
            ).map(([label, result, explanation, record]) => {
              const r = (result || 'none').toLowerCase();
              const badge =
                r === 'pass'
                  ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                  : r === 'fail' || r === 'permerror'
                    ? 'bg-red-50 text-red-800 border-red-200'
                    : r === 'temperror'
                      ? 'bg-purple-50 text-purple-800 border-purple-200'
                      : 'bg-amber-50 text-amber-800 border-amber-200';
              return (
                <div key={label} className="text-xs text-slate-700 space-y-1 pb-2 border-b border-slate-200 last:border-b-0">
                  <div className="flex items-center space-x-2">
                    <span className="font-semibold text-navy-900 w-12">{label}</span>
                    <span className={`px-2 py-0.5 rounded-md text-[11px] font-bold border ${badge}`}>{r.toUpperCase()}</span>
                  </div>
                  {explanation && <div className="leading-relaxed">{explanation}</div>}
                  {record && (
                    <div className="font-mono text-[11px] text-slate-500 break-all">DNS record: {record}</div>
                  )}
                </div>
              );
            })}

          {auth.live_verification.available && auth.live_verification.spf?.client_ip && (
            <div className="text-[11px] text-slate-500">
              SPF evaluated for client IP{' '}
              <span className="font-mono">{auth.live_verification.spf.client_ip}</span>
              {auth.live_verification.spf.client_ip_source
                ? ` (from ${auth.live_verification.spf.client_ip_source})`
                : ''}
              {typeof auth.live_verification.duration_ms === 'number'
                ? ` · ${auth.live_verification.duration_ms} ms`
                : ''}
            </div>
          )}

          {auth.live_verification.dns_errors && auth.live_verification.dns_errors.length > 0 && (
            <ul className="text-[11px] text-purple-800 list-disc pl-4 space-y-0.5">
              {auth.live_verification.dns_errors.map((e, i) => (
                <li key={i}>{e}</li>
              ))}
            </ul>
          )}

          {auth.live_verification.caveats && auth.live_verification.caveats.length > 0 && (
            <ul className="text-[11px] text-amber-800 list-disc pl-4 space-y-0.5">
              {auth.live_verification.caveats.map((c, i) => (
                <li key={i}>{c}</li>
              ))}
            </ul>
          )}
        </div>
      )}

      {/* Trust Limitation Disclaimer */}
      <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-600 space-y-1">
        <div className="flex items-center space-x-1.5 text-navy-900 font-semibold">
          <Info className="w-4 h-4 text-brand-600 flex-shrink-0" />
          <span>Authentication Trust Boundary Limitation</span>
        </div>
        <p className="leading-relaxed">
          {auth.disclaimer || 'Offline email headers contain reported authentication evidence and do not constitute independent cryptographic verification.'}
        </p>
      </div>
    </div>
  );
};
