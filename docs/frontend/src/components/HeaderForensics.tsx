import { useState } from 'react';
import type { FC } from 'react';
import { Copy, Check, ChevronDown, ChevronUp, Mail, ShieldCheck, Route } from 'lucide-react';
import type { EmailHeaderInfo } from '../types/forensics';

interface HeaderForensicsProps {
  headers: EmailHeaderInfo;
}

export const HeaderForensics: FC<HeaderForensicsProps> = ({ headers }) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isReceivedOpen, setIsReceivedOpen] = useState(false);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const primaryHeaderFields = [
    { label: 'Subject', value: headers.subject || '(No Subject Provided)', mono: false },
    { label: 'From', value: headers.from_header || '(Not Specified)', mono: true },
    {
      label: 'To',
      value: headers.to_headers.length > 0 ? headers.to_headers.join(', ') : '(Not Specified)',
      mono: true,
    },
    ...(headers.cc_headers.length > 0
      ? [{ label: 'Cc', value: headers.cc_headers.join(', '), mono: true }]
      : []),
    ...(headers.bcc_headers.length > 0
      ? [{ label: 'Bcc', value: headers.bcc_headers.join(', '), mono: true }]
      : []),
    { label: 'Date', value: headers.date || '(Not Specified)', mono: true },
    { label: 'Message-ID', value: headers.message_id || '(None)', mono: true },
    { label: 'Return-Path', value: headers.return_path || '(None)', mono: true },
    { label: 'Reply-To', value: headers.reply_to || '(None)', mono: true },
    { label: 'Content-Type', value: headers.content_type || '(None)', mono: true },
    { label: 'MIME-Version', value: headers.mime_version || '(None)', mono: true },
  ];

  return (
    <div className="space-y-6">
      {/* Primary Key-Value Headers */}
      <div className="rounded-2xl border border-surface-border bg-white p-5 sm:p-6 shadow-card">
        <div className="flex items-center space-x-2.5 pb-4 mb-5 border-b border-surface-border text-navy-900">
          <Mail className="w-5 h-5 text-brand-600" />
          <h3 className="text-base font-semibold tracking-tight">RFC 5322 Standard Headers</h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
          {primaryHeaderFields.map((field) => (
            <div
              key={field.label}
              className="group p-3.5 rounded-xl bg-surface-subtle border border-surface-border hover:border-slate-300 transition-colors shadow-subtle"
            >
              <div className="flex items-center justify-between text-xs text-slate-500 mb-1">
                <span className="font-semibold uppercase tracking-wider text-[11px] text-slate-600">
                  {field.label}
                </span>
                {field.value && field.value !== '(None)' && field.value !== '(Not Specified)' && (
                  <button
                    onClick={() => handleCopy(field.value, field.label)}
                    className="opacity-0 group-hover:opacity-100 p-1 rounded hover:bg-slate-200 text-slate-500 hover:text-navy-900 transition-all"
                    title={`Copy ${field.label}`}
                  >
                    {copiedKey === field.label ? (
                      <Check className="w-3.5 h-3.5 text-emerald-600" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                  </button>
                )}
              </div>
              <div
                className={`break-all ${
                  field.mono ? 'font-mono text-navy-900 text-xs' : 'font-medium text-navy-900 text-sm'
                }`}
              >
                {field.value}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Authentication & Security Headers Card */}
      <div className="rounded-2xl border border-surface-border bg-white p-5 sm:p-6 shadow-card space-y-5">
        <div className="flex items-center space-x-2.5 pb-4 border-b border-surface-border text-navy-900">
          <ShieldCheck className="w-5 h-5 text-brand-600" />
          <h3 className="text-base font-semibold tracking-tight">
            Authentication &amp; Security Headers
          </h3>
        </div>

        <div className="space-y-4">
          <div>
            <div className="text-xs text-slate-500 uppercase tracking-wider mb-2 font-semibold">
              Authentication-Results Headers ({headers.authentication_results.length})
            </div>
            {headers.authentication_results.length === 0 ? (
              <p className="text-xs text-slate-400 font-mono italic">No Authentication-Results headers present.</p>
            ) : (
              <div className="space-y-2">
                {headers.authentication_results.map((res, i) => (
                  <div
                    key={i}
                    className="p-3.5 rounded-xl bg-surface-subtle border border-surface-border font-mono text-xs text-navy-900 break-all flex justify-between items-start gap-2 shadow-subtle"
                  >
                    <span className="leading-relaxed">{res}</span>
                    <button
                      onClick={() => handleCopy(res, `auth_${i}`)}
                      className="p-1 hover:bg-slate-200 rounded text-slate-500 hover:text-navy-900 flex-shrink-0"
                      title="Copy header"
                    >
                      {copiedKey === `auth_${i}` ? (
                        <Check className="w-3.5 h-3.5 text-emerald-600" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div>
            <div className="text-xs text-slate-500 uppercase tracking-wider mb-2 font-semibold">
              Received-SPF Headers ({headers.received_spf.length})
            </div>
            {headers.received_spf.length === 0 ? (
              <p className="text-xs text-slate-400 font-mono italic">No Received-SPF headers present.</p>
            ) : (
              <div className="space-y-2">
                {headers.received_spf.map((spf, i) => (
                  <div
                    key={i}
                    className="p-3.5 rounded-xl bg-surface-subtle border border-surface-border font-mono text-xs text-emerald-900 break-all flex justify-between items-start gap-2 shadow-subtle"
                  >
                    <span className="leading-relaxed">{spf}</span>
                    <button
                      onClick={() => handleCopy(spf, `spf_${i}`)}
                      className="p-1 hover:bg-slate-200 rounded text-slate-500 hover:text-navy-900 flex-shrink-0"
                      title="Copy header"
                    >
                      {copiedKey === `spf_${i}` ? (
                        <Check className="w-3.5 h-3.5 text-emerald-600" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Raw Received Headers in Extracted Order */}
      <div className="rounded-2xl border border-surface-border bg-white p-5 sm:p-6 shadow-card">
        <button
          onClick={() => setIsReceivedOpen(!isReceivedOpen)}
          className="w-full flex items-center justify-between text-left"
        >
          <div className="flex items-center space-x-2.5 text-navy-900">
            <Route className="w-5 h-5 text-purple-600" />
            <h3 className="text-base font-semibold tracking-tight">
              Complete Received Transit Headers ({headers.received_headers.length} Hops Preserved)
            </h3>
          </div>
          <div className="p-1.5 rounded-lg bg-surface-subtle border border-surface-border text-slate-600 hover:bg-slate-200 transition-colors">
            {isReceivedOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </div>
        </button>

        {isReceivedOpen && (
          <div className="mt-4 space-y-3 pt-4 border-t border-surface-border">
            <p className="text-xs text-slate-500 italic">
              Headers are preserved in exact top-to-bottom order as extracted from the email. The first header (Hop #0) is generally the newest hop, while the last header is generally the oldest hop closest to origin.
            </p>
            {headers.received_headers.map((recv, idx) => (
              <div
                key={idx}
                className="p-3.5 rounded-xl bg-surface-subtle border border-surface-border font-mono text-xs text-navy-900 break-all flex items-start justify-between gap-3 shadow-subtle"
              >
                <div className="flex items-start gap-2.5">
                  <span className="px-2 py-0.5 rounded bg-purple-50 text-purple-700 font-bold border border-purple-200 flex-shrink-0 text-[11px]">
                    Hop #{idx} {idx === 0 ? '(Newest)' : idx === headers.received_headers.length - 1 ? '(Oldest)' : ''}
                  </span>
                  <span className="leading-relaxed">{recv}</span>
                </div>
                <button
                  onClick={() => handleCopy(recv, `recv_${idx}`)}
                  className="p-1 hover:bg-slate-200 rounded text-slate-500 hover:text-navy-900 flex-shrink-0"
                  title="Copy hop"
                >
                  {copiedKey === `recv_${idx}` ? (
                    <Check className="w-3.5 h-3.5 text-emerald-600" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
