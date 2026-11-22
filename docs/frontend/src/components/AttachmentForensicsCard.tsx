import { useState } from 'react';
import type { FC } from 'react';
import { Paperclip, Copy, Check, ShieldCheck, FileWarning, Hash } from 'lucide-react';
import type { AttachmentInfo } from '../types/forensics';

interface AttachmentForensicsCardProps {
  attachments: AttachmentInfo[];
}

export const AttachmentForensicsCard: FC<AttachmentForensicsCardProps> = ({ attachments }) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
  };

  const isSuspiciousExtension = (filename: string): boolean => {
    const ext = filename.split('.').pop()?.toLowerCase();
    const dangerous = ['exe', 'scr', 'vbs', 'bat', 'cmd', 'ps1', 'hta', 'js', 'iso', 'img', 'dll', 'com'];
    return ext ? dangerous.includes(ext) : false;
  };

  return (
    <div className="rounded-2xl border border-surface-border bg-white p-5 sm:p-6 shadow-card space-y-6">
      <div className="flex items-center justify-between pb-4 border-b border-surface-border">
        <div className="flex items-center space-x-2.5 text-navy-900">
          <Paperclip className="w-5 h-5 text-emerald-600" />
          <h3 className="text-base font-semibold tracking-tight">
            Attachment Artifacts &amp; Cryptographic Hashes ({attachments.length})
          </h3>
        </div>
      </div>

      <div className="p-4 rounded-xl bg-emerald-50/60 border border-emerald-200 text-xs text-emerald-900 space-y-1">
        <div className="flex items-center space-x-1.5 font-semibold text-emerald-900">
          <ShieldCheck className="w-4 h-4 text-emerald-600 flex-shrink-0" />
          <span>Execution Isolation Guarantee</span>
        </div>
        <p className="leading-relaxed text-emerald-800">
          All attachments are parsed strictly in isolated memory to calculate their file size and SHA-256 hash.
          <strong className="text-emerald-950 font-semibold"> Attachments are never executed, written to executable paths, or rendered as active payloads.</strong>
        </p>
      </div>

      {attachments.length === 0 ? (
        <div className="text-center py-8 text-slate-500 font-mono text-xs">
          No attachments were detected in this email.
        </div>
      ) : (
        <div className="space-y-3.5">
          {attachments.map((att, idx) => {
            const suspicious = isSuspiciousExtension(att.filename);
            return (
              <div
                key={idx}
                className="p-4 sm:p-5 rounded-xl bg-white border border-surface-border shadow-subtle hover:border-slate-300 transition-colors"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-surface-border">
                  <div className="flex items-center space-x-2.5">
                    {suspicious ? (
                      <FileWarning className="w-5 h-5 text-amber-600 flex-shrink-0" />
                    ) : (
                      <Paperclip className="w-5 h-5 text-emerald-600 flex-shrink-0" />
                    )}
                    <div>
                      <span className="font-mono font-semibold text-navy-900 text-sm break-all">
                        {att.filename}
                      </span>
                      {suspicious && (
                        <span className="ml-2 px-2 py-0.5 rounded bg-red-50 text-red-700 border border-red-200 text-[10px] font-mono uppercase font-bold">
                          Suspicious Executable Extension
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center space-x-3 text-xs text-slate-600">
                    <span className="px-2.5 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-700 font-mono text-[11px]">
                      {att.content_type}
                    </span>
                    <span className="font-semibold text-navy-900 font-mono">{formatBytes(att.size_bytes)}</span>
                  </div>
                </div>

                <div className="pt-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center space-x-2 text-xs font-mono text-slate-600 overflow-hidden">
                    <Hash className="w-3.5 h-3.5 text-slate-400 flex-shrink-0" />
                    <span className="text-slate-500 flex-shrink-0">SHA-256:</span>
                    <span className="text-navy-900 font-semibold truncate select-all">
                      {att.sha256 || '(Unavailable)'}
                    </span>
                  </div>

                  {att.sha256 && (
                    <button
                      onClick={() => handleCopy(att.sha256!, `hash_${idx}`)}
                      className="self-end sm:self-auto inline-flex items-center px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 hover:text-navy-900 text-xs font-mono transition-colors"
                      title="Copy SHA-256 hash"
                    >
                      {copiedKey === `hash_${idx}` ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-600 mr-1.5" />
                          <span>Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5 mr-1.5" />
                          <span>Copy Hash</span>
                        </>
                      )}
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
