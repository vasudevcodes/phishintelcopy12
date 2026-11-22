import { useState } from 'react';
import type { FC } from 'react';
import { AlignLeft, Code2, Copy, Check, EyeOff } from 'lucide-react';
import type { EmailBodyInfo } from '../types/forensics';

interface BodyForensicsCardProps {
  body: EmailBodyInfo;
}

export const BodyForensicsCard: FC<BodyForensicsCardProps> = ({ body }) => {
  const [activeTab, setActiveTab] = useState<'plain' | 'html'>(
    body.has_plain_text ? 'plain' : 'html'
  );
  const [copied, setCopied] = useState(false);

  const currentContent = activeTab === 'plain' ? body.plain_text : body.html_extracted_text;

  const handleCopy = () => {
    if (currentContent) {
      navigator.clipboard.writeText(currentContent);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="rounded-2xl border border-surface-border bg-white p-5 sm:p-6 shadow-card space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-surface-border gap-3">
        <div className="flex items-center space-x-2.5 text-navy-900">
          <AlignLeft className="w-5 h-5 text-brand-600" />
          <h3 className="text-base font-semibold tracking-tight">
            Body Content Forensics
          </h3>
        </div>

        {/* Tab switcher */}
        <div className="flex items-center space-x-1.5 bg-surface-subtle p-1 rounded-xl border border-surface-border text-xs">
          <button
            onClick={() => setActiveTab('plain')}
            className={`px-3 py-1.5 rounded-lg transition-colors flex items-center space-x-1.5 font-medium ${
              activeTab === 'plain'
                ? 'bg-white text-navy-900 shadow-subtle border border-surface-border font-semibold'
                : 'text-slate-600 hover:text-navy-900'
            }`}
          >
            <AlignLeft className="w-3.5 h-3.5" />
            <span>Plain Text ({body.plain_text_char_count} chars)</span>
          </button>

          <button
            onClick={() => setActiveTab('html')}
            className={`px-3 py-1.5 rounded-lg transition-colors flex items-center space-x-1.5 font-medium ${
              activeTab === 'html'
                ? 'bg-white text-navy-900 shadow-subtle border border-surface-border font-semibold'
                : 'text-slate-600 hover:text-navy-900'
            }`}
          >
            <Code2 className="w-3.5 h-3.5" />
            <span>Sanitized HTML Text ({body.html_text_char_count} chars)</span>
          </button>
        </div>
      </div>

      {/* Safety Notice regarding HTML */}
      <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-700 space-y-1">
        <div className="flex items-center space-x-1.5 text-navy-900 font-semibold">
          <EyeOff className="w-4 h-4 text-brand-600 flex-shrink-0" />
          <span>Sanitized Display &amp; Script Neutralization Guarantee</span>
        </div>
        <p className="leading-relaxed text-slate-600">
          Raw untrusted email HTML is parsed through a DOM sanitizer where scripts, active markup, and dangerous tags are stripped.
          <strong className="text-navy-900 font-semibold"> Content is displayed as sanitized preformatted text and is never rendered directly as active browser markup.</strong>
        </p>
      </div>

      {/* Content box */}
      <div className="rounded-xl bg-surface-subtle border border-surface-border overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-surface-border bg-white text-xs text-slate-500">
          <span className="font-medium">
            {activeTab === 'plain'
              ? body.has_plain_text
                ? 'Viewing text/plain content'
                : 'No text/plain section detected'
              : body.has_html
              ? 'Viewing sanitized text extracted from text/html'
              : 'No text/html section detected'}
          </span>

          {currentContent && (
            <button
              onClick={handleCopy}
              className="inline-flex items-center px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 hover:text-navy-900 transition-colors text-xs font-medium"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-600 mr-1" />
                  <span>Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5 mr-1" />
                  <span>Copy Content</span>
                </>
              )}
            </button>
          )}
        </div>

        <div className="p-4 sm:p-5 max-h-96 overflow-y-auto">
          {currentContent ? (
            <pre className="font-mono text-xs sm:text-sm text-navy-900 whitespace-pre-wrap break-words leading-relaxed select-text">
              {currentContent}
            </pre>
          ) : (
            <p className="text-xs text-slate-400 italic">No content available for this section.</p>
          )}
        </div>
      </div>
    </div>
  );
};
