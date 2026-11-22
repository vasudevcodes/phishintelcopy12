import { useState } from 'react';
import type { ReactNode } from 'react';
import {
  Globe,
  Paperclip,
  AlignLeft,
  Mail,
  Network,
  Layers,
  Lock,
  Cpu,
  ShieldCheck,
  Scale,
} from 'lucide-react';
import { Navbar } from './components/Navbar';
import { UploadZone } from './components/UploadZone';
import { EmailOverviewBanner } from './components/EmailOverviewBanner';
import { EvidenceFusionCard } from './components/EvidenceFusionCard';
import { AuthenticationCard } from './components/AuthenticationCard';
import { HeaderForensics } from './components/HeaderForensics';
import { IPCandidatesCard } from './components/IPCandidatesCard';
import { ExtractedURLsCard } from './components/ExtractedURLsCard';
import { AttachmentForensicsCard } from './components/AttachmentForensicsCard';
import { BodyForensicsCard } from './components/BodyForensicsCard';
import type { EmailAnalysisResponse } from './types/forensics';

type TabId = 'all' | 'fusion' | 'auth' | 'headers' | 'ips' | 'urls' | 'attachments' | 'body';

interface TabDef {
  id: TabId;
  label: string;
  icon: ReactNode;
  count?: number;
}

const CAPABILITIES = [
  {
    icon: <Cpu className="w-5 h-5" />,
    title: 'Transformer detection',
    body: 'Subject and body text pass through a fine-tuned DistilBERT model. Scores are reported uncalibrated, with their limitations stated.',
  },
  {
    icon: <Lock className="w-5 h-5" />,
    title: 'Email authentication',
    body: 'SPF, DKIM and DMARC results are parsed from the headers, with DKIM signatures cryptographically re-verified where keys allow.',
  },
  {
    icon: <Network className="w-5 h-5" />,
    title: 'IP provenance',
    body: 'Received hops are rebuilt in order, candidate IPs checked for routability, and the earliest origin relay identified.',
  },
  {
    icon: <ShieldCheck className="w-5 h-5" />,
    title: 'Static URL analysis',
    body: 'Links are scored on structure alone: IP literals, suspicious TLDs, homoglyphs and encodings. No request is ever made.',
  },
  {
    icon: <Scale className="w-5 h-5" />,
    title: 'Evidence fusion',
    body: 'Every signal is weighed into one explainable risk category, with coverage shown so gaps are never hidden.',
  },
];

export function App() {
  const [analysisData, setAnalysisData] = useState<EmailAnalysisResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>('all');

  const handleReset = () => {
    setAnalysisData(null);
    setErrorMessage(null);
    setActiveTab('all');
  };

  const tabs: TabDef[] = analysisData
    ? [
        { id: 'all', label: 'All Forensics', icon: <Layers className="w-4 h-4" /> },
        ...(analysisData.evidence_fusion
          ? [{ id: 'fusion' as const, label: 'Evidence Fusion', icon: <Scale className="w-4 h-4" /> }]
          : []),
        ...(analysisData.authentication_analysis
          ? [{ id: 'auth' as const, label: 'Authentication', icon: <Lock className="w-4 h-4" /> }]
          : []),
        {
          id: 'ips',
          label: 'IP Candidates',
          icon: <Network className="w-4 h-4" />,
          count: analysisData.ip_candidates.length,
        },
        { id: 'urls', label: 'URLs', icon: <Globe className="w-4 h-4" />, count: analysisData.urls.length },
        { id: 'headers', label: 'Headers & Transit', icon: <Mail className="w-4 h-4" /> },
        {
          id: 'attachments',
          label: 'Attachments',
          icon: <Paperclip className="w-4 h-4" />,
          count: analysisData.attachments.length,
        },
        { id: 'body', label: 'Body Forensics', icon: <AlignLeft className="w-4 h-4" /> },
      ]
    : [];

  return (
    <div className="min-h-screen bg-surface-bg text-navy-900 flex flex-col font-sans">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-[60] focus:bg-white focus:px-3 focus:py-2 focus:rounded-md focus:shadow-dropdown"
      >
        Skip to content
      </a>
      <Navbar onBrandClick={analysisData ? handleReset : undefined} />

      <main id="main" className="flex-1">
        {!analysisData ? (
          <>
            {/* Hero */}
            <section className="relative">
              <div className="absolute inset-0 bg-grid pointer-events-none" aria-hidden="true" />
              <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-12 sm:pt-16 pb-14 sm:pb-20">
                <div className="grid lg:grid-cols-12 gap-10 lg:gap-14 items-center">
                  <div className="lg:col-span-5 space-y-6">
                    <h1 className="text-4xl sm:text-5xl font-semibold text-navy-900 tracking-tight leading-[1.08]">
                      Examine a suspicious email without it ever leaving your machine.
                    </h1>
                    <p className="text-base text-slate-600 leading-relaxed max-w-lg">
                      PhishIntel reads the raw <code className="font-mono text-[13px] text-navy-900">.eml</code>{' '}
                      and shows its working: language-model scoring, sender authentication, the route the message
                      took, and every link inside it. Nothing is uploaded, resolved or retained.
                    </p>
                    <dl className="grid grid-cols-3 gap-4 pt-2 max-w-md">
                      {[
                        ['0', 'external lookups'],
                        ['5', 'evidence streams'],
                        ['10 MB', 'per message'],
                      ].map(([value, label]) => (
                        <div key={label} className="border-l-2 border-brand-400 pl-3">
                          <dt className="text-2xl font-semibold font-mono text-navy-900 leading-none">{value}</dt>
                          <dd className="text-xs text-slate-500 mt-1.5">{label}</dd>
                        </div>
                      ))}
                    </dl>
                  </div>

                  <div className="lg:col-span-7">
                    <UploadZone
                      onAnalysisComplete={setAnalysisData}
                      isLoading={isLoading}
                      setIsLoading={setIsLoading}
                      errorMessage={errorMessage}
                      setErrorMessage={setErrorMessage}
                    />
                  </div>
                </div>
              </div>
            </section>

            {/* Capabilities */}
            <section className="border-t border-surface-border bg-white">
              <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-14">
                <h2 className="text-xl font-semibold tracking-tight text-navy-900 mb-1">What each analysis covers</h2>
                <p className="text-sm text-slate-500 mb-8 max-w-2xl">
                  Five independent streams run on every message and are combined only at the end, so you can see
                  which evidence drove the verdict.
                </p>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-px bg-surface-border rounded-2xl overflow-hidden ring-1 ring-surface-border">
                  {CAPABILITIES.map((c) => (
                    <div key={c.title} className="bg-white p-5 space-y-3 hover:bg-brand-50/40 transition-colors">
                      <div className="w-9 h-9 rounded-lg bg-brand-50 text-brand-600 ring-1 ring-brand-100 flex items-center justify-center">
                        {c.icon}
                      </div>
                      <h3 className="text-sm font-semibold text-navy-900">{c.title}</h3>
                      <p className="text-[13px] text-slate-600 leading-relaxed">{c.body}</p>
                    </div>
                  ))}
                </div>
              </div>
            </section>
          </>
        ) : (
          <div className="py-8 space-y-6 animate-fade-in">
            <EmailOverviewBanner data={analysisData} onReset={handleReset} />

            {/* Sticky section navigation */}
            <nav
              aria-label="Forensic sections"
              className="sticky top-16 z-40 bg-surface-bg/85 backdrop-blur border-b border-surface-border"
            >
              <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div role="tablist" className="flex items-center gap-1 overflow-x-auto text-sm font-medium -mb-px">
                  {tabs.map((tab) => {
                    const active = activeTab === tab.id;
                    return (
                      <button
                        key={tab.id}
                        role="tab"
                        aria-selected={active}
                        onClick={() => setActiveTab(tab.id)}
                        className={`flex items-center gap-2 px-3.5 py-3 whitespace-nowrap border-b-2 transition-colors ${
                          active
                            ? 'border-brand-500 text-navy-900'
                            : 'border-transparent text-slate-500 hover:text-navy-900 hover:border-slate-300'
                        }`}
                      >
                        <span className={active ? 'text-brand-600' : 'text-slate-400'}>{tab.icon}</span>
                        <span>{tab.label}</span>
                        {tab.count !== undefined && (
                          <span
                            className={`text-[11px] font-mono px-1.5 py-0.5 rounded ${
                              active ? 'bg-brand-50 text-brand-700' : 'bg-slate-100 text-slate-500'
                            }`}
                          >
                            {tab.count}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              </div>
            </nav>

            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-6">
              {(activeTab === 'all' || activeTab === 'fusion') && analysisData.evidence_fusion && (
                <EvidenceFusionCard fusion={analysisData.evidence_fusion} />
              )}

              {(activeTab === 'all' || activeTab === 'auth') && analysisData.authentication_analysis && (
                <AuthenticationCard auth={analysisData.authentication_analysis} />
              )}

              {(activeTab === 'all' || activeTab === 'ips') && (
                <IPCandidatesCard
                  candidates={analysisData.ip_candidates}
                  ipIntelligence={analysisData.ip_intelligence}
                />
              )}

              {(activeTab === 'all' || activeTab === 'urls') && (
                <ExtractedURLsCard
                  key={`urls-${analysisData.filename}-${analysisData.parsed_at}`}
                  urls={analysisData.urls}
                  urlAnalysis={analysisData.url_analysis}
                />
              )}

              {(activeTab === 'all' || activeTab === 'headers') && (
                <HeaderForensics headers={analysisData.headers} />
              )}

              {(activeTab === 'all' || activeTab === 'attachments') && (
                <AttachmentForensicsCard attachments={analysisData.attachments} />
              )}

              {(activeTab === 'all' || activeTab === 'body') && <BodyForensicsCard body={analysisData.body} />}
            </div>
          </div>
        )}
      </main>

      <footer className="border-t border-surface-border bg-white py-6 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <p className="font-semibold text-navy-900">PhishIntel</p>
          <p>Deterministic offline analysis. No external lookups. Single-file processing. Zero retention.</p>
        </div>
      </footer>
    </div>
  );
}

export default App;
