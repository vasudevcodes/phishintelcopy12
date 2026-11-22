import { useEffect, useState } from 'react';
import type { FC } from 'react';
import { Shield, Cpu, WifiOff, Globe } from 'lucide-react';

export interface NavbarProps {
  onBrandClick?: () => void;
}

export const Navbar: FC<NavbarProps> = ({ onBrandClick }) => {
  // True when the backend performs live DNS SPF/DKIM/DMARC verification.
  const [onlineAuth, setOnlineAuth] = useState<boolean>(false);

  useEffect(() => {
    let cancelled = false;
    fetch('/api/v1/system/status')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (!cancelled && d && typeof d.online_authentication === 'boolean') {
          setOnlineAuth(d.online_authentication);
        }
      })
      .catch(() => {
        /* backend unreachable: keep the offline label */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const brand = (
    <>
      <div className="w-9 h-9 rounded-lg bg-brand-500/15 ring-1 ring-brand-400/40 flex items-center justify-center">
        <Shield className="w-5 h-5 text-brand-300" aria-hidden="true" />
      </div>
      <div className="text-left">
        <div className="flex items-center gap-2">
          <span className="text-lg font-semibold tracking-tight text-white leading-none">
            Phish<span className="text-brand-300">Intel</span>
          </span>
          <span className="text-[10px] font-mono font-medium px-1.5 py-0.5 rounded bg-white/10 text-slate-300 ring-1 ring-white/10">
            Forensics
          </span>
        </div>
        <p className="text-[11px] text-slate-400 hidden md:block mt-1 leading-none">
          Transformer &amp; NLP-Based Email Phishing Detection and IP Intelligence
        </p>
      </div>
    </>
  );

  return (
    <header className="bg-navy-950 sticky top-0 z-50 border-b border-white/5">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {onBrandClick ? (
          <button
            type="button"
            onClick={onBrandClick}
            className="flex items-center gap-3 rounded-lg focus-visible:outline-brand-300"
            aria-label="PhishIntel home – start a new investigation"
          >
            {brand}
          </button>
        ) : (
          <div className="flex items-center gap-3">{brand}</div>
        )}

        <div className="flex items-center gap-2.5">
          <div className="hidden sm:flex items-center gap-2 text-xs text-slate-300 px-3 py-1.5 rounded-md bg-white/5 ring-1 ring-white/10">
            <Cpu className="w-3.5 h-3.5 text-slate-400" aria-hidden="true" />
            <span className="font-mono text-[11px]">DistilBERT + Heuristics</span>
          </div>
          <div className="flex items-center gap-2 text-xs font-medium px-3 py-1.5 rounded-md bg-emerald-500/10 ring-1 ring-emerald-400/30 text-emerald-300">
            <span className="relative flex w-2 h-2">
              <span className="absolute inline-flex w-full h-full rounded-full bg-emerald-400 opacity-60 animate-ping" />
              <span className="relative inline-flex w-2 h-2 rounded-full bg-emerald-400" />
            </span>
            {onlineAuth ? (
              <Globe className="w-3.5 h-3.5 hidden sm:block" aria-hidden="true" />
            ) : (
              <WifiOff className="w-3.5 h-3.5 hidden sm:block" aria-hidden="true" />
            )}
            <span>{onlineAuth ? 'Live DNS · Online' : 'Local · Offline'}</span>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Navbar;
