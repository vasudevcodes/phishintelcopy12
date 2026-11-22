import { useState } from 'react';
import type { FC } from 'react';
import { Network, Info, Copy, Check, Route, MapPin, AlertTriangle } from 'lucide-react';
import type {
  IPCandidate,
  IPClassification,
  IPIntelligenceResult,
} from '../types/forensics';

interface IPCandidatesCardProps {
  candidates: IPCandidate[];
  ipIntelligence?: IPIntelligenceResult | null;
}

export const IPCandidatesCard: FC<IPCandidatesCardProps> = ({
  candidates,
  ipIntelligence,
}) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const getBadgeClass = (classification: IPClassification) => {
    switch (classification) {
      case 'Public':
        return 'bg-blue-50 text-blue-700 border-blue-200';
      case 'Private':
        return 'bg-purple-50 text-purple-700 border-purple-200';
      case 'Loopback':
        return 'bg-slate-100 text-slate-700 border-slate-200';
      case 'Link-Local':
        return 'bg-indigo-50 text-indigo-700 border-indigo-200';
      case 'Documentation':
        return 'bg-amber-50 text-amber-700 border-amber-200';
      case 'Multicast':
      case 'Reserved':
      case 'Special-Purpose':
      default:
        return 'bg-amber-50 text-amber-700 border-amber-200';
    }
  };

  return (
    <div className="rounded-2xl border border-surface-border bg-white p-5 sm:p-6 shadow-card space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-surface-border">
        <div className="flex items-center space-x-2.5 text-navy-900">
          <Network className="w-5 h-5 text-purple-600" />
          <h3 className="text-base font-semibold tracking-tight">
            IP Intelligence ({candidates.length})
          </h3>
        </div>

        {ipIntelligence && (
          <div className="flex items-center space-x-2 text-xs">
            <span className="text-slate-500 font-medium">Offline GeoLite2:</span>
            <span
              className={`px-2.5 py-0.5 rounded-full text-[11px] font-semibold border ${
                ipIntelligence.database_available
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  : 'bg-slate-100 text-slate-600 border-slate-200'
              }`}
            >
              {ipIntelligence.database_available ? 'Database Active' : 'Offline / Not Loaded'}
            </span>
          </div>
        )}
      </div>

      {/* Origin Candidate Summary if IP Intelligence available */}
      {ipIntelligence && (
        <div className="p-4 sm:p-5 rounded-xl bg-surface-subtle border border-surface-border space-y-3.5 shadow-subtle">
          <div className="flex items-center space-x-2 text-navy-900 text-xs font-semibold uppercase tracking-wider">
            <Route className="w-4 h-4 text-purple-600" />
            <span>Apparent Origin Transit Evaluation</span>
          </div>

          <p className="text-xs sm:text-sm text-slate-800 leading-relaxed font-sans">
            {ipIntelligence.origin_assessment}
          </p>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 text-xs border-t border-slate-200">
            <div>
              <span className="text-slate-500 font-medium block">Origin Attribution: </span>
              <span className={`font-semibold block mt-0.5 ${ipIntelligence.origin_attribution_status === 'UNAVAILABLE' ? 'text-amber-700' : 'text-navy-900'}`}>
                {ipIntelligence.origin_attribution_status || (ipIntelligence.origin_candidate ? 'AVAILABLE_UNVERIFIED' : 'UNAVAILABLE')}
              </span>
            </div>
            <div>
              <span className="text-slate-500 font-medium block">Candidate IP: </span>
              <span className="text-slate-800 block mt-0.5 font-mono">
                {ipIntelligence.candidate_ip_classification || ipIntelligence.origin_candidate?.classification || 'Unavailable'}
                {ipIntelligence.is_candidate_routable !== undefined && ipIntelligence.is_candidate_routable !== null ? (
                  <span className="text-slate-500 text-[10px] ml-1">
                    ({ipIntelligence.is_candidate_routable ? 'Public' : 'Non-routable'})
                  </span>
                ) : ipIntelligence.origin_candidate ? (
                  <span className="text-slate-500 text-[10px] ml-1">
                    ({ipIntelligence.origin_candidate.is_routable ? 'Public' : 'Non-routable'})
                  </span>
                ) : null}
              </span>
            </div>
            <div>
              <span className="text-slate-500 font-medium block">Provider Indicator: </span>
              <span className="text-slate-800 block mt-0.5 truncate font-medium" title={ipIntelligence.provider_infrastructure_match || 'None detected'}>
                {ipIntelligence.provider_infrastructure_match || 'None detected'}
              </span>
            </div>
            <div>
              <span className="text-slate-500 font-medium block">Sender Identity: </span>
              <span className="text-slate-800 block mt-0.5 truncate font-medium" title={ipIntelligence.sender_identity_status || 'Not established'}>
                {ipIntelligence.sender_identity_status || 'Not established'}
              </span>
            </div>
          </div>

          <div className="flex items-center justify-between pt-2 text-[11px] font-mono text-slate-600 border-t border-slate-200 flex-wrap gap-2">
            <div>
              <span className="text-slate-500">Origin Candidate IP: </span>
              <span className="text-navy-900 font-bold">{ipIntelligence.origin_candidate?.ip || '(Unavailable)'}</span>
            </div>
            <div>
              <span className="text-slate-500">Hops Breakdown: </span>
              <span>Pub: {ipIntelligence.public_count} | Priv: {ipIntelligence.private_count} | Other: {ipIntelligence.other_count}</span>
            </div>
          </div>
        </div>
      )}

      {candidates.length === 0 ? (
        <div className="text-center py-8 text-slate-500 font-mono text-xs flex items-center justify-center space-x-1.5">
          <AlertTriangle className="w-4 h-4 text-amber-500" />
          <span>No IP address candidates detected in Received headers.</span>
        </div>
      ) : (
        <div className="overflow-x-auto border border-surface-border rounded-xl">
          <table className="w-full text-left text-xs">
            <thead className="bg-surface-subtle border-b border-surface-border text-slate-600 font-semibold">
              <tr>
                <th className="py-3 px-3.5">Hop</th>
                <th className="py-3 px-3.5">Candidate IP</th>
                <th className="py-3 px-3.5">Role / Role Hint</th>
                <th className="py-3 px-3.5">Classification</th>
                <th className="py-3 px-3.5">Routability</th>
                <th className="py-3 px-3.5">Location / Geolocation</th>
                <th className="py-3 px-3.5 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border font-sans">
              {candidates.map((cand, idx) => {
                const candIntel = ipIntelligence?.candidates?.find(
                  (c) => c.ip === cand.ip && (c.hop_index === cand.hop_index || c.hop_index === null)
                );
                const isOrigin =
                  ipIntelligence?.origin_candidate &&
                  ipIntelligence.origin_candidate.ip === cand.ip &&
                  ipIntelligence.origin_candidate.hop_index === cand.hop_index;

                return (
                  <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                    <td className="py-3 px-3.5 text-slate-500 font-mono">
                      <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-700 font-bold">
                        #{cand.hop_index}
                      </span>
                    </td>
                    <td className="py-3 px-3.5 font-mono font-semibold text-navy-900">
                      <span className="break-all">{cand.ip}</span>
                    </td>
                    <td className="py-3 px-3.5">
                      {isOrigin ? (
                        <span className="px-2.5 py-0.5 rounded text-[11px] font-semibold bg-purple-50 text-purple-700 border border-purple-200">
                          {candIntel?.classification === 'Public'
                            ? 'Earliest Public Candidate (Unverified)'
                            : 'Earliest Recorded Hop (Origin Unavailable)'}
                        </span>
                      ) : candIntel?.role_hint ? (
                        <span className="px-2 py-0.5 rounded text-[11px] bg-slate-100 text-slate-700 border border-slate-200">
                          {candIntel.role_hint}
                        </span>
                      ) : (
                        <span className="text-slate-400 text-xs">Relay Hop</span>
                      )}
                    </td>
                    <td className="py-3 px-3.5 font-mono">
                      <span
                        className={`inline-block px-2.5 py-0.5 rounded-full border text-[11px] font-semibold ${getBadgeClass(
                          cand.classification
                        )}`}
                      >
                        {cand.classification}
                      </span>
                    </td>
                    <td className="py-3 px-3.5">
                      {candIntel ? (
                        <span
                          className={`text-xs font-medium ${
                            candIntel.is_routable ? 'text-blue-700' : 'text-slate-500'
                          }`}
                        >
                          {candIntel.is_routable ? 'Public Internet' : 'Non-Routable'}
                        </span>
                      ) : (
                        <span className="text-slate-500 text-xs">
                          {cand.classification === 'Public' ? 'Routable' : 'Internal'}
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-3.5 text-slate-600 text-xs">
                      {candIntel?.geolocation ? (
                        <div className="flex items-center space-x-1 text-slate-800">
                          <MapPin className="w-3.5 h-3.5 text-purple-600 flex-shrink-0" />
                          <span>
                            {[
                              candIntel.geolocation.city_name,
                              candIntel.geolocation.country_name || candIntel.geolocation.country_code,
                            ]
                              .filter(Boolean)
                              .join(', ')}
                          </span>
                        </div>
                      ) : candIntel?.geolocation_status ? (
                        <span className="text-slate-500 font-mono text-[11px]">
                          {candIntel.geolocation_status === 'NOT_ROUTABLE'
                            ? 'Not Routable'
                            : candIntel.geolocation_status === 'DATABASE_UNAVAILABLE'
                            ? 'DB Unavailable'
                            : candIntel.geolocation_status}
                        </span>
                      ) : (
                        <span className="text-slate-400 text-[11px]">N/A</span>
                      )}
                    </td>
                    <td className="py-3 px-3.5 text-right">
                      <button
                        onClick={() => handleCopy(cand.ip, `ip_${idx}`)}
                        className="inline-flex items-center px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-600 hover:text-navy-900 transition-colors"
                        title="Copy IP"
                      >
                        {copiedKey === `ip_${idx}` ? (
                          <Check className="w-3.5 h-3.5 text-emerald-600" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Forensic Disclaimer */}
      <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-600 space-y-1">
        <div className="flex items-center space-x-1.5 text-navy-900 font-semibold">
          <Info className="w-4 h-4 text-brand-600 flex-shrink-0" />
          <span>Forensic IP Provenance Limitation Note</span>
        </div>
        <p className="leading-relaxed">
          {ipIntelligence?.disclaimer ||
            'Received headers prior to the recipient boundary MTA can be spoofed or omitted by untrusted relays. An IP address indicates network routing, not personal identity. Matching cloud provider infrastructure does not confirm sender identity.'}
        </p>
      </div>
    </div>
  );
};
