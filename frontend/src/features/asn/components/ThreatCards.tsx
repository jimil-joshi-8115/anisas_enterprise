import React from 'react';
import { ASNScanResult } from '../../../types/asn';
import { ShieldAlert, AlertTriangle, Activity, CheckCircle2 } from 'lucide-react';

interface ThreatCardsProps {
  scan: ASNScanResult;
}

export const ThreatCards: React.FC<ThreatCardsProps> = ({ scan }) => {
  const { threatIntel, aiEvaluation } = scan;

  return (
    <div className="glass-panel p-6 rounded-xl border border-slate-800 space-y-4">
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-rose-400" />
          <h3 className="text-sm font-bold text-white uppercase tracking-wider">Threat Intelligence Feeds</h3>
        </div>
        <span className="text-xs font-mono text-cyan-400">Multi-Feed Aggregated</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* VirusTotal */}
        <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-300">VirusTotal Detection</span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
              threatIntel.vtMaliciousScore > 0 ? 'bg-rose-500/20 text-rose-400' : 'bg-emerald-500/20 text-emerald-400'
            }`}>
              {threatIntel.vtMaliciousScore > 0 ? `${threatIntel.vtMaliciousScore} Flagged` : 'Clean'}
            </span>
          </div>
          <div className="text-xl font-bold font-mono text-white">{threatIntel.vtMaliciousScore} / 90</div>
          <p className="text-[11px] text-slate-500">Security vendor scanning analysis score</p>
        </div>

        {/* AbuseIPDB */}
        <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-300">AbuseIPDB Confidence</span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
              threatIntel.abuseScore > 20 ? 'bg-amber-500/20 text-amber-400' : 'bg-emerald-500/20 text-emerald-400'
            }`}>
              {threatIntel.abuseScore}% Abuse Score
            </span>
          </div>
          <div className="text-xl font-bold font-mono text-white">{threatIntel.abuseReportsCount} Reports</div>
          <p className="text-[11px] text-slate-500">Community reported abuse events</p>
        </div>

        {/* GreyNoise */}
        <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-300">GreyNoise Classification</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-sm font-bold font-mono text-cyan-300 capitalize">{threatIntel.greyNoiseClassification}</div>
          <p className="text-[11px] text-slate-500">Internet background noise & scanner telemetry</p>
        </div>
      </div>

      {/* AI Summary Box */}
      <div className="p-4 rounded-lg bg-slate-900/60 border border-cyan-500/20 space-y-1.5">
        <div className="text-xs font-bold text-cyan-400 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4" />
          AI Engine Executive Analysis
        </div>
        <p className="text-xs text-slate-300 leading-relaxed font-sans">
          {aiEvaluation.ai_executive_summary}
        </p>
      </div>
    </div>
  );
};
