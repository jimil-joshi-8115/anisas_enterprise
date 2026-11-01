import React from 'react';
import { ASNScanResult } from '../../../types/asn';
import { ThreatCards } from '../components/ThreatCards';
import { ShieldAlert, Activity, AlertOctagon } from 'lucide-react';

interface ThreatOverviewPageProps {
  currentScan: ASNScanResult | null;
}

export const ThreatOverviewPage: React.FC<ThreatOverviewPageProps> = ({ currentScan }) => {
  if (!currentScan) {
    return (
      <div className="glass-panel p-12 text-center rounded-xl border border-slate-800 space-y-3">
        <ShieldAlert className="w-10 h-10 text-slate-600 mx-auto" />
        <h3 className="text-base font-bold text-slate-300">No Active Scan Profile Selected</h3>
        <p className="text-xs text-slate-500">Run a scan on Module 01 to view deep threat vector analytics.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-rose-400" />
            Threat Feeds & Abuse Overview
          </h2>
          <p className="text-xs text-slate-400">Target IP: {currentScan.targetIp} | AS{currentScan.asn.asnNumber}</p>
        </div>
      </div>

      <ThreatCards scan={currentScan} />

      <div className="glass-panel p-6 rounded-xl border border-slate-800 space-y-4">
        <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <AlertOctagon className="w-4 h-4 text-amber-400" />
          Threat Vector Classification Matrix
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
            <div className="text-xs text-slate-400">Active Threat Categories</div>
            <div className="text-sm font-mono font-bold text-cyan-300">
              {currentScan.threatIntel.threatCategories.join(', ')}
            </div>
          </div>
          <div className="p-4 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
            <div className="text-xs text-slate-400">Predicted Threat Severity</div>
            <div className="text-sm font-mono font-bold text-rose-400">
              {currentScan.aiEvaluation.risk_level} LEVEL ({currentScan.aiEvaluation.risk_score}/100)
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
