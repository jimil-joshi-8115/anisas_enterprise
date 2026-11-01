import React from 'react';
import { ASNScanResult } from '../../../types/asn';
import { Network, Server, Globe, Cpu, Hash, FileText } from 'lucide-react';

interface ResultCardsProps {
  scan: ASNScanResult;
}

export const ResultCards: React.FC<ResultCardsProps> = ({ scan }) => {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      {/* ASN Card */}
      <div className="glass-panel p-5 rounded-xl border border-slate-800 space-y-2">
        <div className="flex items-center justify-between text-slate-400">
          <span className="text-xs uppercase font-mono tracking-wider">Autonomous System</span>
          <Hash className="w-4 h-4 text-cyan-400" />
        </div>
        <div className="text-xl font-bold font-mono text-cyan-300">AS{scan.asn.asnNumber}</div>
        <div className="text-xs text-slate-300 truncate">{scan.asn.asnName}</div>
        <div className="text-[10px] text-slate-500 font-mono">Registry: {scan.asn.registry}</div>
      </div>

      {/* Organization / ISP */}
      <div className="glass-panel p-5 rounded-xl border border-slate-800 space-y-2">
        <div className="flex items-center justify-between text-slate-400">
          <span className="text-xs uppercase font-mono tracking-wider">Organization / ISP</span>
          <Server className="w-4 h-4 text-blue-400" />
        </div>
        <div className="text-base font-bold text-white truncate">{scan.asn.organization}</div>
        <div className="text-xs text-slate-400 truncate">Reverse DNS: {scan.geo.reverseDns}</div>
        <div className="text-[10px] text-slate-500 font-mono">ISP: {scan.geo.isp}</div>
      </div>

      {/* CIDR & Prefix */}
      <div className="glass-panel p-5 rounded-xl border border-slate-800 space-y-2">
        <div className="flex items-center justify-between text-slate-400">
          <span className="text-xs uppercase font-mono tracking-wider">Subnet CIDR</span>
          <Network className="w-4 h-4 text-emerald-400" />
        </div>
        <div className="text-base font-bold font-mono text-emerald-300">{scan.asn.cidr}</div>
        <div className="text-xs text-slate-400">Announced Subnets: {scan.asn.prefixes.length}</div>
        <div className="text-[10px] text-slate-500 font-mono">NetRange: {scan.whois.netRange}</div>
      </div>

      {/* Threat & AI Risk Score */}
      <div className="glass-panel p-5 rounded-xl border border-slate-800 space-y-2">
        <div className="flex items-center justify-between text-slate-400">
          <span className="text-xs uppercase font-mono tracking-wider">AI Threat Rating</span>
          <Cpu className="w-4 h-4 text-rose-400" />
        </div>
        <div className="flex items-baseline gap-2">
          <span className={`text-2xl font-bold font-mono ${
            scan.aiEvaluation.risk_level === 'HIGH' || scan.aiEvaluation.risk_level === 'CRITICAL'
              ? 'text-rose-400'
              : 'text-emerald-400'
          }`}>
            {scan.aiEvaluation.risk_score}/100
          </span>
          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
            scan.aiEvaluation.risk_level === 'HIGH' || scan.aiEvaluation.risk_level === 'CRITICAL'
              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
              : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
          }`}>
            {scan.aiEvaluation.risk_level}
          </span>
        </div>
        <div className="text-xs text-slate-400 truncate">Confidence: {scan.aiEvaluation.confidence_score}%</div>
      </div>
    </div>
  );
};
