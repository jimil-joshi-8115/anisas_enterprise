import React from 'react';
import { ASNScanResult } from '../../../types/asn';
import { ResultCards } from '../components/ResultCards';
import { ThreatCards } from '../components/ThreatCards';
import { TimelineCard } from '../components/TimelineCard';
import { ArrowRight, Server, FileText, Globe, Layers } from 'lucide-react';

interface ASNDetailsPageProps {
  scan: ASNScanResult;
  onPassToModule02: (payload: any) => void;
}

export const ASNDetailsPage: React.FC<ASNDetailsPageProps> = ({ scan, onPassToModule02 }) => {
  return (
    <div className="space-y-6">
      {/* Detail Header */}
      <div className="glass-panel p-6 rounded-xl border border-slate-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 font-mono text-xs text-cyan-400">
            <span>Target IP: {scan.targetIp}</span>
            <span>•</span>
            <span>Scan ID: {scan.scanId}</span>
          </div>
          <h2 className="text-2xl font-extrabold text-white mt-1">
            AS{scan.asn.asnNumber} - {scan.asn.asnName}
          </h2>
          <p className="text-xs text-slate-400 mt-1">{scan.asn.organization} ({scan.asn.country})</p>
        </div>

        <button
          onClick={() => onPassToModule02(scan.module02Payload)}
          className="px-6 py-3 rounded-lg bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white text-xs font-bold uppercase tracking-wider flex items-center gap-2 shadow-lg shadow-emerald-500/20 transition"
        >
          <span>Auto-Pass to Module 02: Network Recon</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>

      <ResultCards scan={scan} />

      {/* Tabs / Raw Telemetry breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* WHOIS Record */}
        <div className="glass-panel p-5 rounded-xl border border-slate-800 space-y-3">
          <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
            <FileText className="w-4 h-4 text-cyan-400" />
            WHOIS Registry Data
          </h3>
          <div className="p-4 rounded-lg bg-slate-950/80 border border-slate-800 text-xs font-mono text-slate-300 space-y-1.5 overflow-x-auto">
            <div><span className="text-slate-500">Registrar:</span> {scan.whois.registrar}</div>
            <div><span className="text-slate-500">Owner:</span> {scan.whois.owner}</div>
            <div><span className="text-slate-500">NetRange:</span> {scan.whois.netRange}</div>
            <div><span className="text-slate-500">CIDR:</span> {scan.whois.cidr}</div>
            <div><span className="text-slate-500">Abuse Email:</span> {scan.whois.abuseEmail}</div>
            <div><span className="text-slate-500">Creation Date:</span> {scan.whois.creationDate}</div>
          </div>
        </div>

        {/* RDAP Network Record */}
        <div className="glass-panel p-5 rounded-xl border border-slate-800 space-y-3">
          <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
            <Globe className="w-4 h-4 text-emerald-400" />
            RDAP Network Registration
          </h3>
          <div className="p-4 rounded-lg bg-slate-950/80 border border-slate-800 text-xs font-mono text-slate-300 space-y-1.5 overflow-x-auto">
            <div><span className="text-slate-500">Network Name:</span> {scan.rdap.networkName}</div>
            <div><span className="text-slate-500">Organization:</span> {scan.rdap.organization}</div>
            <div><span className="text-slate-500">Abuse Contact:</span> {scan.rdap.abuseContact}</div>
            <div><span className="text-slate-500">Admin Contact:</span> {scan.rdap.adminContact}</div>
            <div><span className="text-slate-500">Country/Status:</span> {scan.rdap.country} ({scan.rdap.registrationStatus})</div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <ThreatCards scan={scan} />
        </div>
        <TimelineCard scan={scan} />
      </div>
    </div>
  );
};
