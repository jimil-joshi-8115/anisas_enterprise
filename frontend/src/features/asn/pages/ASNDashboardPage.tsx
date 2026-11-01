import React from 'react';
import { ASNScanResult, ScanHistoryItem } from '../../../types/asn';
import { IPInput } from '../components/IPInput';
import { ResultCards } from '../components/ResultCards';
import { ThreatCards } from '../components/ThreatCards';
import { CountryCard, MapCard } from '../components/CountryCard';
import { RechartsVisualizations } from '../components/RechartsVisualizations';
import { ShieldAlert, Network, ArrowRight } from 'lucide-react';

interface ASNDashboardPageProps {
  currentScan: ASNScanResult | null;
  history: ScanHistoryItem[];
  onScan: (ip: string) => void;
  onPassToModule02: (payload: any) => void;
  isLoading: boolean;
}

export const ASNDashboardPage: React.FC<ASNDashboardPageProps> = ({
  currentScan,
  history,
  onScan,
  onPassToModule02,
  isLoading
}) => {
  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="glass-panel p-6 rounded-xl border border-slate-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider">
            Module 01 • Cyber Intelligence Pipeline
          </div>
          <h2 className="text-xl font-extrabold text-white mt-1">ASN & ISP Intelligence Engine</h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Automated OSINT reconnaissance resolving Autonomous Systems, WHOIS, RDAP, BGP prefixes, geographic location, and multi-feed threat intelligence scoring.
          </p>
        </div>

        {currentScan && (
          <button
            onClick={() => onPassToModule02(currentScan.module02Payload)}
            className="px-5 py-2.5 rounded-lg bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white text-xs font-bold uppercase tracking-wider flex items-center gap-2 shadow-lg shadow-emerald-500/20 transition"
          >
            <span>Pass Output to Module 02</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        )}
      </div>

      {/* Input Section */}
      <IPInput onScan={onScan} isLoading={isLoading} />

      {/* Active Scan Results Display */}
      {currentScan && (
        <div className="space-y-6">
          <ResultCards scan={currentScan} />
          
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2">
              <ThreatCards scan={currentScan} />
            </div>
            <div className="space-y-6">
              <CountryCard scan={currentScan} />
              <MapCard scan={currentScan} />
            </div>
          </div>
        </div>
      )}

      {/* Recharts Analytics Section */}
      <RechartsVisualizations />
    </div>
  );
};
