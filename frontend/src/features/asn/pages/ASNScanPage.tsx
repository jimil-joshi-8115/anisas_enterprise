import React from 'react';
import { ASNScanResult } from '../../../types/asn';
import { IPInput } from '../components/IPInput';
import { BulkUpload } from '../components/BulkUpload';
import { ResultCards } from '../components/ResultCards';
import { ThreatCards } from '../components/ThreatCards';
import { downloadJSON, downloadCSV, downloadPDF } from '../../../utils/exporter';
import { Download, FileJson, FileSpreadsheet, FileCode } from 'lucide-react';

interface ASNScanPageProps {
  currentScan: ASNScanResult | null;
  onScan: (ip: string) => void;
  onBulkScan: (ips: string[]) => void;
  isLoading: boolean;
}

export const ASNScanPage: React.FC<ASNScanPageProps> = ({
  currentScan,
  onScan,
  onBulkScan,
  isLoading
}) => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-white">Execute ASN Intelligence Scan</h2>
        {currentScan && (
          <div className="flex items-center gap-2">
            <button
              onClick={() => downloadJSON(currentScan)}
              className="px-3 py-1.5 rounded bg-slate-900 border border-slate-800 hover:bg-slate-800 text-xs font-mono text-cyan-400 flex items-center gap-1.5 transition"
            >
              <FileJson className="w-3.5 h-3.5" />
              JSON
            </button>
            <button
              onClick={() => downloadCSV(currentScan)}
              className="px-3 py-1.5 rounded bg-slate-900 border border-slate-800 hover:bg-slate-800 text-xs font-mono text-emerald-400 flex items-center gap-1.5 transition"
            >
              <FileSpreadsheet className="w-3.5 h-3.5" />
              CSV
            </button>
            <button
              onClick={() => downloadPDF(currentScan)}
              className="px-3 py-1.5 rounded bg-slate-900 border border-slate-800 hover:bg-slate-800 text-xs font-mono text-rose-400 flex items-center gap-1.5 transition"
            >
              <FileCode className="w-3.5 h-3.5" />
              PDF Report
            </button>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <IPInput onScan={onScan} isLoading={isLoading} />
        <BulkUpload onBulkScan={onBulkScan} isLoading={isLoading} />
      </div>

      {currentScan && (
        <div className="space-y-6">
          <ResultCards scan={currentScan} />
          <ThreatCards scan={currentScan} />
        </div>
      )}
    </div>
  );
};
