import React, { useState } from 'react';
import { UploadCloud, FileSpreadsheet, AlertTriangle, CheckCircle } from 'lucide-react';

interface BulkUploadProps {
  onBulkScan: (ips: string[]) => void;
  isLoading: boolean;
}

const ipv4Regex = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.){3}(25[0-5]|(2[0-4]|1\d|[1-9]|)\d)$/;

export const BulkUpload: React.FC<BulkUploadProps> = ({ onBulkScan, isLoading }) => {
  const [validIps, setValidIps] = useState<string[]>([]);
  const [invalidRows, setInvalidRows] = useState<string[]>([]);
  const [fileName, setFileName] = useState<string | null>(null);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = (evt) => {
      const content = evt.target?.result as string;
      const lines = content.split(/[\r\n,;]+/);
      const valid: string[] = [];
      const invalid: string[] = [];

      lines.forEach((line) => {
        const trimmed = line.trim();
        if (!trimmed || trimmed.toLowerCase().includes('ip')) return;
        if (ipv4Regex.test(trimmed)) {
          valid.push(trimmed);
        } else {
          invalid.push(trimmed);
        }
      });

      setValidIps(valid);
      setInvalidRows(invalid);
    };
    reader.readAsText(file);
  };

  return (
    <div className="glass-panel p-6 rounded-xl border border-slate-800 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-base font-bold text-white flex items-center gap-2">
          <FileSpreadsheet className="w-5 h-5 text-cyan-400" />
          Bulk IP CSV Scan Engine
        </h3>
        <span className="text-xs text-slate-400 font-mono">Max 1,000 IPs / Batch</span>
      </div>

      <div className="border-2 border-dashed border-slate-800 rounded-lg p-6 text-center hover:border-cyan-500/50 transition cursor-pointer relative bg-slate-950/40">
        <input
          type="file"
          accept=".csv,.txt"
          onChange={handleFileUpload}
          className="absolute inset-0 opacity-0 cursor-pointer"
        />
        <UploadCloud className="w-8 h-8 text-cyan-400 mx-auto mb-2" />
        <div className="text-xs font-semibold text-slate-300">
          {fileName ? `File Loaded: ${fileName}` : 'Click or Drag CSV File containing IP addresses'}
        </div>
        <div className="text-[11px] text-slate-500 mt-1">Supports standard CSV with IP column</div>
      </div>

      {validIps.length > 0 && (
        <div className="flex items-center justify-between p-3 rounded-lg bg-slate-900 border border-slate-800">
          <div className="flex items-center gap-4 text-xs font-mono">
            <span className="text-emerald-400 flex items-center gap-1">
              <CheckCircle className="w-3.5 h-3.5" />
              {validIps.length} Valid IPs
            </span>
            {invalidRows.length > 0 && (
              <span className="text-rose-400 flex items-center gap-1">
                <AlertTriangle className="w-3.5 h-3.5" />
                {invalidRows.length} Invalid Entries
              </span>
            )}
          </div>

          <button
            onClick={() => onBulkScan(validIps)}
            disabled={isLoading}
            className="px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold uppercase tracking-wider transition disabled:opacity-50"
          >
            {isLoading ? 'Batch Processing...' : `Execute Bulk Scan (${validIps.length})`}
          </button>
        </div>
      )}
    </div>
  );
};
