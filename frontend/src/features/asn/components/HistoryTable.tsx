import React, { useState } from 'react';
import { ScanHistoryItem } from '../../../types/asn';
import { Search, Download, Trash2, ChevronRight, Filter } from 'lucide-react';

interface HistoryTableProps {
  history: ScanHistoryItem[];
  onSelectScan: (scanId: string) => void;
  onDeleteScan: (scanId: string) => void;
}

export const HistoryTable: React.FC<HistoryTableProps> = ({ history, onSelectScan, onDeleteScan }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterRisk, setFilterRisk] = useState<string>('ALL');

  const filtered = history.filter((item) => {
    const matchesSearch = item.targetIp.includes(searchTerm) || item.summary.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesRisk = filterRisk === 'ALL' || item.riskLevel === filterRisk;
    return matchesSearch && matchesRisk;
  });

  return (
    <div className="glass-panel p-6 rounded-xl border border-slate-800 space-y-4">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h3 className="text-base font-bold text-white">ASN Pipeline Scan History</h3>
          <p className="text-xs text-slate-400">Recorded scans stored in PostgreSQL database</p>
        </div>

        <div className="flex items-center gap-3">
          {/* Search */}
          <div className="relative w-48">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search IP / ASN..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          {/* Risk Filter */}
          <select
            value={filterRisk}
            onChange={(e) => setFilterRisk(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Risks</option>
            <option value="LOW">Low Risk</option>
            <option value="MEDIUM">Medium Risk</option>
            <option value="HIGH">High Risk</option>
            <option value="CRITICAL">Critical Risk</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
              <th className="py-3 px-4">Target IP</th>
              <th className="py-3 px-4">Summary</th>
              <th className="py-3 px-4">Threat Score</th>
              <th className="py-3 px-4">Timestamp</th>
              <th className="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={5} className="text-center py-8 text-slate-500">
                  No scan history records found matching criteria.
                </td>
              </tr>
            ) : (
              filtered.map((item) => (
                <tr key={item.id} className="hover:bg-slate-900/50 transition cursor-pointer" onClick={() => onSelectScan(item.scanId)}>
                  <td className="py-3.5 px-4 font-mono font-bold text-cyan-400">{item.targetIp}</td>
                  <td className="py-3.5 px-4 text-slate-300">{item.summary}</td>
                  <td className="py-3.5 px-4">
                    <span className={`px-2 py-0.5 rounded font-mono font-bold text-[10px] ${
                      item.riskLevel === 'HIGH' || item.riskLevel === 'CRITICAL'
                        ? 'bg-rose-500/20 text-rose-400'
                        : 'bg-emerald-500/20 text-emerald-400'
                    }`}>
                      {item.riskScore}/100 ({item.riskLevel})
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-slate-500 font-mono">
                    {new Date(item.timestamp).toLocaleString()}
                  </td>
                  <td className="py-3.5 px-4 text-right">
                    <div className="flex items-center justify-end gap-2" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => onSelectScan(item.scanId)}
                        className="p-1.5 rounded hover:bg-slate-800 text-cyan-400"
                        title="View Full ASN Profile"
                      >
                        <ChevronRight className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => onDeleteScan(item.scanId)}
                        className="p-1.5 rounded hover:bg-rose-500/20 text-slate-500 hover:text-rose-400"
                        title="Delete Scan Record"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
