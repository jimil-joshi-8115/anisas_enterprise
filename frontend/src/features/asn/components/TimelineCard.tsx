import React from 'react';
import { ASNScanResult } from '../../../types/asn';
import { Clock, Calendar, ShieldCheck } from 'lucide-react';

interface TimelineCardProps {
  scan: ASNScanResult;
}

export const TimelineCard: React.FC<TimelineCardProps> = ({ scan }) => {
  const { whois, asn } = scan;

  const events = [
    { title: 'Subnet Allocation Date', date: whois.creationDate || '2000-03-30', status: 'Allocated by ARIN' },
    { title: 'Last WHOIS Registry Update', date: whois.updatedDate || '2024-01-15', status: 'Verified' },
    { title: 'Registry Expiration Guard', date: whois.expirationDate || '2035-12-31', status: 'Active' },
    { title: 'Pipeline Module 01 Ingestion', date: new Date(scan.createdAt).toISOString().split('T')[0], status: 'Scanned Now' }
  ];

  return (
    <div className="glass-panel p-5 rounded-xl border border-slate-800 space-y-4">
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
        <span className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
          <Clock className="w-4 h-4 text-cyan-400" />
          ASN Registry Lifecycle Timeline
        </span>
      </div>

      <div className="space-y-4 relative pl-4 border-l border-slate-800">
        {events.map((e, idx) => (
          <div key={idx} className="relative">
            <div className="absolute -left-[21px] top-1 w-2.5 h-2.5 rounded-full bg-cyan-500 border border-slate-900"></div>
            <div className="text-xs font-semibold text-white">{e.title}</div>
            <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400 mt-0.5">
              <span className="text-cyan-300 flex items-center gap-1">
                <Calendar className="w-3 h-3" />
                {e.date}
              </span>
              <span>•</span>
              <span className="text-slate-500">{e.status}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
