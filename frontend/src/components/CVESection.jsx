import React from 'react';
import { motion } from 'framer-motion';
import { AlertTriangle, ShieldAlert, CheckCircle, ExternalLink, Zap } from 'lucide-react';

export default function CVESection({ cves }) {
  const list = cves && cves.length > 0 ? cves : [
    {
      id: 'CVE-2023-0016',
      description: 'MDS2: Network Access Control (NAC) Authentication Bypass',
      status: 'Inactive',
      cvss: 9.8,
      severity: 'CRITICAL',
    }
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35 }}
      className="glass-card p-6 border border-slate-800/80 shadow-2xl space-y-4 relative overflow-hidden"
    >
      <div className="flex justify-between items-center pb-3 border-b border-slate-800/80">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400">
            <AlertTriangle className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <h3 className="text-sm font-bold tracking-wider text-slate-100 uppercase font-mono flex items-center space-x-2">
              <span>Vulnerability Correlations</span>
              <span className="text-[10px] px-2 py-0.5 bg-rose-500/10 text-rose-400 border border-rose-500/20 rounded font-normal font-mono">
                M05 AI Correlation Engine
              </span>
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              Version-Specific Firmware CVE Matching
            </p>
          </div>
        </div>
        <span className="text-xs font-mono text-rose-400 font-bold">
          {list.length} CVE Correlated
        </span>
      </div>

      <div className="space-y-3">
        {list.map((cve, idx) => (
          <motion.div
            key={idx}
            whileHover={{ scale: 1.01 }}
            className="bg-slate-900/90 rounded-2xl p-4 border border-rose-500/30 shadow-lg relative overflow-hidden group space-y-3"
          >
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2">
              <div className="flex items-center space-x-2">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-ping" />
                <span className="text-sm font-extrabold font-mono text-rose-400">
                  {cve.id}
                </span>
                <span className="text-xs text-slate-300 font-semibold font-mono">
                  — {cve.description}
                </span>
              </div>

              <div className="flex items-center space-x-2 font-mono text-xs">
                <span className="px-2.5 py-0.5 bg-slate-800 text-slate-400 border border-slate-700 rounded-md">
                  Status: <strong className="text-slate-200">{cve.status}</strong>
                </span>
                <span className="px-2.5 py-0.5 bg-rose-500/20 text-rose-300 border border-rose-500/40 rounded-md font-bold">
                  CVSS {cve.cvss} ({cve.severity})
                </span>
              </div>
            </div>

            <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800 text-xs font-mono text-slate-400 flex justify-between items-center">
              <span>NVD Correlation: Unverified version-match suppressed per Rule 3 Firmware Integrity.</span>
              <a 
                href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                target="_blank"
                rel="noreferrer"
                className="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 text-[11px] font-semibold"
              >
                <span>NVD Database</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </motion.div>
        ))}
      </div>
    </motion.div>
  );
}
