import React from 'react';
import { motion } from 'framer-motion';
import { Bot, ShieldAlert, AlertCircle, CheckCircle2, Cpu, Zap, ArrowRight } from 'lucide-react';

export default function ExecutiveSummary({ summary }) {
  const defaultSummary = summary || 'ANISAS AI Risk Engine evaluated target 187.245.231.228 (AS13999 - Mega Cable, S.A. de C.V.). The host is classified as a "SURVEILLANCE_CAMERA_NVR" running Linux 5.4.0 x86_64 / Nginx Edge Proxy with an overall Risk Score of 80/100 (CRITICAL Risk). Security Perimeter audit confirmed active protection via Direct Origin Access (No WAF Header on 187.245.231.228) (Security Score 41/100).';

  const threats = [
    'Exposed Management Service on Port 80 (HTTP Plaintext Management Interface)',
    'Potential Off-Hours Data Burst on IoT Camera (Continuous RTSP Stream Traffic)',
    'CVE Vulnerability Correlation matches for Linux 5.4.0 x86_64 Kernel & Nginx Edge Proxy'
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45 }}
      className="glass-card p-6 border border-slate-800/80 shadow-2xl space-y-5 relative overflow-hidden"
    >
      {/* Background Accent Shimmer */}
      <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-purple-500 via-cyan-400 to-rose-500" />

      {/* Header */}
      <div className="flex items-center space-x-3 pb-3 border-b border-slate-800/80">
        <div className="p-2.5 bg-purple-500/10 rounded-xl border border-purple-500/30 text-purple-400">
          <Bot className="w-6 h-6 animate-pulse" />
        </div>
        <div>
          <h3 className="text-base font-extrabold tracking-tight text-slate-100 uppercase font-mono flex items-center space-x-2">
            <span>AI Risk Engine — Executive Summary</span>
            <span className="text-xs px-2.5 py-0.5 bg-purple-500/10 text-purple-300 border border-purple-500/30 rounded font-mono font-normal">
              Module 05 Heuristics
            </span>
          </h3>
          <p className="text-xs text-slate-400 font-mono">
            Autonomous Machine Intelligence Narrative Synthesis
          </p>
        </div>
      </div>

      {/* Executive Summary Body Text */}
      <div className="bg-slate-900/90 rounded-2xl p-5 border border-slate-800/80 font-sans text-xs md:text-sm text-slate-300 leading-relaxed space-y-3 relative shadow-inner">
        <p className="font-mono text-slate-200">
          {defaultSummary}
        </p>
      </div>

      {/* Key Threats Checklist */}
      <div className="space-y-2">
        <h4 className="text-xs font-bold font-mono text-slate-300 uppercase tracking-wider flex items-center space-x-2">
          <ShieldAlert className="w-4 h-4 text-rose-400" />
          <span>Top Identified Threat Vectors:</span>
        </h4>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {threats.map((threat, idx) => (
            <motion.div
              key={idx}
              whileHover={{ y: -2 }}
              className="bg-rose-950/20 rounded-xl p-3.5 border border-rose-500/30 flex items-start space-x-3 text-xs font-mono text-rose-300 shadow-md"
            >
              <AlertCircle className="w-4 h-4 text-rose-400 flex-shrink-0 mt-0.5" />
              <span className="leading-snug">{threat}</span>
            </motion.div>
          ))}
        </div>
      </div>

    </motion.div>
  );
}
