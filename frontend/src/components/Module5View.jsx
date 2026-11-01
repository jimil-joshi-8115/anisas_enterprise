import React from 'react';
import { ShieldAlert, AlertTriangle, ArrowRight, Brain, Zap } from 'lucide-react';

export default function Module5View({ onNavigate }) {
  return (
    <div className="space-y-6 font-mono text-xs">
      
      {/* Module Header */}
      <div className="soc-card p-6 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="text-xs text-[#A855F7] font-bold uppercase tracking-wider">
            MODULE 05 • AI RISK ENGINE & HEURISTIC CLASSIFIER
          </div>
          <h1 className="text-2xl font-black text-white tracking-wide mt-1 font-sans">
            AI Threat Posture & Risk Classifier
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-sans">
            Evaluates open ports, CVEs, WAF posture, and TLS expiry to generate overall 0-100 Risk Score and executive recommendations.
          </p>
        </div>
        <button
          onClick={() => onNavigate('module6')}
          className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-teal-500 to-cyan-600 hover:from-teal-400 hover:to-cyan-500 text-white font-black text-xs tracking-wider uppercase flex items-center space-x-2 shadow-lg shadow-teal-500/20 transition cursor-pointer shrink-0"
        >
          <span>VIEW MODULE 06 UNIFIED SOC</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>

      {/* 2x2 Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="soc-card p-5 space-y-2">
          <div className="text-slate-400 text-[11px] uppercase tracking-wider flex justify-between">
            <span>OVERALL RISK SCORE</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-3xl font-black text-rose-400">80/100</div>
          <div className="text-xs text-rose-400 font-bold">CRITICAL RISK</div>
        </div>

        <div className="soc-card p-5 space-y-2">
          <div className="text-slate-400 text-[11px] uppercase tracking-wider flex justify-between">
            <span>AI HEURISTIC MODEL</span>
            <Brain className="w-4 h-4 text-[#A855F7]" />
          </div>
          <div className="text-2xl font-black text-[#A855F7]">XGBoost v3</div>
          <div className="text-xs text-slate-400">99.2% Prediction Accuracy</div>
        </div>

        <div className="soc-card p-5 space-y-2">
          <div className="text-slate-400 text-[11px] uppercase tracking-wider flex justify-between">
            <span>EXPOSED VECTORS</span>
            <AlertTriangle className="w-4 h-4 text-[#FFB800]" />
          </div>
          <div className="text-2xl font-black text-[#FFB800]">3 Vectors</div>
          <div className="text-xs text-slate-400">HTTP, Camera NVR, CVE-2021-36260</div>
        </div>

        <div className="soc-card p-5 space-y-2">
          <div className="text-slate-400 text-[11px] uppercase tracking-wider flex justify-between">
            <span>REMEDIATION STATUS</span>
            <Zap className="w-4 h-4 text-[#10B981]" />
          </div>
          <div className="text-2xl font-black text-[#10B981]">2 Actions</div>
          <div className="text-xs text-slate-400">CSP Deployment & WAF Attachment</div>
        </div>
      </div>

    </div>
  );
}
