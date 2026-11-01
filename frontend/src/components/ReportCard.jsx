import React from 'react';
import { motion } from 'framer-motion';
import { Search, Globe, ShieldAlert, Cpu, Server, MapPin, Building2, Lock, Radio } from 'lucide-react';

export default function ReportCard({ report }) {
  const data = report || {
    ip: '187.245.231.228',
    organization: 'Mega Cable, S.A. de C.V.',
    asn: 'AS13999',
    cidr: '187.245.231.0/24',
    registry: 'ARIN',
    country: 'Mexico (MX)',
    location: 'Tuxtla Gutiérrez, Chiapas',
    coordinates: '16.7387, -93.1414',
    security_score: 41,
    waf_status: 'Unprotected Origin',
    ai_detection: 45,
    device_type: 'SURVEILLANCE_CAMERA_NVR',
    confidence: 98.5,
    os: 'Linux 5.4.0 x86_64 / Nginx Edge Proxy',
    risk_score: 80,
    risk_level: 'CRITICAL',
  };

  return (
    <motion.div 
      initial={{ opacity: 0, scale: 0.98 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.4 }}
      className="glass-card p-6 border border-slate-800/80 shadow-2xl space-y-6 relative overflow-hidden"
    >
      {/* Glow Background Accent */}
      <div className="absolute top-0 right-0 w-80 h-80 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center pb-4 border-b border-slate-800/80 gap-2">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-gradient-to-br from-cyan-500/20 to-blue-500/10 rounded-xl border border-cyan-500/30 text-cyan-400">
            <Search className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-extrabold tracking-tight text-slate-100 uppercase font-mono flex items-center space-x-2">
              <span>Target Intelligence Report</span>
              <span className="text-xs px-2 py-0.5 bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 rounded font-normal font-sans">
                Module 01 - 07 Synchronized
              </span>
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              Target Host IP: <span className="text-cyan-300 font-bold">{data.ip}</span>
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <span className="px-3 py-1 bg-rose-500/10 text-rose-400 border border-rose-500/30 rounded-lg text-xs font-mono font-bold flex items-center space-x-1.5">
            <ShieldAlert className="w-4 h-4" />
            <span>RISK SCORE: {data.risk_score}/100 {data.risk_level}</span>
          </span>
        </div>
      </div>

      {/* Grid of 3 Intelligence Sub-Panels */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        
        {/* Panel 1: ASN & BGP Network Identity */}
        <div className="bg-slate-900/80 rounded-2xl p-4 border border-slate-800/80 space-y-3 hover:border-slate-700/80 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider flex items-center space-x-2">
              <Globe className="w-4 h-4" />
              <span>ASN & GeoIP Intel</span>
            </span>
            <span className="text-[10px] text-slate-500 font-mono">M01 Profile</span>
          </div>

          <div className="space-y-2 text-xs font-mono">
            <div>
              <span className="text-slate-500 block text-[10px]">ORGANIZATION</span>
              <span className="text-slate-200 font-semibold">{data.organization}</span>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <span className="text-slate-500 block text-[10px]">ASN NUMBER</span>
                <span className="text-cyan-300 font-bold">{data.asn}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">CIDR RANGE</span>
                <span className="text-slate-300">{data.cidr}</span>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <span className="text-slate-500 block text-[10px]">REGISTRY</span>
                <span className="text-slate-300">{data.registry}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">COUNTRY / LOC</span>
                <span className="text-slate-300 truncate">{data.country}</span>
              </div>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px]">CITY / COORDINATES</span>
              <span className="text-slate-400 flex items-center space-x-1">
                <MapPin className="w-3 h-3 text-cyan-400 inline" />
                <span>{data.location} ({data.coordinates})</span>
              </span>
            </div>
          </div>
        </div>

        {/* Panel 2: Security Perimeter & WAF Audit */}
        <div className="bg-slate-900/80 rounded-2xl p-4 border border-slate-800/80 space-y-3 hover:border-slate-700/80 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-amber-400 font-bold uppercase tracking-wider flex items-center space-x-2">
              <Lock className="w-4 h-4" />
              <span>Perimeter Posture</span>
            </span>
            <span className="text-[10px] text-slate-500 font-mono">M03 WAF</span>
          </div>

          <div className="space-y-3 text-xs font-mono">
            <div>
              <span className="text-slate-500 block text-[10px]">SECURITY POSTURE SCORE</span>
              <div className="flex items-center space-x-2 mt-1">
                <div className="text-lg font-bold text-amber-400">{data.security_score}/100</div>
                <span className="px-2 py-0.5 bg-amber-500/20 text-amber-400 border border-amber-500/30 rounded text-[10px] font-bold uppercase">
                  WEAK POSTURE ⚠️
                </span>
              </div>
            </div>

            <div>
              <span className="text-slate-500 block text-[10px]">WAF ENFORCEMENT</span>
              <span className="text-rose-400 font-bold flex items-center space-x-1.5 mt-0.5">
                <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
                <span>{data.waf_status}</span>
              </span>
            </div>

            <div>
              <span className="text-slate-500 block text-[10px]">BOT / AI PROBING RESILIENCE</span>
              <div className="w-full h-2 bg-slate-950 rounded-full mt-1.5 overflow-hidden border border-slate-800">
                <div 
                  className="h-full bg-gradient-to-r from-amber-500 to-rose-500 rounded-full" 
                  style={{ width: `${data.ai_detection}%` }} 
                />
              </div>
              <span className="text-[10px] text-slate-400 block mt-1">AI Probing Score: {data.ai_detection}%</span>
            </div>
          </div>
        </div>

        {/* Panel 3: Device Type & Hardware Classification */}
        <div className="bg-slate-900/80 rounded-2xl p-4 border border-slate-800/80 space-y-3 hover:border-slate-700/80 transition">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-purple-400 font-bold uppercase tracking-wider flex items-center space-x-2">
              <Cpu className="w-4 h-4" />
              <span>Asset Fingerprint</span>
            </span>
            <span className="text-[10px] text-slate-500 font-mono">M04 Telemetry</span>
          </div>

          <div className="space-y-2 text-xs font-mono">
            <div>
              <span className="text-slate-500 block text-[10px]">HEURISTIC DEVICE TYPE</span>
              <span className="text-purple-300 font-bold text-xs block truncate mt-0.5">
                {data.device_type}
              </span>
              <span className="text-[10px] text-emerald-400 font-semibold">
                ({data.confidence}% ML Confidence)
              </span>
            </div>

            <div>
              <span className="text-slate-500 block text-[10px]">OPERATING SYSTEM & PROXY</span>
              <span className="text-slate-300 block text-xs truncate mt-0.5">
                {data.os}
              </span>
            </div>

            <div>
              <span className="text-slate-500 block text-[10px]">CRITICALITY RATING</span>
              <span className="inline-block mt-1 px-2.5 py-1 bg-rose-500/20 text-rose-300 border border-rose-500/40 rounded-lg text-xs font-bold">
                80/100 CRITICAL RISK
              </span>
            </div>
          </div>
        </div>

      </div>
    </motion.div>
  );
}
