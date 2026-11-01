import React from 'react';
import { Shield, Cloud, ShieldAlert, Brain, ArrowRight, UserShield, Network, GraduationCap } from 'lucide-react';

export default function Module3View({ onNavigate }) {
  return (
    <div className="space-y-6 font-mono text-xs">
      
      {/* Module Header */}
      <div className="soc-card p-6 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="text-xs text-[#10B981] font-bold uppercase tracking-wider">
            MODULE 03 • SECURITY PERIMETER DETECTION ENGINE
          </div>
          <h1 className="text-2xl font-black text-white tracking-wide mt-1 font-sans">
            Perimeter Defense, WAF & Posture Analysis
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-sans">
            Consumes Module 01 & 02 intelligence to detect WAFs, Next-Gen Firewalls, IDS/IPS signatures, DMZ boundaries, and AI Scan Detection Likelihood.
          </p>
        </div>
        <button
          onClick={() => onNavigate('module4')}
          className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-amber-500 to-orange-600 hover:from-amber-400 hover:to-orange-500 text-white font-black text-xs tracking-wider uppercase flex items-center space-x-2 shadow-lg shadow-amber-500/20 transition cursor-pointer shrink-0"
        >
          <span>VIEW MODULE 04 SURVEILLANCE & IOT</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>

      {/* 2x2 Metric Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-2 gap-4">
        
        {/* Card 1: SECURITY POSTURE SCORE */}
        <div className="soc-card p-5 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-[11px] uppercase tracking-wider">
            <span>SECURITY POSTURE SCORE</span>
            <Shield className="w-4 h-4 text-[#10B981]" />
          </div>
          <div className="flex items-baseline space-x-3">
            <div className="text-3xl font-black text-[#10B981]">41/100</div>
            <span className="px-2.5 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/40 text-[10px] font-extrabold uppercase">
              WEAK
            </span>
          </div>
          <div className="text-xs text-slate-400">Overall Perimeter Defense</div>
        </div>

        {/* Card 2: WAF VENDOR */}
        <div className="soc-card p-5 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-[11px] uppercase tracking-wider">
            <span>WAF VENDOR</span>
            <Cloud className="w-4 h-4 text-[#00F0FF]" />
          </div>
          <div className="text-xs md:text-sm font-bold text-[#00F0FF] truncate">
            Direct Origin Access (No WAF Header...)
          </div>
          <div className="text-xs text-slate-400">Status: UNPROTECTED_ORIGIN</div>
        </div>

        {/* Card 3: NEXT-GEN FIREWALL */}
        <div className="soc-card p-5 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-[11px] uppercase tracking-wider">
            <span>NEXT-GEN FIREWALL</span>
            <ShieldAlert className="w-4 h-4 text-[#FFB800]" />
          </div>
          <div className="text-xs md:text-sm font-bold text-[#FFB800] truncate">
            Perimeter Firewall (Mega Cable, S.A...)
          </div>
          <div className="text-xs text-slate-400">Confidence: 95%</div>
        </div>

        {/* Card 4: AI DETECTION LIKELIHOOD */}
        <div className="soc-card p-5 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-[11px] uppercase tracking-wider">
            <span>AI DETECTION LIKELIHOOD</span>
            <Brain className="w-4 h-4 text-[#A855F7]" />
          </div>
          <div className="text-3xl font-black text-rose-400">45%</div>
          <div className="text-xs text-slate-400">Probability SOC Detects Scan</div>
        </div>

      </div>

      {/* EXECUTIVE SECURITY RECOMMENDATIONS Panel */}
      <div className="soc-card p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
          <h3 className="text-xs font-extrabold text-white uppercase tracking-wider flex items-center space-x-2">
            <UserShield className="w-4 h-4 text-[#00F0FF]" />
            <span>EXECUTIVE SECURITY RECOMMENDATIONS</span>
          </h3>
          <span className="text-xs text-[#FFB800] font-bold uppercase tracking-wider">
            Hardening Action Plan
          </span>
        </div>

        <div className="space-y-3">
          {/* Action Card 1 */}
          <div className="soc-card p-4 space-y-2">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-bold text-white">Deploy Content-Security-Policy (CSP) on 187.245.231.228</h4>
              <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/40 text-[10px] font-extrabold">
                HIGH
              </span>
            </div>
            <p className="text-[11px] text-slate-300">Live HTTP header inspection detected missing Content-Security-Policy on 187.245.231.228.</p>
            <div className="text-[11px] text-[#00F0FF]">
              Remediation: Configure web server to emit Content-Security-Policy: default-src 'self' https:.
            </div>
          </div>

          {/* Action Card 2 */}
          <div className="soc-card p-4 space-y-2">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-bold text-white">Attach Web Application Firewall (WAF) to 187.245.231.228</h4>
              <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/40 text-[10px] font-extrabold">
                HIGH
              </span>
            </div>
            <p className="text-[11px] text-slate-300">No edge WAF headers detected for target host 187.245.231.228.</p>
            <div className="text-[11px] text-[#00F0FF]">
              Remediation: Deploy Cloudflare Armor, AWS WAF, or Nginx ModSecurity to inspect inbound HTTP traffic.
            </div>
          </div>
        </div>
      </div>

      {/* BOUNDARY & IDS TOPOLOGY Panel */}
      <div className="soc-card p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
          <h3 className="text-xs font-extrabold text-white uppercase tracking-wider flex items-center space-x-2">
            <Network className="w-4 h-4 text-[#10B981]" />
            <span>BOUNDARY & IDS TOPOLOGY</span>
          </h3>
        </div>

        <div className="space-y-3 font-mono text-xs">
          {/* DMZ Segment Box */}
          <div className="soc-card p-4 space-y-1">
            <div className="text-slate-400 text-[11px]">DMZ Segment:</div>
            <div className="text-[#10B981] font-bold text-xs">PUBLIC_DMZ_SEGMENT</div>
            <div className="text-slate-500 text-[10px]">Gateway: gateway-187.245.231.1</div>
          </div>

          {/* IDS / IPS Vendor Box */}
          <div className="soc-card p-4 space-y-1">
            <div className="text-slate-400 text-[11px]">IDS / IPS Vendor:</div>
            <div className="text-[#00F0FF] font-bold text-xs">Suricata / Snort Enterprise IDS (Mega Cable, S.A. de C.V.)</div>
            <div className="text-slate-500 text-[10px]">Detection: SIGNATURE_AND_BEHAVIORAL_INSPECTION</div>
          </div>
        </div>

        {/* Educational Footer */}
        <div className="pt-3 text-slate-400 text-[11px] flex items-center space-x-2 border-t border-[#1E293B]/60 mt-4">
          <GraduationCap className="w-4 h-4 text-[#00F0FF]" />
          <span className="font-bold text-white">Defensive Awareness Guide</span>
          <span className="text-slate-500">— Educational reference detailing Chunked Encoding and TCP Segment Manipulation for perimeter defender hardening ONLY.</span>
        </div>
      </div>

    </div>
  );
}
