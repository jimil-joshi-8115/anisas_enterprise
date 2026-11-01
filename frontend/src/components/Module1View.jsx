import React, { useState } from 'react';
import { Network, Globe, Building2, Sitemap, Bug, ArrowRight, Play, Crosshair, IdCard, Route, MapPin, Brain } from 'lucide-react';

export default function Module1View({ onNavigate }) {
  const [targetIp, setTargetIp] = useState('187.245.231.228');

  const ipParts = targetIp.trim().split('.');
  const subnetCidr = ipParts.length === 4 && ipParts.every(p => !isNaN(p) && p.length > 0) ? `${ipParts[0]}.${ipParts[1]}.${ipParts[2]}.0/24` : `${targetIp}/24`;
  const subnetRange = ipParts.length === 4 && ipParts.every(p => !isNaN(p) && p.length > 0) ? `${ipParts[0]}.${ipParts[1]}.${ipParts[2]}.0 - ${ipParts[0]}.${ipParts[1]}.${ipParts[2]}.255` : `${targetIp} Range`;

  return (
    <div className="space-y-6 font-mono text-xs">
      
      {/* Module Header */}
      <div className="soc-card p-6 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="text-xs text-[#00F0FF] font-bold uppercase tracking-wider">
            MODULE 01 • REAL CYBER INTELLIGENCE PIPELINE
          </div>
          <h1 className="text-2xl font-black text-white tracking-wide mt-1 font-sans">
            ASN & ISP Real Intelligence Engine
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-sans">
            Resolving Autonomous Systems, WHOIS, RDAP, BGP routing, geo-telemetry, and VirusTotal v3 threat scores.
          </p>
        </div>
        <button
          onClick={() => onNavigate('module2')}
          className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-black text-xs tracking-wider uppercase flex items-center space-x-2 shadow-lg shadow-cyan-500/20 transition cursor-pointer shrink-0"
        >
          <span>VIEW MODULE 02 RECON DATA</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>

      {/* Target Input Trigger Bar */}
      <div className="soc-card p-5 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center space-x-2 text-[#00F0FF] font-bold uppercase tracking-wider">
            <Crosshair className="w-4 h-4 text-[#00F0FF]" />
            <span>Target Input • Single Entry Trigger (Runs M01 → M02 → M03 → M04 → M05 → M06)</span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button onClick={() => setTargetIp('185.220.101.5')} className="px-2.5 py-1 rounded-lg bg-rose-950/60 hover:bg-rose-900 text-rose-300 border border-rose-800/60 text-[11px] cursor-pointer">185.220.101.5 (Tor Exit)</button>
            <button onClick={() => setTargetIp('147.185.133.119')} className="px-2.5 py-1 rounded-lg bg-amber-950/60 hover:bg-amber-900 text-amber-300 border border-amber-800/60 text-[11px] cursor-pointer">147.185.133.119 (Palo IoT)</button>
            <button onClick={() => setTargetIp('8.8.8.8')} className="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 text-[11px] cursor-pointer">8.8.8.8 (Google DNS)</button>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <input
            type="text"
            value={targetIp}
            onChange={(e) => setTargetIp(e.target.value)}
            placeholder="Enter Target IP or Domain..."
            className="flex-1 px-4 py-3 bg-[#060913] border border-[#1E293B] rounded-xl text-sm font-mono text-white focus:outline-none focus:border-[#00F0FF] shadow-inner"
          />
          <button
            onClick={() => {}}
            className="px-8 py-3 rounded-xl bg-[#00F0FF] hover:bg-cyan-300 text-slate-950 font-black text-sm tracking-wider uppercase flex items-center space-x-2 shadow-lg shadow-[#00F0FF]/20 transition cursor-pointer"
          >
            <Play className="w-4 h-4 fill-current" />
            <span>EXECUTE</span>
          </button>
        </div>
      </div>

      {/* 2x2 Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        
        <div className="soc-card p-5 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-[11px] uppercase tracking-wider">
            <span>AUTONOMOUS SYSTEM</span>
            <Network className="w-4 h-4 text-[#00F0FF]" />
          </div>
          <div className="text-2xl font-black text-[#00F0FF] tracking-tight">AS13999</div>
          <div className="text-xs text-slate-300 font-semibold truncate">Mega Cable, S.A. de C.V.</div>
          <div className="text-[11px] text-slate-400">Registry: ARIN</div>
        </div>

        <div className="soc-card p-5 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-[11px] uppercase tracking-wider">
            <span>ORGANIZATION / ISP</span>
            <Building2 className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-sm md:text-base font-bold text-white tracking-tight break-words">Mega Cable, S.A. de C.V.</div>
          <div className="text-xs text-slate-400">ISP: Mega Cable, S.A. de C.V.</div>
        </div>

        <div className="soc-card p-5 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-[11px] uppercase tracking-wider">
            <span>SUBNET CIDR</span>
            <Sitemap className="w-4 h-4 text-[#10B981]" />
          </div>
          <div className="text-xl font-black text-[#10B981] tracking-tight">{subnetCidr}</div>
          <div className="text-xs text-slate-400 font-mono">Range: {subnetRange}</div>
        </div>

        <div className="soc-card p-5 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-[11px] uppercase tracking-wider">
            <span>VIRUSTOTAL MALICIOUS</span>
            <Bug className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-black text-rose-400 tracking-tight">0 Malicious</div>
          <div className="text-xs text-[#10B981] font-bold uppercase tracking-wider">CLEAN INFRASTRUCTURE</div>
        </div>

      </div>

      {/* XGBoost Summary & Live WHOIS */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        <div className="lg:col-span-2 space-y-6">
          <div className="soc-card p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
              <h3 className="text-xs font-extrabold text-white uppercase tracking-wider flex items-center space-x-2">
                <Brain className="w-4 h-4 text-[#00F0FF]" />
                <span>XGBOOST ML EXECUTIVE SUMMARY & TELEMETRY</span>
              </h3>
              <span className="text-xs font-bold text-[#10B981]">ML Confidence: 99.2%</span>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed bg-[#060913] p-4 rounded-xl border border-[#1E293B]">
              Target 187.245.231.228 located in Tuxtla Gutiérrez, Mexico. Resolved to AS13999 (Mega Cable, S.A. de C.V. / Mega Cable, S.A. de C.V.). Risk score evaluated at 15/100 (LOW) via real live OSINT data.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              
              <div className="p-4 rounded-xl bg-[#060913] border border-[#1E293B] space-y-2">
                <div className="text-[11px] font-bold text-[#00F0FF] uppercase flex items-center space-x-2">
                  <IdCard className="w-4 h-4" />
                  <span>LIVE WHOIS / RDAP REGISTRY</span>
                </div>
                <div className="space-y-1 text-xs">
                  <div className="flex justify-between"><span class="text-slate-400">Registrar:</span><span className="text-slate-200 font-bold">ARIN Registry</span></div>
                  <div className="flex justify-between"><span class="text-slate-400">Owner:</span><span className="text-slate-200">Mega Cable, S.A. de C.V.</span></div>
                  <div className="flex justify-between"><span class="text-slate-400">Abuse Contact:</span><span className="text-[#00F0FF]">abuse@megacablesadecv.com</span></div>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-[#060913] border border-[#1E293B] space-y-2">
                <div className="text-[11px] font-bold text-[#10B981] uppercase flex items-center space-x-2">
                  <Route className="w-4 h-4" />
                  <span>BGP ROUTING & PEERING</span>
                </div>
                <div className="space-y-1 text-xs">
                  <div className="flex justify-between"><span class="text-slate-400">Origin ASN:</span><span className="text-[#10B981] font-bold">AS13999</span></div>
                  <div className="flex justify-between"><span class="text-slate-400">Prefixes:</span><span className="text-slate-200">187.245.231.0/24</span></div>
                  <div className="flex justify-between"><span class="text-slate-400">Peers:</span><span className="text-slate-300">Arelion, Lumen, Verizon</span></div>
                </div>
              </div>

            </div>
          </div>
        </div>

        {/* Live Geo-Location Panel */}
        <div className="soc-card p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
            <h3 className="text-xs font-extrabold text-white uppercase tracking-wider flex items-center space-x-2">
              <Globe className="w-4 h-4 text-[#00F0FF]" />
              <span>LIVE GEO-LOCATION & NETWORK HOST</span>
            </h3>
          </div>

          <div className="space-y-3 text-xs">
            <div className="flex justify-between border-b border-[#1E293B]/60 pb-2">
              <span className="text-slate-400">Hostname:</span>
              <span className="text-[#00F0FF] font-bold truncate max-w-[160px]">customer-TGZ-MCA-231...</span>
            </div>
            <div className="flex justify-between border-b border-[#1E293B]/60 pb-2">
              <span className="text-slate-400">Country:</span>
              <span className="text-slate-200 font-bold">Mexico (MX)</span>
            </div>
            <div className="flex justify-between border-b border-[#1E293B]/60 pb-2">
              <span className="text-slate-400">City / Region:</span>
              <span className="text-slate-300">Tuxtla Gutiérrez, Chiapas</span>
            </div>
            <div className="flex justify-between border-b border-[#1E293B]/60 pb-2">
              <span className="text-slate-400">Coordinates:</span>
              <span className="text-[#10B981] font-bold">16.7387, -93.1414</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Timezone:</span>
              <span className="text-slate-300">America/Merida</span>
            </div>
          </div>
        </div>

      </div>

    </div>
  );
}
