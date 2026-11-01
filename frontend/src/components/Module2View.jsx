import React from 'react';
import { Server, Plug, Globe, Sun, ArrowRight, ShieldCheck } from 'lucide-react';

export default function Module2View({ onNavigate }) {
  return (
    <div className="space-y-6 font-mono text-xs">
      
      {/* Module Header */}
      <div className="soc-card p-6 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="text-xs text-[#00F0FF] font-bold uppercase tracking-wider">
            MODULE 02 • NETWORK RECONNAISSANCE OUTPUT
          </div>
          <h1 className="text-2xl font-black text-white tracking-wide mt-1 font-sans">
            Network Discovery & Inventory
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-sans">
            Consumes Module 01 ASN data automatically to discover Subnets, Live Hosts, Open Ports, Service Banners, DNS Records, and TLS Certificates.
          </p>
        </div>
        <button
          onClick={() => onNavigate('module3')}
          className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-white font-black text-xs tracking-wider uppercase flex items-center space-x-2 shadow-lg shadow-emerald-500/20 transition cursor-pointer shrink-0"
        >
          <span>VIEW MODULE 03 PERIMETER INTELLIGENCE</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>

      {/* 2x2 Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        
        <div className="soc-card p-5 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-[11px] uppercase tracking-wider">
            <span>DISCOVERED HOSTS</span>
            <Server className="w-4 h-4 text-[#00F0FF]" />
          </div>
          <div className="text-2xl font-black text-[#00F0FF] tracking-tight">1 Live Hosts</div>
          <div className="text-xs text-slate-400">Linux / Cisco Gateways</div>
        </div>

        <div className="soc-card p-5 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-[11px] uppercase tracking-wider">
            <span>OPEN PORTS & SERVICES</span>
            <Plug className="w-4 h-4 text-[#10B981]" />
          </div>
          <div className="text-2xl font-black text-[#10B981] tracking-tight">2 Open Ports</div>
          <div className="text-xs text-slate-400">HTTP, HTTPS, SSH</div>
        </div>

        <div className="soc-card p-5 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-[11px] uppercase tracking-wider">
            <span>DNS & SUBDOMAINS</span>
            <Globe className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-black text-blue-400 tracking-tight">6 DNS Records</div>
          <div className="text-xs text-slate-400">3 Passive Subdomains</div>
        </div>

        <div className="soc-card p-5 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-[11px] uppercase tracking-wider">
            <span>TLS CERTIFICATE</span>
            <Sun className="w-4 h-4 text-[#FFB800]" />
          </div>
          <div className="text-2xl font-black text-[#FFB800] tracking-tight">TLSv1.3 Valid</div>
          <div className="text-xs text-slate-400">DigiCert Global CA</div>
        </div>

      </div>

      {/* Discovered Service Banners & Open Ports Table */}
      <div className="soc-card p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
          <h3 className="text-xs font-extrabold text-white uppercase tracking-wider flex items-center space-x-2">
            <ShieldCheck className="w-4 h-4 text-[#00F0FF]" />
            <span>DISCOVERED SERVICE BANNERS & OPEN PORTS</span>
          </h3>
          <span className="text-xs text-[#10B981] font-bold flex items-center space-x-1.5">
            <span className="w-2 h-2 rounded-full bg-[#10B981] animate-ping" />
            <span>Live Socket Banner Probe</span>
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-[#1E293B] text-slate-500 uppercase text-[10px]">
                <th className="py-3 px-4">PORT / PROTOCOL</th>
                <th className="py-3 px-4">SERVICE</th>
                <th className="py-3 px-4">STATE</th>
                <th className="py-3 px-4">SERVICE BANNER</th>
                <th className="py-3 px-4">PRODUCT</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E293B]/60 text-slate-300">
              <tr className="hover:bg-slate-900/50 transition">
                <td className="py-3.5 px-4 text-[#00F0FF] font-bold">80 / TCP</td>
                <td className="py-3.5 px-4 font-bold text-white">HTTP</td>
                <td className="py-3.5 px-4 font-bold">
                  <span className="px-2.5 py-0.5 rounded bg-[#00F0FF]/20 text-[#00F0FF] border border-[#00F0FF]/40 text-[10px]">
                    OPEN
                  </span>
                </td>
                <td className="py-3.5 px-4 text-slate-300 font-mono text-[11px]">
                  Live Shodan Telemetry: Open HTTP Port 80
                </td>
                <td className="py-3.5 px-4 text-slate-400 text-[11px]">
                  Discovered Service (187.245.231.228:80)
                </td>
              </tr>

              <tr className="hover:bg-slate-900/50 transition">
                <td className="py-3.5 px-4 text-[#00F0FF] font-bold">8000 / TCP</td>
                <td className="py-3.5 px-4 font-bold text-white">DB-SERVICE</td>
                <td className="py-3.5 px-4 font-bold">
                  <span className="px-2.5 py-0.5 rounded bg-[#00F0FF]/20 text-[#00F0FF] border border-[#00F0FF]/40 text-[10px]">
                    OPEN
                  </span>
                </td>
                <td className="py-3.5 px-4 text-slate-300 font-mono text-[11px]">
                  Live Shodan Telemetry: Open DB-SERVICE Port...
                </td>
                <td className="py-3.5 px-4 text-slate-400 text-[11px]">
                  Discovered Service (187.245.231.228:8000)
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}
