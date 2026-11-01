import React from 'react';
import { Shield, Network, Lock, Eye, Cpu, Layers, Share2, Server, Globe } from 'lucide-react';

export default function HeaderTracker({ activeTab, onTabChange }) {
  const modules = [
    { id: 'module1', label: 'M01: ASN Intel', sub: 'Intel', icon: Network, color: 'cyan' },
    { id: 'module2', label: 'M02: Network Recon', sub: 'Recon', icon: Network, color: 'blue' },
    { id: 'module3', label: 'M03: Perimeter Intel', sub: 'Perimeter', icon: Lock, color: 'emerald' },
    { id: 'module4', label: 'M04: Surveillance & IoT', sub: 'IoT', icon: Eye, color: 'amber' },
    { id: 'module5', label: 'M05: AI Risk Engine', sub: 'Engine', icon: Cpu, color: 'purple' },
    { id: 'module6', label: 'M06: Unified SOC', sub: 'SOC', icon: Layers, color: 'teal' },
  ];

  const extraTabs = [
    { id: 'topology', label: 'Topology Graph', icon: Share2 },
    { id: 'services', label: 'Services & Ports', icon: Server },
    { id: 'dns', label: 'DNS & Subdomains', icon: Globe },
  ];

  return (
    <header className="sticky top-0 z-40 bg-[#080C14]/90 border-b border-[#1E293B] px-6 py-3 backdrop-blur-md">
      <div className="max-w-[1700px] mx-auto flex flex-wrap items-center justify-between gap-4">
        
        {/* Left Brand Title Block */}
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 via-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 border border-cyan-400/30">
            <Shield className="w-5 h-5 text-white animate-pulse" />
          </div>
          <div>
            <div className="text-[13px] font-black text-cyan-400 tracking-wider font-mono uppercase">ANISAS</div>
            <div className="text-[11px] font-extrabold text-slate-100 tracking-wide uppercase font-mono">
              ENTERPRISE CYBER SOC PLATFORM PIPELINE TRACKER:
            </div>
          </div>
        </div>

        {/* Horizontal Pipeline Tracker Module Tabs */}
        <div className="flex items-center space-x-2 font-mono text-xs overflow-x-auto py-1">
          {modules.map((m) => {
            const Icon = m.icon;
            const isActive = activeTab === m.id;

            let activeStyles = 'bg-[#0D1322] text-slate-400 border-[#1E293B] hover:border-slate-700';
            if (isActive) {
              if (m.color === 'amber') {
                activeStyles = 'bg-[#FFB800]/15 text-[#FFB800] border-[#FFB800]/60 shadow-lg shadow-[#FFB800]/20 font-bold';
              } else if (m.color === 'emerald') {
                activeStyles = 'bg-[#10B981]/15 text-[#10B981] border-[#10B981]/60 shadow-lg shadow-[#10B981]/20 font-bold';
              } else if (m.color === 'purple') {
                activeStyles = 'bg-[#A855F7]/15 text-[#A855F7] border-[#A855F7]/60 shadow-lg shadow-[#A855F7]/20 font-bold';
              } else {
                activeStyles = 'bg-[#00F0FF]/15 text-[#00F0FF] border-[#00F0FF]/60 shadow-lg shadow-[#00F0FF]/20 font-bold';
              }
            }

            return (
              <div key={m.id} className="flex flex-col items-center">
                <button
                  onClick={() => onTabChange(m.id)}
                  className={`px-3 py-2 rounded-xl border text-[11px] flex items-center space-x-1.5 transition-all duration-200 cursor-pointer ${activeStyles}`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  <span className="truncate">{m.label}</span>
                </button>
                {/* Sub badge under module tab */}
                <div className="mt-1 flex items-center space-x-1 px-2 py-0.5 rounded bg-[#0D1322] border border-[#1E293B] text-[9px] text-emerald-400 font-mono">
                  <span>{m.sub}</span>
                  <span className="font-bold">✓</span>
                </div>
              </div>
            );
          })}

          {/* Extra Tabs: Topology, Services, DNS */}
          <div className="h-8 w-[1px] bg-[#1E293B] mx-2 hidden lg:block" />

          {extraTabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => onTabChange(tab.id)}
                className={`px-3 py-2 rounded-xl border text-[11px] font-mono flex items-center space-x-1.5 transition cursor-pointer ${
                  isActive
                    ? 'bg-[#00F0FF]/20 text-[#00F0FF] border-[#00F0FF]/60 shadow-md font-bold'
                    : 'bg-[#0D1322] text-slate-400 border-[#1E293B] hover:text-slate-200'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Right Status Badge */}
        <div className="flex items-center space-x-3 font-mono text-xs">
          <div className="flex flex-col items-end">
            <span className="text-[11px] font-bold text-cyan-400">Module 06 SOC Active</span>
            <div className="h-1.5 w-24 bg-[#0D1322] rounded-full overflow-hidden border border-[#1E293B] mt-1">
              <div className="h-full bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-500 w-full animate-pulse"></div>
            </div>
          </div>
        </div>

      </div>
    </header>
  );
}
