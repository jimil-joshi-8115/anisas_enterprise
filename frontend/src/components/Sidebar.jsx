import React from 'react';
import { Shield, Network, Lock, Eye, Cpu, Layers, Check } from 'lucide-react';

export default function Sidebar({ activeTab, onTabChange }) {
  const items = [
    { id: 'module1', label: 'Module 01: ASN Intel', icon: Network, color: 'cyan' },
    { id: 'module2', label: 'Module 02: Network Recon', icon: Network, color: 'blue' },
    { id: 'module3', label: 'Module 03: Security Perimeter', icon: Lock, color: 'emerald' },
    { id: 'module4', label: 'Module 04: IoT & Surveillance', icon: Eye, color: 'amber' },
    { id: 'module5', label: 'Module 05: AI Risk Engine', icon: Cpu, color: 'purple' },
    { id: 'module6', label: 'Module 06: Unified SOC', icon: Layers, color: 'teal' },
  ];

  return (
    <aside className="w-full lg:w-72 flex-shrink-0 space-y-4 font-mono text-xs">
      <div className="soc-card p-5 space-y-4 sticky top-24">
        
        <div className="text-[11px] font-extrabold text-slate-400 uppercase tracking-wider border-b border-[#1E293B] pb-2">
          PIPELINE MODULES
        </div>

        <div className="space-y-2">
          {items.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;

            let buttonStyles = 'text-slate-400 hover:text-slate-100 hover:bg-slate-900/60 border-transparent';
            if (isActive) {
              if (item.color === 'amber') {
                buttonStyles = 'bg-[#FFB800]/15 text-[#FFB800] border-[#FFB800]/60 shadow-lg shadow-[#FFB800]/15 font-bold';
              } else if (item.color === 'emerald') {
                buttonStyles = 'bg-[#10B981]/15 text-[#10B981] border-[#10B981]/60 shadow-lg shadow-[#10B981]/15 font-bold';
              } else if (item.color === 'purple') {
                buttonStyles = 'bg-[#A855F7]/15 text-[#A855F7] border-[#A855F7]/60 shadow-lg shadow-[#A855F7]/15 font-bold';
              } else {
                buttonStyles = 'bg-[#00F0FF]/15 text-[#00F0FF] border-[#00F0FF]/60 shadow-lg shadow-[#00F0FF]/15 font-bold';
              }
            }

            return (
              <button
                key={item.id}
                onClick={() => onTabChange(item.id)}
                className={`w-full px-3.5 py-2.5 rounded-xl border flex items-center justify-between transition cursor-pointer ${buttonStyles}`}
              >
                <div className="flex items-center space-x-2.5 truncate">
                  <Icon className="w-4 h-4 flex-shrink-0" />
                  <span className="truncate">{item.label}</span>
                </div>
                <span className="text-emerald-400 font-bold text-xs ml-1">✓</span>
              </button>
            );
          })}
        </div>

        {/* Bottom Orchestrator Metadata */}
        <div className="pt-4 border-t border-[#1E293B] space-y-2 text-[11px] text-slate-400">
          <div className="flex justify-between items-center">
            <span>Orchestrator:</span>
            <span className="text-[#00F0FF] font-bold">M01 → M02 → M03</span>
          </div>
          <div className="flex justify-between items-center">
            <span>Monorepo API:</span>
            <span className="text-slate-300 font-mono">/api/v1/perimeter/*</span>
          </div>
        </div>

      </div>
    </aside>
  );
}
