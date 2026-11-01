import React from 'react';
import { 
  ShieldAlert, 
  Network, 
  Lock, 
  Cpu, 
  BrainCircuit, 
  LayoutDashboard, 
  History,
  FileSpreadsheet
} from 'lucide-react';

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, setActiveTab }) => {
  const modules = [
    { id: 'dashboard', name: 'SOC Overview', icon: LayoutDashboard },
    { id: 'module1', name: 'Module 01: ASN Intelligence', icon: ShieldAlert, active: true },
    { id: 'module2', name: 'Module 02: Network Recon', icon: Network, disabled: false },
    { id: 'module3', name: 'Module 03: Security Perimeter', icon: Lock, disabled: true },
    { id: 'module4', name: 'Module 04: IoT & Surveillance', icon: Cpu, disabled: true },
    { id: 'module5', name: 'Module 05: AI Risk Engine', icon: BrainCircuit, disabled: true },
    { id: 'history', name: 'Scan History', icon: History },
  ];

  return (
    <aside className="w-64 bg-[#0B0F19]/90 border-r border-slate-800 flex flex-col h-screen sticky top-0 backdrop-blur-md">
      {/* Brand Header */}
      <div className="p-5 border-b border-slate-800 flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-cyan-600 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
          <ShieldAlert className="w-5 h-5 text-white" />
        </div>
        <div>
          <h1 className="font-bold text-lg text-white tracking-wider">ANISAS</h1>
          <p className="text-[10px] text-cyan-400 font-mono uppercase tracking-widest">Cyber SOC Platform</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4 space-y-1.5 overflow-y-auto">
        <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider px-3 mb-2">
          Pipeline Modules
        </div>

        {modules.map((m) => {
          const Icon = m.icon;
          const isActive = activeTab === m.id;
          return (
            <button
              key={m.id}
              onClick={() => !m.disabled && setActiveTab(m.id)}
              disabled={m.disabled}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-xs font-medium transition-all duration-200 ${
                isActive
                  ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/10 text-cyan-400 border border-cyan-500/30 shadow-md shadow-cyan-500/10'
                  : m.disabled
                  ? 'text-slate-600 cursor-not-allowed opacity-60'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
              <span>{m.name}</span>
            </button>
          );
        })}
      </nav>

      {/* Footer Info */}
      <div className="p-4 border-t border-slate-800/80 bg-slate-900/30">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></div>
          <span className="text-xs text-slate-400 font-mono">SOC Engine Online</span>
        </div>
        <div className="text-[10px] text-slate-500 mt-1">v1.0.0 Enterprise Monorepo</div>
      </div>
    </aside>
  );
};
