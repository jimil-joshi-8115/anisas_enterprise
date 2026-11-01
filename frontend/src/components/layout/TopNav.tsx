import React from 'react';
import { Search, Bell, Shield, User, Globe } from 'lucide-react';

interface TopNavProps {
  quickSearch: string;
  setQuickSearch: (val: string) => void;
  onSearchSubmit: () => void;
}

export const TopNav: React.FC<TopNavProps> = ({ quickSearch, setQuickSearch, onSearchSubmit }) => {
  return (
    <header className="h-16 border-b border-slate-800 bg-[#0B0F19]/80 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-30">
      {/* Search Input */}
      <div className="flex items-center gap-3 w-96">
        <div className="relative w-full">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            value={quickSearch}
            onChange={(e) => setQuickSearch(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && onSearchSubmit()}
            placeholder="Quick Scan IPv4 / IPv6 (e.g. 8.8.8.8)..."
            className="w-full bg-slate-900/80 border border-slate-800 rounded-lg pl-9 pr-4 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-all font-mono"
          />
        </div>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-xs text-slate-300">
          <Globe className="w-3.5 h-3.5 text-cyan-400" />
          <span>OSINT Feeds Active</span>
        </div>

        <button className="p-2 rounded-lg bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-400 hover:text-white transition">
          <Bell className="w-4 h-4" />
        </button>

        <div className="flex items-center gap-3 border-l border-slate-800 pl-4">
          <div className="w-8 h-8 rounded-full bg-cyan-600/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 font-bold text-xs">
            SOC
          </div>
          <div>
            <div className="text-xs font-semibold text-white">Lead Architect</div>
            <div className="text-[10px] text-cyan-400 font-mono">SOC Operations</div>
          </div>
        </div>
      </div>
    </header>
  );
};
