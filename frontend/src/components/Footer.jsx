import React from 'react';
import { motion } from 'framer-motion';
import { Shield, Zap, Lock, Globe, Radio } from 'lucide-react';

export default function Footer() {
  return (
    <footer className="mt-12 border-t border-slate-800/80 bg-slate-950/80 backdrop-blur-xl py-6 px-4 font-mono text-xs text-slate-400">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        
        {/* Left Branding */}
        <div className="flex items-center space-x-2">
          <Zap className="w-4 h-4 text-cyan-400 animate-pulse" />
          <span>Powered by</span>
          <span className="font-bold bg-gradient-to-r from-cyan-400 via-sky-300 to-purple-400 bg-clip-text text-transparent">
            ANISAS Enterprise Cyber SOC Platform
          </span>
          <span className="px-2 py-0.5 bg-slate-800 text-slate-400 border border-slate-700 rounded text-[10px]">
            v3.0 Production
          </span>
        </div>

        {/* Middle Status Links */}
        <div className="flex items-center space-x-6 text-[11px] text-slate-400">
          <span className="flex items-center space-x-1.5 hover:text-cyan-400 transition cursor-pointer">
            <Lock className="w-3.5 h-3.5 text-emerald-400" />
            <span>256-Bit Encrypted</span>
          </span>
          <span className="flex items-center space-x-1.5 hover:text-cyan-400 transition cursor-pointer">
            <Globe className="w-3.5 h-3.5 text-cyan-400" />
            <span>Global Threat Feed</span>
          </span>
          <span className="flex items-center space-x-1.5 hover:text-cyan-400 transition cursor-pointer">
            <Radio className="w-3.5 h-3.5 text-purple-400" />
            <span>Telemetry Active</span>
          </span>
        </div>

        {/* Right Live Update Counter */}
        <div className="flex items-center space-x-2 px-3 py-1 bg-slate-900 border border-slate-800 rounded-full text-[11px] text-slate-300">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
          </span>
          <span>Updated 2s ago</span>
        </div>

      </div>
    </footer>
  );
}
