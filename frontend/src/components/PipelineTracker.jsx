import React from 'react';
import { motion } from 'framer-motion';
import { Network, ShieldCheck, Lock, Eye, Cpu, Layers, CheckCircle2, Play, Activity } from 'lucide-react';

export default function PipelineTracker({ activeModule = 'M03', onModuleClick, progress = 67 }) {
  const modules = [
    { id: 'M01', label: 'ASN Intel', desc: 'BGP & GeoIP', icon: Network },
    { id: 'M02', label: 'Network Recon', desc: 'Ports & DNS', icon: ShieldCheck },
    { id: 'M03', label: 'Perimeter Intel', desc: 'WAF & HTTP', icon: Lock },
    { id: 'M04', label: 'IoT & Surveillance', desc: 'ONVIF & RTSP', icon: Eye },
    { id: 'M05', label: 'AI Risk Engine', desc: 'CVE Heuristics', icon: Cpu },
    { id: 'M06', label: 'Unified SOC', desc: 'Topology Graph', icon: Layers },
  ];

  const getModuleStatus = (mId) => {
    const currentIndex = modules.findIndex((m) => m.id === activeModule);
    const mIndex = modules.findIndex((m) => m.id === mId);
    if (mIndex < currentIndex) return 'completed';
    if (mIndex === currentIndex) return 'active';
    return 'pending';
  };

  const activeModuleObj = modules.find((m) => m.id === activeModule) || modules[2];

  return (
    <div className="glass-card p-6 border border-slate-800/80 shadow-2xl relative overflow-hidden">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-6 pb-4 border-b border-slate-800/80 gap-2">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Activity className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <h3 className="text-sm font-bold tracking-wider text-slate-100 uppercase font-mono">
              Reconnaissance Pipeline Tracker
            </h3>
            <p className="text-xs text-slate-400">
              Sequential 6-Module Autonomous Intelligence Flow
            </p>
          </div>
        </div>

        {/* Live Active Status Badge */}
        <div className="flex items-center space-x-3 bg-slate-900/90 px-3 py-1.5 rounded-xl border border-slate-800 text-xs font-mono">
          <span className="flex items-center space-x-1 text-emerald-400">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping mr-1" />
            <span>Running</span>
          </span>
          <span className="text-slate-600">·</span>
          <span className="text-slate-400">⏱️ 2s ago</span>
          <span className="text-slate-600">·</span>
          <span className="text-cyan-400 font-semibold">⏳ {progress}% Fill</span>
        </div>
      </div>

      {/* Pipeline Stepper Nodes */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-6 relative">
        {modules.map((m, idx) => {
          const status = getModuleStatus(m.id);
          const Icon = m.icon;

          return (
            <motion.button
              key={m.id}
              onClick={() => onModuleClick && onModuleClick(m.id)}
              whileHover={{ scale: 1.04 }}
              whileTap={{ scale: 0.96 }}
              className={`relative p-3.5 rounded-xl border text-left flex flex-col justify-between transition-all duration-200 ${
                status === 'active'
                  ? 'bg-gradient-to-b from-cyan-500/20 to-slate-900 border-cyan-500/80 shadow-lg shadow-cyan-500/20'
                  : status === 'completed'
                  ? 'bg-slate-900/80 border-emerald-500/40 text-slate-200'
                  : 'bg-slate-900/40 border-slate-800/80 text-slate-500 hover:border-slate-700'
              }`}
            >
              {/* Connector line indicator for desktop */}
              {idx < modules.length - 1 && (
                <div className="hidden lg:block absolute -right-2 top-1/2 -translate-y-1/2 z-20">
                  <div className={`w-3 h-0.5 ${status === 'completed' ? 'bg-emerald-500' : 'bg-slate-800'}`} />
                </div>
              )}

              <div className="flex items-center justify-between mb-2">
                <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${
                  status === 'active'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : status === 'completed'
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                    : 'bg-slate-800 text-slate-500'
                }`}>
                  {m.id}
                </span>

                {status === 'completed' ? (
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                ) : status === 'active' ? (
                  <Activity className="w-3.5 h-3.5 text-cyan-400 animate-spin" />
                ) : (
                  <span className="w-2 h-2 rounded-full bg-slate-700" />
                )}
              </div>

              <div>
                <h4 className={`text-xs font-bold font-mono truncate ${
                  status === 'active' ? 'text-cyan-300' : status === 'completed' ? 'text-slate-200' : 'text-slate-400'
                }`}>
                  {m.label}
                </h4>
                <p className="text-[10px] text-slate-400 truncate font-sans">
                  {m.desc}
                </p>
              </div>

              {/* Active Pulse Border Indicator */}
              {status === 'active' && (
                <motion.div
                  layoutId="activePipelineGlow"
                  className="absolute inset-0 rounded-xl border-2 border-cyan-400 pointer-events-none"
                  transition={{ repeat: Infinity, duration: 2, ease: "easeInOut" }}
                />
              )}
            </motion.button>
          );
        })}
      </div>

      {/* Detailed Status Bar & Animated Fill Progress */}
      <div className="bg-slate-900/90 rounded-2xl p-4 border border-slate-800/80 space-y-3">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center text-xs font-mono gap-1">
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
            <span className="text-slate-300 font-semibold">Active Execution:</span>
            <span className="text-cyan-300 font-bold">{activeModuleObj.id} — {activeModuleObj.label} ({activeModuleObj.desc})</span>
          </div>
          <span className="text-slate-400 font-mono">Progress: {progress}%</span>
        </div>

        {/* Smooth 60fps Fill Bar */}
        <div className="w-full h-2.5 bg-slate-950 rounded-full overflow-hidden border border-slate-800 p-0.5">
          <motion.div
            initial={{ width: '0%' }}
            animate={{ width: `${progress}%` }}
            transition={{ duration: 0.8, ease: 'easeOut' }}
            className="h-full bg-gradient-to-r from-cyan-500 via-sky-400 to-purple-500 rounded-full shadow-lg shadow-cyan-500/50"
          />
        </div>
      </div>

    </div>
  );
}
