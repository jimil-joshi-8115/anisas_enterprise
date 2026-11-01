import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Search, Rocket, Activity, CheckCircle2, ShieldCheck, Zap } from 'lucide-react';

export default function HeroBanner({ loading, onScan, currentTarget = '187.245.231.228' }) {
  const [inputVal, setInputVal] = useState(currentTarget);
  const [focused, setFocused] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (inputVal.trim() && onScan) {
      onScan(inputVal.trim());
    }
  };

  return (
    <div className="relative overflow-hidden rounded-3xl bg-gradient-to-r from-slate-900 via-[#0d1527] to-slate-950 border border-slate-800/80 p-6 md:p-8 shadow-2xl">
      
      {/* Background Animated Shimmer / Gradient Glow */}
      <div className="absolute -top-24 -left-24 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none animate-pulse" />
      <div className="absolute -bottom-24 -right-24 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl pointer-events-none animate-pulse" />

      <div className="relative z-10 flex flex-col items-center text-center max-w-4xl mx-auto space-y-6">
        
        {/* System Live Pill Badge */}
        <motion.div 
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="inline-flex items-center space-x-3 px-4 py-1.5 rounded-full bg-slate-900/90 border border-slate-700/80 text-xs font-mono text-slate-300 shadow-md backdrop-blur-md"
        >
          <span className="relative flex h-2.5 w-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
          </span>
          <span className="font-semibold text-emerald-400">SYSTEM LIVE</span>
          <span className="text-slate-600">·</span>
          <span>Last Scan: 2 min ago</span>
          <span className="text-slate-600 font-mono">·</span>
          <span className="text-cyan-400 font-mono font-semibold">1.2M IPs Analyzed</span>
        </motion.div>

        {/* Hero Title & Subtitle */}
        <div className="space-y-2">
          <motion.h2 
            initial={{ opacity: 0, scale: 0.98 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.4 }}
            className="text-2xl md:text-4xl font-extrabold tracking-tight text-white"
          >
            Real-time Threat Intelligence & Asset Discovery Engine
          </motion.h2>
          <p className="text-xs md:text-sm text-slate-400 max-w-2xl mx-auto">
            Autonomous multi-module EASM & Reconnaissance platform probing network perimeter, IoT, TLS certificates, and AI threat posture.
          </p>
        </div>

        {/* Google-Style Pill Search Form */}
        <motion.form 
          onSubmit={handleSubmit}
          animate={{ scale: focused ? 1.02 : 1 }}
          transition={{ type: 'spring', stiffness: 300, damping: 25 }}
          className="w-full max-w-2xl relative flex items-center bg-slate-900/90 border border-slate-700/80 hover:border-cyan-500/50 rounded-full p-1.5 shadow-2xl backdrop-blur-xl transition-all duration-300 group"
        >
          <div className="pl-4 text-cyan-400">
            <Search className="w-5 h-5 group-hover:scale-110 transition-transform duration-200" />
          </div>

          <input
            type="text"
            value={inputVal}
            onChange={(e) => setInputVal(e.target.value)}
            onFocus={() => setFocused(true)}
            onBlur={() => setFocused(false)}
            placeholder="Enter IP Address, Hostname, or Subnet (e.g. 187.245.231.228)..."
            className="w-full bg-transparent px-4 py-2.5 text-xs md:text-sm text-slate-100 placeholder-slate-500 font-mono focus:outline-none"
          />

          <motion.button
            whileHover={{ scale: 1.03 }}
            whileTap={{ scale: 0.96 }}
            disabled={loading}
            type="submit"
            className="relative overflow-hidden px-6 py-2.5 bg-gradient-to-r from-cyan-500 via-sky-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold text-xs md:text-sm rounded-full shadow-lg shadow-cyan-500/25 flex items-center space-x-2 transition-all duration-200 disabled:opacity-50"
          >
            {loading ? (
              <>
                <Activity className="w-4 h-4 animate-spin text-white" />
                <span>Scanning...</span>
              </>
            ) : (
              <>
                <Rocket className="w-4 h-4 text-white fill-current" />
                <span>Scan Now</span>
              </>
            )}
          </motion.button>
        </motion.form>

        {/* Quick Quicktags */}
        <div className="flex flex-wrap justify-center items-center gap-2 text-[11px] text-slate-400 font-mono">
          <span className="text-slate-500">Quick Targets:</span>
          {['187.245.231.228', 'reddit.com', '151.101.65.140', 'cloudflare.com'].map((ip) => (
            <button
              key={ip}
              onClick={() => { setInputVal(ip); onScan && onScan(ip); }}
              className="px-2.5 py-1 bg-slate-800/80 hover:bg-cyan-500/20 hover:text-cyan-300 border border-slate-700/60 rounded-md transition duration-150"
            >
              {ip}
            </button>
          ))}
        </div>

      </div>
    </div>
  );
}
