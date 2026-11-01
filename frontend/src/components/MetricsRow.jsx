import React from 'react';
import { motion } from 'framer-motion';
import { BarChart2, ShieldAlert, Cpu, AlertTriangle, TrendingUp, TrendingDown, Target } from 'lucide-react';

export default function MetricsRow({ metrics }) {
  const data = metrics || {
    assets: 1247,
    vendors: 42,
    cves: 18,
    risk: 80,
  };

  const cardVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: (i) => ({
      opacity: 1,
      y: 0,
      transition: { delay: i * 0.1, duration: 0.4, ease: 'easeOut' },
    }),
  };

  // SVG Circular Progress Ring calculations for Risk Score
  const radius = 28;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (data.risk / 100) * circumference;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      
      {/* Card 1: Total Assets */}
      <motion.div
        custom={0}
        initial="hidden"
        animate="visible"
        variants={cardVariants}
        className="glass-card p-5 border border-slate-800/80 flex justify-between items-start relative overflow-hidden group"
      >
        <div className="space-y-2">
          <div className="flex items-center space-x-2 text-xs font-mono text-slate-400 uppercase tracking-wider">
            <BarChart2 className="w-4 h-4 text-cyan-400" />
            <span>Discovered Assets</span>
          </div>
          <div className="text-3xl font-extrabold font-mono text-slate-100 group-hover:text-cyan-300 transition-colors">
            {data.assets.toLocaleString()}
          </div>
          <div className="flex items-center space-x-1 text-xs font-mono text-emerald-400">
            <TrendingUp className="w-3.5 h-3.5" />
            <span className="font-semibold">↑ 12%</span>
            <span className="text-slate-500 font-sans ml-1">vs last week</span>
          </div>
        </div>
        <div className="p-3 bg-cyan-500/10 rounded-2xl border border-cyan-500/20 text-cyan-400">
          <BarChart2 className="w-6 h-6" />
        </div>
      </motion.div>

      {/* Card 2: Hardware Vendors */}
      <motion.div
        custom={1}
        initial="hidden"
        animate="visible"
        variants={cardVariants}
        className="glass-card p-5 border border-slate-800/80 flex justify-between items-start relative overflow-hidden group"
      >
        <div className="space-y-2">
          <div className="flex items-center space-x-2 text-xs font-mono text-slate-400 uppercase tracking-wider">
            <Cpu className="w-4 h-4 text-purple-400" />
            <span>Hardware Vendors</span>
          </div>
          <div className="text-3xl font-extrabold font-mono text-slate-100 group-hover:text-purple-300 transition-colors">
            {data.vendors}
          </div>
          <div className="flex items-center space-x-1 text-xs font-mono text-purple-400">
            <TrendingUp className="w-3.5 h-3.5" />
            <span className="font-semibold">↑ 8%</span>
            <span className="text-slate-500 font-sans ml-1">fingerprinted</span>
          </div>
        </div>
        <div className="p-3 bg-purple-500/10 rounded-2xl border border-purple-500/20 text-purple-400">
          <Cpu className="w-6 h-6" />
        </div>
      </motion.div>

      {/* Card 3: Active CVEs */}
      <motion.div
        custom={2}
        initial="hidden"
        animate="visible"
        variants={cardVariants}
        className="glass-card p-5 border border-slate-800/80 flex justify-between items-start relative overflow-hidden group"
      >
        <div className="space-y-2">
          <div className="flex items-center space-x-2 text-xs font-mono text-slate-400 uppercase tracking-wider">
            <AlertTriangle className="w-4 h-4 text-rose-400" />
            <span>Matched CVEs</span>
          </div>
          <div className="text-3xl font-extrabold font-mono text-slate-100 group-hover:text-rose-300 transition-colors">
            {data.cves}
          </div>
          <div className="flex items-center space-x-1 text-xs font-mono text-emerald-400">
            <TrendingDown className="w-3.5 h-3.5" />
            <span className="font-semibold">↓ 5%</span>
            <span className="text-slate-500 font-sans ml-1">remediated</span>
          </div>
        </div>
        <div className="p-3 bg-rose-500/10 rounded-2xl border border-rose-500/20 text-rose-400">
          <AlertTriangle className="w-6 h-6" />
        </div>
      </motion.div>

      {/* Card 4: Risk Score with Animated SVG Ring */}
      <motion.div
        custom={3}
        initial="hidden"
        animate="visible"
        variants={cardVariants}
        className="glass-card p-5 border border-slate-800/80 flex justify-between items-center relative overflow-hidden group"
      >
        <div className="space-y-1">
          <div className="flex items-center space-x-2 text-xs font-mono text-slate-400 uppercase tracking-wider">
            <Target className="w-4 h-4 text-rose-500" />
            <span>Target Risk</span>
          </div>
          <div className="text-3xl font-extrabold font-mono text-rose-400 flex items-baseline space-x-1">
            <span>{data.risk}</span>
            <span className="text-xs font-normal text-slate-500">/ 100</span>
          </div>
          <div className="inline-block px-2 py-0.5 bg-rose-500/20 text-rose-400 border border-rose-500/40 rounded text-[10px] font-mono font-bold tracking-wide uppercase">
            CRITICAL RISK
          </div>
        </div>

        {/* Circular Progress Ring */}
        <div className="relative flex items-center justify-center">
          <svg className="w-16 h-16 transform -rotate-90">
            <circle
              cx="32"
              cy="32"
              r={radius}
              stroke="rgba(255,255,255,0.08)"
              strokeWidth="6"
              fill="transparent"
            />
            <motion.circle
              cx="32"
              cy="32"
              r={radius}
              stroke="#f43f5e"
              strokeWidth="6"
              fill="transparent"
              strokeDasharray={circumference}
              initial={{ strokeDashoffset: circumference }}
              animate={{ strokeDashoffset }}
              transition={{ duration: 1.2, ease: 'easeOut' }}
              strokeLinecap="round"
            />
          </svg>
          <span className="absolute text-[11px] font-mono font-bold text-rose-400">
            {data.risk}%
          </span>
        </div>
      </motion.div>

    </div>
  );
}
