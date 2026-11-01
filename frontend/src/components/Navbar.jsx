import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, ChevronDown, User, Settings, LogOut, Radio, Activity, Cpu, Database, BarChart2, ShieldAlert } from 'lucide-react';

export default function Navbar({ activeTab, onTabChange }) {
  const [userMenuOpen, setUserMenuOpen] = useState(false);

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: BarChart2 },
    { id: 'pipeline', label: 'Pipeline', icon: Activity },
    { id: 'intelligence', label: 'Intelligence', icon: Cpu },
    { id: 'reports', label: 'Reports', icon: Database },
    { id: 'admin', label: 'Admin', icon: Settings },
  ];

  return (
    <header className="sticky top-0 z-50 glass-panel border-b border-slate-800/80 backdrop-blur-xl bg-[#0a0e1a]/80 transition-all duration-300">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          
          {/* Brand Logo & Version */}
          <div className="flex items-center space-x-3">
            <motion.div 
              whileHover={{ scale: 1.08, rotate: 5 }}
              whileTap={{ scale: 0.95 }}
              className="relative p-2.5 bg-gradient-to-br from-cyan-500/20 via-blue-500/10 to-purple-500/20 rounded-xl border border-cyan-500/30 text-cyan-400 shadow-lg shadow-cyan-500/10"
            >
              <Shield className="w-6 h-6 animate-pulse" />
              <span className="absolute -top-1 -right-1 w-3 h-3 bg-cyan-400 rounded-full animate-ping opacity-75" />
            </motion.div>
            
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-xl font-extrabold tracking-tight bg-gradient-to-r from-cyan-400 via-sky-300 to-purple-400 bg-clip-text text-transparent font-sans">
                  ANISAS
                </h1>
                <span className="px-2 py-0.5 text-[10px] font-mono font-semibold uppercase bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 rounded-md">
                  v3.0 SOC
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-mono tracking-wide hidden sm:block">
                Enterprise Cyber SOC Platform
              </p>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="hidden md:flex items-center space-x-1 bg-slate-900/60 p-1.5 rounded-xl border border-slate-800/60">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onTabChange && onTabChange(item.id)}
                  className={`relative px-4 py-1.5 rounded-lg text-xs font-medium transition-all duration-200 flex items-center space-x-2 ${
                    isActive
                      ? 'text-cyan-300 font-semibold'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                  }`}
                >
                  {isActive && (
                    <motion.div
                      layoutId="activeNavTab"
                      className="absolute inset-0 bg-gradient-to-r from-cyan-500/20 to-blue-500/20 border border-cyan-500/40 rounded-lg shadow-sm"
                      transition={{ type: 'spring', stiffness: 400, damping: 30 }}
                    />
                  )}
                  <Icon className={`w-3.5 h-3.5 relative z-10 ${isActive ? 'text-cyan-400' : ''}`} />
                  <span className="relative z-10">{item.label}</span>
                </button>
              );
            })}
          </nav>

          {/* Live Status Indicator & User Menu */}
          <div className="flex items-center space-x-4">
            
            {/* Live Indicator Dot */}
            <div className="hidden sm:flex items-center space-x-2 px-3 py-1 bg-emerald-500/10 border border-emerald-500/30 rounded-full text-emerald-400 text-xs font-mono">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              <span className="font-semibold tracking-wider text-[11px]">SYSTEM LIVE</span>
            </div>

            {/* User Dropdown */}
            <div className="relative">
              <button
                onClick={() => setUserMenuOpen(!userMenuOpen)}
                className="flex items-center space-x-2 p-1.5 bg-slate-900/80 hover:bg-slate-800/80 rounded-xl border border-slate-700/60 transition duration-200"
              >
                <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-purple-600 flex items-center justify-center text-white font-bold text-xs shadow-md">
                  SA
                </div>
                <span className="text-xs font-medium text-slate-200 hidden lg:inline">SOC Admin</span>
                <ChevronDown className={`w-3.5 h-3.5 text-slate-400 transition-transform duration-200 ${userMenuOpen ? 'rotate-180' : ''}`} />
              </button>

              <AnimatePresence>
                {userMenuOpen && (
                  <motion.div
                    initial={{ opacity: 0, y: 10, scale: 0.95 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: 10, scale: 0.95 }}
                    transition={{ duration: 0.15 }}
                    className="absolute right-0 mt-2 w-48 bg-[#111827] border border-slate-700/80 rounded-xl shadow-2xl py-1 z-50 backdrop-blur-xl"
                  >
                    <div className="px-4 py-2 border-b border-slate-800">
                      <p className="text-xs font-semibold text-slate-100">SecOps Admin</p>
                      <p className="text-[10px] text-slate-400 font-mono">admin@anisas.enterprise</p>
                    </div>
                    
                    <button className="w-full px-4 py-2 text-xs text-slate-300 hover:bg-slate-800/60 flex items-center space-x-2 transition">
                      <User className="w-3.5 h-3.5 text-cyan-400" />
                      <span>User Profile</span>
                    </button>
                    
                    <button className="w-full px-4 py-2 text-xs text-slate-300 hover:bg-slate-800/60 flex items-center space-x-2 transition">
                      <Settings className="w-3.5 h-3.5 text-purple-400" />
                      <span>Platform Settings</span>
                    </button>

                    <div className="border-t border-slate-800 my-1" />
                    
                    <button className="w-full px-4 py-2 text-xs text-rose-400 hover:bg-rose-500/10 flex items-center space-x-2 transition">
                      <LogOut className="w-3.5 h-3.5 text-rose-400" />
                      <span>Logout Session</span>
                    </button>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

          </div>

        </div>
      </div>
    </header>
  );
}
