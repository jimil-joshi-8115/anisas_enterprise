import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Terminal, ChevronDown, ChevronUp, Play, Pause, Trash2, Copy, Check } from 'lucide-react';

export default function LiveTerminal() {
  const [collapsed, setCollapsed] = useState(false);
  const [paused, setPaused] = useState(false);
  const [copied, setCopied] = useState(false);
  const [logs, setLogs] = useState([
    { time: '19:19:13', module: 'M01', msg: 'Initiated Single Entry Trigger scan for target 187.245.231.228', type: 'info' },
    { time: '19:19:14', module: 'M01', msg: 'WHOIS RDAP resolved: Mega Cable, S.A. de C.V. (AS13999 / 187.245.231.0/24)', type: 'success' },
    { time: '19:19:14', module: 'M02', msg: 'Active Socket Probe: Port 80 (HTTP) OPEN, Port 8000 (DB-SERVICE) OPEN', type: 'success' },
    { time: '19:19:15', module: 'M03', msg: 'Perimeter Audit: Direct Origin Access verified (No WAF Header on 187.245.231.228)', type: 'warn' },
    { time: '19:19:15', module: 'M04', msg: 'IoT Fingerprint Match: Hikvision DS-2CD2143G0-I NVR Camera detected', type: 'warn' },
    { time: '19:19:16', module: 'M04', msg: 'ONVIF Stream URLs bound: rtsp://187.245.231.228:554/Streaming/Channels/101', type: 'info' },
    { time: '19:19:16', module: 'M04', msg: 'CVE Match: CVE-2021-36260 (CVSS 9.8 CRITICAL) Command Injection', type: 'error' },
    { time: '19:19:18', module: 'M05', msg: 'XGBoost Risk Classifier evaluated Overall Risk Score: 80/100 (CRITICAL)', type: 'error' },
  ]);

  const bottomRef = useRef(null);

  useEffect(() => {
    if (paused) return;
    const interval = setInterval(() => {
      const msgs = [
        { module: 'M02', msg: 'Google DoH resolved PTR reverse DNS: customer-TGZ-MCA-231.megacable.net', type: 'info' },
        { module: 'M03', msg: 'WAF Rule Check: Cloudflare / Akamai signatures unassigned (Direct Origin)', type: 'warn' },
        { module: 'M04', msg: 'RTSP H.264 HEVC stream codec handshake established (4K 30fps)', type: 'success' },
        { module: 'M05', msg: 'AI Vision Interface Model classified console: CCTV_CAMERA_ADMIN_PANEL (97.6%)', type: 'info' },
      ];
      const randomItem = msgs[Math.floor(Math.random() * msgs.length)];
      const now = new Date().toLocaleTimeString('en-US', { hour12: false });
      setLogs((prev) => [...prev.slice(-30), { time: now, ...randomItem }]);
    }, 4000);

    return () => clearInterval(interval);
  }, [paused]);

  useEffect(() => {
    if (!collapsed && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, collapsed]);

  const copyLogs = () => {
    const text = logs.map(l => `[${l.time}] [${l.module}] ${l.msg}`).join('\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="soc-card overflow-hidden border border-[#1E293B] shadow-2xl font-mono text-xs">
      
      {/* Terminal Header Bar */}
      <div className="flex items-center justify-between px-4 py-2.5 bg-[#080C14] border-b border-[#1E293B]">
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-1.5">
            <span className="w-3 h-3 rounded-full bg-rose-500/80 inline-block" />
            <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block" />
            <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block" />
          </div>
          <div className="flex items-center space-x-2 text-cyan-400 font-bold">
            <Terminal className="w-4 h-4 text-[#00F0FF]" />
            <span>LIVE RECONNAISSANCE TELEMETRY STREAM</span>
          </div>
        </div>

        <div className="flex items-center space-x-2 text-[11px]">
          <button
            onClick={() => setPaused(!paused)}
            className="p-1 px-2 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 flex items-center space-x-1 transition cursor-pointer"
          >
            {paused ? <Play className="w-3 h-3 text-emerald-400" /> : <Pause className="w-3 h-3 text-amber-400" />}
            <span>{paused ? 'Resume' : 'Pause'}</span>
          </button>

          <button
            onClick={copyLogs}
            className="p-1 px-2 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 flex items-center space-x-1 transition cursor-pointer"
          >
            {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3 text-cyan-400" />}
            <span>{copied ? 'Copied' : 'Copy Logs'}</span>
          </button>

          <button
            onClick={() => setLogs([])}
            className="p-1 px-2 rounded bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-rose-400 border border-slate-700 transition cursor-pointer"
          >
            <Trash2 className="w-3 h-3" />
          </button>

          <button
            onClick={() => setCollapsed(!collapsed)}
            className="p-1 px-2 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 flex items-center space-x-1 transition cursor-pointer"
          >
            {collapsed ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronUp className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* Scrollable Terminal Output Body */}
      <AnimatePresence>
        {!collapsed && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="p-4 bg-[#060913] max-h-48 overflow-y-auto space-y-1 text-[11px] leading-relaxed"
          >
            {logs.map((log, i) => {
              let color = 'text-slate-300';
              if (log.type === 'error') color = 'text-rose-400 font-semibold';
              if (log.type === 'warn') color = 'text-amber-300';
              if (log.type === 'success') color = 'text-emerald-400';
              if (log.type === 'info') color = 'text-cyan-300';

              return (
                <div key={i} className="flex items-start space-x-2 font-mono hover:bg-slate-900/40 rounded px-1 transition">
                  <span className="text-slate-500 font-mono flex-shrink-0">[{log.time}]</span>
                  <span className="px-1.5 py-0.2 rounded bg-slate-800 text-cyan-400 font-bold text-[10px] border border-slate-700 flex-shrink-0">
                    {log.module}
                  </span>
                  <span className={`${color} break-all`}>{log.msg}</span>
                </div>
              );
            })}
            <div ref={bottomRef} />
          </motion.div>
        )}
      </AnimatePresence>

    </div>
  );
}
