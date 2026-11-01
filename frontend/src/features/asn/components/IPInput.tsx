import React, { useState } from 'react';
import { Search, ShieldAlert, CheckCircle2, AlertCircle } from 'lucide-react';

interface IPInputProps {
  onScan: (ip: string) => void;
  isLoading: boolean;
}

const ipv4Regex = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.){3}(25[0-5]|(2[0-4]|1\d|[1-9]|)\d)$/;
const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;

export const IPInput: React.FC<IPInputProps> = ({ onScan, isLoading }) => {
  const [ip, setIp] = useState('8.8.8.8');
  const [error, setError] = useState<string | null>(null);

  const handleValidateAndSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const clean = ip.trim();
    if (!ipv4Regex.test(clean) && !ipv6Regex.test(clean)) {
      setError('Please enter a valid public IPv4 address (e.g. 8.8.8.8) or IPv6 address.');
      return;
    }
    setError(null);
    onScan(clean);
  };

  return (
    <div className="glass-panel p-6 rounded-xl border border-slate-800 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-cyan-400" />
            Single Target Intelligence Scan
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Enter an IPv4 or IPv6 target address to trigger automated Module 01 ASN, WHOIS, BGP & Threat resolution.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {['8.8.8.8', '1.1.1.1', '208.67.222.222', '9.9.9.9'].map((preset) => (
            <button
              key={preset}
              type="button"
              onClick={() => {
                setIp(preset);
                setError(null);
              }}
              className="px-2.5 py-1 rounded bg-slate-800/80 hover:bg-slate-700 text-[11px] font-mono text-cyan-300 border border-slate-700 transition"
            >
              {preset}
            </button>
          ))}
        </div>
      </div>

      <form onSubmit={handleValidateAndSubmit} className="space-y-3">
        <div className="flex gap-3">
          <div className="relative flex-1">
            <input
              type="text"
              value={ip}
              onChange={(e) => {
                setIp(e.target.value);
                if (error) setError(null);
              }}
              placeholder="e.g. 8.8.8.8 or 2001:4860:4860::8888"
              className={`w-full bg-slate-950 border ${
                error ? 'border-rose-500/80' : 'border-slate-800'
              } rounded-lg px-4 py-3 text-sm font-mono text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition`}
            />
            {error && (
              <p className="text-xs text-rose-400 mt-1 flex items-center gap-1">
                <AlertCircle className="w-3.5 h-3.5" />
                {error}
              </p>
            )}
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="px-6 py-3 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold uppercase tracking-wider flex items-center gap-2 shadow-lg shadow-cyan-500/20 transition disabled:opacity-50"
          >
            <Search className="w-4 h-4" />
            {isLoading ? 'Scanning Pipeline...' : 'Run Module 01'}
          </button>
        </div>
      </form>
    </div>
  );
};
