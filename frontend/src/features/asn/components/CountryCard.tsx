import React from 'react';
import { ASNScanResult } from '../../../types/asn';
import { Globe, MapPin, Compass } from 'lucide-react';

interface GeoLocationProps {
  scan: ASNScanResult;
}

export const CountryCard: React.FC<GeoLocationProps> = ({ scan }) => {
  const { geo } = scan;

  return (
    <div className="glass-panel p-5 rounded-xl border border-slate-800 space-y-3">
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
        <span className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
          <Globe className="w-4 h-4 text-cyan-400" />
          Country & Location Telemetry
        </span>
        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
          {geo.country}
        </span>
      </div>

      <div className="space-y-2 text-xs">
        <div className="flex justify-between">
          <span className="text-slate-400">City / Region:</span>
          <span className="text-white font-medium">{geo.city}, {geo.region}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-slate-400">Coordinates:</span>
          <span className="text-cyan-300 font-mono">{geo.latitude}, {geo.longitude}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-slate-400">Timezone:</span>
          <span className="text-slate-300 font-mono">{geo.timezone}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-slate-400">Reverse DNS:</span>
          <span className="text-slate-300 font-mono truncate max-w-[200px]">{geo.reverseDns}</span>
        </div>
      </div>
    </div>
  );
};

export const MapCard: React.FC<GeoLocationProps> = ({ scan }) => {
  const { geo } = scan;

  return (
    <div className="glass-panel p-5 rounded-xl border border-slate-800 space-y-3">
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
        <span className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
          <MapPin className="w-4 h-4 text-emerald-400" />
          Geographic Radar Grid
        </span>
        <Compass className="w-4 h-4 text-slate-500 animate-spin-slow" />
      </div>

      <div className="relative h-40 bg-slate-950 rounded-lg border border-slate-800 overflow-hidden flex flex-col items-center justify-center p-4">
        {/* Decorative Grid Lines */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#1f2937_1px,transparent_1px),linear-gradient(to_bottom,#1f2937_1px,transparent_1px)] bg-[size:2rem_2rem] opacity-30"></div>

        {/* Pulsing Radar Target */}
        <div className="relative z-10 text-center space-y-1">
          <div className="w-8 h-8 rounded-full bg-cyan-500/20 border border-cyan-400 flex items-center justify-center mx-auto animate-ping">
            <div className="w-3 h-3 rounded-full bg-cyan-400"></div>
          </div>
          <div className="text-xs font-bold font-mono text-cyan-300 mt-2">
            LAT: {geo.latitude} | LONG: {geo.longitude}
          </div>
          <div className="text-[10px] text-slate-400">{geo.city}, {geo.country}</div>
        </div>
      </div>
    </div>
  );
};
