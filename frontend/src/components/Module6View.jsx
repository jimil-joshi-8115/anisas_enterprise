import React from 'react';
import TopologyGraph from './TopologyGraph';

export default function Module6View() {
  return (
    <div className="space-y-6 font-mono text-xs">
      
      {/* Module Header */}
      <div className="soc-card p-6 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="text-xs text-[#00F0FF] font-bold uppercase tracking-wider">
            MODULE 06 • UNIFIED CYBER SOC DASHBOARD & TOPOLOGY GRAPH
          </div>
          <h1 className="text-2xl font-black text-white tracking-wide mt-1 font-sans">
            Unified SOC Command Center
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-sans">
            Consolidates Module 01-05 reconnaissance into vis-network interactive graph, live telemetry alerts, and full target reports.
          </p>
        </div>
      </div>

      {/* Interactive Topology Graph Container */}
      <div className="soc-card p-6">
        <TopologyGraph />
      </div>

    </div>
  );
}
