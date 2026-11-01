import React, { useState } from 'react';
import HeaderTracker from './components/HeaderTracker';
import Sidebar from './components/Sidebar';
import LiveTerminal from './components/LiveTerminal';
import Module1View from './components/Module1View';
import Module2View from './components/Module2View';
import Module3View from './components/Module3View';
import Module4View from './components/Module4View';
import Module5View from './components/Module5View';
import Module6View from './components/Module6View';

export default function App() {
  const [activeTab, setActiveTab] = useState('module4');

  const renderMainContent = () => {
    switch (activeTab) {
      case 'module1':
        return <Module1View onNavigate={setActiveTab} />;
      case 'module2':
      case 'services':
        return <Module2View onNavigate={setActiveTab} />;
      case 'module3':
        return <Module3View onNavigate={setActiveTab} />;
      case 'module4':
        return <Module4View onNavigate={setActiveTab} />;
      case 'module5':
        return <Module5View onNavigate={setActiveTab} />;
      case 'module6':
      case 'topology':
      case 'dns':
      default:
        return <Module6View onNavigate={setActiveTab} />;
    }
  };

  return (
    <div className="min-h-screen bg-[#060913] text-slate-100 font-sans selection:bg-[#00F0FF]/30 selection:text-white flex flex-col justify-between cyber-grid relative">
      <div>
        {/* Top Header Bar with Pipeline Module Tracker */}
        <HeaderTracker activeTab={activeTab} onTabChange={setActiveTab} />

        {/* Main Layout Container: Left Sidebar + Right Module View */}
        <div className="max-w-[1700px] w-full mx-auto p-6 flex flex-col lg:flex-row gap-6 flex-1">
          {/* Left Vertical Pipeline Modules Sidebar */}
          <Sidebar activeTab={activeTab} onTabChange={setActiveTab} />

          {/* Right Main Content Dashboard View */}
          <main className="flex-1 min-w-0 space-y-6">
            {renderMainContent()}

            {/* Live Terminal Stream Section */}
            <LiveTerminal />
          </main>
        </div>
      </div>

      {/* Footer Bar */}
      <footer className="border-t border-[#1E293B] bg-[#080C14] py-4 px-6 font-mono text-xs text-slate-400 text-center flex flex-col sm:flex-row justify-between items-center max-w-[1700px] mx-auto w-full">
        <div>
          <span className="text-[#00F0FF] font-bold">ANISAS ENTERPRISE CYBER SOC PLATFORM v3.0</span> · Autonomous Intelligence Engine
        </div>
        <div className="text-[11px] text-slate-500 mt-1 sm:mt-0">
          Status: <span className="text-[#10B981] font-bold">🟢 ALL 6 MODULES SYNCHRONIZED</span>
        </div>
      </footer>
    </div>
  );
}
