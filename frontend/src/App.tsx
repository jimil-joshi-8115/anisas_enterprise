import React, { useState, useEffect } from 'react';
import { QueryClient, QueryClientProvider, useQuery, useMutation } from '@tanstack/react-query';
import { Sidebar } from './components/layout/Sidebar';
import { TopNav } from './components/layout/TopNav';
import { ASNDashboardPage } from './features/asn/pages/ASNDashboardPage';
import { ASNScanPage } from './features/asn/pages/ASNScanPage';
import { ScanHistoryPage } from './features/asn/pages/ScanHistoryPage';
import { ASNDetailsPage } from './features/asn/pages/ASNDetailsPage';
import { ThreatOverviewPage } from './features/asn/pages/ThreatOverviewPage';
import { ASNScanResult, ScanHistoryItem } from './types/asn';
import { initiateScan, initiateBulkScan, fetchScanHistory, deleteScanRecord } from './services/api';
import { ArrowRight, CheckCircle2, ShieldAlert } from 'lucide-react';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

function SOCMainApp() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [quickSearch, setQuickSearch] = useState('');
  const [currentScan, setCurrentScan] = useState<ASNScanResult | null>(null);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [module02Active, setModule02Active] = useState<any | null>(null);

  // Initial Scan on load
  useEffect(() => {
    handleRunScan('8.8.8.8');
  }, []);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 4000);
  };

  // Fetch History Query
  const { data: historyData, refetch: refetchHistory } = useQuery({
    queryKey: ['scanHistory'],
    queryFn: fetchScanHistory,
    refetchInterval: 10000
  });

  const history: ScanHistoryItem[] = historyData?.history || [
    {
      id: 'h-1',
      scanId: 'scan-demo-1',
      targetIp: '8.8.8.8',
      summary: 'AS15169 GOOGLE (US) - Low Risk',
      riskLevel: 'LOW',
      riskScore: 12,
      timestamp: new Date().toISOString()
    },
    {
      id: 'h-2',
      scanId: 'scan-demo-2',
      targetIp: '1.1.1.1',
      summary: 'AS13335 CLOUDFLARENET (US) - Low Risk',
      riskLevel: 'LOW',
      riskScore: 10,
      timestamp: new Date().toISOString()
    }
  ];

  // Scan Mutation
  const scanMutation = useMutation({
    mutationFn: (ip: string) => initiateScan(ip),
    onSuccess: (data) => {
      setCurrentScan(data);
      refetchHistory();
      showToast(`Module 01 Scan complete for target ${data.targetIp}`);
    },
    onError: (err: any) => {
      showToast(`Scan Error: ${err.message || 'Server connection issue'}`);
    }
  });

  const handleRunScan = (ip: string) => {
    scanMutation.mutate(ip);
  };

  const handleBulkScan = async (ips: string[]) => {
    try {
      showToast(`Processing bulk batch of ${ips.length} IPs...`);
      await initiateBulkScan(ips);
      refetchHistory();
      showToast(`Bulk scan queue submitted successfully!`);
    } catch (e) {
      showToast(`Bulk Scan Failed: ${(e as Error).message}`);
    }
  };

  const handlePassToModule02 = (payload: any) => {
    setModule02Active(payload);
    setActiveTab('module2');
    showToast(`Data passed automatically from Module 01 -> Module 02: Network Recon!`);
  };

  const handleDeleteScan = async (scanId: string) => {
    await deleteScanRecord(scanId);
    refetchHistory();
    showToast(`Scan ${scanId} deleted.`);
  };

  return (
    <div className="flex bg-[#080C14] min-h-screen text-slate-100 font-sans selection:bg-cyan-500 selection:text-white">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-5 right-5 z-50 px-4 py-3 rounded-lg glass-panel-glow text-xs font-semibold text-cyan-300 flex items-center gap-2 border border-cyan-500/40 shadow-2xl animate-bounce">
          <CheckCircle2 className="w-4 h-4 text-cyan-400" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Sidebar */}
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />

      {/* Main Workspace */}
      <div className="flex-1 flex flex-col min-w-0">
        <TopNav
          quickSearch={quickSearch}
          setQuickSearch={setQuickSearch}
          onSearchSubmit={() => {
            if (quickSearch) {
              handleRunScan(quickSearch);
              setQuickSearch('');
            }
          }}
        />

        <main className="flex-1 p-6 space-y-6 overflow-y-auto">
          {activeTab === 'dashboard' && (
            <ASNDashboardPage
              currentScan={currentScan}
              history={history}
              onScan={handleRunScan}
              onPassToModule02={handlePassToModule02}
              isLoading={scanMutation.isPending}
            />
          )}

          {activeTab === 'module1' && (
            <ASNScanPage
              currentScan={currentScan}
              onScan={handleRunScan}
              onBulkScan={handleBulkScan}
              isLoading={scanMutation.isPending}
            />
          )}

          {activeTab === 'module2' && (
            <div className="glass-panel p-8 rounded-xl border border-slate-800 space-y-4">
              <div className="flex items-center gap-3">
                <div className="p-3 rounded-lg bg-cyan-500/20 text-cyan-400">
                  <ShieldAlert className="w-6 h-6" />
                </div>
                <div>
                  <h2 className="text-xl font-bold text-white">Module 02: Network Reconnaissance</h2>
                  <p className="text-xs text-slate-400">Automated Pipeline Consumer</p>
                </div>
              </div>

              {module02Active ? (
                <div className="p-5 rounded-lg bg-slate-950 border border-slate-800 space-y-3 font-mono text-xs">
                  <div className="text-emerald-400 font-bold flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4" />
                    Module 02 automatically received Module 01 ASN Intelligence Profile:
                  </div>
                  <pre className="p-4 rounded bg-slate-900 text-slate-300 overflow-x-auto text-[11px]">
                    {JSON.stringify(module02Active, null, 2)}
                  </pre>
                  <p className="text-slate-400 font-sans text-xs">
                    Module 02 uses this payload to scan target subnets ({module02Active.subnetsToScan?.join(', ') || 'N/A'}), perform DNS resolution, discover open ports/services, and generate topology graphs.
                  </p>
                </div>
              ) : (
                <div className="p-6 text-center text-slate-500 text-xs font-mono">
                  No active payload passed yet. Run Module 01 scan first and click "Pass Output to Module 02".
                </div>
              )}
            </div>
          )}

          {activeTab === 'history' && (
            <ScanHistoryPage
              history={history}
              onSelectScan={(scanId) => {
                const found = history.find(h => h.scanId === scanId);
                if (found) {
                  handleRunScan(found.targetIp);
                  setActiveTab('dashboard');
                }
              }}
              onDeleteScan={handleDeleteScan}
            />
          )}
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <SOCMainApp />
    </QueryClientProvider>
  );
}
