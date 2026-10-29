import React, { useState, useEffect } from 'react';
import { Header } from './components/landing/Header';
import { HomePage } from './components/landing/HomePage';
import { BankingSystemsCatalog } from './components/BankingSystemsCatalog';
import { BankingRiskOverview } from './components/BankingRiskOverview';
import { WhatIfSimulator } from './components/WhatIfSimulator';
import { StandardsModal } from './components/StandardsModal';
import { JsonExportModal } from './components/JsonExportModal';
import type { ScanResponse } from './types/scan';
import { scanDomain, checkBackendHealth } from './services/api';
import { Shield } from 'lucide-react';

export function App() {
  const [activeView, setActiveView] = useState<'scanner' | 'catalog' | 'risk' | 'simulator'>('scanner');
  const [selectedAssetId, setSelectedAssetId] = useState<string>('');
  const [simulatorAssetId, setSimulatorAssetId] = useState<string>('BANK-PROF-CORE-BANKING');
  const [scanData, setScanData] = useState<ScanResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [backendOnline, setBackendOnline] = useState<boolean>(true);
  const [standardsModalOpen, setStandardsModalOpen] = useState<boolean>(false);
  const [exportModalOpen, setExportModalOpen] = useState<boolean>(false);

  useEffect(() => {
    checkBackendHealth().then(setBackendOnline);
  }, []);

  const handleScan = async (
    domain: string,
    port: number = 443,
    probePqc: boolean = false,
    assetId?: string
  ) => {
    setIsLoading(true);
    setErrorMessage(null);
    if (assetId !== undefined) {
      setSelectedAssetId(assetId);
    }

    try {
      const result = await scanDomain(domain, port, probePqc, assetId || selectedAssetId || undefined);
      setScanData(result);
      setBackendOnline(true);
    } catch (err: any) {
      setErrorMessage(err.message || 'An unexpected error occurred during scan.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleAuditFromCatalog = (profileId: string, suggestedDomain: string = 'api.chase.com') => {
    setSelectedAssetId(profileId);
    setActiveView('scanner');
    handleScan(suggestedDomain, 443, false, profileId);
  };

  const handleOpenSimulator = (profileId: string) => {
    setSimulatorAssetId(profileId);
    setActiveView('simulator');
  };

  const handleGetStarted = () => {
    setActiveView('scanner');
    setTimeout(() => {
      const input = document.getElementById('domain-scanner-input');
      if (input) {
        input.focus();
        input.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }, 50);
  };

  return (
    <div className="min-h-screen bg-[#FCFCFA] text-slate-900 flex flex-col selection:bg-[#5755D9]/20 selection:text-[#5755D9]">
      {/* 1. Recreated Reference Header */}
      <Header
        activeView={activeView}
        onSelectView={setActiveView}
        onOpenDocumentation={() => setStandardsModalOpen(true)}
        onOpenExportModal={() => setExportModalOpen(true)}
        hasScanData={!!scanData}
        onGetStarted={handleGetStarted}
      />

      {/* 2. Main Body Content */}
      <main className="flex-1 w-full">
        {activeView === 'simulator' ? (
          /* View 1: What-If Migration Simulator */
          <div className="max-w-[1500px] mx-auto px-6 sm:px-10 lg:px-[85px] py-8 animate-in fade-in duration-200">
            <WhatIfSimulator initialAssetId={simulatorAssetId} />
          </div>
        ) : activeView === 'catalog' ? (
          /* View 2: Representative Banking Systems Catalog */
          <div className="max-w-[1500px] mx-auto px-6 sm:px-10 lg:px-[85px] py-8 animate-in fade-in duration-200">
            <BankingSystemsCatalog
              onAuditProfile={handleAuditFromCatalog}
              onSimulateProfile={handleOpenSimulator}
            />
          </div>
        ) : activeView === 'risk' ? (
          /* View 3: Banking Migration Prioritization Engine */
          <div className="max-w-[1500px] mx-auto px-6 sm:px-10 lg:px-[85px] py-8 animate-in fade-in duration-200">
            <BankingRiskOverview
              onAuditProfile={handleAuditFromCatalog}
              onSimulateProfile={handleOpenSimulator}
            />
          </div>
        ) : (
          /* View 4: Recreated Reference Home / Landing Page */
          <HomePage
            onScan={handleScan}
            isLoading={isLoading}
            currentDomain={scanData?.target.domain}
            initialAssetId={selectedAssetId}
            scanData={scanData}
            errorMessage={errorMessage}
            onSelectView={setActiveView}
            onOpenSimulator={handleOpenSimulator}
            onAuditProfile={handleAuditFromCatalog}
          />
        )}
      </main>

      {/* Modals */}
      <StandardsModal
        isOpen={standardsModalOpen}
        onClose={() => setStandardsModalOpen(false)}
      />

      <JsonExportModal
        isOpen={exportModalOpen}
        onClose={() => setExportModalOpen(false)}
        data={scanData}
      />

      {/* 3. Enterprise Minimalist Footer */}
      <footer className="border-t border-slate-200/80 bg-white py-8 mt-16 text-center text-xs text-slate-500">
        <div className="max-w-[1500px] mx-auto px-6 sm:px-10 lg:px-[85px] flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center space-x-2">
            <div className="w-5 h-5 rounded-md bg-[#F4F3FF] border border-[#5755D9]/30 flex items-center justify-center text-[#5755D9]">
              <Shield className="w-3 h-3 text-[#5755D9]" />
            </div>
            <span className="font-semibold text-slate-700">QuantumShield</span>
            <span className="text-slate-300">·</span>
            <span className="text-slate-500 text-[11px]">Banking Security Audit & Zero-Trust Readiness</span>
          </div>

          <p className="text-slate-400 text-[11px]">
            Methodology aligned with NIST FIPS 203/204/205 & NSA Commercial National Security Algorithm Suite 2.0 (CNSA 2.0).
          </p>

          <div className="text-[11px] text-slate-400 font-mono">
            Non-invasive · External Configuration Only
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
