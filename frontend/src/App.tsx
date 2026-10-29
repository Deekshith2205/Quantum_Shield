import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { DomainInput } from './components/DomainInput';
import { ScoreCard } from './components/ScoreCard';
import { ExecutiveSummaryCard } from './components/ExecutiveSummaryCard';
import { RoleGroupedAssessments } from './components/RoleGroupedAssessments';
import { TlsOverview } from './components/TlsOverview';
import { CryptographicFindings } from './components/CryptographicFindings';
import { MigrationRoadmap } from './components/MigrationRoadmap';
import { ObservabilityNotes } from './components/ObservabilityNotes';
import { BankingAssetCard } from './components/BankingAssetCard';
import { BankingSystemCard } from './components/BankingSystemCard';
import { BankingSystemsCatalog } from './components/BankingSystemsCatalog';
import { BankingRiskOverview } from './components/BankingRiskOverview';
import { StandardsModal } from './components/StandardsModal';
import { JsonExportModal } from './components/JsonExportModal';
import type { ScanResponse } from './types/scan';
import { scanDomain, checkBackendHealth } from './services/api';
import { AlertCircle, Shield, Globe, Landmark, TrendingUp } from 'lucide-react';

export function App() {
  const [activeView, setActiveView] = useState<'scanner' | 'catalog' | 'risk'>('scanner');
  const [selectedAssetId, setSelectedAssetId] = useState<string>('');
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

  return (
    <div className="min-h-screen bg-[#0b0f19] text-slate-100 flex flex-col selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Navbar */}
      <Navbar
        onOpenStandardsModal={() => setStandardsModalOpen(true)}
        onOpenExportModal={() => setExportModalOpen(true)}
        hasScanData={!!scanData}
        backendOnline={backendOnline}
        activeView={activeView}
        onSelectView={setActiveView}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-8">
        {/* Mobile View Switcher */}
        <div className="flex md:hidden items-center justify-center space-x-1 p-1 rounded-xl bg-slate-900/80 border border-slate-800 text-[11px] max-w-md mx-auto">
          <button
            onClick={() => setActiveView('scanner')}
            className={`flex-1 py-1.5 rounded-lg font-semibold transition text-center cursor-pointer ${
              activeView === 'scanner'
                ? 'bg-gradient-to-r from-cyan-600/90 to-indigo-600/90 text-white shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Scanner
          </button>
          <button
            onClick={() => setActiveView('catalog')}
            className={`flex-1 py-1.5 rounded-lg font-semibold transition text-center cursor-pointer ${
              activeView === 'catalog'
                ? 'bg-gradient-to-r from-cyan-600/90 to-indigo-600/90 text-white shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Banking (5)
          </button>
          <button
            onClick={() => setActiveView('risk')}
            className={`flex-1 py-1.5 rounded-lg font-semibold transition text-center cursor-pointer ${
              activeView === 'risk'
                ? 'bg-gradient-to-r from-cyan-600/90 to-indigo-600/90 text-white shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Priority (P0–P3)
          </button>
        </div>

        {/* View 1: Representative Banking Systems Catalog */}
        {activeView === 'catalog' ? (
          <BankingSystemsCatalog onAuditProfile={handleAuditFromCatalog} />
        ) : activeView === 'risk' ? (
          /* View 2: Banking Migration Prioritization Engine */
          <BankingRiskOverview onAuditProfile={handleAuditFromCatalog} />
        ) : (
          /* View 3: Live Domain Scanner */
          <>
            {/* Domain Search / Assessment Hero */}
            <DomainInput
              onScan={handleScan}
              isLoading={isLoading}
              currentDomain={scanData?.target.domain}
              initialAssetId={selectedAssetId}
            />

            {/* Error Alert Banner */}
            {errorMessage && (
              <div className="max-w-3xl mx-auto p-4 rounded-2xl bg-rose-950/70 border border-rose-800/80 text-rose-200 text-sm flex items-start space-x-3 shadow-lg">
                <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <h4 className="font-bold text-rose-300">Assessment Error</h4>
                  <p className="text-xs text-rose-200/90 leading-relaxed">{errorMessage}</p>
                </div>
              </div>
            )}

            {/* Scan Results View */}
            {scanData && !isLoading && (
              <div className="space-y-8 animate-in fade-in duration-300">
                {/* 0. Banking System Profile & Key Chain Context (Phase 4A & 4B) */}
                {scanData.banking_asset && (
                  <BankingSystemCard
                    profile={scanData.banking_asset}
                    risk={scanData.banking_risk}
                    isDetailedView={true}
                  />
                )}

                {/* 1. Overall Quantum Readiness Score & 5-Role Breakdown */}
                <ScoreCard score={scanData.score} domain={scanData.target.domain} />

                {/* 2. Executive Summary */}
                {scanData.executive_summary && (
                  <ExecutiveSummaryCard summary={scanData.executive_summary} />
                )}

                {/* 3. Findings Grouped by Cryptographic Role */}
                {scanData.role_assessments && scanData.role_assessments.length > 0 && (
                  <RoleGroupedAssessments assessments={scanData.role_assessments} />
                )}

                {/* 4. Public TLS Configuration Overview */}
                <TlsOverview
                  target={scanData.target}
                  certificate={scanData.certificate}
                  tls={scanData.tls}
                />

                {/* 5. Detailed Cryptographic Findings */}
                <CryptographicFindings findings={scanData.findings} />

                {/* 6. Prioritized Post-Quantum Migration Roadmap (P0, P1, P2, P3) */}
                <MigrationRoadmap plan={scanData.migration_plan} />

                {/* 7. Observability Scope (What QuantumShield Can Observe) */}
                <ObservabilityNotes
                  scope={scanData.observability_scope}
                  notes={scanData.not_observable_notes}
                />
              </div>
            )}
          </>
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

      {/* Security Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/60 py-6 mt-12 text-center text-xs text-slate-500 space-y-2">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center space-x-2">
            <Shield className="w-4 h-4 text-cyan-500" />
            <span className="font-semibold text-slate-400">QuantumShield Assessment Platform</span>
          </div>
          <p className="text-slate-500 text-[11px]">
            Methodology aligned with NIST FIPS 203/204/205 & NSA Commercial National Security Algorithm Suite 2.0 (CNSA 2.0).
          </p>
          <div className="text-[11px] text-slate-500 font-mono">
            Non-invasive · External Configuration Only
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
