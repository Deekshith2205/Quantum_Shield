import React, { useRef, useEffect } from 'react';
import { HeroSection } from './HeroSection';
import { CapabilityGrid } from './CapabilityGrid';
import type { ScanResponse } from '../../types/scan';
import { ScoreCard } from '../ScoreCard';
import { ExecutiveSummaryCard } from '../ExecutiveSummaryCard';
import { RoleGroupedAssessments } from '../RoleGroupedAssessments';
import { TlsOverview } from '../TlsOverview';
import { CryptographicFindings } from '../CryptographicFindings';
import { MigrationRoadmap } from '../MigrationRoadmap';
import { ObservabilityNotes } from '../ObservabilityNotes';
import { BankingSystemCard } from '../BankingSystemCard';
import { AlertCircle, CheckCircle2, Shield, ArrowUpRight } from 'lucide-react';

interface HomePageProps {
  onScan: (domain: string, port: number, probePqc?: boolean, assetId?: string) => void;
  isLoading: boolean;
  currentDomain?: string;
  initialAssetId?: string;
  scanData: ScanResponse | null;
  errorMessage: string | null;
  onSelectView: (view: 'scanner' | 'catalog' | 'risk' | 'simulator') => void;
  onOpenSimulator: (assetId: string) => void;
  onAuditProfile: (profileId: string, domain?: string) => void;
}

export const HomePage: React.FC<HomePageProps> = ({
  onScan,
  isLoading,
  currentDomain,
  initialAssetId,
  scanData,
  errorMessage,
  onSelectView,
  onOpenSimulator,
  onAuditProfile,
}) => {
  const resultsRef = useRef<HTMLDivElement>(null);

  // Smooth scroll to results when scan finishes
  useEffect(() => {
    if (scanData && !isLoading && resultsRef.current) {
      resultsRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, [scanData, isLoading]);

  const handleStartScanning = () => {
    const input = document.getElementById('domain-scanner-input');
    if (input) {
      input.focus();
      input.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  };

  return (
    <div className="w-full flex flex-col">
      {/* 1. Main Two-Column Editorial Hero */}
      <HeroSection
        onScan={onScan}
        isLoading={isLoading}
        currentDomain={currentDomain}
        initialAssetId={initialAssetId}
      />

      {/* 2. Error Alert Banner (if scan fails) */}
      {errorMessage && (
        <div className="max-w-4xl mx-auto px-6 w-full mb-8">
          <div className="p-4 rounded-2xl bg-rose-50 border border-rose-200 text-rose-900 text-sm flex items-start space-x-3 shadow-xs">
            <AlertCircle className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <h4 className="font-semibold text-rose-800">Assessment Error</h4>
              <p className="text-xs text-rose-700 leading-relaxed">{errorMessage}</p>
            </div>
          </div>
        </div>
      )}

      {/* 3. Four-Column Capability Section */}
      <CapabilityGrid
        onStartScanning={handleStartScanning}
        onViewRiskModel={() => onSelectView('risk')}
        onTrySimulation={() => onSelectView('simulator')}
        onExploreBankingSystems={() => onSelectView('catalog')}
      />

      {/* 4. Live Cryptographic Scan Telemetry & Results View */}
      {scanData && !isLoading && (
        <div
          ref={resultsRef}
          id="scan-results"
          className="w-full max-w-[1500px] mx-auto px-6 sm:px-10 lg:px-[85px] py-10 space-y-8 animate-in fade-in duration-500 border-t border-slate-200/80 mt-4"
        >
          {/* Results Section Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-200/80 gap-3">
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xs font-mono uppercase px-2.5 py-0.5 rounded-full bg-[#EEF2FF] text-[#5B5BD6] font-semibold tracking-wider">
                  Live Audit Telemetry
                </span>
                <span className="text-xs text-slate-500 font-mono">
                  {scanData.target.domain}:{scanData.target.port}
                </span>
              </div>
              <h2 className="text-2xl font-light text-slate-900 tracking-tight mt-1">
                Cryptographic & Quantum Readiness Assessment
              </h2>
            </div>

            <div className="flex items-center space-x-3">
              <button
                type="button"
                onClick={handleStartScanning}
                className="text-xs font-medium text-slate-600 hover:text-slate-900 transition cursor-pointer"
              >
                ← Scan Another Domain
              </button>
            </div>
          </div>

          {/* Results Telemetry Container */}
          <div className="space-y-8">
            {/* 0. Banking System Profile & Key Chain Context (Phase 4A & 4B) */}
            {scanData.banking_asset && (
              <BankingSystemCard
                profile={scanData.banking_asset}
                risk={scanData.banking_risk}
                onSimulate={onOpenSimulator}
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
        </div>
      )}
    </div>
  );
};
