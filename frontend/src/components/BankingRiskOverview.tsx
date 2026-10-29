import React, { useState, useEffect } from 'react';
import type { BankingRiskAssessment } from '../types/scan';
import { getBankingRiskRankings } from '../services/api';
import {
  ShieldAlert,
  ArrowRight,
  TrendingUp,
  AlertTriangle,
  Lock,
  Layers,
  Clock,
  KeyRound,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Loader2,
  Info,
  Sliders,
} from 'lucide-react';

interface BankingRiskOverviewProps {
  onAuditProfile: (profileId: string, suggestedDomain?: string) => void;
}

const PROFILE_DEFAULT_DOMAINS: Record<string, string> = {
  'BANK-PROF-PAYMENT-GATEWAY': 'api.chase.com',
  'BANK-PROF-CORE-BANKING': 'python.org',
  'BANK-PROF-KYC-DB': 'cloudflare.com',
  'BANK-PROF-NET-BANKING': 'google.com',
  'BANK-PROF-ATM-NETWORK': 'api.chase.com',
};

export const BankingRiskOverview: React.FC<BankingRiskOverviewProps> = ({ onAuditProfile }) => {
  const [rankings, setRankings] = useState<BankingRiskAssessment[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>('BANK-PROF-CORE-BANKING');

  useEffect(() => {
    let isMounted = true;
    setIsLoading(true);
    getBankingRiskRankings()
      .then((data) => {
        if (isMounted) {
          setRankings(data);
          setError(null);
        }
      })
      .catch((err) => {
        if (isMounted) {
          setError(err.message || 'Failed to load banking risk rankings.');
        }
      })
      .finally(() => {
        if (isMounted) setIsLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, []);

  const getPriorityBadge = (priority: string) => {
    switch (priority) {
      case 'P0':
        return 'bg-rose-950/90 text-rose-300 border-rose-800 shadow-rose-950/50';
      case 'P1':
        return 'bg-amber-950/90 text-amber-300 border-amber-800 shadow-amber-950/50';
      case 'P2':
        return 'bg-sky-950/90 text-sky-300 border-sky-800 shadow-sky-950/50';
      case 'P3':
        return 'bg-emerald-950/90 text-emerald-300 border-emerald-800 shadow-emerald-950/50';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getChainBadge = (status: string) => {
    switch (status) {
      case 'QUANTUM_READY':
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-800/80';
      case 'PARTIALLY_QUANTUM_READY':
        return 'bg-sky-950/80 text-sky-300 border-sky-800/80';
      case 'QUANTUM_EXPOSED':
        return 'bg-rose-950/80 text-rose-300 border-rose-800/80';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header & Principle Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-br from-slate-900/90 via-slate-900/70 to-slate-950/90 border border-slate-800 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-40 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start space-x-3.5">
            <div className="p-3 rounded-xl bg-gradient-to-br from-cyan-950/90 to-indigo-950/90 border border-cyan-800/60 text-cyan-400 shrink-0">
              <TrendingUp className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-xl font-bold text-white tracking-wide">
                  Banking Migration Priority & Criticality Engine
                </h2>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/60 font-semibold">
                  Phase 4B
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
                Answers: <strong>Which banking systems should be migrated first, and why?</strong> Correlates
                technical cryptographic risk with business criticality, data sensitivity, SNDL lifetime, network
                exposure, and multi-year migration effort.
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2 px-3 py-1.5 rounded-xl bg-slate-950/80 border border-slate-800 self-start md:self-auto text-xs font-mono">
            <span className="text-slate-400">Formula:</span>
            <span className="text-cyan-300 font-bold">Tech Risk &times; Business Exposure &times; Urgency</span>
          </div>
        </div>

        {/* Core Principles Alert */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-4 text-xs">
          <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/60 flex items-start space-x-2.5">
            <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
            <div className="text-slate-300 leading-relaxed text-[11px]">
              <strong className="text-cyan-300 font-semibold">Store Now, Decrypt Later (SNDL):</strong> Long-lived
              sensitive data has greater exposure to Store Now, Decrypt Later risk because confidentiality must remain intact
              for an extended period. Systems holding multi-decade financial records (e.g. Core Banking general ledger, KYC records)
              take migration precedence over ephemeral public sessions.
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/60 flex items-start space-x-2.5">
            <Lock className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <div className="text-slate-300 leading-relaxed text-[11px]">
              <strong className="text-amber-300 font-semibold">AES-256 Grover Resilience:</strong> AES-256 retains
              approximately 128-bit security against an idealized Grover search and is not treated as a quantum-broken
              primitive by QuantumShield. Migration priority focuses on asymmetric key wrapping (RSA/ECDH) and root authentication signatures.
            </div>
          </div>
        </div>

        {/* Synthetic Environment Disclaimer */}
        <div className="p-3 rounded-xl bg-amber-950/30 border border-amber-800/50 text-amber-200/90 text-[11px] flex items-start space-x-2.5 mt-3">
          <Info className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <p className="leading-relaxed">
            <strong className="text-amber-300 font-semibold">Synthetic Environment Disclaimer:</strong>{' '}
            QuantumShield's banking profiles are representative synthetic environments used to demonstrate security
            auditing and migration prioritization. They do not represent the actual architecture or configuration of
            any specific bank.
          </p>
        </div>
      </div>

      {/* Loading & Error States */}
      {isLoading && (
        <div className="p-12 text-center space-y-3">
          <Loader2 className="w-8 h-8 animate-spin text-cyan-400 mx-auto" />
          <p className="text-xs text-slate-400 font-mono">Computing multidimensional banking migration rankings...</p>
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/60 border border-rose-800/80 text-rose-200 text-xs flex items-start space-x-3">
          <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />
          <div>
            <div className="font-bold text-rose-300">Failed to load risk rankings</div>
            <div className="text-slate-300 mt-0.5">{error}</div>
          </div>
        </div>
      )}

      {/* Ranked Systems List */}
      {!isLoading && !error && (
        <div className="space-y-4">
          <div className="flex items-center justify-between text-xs text-slate-400 px-1 font-mono">
            <span>PRIORITIZED MIGRATION QUEUE ({rankings.length} Systems Ranked)</span>
            <span>Deterministic 0-100 Priority Score</span>
          </div>

          {rankings.map((item, idx) => {
            const isExpanded = expandedId === item.asset_id;
            return (
              <div
                key={item.asset_id}
                className="rounded-2xl bg-gradient-to-br from-slate-900/90 via-slate-900/70 to-slate-950/90 border border-slate-800 shadow-xl overflow-hidden transition-all duration-200 hover:border-slate-700"
              >
                {/* Ranking Card Header */}
                <div className="p-5">
                  <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                    <div className="flex items-start space-x-3.5">
                      {/* Rank Index Pill */}
                      <div className="flex flex-col items-center justify-center w-11 h-11 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 font-black text-base shrink-0 font-mono shadow-inner">
                        <span className="text-[9px] text-slate-500 font-normal">RANK</span>
                        <span>#{idx + 1}</span>
                      </div>

                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <h3 className="text-base font-bold text-white tracking-wide">{item.asset_name}</h3>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                            {item.asset_id}
                          </span>
                          <span
                            className={`text-[10px] font-mono font-bold px-2.5 py-0.5 rounded-full border uppercase shadow-sm ${getPriorityBadge(
                              item.migration_priority
                            )}`}
                          >
                            {item.priority_band_label}
                          </span>
                        </div>

                        <div className="flex flex-wrap items-center gap-3 mt-1.5 text-xs text-slate-400">
                          <span className="font-mono text-[11px] text-cyan-300">
                            Planning: {item.recommended_planning_window}
                          </span>
                          <span>&bull;</span>
                          <span className="font-mono text-[11px] text-slate-300">
                            Criticality: <strong className="text-white">{item.business_context.criticality_label}</strong>
                          </span>
                          <span>&bull;</span>
                          <span className="font-mono text-[11px] text-slate-300">
                            SNDL Lifetime: <strong className="text-white">{item.business_context.lifetime_label}</strong>
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Score Gauge & Actions */}
                    <div className="flex items-center space-x-4 self-end lg:self-center shrink-0">
                      <div className="text-right">
                        <div className="text-[10px] font-mono uppercase text-slate-400">Priority Score</div>
                        <div className="text-2xl font-black text-cyan-400 font-mono leading-none mt-0.5">
                          {item.priority_score}
                          <span className="text-xs text-slate-500 font-normal">/100</span>
                        </div>
                      </div>

                      <button
                        onClick={() => {
                          const suggested = PROFILE_DEFAULT_DOMAINS[item.asset_id] || 'example.com';
                          onAuditProfile(item.asset_id, suggested);
                        }}
                        className="inline-flex items-center space-x-1 px-3 py-2 rounded-lg bg-cyan-600/80 hover:bg-cyan-500 text-white text-xs font-semibold shadow-md transition cursor-pointer"
                        title="Audit this banking system with live external scan"
                      >
                        <span>Audit</span>
                        <ArrowRight className="w-3.5 h-3.5" />
                      </button>

                      <button
                        onClick={() => setExpandedId(isExpanded ? null : item.asset_id)}
                        className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition cursor-pointer"
                        aria-label={isExpanded ? 'Collapse analysis' : 'Expand analysis'}
                      >
                        {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  {/* Weak Links Quick Chips */}
                  {item.key_protection.weak_links.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1.5 mt-3 pt-3 border-t border-slate-800/60 text-xs">
                      <span className="text-[11px] font-mono text-slate-400 flex items-center space-x-1">
                        <AlertTriangle className="w-3 h-3 text-amber-400" />
                        <span>Key Weak Links:</span>
                      </span>
                      {item.key_protection.weak_links.map((link, lIdx) => (
                        <span
                          key={lIdx}
                          className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950/60 text-rose-300 border border-rose-800/60"
                        >
                          {link}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                {/* Expanded Detailed Analysis */}
                {isExpanded && (
                  <div className="p-5 bg-slate-950/60 border-t border-slate-800 space-y-5 animate-in fade-in duration-200">
                    {/* Narrative Explanation */}
                    <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-1.5">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-bold text-slate-200 flex items-center space-x-2">
                          <Sliders className="w-3.5 h-3.5 text-cyan-400" />
                          <span>Why {item.migration_priority}? Deterministic Risk Rationale</span>
                        </span>
                        <span className="text-[10px] font-mono text-slate-400">
                          {item.priority_band_label}
                        </span>
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed">{item.explanation}</p>
                    </div>

                    {/* "Why This Ranking?" Contributor Bars */}
                    <div>
                      <div className="text-xs font-bold text-slate-200 mb-3 flex items-center justify-between">
                        <span>Risk & Business Factor Contributors</span>
                        <span className="text-[10px] font-mono text-slate-500">6 Dimension Assessment</span>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                        {item.contributors.map((contrib, cIdx) => (
                          <div
                            key={cIdx}
                            className="p-3 rounded-xl bg-slate-900/70 border border-slate-800/80 space-y-1.5"
                          >
                            <div className="flex items-center justify-between text-xs">
                              <span className="text-slate-400 text-[11px] font-medium">{contrib.factor}</span>
                              <span className="font-mono text-xs font-bold text-cyan-300">{contrib.label}</span>
                            </div>

                            {/* Contributor Visual Bar */}
                            <div className="w-full h-1.5 bg-slate-950 rounded-full overflow-hidden border border-slate-800">
                              <div
                                className="h-full bg-gradient-to-r from-cyan-500 to-indigo-500 rounded-full transition-all duration-300"
                                style={{ width: `${Math.max(12, contrib.weight_pct)}%` }}
                              />
                            </div>

                            {contrib.description && (
                              <p className="text-[10px] text-slate-500 line-clamp-1">{contrib.description}</p>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Key Protection Chain Analysis */}
                    <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-slate-200 flex items-center space-x-2">
                          <Lock className="w-3.5 h-3.5 text-cyan-400" />
                          <span>Key Protection Chain Posture</span>
                        </span>
                        <span
                          className={`text-[10px] font-mono font-semibold px-2.5 py-0.5 rounded border uppercase ${getChainBadge(
                            item.key_protection.status
                          )}`}
                        >
                          {item.key_protection.status.replace(/_/g, ' ')}
                        </span>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-4 gap-2 text-xs">
                        <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800">
                          <span className="text-[10px] font-mono text-slate-500 block uppercase">1. Data Encryption</span>
                          <span className="font-mono text-xs font-bold text-emerald-400">
                            {item.key_protection.data_encryption_algorithm || 'None'}
                          </span>
                          <span className="text-[10px] text-slate-400 block mt-0.5">
                            {item.key_protection.data_encryption_status === 'ADEQUATE_GROVER_RESILIENT'
                              ? '✓ Grover Resilient'
                              : item.key_protection.data_encryption_status}
                          </span>
                        </div>

                        <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800">
                          <span className="text-[10px] font-mono text-slate-500 block uppercase">2. Key Wrapping</span>
                          <span className="font-mono text-xs font-bold text-sky-400">
                            {item.key_protection.key_wrapping_algorithm || 'None'}
                          </span>
                          <span className="text-[10px] text-slate-400 block mt-0.5">
                            {item.key_protection.key_wrapping_status === 'QUANTUM_READY'
                              ? '✓ Quantum Ready'
                              : item.key_protection.key_wrapping_status === 'QUANTUM_VULNERABLE'
                              ? '⚠ Quantum Vulnerable'
                              : item.key_protection.key_wrapping_status}
                          </span>
                        </div>

                        <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800">
                          <span className="text-[10px] font-mono text-slate-500 block uppercase">3. Key Storage</span>
                          <span className="font-mono text-xs font-bold text-amber-400">
                            {item.key_protection.key_storage_facility || 'Standard'}
                          </span>
                          <span className="text-[10px] text-slate-400 block mt-0.5">
                            {item.key_protection.key_storage_status === 'HARDWARE_PROTECTED'
                              ? '✓ Certified HSM'
                              : item.key_protection.key_storage_status === 'CLOUD_KMS_PROTECTED'
                              ? '✓ Cloud KMS'
                              : item.key_protection.key_storage_status}
                          </span>
                        </div>

                        <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800">
                          <span className="text-[10px] font-mono text-slate-500 block uppercase">4. Authentication</span>
                          <span className="font-mono text-xs font-bold text-violet-400">
                            {item.key_protection.authentication_algorithm || 'Standard'}
                          </span>
                          <span className="text-[10px] text-slate-400 block mt-0.5">
                            {item.key_protection.authentication_status === 'QUANTUM_READY'
                              ? '✓ Post-Quantum Sign'
                              : item.key_protection.authentication_status === 'QUANTUM_VULNERABLE'
                              ? '⚠ Quantum Vulnerable'
                              : item.key_protection.authentication_status}
                          </span>
                        </div>
                      </div>

                      {item.key_protection.primary_migration_dependencies.length > 0 && (
                        <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/80 text-[11px] space-y-1">
                          <span className="font-semibold text-cyan-300">Primary Migration Dependencies:</span>
                          <ul className="list-disc list-inside space-y-0.5 text-slate-300">
                            {item.key_protection.primary_migration_dependencies.map((dep, dIdx) => (
                              <li key={dIdx}>{dep}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

