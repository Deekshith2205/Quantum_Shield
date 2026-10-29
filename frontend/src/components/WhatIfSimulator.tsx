import React, { useState, useEffect } from 'react';
import type {
  BankingAsset,
  MigrationComponent,
  MigrationAction,
  WhatIfMigrationResult,
} from '../types/scan';
import { getBankingProfiles, simulateMigration } from '../services/api';
import {
  Sparkles,
  ArrowRight,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Layers,
  Cpu,
  Shield,
  Loader2,
  Info,
  Plus,
  Trash2,
  Check,
  TrendingDown,
  FileCheck2,
} from 'lucide-react';

interface WhatIfSimulatorProps {
  initialAssetId?: string;
  onClose?: () => void;
}

const SUPPORTED_TARGETS: Record<MigrationComponent, { value: string; label: string; desc: string }[]> = {
  KEY_WRAPPING: [
    { value: 'ML-KEM-768', label: 'ML-KEM-768 (FIPS 203)', desc: 'NIST Standardized Category 3 Lattice KEM (Primary)' },
    { value: 'ML-KEM-1024', label: 'ML-KEM-1024 (FIPS 203)', desc: 'NIST Category 5 Maximum Security Lattice KEM' },
    { value: 'X25519MLKEM768', label: 'X25519MLKEM768 Hybrid', desc: 'IETF RFC 9870 Hybrid Classical + PQC KEM' },
    { value: 'AES-256-KW', label: 'AES-256 Key Wrap (NIST SP 800-38F)', desc: 'Symmetric Key Wrap (Grover Resilient)' },
  ],
  AUTHENTICATION: [
    { value: 'ML-DSA-65', label: 'ML-DSA-65 (FIPS 204)', desc: 'NIST Standardized Lattice Signature (Primary)' },
    { value: 'ML-DSA-87', label: 'ML-DSA-87 (FIPS 204)', desc: 'NIST Category 5 High Security Lattice Signature' },
    { value: 'SLH-DSA-128s', label: 'SLH-DSA-128s (FIPS 205)', desc: 'Stateless Hash-Based Digital Signature Standard' },
    { value: 'SLH-DSA-128f', label: 'SLH-DSA-128f (FIPS 205)', desc: 'Fast Hash-Based Digital Signature' },
  ],
  TLS_PROTOCOL: [
    { value: 'TLSv1.3', label: 'TLS 1.3 (RFC 8446)', desc: 'Modern Transport Protocol removing obsolete ciphers' },
  ],
  TLS_KEY_EXCHANGE: [
    { value: 'X25519MLKEM768', label: 'X25519MLKEM768 Hybrid (0x11ec)', desc: 'IETF Draft Hybrid Key Agreement for TLS 1.3' },
    { value: 'SecP256r1MLKEM768', label: 'SecP256r1MLKEM768 Hybrid (0x11ed)', desc: 'NIST P-256 + ML-KEM-768 Hybrid Key Agreement' },
    { value: 'X448MLKEM1024', label: 'X448MLKEM1024 Hybrid (0x11ee)', desc: 'X448 + ML-KEM-1024 High Security Hybrid Group' },
  ],
};

export const WhatIfSimulator: React.FC<WhatIfSimulatorProps> = ({
  initialAssetId = 'BANK-PROF-CORE-BANKING',
  onClose,
}) => {
  const [profiles, setProfiles] = useState<BankingAsset[]>([]);
  const [selectedAssetId, setSelectedAssetId] = useState<string>(initialAssetId);
  const [changes, setChanges] = useState<MigrationAction[]>([
    {
      component: 'KEY_WRAPPING',
      target_algorithm: 'ML-KEM-768',
      description: 'Upgrade asymmetric key wrapping to NIST FIPS 203 ML-KEM-768',
    },
  ]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [result, setResult] = useState<WhatIfMigrationResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (initialAssetId) {
      setSelectedAssetId(initialAssetId);
      setResult(null);
    }
  }, [initialAssetId]);

  useEffect(() => {
    let isMounted = true;
    setIsLoading(true);
    getBankingProfiles()
      .then((data) => {
        if (isMounted) {
          setProfiles(data);
          if (!data.some((p) => p.id === selectedAssetId) && data.length > 0) {
            setSelectedAssetId(data[0].id);
          }
        }
      })
      .catch((err) => {
        if (isMounted) setError(err.message || 'Failed to load banking profiles.');
      })
      .finally(() => {
        if (isMounted) setIsLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, []);

  const selectedAsset = profiles.find((p) => p.id === selectedAssetId);

  const handleAddChange = () => {
    if (changes.length >= 5) return;
    setChanges([
      ...changes,
      {
        component: 'AUTHENTICATION',
        target_algorithm: 'ML-DSA-65',
        description: 'Upgrade root authentication signatures to FIPS 204 ML-DSA',
      },
    ]);
  };

  const handleRemoveChange = (index: number) => {
    if (changes.length <= 1) return;
    setChanges(changes.filter((_, i) => i !== index));
  };

  const handleUpdateChange = (index: number, updated: Partial<MigrationAction>) => {
    const next = [...changes];
    const curr = next[index];
    const newComponent = updated.component || curr.component;
    let newTarget = updated.target_algorithm || curr.target_algorithm;

    const allowed = SUPPORTED_TARGETS[newComponent];
    if (!allowed.some((a) => a.value === newTarget)) {
      newTarget = allowed[0].value;
    }

    next[index] = {
      ...curr,
      ...updated,
      component: newComponent,
      target_algorithm: newTarget,
    };
    setChanges(next);
  };

  const applyPreset = (presetType: 'wrapping' | 'auth' | 'full' | 'transport') => {
    if (presetType === 'wrapping') {
      setChanges([
        {
          component: 'KEY_WRAPPING',
          target_algorithm: 'ML-KEM-768',
          description: 'Migrate asymmetric key wrapping to NIST FIPS 203 ML-KEM-768',
        },
      ]);
    } else if (presetType === 'auth') {
      setChanges([
        {
          component: 'AUTHENTICATION',
          target_algorithm: 'ML-DSA-65',
          description: 'Transition digital signatures to NIST FIPS 204 ML-DSA-65',
        },
      ]);
    } else if (presetType === 'full') {
      setChanges([
        {
          component: 'KEY_WRAPPING',
          target_algorithm: 'ML-KEM-768',
          description: 'Migrate asymmetric key wrapping to NIST FIPS 203 ML-KEM-768',
        },
        {
          component: 'AUTHENTICATION',
          target_algorithm: 'ML-DSA-65',
          description: 'Transition digital signatures to NIST FIPS 204 ML-DSA-65',
        },
      ]);
    } else if (presetType === 'transport') {
      setChanges([
        {
          component: 'TLS_PROTOCOL',
          target_algorithm: 'TLSv1.3',
          description: 'Enforce modern TLS 1.3 protocol',
        },
        {
          component: 'TLS_KEY_EXCHANGE',
          target_algorithm: 'X25519MLKEM768',
          description: 'Deploy hybrid post-quantum key agreement group',
        },
      ]);
    }
  };

  const handleRunSimulation = async () => {
    setIsSimulating(true);
    setError(null);
    try {
      const simResult = await simulateMigration({
        asset_id: selectedAssetId,
        changes,
      });
      setResult(simResult);
    } catch (err: any) {
      setError(err.message || 'Simulation execution failed.');
    } finally {
      setIsSimulating(false);
    }
  };

  const getPriorityBadgeClass = (priority: string) => {
    switch (priority) {
      case 'P0':
        return 'bg-red-50 text-red-700 border-red-200';
      case 'P1':
        return 'bg-amber-50 text-amber-800 border-amber-200';
      case 'P2':
        return 'bg-indigo-50 text-indigo-700 border-indigo-200';
      case 'P3':
        return 'bg-emerald-50 text-emerald-800 border-emerald-200';
      default:
        return 'bg-slate-100 text-slate-700 border-slate-200';
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Editorial Page Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 pb-2">
        <div className="space-y-2">
          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono uppercase tracking-widest text-[#5755D9] font-semibold">
              POST-QUANTUM MIGRATION
            </span>
            <span className="text-slate-300">/</span>
            <span className="text-xs font-mono text-slate-500">
              Hypothetical Modeling Engine
            </span>
          </div>
          <div className="flex items-center space-x-3">
            <h1 className="text-3xl sm:text-4xl font-light text-[#17181C] tracking-tight">
              What-If Migration Simulator
            </h1>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-50 text-[#5755D9] border border-indigo-200 font-semibold uppercase">
              Phase 4C
            </span>
          </div>
          <p className="text-sm text-[#62656D] max-w-2xl leading-relaxed">
            Answers: <strong>"What happens to this banking system's risk if we replace a vulnerable mechanism?"</strong>{' '}
            Tests hypothetical migrations against the Phase 4B risk engine without mutating persistent state.
          </p>
        </div>

        <div className="flex items-center space-x-2 self-start md:self-auto">
          <span className="text-[10px] font-mono uppercase px-3 py-1.5 rounded-full bg-indigo-50 text-[#5755D9] border border-indigo-200 font-bold tracking-wider flex items-center space-x-1.5">
            <span className="w-2 h-2 rounded-full bg-[#5755D9] animate-pulse" />
            <span>SIMULATED PROVENANCE</span>
          </span>
        </div>
      </div>

      {/* Process Workflow Steps (Editorial 01-04) */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 py-1">
        <div className="p-3 rounded-xl bg-white border border-slate-200/90 shadow-xs">
          <span className="text-[10px] font-mono text-slate-400 font-bold block mb-0.5">01</span>
          <span className="text-xs font-bold text-slate-800">SELECT SYSTEM</span>
          <p className="text-[10px] text-slate-500 mt-0.5">Choose target banking asset</p>
        </div>
        <div className="p-3 rounded-xl bg-white border border-slate-200/90 shadow-xs">
          <span className="text-[10px] font-mono text-slate-400 font-bold block mb-0.5">02</span>
          <span className="text-xs font-bold text-slate-800">CONFIGURE MIGRATION</span>
          <p className="text-[10px] text-slate-500 mt-0.5">Define PQC substitutions</p>
        </div>
        <div className="p-3 rounded-xl bg-white border border-slate-200/90 shadow-xs">
          <span className="text-[10px] font-mono text-slate-400 font-bold block mb-0.5">03</span>
          <span className="text-xs font-bold text-slate-800">RUN SIMULATION</span>
          <p className="text-[10px] text-slate-500 mt-0.5">Execute isolated re-scoring</p>
        </div>
        <div className="p-3 rounded-xl bg-white border border-slate-200/90 shadow-xs">
          <span className="text-[10px] font-mono text-slate-400 font-bold block mb-0.5">04</span>
          <span className="text-xs font-bold text-slate-800">COMPARE RESULTS</span>
          <p className="text-[10px] text-slate-500 mt-0.5">Review delta & risk reduction</p>
        </div>
      </div>

      {/* Disclaimer Callout */}
      <div className="p-4 rounded-xl bg-slate-50 border border-slate-200/90 text-slate-700 text-xs flex items-start space-x-3">
        <Info className="w-4 h-4 text-[#5755D9] shrink-0 mt-0.5" />
        <p className="leading-relaxed text-xs">
          <strong className="text-slate-900 font-semibold">Hypothetical Simulation Semantics:</strong> This tool performs
          isolated mathematical risk recomputations against a temporary copy. It evaluates the impact of post-quantum replacements
          (FIPS 203 ML-KEM, FIPS 204 ML-DSA, hybrid TLS 1.3) before committing production engineering resources.
        </p>
      </div>

      {/* Main Simulation Builder */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Configuration & Controls (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          {/* Target System Picker */}
          <div className="p-4 rounded-xl bg-white border border-slate-200/90 shadow-xs space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="font-bold text-slate-900 flex items-center space-x-1.5">
                <Shield className="w-3.5 h-3.5 text-[#5755D9]" />
                <span>1. Select Banking System to Simulate</span>
              </span>
              <span className="font-mono text-[10px] text-slate-500">Synthetic Profile</span>
            </div>

            <select
              value={selectedAssetId}
              onChange={(e) => {
                setSelectedAssetId(e.target.value);
                setResult(null);
              }}
              className="w-full px-3 py-2 rounded-lg bg-white border border-slate-200 text-xs text-slate-900 focus:outline-none focus:border-[#5755D9] focus:ring-1 focus:ring-[#5755D9] transition cursor-pointer font-sans"
            >
              {profiles.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.id}) — {p.criticality}
                </option>
              ))}
            </select>

            {/* Current Crypto Architecture Preview */}
            {selectedAsset && selectedAsset.cryptography && (
              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-[11px] font-mono space-y-1.5 text-slate-700">
                <div className="text-[10px] uppercase text-slate-500 font-semibold">Current Baseline Crypto:</div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Key Wrapping:</span>
                  <span className="text-amber-800 font-bold">
                    {selectedAsset.cryptography.key_chain?.key_wrapping || 'None'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Root Authentication:</span>
                  <span className="text-amber-800 font-bold">
                    {selectedAsset.cryptography.key_chain?.authentication || 'None'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Bulk Data Encryption:</span>
                  <span className="text-emerald-700 font-bold">
                    {selectedAsset.cryptography.key_chain?.data_encryption || 'AES-256'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Transport Key Exchange:</span>
                  <span className="text-[#5755D9] font-medium">
                    {selectedAsset.cryptography.key_exchange || 'ECDHE'}
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* Migration Substitution Operations */}
          <div className="p-4 rounded-xl bg-white border border-slate-200/90 shadow-xs space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="font-bold text-slate-900 flex items-center space-x-1.5">
                <Cpu className="w-3.5 h-3.5 text-[#5755D9]" />
                <span>2. Configure Hypothetical Substitutions</span>
              </span>
              <span className="font-mono text-[10px] text-slate-500">{changes.length}/5 Ops</span>
            </div>

            {/* Quick 1-Click Presets */}
            <div className="space-y-1.5">
              <span className="text-[10px] font-mono text-slate-500">Quick Substitution Presets:</span>
              <div className="grid grid-cols-2 gap-1.5 text-[11px]">
                <button
                  type="button"
                  onClick={() => applyPreset('wrapping')}
                  className="px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-50 text-slate-700 hover:text-slate-900 border border-slate-200 text-left transition truncate cursor-pointer shadow-xs"
                >
                  ⚡ ML-KEM-768 Wrapping
                </button>
                <button
                  type="button"
                  onClick={() => applyPreset('auth')}
                  className="px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-50 text-slate-700 hover:text-slate-900 border border-slate-200 text-left transition truncate cursor-pointer shadow-xs"
                >
                  ⚡ ML-DSA-65 Signatures
                </button>
                <button
                  type="button"
                  onClick={() => applyPreset('full')}
                  className="px-2.5 py-1.5 rounded-lg bg-indigo-50/60 hover:bg-indigo-50 text-[#5755D9] border border-indigo-200 text-left transition truncate cursor-pointer font-semibold shadow-xs"
                >
                  🛡️ Full Stack PQC (KEM + DSA)
                </button>
                <button
                  type="button"
                  onClick={() => applyPreset('transport')}
                  className="px-2.5 py-1.5 rounded-lg bg-white hover:bg-slate-50 text-slate-700 hover:text-slate-900 border border-slate-200 text-left transition truncate cursor-pointer shadow-xs"
                >
                  🌐 Hybrid TLS 1.3 Transport
                </button>
              </div>
            </div>

            {/* Dynamic Operations List */}
            <div className="space-y-2.5 pt-2 border-t border-slate-100">
              {changes.map((change, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-2 relative"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono text-[#5755D9] font-bold uppercase">
                      Substitution #{idx + 1}
                    </span>
                    {changes.length > 1 && (
                      <button
                        type="button"
                        onClick={() => handleRemoveChange(idx)}
                        className="text-slate-400 hover:text-rose-600 transition cursor-pointer p-0.5"
                        title="Remove substitution"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div>
                      <label className="text-[10px] text-slate-500 font-mono block mb-1">Component</label>
                      <select
                        value={change.component}
                        onChange={(e) =>
                          handleUpdateChange(idx, { component: e.target.value as MigrationComponent })
                        }
                        className="w-full px-2 py-1.5 rounded bg-white border border-slate-200 text-[11px] text-slate-800 focus:outline-none focus:border-[#5755D9] cursor-pointer font-sans"
                      >
                        <option value="KEY_WRAPPING">Key Wrapping (KEK)</option>
                        <option value="AUTHENTICATION">Root Authentication</option>
                        <option value="TLS_KEY_EXCHANGE">TLS Key Exchange</option>
                        <option value="TLS_PROTOCOL">TLS Protocol</option>
                      </select>
                    </div>

                    <div>
                      <label className="text-[10px] text-slate-500 font-mono block mb-1">Target Algorithm</label>
                      <select
                        value={change.target_algorithm}
                        onChange={(e) => handleUpdateChange(idx, { target_algorithm: e.target.value })}
                        className="w-full px-2 py-1.5 rounded bg-white border border-slate-200 text-[11px] text-[#5755D9] font-bold focus:outline-none focus:border-[#5755D9] cursor-pointer font-mono"
                      >
                        {SUPPORTED_TARGETS[change.component].map((t) => (
                          <option key={t.value} value={t.value}>
                            {t.label}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Add More Button */}
            {changes.length < 5 && (
              <button
                type="button"
                onClick={handleAddChange}
                className="w-full py-1.5 rounded-lg border border-dashed border-slate-300 hover:border-slate-400 text-slate-600 hover:text-slate-900 text-xs font-semibold flex items-center justify-center space-x-1 transition cursor-pointer bg-white"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add Another Substitution ({changes.length}/5)</span>
              </button>
            )}

            {/* Run Action */}
            <button
              type="button"
              onClick={handleRunSimulation}
              disabled={isSimulating}
              className="w-full py-2.5 rounded-xl bg-[#18181B] hover:bg-black text-white font-bold text-xs shadow-xs flex items-center justify-center space-x-2 transition cursor-pointer disabled:opacity-50"
            >
              {isSimulating ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Computing Phase 4B Re-Evaluation...</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4 text-white" />
                  <span>Execute What-If Simulation</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </div>
        </div>

        {/* Right Column: Simulation Results & Delta Analytics (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          {error && (
            <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-rose-800 text-xs flex items-start space-x-2.5">
              <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
              <div>
                <strong className="text-rose-900">Simulation Error:</strong> {error}
              </div>
            </div>
          )}

          {!result && !error && (
            <div className="p-12 rounded-2xl bg-white border border-slate-200/90 shadow-xs text-center space-y-3">
              <div className="w-12 h-12 rounded-2xl bg-indigo-50 border border-indigo-100 text-[#5755D9] flex items-center justify-center mx-auto">
                <Sparkles className="w-6 h-6 text-[#5755D9]" />
              </div>
              <h3 className="text-sm font-bold text-slate-900">Simulation Ready</h3>
              <p className="text-xs text-slate-500 max-w-md mx-auto leading-relaxed">
                Select a banking system and configure 1 to 5 hypothetical substitutions on the left, then click{' '}
                <strong className="text-slate-900">Execute What-If Simulation</strong> to evaluate the projected risk reduction.
              </p>
            </div>
          )}

          {result && (
            <div className="space-y-4 animate-in fade-in duration-300">
              {/* Simulation Header Badge */}
              <div className="flex items-center justify-between text-xs px-1">
                <div className="flex items-center space-x-2">
                  <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-indigo-50 text-[#5755D9] border border-indigo-200 font-bold uppercase">
                    {result.simulation_id}
                  </span>
                  <span className="font-mono text-slate-600 text-[11px]">{result.asset_name}</span>
                </div>
                <span className="text-[10px] font-mono text-emerald-700 font-semibold flex items-center space-x-1">
                  <Check className="w-3 h-3" />
                  <span>Phase 4B Recomputed</span>
                </span>
              </div>

              {/* Before vs After Score Cards */}
              <div className="grid grid-cols-2 gap-3">
                {/* BEFORE CARD */}
                <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-2">
                  <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">
                    Current Baseline
                  </div>
                  <div className="flex items-baseline justify-between">
                    <span
                      className={`text-xs font-mono font-bold px-2.5 py-0.5 rounded border uppercase ${getPriorityBadgeClass(
                        result.before.migration_priority
                      )}`}
                    >
                      {result.before.migration_priority}
                    </span>
                    <div className="text-2xl font-black text-slate-900 font-mono">
                      {result.before.priority_score}
                      <span className="text-[10px] text-slate-400 font-normal">/100</span>
                    </div>
                  </div>
                  <div className="text-[11px] font-mono text-slate-500 truncate">
                    Status: <strong className="text-amber-800">{result.before.key_protection.status}</strong>
                  </div>
                </div>

                {/* AFTER CARD */}
                <div className="p-4 rounded-xl bg-indigo-50/40 border-2 border-[#5755D9]/40 space-y-2 shadow-xs">
                  <div className="text-[10px] font-mono text-[#5755D9] uppercase tracking-wider flex items-center space-x-1 font-semibold">
                    <Sparkles className="w-3 h-3 text-[#5755D9]" />
                    <span>Simulated State</span>
                  </div>
                  <div className="flex items-baseline justify-between">
                    <span
                      className={`text-xs font-mono font-bold px-2.5 py-0.5 rounded border uppercase ${getPriorityBadgeClass(
                        result.after.migration_priority
                      )}`}
                    >
                      {result.after.migration_priority}
                    </span>
                    <div className="text-2xl font-black text-[#5755D9] font-mono">
                      {result.after.priority_score}
                      <span className="text-[10px] text-slate-400 font-normal">/100</span>
                    </div>
                  </div>
                  <div className="text-[11px] font-mono text-slate-500 truncate">
                    Status: <strong className="text-emerald-700">{result.after.key_protection.status}</strong>
                  </div>
                </div>
              </div>

              {/* Delta Impact Banner */}
              <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-200 flex items-center justify-between text-emerald-900">
                <div>
                  <div className="text-[10px] font-mono uppercase text-emerald-700 font-semibold">Projected Risk Reduction</div>
                  <div className="text-lg font-bold text-emerald-950 flex items-center space-x-2 mt-0.5">
                    <span className="font-mono text-emerald-700 flex items-center space-x-1">
                      <TrendingDown className="w-4 h-4" />
                      <span>{result.comparison.risk_reduction} Points</span>
                    </span>
                    <span className="text-emerald-800 text-xs font-normal">
                      ({result.comparison.priority_transition})
                    </span>
                  </div>
                </div>

                <div className="text-right">
                  <div className="text-[10px] font-mono uppercase text-emerald-700 font-semibold">Key Chain Posture Transition</div>
                  <div className="text-xs font-mono text-emerald-900 mt-0.5 font-bold">
                    {result.comparison.key_chain_transition}
                  </div>
                </div>
              </div>

              {/* Resolved vs Remaining Findings */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                {/* Resolved */}
                <div className="p-3.5 rounded-xl bg-white border border-slate-200 shadow-xs space-y-2">
                  <div className="flex items-center space-x-1.5 text-emerald-700 font-semibold">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Resolved Weak Links ({result.comparison.resolved_findings.length})</span>
                  </div>
                  {result.comparison.resolved_findings.length === 0 ? (
                    <p className="text-[11px] text-slate-500 italic">No existing weak links removed by this substitution.</p>
                  ) : (
                    <ul className="space-y-1">
                      {result.comparison.resolved_findings.map((item, i) => (
                        <li key={i} className="text-[11px] text-emerald-700 font-mono flex items-start space-x-1.5">
                          <span className="text-emerald-600 font-bold">✓</span>
                          <span>{item}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>

                {/* Remaining */}
                <div className="p-3.5 rounded-xl bg-white border border-slate-200 shadow-xs space-y-2">
                  <div className="flex items-center space-x-1.5 text-amber-800 font-semibold">
                    <AlertTriangle className="w-4 h-4 text-amber-600" />
                    <span>Remaining Weak Links ({result.comparison.remaining_findings.length})</span>
                  </div>
                  {result.comparison.remaining_findings.length === 0 ? (
                    <p className="text-[11px] text-emerald-700 font-mono font-semibold">
                      ✓ All modeled key-chain weaknesses resolved!
                    </p>
                  ) : (
                    <ul className="space-y-1">
                      {result.comparison.remaining_findings.map((item, i) => (
                        <li key={i} className="text-[11px] text-amber-800 font-mono flex items-start space-x-1.5">
                          <span className="text-amber-600 font-bold">⚠</span>
                          <span>{item}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>

              {/* Narrative Explanation */}
              <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1.5">
                <div className="text-xs font-bold text-slate-900 flex items-center space-x-2">
                  <FileCheck2 className="w-3.5 h-3.5 text-[#5755D9]" />
                  <span>Simulation Technical Rationale</span>
                </div>
                <p className="text-xs text-slate-600 leading-relaxed font-sans">
                  {result.explanation}
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
