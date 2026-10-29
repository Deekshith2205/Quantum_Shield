import React, { useState } from 'react';
import type { BankingAsset, EvidenceItem, EvidenceGap } from '../types/scan';
import {
  Landmark,
  ShieldAlert,
  Network,
  Clock,
  Layers,
  KeyRound,
  FileCheck2,
  AlertTriangle,
  ArrowRight,
  ChevronDown,
  ChevronUp,
  Cpu,
  Lock,
  Database,
  ExternalLink,
  Info,
} from 'lucide-react';

interface BankingSystemCardProps {
  profile: BankingAsset;
  onAuditWithScan?: (profileId: string) => void;
  isDetailedView?: boolean;
}

export const BankingSystemCard: React.FC<BankingSystemCardProps> = ({
  profile,
  onAuditWithScan,
  isDetailedView = false,
}) => {
  const [activeTab, setActiveTab] = useState<'crypto' | 'evidence' | 'gaps'>('crypto');
  const [expanded, setExpanded] = useState<boolean>(isDetailedView);

  const getCriticalityBadge = (criticality: string) => {
    switch (criticality) {
      case 'CRITICAL':
        return 'bg-rose-950/80 text-rose-300 border-rose-800/80';
      case 'HIGH':
        return 'bg-amber-950/80 text-amber-300 border-amber-800/80';
      case 'MEDIUM':
        return 'bg-yellow-950/80 text-yellow-300 border-yellow-800/80';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getSourceBadge = (source: string) => {
    switch (source) {
      case 'EXTERNAL_SCAN':
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-800/80';
      case 'CONFIGURATION_FILE':
        return 'bg-indigo-950/80 text-indigo-300 border-indigo-800/80';
      case 'OPERATOR_DECLARED':
        return 'bg-amber-950/80 text-amber-300 border-amber-800/80';
      case 'INFERRED':
        return 'bg-purple-950/80 text-purple-300 border-purple-800/80';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getLayerBadge = (layer?: string) => {
    switch (layer) {
      case 'EDGE':
        return 'bg-cyan-950/80 text-cyan-300 border-cyan-800/70';
      case 'API_GATEWAY':
        return 'bg-sky-950/80 text-sky-300 border-sky-800/70';
      case 'SERVICE_TO_SERVICE':
        return 'bg-violet-950/80 text-violet-300 border-violet-800/70';
      case 'DATA_AND_KEYS':
        return 'bg-amber-950/80 text-amber-300 border-amber-800/70';
      case 'ADMINISTRATIVE':
        return 'bg-rose-950/80 text-rose-300 border-rose-800/70';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const crypto = profile.cryptography;
  const keyChain = crypto?.key_chain;
  const evidenceItems: EvidenceItem[] = profile.evidence_items || [];
  const evidenceGaps: EvidenceGap[] = profile.evidence_gaps || [];

  return (
    <div className="rounded-2xl bg-gradient-to-br from-slate-900/90 via-slate-900/70 to-slate-950/90 border border-slate-800 shadow-xl overflow-hidden transition-all duration-200 hover:border-slate-700">
      {/* Header bar */}
      <div className="p-5 border-b border-slate-800/80">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-start space-x-3.5">
            <div className="p-3 rounded-xl bg-cyan-950/80 border border-cyan-800/60 text-cyan-400 shrink-0 mt-0.5">
              <Landmark className="w-5 h-5" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-lg font-bold text-white tracking-wide">{profile.name}</h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                  {profile.id}
                </span>
                <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/60 uppercase">
                  {(profile.system_type || profile.asset_type).replace(/_/g, ' ')}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1 max-w-3xl leading-relaxed">
                {profile.description}
              </p>
            </div>
          </div>

          {/* Badges & Action */}
          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <span
              className={`text-xs font-mono font-bold px-3 py-1 rounded-lg border uppercase tracking-wider ${getCriticalityBadge(
                profile.criticality
              )}`}
            >
              {profile.criticality} CRITICALITY
            </span>

            {onAuditWithScan && (
              <button
                onClick={() => onAuditWithScan(profile.id)}
                className="inline-flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white text-xs font-semibold shadow-md shadow-cyan-950/50 transition cursor-pointer"
              >
                <span>Audit with Live Scan</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            )}

            {!isDetailedView && (
              <button
                onClick={() => setExpanded(!expanded)}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition cursor-pointer"
                aria-label={expanded ? 'Collapse profile details' : 'Expand profile details'}
              >
                {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </button>
            )}
          </div>
        </div>

        {/* Security Architecture Attributes Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 mt-4 text-xs">
          <div className="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800/60">
            <div className="flex items-center space-x-1.5 text-slate-400 font-mono text-[10px] mb-0.5">
              <Network className="w-3 h-3 text-indigo-400" />
              <span>Trust Zone</span>
            </div>
            <div className="font-semibold text-slate-200 font-mono text-xs">{profile.trust_zone}</div>
          </div>

          <div className="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800/60">
            <div className="flex items-center space-x-1.5 text-slate-400 font-mono text-[10px] mb-0.5">
              <Layers className="w-3 h-3 text-sky-400" />
              <span>Network Exposure</span>
            </div>
            <div className="font-semibold text-slate-200 font-mono text-xs">{profile.exposure}</div>
          </div>

          <div className="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800/60">
            <div className="flex items-center space-x-1.5 text-slate-400 font-mono text-[10px] mb-0.5">
              <ShieldAlert className="w-3 h-3 text-amber-400" />
              <span>Data Sensitivity</span>
            </div>
            <div className="font-semibold text-slate-200 font-mono text-xs">{profile.data_sensitivity.replace(/_/g, ' ')}</div>
          </div>

          <div className="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800/60">
            <div className="flex items-center space-x-1.5 text-slate-400 font-mono text-[10px] mb-0.5">
              <Clock className="w-3 h-3 text-emerald-400" />
              <span>SNDL Lifetime</span>
            </div>
            <div className="font-semibold text-slate-200 font-mono text-xs">{profile.data_lifetime.replace(/_/g, ' ')}</div>
          </div>
        </div>
      </div>

      {/* Expandable Tabs Section */}
      {expanded && (
        <div className="p-5 space-y-5 bg-slate-950/40">
          {/* Sub-navigation tabs */}
          <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 pb-3">
            <button
              onClick={() => setActiveTab('crypto')}
              className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer ${
                activeTab === 'crypto'
                  ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-800/70 shadow-sm'
                  : 'bg-slate-900/60 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              <KeyRound className="w-3.5 h-3.5 text-cyan-400" />
              <span>Key Chain & Cryptography</span>
            </button>

            <button
              onClick={() => setActiveTab('evidence')}
              className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer ${
                activeTab === 'evidence'
                  ? 'bg-indigo-950/80 text-indigo-300 border border-indigo-800/70 shadow-sm'
                  : 'bg-slate-900/60 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              <FileCheck2 className="w-3.5 h-3.5 text-indigo-400" />
              <span>Configuration Evidence ({evidenceItems.length})</span>
            </button>

            <button
              onClick={() => setActiveTab('gaps')}
              className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition cursor-pointer ${
                activeTab === 'gaps'
                  ? 'bg-amber-950/80 text-amber-300 border border-amber-800/70 shadow-sm'
                  : 'bg-slate-900/60 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              <span>Evidence Gaps ({evidenceGaps.length})</span>
            </button>
          </div>

          {/* TAB 1: Key Chain & Cryptography */}
          {activeTab === 'crypto' && (
            <div className="space-y-4 animate-in fade-in duration-200">
              {/* Key Protection Chain visual sequence */}
              {keyChain && (
                <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xs font-bold text-slate-300 tracking-wide flex items-center space-x-2">
                      <Lock className="w-4 h-4 text-cyan-400" />
                      <span>Key Protection Chain Hierarchy</span>
                    </span>
                    <span className="text-[10px] font-mono text-cyan-400/80">
                      Data At-Rest &rarr; KEK &rarr; Master Key &rarr; Root Authentication
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                    <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800">
                      <span className="text-[10px] font-mono uppercase text-slate-400 block mb-1">
                        1. Data Encryption
                      </span>
                      <div className="font-mono text-xs font-bold text-emerald-400">
                        {keyChain.data_encryption || 'None / Not Observable'}
                      </div>
                      <span className="text-[10px] text-slate-500 mt-1 block">Bulk Data Payload (AES/GCM)</span>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800">
                      <span className="text-[10px] font-mono uppercase text-slate-400 block mb-1">
                        2. Key Wrapping
                      </span>
                      <div className="font-mono text-xs font-bold text-sky-400">
                        {keyChain.key_wrapping || 'None / Direct'}
                      </div>
                      <span className="text-[10px] text-slate-500 mt-1 block">Key Encapsulation / KEK</span>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800">
                      <span className="text-[10px] font-mono uppercase text-slate-400 block mb-1">
                        3. Key Storage
                      </span>
                      <div className="font-mono text-xs font-bold text-amber-400">
                        {keyChain.key_storage || 'Local / Plaintext'}
                      </div>
                      <span className="text-[10px] text-slate-500 mt-1 block">Hardware Module or KMS</span>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800">
                      <span className="text-[10px] font-mono uppercase text-slate-400 block mb-1">
                        4. Authentication
                      </span>
                      <div className="font-mono text-xs font-bold text-violet-400">
                        {keyChain.authentication || 'Standard Signature'}
                      </div>
                      <span className="text-[10px] text-slate-500 mt-1 block">Master Identity / Signature</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Cryptography Parameters Detail */}
              {crypto && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
                    <h4 className="font-semibold text-slate-200 text-xs flex items-center space-x-1.5">
                      <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Perimeter Transport Cryptography</span>
                    </h4>
                    <div className="space-y-1.5 text-[11px] font-mono">
                      <div className="flex justify-between py-1 border-b border-slate-800/60">
                        <span className="text-slate-400">TLS Versions:</span>
                        <span className="text-slate-200">{crypto.tls_versions?.join(', ') || 'N/A'}</span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-800/60">
                        <span className="text-slate-400">Key Exchange / Group:</span>
                        <span className="text-cyan-300 font-bold">{crypto.key_exchange || 'TLS 1.2 ECDHE'}</span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-800/60">
                        <span className="text-slate-400">Leaf Certificate:</span>
                        <span className="text-slate-200 truncate max-w-[240px]">
                          {crypto.certificates?.[0] || 'Standard X.509'}
                        </span>
                      </div>
                      <div className="flex justify-between py-1">
                        <span className="text-slate-400">Signature Algorithm:</span>
                        <span className="text-slate-200">{crypto.signature_algorithm || 'SHA-256 with RSA'}</span>
                      </div>
                    </div>
                  </div>

                  <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
                    <h4 className="font-semibold text-slate-200 text-xs flex items-center space-x-1.5">
                      <Database className="w-3.5 h-3.5 text-indigo-400" />
                      <span>Data Protection & Key Appliance</span>
                    </h4>
                    <div className="space-y-1.5 text-[11px] font-mono">
                      <div className="flex justify-between py-1 border-b border-slate-800/60">
                        <span className="text-slate-400">Data At-Rest Algorithm:</span>
                        <span className="text-emerald-300 font-bold">
                          {crypto.data_encryption_algorithm || 'AES-256'}
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-800/60">
                        <span className="text-slate-400">Key Wrapping Algorithm:</span>
                        <span className="text-sky-300 font-bold">{crypto.key_wrapping_algorithm || 'N/A'}</span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-800/60">
                        <span className="text-slate-400">Storage Facility:</span>
                        <span className="text-amber-300 font-bold">{crypto.key_storage || 'Local Key Store'}</span>
                      </div>
                      <div className="flex justify-between py-1">
                        <span className="text-slate-400">Appliance Model / Cloud KMS:</span>
                        <span className="text-slate-200 truncate max-w-[240px]">
                          {crypto.kms_or_hsm || 'Not Configured'}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: Configuration Evidence Items */}
          {activeTab === 'evidence' && (
            <div className="space-y-3 animate-in fade-in duration-200">
              <div className="flex items-center justify-between text-xs text-slate-400 pb-1">
                <span>Normalized Multi-Layer Security Architecture Controls</span>
                <span className="font-mono text-[10px]">Explicit Origin Tracking</span>
              </div>

              <div className="space-y-2">
                {evidenceItems.map((item) => (
                  <div
                    key={item.id}
                    className="p-3 rounded-xl bg-slate-900/70 border border-slate-800 hover:border-slate-700 transition"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-1.5">
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-xs text-slate-200">{item.control}</span>
                        <span className="text-[10px] font-mono text-slate-500">[{item.id}]</span>
                      </div>

                      <div className="flex flex-wrap items-center gap-1.5">
                        {item.layer && (
                          <span
                            className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded border ${getLayerBadge(
                              item.layer
                            )}`}
                          >
                            {item.layer}
                          </span>
                        )}
                        <span
                          className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded border ${getSourceBadge(
                            item.source
                          )}`}
                        >
                          {item.source}
                        </span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                          {item.observability}
                        </span>
                      </div>
                    </div>

                    <div className="font-mono text-xs text-cyan-300 font-semibold mb-1">
                      {item.value}
                    </div>

                    {item.description && (
                      <p className="text-[11px] text-slate-400 leading-relaxed">
                        {item.description}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 3: Evidence Gaps (Internal Controls) */}
          {activeTab === 'gaps' && (
            <div className="space-y-3 animate-in fade-in duration-200">
              {/* Core Invariant Banner */}
              <div className="p-3.5 rounded-xl bg-amber-950/40 border border-amber-800/60 text-amber-200 text-xs flex items-start space-x-3">
                <Info className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <div className="font-bold text-amber-300 tracking-wide">
                    AUDIT INVARIANT: NOT_OBSERVABLE &ne; VULNERABLE
                  </div>
                  <p className="text-[11px] text-amber-200/90 leading-relaxed">
                    Internal banking controls (e.g., service mesh mTLS, HSM physical tamper sensors, KMS key rotation)
                    reside entirely inside private VPCs or secure hardware coprocessors. They cannot be observed through
                    external perimeter scans alone. Missing evidence is categorized as an{' '}
                    <strong>observability gap</strong> requiring internal audit manifests, not a failed control.
                  </p>
                </div>
              </div>

              <div className="space-y-2">
                {evidenceGaps.map((gap, idx) => (
                  <div
                    key={idx}
                    className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800 hover:border-slate-700 transition"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-xs text-slate-200">{gap.control}</span>
                        <span className="text-[10px] font-mono text-amber-400/90 bg-amber-950/60 border border-amber-800/60 px-2 py-0.5 rounded">
                          {gap.gap_type}
                        </span>
                      </div>
                      <span
                        className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded border self-start sm:self-auto ${getLayerBadge(
                          gap.layer
                        )}`}
                      >
                        {gap.layer}
                      </span>
                    </div>

                    <p className="text-[11px] text-slate-400 mb-2 leading-relaxed">
                      {gap.description}
                    </p>

                    <div className="p-2 rounded-lg bg-slate-950/80 border border-slate-800 text-[11px] font-mono flex items-start space-x-2">
                      <span className="text-cyan-400 font-bold shrink-0">Telemetry Needed:</span>
                      <span className="text-slate-300">{gap.evidence_needed}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

