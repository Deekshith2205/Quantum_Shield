import React, { useState } from 'react';
import type { QuantumFinding } from '../types/scan';
import { ShieldAlert, AlertTriangle, Info, CheckCircle2, Eye, EyeOff, Filter } from 'lucide-react';

interface CryptographicFindingsProps {
  findings: QuantumFinding[];
}

export const CryptographicFindings: React.FC<CryptographicFindingsProps> = ({ findings }) => {
  const [filterRisk, setFilterRisk] = useState<string>('ALL');

  const filteredFindings = filterRisk === 'ALL'
    ? findings
    : findings.filter((f) => f.risk_level === filterRisk);

  const getRiskBadge = (level: string) => {
    switch (level) {
      case 'CRITICAL':
        return {
          bg: 'bg-red-50 text-red-700 border-red-200',
          indicator: 'bg-red-500',
        };
      case 'HIGH':
        return {
          bg: 'bg-orange-50 text-orange-800 border-orange-200',
          indicator: 'bg-orange-500',
        };
      case 'MEDIUM':
        return {
          bg: 'bg-amber-50 text-amber-800 border-amber-200',
          indicator: 'bg-amber-500',
        };
      case 'LOW':
        return {
          bg: 'bg-emerald-50 text-emerald-800 border-emerald-200',
          indicator: 'bg-emerald-500',
        };
      case 'INFORMATIONAL':
      case 'INFO':
      default:
        return {
          bg: 'bg-slate-100 text-slate-700 border-slate-200',
          indicator: 'bg-slate-400',
        };
    }
  };

  const getEvidenceBadge = (status?: string) => {
    switch (status?.toUpperCase()) {
      case 'OBSERVED':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-md text-[11px] font-mono font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
            <Eye className="w-3 h-3" />
            <span>OBSERVED</span>
          </span>
        );
      case 'CAPABILITY_PROBED':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-md text-[11px] font-mono font-bold bg-indigo-50 text-[#5755D9] border border-indigo-200">
            <span>CAPABILITY_PROBED</span>
          </span>
        );
      case 'CLASSICAL_ONLY_OBSERVED':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-md text-[11px] font-mono font-bold bg-blue-50 text-blue-700 border border-blue-200">
            <Eye className="w-3 h-3 text-blue-600" />
            <span>CLASSICAL_ONLY</span>
          </span>
        );
      case 'PROBED_UNSUPPORTED':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-md text-[11px] font-mono font-bold bg-red-50 text-red-700 border border-red-200">
            <AlertTriangle className="w-3 h-3 text-red-600" />
            <span>PROBED_UNSUPPORTED</span>
          </span>
        );
      case 'INFERRED':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-md text-[11px] font-mono font-bold bg-amber-50 text-amber-800 border border-amber-200">
            <span>INFERRED</span>
          </span>
        );
      case 'NOT_OBSERVABLE':
      default:
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-md text-[11px] font-mono font-bold bg-slate-100 text-slate-600 border border-slate-200">
            <EyeOff className="w-3 h-3" />
            <span>NOT_OBSERVABLE</span>
          </span>
        );
    }
  };

  return (
    <div className="space-y-4">
      {/* Section Header & Filters */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-bold text-slate-900 tracking-tight flex items-center space-x-2">
            <ShieldAlert className="w-5 h-5 text-[#5755D9]" />
            <span>Detailed Cryptographic Findings ({findings.length})</span>
          </h2>
          <p className="text-xs text-slate-500">
            Structured analysis of observable perimeter mechanisms against Shor's and Grover's quantum threat models.
          </p>
        </div>

        {/* Risk Filter Pills */}
        <div className="flex items-center space-x-1.5 p-1 rounded-lg bg-white border border-slate-200 text-xs shadow-xs">
          <Filter className="w-3.5 h-3.5 text-slate-400 ml-1.5 mr-0.5" />
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'].map((lvl) => (
            <button
              key={lvl}
              onClick={() => setFilterRisk(lvl)}
              className={`px-2.5 py-1 rounded text-[11px] font-mono transition cursor-pointer ${
                filterRisk === lvl
                  ? 'bg-indigo-50 text-[#5755D9] border border-indigo-200 font-semibold'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              {lvl}
            </button>
          ))}
        </div>
      </div>

      {/* Findings Cards */}
      <div className="space-y-3.5">
        {filteredFindings.map((finding) => {
          const badge = getRiskBadge(finding.risk_level);
          const evidenceStatus = finding.evidence || finding.observability;
          const displayRole = finding.role || (finding.category === 'public_key' ? 'Certificate Public Key' : (finding.category === 'key_exchange' ? 'Key Establishment' : (finding.category === 'symmetric_cipher' ? 'Symmetric Encryption' : (finding.category === 'signature' ? 'Certificate Signature' : 'TLS Configuration'))));
          const displayValue = finding.value || finding.algorithm;
          const displaySource = finding.source || finding.observed_from;
          const displayThreat = finding.quantum_threat || finding.quantum_threat_vector;
          const displayImpact = finding.security_impact || finding.reason;
          const displayTarget = finding.migration_target || finding.target_pqc_standard || 'Standard PQC';

          return (
            <div
              key={finding.id}
              className="p-5 rounded-2xl bg-white border border-slate-200/90 hover:border-slate-300 transition shadow-xs space-y-3 relative overflow-hidden"
            >
              {/* Left accent strip */}
              <div className={`absolute top-0 left-0 bottom-0 w-1.5 ${badge.indicator}`} />

              {/* Title & Badges Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pl-2">
                <div className="space-y-0.5">
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-mono font-bold text-slate-400">{finding.id}</span>
                    <h3 className="text-base font-bold text-slate-900">{finding.title}</h3>
                  </div>
                  <div className="text-xs font-mono text-[#5755D9] font-semibold">
                    {displayRole} &mdash; <span className="text-slate-900 font-bold">{displayValue}</span>
                  </div>
                </div>

                <div className="flex items-center space-x-2 shrink-0">
                  <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-slate-100 text-amber-800 border border-slate-200">
                    {finding.priority}
                  </span>
                  {getEvidenceBadge(evidenceStatus)}
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-md text-xs font-mono font-extrabold border ${badge.bg}`}>
                    {finding.risk_level}
                  </span>
                </div>
              </div>

              {/* Explicit Evidence & Threat Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5 text-xs font-mono pl-2">
                <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
                  <span className="text-slate-400 block text-[10px] uppercase">Observable Source</span>
                  <span className="text-slate-800 block truncate" title={displaySource}>{displaySource}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
                  <span className="text-slate-400 block text-[10px] uppercase">Quantum Threat Model</span>
                  <span className="text-slate-800 block truncate" title={displayThreat}>{displayThreat}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200">
                  <span className="text-slate-400 block text-[10px] uppercase">Recommended Migration</span>
                  <span className="text-[#5755D9] font-bold block truncate" title={displayTarget}>{displayTarget}</span>
                </div>
              </div>

              {/* Impact and Action */}
              <div className="space-y-2 text-xs pl-2 pt-1 border-t border-slate-100">
                <div>
                  <span className="font-semibold text-slate-800 block mb-0.5">Why It Matters:</span>
                  <p className="text-slate-600 leading-relaxed">{displayImpact}</p>
                </div>
                <div>
                  <span className="font-semibold text-[#5755D9] block mb-0.5">Recommended Action:</span>
                  <p className="text-slate-700 leading-relaxed">{finding.recommendation}</p>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
