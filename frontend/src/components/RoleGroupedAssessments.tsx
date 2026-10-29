import React from 'react';
import type { RoleCategoryAssessment } from '../types/scan';
import { Layers, ShieldAlert, ShieldCheck, Eye, EyeOff, ArrowRight } from 'lucide-react';

interface RoleGroupedAssessmentsProps {
  assessments: RoleCategoryAssessment[];
}

export const RoleGroupedAssessments: React.FC<RoleGroupedAssessmentsProps> = ({ assessments }) => {
  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'EXCELLENT':
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-800';
      case 'GOOD':
        return 'bg-cyan-950/80 text-cyan-300 border-cyan-800';
      case 'MODERATE':
      case 'MEDIUM RISK':
        return 'bg-amber-950/80 text-amber-300 border-amber-800';
      case 'HIGH RISK':
        return 'bg-orange-950/80 text-orange-300 border-orange-800';
      case 'CRITICAL':
        return 'bg-rose-950/80 text-rose-300 border-rose-800';
      case 'INFORMATIONAL':
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getEvidenceBadge = (status?: string) => {
    switch (status?.toUpperCase()) {
      case 'OBSERVED':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950/80 text-emerald-400 border border-emerald-800/60">
            <Eye className="w-3 h-3" />
            <span>OBSERVED</span>
          </span>
        );
      case 'CAPABILITY_PROBED':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-700/60">
            <span>CAPABILITY_PROBED</span>
          </span>
        );
      case 'CLASSICAL_ONLY_OBSERVED':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-950/80 text-blue-300 border border-blue-700/60">
            <Eye className="w-3 h-3 text-blue-400" />
            <span>CLASSICAL_ONLY</span>
          </span>
        );
      case 'PROBED_UNSUPPORTED':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950/80 text-rose-300 border border-rose-800/60">
            <span>PROBED_UNSUPPORTED</span>
          </span>
        );
      case 'INFERRED':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950/80 text-amber-400 border border-amber-800/60">
            <span>INFERRED</span>
          </span>
        );
      case 'NOT_OBSERVABLE':
      default:
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-400 border border-slate-700">
            <EyeOff className="w-3 h-3" />
            <span>NOT_OBSERVABLE</span>
          </span>
        );
    }
  };

  return (
    <div className="space-y-4">
      {/* Section Header */}
      <div>
        <h2 className="text-lg font-bold text-white tracking-wide flex items-center space-x-2">
          <Layers className="w-5 h-5 text-cyan-400" />
          <span>Cryptographic Role Grouping & Status</span>
        </h2>
        <p className="text-xs text-slate-400">
          Evaluates perimeter posture grouped strictly by cryptographic role to prevent cross-component misattribution.
        </p>
      </div>

      {/* Grid of 5 Role Categories */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {assessments.map((cat) => {
          return (
            <div
              key={cat.category_id}
              className="p-5 rounded-2xl bg-slate-900/90 border border-slate-800 hover:border-slate-700 transition shadow-lg flex flex-col justify-between space-y-4"
            >
              {/* Category Header */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-slate-500 uppercase tracking-wider">
                    Weight: {cat.weight_percentage}%
                  </span>
                  <div className="flex items-center space-x-1.5">
                    {getEvidenceBadge(cat.evidence)}
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getStatusBadge(cat.status)}`}>
                      {cat.status}
                    </span>
                  </div>
                </div>

                <h3 className="text-base font-bold text-white">{cat.category_name}</h3>

                {/* Score bar */}
                <div className="space-y-1 pt-1">
                  <div className="flex justify-between text-xs font-mono">
                    <span className="text-slate-400">Readiness Score</span>
                    <span className="text-white font-bold">{cat.readiness_score} / 100</span>
                  </div>
                  <div className="w-full h-1.5 rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className={`h-full ${
                        cat.readiness_score >= 85 ? 'bg-emerald-500' :
                        cat.readiness_score >= 70 ? 'bg-cyan-500' :
                        cat.readiness_score >= 55 ? 'bg-amber-500' :
                        cat.readiness_score >= 40 ? 'bg-orange-500' : 'bg-rose-500'
                      }`}
                      style={{ width: `${cat.readiness_score}%` }}
                    />
                  </div>
                </div>
              </div>

              {/* Observed Value & Threat */}
              <div className="space-y-2 text-xs font-mono pt-2 border-t border-slate-800/80">
                <div className="flex justify-between">
                  <span className="text-slate-500">Value:</span>
                  <span className="text-cyan-300 font-bold truncate max-w-[170px]" title={cat.observed_value}>
                    {cat.observed_value}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Quantum Threat:</span>
                  <span className="text-slate-300 truncate max-w-[170px]" title={cat.quantum_threat}>
                    {cat.quantum_threat}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">PQC Target:</span>
                  <span className="text-slate-200 font-semibold">{cat.migration_target}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Priority:</span>
                  <span className="text-orange-400 font-bold">{cat.priority}</span>
                </div>
              </div>

              {/* Action recommendation */}
              <div className="pt-2 border-t border-slate-800/80 text-xs">
                <span className="text-slate-500 block text-[10px] uppercase font-mono mb-0.5">Recommended Action</span>
                <p className="text-slate-300 leading-normal text-[11px]">{cat.recommended_action}</p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

