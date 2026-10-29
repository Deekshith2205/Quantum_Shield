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
        return 'bg-emerald-50 text-emerald-800 border-emerald-200';
      case 'GOOD':
        return 'bg-indigo-50 text-[#5755D9] border-indigo-200';
      case 'MODERATE':
      case 'MEDIUM RISK':
        return 'bg-amber-50 text-amber-800 border-amber-200';
      case 'HIGH RISK':
        return 'bg-orange-50 text-orange-800 border-orange-200';
      case 'CRITICAL':
        return 'bg-red-50 text-red-700 border-red-200';
      case 'INFORMATIONAL':
      default:
        return 'bg-slate-100 text-slate-700 border-slate-200';
    }
  };

  const getEvidenceBadge = (status?: string) => {
    switch (status?.toUpperCase()) {
      case 'OBSERVED':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
            <Eye className="w-3 h-3" />
            <span>OBSERVED</span>
          </span>
        );
      case 'CAPABILITY_PROBED':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-50 text-[#5755D9] border border-indigo-200">
            <span>CAPABILITY_PROBED</span>
          </span>
        );
      case 'CLASSICAL_ONLY_OBSERVED':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-50 text-blue-700 border border-blue-200">
            <Eye className="w-3 h-3 text-blue-600" />
            <span>CLASSICAL_ONLY</span>
          </span>
        );
      case 'PROBED_UNSUPPORTED':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-50 text-red-700 border border-red-200">
            <span>PROBED_UNSUPPORTED</span>
          </span>
        );
      case 'INFERRED':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-50 text-amber-800 border border-amber-200">
            <span>INFERRED</span>
          </span>
        );
      case 'NOT_OBSERVABLE':
      default:
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-100 text-slate-600 border border-slate-200">
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
        <h2 className="text-lg font-bold text-slate-900 tracking-tight flex items-center space-x-2">
          <Layers className="w-5 h-5 text-[#5755D9]" />
          <span>Cryptographic Role Grouping & Status</span>
        </h2>
        <p className="text-xs text-slate-500">
          Evaluates perimeter posture grouped strictly by cryptographic role to prevent cross-component misattribution.
        </p>
      </div>

      {/* Grid of 5 Role Categories */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {assessments.map((cat) => {
          return (
            <div
              key={cat.category_id}
              className="p-5 rounded-2xl bg-white border border-slate-200/90 hover:border-slate-300 transition shadow-xs flex flex-col justify-between space-y-4"
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

                <h3 className="text-base font-bold text-slate-900">{cat.category_name}</h3>

                {/* Score bar */}
                <div className="space-y-1 pt-1">
                  <div className="flex justify-between text-xs font-mono">
                    <span className="text-slate-500">Readiness Score</span>
                    <span className="text-slate-900 font-bold">{cat.readiness_score} / 100</span>
                  </div>
                  <div className="w-full h-1.5 rounded-full bg-slate-100 border border-slate-200 overflow-hidden">
                    <div
                      className={`h-full ${
                        cat.readiness_score >= 85 ? 'bg-emerald-500' :
                        cat.readiness_score >= 70 ? 'bg-[#5755D9]' :
                        cat.readiness_score >= 55 ? 'bg-amber-500' :
                        cat.readiness_score >= 40 ? 'bg-orange-500' : 'bg-red-500'
                      }`}
                      style={{ width: `${cat.readiness_score}%` }}
                    />
                  </div>
                </div>
              </div>

              {/* Observed Value & Threat */}
              <div className="space-y-2 text-xs font-mono pt-2 border-t border-slate-100">
                <div className="flex justify-between">
                  <span className="text-slate-500">Value:</span>
                  <span className="text-[#5755D9] font-bold truncate max-w-[170px]" title={cat.observed_value}>
                    {cat.observed_value}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Quantum Threat:</span>
                  <span className="text-slate-700 truncate max-w-[170px]" title={cat.quantum_threat}>
                    {cat.quantum_threat}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">PQC Target:</span>
                  <span className="text-slate-900 font-semibold">{cat.migration_target}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Priority:</span>
                  <span className="text-amber-800 font-bold">{cat.priority}</span>
                </div>
              </div>

              {/* Action recommendation */}
              <div className="pt-2 border-t border-slate-100 text-xs">
                <span className="text-slate-500 block text-[10px] uppercase font-mono mb-0.5">Recommended Action</span>
                <p className="text-slate-600 leading-normal text-[11px]">{cat.recommended_action}</p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
