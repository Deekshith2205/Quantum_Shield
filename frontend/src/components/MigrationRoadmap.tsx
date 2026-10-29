import React from 'react';
import type { MigrationStep } from '../types/scan';
import { Zap, Clock, ArrowRight, ShieldCheck, Award, Eye, EyeOff } from 'lucide-react';

interface MigrationRoadmapProps {
  plan: MigrationStep[];
}

export const MigrationRoadmap: React.FC<MigrationRoadmapProps> = ({ plan }) => {
  const getPriorityTheme = (prio: string) => {
    switch (prio) {
      case 'P0':
        return {
          badge: 'bg-red-50 text-red-700 border-red-200',
          indicator: 'bg-red-500',
          border: 'border-slate-200/90',
          text: 'text-red-700',
        };
      case 'P1':
        return {
          badge: 'bg-orange-50 text-orange-800 border-orange-200',
          indicator: 'bg-orange-500',
          border: 'border-slate-200/90',
          text: 'text-orange-800',
        };
      case 'P2':
        return {
          badge: 'bg-amber-50 text-amber-800 border-amber-200',
          indicator: 'bg-amber-500',
          border: 'border-slate-200/90',
          text: 'text-amber-800',
        };
      case 'P3':
      default:
        return {
          badge: 'bg-slate-100 text-slate-700 border-slate-200',
          indicator: 'bg-slate-400',
          border: 'border-slate-200/90',
          text: 'text-slate-600',
        };
    }
  };

  const getEvidenceBadge = (evidence?: string) => {
    switch (evidence?.toUpperCase()) {
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
          <Zap className="w-5 h-5 text-[#5755D9]" />
          <span>Prioritized Post-Quantum Migration Roadmap</span>
        </h2>
        <p className="text-xs text-slate-500">
          Ranked upgrade plan answering: <em>"What cryptographic component should your organization upgrade first?"</em>
        </p>
      </div>

      {/* Migration Sequence */}
      <div className="space-y-3.5">
        {plan.map((step) => {
          const prioTheme = getPriorityTheme(step.priority);
          return (
            <div
              key={step.priority_rank}
              className="p-5 rounded-2xl border border-slate-200/90 bg-white hover:border-slate-300 transition shadow-xs relative overflow-hidden"
            >
              {/* Header row */}
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 mb-3">
                <div className="flex items-start space-x-3">
                  <div
                    className={`flex items-center justify-center w-8 h-8 rounded-xl font-mono font-extrabold text-sm shrink-0 border ${prioTheme.badge}`}
                  >
                    {step.priority}
                  </div>
                  <div className="space-y-0.5">
                    <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
                      Step #{step.priority_rank} &bull; {step.affected_component}
                    </span>
                    <h3 className="text-base font-bold text-slate-900">{step.title}</h3>
                    <div className="text-xs font-mono text-[#5755D9] flex items-center space-x-2">
                      <span>Current: <strong className="text-slate-800">{step.current_mechanism}</strong></span>
                      <span>&rarr;</span>
                      <span>Target: <strong className="text-[#5755D9]">{step.recommended_target}</strong></span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center space-x-2 shrink-0">
                  {getEvidenceBadge(step.evidence)}
                  <span className={`px-2.5 py-1 rounded-md text-[11px] font-mono font-bold border ${prioTheme.badge}`}>
                    {step.urgency}
                  </span>
                </div>
              </div>

              {/* Rationale & Migration Approach */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs mt-3 pt-3 border-t border-slate-100">
                <div className="space-y-1">
                  <span className="font-semibold text-slate-900 block">Why Upgrade This Component:</span>
                  <p className="text-slate-600 leading-relaxed">{step.reason}</p>
                </div>
                <div className="space-y-1">
                  <span className="font-semibold text-[#5755D9] block">Migration Approach:</span>
                  <p className="text-slate-700 leading-relaxed">{step.migration_approach}</p>
                </div>
              </div>

              {/* Standards Tags */}
              {step.target_standards && step.target_standards.length > 0 && (
                <div className="mt-3 pt-2 flex flex-wrap items-center gap-1.5 text-xs font-mono">
                  <span className="text-[11px] text-slate-400">Target PQC Standards:</span>
                  {step.target_standards.map((std, i) => (
                    <span
                      key={i}
                      className="px-2 py-0.5 rounded text-[10px] bg-slate-50 text-[#5755D9] border border-slate-200 font-semibold"
                    >
                      {std}
                    </span>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
