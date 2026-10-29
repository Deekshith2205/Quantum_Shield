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
          badge: 'bg-rose-950 text-rose-300 border-rose-800',
          indicator: 'bg-rose-500',
          border: 'border-rose-500/50',
          text: 'text-rose-400',
        };
      case 'P1':
        return {
          badge: 'bg-orange-950 text-orange-300 border-orange-800',
          indicator: 'bg-orange-500',
          border: 'border-orange-500/50',
          text: 'text-orange-400',
        };
      case 'P2':
        return {
          badge: 'bg-amber-950 text-amber-300 border-amber-800',
          indicator: 'bg-amber-500',
          border: 'border-amber-500/40',
          text: 'text-amber-400',
        };
      case 'P3':
      default:
        return {
          badge: 'bg-slate-800 text-slate-300 border-slate-700',
          indicator: 'bg-slate-600',
          border: 'border-slate-800',
          text: 'text-slate-400',
        };
    }
  };

  const getEvidenceBadge = (evidence?: string) => {
    switch (evidence?.toUpperCase()) {
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
          <Zap className="w-5 h-5 text-amber-400" />
          <span>Prioritized Post-Quantum Migration Roadmap</span>
        </h2>
        <p className="text-xs text-slate-400">
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
              className={`p-5 rounded-2xl border bg-slate-900/90 hover:border-slate-700 transition shadow-lg relative overflow-hidden ${prioTheme.border}`}
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
                    <span className="text-[11px] font-mono uppercase tracking-wider text-slate-500">
                      Step #{step.priority_rank} &bull; {step.affected_component}
                    </span>
                    <h3 className="text-base font-bold text-white">{step.title}</h3>
                    <div className="text-xs font-mono text-cyan-300 flex items-center space-x-2">
                      <span>Current: <strong className="text-white">{step.current_mechanism}</strong></span>
                      <span>&rarr;</span>
                      <span>Target: <strong className="text-cyan-400">{step.recommended_target}</strong></span>
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
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs mt-3 pt-3 border-t border-slate-800/80">
                <div className="space-y-1">
                  <span className="font-semibold text-slate-300 block">Why Upgrade This Component:</span>
                  <p className="text-slate-400 leading-relaxed">{step.reason}</p>
                </div>
                <div className="space-y-1">
                  <span className="font-semibold text-cyan-300 block">Migration Approach:</span>
                  <p className="text-slate-300 leading-relaxed">{step.migration_approach}</p>
                </div>
              </div>

              {/* Standards Tags */}
              {step.target_standards && step.target_standards.length > 0 && (
                <div className="mt-3 pt-2 flex flex-wrap items-center gap-1.5 text-xs font-mono">
                  <span className="text-[11px] text-slate-500">Target PQC Standards:</span>
                  {step.target_standards.map((std, i) => (
                    <span
                      key={i}
                      className="px-2 py-0.5 rounded text-[10px] bg-slate-950 text-cyan-300 border border-slate-800 font-semibold"
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
