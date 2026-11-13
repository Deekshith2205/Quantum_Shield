import React, { useEffect, useState } from 'react';
import type { RankedUpgradePlan } from '../types/scan';
import { getBankingUpgradePlan } from '../services/api';
import {
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Info,
  Loader2,
  TrendingUp,
} from 'lucide-react';


export const BankingUpgradePlan: React.FC = () => {
  const [plan, setPlan] = useState<RankedUpgradePlan | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [retryCount, setRetryCount] = useState(0);

  useEffect(() => {
    let isMounted = true;

    setIsLoading(true);
    setError(null);

    getBankingUpgradePlan()
      .then((data) => {
        if (isMounted) {
          setPlan(data);
        }
      })
      .catch((err: unknown) => {
        if (isMounted) {
          setError(
            err instanceof Error
              ? err.message
              : 'Failed to load the ranked upgrade plan.'
          );
        }
      })
      .finally(() => {
        if (isMounted) setIsLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, [retryCount]);

  const getPriorityBadge = (priority: string) => {
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
      <div className="space-y-2">
        <div className="flex items-center space-x-2">
          <span className="text-xs font-mono uppercase tracking-widest text-[#5755D9] font-semibold">
            QUANTUM MIGRATION ROADMAP
          </span>
          <span className="text-slate-300">/</span>
          <span className="text-xs font-mono text-slate-500">
            Ranked Upgrade Plan
          </span>
        </div>

        <h1 className="text-3xl sm:text-4xl font-light text-[#17181C] tracking-tight">
          Prioritized Upgrade Plan
        </h1>

        <p className="text-sm text-[#62656D] max-w-2xl leading-relaxed">
          A deterministic migration queue showing which banking systems
          should be upgraded first, the factors behind each priority score,
          and the recommended migration direction.
        </p>
      </div>

      {isLoading && (
        <div className="p-12 text-center space-y-3">
          <Loader2 className="w-8 h-8 animate-spin text-[#5755D9] mx-auto" />
          <p className="text-xs text-slate-500 font-mono">
            Loading ranked banking upgrade plan...
          </p>
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-rose-800 text-xs flex items-start space-x-3">
          <AlertTriangle className="w-5 h-5 text-rose-600 shrink-0" />
          <div>
            <div className="font-bold text-rose-900">
              Failed to load upgrade plan
            </div>
            <div className="text-rose-700 mt-0.5">{error}</div>
            <button
                onClick={() => setRetryCount((count) => count + 1)}
                className="mt-3 px-3 py-1.5 rounded-lg bg-white border border-rose-200 text-rose-700 hover:bg-rose-100 font-semibold cursor-pointer"
            >
            Retry loading upgrade plan
            </button>
          </div>
        </div>
      )}
      {!isLoading && !error && plan && (
        <div className="space-y-5">
          {/* Priority Summary */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            {[
              {
                label: 'Critical · P0',
                count: plan.p0_count,
                color: 'border-red-200 bg-red-50 text-red-700',
              },
              {
                label: 'High · P1',
                count: plan.p1_count,
                color: 'border-amber-200 bg-amber-50 text-amber-800',
              },
              {
                label: 'Medium · P2',
                count: plan.p2_count,
                color: 'border-indigo-200 bg-indigo-50 text-indigo-700',
              },
              {
                label: 'Low · P3',
                count: plan.p3_count,
                color: 'border-emerald-200 bg-emerald-50 text-emerald-800',
              },
            ].map((item) => (
              <div
                key={item.label}
                className={`p-4 rounded-xl border ${item.color}`}
              >
                <div className="text-[11px] font-mono uppercase tracking-wide">
                  {item.label}
                </div>
                <div className="text-3xl font-black mt-1">
                  {item.count}
                </div>
                <div className="text-[10px] mt-1 opacity-75">
                  Ranked systems
                </div>
              </div>
            ))}
          </div>

          {/* Queue Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 px-1">
            <div>
              <h2 className="text-base font-bold text-slate-900">
                Ranked Migration Queue
              </h2>
              <p className="text-xs text-slate-500 mt-1">
                {plan.total_systems} systems · Ordered by deterministic
                priority score
              </p>
            </div>
            <div className="text-[10px] font-mono text-slate-500">
              GENERATED: {new Date(plan.timestamp).toLocaleString()}
            </div>
          </div>

          {/* Ranked Queue */}
          {plan.queue.map((item) => {
            const isExpanded = expandedId === item.system_id;

            return (
              <div
                key={item.system_id}
                className="rounded-2xl bg-white border border-slate-200/90 shadow-xs overflow-hidden transition-all duration-200 hover:border-slate-300"
              >
                <div className="p-5">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div className="flex items-start gap-3.5">
                      <div className="flex flex-col items-center justify-center w-11 h-11 rounded-xl bg-slate-100 border border-slate-200 text-slate-900 font-black text-base shrink-0 font-mono">
                        <span className="text-[9px] text-slate-500 font-normal">
                          RANK
                        </span>
                        <span>#{item.rank}</span>
                      </div>

                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <h3 className="text-base font-bold text-slate-900">
                            {item.system_name}
                          </h3>
                          <span
                            className={`text-[10px] font-mono font-bold px-2.5 py-0.5 rounded-full border ${getPriorityBadge(item.priority)}`}
                          >
                            {item.priority}
                          </span>
                        </div>

                        <p className="text-[11px] font-mono text-slate-500 mt-1">
                          {item.system_id}
                        </p>

                        <p className="text-xs text-slate-600 mt-2">
                          {item.recommended_migration}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center justify-between sm:justify-end gap-4 shrink-0">
                      <div className="text-right">
                        <div className="text-[10px] font-mono uppercase text-slate-500">
                          Priority Score
                        </div>
                        <div className="text-2xl font-black text-[#5755D9] font-mono">
                          {item.priority_score}
                          <span className="text-xs text-slate-400 font-normal">
                            /100
                          </span>
                        </div>
                      </div>

                      <button
                        onClick={() =>
                          setExpandedId(isExpanded ? null : item.system_id)
                        }
                        className="p-2 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-200 transition cursor-pointer"
                        aria-label={
                          isExpanded ? 'Collapse analysis' : 'Expand analysis'
                        }
                      >
                        {isExpanded ? (
                          <ChevronUp className="w-4 h-4" />
                        ) : (
                          <ChevronDown className="w-4 h-4" />
                        )}
                      </button>
                    </div>
                  </div>

                  <div className="flex flex-wrap gap-2 mt-4 pt-3 border-t border-slate-100">
                    <span className="text-[10px] font-mono px-2 py-1 rounded bg-slate-50 border border-slate-200 text-slate-600">
                      Technical risk: {item.score_breakdown.governing_technical_risk}/4
                    </span>
                    <span className="text-[10px] font-mono px-2 py-1 rounded bg-slate-50 border border-slate-200 text-slate-600">
                      Migration effort: {item.score_breakdown.migration_effort_score}/4
                    </span>
                    <span className="text-[10px] font-mono px-2 py-1 rounded bg-slate-50 border border-slate-200 text-slate-600">
                      Complexity: {item.migration_complexity}
                    </span>
                  </div>
                </div>

                {isExpanded && (
                  <div className="p-5 bg-[#FCFCFA] border-t border-slate-100 space-y-4">
                    {/* Deterministic Score Breakdown */}
                    <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-4">
                      <div className="flex items-center gap-2">
                        <TrendingUp className="w-4 h-4 text-[#5755D9]" />
                        <h4 className="text-xs font-bold text-slate-900">
                          Why This Priority Score?
                        </h4>
                      </div>

                      <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
                        <div className="text-[10px] font-mono uppercase text-slate-500">
                          Deterministic Priority Formula
                        </div>
                        <p className="text-xs font-mono font-semibold text-slate-900">
                          Priority = 100 × Technical Risk × Composite Urgency
                        </p>
                        <p className="text-xs font-mono text-slate-600">
                          Composite Urgency = (0.70 × Business Exposure) + (0.30 × Migration Effort)
                        </p>
                        <p className="text-[11px] text-[#5755D9] font-semibold">
                          Calculated score: {item.priority_score}/100
                        </p>
                      </div>

                      <div>
                        <h5 className="text-[11px] font-bold text-slate-800 mb-2">
                          1. Technical Risk
                        </h5>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                            <div className="text-[10px] text-slate-500">
                              Governing technical risk
                            </div>
                            <div className="text-lg font-bold text-slate-900">
                              {item.score_breakdown.governing_technical_risk}/4
                            </div>
                            <div className="text-[10px] text-slate-500">
                              Normalized factor: {item.score_breakdown.technical_risk_factor.toFixed(4)}
                            </div>
                          </div>
                        </div>
                      </div>

                      <div>
                        <h5 className="text-[11px] font-bold text-slate-800 mb-2">
                          2. Business Exposure
                        </h5>
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                          {[
                            {
                              label: 'Criticality',
                              score: item.score_breakdown.criticality_score,
                            },
                            {
                              label: 'Sensitivity',
                              score: item.score_breakdown.sensitivity_score,
                            },
                            {
                              label: 'Data lifetime',
                              score: item.score_breakdown.lifetime_score,
                            },
                            {
                              label: 'Exposure',
                              score: item.score_breakdown.exposure_score,
                            },
                          ].map((factor) => (
                            <div
                              key={factor.label}
                              className="p-3 rounded-lg bg-slate-50 border border-slate-200"
                            >
                              <div className="text-[10px] text-slate-500">
                                {factor.label}
                              </div>
                              <div className="text-lg font-bold text-slate-900">
                                {factor.score}/4
                              </div>
                            </div>
                          ))}
                        </div>
                        <div className="mt-2 p-3 rounded-lg bg-indigo-50 border border-indigo-100">
                          <div className="text-[10px] text-indigo-700">
                            Weighted business exposure factor
                          </div>
                          <div className="text-lg font-bold text-indigo-800">
                            {item.score_breakdown.business_exposure_factor.toFixed(4)}
                          </div>
                          <p className="text-[10px] text-indigo-700 mt-1">
                            Criticality 30% · Sensitivity 25% · Data lifetime 30% · Exposure 15%
                          </p>
                        </div>
                      </div>

                      <div>
                        <h5 className="text-[11px] font-bold text-slate-800 mb-2">
                          3. Migration Effort
                        </h5>
                        <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                          <div className="text-[10px] text-slate-500">
                            Migration effort score
                          </div>
                          <div className="text-lg font-bold text-slate-900">
                            {item.score_breakdown.migration_effort_score}/4
                          </div>
                          <div className="text-[10px] text-slate-500">
                            Normalized factor: {item.score_breakdown.migration_effort_factor.toFixed(4)}
                          </div>
                        </div>
                      </div>

                      <div className="p-3 rounded-lg bg-[#F4F3FF] border border-[#DDD9FF]">
                        <div className="text-[10px] text-[#5755D9] font-semibold uppercase">
                          Composite urgency factor
                        </div>
                        <div className="text-xl font-black text-[#403D9B]">
                          {item.score_breakdown.composite_urgency_factor.toFixed(4)}
                        </div>
                      </div>

                      <div className="flex items-start gap-2 text-[10px] text-slate-500 leading-relaxed">
                        <Info className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                        <p>
                          Dimension scores use a 1–4 scale. The business exposure
                          factor combines the four business dimensions using the
                          displayed weights. Technical risk and migration effort
                          are normalized separately before calculating the final
                          priority score.
                        </p>
                      </div>
                    </div>

                    {/* Migration Recommendation */}
                    <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-3">
                      <h4 className="text-xs font-bold text-slate-900">
                        Recommended Migration
                      </h4>
                      <p className="text-xs text-slate-700 leading-relaxed">
                        {item.recommended_migration}
                      </p>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <div>
                          <div className="text-[10px] uppercase font-mono text-slate-500">
                            Recommended upgrade
                          </div>
                          <p className="text-xs text-slate-800 mt-1">
                            {item.recommended_upgrade}
                          </p>
                        </div>
                        <div>
                          <div className="text-[10px] uppercase font-mono text-slate-500">
                            Migration complexity
                          </div>
                          <p className="text-xs text-slate-800 mt-1">
                            {item.estimated_migration_complexity}
                          </p>
                        </div>
                      </div>
                    </div>

                    {/* Evidence and Findings */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div className="p-4 rounded-xl bg-white border border-slate-200 space-y-2">
                        <h4 className="text-xs font-bold text-slate-900">
                          Top Findings
                        </h4>
                        {item.top_findings.length > 0 ? (
                          <ul className="list-disc list-inside space-y-1 text-xs text-slate-600">
                            {item.top_findings.map((finding, index) => (
                              <li key={index}>{finding}</li>
                            ))}
                          </ul>
                        ) : (
                          <p className="text-xs text-slate-500">
                            No top findings provided.
                          </p>
                        )}
                      </div>

                      <div className="p-4 rounded-xl bg-white border border-slate-200 space-y-2">
                        <h4 className="text-xs font-bold text-slate-900 flex items-center gap-2">
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
                          Evidence Gaps
                        </h4>
                        {item.evidence_gaps.length > 0 ? (
                          <ul className="list-disc list-inside space-y-1 text-xs text-slate-600">
                            {item.evidence_gaps.map((gap, index) => (
                              <li key={index}>{gap}</li>
                            ))}
                          </ul>
                        ) : (
                          <p className="text-xs text-slate-500">
                            No evidence gaps reported.
                          </p>
                        )}
                      </div>
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
