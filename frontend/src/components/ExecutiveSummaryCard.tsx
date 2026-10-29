import React from 'react';
import type { ExecutiveSummary } from '../types/scan';
import { FileText, AlertTriangle, CheckCircle2, EyeOff, ArrowRight } from 'lucide-react';

interface ExecutiveSummaryCardProps {
  summary: ExecutiveSummary;
}

export const ExecutiveSummaryCard: React.FC<ExecutiveSummaryCardProps> = ({ summary }) => {
  return (
    <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-6 shadow-xl space-y-5">
      {/* Header */}
      <div className="flex items-center space-x-2 pb-3 border-b border-slate-800">
        <FileText className="w-5 h-5 text-cyan-400" />
        <h2 className="text-lg font-bold text-white tracking-wide">Executive Quantum Readiness Summary</h2>
      </div>

      {/* 4 Core Executive Insights */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
        {/* 1. Readiness Verdict */}
        <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
          <div className="flex items-center space-x-2 text-cyan-400 font-bold uppercase tracking-wider font-mono text-[11px]">
            <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
            <span>1. Quantum Era Readiness Verdict</span>
          </div>
          <p className="text-slate-300 leading-relaxed font-sans text-sm">
            {summary.readiness_verdict}
          </p>
        </div>

        {/* 2. Primary & Secondary Concerns */}
        <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
          <div className="flex items-center space-x-2 text-orange-400 font-bold uppercase tracking-wider font-mono text-[11px]">
            <AlertTriangle className="w-4 h-4 text-orange-400 shrink-0" />
            <span>2. Primary & Secondary Concerns</span>
          </div>
          <div className="space-y-1.5 text-slate-300">
            <p className="leading-relaxed">
              <strong className="text-white">Primary:</strong> {summary.primary_concern}
            </p>
            {summary.secondary_concern && (
              <p className="text-slate-400 leading-relaxed">
                <strong className="text-slate-300">Secondary:</strong> {summary.secondary_concern}
              </p>
            )}
          </div>
        </div>

        {/* 3. Recommended Next Steps */}
        <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
          <div className="flex items-center space-x-2 text-emerald-400 font-bold uppercase tracking-wider font-mono text-[11px]">
            <ArrowRight className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>3. Recommended Immediate Next Steps</span>
          </div>
          <ul className="space-y-1 text-slate-300">
            {summary.recommended_next_steps.map((step, idx) => (
              <li key={idx} className="leading-relaxed flex items-start space-x-1.5">
                <span className="text-emerald-400 font-mono font-bold">{idx + 1}.</span>
                <span>{step.replace(/^\d+\.\s*/, '')}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* 4. Visibility Limitations */}
        <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
          <div className="flex items-center space-x-2 text-slate-400 font-bold uppercase tracking-wider font-mono text-[11px]">
            <EyeOff className="w-4 h-4 text-slate-400 shrink-0" />
            <span>4. External Visibility Boundaries</span>
          </div>
          <p className="text-slate-400 leading-relaxed">
            {summary.visibility_limitations}
          </p>
        </div>
      </div>
    </div>
  );
};

