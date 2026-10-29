import React, { useState } from 'react';
import type { QuantumScore } from '../types/scan';
import { ShieldAlert, ShieldCheck, Info, ChevronDown, ChevronUp, Layers, CheckCircle2 } from 'lucide-react';

interface ScoreCardProps {
  score: QuantumScore;
  domain: string;
}

export const ScoreCard: React.FC<ScoreCardProps> = ({ score, domain }) => {
  const [showFormula, setShowFormula] = useState(false);

  const getGradeTheme = (grade: string) => {
    switch (grade) {
      case 'Excellent':
        return {
          text: 'text-emerald-700',
          bg: 'bg-emerald-50',
          border: 'border-emerald-200',
          gauge: 'from-emerald-500 to-teal-500',
          badgeText: 'text-emerald-800',
        };
      case 'Good':
        return {
          text: 'text-[#5755D9]',
          bg: 'bg-indigo-50',
          border: 'border-indigo-200',
          gauge: 'from-indigo-500 to-violet-500',
          badgeText: 'text-[#5755D9]',
        };
      case 'Moderate':
        return {
          text: 'text-amber-800',
          bg: 'bg-amber-50',
          border: 'border-amber-200',
          gauge: 'from-amber-400 to-yellow-500',
          badgeText: 'text-amber-900',
        };
      case 'Needs Improvement':
        return {
          text: 'text-orange-800',
          bg: 'bg-orange-50',
          border: 'border-orange-200',
          gauge: 'from-orange-500 to-amber-500',
          badgeText: 'text-orange-900',
        };
      case 'Critical':
      default:
        return {
          text: 'text-red-700',
          bg: 'bg-red-50',
          border: 'border-red-200',
          gauge: 'from-red-500 to-rose-600',
          badgeText: 'text-red-800',
        };
    }
  };

  const theme = getGradeTheme(score.grade);
  const cb = score.category_breakdown;

  const categories = [
    { label: 'Certificate & Signatures', score: cb?.certificates ?? 60, weight: '30%' },
    { label: 'Key Establishment', score: cb?.key_establishment ?? 70, weight: '30%' },
    { label: 'Symmetric Encryption', score: cb?.symmetric_encryption ?? 100, weight: '20%' },
    { label: 'Hashing & Integrity', score: cb?.hashing ?? 90, weight: '10%' },
    { label: 'TLS Configuration', score: cb?.tls_configuration ?? 100, weight: '10%' },
  ];

  const getScoreColor = (val: number) => {
    if (val >= 85) return 'text-emerald-700 bg-emerald-500';
    if (val >= 70) return 'text-[#5755D9] bg-[#5755D9]';
    if (val >= 55) return 'text-amber-800 bg-amber-500';
    if (val >= 40) return 'text-orange-800 bg-orange-500';
    return 'text-red-700 bg-red-500';
  };

  return (
    <div className="rounded-2xl bg-white border border-slate-200/90 p-6 shadow-xs relative overflow-hidden space-y-6">
      {/* Top Banner: Target & Unambiguous Score */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
        {/* Main Readiness Gauge */}
        <div className="lg:col-span-5 flex flex-col items-center sm:items-start space-y-3">
          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono uppercase text-slate-500 tracking-wider">Target Domain:</span>
            <span className="text-sm font-mono font-bold text-slate-900 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
              {domain}
            </span>
          </div>

          <div className="flex items-baseline space-x-3">
            <span className={`text-6xl sm:text-7xl font-black tracking-tight font-mono ${theme.text}`}>
              {score.score}
            </span>
            <div className="flex flex-col">
              <span className="text-2xl font-extrabold text-slate-400 font-mono">/ 100</span>
              <span className="text-xs text-slate-500 uppercase tracking-wider font-semibold">Quantum Readiness</span>
            </div>
          </div>

          {/* Qualitative Grade Badge */}
          <div className="flex items-center space-x-2.5">
            <span
              className={`inline-flex items-center space-x-1.5 px-3.5 py-1 rounded-full text-xs font-extrabold tracking-wide border ${theme.bg} ${theme.badgeText} ${theme.border}`}
            >
              <span>{score.grade} Readiness</span>
            </span>
            <span className="text-xs text-slate-500">
              Exposure Risk: <strong className="text-slate-800 font-mono">{score.exposure_risk_score}</strong>
            </span>
          </div>

          {/* Progress bar gauge */}
          <div className="w-full space-y-1 pt-1">
            <div className="w-full h-2.5 rounded-full bg-slate-100 border border-slate-200 overflow-hidden flex">
              <div
                className={`h-full bg-gradient-to-r ${theme.gauge} transition-all duration-700`}
                style={{ width: `${Math.max(5, Math.min(100, score.score))}%` }}
              />
            </div>
            <div className="flex justify-between text-[10px] text-slate-400 font-mono">
              <span>0 (Extremely Poor)</span>
              <span>50 (Moderate)</span>
              <span>100 (Excellent)</span>
            </div>
          </div>
        </div>

        {/* 5-Category Score Breakdown Visualization */}
        <div className="lg:col-span-7 flex flex-col justify-between space-y-3 lg:border-l lg:border-slate-200 lg:pl-6">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center space-x-1.5 font-mono">
              <Layers className="w-4 h-4 text-[#5755D9]" />
              <span>Cryptographic Role Readiness Breakdown</span>
            </span>
            <span className="text-[11px] font-mono text-slate-500">Scale: 0–100</span>
          </div>

          <div className="space-y-2.5 pt-1">
            {categories.map((cat, idx) => {
              const colorInfo = getScoreColor(cat.score);
              const barBg = colorInfo.split(' ')[1];
              const textCol = colorInfo.split(' ')[0];

              return (
                <div key={idx} className="space-y-1">
                  <div className="flex justify-between text-xs font-mono">
                    <span className="text-slate-700">
                      {cat.label} <span className="text-slate-400 text-[10px]">({cat.weight})</span>
                    </span>
                    <span className={`font-bold ${textCol}`}>{cat.score} / 100</span>
                  </div>
                  <div className="w-full h-1.5 rounded-full bg-slate-100 border border-slate-200 overflow-hidden">
                    <div
                      className={`h-full ${barBg} transition-all duration-500`}
                      style={{ width: `${cat.score}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Transparent Formula & Methodology Explainer */}
      <div className="pt-4 border-t border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
        <p className="text-slate-600 text-xs">
          {score.summary}
        </p>

        <button
          onClick={() => setShowFormula(!showFormula)}
          className="flex items-center space-x-1 text-[#5755D9] hover:text-[#4745C9] font-mono text-xs cursor-pointer shrink-0 font-medium"
        >
          <span>{showFormula ? 'Hide Formula' : 'Scoring Formula'}</span>
          {showFormula ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </button>
      </div>

      {showFormula && (
        <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 text-xs space-y-2 font-mono">
          <div className="text-[#5755D9] font-bold">
            Readiness Score Formula:
          </div>
          <p className="text-slate-700 leading-relaxed">
            Quantum Readiness = 0.30 &times; (Certificate & Signatures) + 0.30 &times; (Key Establishment) + 0.20 &times; (Symmetric Encryption) + 0.10 &times; (Hashing) + 0.10 &times; (TLS Configuration).
          </p>
          <p className="text-slate-500 text-[11px] leading-relaxed">
            Higher score indicates superior quantum resistance. Unobservable parameters (e.g. TLS 1.3 KeyShare group) are treated as neutral baselines (70) without penalizing the organization for external scanner visibility boundaries.
          </p>
        </div>
      )}
    </div>
  );
};
