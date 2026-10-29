import React, { useState } from 'react';
import type { QuantumScore } from '../types/scan';
import { ShieldAlert, ShieldCheck, Info, ChevronDown, ChevronUp, Layers, CheckCircle2 } from 'lucide-react';

interface ScoreCardProps {
  score: QuantumScore;
  domain: string;
}

export const ScoreCard: React.FC<ScoreCardProps> = ({ score, domain }) => {
  const [showFormula, setShowFormula] = useState(false);

  // Grade color theme mapping for Quantum Readiness Score (higher is better)
  const getGradeTheme = (grade: string) => {
    switch (grade) {
      case 'Excellent':
        return {
          text: 'text-emerald-400',
          bg: 'bg-emerald-950/60',
          border: 'border-emerald-500/50',
          gauge: 'from-emerald-500 to-teal-400',
          badgeText: 'text-emerald-300',
        };
      case 'Good':
        return {
          text: 'text-cyan-400',
          bg: 'bg-cyan-950/60',
          border: 'border-cyan-500/50',
          gauge: 'from-cyan-500 to-blue-500',
          badgeText: 'text-cyan-300',
        };
      case 'Moderate':
        return {
          text: 'text-amber-400',
          bg: 'bg-amber-950/60',
          border: 'border-amber-500/50',
          gauge: 'from-amber-500 to-yellow-400',
          badgeText: 'text-amber-300',
        };
      case 'Needs Improvement':
        return {
          text: 'text-orange-400',
          bg: 'bg-orange-950/60',
          border: 'border-orange-500/50',
          gauge: 'from-orange-500 to-amber-500',
          badgeText: 'text-orange-300',
        };
      case 'Critical':
      default:
        return {
          text: 'text-rose-400',
          bg: 'bg-rose-950/60',
          border: 'border-rose-500/50',
          gauge: 'from-rose-500 to-red-600',
          badgeText: 'text-rose-300',
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
    if (val >= 85) return 'text-emerald-400 bg-emerald-500';
    if (val >= 70) return 'text-cyan-400 bg-cyan-500';
    if (val >= 55) return 'text-amber-400 bg-amber-500';
    if (val >= 40) return 'text-orange-400 bg-orange-500';
    return 'text-rose-400 bg-rose-500';
  };

  return (
    <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-6 shadow-xl relative overflow-hidden space-y-6">
      {/* Background cyber glow */}
      <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

      {/* Top Banner: Target & Unambiguous Score */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
        {/* Main Readiness Gauge */}
        <div className="lg:col-span-5 flex flex-col items-center sm:items-start space-y-3">
          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono uppercase text-slate-400 tracking-wider">Target Domain:</span>
            <span className="text-sm font-mono font-bold text-white bg-slate-800/80 px-2 py-0.5 rounded border border-slate-700">
              {domain}
            </span>
          </div>

          <div className="flex items-baseline space-x-3">
            <span className={`text-6xl sm:text-7xl font-black tracking-tight font-mono ${theme.text}`}>
              {score.score}
            </span>
            <div className="flex flex-col">
              <span className="text-2xl font-extrabold text-slate-400 font-mono">/ 100</span>
              <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Quantum Readiness</span>
            </div>
          </div>

          {/* Qualitative Grade Badge */}
          <div className="flex items-center space-x-2.5">
            <span
              className={`inline-flex items-center space-x-1.5 px-3.5 py-1 rounded-full text-xs font-extrabold tracking-wide border ${theme.bg} ${theme.badgeText} ${theme.border}`}
            >
              <span>{score.grade} Readiness</span>
            </span>
            <span className="text-xs text-slate-400">
              Exposure Risk: <strong className="text-slate-200 font-mono">{score.exposure_risk_score}</strong>
            </span>
          </div>

          {/* Progress bar gauge (0 = poor, 100 = excellent) */}
          <div className="w-full space-y-1 pt-1">
            <div className="w-full h-2.5 rounded-full bg-slate-800 overflow-hidden flex">
              <div
                className={`h-full bg-gradient-to-r ${theme.gauge} transition-all duration-700`}
                style={{ width: `${Math.max(5, Math.min(100, score.score))}%` }}
              />
            </div>
            <div className="flex justify-between text-[10px] text-slate-500 font-mono">
              <span>0 (Extremely Poor)</span>
              <span>50 (Moderate)</span>
              <span>100 (Excellent)</span>
            </div>
          </div>
        </div>

        {/* 5-Category Score Breakdown Visualization (Requirement 8) */}
        <div className="lg:col-span-7 flex flex-col justify-between space-y-3 lg:border-l lg:border-slate-800 lg:pl-6">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5 font-mono">
              <Layers className="w-4 h-4 text-cyan-400" />
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
                    <span className="text-slate-300">
                      {cat.label} <span className="text-slate-500 text-[10px]">({cat.weight})</span>
                    </span>
                    <span className={`font-bold ${textCol}`}>{cat.score} / 100</span>
                  </div>
                  <div className="w-full h-1.5 rounded-full bg-slate-800 overflow-hidden">
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
      <div className="pt-4 border-t border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
        <p className="text-slate-400 text-xs">
          {score.summary}
        </p>

        <button
          onClick={() => setShowFormula(!showFormula)}
          className="flex items-center space-x-1 text-cyan-400 hover:text-cyan-300 font-mono text-xs cursor-pointer shrink-0"
        >
          <span>{showFormula ? 'Hide Formula' : 'Scoring Formula'}</span>
          {showFormula ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </button>
      </div>

      {showFormula && (
        <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 text-xs space-y-2 font-mono">
          <div className="text-cyan-300 font-bold">
            Readiness Score Formula:
          </div>
          <p className="text-slate-300 leading-relaxed">
            Quantum Readiness = 0.30 &times; (Certificate & Signatures) + 0.30 &times; (Key Establishment) + 0.20 &times; (Symmetric Encryption) + 0.10 &times; (Hashing) + 0.10 &times; (TLS Configuration).
          </p>
          <p className="text-slate-400 text-[11px] leading-relaxed">
            Higher score indicates superior quantum resistance. Unobservable parameters (e.g. TLS 1.3 KeyShare group) are treated as neutral baselines (70) without penalizing the organization for external scanner visibility boundaries.
          </p>
        </div>
      )}
    </div>
  );
};
