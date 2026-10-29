import React from 'react';
import type { BankingAsset } from '../types/scan';
import { Landmark, ShieldAlert, Network, Clock, Eye, Layers } from 'lucide-react';

interface BankingAssetCardProps {
  asset: BankingAsset;
}

export const BankingAssetCard: React.FC<BankingAssetCardProps> = ({ asset }) => {
  const getCriticalityBadge = (criticality: string) => {
    switch (criticality) {
      case 'CRITICAL':
        return 'bg-rose-950/80 text-rose-300 border-rose-800/70';
      case 'HIGH':
        return 'bg-amber-950/80 text-amber-300 border-amber-800/70';
      case 'MEDIUM':
        return 'bg-yellow-950/80 text-yellow-300 border-yellow-800/70';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="p-5 rounded-2xl bg-gradient-to-br from-slate-900/90 via-slate-900/70 to-slate-950/90 border border-slate-800 shadow-xl relative overflow-hidden">
      <div className="absolute top-0 right-0 w-64 h-32 bg-cyan-500/5 rounded-full blur-2xl pointer-events-none" />

      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-xl bg-cyan-950/80 border border-cyan-800/60 text-cyan-400">
            <Landmark className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-base font-bold text-white tracking-wide">{asset.name}</h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                {asset.id}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">{asset.description}</p>
          </div>
        </div>

        {/* Business Criticality (Distinct from Vulnerability Severity) */}
        <div className="flex items-center space-x-2">
          <span className="text-xs font-mono text-slate-400">Asset Criticality:</span>
          <span
            className={`text-xs font-mono font-bold px-3 py-1 rounded-lg border uppercase tracking-wider ${getCriticalityBadge(
              asset.criticality
            )}`}
          >
            {asset.criticality}
          </span>
        </div>
      </div>

      {/* Banking Context Attributes Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-4 text-xs">
        <div className="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800/60">
          <div className="flex items-center space-x-1.5 text-slate-400 font-mono text-[11px] mb-1">
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            <span>Asset Type</span>
          </div>
          <div className="font-semibold text-slate-200 font-mono">{asset.asset_type.replace('_', ' ')}</div>
        </div>

        <div className="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800/60">
          <div className="flex items-center space-x-1.5 text-slate-400 font-mono text-[11px] mb-1">
            <Network className="w-3.5 h-3.5 text-indigo-400" />
            <span>Trust Zone</span>
          </div>
          <div className="font-semibold text-slate-200 font-mono">{asset.trust_zone}</div>
        </div>

        <div className="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800/60">
          <div className="flex items-center space-x-1.5 text-slate-400 font-mono text-[11px] mb-1">
            <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
            <span>Data Sensitivity</span>
          </div>
          <div className="font-semibold text-slate-200 font-mono">{asset.data_sensitivity.replace('_', ' ')}</div>
        </div>

        <div className="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800/60">
          <div className="flex items-center space-x-1.5 text-slate-400 font-mono text-[11px] mb-1">
            <Clock className="w-3.5 h-3.5 text-emerald-400" />
            <span>SNDL Lifetime</span>
          </div>
          <div className="font-semibold text-slate-200 font-mono">{asset.data_lifetime.replace('_', ' ')}</div>
        </div>
      </div>
    </div>
  );
};

