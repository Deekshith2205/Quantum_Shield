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
        return 'bg-red-50 text-red-700 border-red-200';
      case 'HIGH':
        return 'bg-amber-50 text-amber-800 border-amber-200';
      case 'MEDIUM':
        return 'bg-yellow-50 text-yellow-800 border-yellow-200';
      default:
        return 'bg-slate-100 text-slate-700 border-slate-200';
    }
  };

  return (
    <div className="p-5 rounded-2xl bg-white border border-slate-200/90 shadow-xs relative overflow-hidden">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-100">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-xl bg-indigo-50 border border-indigo-100 text-[#5755D9]">
            <Landmark className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-base font-bold text-slate-900 tracking-tight">{asset.name}</h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                {asset.id}
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-0.5">{asset.description}</p>
          </div>
        </div>

        {/* Business Criticality (Distinct from Vulnerability Severity) */}
        <div className="flex items-center space-x-2">
          <span className="text-xs font-mono text-slate-500">Asset Criticality:</span>
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
        <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200">
          <div className="flex items-center space-x-1.5 text-slate-500 font-mono text-[11px] mb-1">
            <Layers className="w-3.5 h-3.5 text-[#5755D9]" />
            <span>Trust Zone</span>
          </div>
          <div className="font-semibold text-slate-800 font-mono text-xs">{asset.trust_zone}</div>
        </div>

        <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200">
          <div className="flex items-center space-x-1.5 text-slate-500 font-mono text-[11px] mb-1">
            <Network className="w-3.5 h-3.5 text-sky-600" />
            <span>Exposure</span>
          </div>
          <div className="font-semibold text-slate-800 font-mono text-xs">{asset.exposure}</div>
        </div>

        <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200">
          <div className="flex items-center space-x-1.5 text-slate-500 font-mono text-[11px] mb-1">
            <ShieldAlert className="w-3.5 h-3.5 text-amber-600" />
            <span>Sensitivity</span>
          </div>
          <div className="font-semibold text-slate-800 font-mono text-xs">{asset.data_sensitivity}</div>
        </div>

        <div className="p-2.5 rounded-xl bg-slate-50 border border-slate-200">
          <div className="flex items-center space-x-1.5 text-slate-500 font-mono text-[11px] mb-1">
            <Clock className="w-3.5 h-3.5 text-emerald-600" />
            <span>SNDL Lifetime</span>
          </div>
          <div className="font-semibold text-slate-800 font-mono text-xs">{asset.data_lifetime}</div>
        </div>
      </div>
    </div>
  );
};
