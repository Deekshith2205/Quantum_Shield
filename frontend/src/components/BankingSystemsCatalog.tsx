import React, { useState, useEffect } from 'react';
import type { BankingAsset, BankingRiskAssessment } from '../types/scan';
import { BankingSystemCard } from './BankingSystemCard';
import { getBankingProfiles, getBankingRiskRankings } from '../services/api';
import {
  Landmark,
  ShieldAlert,
  Search,
  Filter,
  Info,
  Layers,
  Sparkles,
  Loader2,
  AlertCircle,
} from 'lucide-react';

interface BankingSystemsCatalogProps {
  onAuditProfile: (profileId: string, suggestedDomain?: string) => void;
  onSimulateProfile?: (profileId: string) => void;
}

const PROFILE_DEFAULT_DOMAINS: Record<string, string> = {
  'BANK-PROF-PAYMENT-GATEWAY': 'api.chase.com',
  'BANK-PROF-CORE-BANKING': 'python.org',
  'BANK-PROF-KYC-DB': 'cloudflare.com',
  'BANK-PROF-NET-BANKING': 'google.com',
  'BANK-PROF-ATM-NETWORK': 'api.chase.com',
};

export const BankingSystemsCatalog: React.FC<BankingSystemsCatalogProps> = ({
  onAuditProfile,
  onSimulateProfile,
}) => {
  const [profiles, setProfiles] = useState<BankingAsset[]>([]);
  const [risks, setRisks] = useState<Record<string, BankingRiskAssessment>>({});
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [selectedCriticality, setSelectedCriticality] = useState<string>('ALL');

  useEffect(() => {
    let isMounted = true;
    setIsLoading(true);
    Promise.all([getBankingProfiles(), getBankingRiskRankings()])
      .then(([profilesData, risksData]) => {
        if (isMounted) {
          setProfiles(profilesData);
          const riskMap: Record<string, BankingRiskAssessment> = {};
          risksData.forEach((r) => {
            riskMap[r.asset_id] = r;
          });
          setRisks(riskMap);
          setError(null);
        }
      })
      .catch((err) => {
        if (isMounted) {
          setError(err.message || 'Failed to load banking system profiles.');
        }
      })
      .finally(() => {
        if (isMounted) setIsLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, []);

  const filteredProfiles = profiles.filter((p) => {
    const matchesSearch =
      p.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (p.tags && p.tags.some((t) => t.toLowerCase().includes(searchTerm.toLowerCase())));

    const matchesCriticality =
      selectedCriticality === 'ALL' || p.criticality === selectedCriticality;

    return matchesSearch && matchesCriticality;
  });

  const handleAudit = (profileId: string) => {
    const suggestedDomain = PROFILE_DEFAULT_DOMAINS[profileId] || 'example.com';
    onAuditProfile(profileId, suggestedDomain);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Editorial Page Header */}
      <div className="space-y-2">
        <div className="flex items-center space-x-2">
          <span className="text-xs font-mono uppercase tracking-widest text-[#5755D9] font-semibold">
            BANKING SYSTEMS
          </span>
          <span className="text-slate-300">/</span>
          <span className="text-xs font-mono text-slate-500">
            {profiles.length} Profiles Modeled
          </span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-light text-[#17181C] tracking-tight">
          Representative Banking Systems
        </h1>
        <p className="text-sm text-[#62656D] max-w-3xl leading-relaxed">
          Standardized financial infrastructure security models with multi-layer architecture,
          explicit evidence provenance (Observed vs Declared), key-protection hierarchies, and structured evidence gaps.
        </p>
      </div>

      {/* Official Synthetic Environment Disclaimer */}
      <div className="p-4 rounded-xl bg-slate-50 border border-slate-200/90 text-slate-700 text-xs flex items-start space-x-3">
        <Info className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
        <p className="leading-relaxed text-xs">
          <strong className="text-slate-900 font-semibold">Synthetic Environment Disclaimer:</strong>{' '}
          QuantumShield's banking profiles are representative synthetic environments used to demonstrate security
          auditing and migration prioritization. They do not represent the actual architecture or configuration of
          any specific bank.
        </p>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-3 rounded-xl bg-white border border-slate-200/90 shadow-xs text-xs">
        <div className="flex items-center space-x-2.5 w-full sm:w-auto flex-1 max-w-md px-3.5 py-2 rounded-lg bg-slate-50 border border-slate-200 focus-within:bg-white focus-within:border-[#5755D9] focus-within:ring-1 focus-within:ring-[#5755D9] transition">
          <Search className="w-4 h-4 text-slate-400 shrink-0" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search banking profiles by name, ID, or tag..."
            className="w-full bg-transparent text-xs text-[#17181C] placeholder-slate-400 focus:outline-none font-mono"
          />
        </div>

        <div className="flex items-center space-x-2 w-full sm:w-auto">
          <Filter className="w-4 h-4 text-slate-500 shrink-0" />
          <span className="text-slate-600 text-xs font-mono">Criticality:</span>
          <select
            value={selectedCriticality}
            onChange={(e) => setSelectedCriticality(e.target.value)}
            className="px-3 py-2 rounded-lg bg-white border border-slate-200 text-xs text-slate-800 focus:outline-none focus:border-[#5755D9] cursor-pointer font-sans"
          >
            <option value="ALL">All Criticalities</option>
            <option value="CRITICAL">Critical Only</option>
            <option value="HIGH">High Only</option>
            <option value="MEDIUM">Medium Only</option>
          </select>
        </div>
      </div>

      {/* Loading & Error States */}
      {isLoading && (
        <div className="p-12 text-center space-y-3">
          <Loader2 className="w-8 h-8 animate-spin text-[#5755D9] mx-auto" />
          <p className="text-xs text-slate-500 font-mono">Loading representative banking profiles catalog...</p>
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-rose-800 text-xs flex items-start space-x-3">
          <AlertCircle className="w-5 h-5 text-rose-600 shrink-0" />
          <div>
            <div className="font-bold text-rose-900">Failed to load profiles</div>
            <div className="text-rose-700 mt-0.5">{error}</div>
          </div>
        </div>
      )}

      {/* Profile Cards List */}
      {!isLoading && !error && (
        <div className="space-y-4">
          {filteredProfiles.length === 0 ? (
            <div className="p-8 text-center text-slate-500 text-xs font-mono bg-white rounded-xl border border-slate-200">
              No representative banking systems match the filter criteria.
            </div>
          ) : (
            filteredProfiles.map((prof) => (
              <BankingSystemCard
                key={prof.id}
                profile={prof}
                risk={risks[prof.id]}
                onAuditWithScan={handleAudit}
                onSimulate={onSimulateProfile}
                isDetailedView={true}
              />
            ))
          )}
        </div>
      )}
    </div>
  );
};
