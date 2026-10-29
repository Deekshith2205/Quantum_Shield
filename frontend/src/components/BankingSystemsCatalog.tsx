import React, { useState, useEffect } from 'react';
import type { BankingAsset } from '../types/scan';
import { BankingSystemCard } from './BankingSystemCard';
import { getBankingProfiles } from '../services/api';
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
}

const PROFILE_DEFAULT_DOMAINS: Record<string, string> = {
  'BANK-PROF-PAYMENT-GATEWAY': 'api.chase.com',
  'BANK-PROF-CORE-BANKING': 'python.org',
  'BANK-PROF-KYC-DB': 'cloudflare.com',
  'BANK-PROF-NET-BANKING': 'google.com',
  'BANK-PROF-ATM-NETWORK': 'api.chase.com',
};

export const BankingSystemsCatalog: React.FC<BankingSystemsCatalogProps> = ({ onAuditProfile }) => {
  const [profiles, setProfiles] = useState<BankingAsset[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [selectedCriticality, setSelectedCriticality] = useState<string>('ALL');

  useEffect(() => {
    let isMounted = true;
    setIsLoading(true);
    getBankingProfiles()
      .then((data) => {
        if (isMounted) {
          setProfiles(data);
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
      {/* Header & Disclaimer */}
      <div className="p-6 rounded-2xl bg-gradient-to-br from-slate-900/90 via-slate-900/70 to-slate-950/90 border border-slate-800 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-40 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

        <div className="flex items-start space-x-3.5 mb-3">
          <div className="p-3 rounded-xl bg-cyan-950/80 border border-cyan-800/60 text-cyan-400">
            <Landmark className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white tracking-wide">
              Representative Banking Systems Catalog
            </h2>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
              Standardized financial infrastructure security models with multi-layer architecture,
              explicit evidence provenance (Observed vs Declared), key-protection hierarchies, and structured evidence gaps.
            </p>
          </div>
        </div>

        {/* Official Synthetic Environment Disclaimer */}
        <div className="p-3.5 rounded-xl bg-amber-950/30 border border-amber-800/50 text-amber-200/90 text-xs flex items-start space-x-2.5 mt-4">
          <Info className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <p className="leading-relaxed">
            <strong className="text-amber-300 font-semibold">Synthetic Environment Disclaimer:</strong>{' '}
            QuantumShield's banking profiles are representative synthetic environments used to demonstrate security
            auditing and migration prioritization. They do not represent the actual architecture or configuration of
            any specific bank.
          </p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-xs">
        <div className="flex items-center space-x-2 w-full sm:w-auto flex-1 max-w-md px-3 py-2 rounded-lg bg-slate-950/80 border border-slate-800">
          <Search className="w-4 h-4 text-slate-500 shrink-0" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search banking profiles by name, ID, or tag..."
            className="w-full bg-transparent text-xs text-white placeholder-slate-500 focus:outline-none font-mono"
          />
        </div>

        <div className="flex items-center space-x-2 w-full sm:w-auto">
          <Filter className="w-4 h-4 text-slate-400 shrink-0" />
          <span className="text-slate-400 text-xs font-mono">Criticality:</span>
          <select
            value={selectedCriticality}
            onChange={(e) => setSelectedCriticality(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none cursor-pointer"
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
          <Loader2 className="w-8 h-8 animate-spin text-cyan-400 mx-auto" />
          <p className="text-xs text-slate-400 font-mono">Loading representative banking profiles catalog...</p>
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/60 border border-rose-800/80 text-rose-200 text-xs flex items-start space-x-3">
          <AlertCircle className="w-5 h-5 text-rose-400 shrink-0" />
          <div>
            <div className="font-bold text-rose-300">Failed to load profiles</div>
            <div className="text-slate-300 mt-0.5">{error}</div>
          </div>
        </div>
      )}

      {/* Profile Cards List */}
      {!isLoading && !error && (
        <div className="space-y-4">
          {filteredProfiles.length === 0 ? (
            <div className="p-8 text-center text-slate-500 text-xs font-mono">
              No representative banking systems match the filter criteria.
            </div>
          ) : (
            filteredProfiles.map((prof) => (
              <BankingSystemCard
                key={prof.id}
                profile={prof}
                onAuditWithScan={handleAudit}
                isDetailedView={true}
              />
            ))
          )}
        </div>
      )}
    </div>
  );
};

