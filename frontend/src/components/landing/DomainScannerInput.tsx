import React, { useState, useEffect } from 'react';
import { Globe, ArrowRight, Loader2, SlidersHorizontal, ChevronDown, ChevronUp } from 'lucide-react';

interface DomainScannerInputProps {
  onScan: (domain: string, port: number, probePqc?: boolean, assetId?: string) => void;
  isLoading: boolean;
  currentDomain?: string;
  initialAssetId?: string;
  className?: string;
}

const EXAMPLE_DOMAINS = [
  { domain: 'google.com', assetId: 'BANK-PROF-NET-BANKING' },
  { domain: 'python.org', assetId: 'BANK-PROF-CORE-BANKING' },
  { domain: 'cloudflare.com', assetId: 'BANK-PROF-PAYMENT-GATEWAY' },
  { domain: 'tls-v1-2.badssl.com', assetId: 'BANK-PROF-ATM-NETWORK' },
];

const BANKING_PROFILES = [
  { id: '', label: 'Auto-infer profile from target domain' },
  { id: 'BANK-PROF-PAYMENT-GATEWAY', label: 'Modern Payment Gateway (Critical / PQC Hybrid / HSM)' },
  { id: 'BANK-PROF-CORE-BANKING', label: 'Legacy Core Banking (Critical / RSA-2048 / Mainframe)' },
  { id: 'BANK-PROF-KYC-DB', label: 'Customer / KYC Database (Critical / Long SNDL / HSM)' },
  { id: 'BANK-PROF-NET-BANKING', label: 'Net Banking Portal (High / Web Banking / TLS 1.3)' },
  { id: 'BANK-PROF-ATM-NETWORK', label: 'ATM Network (High / 3DES / Dedicated Hardware)' },
];

export const DomainScannerInput: React.FC<DomainScannerInputProps> = ({
  onScan,
  isLoading,
  currentDomain = '',
  initialAssetId = '',
  className = '',
}) => {
  const [domain, setDomain] = useState(currentDomain);
  const [port, setPort] = useState(443);
  const [probePqc, setProbePqc] = useState(false);
  const [assetId, setAssetId] = useState(initialAssetId);
  const [showAdvanced, setShowAdvanced] = useState(false);

  useEffect(() => {
    if (initialAssetId) {
      setAssetId(initialAssetId);
    }
  }, [initialAssetId]);

  useEffect(() => {
    if (currentDomain) {
      setDomain(currentDomain);
    }
  }, [currentDomain]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = domain.trim();
    if (trimmed && !isLoading) {
      onScan(trimmed, port, probePqc, assetId || undefined);
    }
  };

  const handleSelectExample = (exampleDomain: string, exampleAssetId?: string) => {
    setDomain(exampleDomain);
    const chosenAsset = exampleAssetId || assetId;
    if (exampleAssetId) setAssetId(exampleAssetId);
    onScan(exampleDomain, 443, probePqc, chosenAsset || undefined);
  };

  return (
    <div className={`w-full max-w-[650px] space-y-3 ${className}`}>
      {/* Primary Input Container: ~650px wide, ~52px tall */}
      <form onSubmit={handleSubmit} className="relative w-full">
        <div className="flex items-center w-full h-[52px] bg-white rounded-[10px] border border-slate-200 shadow-[0_1px_4px_rgba(0,0,0,0.03)] focus-within:border-[#5755D9] focus-within:ring-2 focus-within:ring-[#5755D9]/10 transition-all pl-3.5 pr-1.5">
          {/* Globe Icon */}
          <div className="text-slate-400 shrink-0 mr-2.5">
            <Globe className="w-4 h-4 text-slate-400" strokeWidth={1.8} />
          </div>

          {/* Text Input */}
          <input
            id="domain-scanner-input"
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="Enter a domain to scan (e.g., example.com)"
            disabled={isLoading}
            className="w-full bg-transparent text-[14.5px] text-[#0F172A] placeholder:text-slate-400 focus:outline-none py-2 font-normal"
          />

          {/* Scan Now Button */}
          <button
            type="submit"
            disabled={isLoading || !domain.trim()}
            className="h-[40px] px-5 bg-[#18181B] hover:bg-black text-white text-[13.5px] font-medium rounded-[8px] flex items-center space-x-1.5 transition-all shadow-xs shrink-0 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed group"
          >
            {isLoading ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin text-white" />
                <span>Scanning...</span>
              </>
            ) : (
              <>
                <span>Scan Now</span>
                <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
              </>
            )}
          </button>
        </div>
      </form>

      {/* Example Domains Tag Pills */}
      <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
        <span className="text-[12.5px] text-slate-500 font-normal mr-1">Try examples:</span>
        {EXAMPLE_DOMAINS.map((item) => (
          <button
            key={item.domain}
            type="button"
            onClick={() => handleSelectExample(item.domain, item.assetId)}
            disabled={isLoading}
            className="text-[11.5px] font-normal px-2.5 py-0.5 rounded-full bg-[#F3F4F6] hover:bg-[#E5E7EB] text-[#4B5563] hover:text-[#0F172A] border border-slate-200/50 transition-colors cursor-pointer disabled:opacity-50 font-mono"
          >
            {item.domain}
          </button>
        ))}

        {/* Subtle toggle for advanced audit parameters */}
        <button
          type="button"
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="ml-auto text-[11px] text-slate-400 hover:text-slate-600 transition flex items-center space-x-1 cursor-pointer font-mono"
        >
          <SlidersHorizontal className="w-3 h-3" />
          <span>{showAdvanced ? 'Hide Options' : 'Options'}</span>
          {showAdvanced ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
        </button>
      </div>

      {/* Collapsible Advanced Audit Options */}
      {showAdvanced && (
        <div className="p-3.5 rounded-xl bg-slate-50/90 border border-slate-200 text-xs space-y-2.5 animate-in fade-in duration-150">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
            <label className="text-[11.5px] font-medium text-slate-600">
              Banking Profile Context:
            </label>
            <select
              value={assetId}
              onChange={(e) => setAssetId(e.target.value)}
              disabled={isLoading}
              className="w-full sm:w-auto px-2.5 py-1 rounded-lg bg-white border border-slate-300 text-slate-800 text-xs focus:outline-none cursor-pointer max-w-xs truncate"
            >
              {BANKING_PROFILES.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.label}
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center justify-between pt-1 border-t border-slate-200/80">
            <span className="text-[11.5px] text-slate-600">
              Active Hybrid PQC Probe (ML-KEM):
            </span>
            <input
              type="checkbox"
              checked={probePqc}
              onChange={(e) => setProbePqc(e.target.checked)}
              disabled={isLoading}
              className="rounded border-slate-300 text-[#5755D9] focus:ring-0 cursor-pointer w-4 h-4"
            />
          </div>
        </div>
      )}
    </div>
  );
};
