import React, { useState, useEffect } from 'react';
import { Search, Loader2, Globe, ShieldAlert, ArrowRight, Landmark } from 'lucide-react';

interface DomainInputProps {
  onScan: (domain: string, port: number, probePqc?: boolean, assetId?: string) => void;
  isLoading: boolean;
  currentDomain?: string;
  initialAssetId?: string;
}

const SAMPLE_DOMAINS = [
  { name: 'api.chase.com', note: 'Banking API Gateway (HIGH Criticality)', assetId: 'BANK-PROF-PAYMENT-GATEWAY' },
  { name: 'cloudflare.com', note: 'Financial CDN Edge (PQC Hybrid)', assetId: 'BANK-PROF-PAYMENT-GATEWAY' },
  { name: 'google.com', note: 'ECDSA P-256 + TLS 1.3', assetId: 'BANK-PROF-NET-BANKING' },
  { name: 'python.org', note: 'RSA-2048 + TLS 1.3', assetId: 'BANK-PROF-CORE-BANKING' },
];

const BANKING_PROFILES = [
  { id: '', label: 'Auto-infer profile from target domain' },
  { id: 'BANK-PROF-PAYMENT-GATEWAY', label: 'Modern Payment Gateway (Critical / PQC Hybrid / HSM)' },
  { id: 'BANK-PROF-CORE-BANKING', label: 'Legacy Core Banking (Critical / RSA-2048 / Mainframe)' },
  { id: 'BANK-PROF-KYC-DB', label: 'Customer / KYC Database (Critical / Long SNDL / HSM)' },
  { id: 'BANK-PROF-NET-BANKING', label: 'Net Banking Portal (High / Web Banking / TLS 1.3)' },
  { id: 'BANK-PROF-ATM-NETWORK', label: 'ATM Network (High / 3DES / Dedicated Hardware)' },
];

export const DomainInput: React.FC<DomainInputProps> = ({
  onScan,
  isLoading,
  currentDomain = '',
  initialAssetId = '',
}) => {
  const [domain, setDomain] = useState(currentDomain);
  const [port, setPort] = useState(443);
  const [probePqc, setProbePqc] = useState(false);
  const [assetId, setAssetId] = useState(initialAssetId);

  useEffect(() => {
    if (initialAssetId) {
      setAssetId(initialAssetId);
    }
  }, [initialAssetId]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (domain.trim()) {
      onScan(domain.trim(), port, probePqc, assetId ? assetId : undefined);
    }
  };

  const handleSelectSample = (sample: string, sampleAssetId?: string) => {
    setDomain(sample);
    const chosenAsset = sampleAssetId || assetId;
    if (sampleAssetId) setAssetId(sampleAssetId);
    onScan(sample, 443, probePqc, chosenAsset ? chosenAsset : undefined);
  };

  return (
    <section className="relative pt-10 pb-8 px-4 sm:px-6 max-w-4xl mx-auto text-center">
      {/* Decorative cyber gradient glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-48 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none -z-10" />

      {/* Main Tagline & Problem Statement */}
      <div className="space-y-3 mb-8">
        <h1 className="text-3xl sm:text-5xl font-black tracking-tight text-white">
          QUANTUM<span className="text-cyan-400">SHIELD</span>
        </h1>
        <p className="text-base sm:text-xl text-slate-300 font-medium max-w-2xl mx-auto">
          "Know your cryptographic exposure before quantum computers do."
        </p>
        <p className="text-xs sm:text-sm text-slate-400 max-w-xl mx-auto">
          Non-invasive banking security audit and external TLS assessment evaluating perimeter cryptography against Shor's and Grover's quantum threat models.
        </p>
      </div>

      {/* Input Search Form */}
      <form onSubmit={handleSubmit} className="max-w-2xl mx-auto">
        <div className="flex flex-col sm:flex-row items-center gap-2.5 p-1.5 rounded-2xl bg-slate-900/90 border border-slate-700/80 shadow-2xl shadow-cyan-950/30 focus-within:border-cyan-500/80 transition">
          <div className="flex items-center w-full px-3 py-2.5 space-x-2.5">
            <Globe className="w-5 h-5 text-slate-400 shrink-0" />
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="Enter public domain (e.g. example.com)..."
              disabled={isLoading}
              className="w-full bg-transparent text-sm sm:text-base text-white placeholder-slate-500 focus:outline-none font-mono"
            />
          </div>

          <button
            type="submit"
            disabled={isLoading || !domain.trim()}
            className="w-full sm:w-auto px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white font-semibold text-sm tracking-wide transition shadow-lg shadow-cyan-950/50 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-2 shrink-0 cursor-pointer"
          >
            {isLoading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-white" />
                <span>Auditing...</span>
              </>
            ) : (
              <>
                <span>AUDIT DOMAIN</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>

        {/* Banking System Profile & PQC Probe Options */}
        <div className="mt-3 flex flex-col sm:flex-row items-center justify-center gap-2 text-xs">
          {/* Banking Asset Profile Selector */}
          <div className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-900/60 border border-slate-800 text-slate-300 w-full sm:w-auto">
            <Landmark className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <select
              value={assetId}
              onChange={(e) => setAssetId(e.target.value)}
              disabled={isLoading}
              className="bg-transparent text-xs text-slate-300 focus:outline-none cursor-pointer max-w-[280px] truncate"
            >
              {BANKING_PROFILES.map((p) => (
                <option key={p.id} value={p.id} className="bg-slate-900 text-slate-200">
                  {p.label}
                </option>
              ))}
            </select>
          </div>

          {/* Active PQC Probe Toggle */}
          <label className="inline-flex items-center space-x-2 cursor-pointer bg-slate-900/60 border border-slate-800 hover:border-cyan-500/50 px-3 py-1.5 rounded-lg transition w-full sm:w-auto justify-center">
            <input
              type="checkbox"
              checked={probePqc}
              onChange={(e) => setProbePqc(e.target.checked)}
              disabled={isLoading}
              className="rounded bg-slate-950 border-slate-700 text-cyan-500 focus:ring-0 focus:ring-offset-0 cursor-pointer"
            />
            <span className="text-slate-300 font-mono text-xs">
              Hybrid PQC Probe <span className="text-cyan-400 font-semibold">(ML-KEM)</span>
            </span>
          </label>
        </div>

        {/* Quick sample chips */}
        <div className="mt-4 flex flex-wrap items-center justify-center gap-2">
          <span className="text-xs text-slate-500 font-mono">Sample targets:</span>
          {SAMPLE_DOMAINS.map((item) => (
            <button
              key={item.name}
              type="button"
              onClick={() => handleSelectSample(item.name, item.assetId)}
              disabled={isLoading}
              className="text-xs font-mono px-2.5 py-1 rounded-md bg-slate-800/80 hover:bg-slate-700/80 text-cyan-300 border border-slate-700/60 hover:border-cyan-500/40 transition disabled:opacity-50 cursor-pointer"
              title={item.note}
            >
              {item.name}
            </button>
          ))}
        </div>
      </form>
    </section>
  );
};
