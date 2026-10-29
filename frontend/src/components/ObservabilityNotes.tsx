import React from 'react';
import type { ObservabilityScope } from '../types/scan';
import { Eye, EyeOff, HelpCircle, CheckCircle2 } from 'lucide-react';

interface ObservabilityNotesProps {
  scope?: ObservabilityScope;
  notes?: string[];
}

export const ObservabilityNotes: React.FC<ObservabilityNotesProps> = ({ scope, notes = [] }) => {
  const observedList = scope?.observed_externally && scope.observed_externally.length > 0
    ? scope.observed_externally
    : [
        'TLS protocol version (e.g. TLSv1.3)',
        'Negotiated cipher suite (e.g. TLS_AES_256_GCM_SHA384)',
        'X.509 certificate public-key algorithm (RSA, ECC, EdDSA)',
        'RSA key size (e.g. 2048, 4096 bits) and EC curve parameters (e.g. NIST P-256)',
        'Certificate signature algorithm (e.g. ecdsa-with-SHA256, sha256WithRSAEncryption)',
        'Issuer and subject distinguished names',
        'Validity periods and expiration countdown',
        'Subject Alternative Names (SANs)',
        'ALPN protocol (e.g. h2, http/1.1)',
      ];

  const inferredList = scope?.potentially_inferred && scope.potentially_inferred.length > 0
    ? scope.potentially_inferred
    : [
        'TLS 1.2 Key Exchange prefix (e.g. ECDHE, DHE) when explicitly named in cipher suite',
        'Symmetric mode of operation (GCM, CBC, CCM) derived from cipher suite standard',
      ];

  const unobservableList = scope?.not_externally_observable && scope.not_externally_observable.length > 0
    ? scope.not_externally_observable
    : [
        'TLS 1.3 KeyShare group if unavailable from client TLS socket APIs',
        'Server private keys and hardware security module (HSM) seed entropy',
        'Internal database at-rest encryption and Key Management Service (KMS) policies',
        'Application-level cryptography (JWT secrets, session tokens, password hashes)',
        'Internal service-to-service mutual TLS (mTLS) configurations',
        'VPN and internal corporate network transport cryptography',
      ];

  return (
    <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-6 space-y-5 shadow-xl">
      <div className="flex items-center space-x-2 pb-2 border-b border-slate-800">
        <HelpCircle className="w-5 h-5 text-cyan-400" />
        <h2 className="text-lg font-bold text-white tracking-wide font-mono">
          WHAT QUANTUMSHIELD CAN OBSERVE
        </h2>
      </div>
      <p className="text-xs text-slate-400 leading-relaxed">
        To maintain strict technical rigor, QuantumShield evaluates exclusively publicly observable parameters obtained from external TLS connections and leaf certificates. Internal, proprietary, or host-bound cryptography is never guessed.
      </p>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
        {/* Column 1: Observed Externally */}
        <div className="p-4 rounded-xl bg-slate-950/60 border border-emerald-900/40 space-y-2.5">
          <div className="flex items-center space-x-1.5 text-emerald-400 font-bold uppercase text-[11px]">
            <Eye className="w-3.5 h-3.5" />
            <span>Observed Externally</span>
          </div>
          <ul className="space-y-1.5 text-slate-300 text-[11px]">
            {observedList.map((item, idx) => (
              <li key={idx} className="flex items-start space-x-1.5">
                <span className="text-emerald-500 font-bold">&bull;</span>
                <span className="leading-tight">{item}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* Column 2: Potentially Inferred */}
        <div className="p-4 rounded-xl bg-slate-950/60 border border-amber-900/40 space-y-2.5">
          <div className="flex items-center space-x-1.5 text-amber-400 font-bold uppercase text-[11px]">
            <span>Potentially Inferred</span>
          </div>
          <ul className="space-y-1.5 text-slate-300 text-[11px]">
            {inferredList.map((item, idx) => (
              <li key={idx} className="flex items-start space-x-1.5">
                <span className="text-amber-500 font-bold">&bull;</span>
                <span className="leading-tight">{item}</span>
              </li>
            ))}
          </ul>
          <p className="text-[10px] text-slate-500 pt-1">
            *Inferences are only made when formal protocol specifications guarantee standard mapping.
          </p>
        </div>

        {/* Column 3: Not Externally Observable */}
        <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2.5">
          <div className="flex items-center space-x-1.5 text-slate-400 font-bold uppercase text-[11px]">
            <EyeOff className="w-3.5 h-3.5" />
            <span>Not Externally Observable</span>
          </div>
          <ul className="space-y-1.5 text-slate-400 text-[11px]">
            {unobservableList.map((item, idx) => (
              <li key={idx} className="flex items-start space-x-1.5">
                <span className="text-slate-600 font-bold">&bull;</span>
                <span className="leading-tight">{item}</span>
              </li>
            ))}
          </ul>
          <p className="text-[10px] text-slate-500 pt-1">
            *External scans cannot assess internal host components. Lack of visibility is not proof of insecurity.
          </p>
        </div>
      </div>
    </div>
  );
};
