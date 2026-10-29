import React from 'react';
import type { TargetInfo, CertificateInfo, TlsInfo } from '../types/scan';
import { Lock, ShieldCheck, Key, Server, CheckCircle, AlertTriangle, Activity, Eye, EyeOff, Zap, Cpu, Radio } from 'lucide-react';

interface TlsOverviewProps {
  target: TargetInfo;
  certificate: CertificateInfo;
  tls: TlsInfo;
}

export const TlsOverview: React.FC<TlsOverviewProps> = ({
  target,
  certificate,
  tls,
}) => {
  const getEvidenceBadge = (status?: string) => {
    switch (status?.toUpperCase()) {
      case 'OBSERVED':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950/80 text-emerald-400 border border-emerald-800/60">
            <Eye className="w-3 h-3" />
            <span>OBSERVED</span>
          </span>
        );
      case 'CAPABILITY_PROBED':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-700/60">
            <Zap className="w-3 h-3 text-cyan-400" />
            <span>CAPABILITY_PROBED</span>
          </span>
        );
      case 'CLASSICAL_ONLY_OBSERVED':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-950/80 text-blue-300 border border-blue-700/60">
            <Eye className="w-3 h-3 text-blue-400" />
            <span>CLASSICAL_ONLY</span>
          </span>
        );
      case 'PROBED_UNSUPPORTED':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950/80 text-rose-300 border border-rose-800/60">
            <AlertTriangle className="w-3 h-3 text-rose-400" />
            <span>PROBED_UNSUPPORTED</span>
          </span>
        );
      case 'INFERRED':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950/80 text-amber-400 border border-amber-800/60">
            <span>INFERRED</span>
          </span>
        );
      case 'NOT_OBSERVABLE':
      default:
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-400 border border-slate-700">
            <EyeOff className="w-3 h-3" />
            <span>NOT_OBSERVABLE</span>
          </span>
        );
    }
  };

  const isKxObservable = tls.key_exchange_evidence !== 'NOT_OBSERVABLE';
  const kxValue = isKxObservable ? tls.key_exchange_value || 'Not observable' : 'Not observable';
  const pqcEv = tls.pqc_evidence;

  return (
    <div className="space-y-4">
      {/* Section Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div className="flex items-center space-x-2">
          <Lock className="w-5 h-5 text-cyan-400" />
          <h2 className="text-lg font-bold text-white tracking-wide">Public TLS/SSL Configuration Overview</h2>
        </div>
        <div className="flex items-center space-x-3 text-xs font-mono text-slate-400">
          <span className="flex items-center space-x-1">
            <Server className="w-3.5 h-3.5 text-slate-500" />
            <span>{target.resolved_ip} ({target.ip_version})</span>
          </span>
          <span className="flex items-center space-x-1">
            <Activity className="w-3.5 h-3.5 text-slate-500" />
            <span>{target.connection_time_ms} ms</span>
          </span>
        </div>
      </div>

      {/* Grid of 4 parameter panels with explicit Role, Value, Source, and Evidence Status */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Panel 1: TLS Protocol */}
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase text-slate-400 tracking-wider">Role: TLS Protocol</span>
            {getEvidenceBadge('OBSERVED')}
          </div>
          <div>
            <span className="text-[10px] text-slate-500 uppercase block font-mono">Value</span>
            <div className="text-xl font-bold font-mono text-white">{tls.negotiated_protocol}</div>
          </div>
          <div className="text-xs text-slate-400 space-y-1 pt-2 border-t border-slate-800/80">
            <div className="flex justify-between">
              <span className="text-slate-500">Source:</span>
              <span className="font-mono text-slate-300">TLS Connection Handshake</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">ALPN:</span>
              <span className="font-mono text-slate-300">{tls.alpn_protocol || 'None'}</span>
            </div>
          </div>
        </div>

        {/* Panel 2: Key Exchange */}
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase text-slate-400 tracking-wider">Role: Key Exchange</span>
            {getEvidenceBadge(tls.key_exchange_evidence || 'NOT_OBSERVABLE')}
          </div>
          <div>
            <span className="text-[10px] text-slate-500 uppercase block font-mono">Value</span>
            <div className={`text-base font-bold font-mono ${isKxObservable ? (pqcEv?.is_hybrid ? 'text-cyan-300' : 'text-white') : 'text-slate-400'}`}>
              {kxValue}
            </div>
          </div>
          <div className="text-xs text-slate-400 space-y-1 pt-2 border-t border-slate-800/80">
            <div className="flex justify-between">
              <span className="text-slate-500">Source:</span>
              <span className="font-mono text-slate-300 truncate max-w-[140px]" title={pqcEv?.source || (isKxObservable ? 'TLS 1.2 Cipher Prefix' : 'Client TLS API')}>
                {pqcEv ? (pqcEv.probe_attempted ? 'Probed KeyShare' : 'OpenSSL KeyShare') : (isKxObservable ? 'TLS 1.2 Cipher Prefix' : 'Client TLS API')}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">PQC Status:</span>
              <span className={`font-mono ${pqcEv?.is_hybrid ? 'text-emerald-400 font-semibold' : 'text-cyan-400'}`}>
                {pqcEv?.is_hybrid ? 'Hybrid Active' : (pqcEv?.status === 'PROBED_UNSUPPORTED' ? 'Unsupported' : 'ML-KEM Target')}
              </span>
            </div>
          </div>
        </div>

        {/* Panel 3: Cipher Suite */}
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase text-slate-400 tracking-wider">Role: Symmetric Cipher</span>
            {getEvidenceBadge('OBSERVED')}
          </div>
          <div>
            <span className="text-[10px] text-slate-500 uppercase block font-mono">Value</span>
            <div className="text-sm font-bold font-mono text-white truncate" title={tls.negotiated_cipher}>
              {tls.negotiated_cipher}
            </div>
          </div>
          <div className="text-xs text-slate-400 space-y-1 pt-2 border-t border-slate-800/80">
            <div className="flex justify-between">
              <span className="text-slate-500">Source:</span>
              <span className="font-mono text-slate-300">Negotiated Cipher Suite</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Key Length:</span>
              <span className="font-mono text-slate-300">{tls.cipher_bits} bits</span>
            </div>
          </div>
        </div>

        {/* Panel 4: Certificate Auth */}
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase text-slate-400 tracking-wider">Role: Certificate Public Key</span>
            {getEvidenceBadge('OBSERVED')}
          </div>
          <div>
            <span className="text-[10px] text-slate-500 uppercase block font-mono">Value</span>
            <div className="text-sm font-bold font-mono text-white truncate">
              {certificate.public_key_algorithm} {certificate.key_size_bits ? `${certificate.key_size_bits}b` : ''}
              {certificate.curve_name ? ` (${certificate.curve_name})` : ''}
            </div>
          </div>
          <div className="text-xs text-slate-400 space-y-1 pt-2 border-t border-slate-800/80">
            <div className="flex justify-between">
              <span className="text-slate-500">Source:</span>
              <span className="font-mono text-slate-300">TLS Leaf Certificate</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">PQC Target:</span>
              <span className="font-mono text-cyan-400">ML-DSA / SLH-DSA</span>
            </div>
          </div>
        </div>
      </div>

      {/* TLS 1.3 Key Establishment & Hybrid PQC Card */}
      <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 text-xs space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-slate-800 gap-2">
          <span className="font-semibold text-slate-300 flex items-center space-x-1.5">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span>TLS 1.3 Key Establishment & PQC Telemetry (IETF RFC 9870 / NIST FIPS 203)</span>
          </span>
          <div className="flex items-center space-x-2">
            {getEvidenceBadge(tls.key_exchange_evidence || (pqcEv?.status ?? 'NOT_OBSERVABLE'))}
            {pqcEv?.is_hybrid && (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950/90 text-emerald-300 border border-emerald-700/60">
                PQC SECURE
              </span>
            )}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 text-slate-300 font-mono">
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">Negotiated / Probed Group</span>
            <span className={`font-bold block ${pqcEv?.is_hybrid ? 'text-cyan-300' : (isKxObservable ? 'text-white' : 'text-slate-400')}`}>
              {pqcEv?.raw_group || kxValue}
            </span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">Classical Component</span>
            <span className="text-white block">
              {pqcEv?.classical_component || (isKxObservable ? kxValue : 'Unverified')}
            </span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">Post-Quantum Component</span>
            <span className={`block font-semibold ${pqcEv?.pqc_component ? 'text-emerald-400' : 'text-slate-400'}`}>
              {pqcEv?.pqc_component || (pqcEv?.is_hybrid ? 'ML-KEM-768' : 'None (Classical Only)')}
            </span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">Hybrid Architecture</span>
            <span className={`block ${pqcEv?.is_hybrid ? 'text-emerald-400 font-semibold' : 'text-amber-400'}`}>
              {pqcEv?.is_hybrid ? 'Dual ECDHE + Lattice KEM' : 'Single Classical Curve'}
            </span>
          </div>

          <div className="lg:col-span-2 pt-1 border-t border-slate-800/60">
            <span className="text-slate-500 block text-[10px] uppercase">Telemetry Evidence Source</span>
            <span className="text-slate-300 block truncate">
              {pqcEv?.source || (isKxObservable ? 'TLS 1.2 Cipher Prefix' : 'Standard Client TLS Socket API')}
              {pqcEv?.confidence ? ` (Confidence: ${pqcEv.confidence})` : ''}
            </span>
          </div>
          <div className="lg:col-span-2 pt-1 border-t border-slate-800/60">
            <span className="text-slate-500 block text-[10px] uppercase">Capability Probe Result</span>
            <span className="text-slate-300 block">
              {pqcEv?.probe_attempted
                ? `Active Probe: ${pqcEv.probe_result || 'Executed'} (Offered: ${pqcEv.requested_group || 'X25519MLKEM768'})`
                : 'Passive Observation (Client default handshake)'}
            </span>
          </div>
        </div>

        {/* Observability Honesty Banner */}
        <div className="mt-2 p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/80 text-[11px] text-slate-400 space-y-1">
          <div className="flex items-center space-x-1.5 text-slate-300 font-semibold">
            <Radio className="w-3 h-3 text-cyan-400" />
            <span>Cryptographic Observability Guarantee:</span>
          </div>
          <p>
            {pqcEv?.details ||
              (pqcEv?.is_hybrid
                ? 'Server natively negotiated hybrid post-quantum key agreement without requiring capability forcing.'
                : tls.key_exchange_evidence === 'CLASSICAL_ONLY_OBSERVED'
                ? 'Server negotiated a classical curve by default. Note: This does not prove the server has zero PQC support on other groups.'
                : tls.key_exchange_evidence === 'PROBED_UNSUPPORTED'
                ? 'Active capability probe offering X25519MLKEM768 was rejected by the server (handshake failure). Server operates classical key exchange.'
                : 'TLS 1.3 KeyShare negotiation is decoupled from cipher suites; external client TLS APIs cannot expose the negotiated group.')}
          </p>
        </div>
      </div>

      {/* Expanded Certificate Details Card */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-xs space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-slate-800">
          <span className="font-semibold text-slate-300 flex items-center space-x-1.5">
            <Key className="w-3.5 h-3.5 text-cyan-400" />
            <span>X.509 Certificate Metadata (Observed from Leaf Certificate)</span>
          </span>
          <div className="flex items-center space-x-2">
            {certificate.is_trusted ? (
              <span className="flex items-center space-x-1 text-[11px] font-mono text-emerald-400">
                <CheckCircle className="w-3 h-3" />
                <span>Trusted CA</span>
              </span>
            ) : (
              <span className="flex items-center space-x-1 text-[11px] font-mono text-rose-400">
                <AlertTriangle className="w-3 h-3" />
                <span>Untrusted</span>
              </span>
            )}
            <span className="font-mono text-[11px] text-slate-500">|</span>
            <span className="font-mono text-[11px] text-slate-400">
              Chain: {certificate.chain_length} cert(s)
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 text-slate-300 font-mono">
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">Subject CN</span>
            <span className="text-white truncate block">{certificate.subject_cn || target.domain}</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">Issuer CN</span>
            <span className="text-white truncate block">{certificate.issuer_cn || 'Standard CA'}</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">Signature Algorithm</span>
            <span className="text-white truncate block">{certificate.signature_algorithm}</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">Validity Remaining</span>
            <span className={`block ${certificate.is_expired ? 'text-rose-400' : 'text-slate-200'}`}>
              {certificate.is_expired ? 'Expired' : `${certificate.days_remaining} days`}
            </span>
          </div>
          <div className="lg:col-span-4 pt-1">
            <span className="text-slate-500 block text-[10px] uppercase">SHA-256 Fingerprint</span>
            <span className="text-cyan-300 text-[11px] break-all select-all font-mono">{certificate.fingerprint_sha256}</span>
          </div>
        </div>
      </div>
    </div>
  );
};
