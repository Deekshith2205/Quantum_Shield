import React, { useState } from 'react';
import type {
  BankingAsset,
  EvidenceItem,
  EvidenceGap,
  BankingRiskAssessment,
  AuditVerificationResult,
} from '../types/scan';

import {
  getBankingSystemJsonReport,
  getBankingSystemPdfReport,
  verifyAuditRecord,
} from '../services/api';

import {
  Landmark,
  ShieldAlert,
  AlertTriangle,
  ArrowRight,
  ChevronDown,
  ChevronUp,
  Cpu,
  Lock,
  Database,
  Info,
  Sliders,
  FileJson,
  FileText,
  ShieldCheck,
} from 'lucide-react';

interface BankingSystemCardProps {
  profile: BankingAsset;
  risk?: BankingRiskAssessment;
  onAuditWithScan?: (profileId: string) => void;
  onSimulate?: (profileId: string) => void;
  isDetailedView?: boolean;
}

export const BankingSystemCard: React.FC<BankingSystemCardProps> = ({
  profile,
  risk,
  onAuditWithScan,
  onSimulate,
  isDetailedView = false,
}) => {
  const [activeTab, setActiveTab] = useState<
    'crypto' | 'risk' | 'evidence' | 'gaps'
  >(risk ? 'risk' : 'crypto');

  const [expanded, setExpanded] = useState<boolean>(isDetailedView);

  const [reportBusy, setReportBusy] = useState<
    'json' | 'pdf' | 'audit' | null
  >(null);

  const [auditResult, setAuditResult] =
    useState<AuditVerificationResult | null>(null);

  const [reportActionError, setReportActionError] =
    useState<string | null>(null);

  // ==========================================================================
  // BADGE HELPERS
  // ==========================================================================

  const getPriorityBadge = (priority: string) => {
    switch (priority) {
      case 'P0':
        return 'bg-red-50 text-red-700 border-red-200';
      case 'P1':
        return 'bg-amber-50 text-amber-800 border-amber-200';
      case 'P2':
        return 'bg-indigo-50 text-indigo-700 border-indigo-200';
      case 'P3':
        return 'bg-emerald-50 text-emerald-800 border-emerald-200';
      default:
        return 'bg-slate-100 text-slate-700 border-slate-200';
    }
  };

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

  const getSourceBadge = (source: string) => {
    switch (source) {
      case 'EXTERNAL_SCAN':
        return 'bg-emerald-50 text-emerald-700 border-emerald-200';
      case 'CONFIGURATION_FILE':
        return 'bg-indigo-50 text-indigo-700 border-indigo-200';
      case 'OPERATOR_DECLARED':
        return 'bg-amber-50 text-amber-800 border-amber-200';
      case 'INFERRED':
        return 'bg-purple-50 text-purple-700 border-purple-200';
      default:
        return 'bg-slate-100 text-slate-700 border-slate-200';
    }
  };

  const getLayerBadge = (layer?: string) => {
    switch (layer) {
      case 'EDGE':
        return 'bg-sky-50 text-sky-700 border-sky-200';
      case 'API_GATEWAY':
        return 'bg-blue-50 text-blue-700 border-blue-200';
      case 'SERVICE_TO_SERVICE':
        return 'bg-indigo-50 text-indigo-700 border-indigo-200';
      case 'DATA_AND_KEYS':
        return 'bg-amber-50 text-amber-800 border-amber-200';
      case 'ADMINISTRATIVE':
        return 'bg-rose-50 text-rose-700 border-rose-200';
      default:
        return 'bg-slate-100 text-slate-700 border-slate-200';
    }
  };

  // ==========================================================================
  // PROFILE DATA
  // ==========================================================================

  const crypto = profile.cryptography;
  const keyChain = crypto?.key_chain;

  const evidenceItems: EvidenceItem[] =
    profile.evidence_items || [];

  const evidenceGaps: EvidenceGap[] =
    profile.evidence_gaps || [];

  // ==========================================================================
  // TASK 5: COMPREHENSIVE JSON REPORT DOWNLOAD
  // ==========================================================================

  const handleDownloadJson = async () => {
    setReportBusy('json');
    setReportActionError(null);

    try {
      const report = await getBankingSystemJsonReport(profile.id);

      const blob = new Blob(
        [JSON.stringify(report, null, 2)],
        { type: 'application/json' }
      );

      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');

      link.href = url;
      link.download = `quantumshield-report-${profile.id}.json`;

      document.body.appendChild(link);
      link.click();
      link.remove();

      URL.revokeObjectURL(url);
    } catch (error) {
      setReportActionError(
        error instanceof Error
          ? error.message
          : 'JSON report download failed.'
      );
    } finally {
      setReportBusy(null);
    }
  };

  // ==========================================================================
  // TASK 5: COMPREHENSIVE PDF REPORT DOWNLOAD
  // ==========================================================================

  const handleDownloadPdf = async () => {
    setReportBusy('pdf');
    setReportActionError(null);

    try {
      const blob = await getBankingSystemPdfReport(profile.id);

      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');

      link.href = url;
      link.download = `quantumshield-report-${profile.id}.pdf`;

      document.body.appendChild(link);
      link.click();
      link.remove();

      URL.revokeObjectURL(url);
    } catch (error) {
      setReportActionError(
        error instanceof Error
          ? error.message
          : 'PDF report download failed.'
      );
    } finally {
      setReportBusy(null);
    }
  };

  // ==========================================================================
  // TASK 5: CRYPTOGRAPHIC AUDIT VERIFICATION
  // ==========================================================================

  const handleVerifyAudit = async () => {
    setReportBusy('audit');
    setReportActionError(null);
    setAuditResult(null);

    try {
      const report = await getBankingSystemJsonReport(profile.id);

      const result = await verifyAuditRecord(report.audit);

      setAuditResult(result);
    } catch (error) {
      setReportActionError(
        error instanceof Error
          ? error.message
          : 'Audit verification failed.'
      );
    } finally {
      setReportBusy(null);
    }
  };

  // ==========================================================================
  // COMPONENT RENDER
  // ==========================================================================

  return (
    <div className="rounded-2xl bg-white border border-slate-200/90 shadow-xs overflow-hidden transition-all duration-200 hover:border-slate-300">

      {/* ================================================================== */}
      {/* HEADER BAR */}
      {/* ================================================================== */}

      <div className="p-5 border-b border-slate-100">

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">

          {/* Banking System Identity */}
          <div className="flex items-start space-x-3.5">

            <div className="p-3 rounded-xl bg-indigo-50/80 border border-indigo-100 text-[#5755D9] shrink-0 mt-0.5">
              <Landmark className="w-5 h-5" />
            </div>

            <div>
              <div className="flex flex-wrap items-center gap-2">

                <h3 className="text-lg font-bold text-slate-900 tracking-tight">
                  {profile.name}
                </h3>

                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                  {profile.id}
                </span>

                <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-indigo-50 text-[#5755D9] border border-indigo-100 uppercase">
                  {(profile.system_type || profile.asset_type).replace(/_/g, ' ')}
                </span>

              </div>

              <p className="text-xs text-slate-500 mt-1 max-w-3xl leading-relaxed">
                {profile.description}
              </p>
            </div>

          </div>

          {/* Badges & Actions */}
          <div className="flex flex-wrap items-center gap-2.5 shrink-0">

            {risk && (
              <span
                className={`text-xs font-mono font-bold px-3 py-1 rounded-lg border uppercase tracking-wider ${getPriorityBadge(
                  risk.migration_priority
                )}`}
              >
                {risk.priority_band_label} · {risk.priority_score}/100
              </span>
            )}

            <span
              className={`text-xs font-mono font-bold px-3 py-1 rounded-lg border uppercase tracking-wider ${getCriticalityBadge(
                profile.criticality
              )}`}
            >
              {profile.criticality} CRITICALITY
            </span>

            {profile.migration_effort && (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                MIGRATION: {profile.migration_effort.replace(/_/g, ' ')}
              </span>
            )}

            {onAuditWithScan && (
              <button
                onClick={() => onAuditWithScan(profile.id)}
                className="inline-flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-[#18181B] hover:bg-black text-white text-xs font-semibold shadow-xs transition cursor-pointer"
              >
                <span>Audit with Live Scan</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            )}

            {onSimulate && (
              <button
                onClick={() => onSimulate(profile.id)}
                className="inline-flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-white border border-slate-300 text-slate-800 hover:border-[#5755D9] hover:text-[#5755D9] text-xs font-semibold shadow-xs transition cursor-pointer"
                title="Run What-If Migration Simulation for this system"
              >
                <Sliders className="w-3.5 h-3.5" />
                <span>What-If</span>
              </button>
            )}

            {/* Task 5: JSON Report Download */}
            <button
              onClick={handleDownloadJson}
              disabled={reportBusy !== null}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-white border border-slate-300 text-slate-700 hover:border-indigo-400 hover:text-indigo-700 text-xs font-semibold transition cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
              title="Download comprehensive JSON assessment report"
            >
              <FileJson className="w-3.5 h-3.5" />
              <span>
                {reportBusy === 'json' ? 'Preparing...' : 'JSON Report'}
              </span>
            </button>

            {/* Task 5: PDF Report Download */}
            <button
              onClick={handleDownloadPdf}
              disabled={reportBusy !== null}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-white border border-slate-300 text-slate-700 hover:border-indigo-400 hover:text-indigo-700 text-xs font-semibold transition cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
              title="Download comprehensive PDF assessment report"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>
                {reportBusy === 'pdf' ? 'Preparing...' : 'PDF Report'}
              </span>
            </button>

            {/* Task 5: Audit Verification */}
            <button
              onClick={handleVerifyAudit}
              disabled={reportBusy !== null}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-white border border-slate-300 text-slate-700 hover:border-emerald-400 hover:text-emerald-700 text-xs font-semibold transition cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
              title="Verify the report's cryptographic audit record"
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>
                {reportBusy === 'audit' ? 'Verifying...' : 'Verify Audit'}
              </span>
            </button>

            {!isDetailedView && (
              <button
                onClick={() => setExpanded(!expanded)}
                className="p-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-200 transition cursor-pointer"
                aria-label={
                  expanded
                    ? 'Collapse profile details'
                    : 'Expand profile details'
                }
              >
                {expanded ? (
                  <ChevronUp className="w-4 h-4" />
                ) : (
                  <ChevronDown className="w-4 h-4" />
                )}
              </button>
            )}

          </div>

        </div>

        {/* Task 5: Audit Verification Status */}
        {(auditResult || reportActionError) && (
          <div className="mt-3 space-y-2">

            {auditResult && (
              <div
                className={`flex items-center gap-2 text-xs font-semibold ${
                  auditResult.valid
                    ? 'text-emerald-700'
                    : 'text-red-700'
                }`}
                role="status"
              >
                {auditResult.valid ? (
                  <ShieldCheck className="w-4 h-4" />
                ) : (
                  <ShieldAlert className="w-4 h-4" />
                )}

                <span>
                  {auditResult.valid
                    ? 'Audit record verified'
                    : `Audit verification failed: ${
                        auditResult.error ||
                        'Integrity check unsuccessful'
                      }`}
                </span>
              </div>
            )}

            {reportActionError && (
              <p className="text-xs text-red-700" role="alert">
                {reportActionError}
              </p>
            )}

          </div>
        )}

      </div>

      {/* ================================================================== */}
      {/* EXPANDABLE PROFILE DETAILS */}
      {/* ================================================================== */}

      {expanded && (
        <div className="p-5 space-y-5">

          {/* ============================================================ */}
          {/* TAB NAVIGATION */}
          {/* ============================================================ */}

          <div className="flex flex-wrap gap-2 border-b border-slate-200 pb-3">

            {risk && (
              <button
                onClick={() => setActiveTab('risk')}
                className={`px-3 py-2 rounded-lg text-xs font-semibold transition ${
                  activeTab === 'risk'
                    ? 'bg-indigo-50 text-indigo-700 border border-indigo-200'
                    : 'bg-white text-slate-600 border border-slate-200 hover:border-indigo-300'
                }`}
              >
                Migration Risk
              </button>
            )}

            <button
              onClick={() => setActiveTab('crypto')}
              className={`px-3 py-2 rounded-lg text-xs font-semibold transition ${
                activeTab === 'crypto'
                  ? 'bg-indigo-50 text-indigo-700 border border-indigo-200'
                  : 'bg-white text-slate-600 border border-slate-200 hover:border-indigo-300'
              }`}
            >
              Cryptography
            </button>

            <button
              onClick={() => setActiveTab('evidence')}
              className={`px-3 py-2 rounded-lg text-xs font-semibold transition ${
                activeTab === 'evidence'
                  ? 'bg-indigo-50 text-indigo-700 border border-indigo-200'
                  : 'bg-white text-slate-600 border border-slate-200 hover:border-indigo-300'
              }`}
            >
              Evidence
            </button>

            <button
              onClick={() => setActiveTab('gaps')}
              className={`px-3 py-2 rounded-lg text-xs font-semibold transition ${
                activeTab === 'gaps'
                  ? 'bg-indigo-50 text-indigo-700 border border-indigo-200'
                  : 'bg-white text-slate-600 border border-slate-200 hover:border-indigo-300'
              }`}
            >
              Evidence Gaps
            </button>

          </div>

          {/* ============================================================ */}
          {/* TAB 0: MIGRATION RISK */}
          {/* ============================================================ */}

          {activeTab === 'risk' && risk && (
            <div className="space-y-4 animate-in fade-in duration-200">

              {/* Priority & Planning Banner */}
              <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-3">

                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">

                  <div>
                    <div className="flex items-center space-x-2">

                      <span
                        className={`text-xs font-mono font-bold px-3 py-1 rounded-lg border uppercase tracking-wider ${getPriorityBadge(
                          risk.migration_priority
                        )}`}
                      >
                        {risk.priority_band_label}
                      </span>

                      <span className="text-xs font-mono text-slate-600">
                        Planning Window:{' '}
                        <strong className="text-slate-900">
                          {risk.recommended_planning_window}
                        </strong>
                      </span>

                    </div>

                    <p className="text-xs text-slate-600 mt-2 leading-relaxed">
                      {risk.explanation}
                    </p>
                  </div>

                  <div className="text-right shrink-0 bg-slate-50 p-3 rounded-xl border border-slate-200 self-start sm:self-auto">
                    <div className="text-[10px] font-mono uppercase text-slate-500">
                      Priority Score
                    </div>

                    <div className="text-3xl font-black text-[#5755D9] font-mono leading-none mt-0.5">
                      {risk.priority_score}
                      <span className="text-xs text-slate-400 font-normal">
                        /100
                      </span>
                    </div>
                  </div>

                </div>

                {/* Weak Links */}
                {risk.key_protection?.weak_links &&
                  risk.key_protection.weak_links.length > 0 && (
                    <div className="p-3 rounded-lg bg-red-50 border border-red-200 flex items-start space-x-2">

                      <AlertTriangle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />

                      <div className="text-xs space-y-1">

                        <span className="font-bold text-red-900">
                          Identified Key-Chain Weak Links:
                        </span>

                        <div className="flex flex-wrap gap-1.5 mt-1">
                          {risk.key_protection.weak_links.map(
                            (link, idx) => (
                              <span
                                key={idx}
                                className="text-[10px] font-mono px-2 py-0.5 rounded bg-white text-red-700 border border-red-200"
                              >
                                {link}
                              </span>
                            )
                          )}
                        </div>

                      </div>
                    </div>
                  )}

              </div>

              {/* 6-Dimension Contributor Breakdown */}
              {risk.contributors &&
                risk.contributors.length > 0 && (
                  <div className="space-y-2">

                    <div className="flex items-center justify-between text-xs text-slate-500">
                      <span className="font-semibold text-slate-800">
                        Risk & Business Factor Contributors
                      </span>

                      <span className="font-mono text-[10px]">
                        Deterministic Multi-Dimensional Weighting
                      </span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">

                      {risk.contributors.map((contrib, idx) => (
                        <div
                          key={idx}
                          className="p-3 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1.5"
                        >

                          <div className="flex items-center justify-between text-xs">
                            <span className="text-slate-700 text-[11px] font-medium">
                              {contrib.factor}
                            </span>

                            <span className="font-mono text-xs font-bold text-[#5755D9]">
                              {contrib.label}
                            </span>
                          </div>

                          <div className="w-full h-1.5 bg-slate-100 rounded-full overflow-hidden border border-slate-200">
                            <div
                              className="h-full bg-[#5755D9] rounded-full transition-all duration-300"
                              style={{
                                width: `${Math.max(12, contrib.weight_pct)}%`,
                              }}
                            />
                          </div>

                          {contrib.description && (
                            <p
                              className="text-[10px] text-slate-500 truncate"
                              title={contrib.description}
                            >
                              {contrib.description}
                            </p>
                          )}

                        </div>
                      ))}

                    </div>
                  </div>
                )}

            </div>
          )}

          {/* ============================================================ */}
          {/* TAB 1: KEY CHAIN & CRYPTOGRAPHY */}
          {/* ============================================================ */}

          {activeTab === 'crypto' && (
            <div className="space-y-4 animate-in fade-in duration-200">

              {/* AES-256 Grover Resilience Callout */}
              <div className="p-3.5 rounded-xl bg-indigo-50/60 border border-indigo-100 text-xs flex items-start space-x-3 text-slate-700">

                <Info className="w-4 h-4 text-[#5755D9] shrink-0 mt-0.5" />

                <div className="text-[11px] leading-relaxed">

                  <strong className="text-[#5755D9] font-semibold">
                    AES-256 Grover Resilience:
                  </strong>{' '}
                  AES-256 retains approximately 128-bit security against
                  an idealized Grover search and is not treated as a
                  quantum-broken primitive by QuantumShield.
                  Vulnerabilities in data-at-rest protection stem from
                  asymmetric key wrapping (RSA-2048/4096, ECDH) and
                  root authentication signatures protecting keys, rather
                  than AES-256 bulk payload encryption itself.

                </div>
              </div>

              {/* Key Protection Chain */}
              {keyChain && (
                <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs">

                  <div className="flex items-center justify-between mb-3">

                    <span className="text-xs font-bold text-slate-900 tracking-wide flex items-center space-x-2">
                      <Lock className="w-4 h-4 text-[#5755D9]" />
                      <span>Key Protection Chain Hierarchy</span>
                    </span>

                    <span className="text-[10px] font-mono text-[#5755D9]">
                      Data At-Rest &rarr; KEK &rarr; Master Key &rarr; Root Authentication
                    </span>

                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-4 gap-3">

                    <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                      <span className="text-[10px] font-mono uppercase text-slate-500 block mb-1">
                        1. Data Encryption
                      </span>

                      <div className="font-mono text-xs font-bold text-emerald-700">
                        {keyChain.data_encryption || 'None / Not Observable'}
                      </div>

                      <span className="text-[10px] text-slate-500 mt-1 block">
                        Bulk Data Payload (AES/GCM)
                      </span>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                      <span className="text-[10px] font-mono uppercase text-slate-500 block mb-1">
                        2. Key Wrapping
                      </span>

                      <div className="font-mono text-xs font-bold text-indigo-700">
                        {keyChain.key_wrapping || 'None / Direct'}
                      </div>

                      <span className="text-[10px] text-slate-500 mt-1 block">
                        Key Encapsulation / KEK
                      </span>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                      <span className="text-[10px] font-mono uppercase text-slate-500 block mb-1">
                        3. Key Storage
                      </span>

                      <div className="font-mono text-xs font-bold text-amber-700">
                        {keyChain.key_storage || 'Local / Plaintext'}
                      </div>

                      <span className="text-[10px] text-slate-500 mt-1 block">
                        Hardware Module or KMS
                      </span>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                      <span className="text-[10px] font-mono uppercase text-slate-500 block mb-1">
                        4. Authentication
                      </span>

                      <div className="font-mono text-xs font-bold text-violet-700">
                        {keyChain.authentication || 'Standard Signature'}
                      </div>

                      <span className="text-[10px] text-slate-500 mt-1 block">
                        Master Identity / Signature
                      </span>
                    </div>

                  </div>
                </div>
              )}

              {/* Cryptography Parameters */}
              {crypto && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">

                  {/* Perimeter Transport Cryptography */}
                  <div className="p-3.5 rounded-xl bg-white border border-slate-200 shadow-xs space-y-2">

                    <h4 className="font-semibold text-slate-900 text-xs flex items-center space-x-1.5">
                      <Cpu className="w-3.5 h-3.5 text-[#5755D9]" />
                      <span>Perimeter Transport Cryptography</span>
                    </h4>

                    <div className="space-y-1.5 text-[11px] font-mono">

                      <div className="flex justify-between py-1 border-b border-slate-100">
                        <span className="text-slate-500">TLS Versions:</span>
                        <span className="text-slate-900">
                          {crypto.tls_versions?.join(', ') || 'N/A'}
                        </span>
                      </div>

                      <div className="flex justify-between py-1 border-b border-slate-100">
                        <span className="text-slate-500">Key Exchange / Group:</span>
                        <span className="text-[#5755D9] font-bold">
                          {crypto.key_exchange || 'TLS 1.2 ECDHE'}
                        </span>
                      </div>

                      <div className="flex justify-between py-1 border-b border-slate-100">
                        <span className="text-slate-500">Leaf Certificate:</span>
                        <span className="text-slate-800 truncate max-w-[240px]">
                          {crypto.certificates?.[0] || 'Standard X.509'}
                        </span>
                      </div>

                      <div className="flex justify-between py-1">
                        <span className="text-slate-500">Signature Algorithm:</span>
                        <span className="text-slate-800">
                          {crypto.signature_algorithm || 'SHA-256 with RSA'}
                        </span>
                      </div>

                    </div>
                  </div>

                  {/* Data Protection & Key Appliance */}
                  <div className="p-3.5 rounded-xl bg-white border border-slate-200 shadow-xs space-y-2">

                    <h4 className="font-semibold text-slate-900 text-xs flex items-center space-x-1.5">
                      <Database className="w-3.5 h-3.5 text-indigo-600" />
                      <span>Data Protection & Key Appliance</span>
                    </h4>

                    <div className="space-y-1.5 text-[11px] font-mono">

                      <div className="flex justify-between py-1 border-b border-slate-100">
                        <span className="text-slate-500">Data At-Rest Algorithm:</span>
                        <span className="text-emerald-700 font-bold">
                          {crypto.data_encryption_algorithm || 'AES-256'}
                        </span>
                      </div>

                      <div className="flex justify-between py-1 border-b border-slate-100">
                        <span className="text-slate-500">Key Wrapping Algorithm:</span>
                        <span className="text-indigo-700 font-bold">
                          {crypto.key_wrapping_algorithm || 'N/A'}
                        </span>
                      </div>

                      <div className="flex justify-between py-1 border-b border-slate-100">
                        <span className="text-slate-500">Storage Facility:</span>
                        <span className="text-amber-700 font-bold">
                          {crypto.key_storage || 'Local Key Store'}
                        </span>
                      </div>

                      <div className="flex justify-between py-1">
                        <span className="text-slate-500">Appliance Model / Cloud KMS:</span>
                        <span className="text-slate-800 truncate max-w-[240px]">
                          {crypto.kms_or_hsm || 'Not Configured'}
                        </span>
                      </div>

                    </div>
                  </div>

                </div>
              )}

            </div>
          )}

          {/* ============================================================ */}
          {/* TAB 2: CONFIGURATION EVIDENCE ITEMS */}
          {/* ============================================================ */}

          {activeTab === 'evidence' && (
            <div className="space-y-3 animate-in fade-in duration-200">

              <div className="flex items-center justify-between text-xs text-slate-500 pb-1">
                <span>
                  Normalized Multi-Layer Security Architecture Controls
                </span>

                <span className="font-mono text-[10px]">
                  Explicit Origin Tracking
                </span>
              </div>

              <div className="space-y-2">

                {evidenceItems.map((item) => (
                  <div
                    key={item.id}
                    className="p-3.5 rounded-xl bg-white border border-slate-200 shadow-xs hover:border-slate-300 transition"
                  >

                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-1.5">

                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-xs text-slate-900">
                          {item.control}
                        </span>

                        <span className="text-[10px] font-mono text-slate-500">
                          [{item.id}]
                        </span>
                      </div>

                      <div className="flex flex-wrap items-center gap-1.5">

                        {item.layer && (
                          <span
                            className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded border ${getLayerBadge(
                              item.layer
                            )}`}
                          >
                            {item.layer}
                          </span>
                        )}

                        <span
                          className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded border ${getSourceBadge(
                            item.source
                          )}`}
                        >
                          {item.source}
                        </span>

                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                          {item.observability}
                        </span>

                      </div>
                    </div>

                    <div className="font-mono text-xs text-[#5755D9] font-semibold mb-1">
                      {item.value}
                    </div>

                    {item.description && (
                      <p className="text-[11px] text-slate-600 leading-relaxed">
                        {item.description}
                      </p>
                    )}

                  </div>
                ))}

                {evidenceItems.length === 0 && (
                  <p className="text-xs text-slate-500 p-4 rounded-lg bg-slate-50 border border-slate-200">
                    No configuration evidence items are available for this system.
                  </p>
                )}

              </div>
            </div>
          )}

          {/* ============================================================ */}
          {/* TAB 3: EVIDENCE GAPS */}
          {/* ============================================================ */}

          {activeTab === 'gaps' && (
            <div className="space-y-3 animate-in fade-in duration-200">

              {/* Core Invariant Banner */}
              <div className="p-3.5 rounded-xl bg-amber-50 border border-amber-200 text-amber-900 text-xs flex items-start space-x-3">

                <Info className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />

                <div className="space-y-1">

                  <div className="font-bold text-amber-950 tracking-wide">
                    AUDIT INVARIANT: NOT_OBSERVABLE ≠ VULNERABLE
                  </div>

                  <p className="text-[11px] text-amber-900 leading-relaxed">
                    Internal banking controls (e.g., service mesh mTLS,
                    HSM physical tamper sensors, KMS key rotation) reside
                    entirely inside private VPCs or secure hardware
                    coprocessors. They cannot be observed through external
                    perimeter scans alone. Missing evidence is categorized
                    as an{' '}
                    <strong>
                      observability gap
                    </strong>{' '}
                    requiring internal audit manifests, not a failed control.
                  </p>

                </div>
              </div>

              <div className="space-y-2">

                {evidenceGaps.map((gap, idx) => (
                  <div
                    key={idx}
                    className="p-3.5 rounded-xl bg-white border border-slate-200 shadow-xs hover:border-slate-300 transition"
                  >

                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">

                      <div className="flex items-center space-x-2">

                        <span className="font-bold text-xs text-slate-900">
                          {gap.control}
                        </span>

                        <span className="text-[10px] font-mono text-amber-800 bg-amber-50 border border-amber-200 px-2 py-0.5 rounded">
                          {gap.gap_type}
                        </span>

                      </div>

                      <span
                        className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded border self-start sm:self-auto ${getLayerBadge(
                          gap.layer
                        )}`}
                      >
                        {gap.layer}
                      </span>

                    </div>

                    <p className="text-[11px] text-slate-600 mb-2 leading-relaxed">
                      {gap.description}
                    </p>

                    <div className="p-2 rounded-lg bg-slate-50 border border-slate-200 text-[11px] font-mono flex items-start space-x-2">

                      <span className="text-[#5755D9] font-bold shrink-0">
                        Telemetry Needed:
                      </span>

                      <span className="text-slate-700">
                        {gap.evidence_needed}
                      </span>

                    </div>

                  </div>
                ))}

                {evidenceGaps.length === 0 && (
                  <p className="text-xs text-slate-500 p-4 rounded-lg bg-slate-50 border border-slate-200">
                    No evidence gaps are currently listed for this system.
                  </p>
                )}

              </div>
            </div>
          )}

        </div>
      )}

    </div>
  );
};
