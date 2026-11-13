
import React, { useState } from 'react';
import type {
  ArtifactFindingsResponse,
  NormalizedFinding,
  UploadedCertificateResponse,
} from '../types/scan';
import {
  scanUploadedConfig,
  scanUploadedCode,
  scanUploadedCertificate,
} from '../services/api';
import {
  AlertCircle,
  CheckCircle2,
  FileCode2,
  FileKey2,
  FileText,
  Loader2,
  ShieldCheck,
  Upload,
} from 'lucide-react';

type UploadMode = 'config' | 'code' | 'certificate';

const uploadModes: {
  id: UploadMode;
  label: string;
  description: string;
  icon: React.ElementType;
}[] = [
  {
    id: 'config',
    label: 'Configuration',
    description: 'Inspect configuration files for cryptographic settings.',
    icon: FileText,
  },
  {
    id: 'code',
    label: 'Source Code',
    description: 'Statically inspect source code for cryptographic misuse.',
    icon: FileCode2,
  },
  {
    id: 'certificate',
    label: 'Certificate',
    description: 'Parse an uploaded PEM certificate offline.',
    icon: FileKey2,
  },
];

const acceptedExtensions: Record<UploadMode, string | undefined> = {
  config: undefined,
  code: '.py,.java,.js,.jsx,.ts,.tsx,.mjs,.cjs,.php,.phtml',
  certificate: '.pem,.crt,.cer',
};

const severityClass = (severity: string): string => {
  switch (severity.toUpperCase()) {
    case 'CRITICAL':
      return 'bg-red-50 text-red-700 border-red-200';
    case 'HIGH':
      return 'bg-orange-50 text-orange-800 border-orange-200';
    case 'MEDIUM':
      return 'bg-amber-50 text-amber-800 border-amber-200';
    case 'LOW':
      return 'bg-emerald-50 text-emerald-800 border-emerald-200';
    default:
      return 'bg-slate-100 text-slate-700 border-slate-200';
  }
};

const evidenceClass = (status: string): string => {
  switch (status.toUpperCase()) {
    case 'OBSERVED':
      return 'bg-emerald-50 text-emerald-700 border-emerald-200';
    case 'INFERRED':
      return 'bg-amber-50 text-amber-800 border-amber-200';
    default:
      return 'bg-slate-100 text-slate-600 border-slate-200';
  }
};

const formatLabel = (value: string | null | undefined): string => {
  if (!value) return 'Not available';
  return value.replace(/_/g, ' ');
};

const FindingCard: React.FC<{
  finding: NormalizedFinding;
}> = ({ finding }) => (
  <article className="rounded-xl border border-slate-200 bg-white p-4 space-y-3">
    <div className="flex flex-wrap items-start justify-between gap-2">
      <div className="min-w-0">
        <h4 className="text-sm font-semibold text-slate-900">
          {finding.title}
        </h4>
        <p className="text-xs text-slate-500 font-mono mt-1">
          {finding.rule_id}
        </p>
      </div>

      <div className="flex flex-wrap gap-1.5">
        <span
          className={`px-2 py-1 rounded-md border text-[10px] font-mono font-bold ${severityClass(finding.severity)}`}
        >
          {finding.severity}
        </span>
        <span
          className={`px-2 py-1 rounded-md border text-[10px] font-mono font-bold ${evidenceClass(finding.evidence_status)}`}
        >
          {finding.evidence_status}
        </span>
      </div>
    </div>

    <p className="text-sm text-slate-700 break-words">
      {finding.message}
    </p>

    {finding.value && (
      <div className="rounded-lg bg-slate-50 border border-slate-100 p-3">
        <p className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1">
          Detected value
        </p>
        <p className="text-xs text-slate-800 font-mono break-all">
          {finding.value}
        </p>
      </div>
    )}

    <div className="text-xs text-slate-600 space-y-1">
      <p>
        <span className="font-semibold">Risk:</span>{' '}
        {formatLabel(finding.risk)}
      </p>
      <p>
        <span className="font-semibold">Role:</span>{' '}
        {formatLabel(finding.role)}
      </p>
      {finding.source_file && (
        <p className="break-all">
          <span className="font-semibold">File:</span>{' '}
          {finding.source_file}
          {finding.source_line != null && `:${finding.source_line}`}
        </p>
      )}
    </div>

    {finding.recommendation && (
      <div className="border-t border-slate-100 pt-3">
        <p className="text-[10px] uppercase tracking-wider text-[#5755D9] font-semibold mb-1">
          Recommendation
        </p>
        <p className="text-xs text-slate-700 leading-relaxed">
          {finding.recommendation}
        </p>
      </div>
    )}
  </article>
);

const CertificateResult: React.FC<{
  result: UploadedCertificateResponse;
}> = ({ result }) => {
  const certificate = result.certificate;

  const details: { label: string; value: string }[] = [
    { label: 'Subject', value: certificate.subject_cn || 'Not available' },
    { label: 'Organization', value: certificate.subject_org || 'Not available' },
    { label: 'Issuer', value: certificate.issuer_cn || 'Not available' },
    {
      label: 'Public key algorithm',
      value: certificate.public_key_algorithm,
    },
    {
      label: 'Key size',
      value: certificate.key_size_bits != null
        ? `${certificate.key_size_bits} bits`
        : 'Not available',
    },
    { label: 'Curve', value: certificate.curve_name || 'Not available' },
    { label: 'Signature algorithm', value: certificate.signature_algorithm },
    {
      label: 'Signature hash',
      value: certificate.signature_hash_algorithm || 'Not available',
    },
    { label: 'Valid from', value: certificate.not_valid_before },
    { label: 'Valid until', value: certificate.not_valid_after },
    { label: 'Days remaining', value: String(certificate.days_remaining) },
    {
      label: 'SHA-256 fingerprint',
      value: certificate.fingerprint_sha256,
    },
  ];

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 space-y-4">
      <div className="flex items-center gap-2">
        <ShieldCheck className="w-5 h-5 text-emerald-600" />
        <div>
          <h3 className="text-sm font-semibold text-slate-900">
            Certificate parsed successfully
          </h3>
          <p className="text-xs text-slate-500 break-all">
            {result.source_file}
          </p>
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        <span className="px-2.5 py-1 rounded-md bg-emerald-50 border border-emerald-200 text-emerald-700 text-[10px] font-mono font-bold">
          {result.evidence_status}
        </span>
        <span
          className={`px-2.5 py-1 rounded-md border text-[10px] font-mono font-bold ${
            certificate.is_expired
              ? 'bg-red-50 border-red-200 text-red-700'
              : 'bg-emerald-50 border-emerald-200 text-emerald-700'
          }`}
        >
          {certificate.is_expired ? 'EXPIRED' : 'NOT EXPIRED'}
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {details.map((detail) => (
          <div
            key={detail.label}
            className="rounded-lg bg-slate-50 border border-slate-100 p-3 min-w-0"
          >
            <p className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1">
              {detail.label}
            </p>
            <p className="text-xs text-slate-800 break-all">
              {detail.value}
            </p>
          </div>
        ))}
      </div>

      {certificate.subject_alt_names.length > 0 && (
        <div>
          <p className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-2">
            Subject alternative names
          </p>
          <div className="flex flex-wrap gap-2">
            {certificate.subject_alt_names.map((name, index) => (
              <span
                key={`${name}-${index}`}
                className="px-2 py-1 rounded-md bg-slate-100 text-slate-700 text-xs break-all"
              >
                {name}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export const ArtifactUploadPanel: React.FC = () => {
  const [mode, setMode] = useState<UploadMode>('config');
  const [files, setFiles] = useState<File[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [findingsResult, setFindingsResult] =
    useState<ArtifactFindingsResponse | null>(null);
  const [certificateResult, setCertificateResult] =
    useState<UploadedCertificateResponse | null>(null);

  const resetResults = () => {
    setError(null);
    setFindingsResult(null);
    setCertificateResult(null);
  };

  const handleModeChange = (nextMode: UploadMode) => {
    setMode(nextMode);
    setFiles([]);
    resetResults();
  };

  const handleFileChange = (
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    const selectedFiles = Array.from(event.target.files || []);
    setFiles(selectedFiles);
    resetResults();
  };

  const handleScan = async () => {
    if (files.length === 0) {
      setError('Please select at least one file.');
      return;
    }

    if (mode === 'certificate' && files.length !== 1) {
      setError('Select exactly one certificate file.');
      return;
    }

    setIsLoading(true);
    resetResults();

    try {
      if (mode === 'config') {
        const result = await scanUploadedConfig(files);
        setFindingsResult(result);
      } else if (mode === 'code') {
        const result = await scanUploadedCode(files);
        setFindingsResult(result);
      } else {
        const result = await scanUploadedCertificate(files[0]);
        setCertificateResult(result);
      }
    } catch (err: unknown) {
      setError(
        err instanceof Error
          ? err.message
          : 'The uploaded files could not be scanned.'
      );
    } finally {
      setIsLoading(false);
    }
  };

  const activeMode = uploadModes.find((item) => item.id === mode)!;
  const ActiveIcon = activeMode.icon;

  return (
    <section className="max-w-7xl mx-auto space-y-5">
      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono uppercase tracking-widest text-[#5755D9] font-semibold">
            LOCAL ARTIFACT ANALYSIS
          </span>
          <span className="text-slate-300">/</span>
          <span className="text-xs font-mono text-slate-500">
            Upload & Scan
          </span>
        </div>

        <h2 className="text-2xl sm:text-3xl font-light text-[#17181C] tracking-tight">
          Analyze Your Cryptographic Artifacts
        </h2>

        <p className="text-sm text-[#62656D] max-w-3xl leading-relaxed">
          Upload configuration files, source code, or PEM certificates
          for focused cryptographic analysis. Uploaded source code is
          statically inspected and is never executed.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {uploadModes.map((item) => {
          const Icon = item.icon;
          const isActive = mode === item.id;

          return (
            <button
              key={item.id}
              type="button"
              onClick={() => handleModeChange(item.id)}
              disabled={isLoading}
              aria-pressed={isActive}
              className={`text-left rounded-xl border p-4 transition ${
                isActive
                  ? 'border-[#5755D9] bg-indigo-50/60 shadow-sm'
                  : 'border-slate-200 bg-white hover:border-indigo-200'
              } disabled:opacity-60`}
            >
              <div className="flex items-center gap-2 mb-2">
                <Icon
                  className={`w-5 h-5 ${
                    isActive ? 'text-[#5755D9]' : 'text-slate-500'
                  }`}
                />
                <span className="text-sm font-semibold text-slate-900">
                  {item.label}
                </span>
              </div>
              <p className="text-xs text-slate-500 leading-relaxed">
                {item.description}
              </p>
            </button>
          );
        })}
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white p-5 sm:p-6 space-y-5">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-indigo-50 flex items-center justify-center">
            <ActiveIcon className="w-5 h-5 text-[#5755D9]" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-slate-900">
              Upload {activeMode.label}
            </h3>
            <p className="text-xs text-slate-500">
              {mode === 'config'
                ? 'YAML, JSON, TOML, INI, properties, ENV, and XML files.'
                : mode === 'code'
                  ? 'Python, Java, JavaScript, TypeScript, PHP, and supported variants.'
                  : 'One PEM certificate in .pem, .crt, or .cer format.'}
            </p>
          </div>
        </div>

        <label
          htmlFor="artifact-upload-input"
          className="flex flex-col items-center justify-center rounded-xl border-2 border-dashed border-slate-300 bg-slate-50/70 hover:bg-indigo-50/40 hover:border-indigo-300 p-8 text-center cursor-pointer transition"
        >
          <Upload className="w-8 h-8 text-[#5755D9] mb-3" />
          <span className="text-sm font-semibold text-slate-800">
            Choose {mode === 'certificate' ? 'certificate' : 'file(s)'}
          </span>
          <span className="text-xs text-slate-500 mt-1">
            {mode === 'certificate'
              ? 'Select one certificate file'
              : 'Select between 1 and 20 files'}
          </span>
          <input
            key={mode}
            id="artifact-upload-input"
            type="file"
            className="sr-only"
            accept={acceptedExtensions[mode]}
            multiple={mode !== 'certificate'}
            disabled={isLoading}
            onChange={handleFileChange}
          />
        </label>

        {files.length > 0 && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <p className="text-xs font-semibold text-slate-700">
                Selected files ({files.length})
              </p>
              <button
                type="button"
                onClick={() => {
                  setFiles([]);
                  resetResults();
                }}
                disabled={isLoading}
                className="text-xs text-rose-600 hover:text-rose-700 font-medium disabled:opacity-50"
              >
                Clear selection
              </button>
            </div>

            <div className="space-y-1.5">
              {files.map((file, index) => (
                <div
                  key={`${file.name}-${index}`}
                  className="flex items-center justify-between gap-3 rounded-lg bg-slate-50 border border-slate-100 px-3 py-2"
                >
                  <span className="text-xs text-slate-700 truncate">
                    {file.name}
                  </span>
                  <span className="text-[10px] text-slate-500 font-mono shrink-0">
                    {(file.size / 1024).toFixed(1)} KB
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="rounded-lg bg-slate-50 border border-slate-100 p-3">
          <p className="text-[11px] text-slate-600 leading-relaxed">
            <strong>Upload limits:</strong> Maximum 1 MiB per file.
            Configuration and source-code uploads allow up to 20 files
            and 5 MiB combined. Certificate uploads allow one file.
          </p>
          <p className="text-[11px] text-slate-500 leading-relaxed mt-1">
            Analysis uses the existing backend scanners. No uploaded
            source code is executed, and certificate parsing does not
            contact external systems.
          </p>
        </div>

        {error && (
          <div
            role="alert"
            className="flex items-start gap-2 rounded-lg border border-rose-200 bg-rose-50 p-3 text-rose-800"
          >
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <p className="text-xs leading-relaxed">{error}</p>
          </div>
        )}

        <button
          type="button"
          onClick={handleScan}
          disabled={isLoading || files.length === 0}
          className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-lg bg-[#5755D9] hover:bg-[#4644C5] disabled:bg-slate-300 disabled:cursor-not-allowed text-white text-sm font-semibold px-6 py-3 transition"
        >
          {isLoading ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Analyzing artifacts...
            </>
          ) : (
            <>
              <ShieldCheck className="w-4 h-4" />
              Scan Uploaded {activeMode.label}
            </>
          )}
        </button>
      </div>

      {findingsResult && (
        <div className="space-y-4">
          <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-4 flex items-start gap-3">
            <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0" />
            <div>
              <h3 className="text-sm font-semibold text-emerald-900">
                Artifact scan completed
              </h3>
              <p className="text-xs text-emerald-800 mt-1">
                {findingsResult.files_scanned} file(s) scanned and{' '}
                {findingsResult.finding_count} finding(s) returned.
              </p>
            </div>
          </div>

          {findingsResult.findings.length === 0 ? (
            <div className="rounded-xl border border-slate-200 bg-white p-6 text-center">
              <CheckCircle2 className="w-7 h-7 text-emerald-600 mx-auto mb-2" />
              <p className="text-sm font-semibold text-slate-800">
                No findings returned
              </p>
              <p className="text-xs text-slate-500 mt-1">
                The scanner did not report any findings for these files.
                This does not establish that every cryptographic property
                is secure or observable.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              <h3 className="text-sm font-semibold text-slate-900">
                Scan Findings ({findingsResult.findings.length})
              </h3>
              {findingsResult.findings.map((finding, index) => (
                <FindingCard
                  key={`${finding.rule_id}-${finding.source_file || ''}-${index}`}
                  finding={finding}
                />
              ))}
            </div>
          )}
        </div>
      )}

      {certificateResult && (
        <CertificateResult result={certificateResult} />
      )}
    </section>
  );
};
