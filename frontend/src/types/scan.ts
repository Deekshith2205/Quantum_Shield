export type TargetInfo = {
  domain: string;
  port: number;
  resolved_ip: string;
  ip_version: string;
  scan_timestamp: string;
  connection_time_ms: number;
  all_resolved_ips?: string[];
};

export type CertificateSummary = {
  subject_cn?: string;
  issuer_cn?: string;
  public_key_algorithm: string;
  key_size_bits?: number;
  curve_name?: string;
  signature_algorithm: string;
  fingerprint_sha256: string;
  not_valid_after: string;
};

export type CertificateInfo = {
  subject_cn?: string;
  subject_org?: string;
  subject_alt_names: string[];
  issuer_cn?: string;
  issuer_org?: string;
  serial_number: string;
  fingerprint_sha256: string;
  not_valid_before: string;
  not_valid_after: string;
  days_remaining: number;
  is_expired: boolean;
  public_key_algorithm: string;
  key_size_bits?: number;
  curve_name?: string;
  signature_algorithm: string;
  signature_hash_algorithm?: string;
  chain_length: number;
  chain_certificates: CertificateSummary[];
  verification_status: string;
  is_trusted: boolean;
};

export type PqcKeyExchangeEvidence = {
  raw_group: string;
  status: 'OBSERVED' | 'CAPABILITY_PROBED' | 'CLASSICAL_ONLY_OBSERVED' | 'PROBED_UNSUPPORTED' | 'NOT_OBSERVABLE' | string;
  classical_component?: string;
  pqc_component?: string;
  is_hybrid: boolean;
  source: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' | string;
  probe_attempted: boolean;
  requested_group?: string;
  probe_result?: string;
  details?: string;
};

export type TlsInfo = {
  negotiated_protocol: string;
  negotiated_cipher: string;
  cipher_bits: number;
  alpn_protocol?: string;
  session_reused: boolean;
  key_exchange_value?: string;
  key_exchange_evidence?: 'OBSERVED' | 'CAPABILITY_PROBED' | 'CLASSICAL_ONLY_OBSERVED' | 'PROBED_UNSUPPORTED' | 'NOT_OBSERVABLE' | 'INFERRED' | string;
  key_exchange_inferred?: string;
  symmetric_encryption_inferred?: string;
  hash_mac_inferred?: string;
  pqc_evidence?: PqcKeyExchangeEvidence;
};

export type NormalizedCryptoMechanism = {
  role: string;
  value: string;
  source: string;
  evidence: 'OBSERVED' | 'INFERRED' | 'NOT_OBSERVABLE' | string;
  component: string;
  algorithm_family: string;
  algorithm_name: string;
  category: string;
  key_size?: number;
  curve?: string;
  observability: 'OBSERVED' | 'INFERRED' | 'NOT_OBSERVABLE' | string;
  evidence_source: string;
  raw_observed_value: string;
};

export type QuantumFinding = {
  id: string;
  title: string;
  role: string;
  value: string;
  source: string;
  evidence: 'OBSERVED' | 'INFERRED' | 'NOT_OBSERVABLE' | string;
  component: string;
  algorithm: string;
  category: string;
  quantum_threat: string;
  quantum_threat_vector: string;
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  security_impact: string;
  reason: string;
  recommendation: string;
  migration_target: string;
  priority: 'P0' | 'P1' | 'P2' | 'P3' | string;
  priority_score: number;
  observed_from: string;
  observability: string;
  target_pqc_standard?: string;
};

export type CategoryScoreBreakdown = {
  certificates: number;
  key_establishment: number;
  symmetric_encryption: number;
  hashing: number;
  tls_configuration: number;
};

export type ScoreBreakdownItem = {
  factor: string;
  impact: string;
  points: number;
  explanation: string;
};

export type QuantumScore = {
  score: number; // 0 = extremely poor, 100 = excellent readiness
  readiness_score: number;
  exposure_risk_score: number;
  grade: 'Excellent' | 'Good' | 'Moderate' | 'Needs Improvement' | 'Critical';
  summary: string;
  category_breakdown: CategoryScoreBreakdown;
  score_breakdown: ScoreBreakdownItem[];
  methodology_disclaimer: string;
  formula_description: string;
};

export type RoleCategoryAssessment = {
  category_id: string;
  category_name: string;
  status: 'EXCELLENT' | 'GOOD' | 'MODERATE' | 'HIGH RISK' | 'CRITICAL' | 'INFORMATIONAL' | string;
  readiness_score: number;
  weight_percentage: number;
  observed_value: string;
  evidence: 'OBSERVED' | 'INFERRED' | 'NOT_OBSERVABLE' | string;
  source: string;
  quantum_threat: string;
  migration_target: string;
  priority: 'P0' | 'P1' | 'P2' | 'P3' | string;
  recommended_action: string;
  findings: QuantumFinding[];
};

export type ExecutiveSummary = {
  domain: string;
  readiness_verdict: string;
  primary_concern: string;
  secondary_concern?: string;
  visibility_limitations: string;
  recommended_next_steps: string[];
  full_text: string;
};

export type MigrationStep = {
  priority: 'P0' | 'P1' | 'P2' | 'P3' | string;
  priority_rank: number;
  title: string;
  affected_component: string;
  current_mechanism: string;
  reason: string;
  recommended_target: string;
  migration_approach: string;
  evidence: 'OBSERVED' | 'INFERRED' | 'NOT_OBSERVABLE' | string;
  urgency: string;
  target_standards: string[];
  // Backwards compatibility
  risk_level?: string;
  why_it_matters?: string;
  recommended_action?: string;
  migration_urgency?: string;
  observability?: string;
};

export type ObservabilityScope = {
  observed_externally: string[];
  potentially_inferred: string[];
  not_externally_observable: string[];
};

export type BankingAssetType =
  // Phase 4A Systems
  | 'NET_BANKING_PORTAL'
  | 'MOBILE_BANKING_API'
  | 'PAYMENT_GATEWAY'
  | 'UPI_PAYMENT_SERVICE'
  | 'CARD_PROCESSING'
  | 'CORE_BANKING'
  | 'CUSTOMER_DATABASE'
  | 'PAYMENT_DATABASE'
  | 'INTER_BANK_GATEWAY'
  | 'ATM_NETWORK'
  | 'ADMIN_PORTAL'
  | 'AUTHENTICATION_SERVICE'
  | 'NOTIFICATION_SERVICE'
  | 'INTERNAL_SERVICE'
  | 'OTHER'
  // Legacy Phase 0 types
  | 'PUBLIC_WEBSITE'
  | 'WEB_BANKING'
  | 'MOBILE_API'
  | 'API_GATEWAY'
  | 'PAYMENT_SERVICE'
  | 'TRANSACTION_SERVICE'
  | 'ACCOUNT_SERVICE';

export type AssetCriticality = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type DataSensitivity = 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'HIGHLY_SENSITIVE';
export type AssetExposure = 'INTERNET' | 'PARTNER' | 'INTERNAL' | 'RESTRICTED';
export type DataLifetime = 'SHORT' | 'MEDIUM' | 'LONG' | 'VERY_LONG';
export type TrustZone = 'PUBLIC' | 'DMZ' | 'APPLICATION' | 'DATA' | 'ADMIN' | 'THIRD_PARTY';

export type SecurityLayer =
  | 'EDGE'
  | 'API_GATEWAY'
  | 'SERVICE_TO_SERVICE'
  | 'DATA_AND_KEYS'
  | 'ADMINISTRATIVE';

export type EvidenceSource =
  | 'EXTERNAL_SCAN'
  | 'OPERATOR_DECLARED'
  | 'CONFIGURATION_FILE'
  | 'INFERRED';

export type EvidenceGapType =
  | 'INTERNAL_MTLS'
  | 'HSM_USAGE'
  | 'KMS_USAGE'
  | 'KEY_ROTATION'
  | 'DATABASE_ENCRYPTION_AT_REST'
  | 'PRIVILEGED_ACCESS_POLICY'
  | 'MFA_POLICY'
  | 'SERVICE_IDENTITY'
  | 'LEAST_PRIVILEGE'
  | 'CONTINUOUS_VERIFICATION'
  | 'KEY_WRAPPING'
  | 'INTERNAL_CERTIFICATE_POLICY';

export type KeyProtectionChain = {
  data_encryption?: string;
  key_wrapping?: string;
  key_storage?: string;
  authentication?: string;
};

export type CryptoConfiguration = {
  tls_versions: string[];
  cipher_suites: string[];
  key_exchange?: string;
  certificates: string[];
  signature_algorithm?: string;
  certificate_key_algorithm?: string;
  certificate_key_size?: number;
  data_encryption_algorithm?: string;
  key_wrapping_algorithm?: string;
  key_storage?: string;
  kms_or_hsm?: string;
  key_chain?: KeyProtectionChain;
};

export type EvidenceItem = {
  id: string;
  control: string;
  value: string;
  source: EvidenceSource;
  observability: ObservabilityState | string;
  confidence?: string;
  description?: string;
  layer?: SecurityLayer;
  metadata?: Record<string, any>;
};

export type EvidenceGap = {
  gap_type: EvidenceGapType;
  layer: SecurityLayer;
  control: string;
  description: string;
  evidence_needed: string;
  observability: ObservabilityState | string;
  source?: EvidenceSource;
};

export type BankingAsset = {
  id: string;
  name: string;
  asset_type: BankingAssetType;
  system_type?: BankingAssetType;
  description: string;
  criticality: AssetCriticality;
  data_sensitivity: DataSensitivity;
  exposure: AssetExposure;
  data_lifetime: DataLifetime;
  trust_zone: TrustZone;
  tags: string[];
  layers?: Partial<Record<SecurityLayer, EvidenceItem[]>>;
  cryptography?: CryptoConfiguration;
  key_management?: Record<string, any>;
  authentication?: Record<string, any>;
  evidence_items?: EvidenceItem[];
  evidence_gaps?: EvidenceGap[];
  metadata?: Record<string, any>;
};

export type BankingSystemProfile = BankingAsset;

export type AuditDomain =
  | 'CRYPTOGRAPHY'
  | 'QUANTUM_SECURITY'
  | 'ZERO_TRUST'
  | 'IDENTITY'
  | 'ACCESS_CONTROL'
  | 'NETWORK_SECURITY'
  | 'CONFIGURATION'
  | 'CLASSICAL_SECURITY';

export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
export type RemediationPriority = 'P0' | 'P1' | 'P2' | 'P3';
export type ObservabilityState =
  | 'OBSERVED'
  | 'NOT_OBSERVABLE'
  | 'CAPABILITY_PROBED'
  | 'PROBED_UNSUPPORTED'
  | 'CLASSICAL_ONLY_OBSERVED';

export type AuditFinding = {
  id: string;
  asset_id: string;
  domain: AuditDomain;
  control: string;
  title: string;
  severity: FindingSeverity;
  evidence: string;
  evidence_source: string;
  observability: ObservabilityState;
  impact: string;
  recommendation: string;
  remediation_priority: RemediationPriority;
  metadata?: Record<string, any>;
};

export type ZeroTrustPillar =
  | 'IDENTITY'
  | 'DEVICE_CONTEXT'
  | 'RESOURCE'
  | 'POLICY'
  | 'LEAST_PRIVILEGE'
  | 'CONTINUOUS_VERIFICATION';

export type ZeroTrustControlStatus =
  | 'VERIFIED'
  | 'PARTIALLY_VERIFIED'
  | 'NOT_OBSERVABLE_EXTERNALLY'
  | 'UNVERIFIED';

export type ZeroTrustControl = {
  pillar: ZeroTrustPillar;
  control_id: string;
  name: string;
  status: ZeroTrustControlStatus;
  observability: ObservabilityState;
  description: string;
  evidence?: string;
  notes?: string;
};

export type ZeroTrustAssessment = {
  asset_id: string;
  identity_control: ZeroTrustControl;
  context_control: ZeroTrustControl;
  resource_control: ZeroTrustControl;
  policy_control: ZeroTrustControl;
  least_privilege_control: ZeroTrustControl;
  continuous_verification_control: ZeroTrustControl;
  findings: AuditFinding[];
};

export type ScanResponse = {
  target: TargetInfo;
  scan_status: string;
  certificate: CertificateInfo;
  tls: TlsInfo;
  cryptography: NormalizedCryptoMechanism[];
  findings: QuantumFinding[];
  score: QuantumScore;
  role_assessments: RoleCategoryAssessment[];
  executive_summary: ExecutiveSummary;
  migration_plan: MigrationStep[];
  observability_scope: ObservabilityScope;
  not_observable_notes: string[];
  banking_asset?: BankingAsset;
  audit_findings?: AuditFinding[];
  zero_trust?: ZeroTrustAssessment;
};

export type ApiError = {
  error: string;
  detail: string;
  target_domain?: string;
};
