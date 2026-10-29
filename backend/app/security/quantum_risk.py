"""Deterministic Quantum Risk Assessment and Assessment Intelligence Engine.
Phase 2B - Unambiguous Quantum Readiness Score (0-100), 5-Role Category Grouping,
Executive Summary Generator, and Role-Aware Migration Sequencing.
"""

from typing import List, Dict, Any, Tuple, Optional
from app.schemas.scan import (
    NormalizedCryptoMechanism,
    QuantumFinding,
    QuantumScore,
    ScoreBreakdownItem,
    CategoryScoreBreakdown,
    RoleCategoryAssessment,
    ExecutiveSummary,
    MigrationStep,
    ObservabilityScope,
)
from app.security.crypto_catalog import (
    RiskLevel,
    QuantumThreatVector,
    ALGORITHM_CATALOG,
    PQC_STANDARDS,
)


def evaluate_quantum_risk(
    mechanisms: List[NormalizedCryptoMechanism],
    tls_info: Dict[str, Any],
    certificate_info: Dict[str, Any],
    domain: str = "target"
) -> Tuple[
    List[QuantumFinding],
    QuantumScore,
    List[RoleCategoryAssessment],
    ExecutiveSummary,
    List[MigrationStep],
    ObservabilityScope
]:
    """
    Evaluates observed and normalized cryptographic mechanisms across 5 standard roles:
    1. Certificate & Digital Signatures (Weight: 30%)
    2. Key Establishment (Weight: 30%)
    3. Symmetric Encryption (Weight: 20%)
    4. Hashing & Integrity (Weight: 10%)
    5. TLS Configuration (Weight: 10%)

    Produces:
    - Structured findings (strictly role-aware)
    - Deterministic Quantum Readiness Score (0 = extremely poor, 100 = excellent)
    - 5 Role Group Assessments
    - Dynamic Executive Summary
    - Prioritized Roadmap (P0, P1, P2, P3)
    - Observability Scope (Observed vs Inferred vs Not Observable)
    """
    findings: List[QuantumFinding] = []
    score_breakdown: List[ScoreBreakdownItem] = []

    # -------------------------------------------------------------
    # 1. EVALUATE CERTIFICATE & DIGITAL SIGNATURES (Weight: 30%)
    # -------------------------------------------------------------
    pk_mech = next((m for m in mechanisms if m.category == "public_key"), None)
    sig_mech = next((m for m in mechanisms if m.category == "signature"), None)
    sig_algo = certificate_info.get("signature_algorithm") or ""
    is_trusted = certificate_info.get("is_trusted", True)
    is_expired = certificate_info.get("is_expired", False)

    cert_readiness = 60  # baseline for classical RSA-2048 / ECC
    cert_status = "HIGH RISK"
    cert_threat = "Shor's Algorithm (Integer Factorization / ECDLP)"
    cert_val = pk_mech.value if pk_mech else "Unknown Public Key"
    cert_src = pk_mech.source if pk_mech else "TLS Leaf Certificate"
    cert_evidence = pk_mech.evidence if pk_mech else "OBSERVED"

    if pk_mech:
        if pk_mech.algorithm_family == "RSA":
            key_size = pk_mech.key_size or 2048
            if key_size < 2048:
                cert_readiness = 20
                cert_status = "CRITICAL"
                cert_threat = "Classically Deprecated & Shor's Algorithm Vulnerable"
                findings.append(
                    QuantumFinding(
                        id="FND-CERT-01",
                        title=f"Legacy RSA Certificate Key Modulus ({key_size} bits)",
                        role="Certificate Public Key",
                        value=f"RSA-{key_size}",
                        source=pk_mech.source,
                        evidence="OBSERVED",
                        component=pk_mech.component,
                        algorithm=pk_mech.algorithm_name,
                        category="public_key",
                        quantum_threat="Shor's algorithm (Integer Factorization)",
                        quantum_threat_vector=QuantumThreatVector.CLASSICAL_BROKEN.value,
                        risk_level=RiskLevel.CRITICAL.value,
                        security_impact=f"RSA key size of {key_size} bits violates baseline industry security standards and is trivially breakable on modest quantum systems.",
                        reason="RSA keys under 2048 bits fail classical cryptographic minimums and require minimal quantum resources to factor.",
                        recommendation="Immediately reissue certificate with minimum RSA-3072 or prepare migration to NIST FIPS 204 (ML-DSA).",
                        migration_target="ML-DSA / SLH-DSA",
                        priority="P0",
                        priority_score=100,
                        observed_from=pk_mech.source,
                        observability="OBSERVED",
                        target_pqc_standard=PQC_STANDARDS["ML_DSA"]["standard"],
                    )
                )
            else:
                cert_readiness = 60
                cert_status = "HIGH RISK"
                cert_threat = "Shor's Algorithm (Polynomial Integer Factorization)"
                findings.append(
                    QuantumFinding(
                        id="FND-CERT-02",
                        title=f"RSA Public Key Certificate ({key_size} bits) Vulnerable to Shor's Algorithm",
                        role="Certificate Public Key",
                        value=f"RSA-{key_size}",
                        source=pk_mech.source,
                        evidence="OBSERVED",
                        component=pk_mech.component,
                        algorithm=pk_mech.algorithm_name,
                        category="public_key",
                        quantum_threat="Shor's algorithm",
                        quantum_threat_vector=QuantumThreatVector.SHOR.value,
                        risk_level=RiskLevel.HIGH.value,
                        security_impact="RSA public-key authentication is vulnerable to sufficiently capable quantum computers via polynomial-time integer factorization.",
                        reason=f"Shor's algorithm completely breaks RSA integer factorization once a CRQC is developed, allowing signature forgery and identity impersonation.",
                        recommendation="Prepare migration to a post-quantum digital signature standard under NIST FIPS 204 (ML-DSA) or FIPS 205 (SLH-DSA).",
                        migration_target="ML-DSA / SLH-DSA",
                        priority="P1",
                        priority_score=85,
                        observed_from=pk_mech.source,
                        observability="OBSERVED",
                        target_pqc_standard=PQC_STANDARDS["ML_DSA"]["standard"],
                    )
                )
        elif pk_mech.algorithm_family in ("ECC", "EdDSA"):
            cert_readiness = 60
            cert_status = "HIGH RISK"
            cert_threat = "Shor's Algorithm (Elliptic Curve Discrete Logarithm)"
            findings.append(
                QuantumFinding(
                    id="FND-CERT-03",
                    title=f"Elliptic Curve Public Key ({pk_mech.value}) Vulnerable to Shor's Algorithm",
                    role="Certificate Public Key",
                    value=pk_mech.value,
                    source=pk_mech.source,
                    evidence="OBSERVED",
                    component=pk_mech.component,
                    algorithm=pk_mech.algorithm_name,
                    category="public_key",
                    quantum_threat="Shor's algorithm",
                    quantum_threat_vector=QuantumThreatVector.SHOR.value,
                    risk_level=RiskLevel.HIGH.value,
                    security_impact="Elliptic-curve discrete logarithms are solved in polynomial time by Shor's algorithm, allowing digital signature forgery.",
                    reason="Standard curves (P-256, P-384, Ed25519) require fewer logical qubits to break under Shor's algorithm than 2048-bit RSA.",
                    recommendation="Prepare migration to post-quantum digital signatures under NIST FIPS 204 (ML-DSA) or composite X.509 dual signatures.",
                    migration_target="ML-DSA / SLH-DSA",
                    priority="P1",
                    priority_score=87,
                    observed_from=pk_mech.source,
                    observability="OBSERVED",
                    target_pqc_standard=PQC_STANDARDS["ML_DSA"]["standard"],
                )
            )

    # Check certificate signature broken hashes
    if "sha1" in sig_algo.lower() or "md5" in sig_algo.lower():
        cert_readiness = max(0, cert_readiness - 30)
        cert_status = "CRITICAL"
        findings.append(
            QuantumFinding(
                id="FND-SIG-01",
                title="Classically Broken Hash in Certificate Signature",
                role="Certificate Signature",
                value=sig_algo,
                source="TLS Leaf Certificate (SignatureAlgorithm OID)",
                evidence="OBSERVED",
                component="certificate_signature",
                algorithm=sig_algo,
                category="signature",
                quantum_threat="Classical Collision Break & Zero Quantum Margin",
                quantum_threat_vector=QuantumThreatVector.CLASSICAL_BROKEN.value,
                risk_level=RiskLevel.CRITICAL.value,
                security_impact="Certificate signature relies on a collision-broken hash function, invalidating classical trust anchors.",
                reason="SHA-1 and MD5 collision attacks are well documented classically and provide no quantum safety.",
                recommendation="Immediately reissue certificate with SHA-256 or SHA-384 signature algorithm.",
                migration_target="SHA-384 with ML-DSA",
                priority="P0",
                priority_score=100,
                observed_from="TLS Leaf Certificate",
                observability="OBSERVED",
                target_pqc_standard=PQC_STANDARDS["SHA_384"]["standard"],
            )
        )
    elif not is_trusted or is_expired:
        cert_readiness = max(10, cert_readiness - 20)

    # -------------------------------------------------------------
    # 2. EVALUATE KEY ESTABLISHMENT (Weight: 30%)
    # -------------------------------------------------------------
    kx_mech = next((m for m in mechanisms if m.category == "key_exchange"), None)
    kx_val = kx_mech.value if kx_mech else "Not observable"
    kx_evidence = kx_mech.evidence if kx_mech else "NOT_OBSERVABLE"
    kx_source = kx_mech.source if kx_mech else "Client TLS API"

    if kx_mech and (kx_mech.algorithm_family == "Hybrid ML-KEM" or kx_evidence in ("OBSERVED", "CAPABILITY_PROBED") and "MLKEM" in (kx_mech.value or "").upper()):
        # Hybrid Post-Quantum Key Exchange Active (e.g. X25519MLKEM768)
        kx_readiness = 100
        kx_status = "EXCELLENT"
        kx_threat = "None / Quantum Resistant (NIST FIPS 203 Hybrid ML-KEM)"
        findings.append(
            QuantumFinding(
                id="FND-KX-PQC-01",
                title=f"Hybrid Post-Quantum Key Exchange Active ({kx_val})",
                role="Key Establishment",
                value=kx_val,
                source=kx_source,
                evidence=kx_evidence,
                component=kx_mech.component,
                algorithm=kx_mech.algorithm_name,
                category="key_exchange",
                quantum_threat="Protected against Store Now, Decrypt Later (SNDL) via NIST FIPS 203 hybrid KEM",
                quantum_threat_vector=QuantumThreatVector.RESISTANT.value,
                risk_level=RiskLevel.INFORMATIONAL.value,
                security_impact="Session key establishment combines classical ECDHE with NIST FIPS 203 (ML-KEM-768), defeating quantum ciphertext harvesting and retroactive decryption.",
                reason="Hybrid key encapsulation ensures confidentiality holds as long as either the classical or the post-quantum lattice component remains unbroken.",
                recommendation="Maintain hybrid post-quantum key agreement. Monitor transition to pure post-quantum KEM as IETF standards finalize.",
                migration_target="NIST FIPS 203 (ML-KEM-768)",
                priority="P3",
                priority_score=15,
                observed_from=kx_source,
                observability=kx_evidence,
                target_pqc_standard=PQC_STANDARDS["ML_KEM"]["hybrid_target"],
            )
        )
    elif kx_evidence == "CLASSICAL_ONLY_OBSERVED":
        kx_readiness = 50
        kx_status = "HIGH RISK"
        kx_threat = "Shor's Algorithm & Store Now, Decrypt Later (SNDL)"
        findings.append(
            QuantumFinding(
                id="FND-KX-02",
                title=f"Classical Key Exchange ({kx_val}) Exposed to 'Store Now, Decrypt Later' (SNDL)",
                role="Key Establishment",
                value=kx_val,
                source=kx_source,
                evidence="CLASSICAL_ONLY_OBSERVED",
                component=kx_mech.component,
                algorithm=kx_mech.algorithm_name,
                category="key_exchange",
                quantum_threat="Shor's algorithm (SNDL)",
                quantum_threat_vector=QuantumThreatVector.SNDL.value,
                risk_level=RiskLevel.HIGH.value,
                security_impact="Recorded encrypted traffic can be retroactively decrypted once a cryptanalytically relevant quantum computer becomes operational.",
                reason=f"The server negotiated classical group {kx_val} by default. Stored session ciphertexts are vulnerable to retroactive Shor's algorithm attacks. An active probe offering X25519MLKEM768 can verify whether the server supports hybrid PQC.",
                recommendation="Enable hybrid post-quantum key exchange combining classical ECDHE with NIST FIPS 203 (ML-KEM-768 / Kyber).",
                migration_target="ML-KEM / Hybrid ML-KEM",
                priority="P1",
                priority_score=95,
                observed_from=kx_source,
                observability="CLASSICAL_ONLY_OBSERVED",
                target_pqc_standard=PQC_STANDARDS["ML_KEM"]["hybrid_target"],
            )
        )
    elif kx_evidence == "PROBED_UNSUPPORTED":
        kx_readiness = 50
        kx_status = "HIGH RISK"
        kx_threat = "Shor's Algorithm & Store Now, Decrypt Later (SNDL) - PQC Unsupported"
        findings.append(
            QuantumFinding(
                id="FND-KX-02",
                title=f"Classical Key Exchange ({kx_val}) Exposed to SNDL - X25519MLKEM768 Unsupported",
                role="Key Establishment",
                value=kx_val,
                source=kx_source,
                evidence="PROBED_UNSUPPORTED",
                component=kx_mech.component,
                algorithm=kx_mech.algorithm_name,
                category="key_exchange",
                quantum_threat="Shor's algorithm (SNDL)",
                quantum_threat_vector=QuantumThreatVector.SNDL.value,
                risk_level=RiskLevel.HIGH.value,
                security_impact="Active probe confirmed the target does not support X25519MLKEM768 hybrid key exchange (handshake rejected). Recorded sessions remain vulnerable to retroactive decryption under SNDL.",
                reason="Target rejected ClientHello offering hybrid post-quantum group X25519MLKEM768. The server strictly requires classical key exchange.",
                recommendation="Upgrade edge proxy, web server, or CDN (Cloudflare, AWS CloudFront, Envoy, NGINX) to enable NIST FIPS 203 (ML-KEM-768) hybrid key agreement.",
                migration_target="ML-KEM / Hybrid ML-KEM",
                priority="P1",
                priority_score=95,
                observed_from=kx_source,
                observability="PROBED_UNSUPPORTED",
                target_pqc_standard=PQC_STANDARDS["ML_KEM"]["hybrid_target"],
            )
        )
    elif kx_evidence == "NOT_OBSERVABLE":
        # In TLS 1.3, the client TLS API cannot expose the negotiated group.
        # This is a visibility boundary, NOT proof of insecurity.
        kx_readiness = 70  # Baseline: TLS 1.3 enforces PFS classically, but PQC hybrid unverified
        kx_status = "INFORMATIONAL"
        kx_threat = "Store Now, Decrypt Later (SNDL) - Unverified Status"
        findings.append(
            QuantumFinding(
                id="FND-KX-01",
                title="TLS 1.3 Key Exchange Group Not Observable from External TLS Probe",
                role="Key Establishment",
                value="Not observable",
                source=kx_source,
                evidence="NOT_OBSERVABLE",
                component=kx_mech.component if kx_mech else "tls_key_exchange",
                algorithm="Not observable",
                category="key_exchange",
                quantum_threat="Store Now, Decrypt Later (SNDL) - Unverified",
                quantum_threat_vector=QuantumThreatVector.SNDL.value,
                risk_level=RiskLevel.INFORMATIONAL.value,
                security_impact="The negotiated TLS 1.3 KeyShare group cannot be confirmed from the external client TLS API. Server may use classical ECDHE (X25519/P-256) or hybrid ML-KEM-768.",
                reason="In TLS 1.3, key exchange is decoupled from cipher suites. Because standard client TLS socket APIs do not expose which KeyShare group was negotiated, external confirmation is not possible.",
                recommendation="Audit server-side TLS configuration or edge CDN settings to verify that hybrid post-quantum key exchange (X25519 + ML-KEM-768) is enabled.",
                migration_target="ML-KEM / Hybrid ML-KEM",
                priority="P1",
                priority_score=40,
                observed_from=kx_source,
                observability="NOT_OBSERVABLE",
                target_pqc_standard=PQC_STANDARDS["ML_KEM"]["hybrid_target"],
            )
        )
    elif kx_evidence in ("OBSERVED", "INFERRED"):
        if kx_mech.algorithm_family in ("ECC", "Diffie-Hellman"):
            kx_readiness = 50  # PFS active, but completely vulnerable to Shor + SNDL
            kx_status = "HIGH RISK"
            kx_threat = "Shor's Algorithm & Store Now, Decrypt Later (SNDL)"
            findings.append(
                QuantumFinding(
                    id="FND-KX-02",
                    title=f"Classical Key Exchange ({kx_mech.value}) Exposed to 'Store Now, Decrypt Later' (SNDL)",
                    role="Key Establishment",
                    value=kx_mech.value,
                    source=kx_source,
                    evidence=kx_evidence,
                    component=kx_mech.component,
                    algorithm=kx_mech.algorithm_name,
                    category="key_exchange",
                    quantum_threat="Shor's algorithm (SNDL)",
                    quantum_threat_vector=QuantumThreatVector.SNDL.value,
                    risk_level=RiskLevel.HIGH.value,
                    security_impact="Recorded encrypted traffic can be retroactively decrypted once a cryptanalytically relevant quantum computer becomes operational.",
                    reason="Shor's algorithm solves discrete logarithms in polynomial time. Classical key exchanges offer zero long-term confidentiality against stored ciphertext harvesting.",
                    recommendation="Enable hybrid post-quantum key exchange combining classical ECDHE with NIST FIPS 203 (ML-KEM-768 / Kyber).",
                    migration_target="ML-KEM / Hybrid ML-KEM",
                    priority="P1",
                    priority_score=95,
                    observed_from=kx_source,
                    observability=kx_evidence,
                    target_pqc_standard=PQC_STANDARDS["ML_KEM"]["hybrid_target"],
                )
            )
        elif kx_mech.algorithm_family == "RSA":
            kx_readiness = 15  # No PFS, trivially broken
            kx_status = "CRITICAL"
            kx_threat = "Static RSA (No PFS) Broken by Shor's Algorithm"
            findings.append(
                QuantumFinding(
                    id="FND-KX-03",
                    title="Insecure Static RSA Key Exchange Without Forward Secrecy",
                    role="Key Establishment",
                    value="Static RSA",
                    source=kx_source,
                    evidence=kx_evidence,
                    component=kx_mech.component,
                    algorithm=kx_mech.algorithm_name,
                    category="key_exchange",
                    quantum_threat="Shor's algorithm (Integer Factorization)",
                    quantum_threat_vector=QuantumThreatVector.SHOR.value,
                    risk_level=RiskLevel.CRITICAL.value,
                    priority_score=100,
                    security_impact="Static RSA provides no forward secrecy. Compromise of the private key allows retroactive decryption of all past and future traffic.",
                    reason="Static RSA key transport is deprecated classically and immediately vulnerable to polynomial-time quantum integer factorization.",
                    recommendation="Disable static RSA key transport suites and mandate ephemeral hybrid post-quantum key exchange.",
                    migration_target="ML-KEM / Hybrid ML-KEM",
                    priority="P0",
                    observed_from=kx_source,
                    observability=kx_evidence,
                    target_pqc_standard=PQC_STANDARDS["ML_KEM"]["standard"],
                )
            )
        else:
            kx_readiness = 70
            kx_status = "MODERATE"
            kx_threat = "Unclassified Key Exchange"
    else:
        kx_readiness = 70
        kx_status = "INFORMATIONAL"
        kx_threat = "Unknown"

    # -------------------------------------------------------------
    # 3. EVALUATE SYMMETRIC ENCRYPTION (Weight: 20%)
    # -------------------------------------------------------------
    sym_mech = next((m for m in mechanisms if m.category == "symmetric_cipher"), None)
    sym_val = sym_mech.value if sym_mech else "Unknown"
    sym_src = sym_mech.source if sym_mech else "TLS Negotiated Cipher Suite"

    if sym_mech and sym_mech.key_size and sym_mech.key_size <= 128:
        sym_readiness = 65  # Grover reduces 128 bits to 64 bits
        sym_status = "MEDIUM RISK"
        sym_threat = "Grover's Algorithm (Halved Key Strength to ~64 bits)"
        findings.append(
            QuantumFinding(
                id="FND-SYM-01",
                title=f"128-bit Symmetric Cipher ({sym_mech.value}) Degraded by Grover's Algorithm",
                role="Symmetric Encryption",
                value=sym_mech.value,
                source=sym_src,
                evidence="OBSERVED",
                component=sym_mech.component,
                algorithm=sym_mech.algorithm_name,
                category="symmetric_cipher",
                quantum_threat="Grover's algorithm",
                quantum_threat_vector=QuantumThreatVector.GROVER.value,
                risk_level=RiskLevel.MEDIUM.value,
                priority_score=60,
                security_impact="Grover's algorithm halves brute-force security to ~64 bits, providing a reduced security margin against well-resourced quantum adversaries.",
                reason="Grover's algorithm provides quadratic speedup for unstructured key search, reducing effective strength of 128-bit keys to 2^64 operations.",
                recommendation="Prioritize AES-256-GCM or ChaCha20-Poly1305 over 128-bit ciphers to achieve a ~128-bit post-quantum security margin.",
                migration_target="AES-256-GCM",
                priority="P2",
                observed_from=sym_src,
                observability="OBSERVED",
                target_pqc_standard=PQC_STANDARDS["AES_256"]["standard"],
            )
        )
    elif sym_mech and sym_mech.key_size and sym_mech.key_size >= 256:
        sym_readiness = 100  # Grover reduces 256 bits to 128 bits (fully quantum resistant)
        sym_status = "EXCELLENT"
        sym_threat = "None / Quantum Resistant (Retains ~128-bit security)"
        findings.append(
            QuantumFinding(
                id="FND-SYM-02",
                title=f"256-bit Symmetric Cipher ({sym_mech.value}) Resists Quantum Search",
                role="Symmetric Encryption",
                value=sym_mech.value,
                source=sym_src,
                evidence="OBSERVED",
                component=sym_mech.component,
                algorithm=sym_mech.algorithm_name,
                category="symmetric_cipher",
                quantum_threat="Grover's algorithm (Resistant)",
                quantum_threat_vector=QuantumThreatVector.RESISTANT.value,
                risk_level=RiskLevel.LOW.value,
                priority_score=20,
                security_impact="Under Grover's algorithm, a 256-bit key maintains ~128 bits of security, which is computationally intractable for any quantum computer.",
                reason="Quadratic acceleration reduces 256-bit keys to 2^128 operations, exceeding NIST CNSA 2.0 post-quantum protection requirements.",
                recommendation="Maintain AES-256-GCM or ChaCha20-Poly1305 as the preferred symmetric encryption cipher suite.",
                migration_target="AES-256-GCM (Compliant)",
                priority="P3",
                observed_from=sym_src,
                observability="OBSERVED",
                target_pqc_standard=PQC_STANDARDS["AES_256"]["standard"],
            )
        )
    else:
        sym_readiness = 80
        sym_status = "GOOD"
        sym_threat = "Standard"

    # -------------------------------------------------------------
    # 4. EVALUATE HASHING & INTEGRITY (Weight: 10%)
    # -------------------------------------------------------------
    hash_mech = next((m for m in mechanisms if m.category == "hash"), None)
    hash_val = hash_mech.value if hash_mech else "SHA-2"
    hash_src = hash_mech.source if hash_mech else "TLS Negotiated Cipher Suite PRF"

    if hash_mech and hash_mech.algorithm_name in ("SHA-384", "SHA-512"):
        hash_readiness = 100
        hash_status = "EXCELLENT"
        hash_threat = "None / CNSA 2.0 Compliant"
    elif hash_mech and hash_mech.algorithm_name == "SHA-256":
        hash_readiness = 90
        hash_status = "GOOD"
        hash_threat = "Quantum Collision Search (BHT ~2^85 operations, adequate)"
    elif hash_mech and hash_mech.algorithm_name in ("SHA-1", "MD5"):
        hash_readiness = 0
        hash_status = "CRITICAL"
        hash_threat = "Classically Broken Collision Resistance"
    else:
        hash_readiness = 90
        hash_status = "GOOD"
        hash_threat = "Standard Hash"

    # -------------------------------------------------------------
    # 5. EVALUATE TLS CONFIGURATION (Weight: 10%)
    # -------------------------------------------------------------
    protocol = tls_info.get("negotiated_protocol") or "UNKNOWN"
    if protocol == "TLSv1.3":
        tls_readiness = 100
        tls_status = "EXCELLENT"
        tls_threat = "Modern Architecture (Enables PQC KeyShare Negotiation)"
        findings.append(
            QuantumFinding(
                id="FND-PROTO-01",
                title="TLS 1.3 Protocol Negotiated",
                role="TLS Configuration",
                value="TLSv1.3",
                source="TLS Connection Handshake",
                evidence="OBSERVED",
                component="tls_protocol",
                algorithm="TLSv1.3",
                category="protocol",
                quantum_threat="None / Modern Protocol",
                quantum_threat_vector=QuantumThreatVector.RESISTANT.value,
                risk_level=RiskLevel.INFORMATIONAL.value,
                priority_score=10,
                security_impact="TLS 1.3 modernizes handshake security, enforces forward secrecy, and natively supports hybrid post-quantum KeyShare extensions.",
                reason="RFC 8446 removes legacy insecure cipher suites and provides the necessary extension mechanism for IETF post-quantum hybrid key exchange.",
                recommendation="Continue enforcing TLS 1.3 as the default minimum protocol across all endpoints.",
                migration_target="TLS 1.3 (RFC 8446)",
                priority="P3",
                observed_from="TLS Connection Handshake",
                observability="OBSERVED",
                target_pqc_standard="RFC 8446 / IETF PQC TLS",
            )
        )
    elif protocol == "TLSv1.2":
        tls_readiness = 65
        tls_status = "MEDIUM RISK"
        tls_threat = "Lacks Standardized PQC KeyShare Negotiation"
        findings.append(
            QuantumFinding(
                id="FND-PROTO-02",
                title="Legacy TLS 1.2 Negotiated",
                role="TLS Configuration",
                value="TLSv1.2",
                source="TLS Connection Handshake",
                evidence="OBSERVED",
                component="tls_protocol",
                algorithm="TLSv1.2",
                category="protocol",
                quantum_threat="Lacks Native PQC Extension Support",
                quantum_threat_vector=QuantumThreatVector.CLASSICAL_BROKEN.value,
                risk_level=RiskLevel.MEDIUM.value,
                priority_score=50,
                security_impact="TLS 1.2 lacks standardized hybrid key exchange extensions and permits legacy non-forward-secret cipher suites.",
                reason="Standardized ML-KEM hybrid key encapsulation (IETF draft-ietf-tls-hybrid-design) requires TLS 1.3 KeyShare structures.",
                recommendation="Upgrade web servers and edge reverse proxies to enforce TLS 1.3.",
                migration_target="TLS 1.3 (RFC 8446)",
                priority="P2",
                observed_from="TLS Connection Handshake",
                observability="OBSERVED",
                target_pqc_standard="TLS 1.3 (RFC 8446)",
            )
        )
    else:
        tls_readiness = 0
        tls_status = "CRITICAL"
        tls_threat = "Deprecated Protocol (Vulnerable to classical attacks)"

    # -------------------------------------------------------------
    # 6. COMPUTE OVERALL QUANTUM READINESS SCORE
    # -------------------------------------------------------------
    # Formula: 0.30*Cert + 0.30*KX + 0.20*Sym + 0.10*Hash + 0.10*TLS
    weighted_readiness = (
        0.30 * cert_readiness +
        0.30 * kx_readiness +
        0.20 * sym_readiness +
        0.10 * hash_readiness +
        0.10 * tls_readiness
    )
    overall_readiness = int(round(weighted_readiness))
    exposure_risk = 100 - overall_readiness

    # Assign qualitative grade based on Quantum Readiness Score (0-100):
    if overall_readiness >= 85:
        grade = "Excellent"
        summary_verdict = f"{domain} demonstrates excellent post-quantum readiness with modern protocols and quantum-resistant algorithms."
    elif overall_readiness >= 70:
        grade = "Good"
        summary_verdict = f"{domain} demonstrates good classical security with a robust TLS 1.3 perimeter, but relies on classical asymmetric authentication requiring a post-quantum migration roadmap."
    elif overall_readiness >= 55:
        grade = "Moderate"
        summary_verdict = f"{domain} shows moderate quantum readiness. While operational classically, it exhibits exposure to future quantum attacks on asymmetric key exchange and public-key certificates."
    elif overall_readiness >= 40:
        grade = "Needs Improvement"
        summary_verdict = f"{domain} needs improvement. Multiple cryptographic layers rely on classical algorithms vulnerable to Shor's or Grover's quantum attacks."
    else:
        grade = "Critical"
        summary_verdict = f"{domain} exhibits critical quantum vulnerabilities and/or classically deprecated cryptographic primitives."

    category_breakdown = CategoryScoreBreakdown(
        certificates=cert_readiness,
        key_establishment=kx_readiness,
        symmetric_encryption=sym_readiness,
        hashing=hash_readiness,
        tls_configuration=tls_readiness,
    )

    score_breakdown = [
        ScoreBreakdownItem(
            factor="Certificate & Digital Signatures",
            impact=f"{cert_readiness} / 100 (Weight: 30%)",
            points=int(round(0.30 * cert_readiness)),
            explanation=f"Evaluates leaf certificate public key ({cert_val}) against Shor's algorithm polynomial speedup.",
        ),
        ScoreBreakdownItem(
            factor="Key Establishment",
            impact=f"{kx_readiness} / 100 (Weight: 30%)",
            points=int(round(0.30 * kx_readiness)),
            explanation=(
                f"Evaluates session key agreement against 'Store Now, Decrypt Later' (SNDL). Evidence: {kx_evidence}."
            ),
        ),
        ScoreBreakdownItem(
            factor="Symmetric Encryption",
            impact=f"{sym_readiness} / 100 (Weight: 20%)",
            points=int(round(0.20 * sym_readiness)),
            explanation=f"Evaluates bulk cipher ({sym_val}) key length against Grover's quadratic brute-force acceleration.",
        ),
        ScoreBreakdownItem(
            factor="Hashing & Integrity",
            impact=f"{hash_readiness} / 100 (Weight: 10%)",
            points=int(round(0.10 * hash_readiness)),
            explanation=f"Evaluates collision resistance of hash function ({hash_val}) under quantum search algorithms.",
        ),
        ScoreBreakdownItem(
            factor="TLS Configuration",
            impact=f"{tls_readiness} / 100 (Weight: 10%)",
            points=int(round(0.10 * tls_readiness)),
            explanation=f"Evaluates negotiated handshake protocol ({protocol}) support for post-quantum hybrid extensions.",
        ),
    ]

    formula_desc = (
        "Quantum Readiness Score = 0.30*(Cert & Signatures) + 0.30*(Key Establishment) + "
        "0.20*(Symmetric Encryption) + 0.10*(Hashing) + 0.10*(TLS Configuration). "
        "Scale: 0 = Extremely Poor Readiness, 100 = Excellent Post-Quantum Readiness."
    )

    methodology_disc = (
        "The Quantum Readiness Score (0-100) measures resilience against Shor's and Grover's quantum threat models. "
        "Higher score indicates superior quantum readiness. Unobservable parameters (such as TLS 1.3 KeyShare groups) "
        "are labeled NOT_OBSERVABLE and assigned a neutral baseline without penalizing the target."
    )

    quantum_score = QuantumScore(
        score=overall_readiness,
        readiness_score=overall_readiness,
        exposure_risk_score=exposure_risk,
        grade=grade,
        summary=summary_verdict,
        category_breakdown=category_breakdown,
        score_breakdown=score_breakdown,
        methodology_disclaimer=methodology_disc,
        formula_description=formula_desc,
    )

    # -------------------------------------------------------------
    # 7. ASSEMBLE 5 ROLE GROUP ASSESSMENTS
    # -------------------------------------------------------------
    role_assessments = [
        RoleCategoryAssessment(
            category_id="certificates",
            category_name="Certificate & Digital Signatures",
            status=cert_status,
            readiness_score=cert_readiness,
            weight_percentage=30,
            observed_value=cert_val,
            evidence=cert_evidence,
            source=cert_src,
            quantum_threat=cert_threat,
            migration_target="ML-DSA / SLH-DSA",
            priority="P1" if cert_readiness >= 40 else "P0",
            recommended_action="Plan transition to NIST FIPS 204 (ML-DSA) dual/composite certificates as public CAs deploy PQC roots.",
            findings=[f for f in findings if f.category in ("public_key", "signature")],
        ),
        RoleCategoryAssessment(
            category_id="key_establishment",
            category_name="Key Establishment",
            status=kx_status,
            readiness_score=kx_readiness,
            weight_percentage=30,
            observed_value=kx_val,
            evidence=kx_evidence,
            source=kx_source,
            quantum_threat=kx_threat,
            migration_target="ML-KEM / Hybrid ML-KEM",
            priority="P1",
            recommended_action=(
                "Verify edge load balancer / CDN support for hybrid key encapsulation (X25519 + ML-KEM-768 under NIST FIPS 203) "
                "to defend against Store Now, Decrypt Later (SNDL) attacks."
            ),
            findings=[f for f in findings if f.category == "key_exchange"],
        ),
        RoleCategoryAssessment(
            category_id="symmetric_encryption",
            category_name="Symmetric Encryption",
            status=sym_status,
            readiness_score=sym_readiness,
            weight_percentage=20,
            observed_value=sym_val,
            evidence="OBSERVED",
            source=sym_src,
            quantum_threat=sym_threat,
            migration_target="AES-256-GCM",
            priority="P2" if sym_readiness < 100 else "P3",
            recommended_action=(
                "Enforce AES-256-GCM or ChaCha20-Poly1305 as the preferred symmetric cipher suite to retain ~128-bit quantum security."
                if sym_readiness < 100 else "Maintain AES-256-GCM as preferred symmetric cipher suite."
            ),
            findings=[f for f in findings if f.category == "symmetric_cipher"],
        ),
        RoleCategoryAssessment(
            category_id="hashing",
            category_name="Hashing & Integrity",
            status=hash_status,
            readiness_score=hash_readiness,
            weight_percentage=10,
            observed_value=hash_val,
            evidence="OBSERVED",
            source=hash_src,
            quantum_threat=hash_threat,
            migration_target="SHA-384",
            priority="P3" if hash_readiness >= 90 else "P0",
            recommended_action="Maintain SHA-256 / SHA-384 for message authentication and PRF.",
            findings=[],
        ),
        RoleCategoryAssessment(
            category_id="tls_configuration",
            category_name="TLS Configuration",
            status=tls_status,
            readiness_score=tls_readiness,
            weight_percentage=10,
            observed_value=protocol,
            evidence="OBSERVED",
            source="TLS Connection Handshake",
            quantum_threat=tls_threat,
            migration_target="TLS 1.3 (RFC 8446)",
            priority="P2" if protocol != "TLSv1.3" else "P3",
            recommended_action="Enforce TLS 1.3 and disable deprecated protocol versions.",
            findings=[f for f in findings if f.category == "protocol"],
        ),
    ]

    # -------------------------------------------------------------
    # 8. DYNAMIC EXECUTIVE SUMMARY
    # -------------------------------------------------------------
    primary_concern = (
        f"The publicly observable TLS certificate uses {cert_val}, which is vulnerable to Shor's algorithm on a cryptanalytically relevant quantum computer."
        if cert_readiness < 100 else "Certificate authentication appears post-quantum ready."
    )

    secondary_concern = None
    if sym_readiness < 100:
        secondary_concern = f"Negotiated symmetric encryption ({sym_val}) provides a reduced quantum security margin (~64 bits) under Grover's algorithm compared to AES-256."
    elif kx_readiness < 100 and kx_evidence in ("OBSERVED", "CLASSICAL_ONLY_OBSERVED", "PROBED_UNSUPPORTED"):
        secondary_concern = f"Key exchange ({kx_val}) provides forward secrecy classically, but remains vulnerable to 'Store Now, Decrypt Later' (SNDL) attacks."

    if kx_evidence == "NOT_OBSERVABLE":
        visibility_limitations = (
            "The external scan could not determine the exact TLS 1.3 KeyShare group from standard client TLS socket APIs. "
            "Internal database encryption, KMS configurations, and backend microservice mTLS remain unobservable from the perimeter."
        )
    else:
        visibility_limitations = (
            f"TLS 1.3 KeyShare group was evaluated ({kx_val}, evidence: {kx_evidence}). "
            "Internal database encryption, KMS configurations, and backend microservice mTLS remain unobservable from the perimeter."
        )

    next_steps = [
        "1. Plan digital signature migration for X.509 certificates to NIST FIPS 204 (ML-DSA) or hybrid composite certificates.",
    ]
    if kx_readiness == 100:
        next_steps.append(f"2. Maintain active hybrid post-quantum key agreement ({kx_val}) and track IETF pure PQC transitions.")
    else:
        next_steps.append("2. Audit server-side / CDN configuration to verify support for hybrid key encapsulation (X25519 + ML-KEM-768 under NIST FIPS 203).")

    if sym_readiness < 100:
        next_steps.append("3. Adjust web server cipher preference lists to mandate AES-256-GCM for long-term symmetric confidentiality.")
    if protocol != "TLSv1.3":
        next_steps.append("4. Upgrade perimeter infrastructure to mandate TLS 1.3.")

    full_exec_text = (
        f"QUANTUM READINESS SUMMARY\n\n"
        f"{domain} currently demonstrates a {grade.lower()} level of quantum readiness (Score: {overall_readiness} / 100).\n\n"
        f"Primary concern:\n{primary_concern}\n\n"
        + (f"Secondary concern:\n{secondary_concern}\n\n" if secondary_concern else "")
        + f"Visibility limitations:\n{visibility_limitations}\n\n"
        f"Recommended next steps:\n" + "\n".join(next_steps)
    )

    executive_summary = ExecutiveSummary(
        domain=domain,
        readiness_verdict=summary_verdict,
        primary_concern=primary_concern,
        secondary_concern=secondary_concern,
        visibility_limitations=visibility_limitations,
        recommended_next_steps=next_steps,
        full_text=full_exec_text,
    )

    # -------------------------------------------------------------
    # 9. PRIORITIZED MIGRATION ROADMAP (P0, P1, P2, P3)
    # -------------------------------------------------------------
    migration_plan = _build_migration_plan(findings, role_assessments, domain)

    # -------------------------------------------------------------
    # 10. OBSERVABILITY SCOPE (What QuantumShield Can Observe)
    # -------------------------------------------------------------
    observability_scope = ObservabilityScope(
        observed_externally=[
            f"TLS Protocol Version ({protocol})",
            f"Negotiated Cipher Suite ({tls_info.get('negotiated_cipher', 'Unknown')})",
            f"Certificate Public Key Algorithm & Key Size ({cert_val})",
            f"Certificate Signature Algorithm ({sig_algo})",
            f"Certificate Validity Period & Expiry ({certificate_info.get('days_remaining', 0)} days remaining)",
            f"Certificate Subject & Issuer DN ({certificate_info.get('issuer_cn', 'Standard CA')})",
            f"Subject Alternative Names (SANs) ({len(certificate_info.get('subject_alt_names', []))} domain names)",
            f"ALPN Protocol ({tls_info.get('alpn_protocol') or 'None'})",
        ],
        potentially_inferred=[
            "TLS 1.2 Key Exchange algorithm prefix when explicitly negotiated in cipher suite name",
            "Symmetric encryption mode (GCM/CBC) derived from standardized cipher suite definition",
        ],
        not_externally_observable=[
            "TLS 1.3 KeyShare group if unavailable from standard client socket APIs",
            "Server private keys and seed generation entropy",
            "Internal database at-rest encryption and Key Management Service (KMS) policies",
            "Application-level cryptographic tokens, JWT signing secrets, and password hashes",
            "Backend microservice-to-microservice mutual TLS (mTLS) configurations",
            "Internal VPN and corporate network cryptographic configurations",
        ],
    )

    # Sort findings by priority score descending
    findings.sort(key=lambda f: f.priority_score, reverse=True)

    return findings, quantum_score, role_assessments, executive_summary, migration_plan, observability_scope


def _build_migration_plan(
    findings: List[QuantumFinding],
    role_assessments: List[RoleCategoryAssessment],
    domain: str
) -> List[MigrationStep]:
    """
    Constructs an actionable migration roadmap with P0, P1, P2, P3 priorities.
    Strictly aligns target post-quantum standards with the cryptographic role:
    - Key establishment -> NIST FIPS 203 (ML-KEM)
    - Digital signatures / Certificates -> NIST FIPS 204 (ML-DSA) / FIPS 205 (SLH-DSA)
    - Symmetric encryption -> AES-256
    """
    steps: List[MigrationStep] = []
    rank = 1

    # Check for P0 (Immediate: e.g. broken hashes or static RSA)
    crit_cert = next((f for f in findings if f.priority == "P0" and f.category in ("public_key", "signature")), None)
    if crit_cert:
        steps.append(
            MigrationStep(
                priority="P0",
                priority_rank=rank,
                title=f"Immediate Remediation: Replace Compromised Certificate Cryptography ({crit_cert.value})",
                affected_component=crit_cert.role or "Certificate",
                current_mechanism=crit_cert.value,
                reason=crit_cert.security_impact or crit_cert.reason,
                recommended_target="RSA-3072 / ECDSA P-384 with SHA-384 (Immediate) -> ML-DSA-65 (PQC)",
                migration_approach="Reissue certificate immediately using modern classical parameters while preparing CA pipeline for PQC roots.",
                evidence=crit_cert.evidence,
                urgency="Immediate (Classical / PQC Defect)",
                target_standards=["NIST SP 800-131A Rev 2", "NIST FIPS 204 (ML-DSA)"],
                risk_level="CRITICAL",
                why_it_matters=crit_cert.security_impact,
                recommended_action=crit_cert.recommendation,
                migration_urgency="Immediate",
                observability=crit_cert.evidence,
            )
        )
        rank += 1

    # P1/P3: Key Establishment Migration (Mitigate 'Store Now, Decrypt Later')
    kx_assessment = next((r for r in role_assessments if r.category_id == "key_establishment"), None)
    if kx_assessment:
        if kx_assessment.readiness_score == 100:
            steps.append(
                MigrationStep(
                    priority="P3",
                    priority_rank=rank,
                    title=f"Maintain Hybrid Post-Quantum Key Exchange ({kx_assessment.observed_value})",
                    affected_component="Key Establishment (TLS Handshake)",
                    current_mechanism=kx_assessment.observed_value,
                    reason="Target already negotiates hybrid post-quantum key agreement (ML-KEM-768), defeating Store Now, Decrypt Later (SNDL) attacks.",
                    recommended_target="NIST FIPS 203 (ML-KEM-768) / Pure PQC KEM (Future)",
                    migration_approach="Maintain active hybrid deployment and monitor IETF standardization of pure post-quantum KEM.",
                    evidence=kx_assessment.evidence,
                    urgency="Low Priority (Compliant / Monitoring)",
                    target_standards=["NIST FIPS 203 (ML-KEM-768)", "IETF RFC 9870"],
                    risk_level="INFORMATIONAL",
                    why_it_matters="Session key confidentiality is protected against retroactive decryption by quantum adversaries.",
                    recommended_action="Continue monitoring PQC standards and maintain hybrid KEM.",
                    migration_urgency="Low Priority",
                    observability=kx_assessment.evidence,
                )
            )
            rank += 1
        else:
            is_unobservable = kx_assessment.evidence == "NOT_OBSERVABLE"
            steps.append(
                MigrationStep(
                    priority="P1",
                    priority_rank=rank,
                    title="Deploy Hybrid Post-Quantum Key Exchange (ML-KEM / Kyber)",
                    affected_component="Key Establishment (TLS Handshake)",
                    current_mechanism=kx_assessment.observed_value,
                    reason=(
                        "In TLS 1.3, the KeyShare group cannot be confirmed externally. Because adversaries can harvest encrypted "
                        "sessions today for retroactive decryption once a CRQC exists (Store Now, Decrypt Later), validating hybrid KEM is critical."
                        if is_unobservable else
                        f"Observed key exchange ({kx_assessment.observed_value}) is vulnerable to Shor's algorithm on a quantum computer under Store Now, Decrypt Later (SNDL)."
                    ),
                    recommended_target="NIST FIPS 203 (ML-KEM-768 / Kyber) in hybrid mode with X25519",
                    migration_approach="Configure edge load balancers / CDNs (Cloudflare, AWS CloudFront, NGINX) to enable X25519MLKEM768 hybrid key agreement.",
                    evidence=kx_assessment.evidence,
                    urgency="High Priority (SNDL Risk)",
                    target_standards=["NIST FIPS 203 (ML-KEM-768)", "IETF RFC 9870"],
                    risk_level="HIGH",
                    why_it_matters="Encrypted traffic recorded today can be decrypted tomorrow if classical key exchange is used.",
                    recommended_action="Enable X25519 + ML-KEM-768 hybrid key agreement on public perimeter endpoints.",
                    migration_urgency="High Priority",
                    observability=kx_assessment.evidence,
                )
            )
            rank += 1

    # P1: Certificate Public Key Migration (Digital Signatures -> ML-DSA / SLH-DSA)
    cert_assessment = next((r for r in role_assessments if r.category_id == "certificates"), None)
    if cert_assessment and cert_assessment.readiness_score < 100 and not crit_cert:
        steps.append(
            MigrationStep(
                priority="P1",
                priority_rank=rank,
                title=f"Prepare PKI for Post-Quantum Digital Signatures ({cert_assessment.observed_value} Migration)",
                affected_component="Certificate & Digital Signatures",
                current_mechanism=cert_assessment.observed_value,
                reason="Public-key cryptography based on integer factorization or discrete logarithms is breakable in polynomial time by Shor's algorithm.",
                recommended_target="NIST FIPS 204 (ML-DSA / Dilithium) or NIST FIPS 205 (SLH-DSA / SPHINCS+)",
                migration_approach="Inventory all automated certificate management (ACME/Certbot) and prepare dual/composite certificate issuance.",
                evidence="OBSERVED",
                urgency="High Priority (Medium-Term Horizon)",
                target_standards=["NIST FIPS 204 (ML-DSA-65)", "NIST FIPS 205 (SLH-DSA)"],
                risk_level="HIGH",
                why_it_matters="An adversary with a quantum computer can forge digital signatures and impersonate the domain.",
                recommended_action="Track CA/Browser Forum PQC root rollout and test ML-DSA in non-production environments.",
                migration_urgency="High Priority",
                observability="OBSERVED",
            )
        )
        rank += 1

    # P2: Symmetric Encryption Hardening (if AES-128)
    sym_assessment = next((r for r in role_assessments if r.category_id == "symmetric_encryption"), None)
    if sym_assessment and sym_assessment.readiness_score < 100:
        steps.append(
            MigrationStep(
                priority="P2",
                priority_rank=rank,
                title="Enforce 256-bit Symmetric Cipher Suites (AES-256-GCM)",
                affected_component="Symmetric Encryption",
                current_mechanism=sym_assessment.observed_value,
                reason="Grover's algorithm halves effective symmetric key strength. 128-bit ciphers provide only ~64 bits of quantum security margin.",
                recommended_target="AES-256-GCM / ChaCha20-Poly1305 (NIST SP 800-131A / CNSA 2.0)",
                migration_approach="Update web server cipher suite preferences to place AES-256-GCM and ChaCha20-Poly1305 above AES-128.",
                evidence="OBSERVED",
                urgency="Medium Priority (Configuration Change)",
                target_standards=["NIST SP 800-131A Rev 2", "NSA CNSA 2.0"],
                risk_level="MEDIUM",
                why_it_matters="AES-256 maintains ~128 bits of security under Grover's search, providing long-term safety.",
                recommended_action="Prioritize AES-256-GCM over AES-128-GCM in server configuration.",
                migration_urgency="Medium Priority",
                observability="OBSERVED",
            )
        )
        rank += 1

    # P2: TLS Protocol Modernization (if TLS 1.2)
    tls_assessment = next((r for r in role_assessments if r.category_id == "tls_configuration"), None)
    if tls_assessment and tls_assessment.observed_value != "TLSv1.3":
        steps.append(
            MigrationStep(
                priority="P2",
                priority_rank=rank,
                title="Enforce TLS 1.3 Protocol Architecture",
                affected_component="TLS Configuration",
                current_mechanism=tls_assessment.observed_value,
                reason="TLS 1.2 lacks native support for standardized post-quantum KeyShare extensions and permits non-forward-secret ciphers.",
                recommended_target="RFC 8446 (TLS 1.3)",
                migration_approach="Upgrade edge load balancers, reverse proxies, and web servers to require TLS 1.3.",
                evidence="OBSERVED",
                urgency="Medium Priority",
                target_standards=["RFC 8446 (TLS 1.3)", "NIST SP 800-52 Rev 2"],
                risk_level="MEDIUM",
                why_it_matters="TLS 1.3 is the mandatory foundation for post-quantum hybrid key exchange.",
                recommended_action="Configure web servers to enforce TLS 1.3 as the minimum protocol.",
                migration_urgency="Medium Priority",
                observability="OBSERVED",
            )
        )
        rank += 1

    # P3: CA Trust Chain Monitoring
    steps.append(
        MigrationStep(
            priority="P3",
            priority_rank=rank,
            title="Establish Post-Quantum CA & Root Store Monitoring",
            affected_component="Certificate Trust Chain",
            current_mechanism="Standard Classical Web PKI",
            reason="Complete end-to-end post-quantum protection requires root and intermediate CAs to transition to quantum-safe signatures.",
            recommended_target="Cross-signed PQC Root Anchors (NIST FIPS 204)",
            migration_approach="Monitor operating system and browser trust store releases for PQC root anchor inclusions.",
            evidence="OBSERVED",
            urgency="Monitor (Ongoing)",
            target_standards=["NIST FIPS 204", "CA/Browser Forum PQC Guidelines"],
            risk_level="LOW",
            why_it_matters="Leaf certificate migration depends on public CAs supporting post-quantum issuance.",
            recommended_action="Track Let's Encrypt, DigiCert, and Google Trust Services PQC availability.",
            migration_urgency="Monitor",
            observability="OBSERVED",
        )
    )

    return steps
