# QuantumShield 🛡️⚛️

> **"Banking Security Audit and Zero-Trust Readiness Platform with Quantum-Safe Cryptographic Assessment."**
> Evidence-backed security posture, asset criticality context, and post-quantum migration planning for financial infrastructure.

---

## 1. Overview & Architecture

QuantumShield models financial institution security posture under quantum computing threats (Shor's and Grover's algorithms) and Zero Trust architecture (NIST SP 800-207).

### Target Architecture

```
                         QUANTUMSHIELD
                              │
                              ▼
                    ┌──────────────────┐
                    │ BANKING ASSET    │
                    │ MODEL            │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ AUDIT LAYER      │
                    └────────┬─────────┘
                             │
             ┌───────────────┼────────────────┐
             │               │                │
             ▼               ▼                ▼
       CRYPTO AUDIT    ZERO TRUST AUDIT   CLASSICAL AUDIT
             │               │                │
             ▼               ▼                ▼
       QUANTUM RISK      ACCESS RISK      SECURITY RISK
             │               │                │
             └───────────────┼────────────────┘
                             ▼
                    ┌──────────────────┐
                    │ CONTEXT /        │
                    │ CRITICALITY      │
                    │ ENGINE           │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ UNIFIED RISK     │
                    │ ENGINE           │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ REMEDIATION      │
                    │ ENGINE           │
                    └──────────────────┘
```

### Core Architecture Rules:
1. **Scanner discovers evidence**: External passive inspection only; zero intrusive probing or exploitation.
2. **Normalizer converts raw observations into normalized security facts**.
3. **Audit Layer represents security findings**: Every finding defines domain, control, title, severity, evidence, source, impact, and remediation priority.
4. **Criticality provides business context**: Business criticality (CRITICAL, HIGH, MEDIUM, LOW) is decoupled from technical vulnerability severity.
5. **Risk Engine correlates technical risk with business context**.
6. **Remediation Engine recommends actions**: Formulated with target NIST PQC standards (FIPS 203, 204, 205).
7. **Zero Trust is a separate security domain**: Evaluated across 6 NIST SP 800-207 pillars.
8. **Quantum security is a separate security domain**: Evaluated against Shor's and Grover's algorithm exposure.
9. **Never fabricate evidence**: Only report observable or reliably verified properties.
10. **Never treat NOT_OBSERVABLE as vulnerable**: Lack of external observability indicates architectural opacity, NOT vulnerability.

---

## 3. Scanner Security Hardening & SSRF Defense (Phase 2C)

QuantumShield inspects external public websites while maintaining defense-in-depth protection:

### A. SSRF & Unsafe Target Rejection
Every resolved IP address is validated through `app.security.network`. Scans against the following are strictly blocked:
- **Loopback**: `127.0.0.0/8`, `::1`
- **Private Networks (RFC 1918)**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` (ULA)
- **Link-Local & Cloud Metadata**: `169.254.0.0/16` (including AWS/GCP/Azure `169.254.169.254`), `fe80::/10`
- **Multicast & Reserved**: `224.0.0.0/4`, `240.0.0.0/4`, `ff00::/8`
- **Unspecified & Broadcast**: `0.0.0.0/8`, `::/128`, `255.255.255.255/32`
- **Documentation & Benchmarks**: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `198.18.0.0/15`, `2001:db8::/32`
- **Carrier-Grade NAT (RFC 6598)**: `100.64.0.0/10`

### B. Mixed DNS & DNS Rebinding Defenses
- **Mixed DNS Rejection**: The security resolver collects all A and AAAA records in a single resolution. If **any** returned record points to an internal or non-public address, the target is rejected immediately.
- **DNS Rebinding Prevention**: Hostname resolution happens exactly once. The TCP socket connects directly to the validated IP address tuple without re-resolving.
- **SNI Preservation**: When establishing TLS over the direct IP socket, the original hostname is preserved and passed to `ctx.wrap_socket(raw_sock, server_hostname=domain)` for accurate Server Name Indication and certificate verification.

### C. Strict Domain Input Validation
Input is limited strictly to valid Fully Qualified Domain Names (RFC 1035 / RFC 1123). The scanner rejects:
- Direct IP literals (`127.0.0.1`, `[::1]`, `93.184.216.34`)
- URLs with schemes (`http://`, `https://`, `ftp://`)
- URL paths (`example.com/test`)
- Query parameters and fragments (`example.com?q=1`, `example.com#sec`)
- Inline credentials (`user:pass@domain`)
- Inline ports (`example.com:443`)
- Internal and local namespaces (`localhost`, `*.local`, `*.internal`, `*.lan`, `*.corp`, `*.test`, `*.onion`, single-label hostnames)

### D. Bounded Timeouts & Resource Controls
- **Connect Timeout**: Bounded to 5.0 seconds for TCP connection establishment.
- **TLS Handshake Timeout**: Bounded to 8.0 seconds for TLS cryptographic exchange.
- **Rate Limiting**: In-memory sliding-window rate limiter restricting clients to **10 scans per minute per IP**, returning HTTP 429 with `Retry-After`.
- **Bounded Concurrency**: Managed by `asyncio.Semaphore` restricting concurrent scans to **5 simultaneous tasks** to prevent scanner exhaustion.
- **Safe Error Disclosure**: Error responses do not leak internal IP addresses, network topology, or system tracebacks.

---

## 4. TLS 1.3 Key-Exchange & Hybrid PQC Observation (Phase 3B)

Standard client TLS socket APIs (including Python's `ssl.SSLSocket`) do not expose the negotiated TLS 1.3 KeyShare group. QuantumShield bridges this visibility gap through a security-hardened OpenSSL observation wrapper (`app.scanners.tls13_pqc`):

### A. Five Explicit Evidence States
1. `OBSERVED`: Target natively negotiated a hybrid or classical group in the default handshake.
2. `CAPABILITY_PROBED`: Active capability probe verified that the target supports hybrid post-quantum key exchange (e.g. `X25519MLKEM768`).
3. `CLASSICAL_ONLY_OBSERVED`: Target negotiated a classical group (e.g. `X25519`) by default; active capability probe was not requested (`probe_pqc=False`).
4. `PROBED_UNSUPPORTED`: Active probe offering `X25519MLKEM768` was rejected by the server; server requires classical key exchange.
5. `NOT_OBSERVABLE`: OpenSSL unavailable or handshake group telemetry unexposed.

### B. Core Observability Invariants
- `NOT_OBSERVABLE != VULNERABLE`: External unobservability indicates visibility boundaries, never intrinsic vulnerability.
- `CLASSICAL_ONLY_OBSERVED != PROVEN_NO_PQC_SUPPORT`: Defaulting to classical negotiation does not prove a server has zero PQC support on other groups.
- `PROBED_UNSUPPORTED != PROVEN_NO_PQC_SUPPORT`: Rejection of `X25519MLKEM768` documents specific rejection of that group, not absence of other PQC implementations.
- **Zero Double Counting**: Exactly ONE finding is generated for TLS Key Establishment across all risk layers.

### C. Subprocess Security Hardening
- Direct TCP connection strictly to the validated IP (`-connect IP:PORT`) preventing DNS rebinding.
- Hostname strictly preserved for Server Name Indication (`-servername HOSTNAME`).
- `shell=False`, argument list invocation, immediate stdin closing (`input=b""`), and bounded execution timeout (8.0s).
- Passive by default (`probe_pqc=False`). If `probe_pqc=True`, executes at most **ONE** controlled probe.

---

## 5. Quantum Readiness Score Formula

We use ONE unambiguous product metric: **Quantum Readiness Score (0–100)**:
- **0 = Extremely Poor Quantum Readiness**
- **100 = Excellent Quantum Readiness**
- **Higher score strictly indicates better readiness**

$$\text{Readiness Score} = \text{round}\left(0.30 \times S_{\text{cert}} + 0.30 \times S_{\text{kx}} + 0.20 \times S_{\text{sym}} + 0.10 \times S_{\text{hash}} + 0.10 \times S_{\text{proto}}\right)$$

| Cryptographic Role | Weight | Evaluated Components & Standards | Typical Score |
| :--- | :--- | :--- | :--- |
| **Certificate & Digital Signatures** | 30% | Leaf public key (RSA/ECC) evaluated against Shor's algorithm $\to$ **NIST FIPS 204 (ML-DSA)** / **FIPS 205 (SLH-DSA)** | Classical RSA/ECC = 60; Weak <2048 = 20; PQC = 100 |
| **Key Establishment** | 30% | Key exchange evaluated against Store Now, Decrypt Later (SNDL) $\to$ **NIST FIPS 203 (ML-KEM-768)** | TLS 1.3 unobservable = 70; TLS 1.2 ECDHE = 50; Static RSA = 15; Hybrid KEM = 100 |
| **Symmetric Encryption** | 20% | Bulk cipher evaluated against Grover's algorithm $\to$ **AES-256-GCM** | AES-256 / ChaCha20 = 100; AES-128 = 65; Deprecated = 0 |
| **Hashing & Integrity** | 10% | Collision resistance under BHT quantum search $\to$ **SHA-384** / **SHA-256** | SHA-384/512 = 100; SHA-256 = 90; SHA-1/MD5 = 0 |
| **TLS Configuration** | 10% | Protocol architecture support for post-quantum hybrid extensions $\to$ **RFC 8446 (TLS 1.3)** | TLS 1.3 = 100; TLS 1.2 = 65; Legacy = 0 |

---

## 4. Representative Banking Systems & Configuration Evidence Model (Phase 4A)

QuantumShield provides a normalized representation of representative financial institution systems, their multi-layer security architecture, explicit evidence provenance, key-protection chains, and structured evidence gaps.

> **DISCLAIMER:**  
> QuantumShield's banking profiles are representative synthetic environments used to demonstrate security auditing and migration prioritization. They do not represent the actual architecture or configuration of any specific bank.

### A. Normalized Banking Architecture Layers
Security controls are classified into 5 architectural layers:
- `EDGE`: Public perimeter, reverse proxies, and ingress load balancers.
- `API_GATEWAY`: Perimeter API termination, client mutual TLS (mTLS), and token validation.
- `SERVICE_TO_SERVICE`: Internal microservice communication, service mesh (Istio/Envoy SPIFFE/SPIRE).
- `DATA_AND_KEYS`: Database payload encryption at rest, Key Wrapping (KEK), and Hardware Security Modules (HSM / Cloud KMS).
- `ADMINISTRATIVE`: Privileged access management, hardware security key MFA (FIDO2), and bastion ingress.

### B. Key Protection Chain
Cryptographic key protection is traced through a 4-tier chain:
$$\text{Data Encryption} \longrightarrow \text{Key Wrapping} \longrightarrow \text{Key Storage} \longrightarrow \text{Root Authentication}$$
- Example Classical: `AES-256-GCM` $\to$ `RSA-2048` $\to$ `HSM` $\to$ `RSA-2048`
- Example Post-Quantum Hybrid: `AES-256-GCM` $\to$ `ML-KEM-768` $\to$ `HSM (FIPS 140-3 Level 3)` $\to$ `ECDSA-P256`

### C. Explicit Evidence Provenance
Every control or finding maintains provenance tracking:
- `EXTERNAL_SCAN`: Directly observed or probed via TLS/X.509 handshake telemetry.
- `OPERATOR_DECLARED`: Declared by system operators or compliance officers.
- `CONFIGURATION_FILE`: Extracted from verified configuration manifests or IaC templates.
- `INFERRED`: Derived from protocol constraints and handshake metadata.

### D. Structured Evidence Gaps & Core Audit Invariant
$$\mathbf{NOT\_OBSERVABLE} \neq \mathbf{VULNERABLE} \quad \text{and} \quad \mathbf{NOT\_OBSERVABLE} \neq \mathbf{FAILED\_CONTROL}$$
Internal controls such as pod-to-pod mTLS, database column-level encryption, KMS key rotation policies, or physical ATM hardware attestation cannot be determined externally. QuantumShield treats these as **evidence gaps** requiring internal audit telemetry, never as vulnerabilities.

### E. Synthetic Banking System Profiles
1. **Modern Payment Gateway** (`BANK-PROF-PAYMENT-GATEWAY`): High-throughput cardholder operations, TLS 1.3 + hybrid PQC (`X25519MLKEM768`), Thales payShield HSM, FIPS 140-3 Level 3.
2. **Legacy Core Banking** (`BANK-PROF-CORE-BANKING`): High-value accounting ledger, IBM z/OS mainframe, legacy TLS 1.2, RSA-2048 key exchange and certificates, 30-year SNDL exposure.
3. **Customer & KYC Records Vault** (`BANK-PROF-KYC-DB`): Sensitive customer PII/KYC repository, internal VPC, Oracle TDE AES-256, Cloud KMS, 25-year lifetime.
4. **Retail Net Banking Portal** (`BANK-PROF-NET-BANKING`): Customer-facing web banking interface, TLS 1.3, ECDSA-P256, FIDO2 MFA, Internet DMZ.
5. **ATM Transaction Processing Network** (`BANK-PROF-ATM-NETWORK`): ISO 8583 switch and terminal fleet, dedicated leased lines, Triple DES (3DES) key wrapping, hardware PIN pads.

---

- **Backend**: Python 3.13, FastAPI, `cryptography` (pyca), `certifi`, Pydantic v2, `pytest`, `pytest-asyncio`, `httpx`
- **Frontend**: React 19, TypeScript, Vite, Tailwind CSS v4, Lucide React
- **Architecture**: Stateless REST API + Modern Cyber Dashboard

---

## 7. Running the Platform Locally

### Backend Setup:
```bash
# Navigate to backend and install dependencies
cd backend
pip install -r requirements.txt

# Start backend server
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
API docs available at: `http://127.0.0.1:8000/docs`

### Frontend Setup:
```bash
# Navigate to frontend and install dependencies
cd frontend
npm install

# Start Vite development server
npm run dev
```
Dashboard available at: `http://127.0.0.1:5173`

---

## 8. Running the Automated Test Suite

```bash
# Run all unit, integration, and security regression tests
pytest
```

Includes **176 passing unit, integration, and security tests** covering:
- Representative Banking System Profiles, architecture layers, and synthetic catalog (`app.models.profiles`)
- Multi-tier Key Protection Chains (`KeyProtectionChain`: Data Encryption -> Key Wrapping -> Key Storage -> Authentication)
- Explicit Evidence Provenance tracking (`EvidenceSource`: EXTERNAL_SCAN, OPERATOR_DECLARED, CONFIGURATION_FILE, INFERRED)
- Standardized Evidence Gaps and core invariant enforcement (`NOT_OBSERVABLE != VULNERABLE`)
- Banking profile catalog API endpoints (`GET /api/banking/profiles`, `GET /api/banking/profiles/{id}`)
- Telemetry integrity: associating banking asset context without modifying observed TLS scan facts
- TLS 1.3 KeyShare group observation and hybrid PQC capability probing (`app.scanners.tls13_pqc`)
- OpenSSL discovery, version validation, and subprocess security hardening (direct IP connect, SNI preservation, bounded timeout)
- Group catalog parsing and normalization (`X25519MLKEM768`, `X448MLKEM1024`, `SecP256r1MLKEM768`, etc.)
- Five explicit evidence states: `OBSERVED`, `CAPABILITY_PROBED`, `CLASSICAL_ONLY_OBSERVED`, `PROBED_UNSUPPORTED`, `NOT_OBSERVABLE`
- Core invariant enforcement: `NOT_OBSERVABLE != VULNERABLE`, `CLASSICAL_ONLY_OBSERVED != PROVEN_NO_PQC_SUPPORT`, `PROBED_UNSUPPORTED != PROVEN_NO_PQC_SUPPORT`
- Zero double counting: exactly ONE finding generated for TLS Key Establishment
- Banking asset models, business criticality, data sensitivity, exposure, lifetime, and trust zones
- Unified Audit Layer models and evidence mapping (`AuditFinding`, `ObservabilityState`, `AuditDomain.QUANTUM_SECURITY`)
- Zero Trust Architecture domain modeling (6 NIST SP 800-207 pillars)
- Multidimensional risk separation (quantum risk, classical risk, zero trust, asset criticality)
- Network security & SSRF prevention (RFC 1918, loopback, link-local, cloud metadata, multicast, reserved)
- Mixed DNS response rejection & DNS rebinding defenses
- SNI preservation during direct IP connection
- Strict input validation (rejection of schemes, paths, queries, ports, IP literals)
- Bounded connect (5.0s) & TLS handshake (8.0s) timeouts
- In-memory rate limiting (10 scans/min) & bounded concurrency (5 concurrent scans)
- Safe error disclosure without leaking internal IPs or stack traces
- X.509 certificate parsing (RSA, ECDSA curves, Ed25519, expired certs, trust chains)
- Cryptographic normalization (TLS 1.2 vs TLS 1.3, AES-128 vs AES-256)
- Deterministic Quantum Risk Engine & Readiness Scoring (0–100)
- FastAPI endpoints (`/api/scan`, `/api/audit`, `/api/health`) and contract verification

---

## 9. Standards Alignment

- **NIST FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM / Kyber)
- **NIST FIPS 204**: Module-Lattice-Based Digital Signature Standard (ML-DSA / Dilithium)
- **NIST FIPS 205**: Stateless Hash-Based Digital Signature Standard (SLH-DSA / SPHINCS+)
- **IETF RFC 9870**: Post-Quantum Hybrid Key Exchange in TLS 1.3
- **NSA CNSA 2.0**: Commercial National Security Algorithm Suite 2.0 (AES-256, SHA-384)
