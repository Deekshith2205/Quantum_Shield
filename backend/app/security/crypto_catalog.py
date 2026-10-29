"""Cryptographic Catalog and Post-Quantum Knowledge Base.
Defines risk classifications, quantum threat vectors (Shor vs Grover),
and NIST Post-Quantum Cryptography (PQC) standards mappings.
"""

from typing import Dict, Any, Optional
from enum import Enum


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    INFO = "INFORMATIONAL"


class QuantumThreatVector(str, Enum):
    SHOR = "Shor's Algorithm (Polynomial Speedup)"
    GROVER = "Grover's Algorithm (Quadratic Speedup)"
    SNDL = "Store Now, Decrypt Later (SNDL)"
    CLASSICAL_BROKEN = "Classically Broken & Quantum Insecure"
    RESISTANT = "Quantum Resistant (Adequate Margin)"
    POST_QUANTUM = "Post-Quantum Cryptographic Primitive"


# NIST PQC Standards Reference Catalog
PQC_STANDARDS = {
    "ML_KEM": {
        "standard": "NIST FIPS 203 (ML-KEM / Kyber)",
        "description": "Module-Lattice-Based Key-Encapsulation Mechanism for general encryption and key exchange.",
        "levels": ["ML-KEM-512 (Category 1)", "ML-KEM-768 (Category 3)", "ML-KEM-1024 (Category 5)"],
        "hybrid_target": "X25519 + ML-KEM-768 hybrid key exchange (RFC 9870 / draft-ietf-tls-hybrid-design)",
    },
    "ML_DSA": {
        "standard": "NIST FIPS 204 (ML-DSA / Dilithium)",
        "description": "Module-Lattice-Based Digital Signature Standard for identity authentication and certificates.",
        "levels": ["ML-DSA-44 (Category 2)", "ML-DSA-65 (Category 3)", "ML-DSA-87 (Category 5)"],
        "hybrid_target": "Dual-signature or composite X.509 certificates (ECDSA + ML-DSA)",
    },
    "SLH_DSA": {
        "standard": "NIST FIPS 205 (SLH-DSA / SPHINCS+)",
        "description": "Stateless Hash-Based Digital Signature Standard, stateless alternative avoiding lattice assumptions.",
        "levels": ["SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-256f"],
        "target_use": "Long-lived root CAs and firmware signing where lattice security is conservative.",
    },
    "AES_256": {
        "standard": "NIST SP 800-131A Rev 2 / CNSA 2.0",
        "description": "256-bit symmetric encryption providing ~128 bits of security against Grover's algorithm.",
    },
    "SHA_384": {
        "standard": "NIST FIPS 180-4 / CNSA 2.0",
        "description": "SHA-384 or SHA-512 provides robust collision resistance under quantum collision search algorithms.",
    }
}


# Catalog of algorithm profiles with quantum assessment metadata
ALGORITHM_CATALOG: Dict[str, Dict[str, Any]] = {
    # Asymmetric Public Key & Signatures (Shor's Algorithm)
    "RSA": {
        "family": "RSA",
        "category": "public_key",
        "threat_vector": QuantumThreatVector.SHOR.value,
        "shor_vulnerable": True,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "RSA relies on the computational difficulty of factoring large composite integers. "
            "Shor's algorithm solves prime factorization in polynomial time O((log N)^3) on a "
            "cryptanalytically relevant quantum computer (CRQC), breaking all standard RSA key sizes."
        ),
        "target_standard": PQC_STANDARDS["ML_DSA"]["standard"],
    },
    "ECC": {
        "family": "ECC",
        "category": "public_key",
        "threat_vector": QuantumThreatVector.SHOR.value,
        "shor_vulnerable": True,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "Elliptic Curve Cryptography relies on the Elliptic Curve Discrete Logarithm Problem (ECDLP). "
            "Shor's algorithm solves ECDLP in polynomial time. Standard curves (P-256, P-384, P-521) require "
            "fewer logical qubits to break than 2048-bit RSA, rendering them completely vulnerable to CRQCs."
        ),
        "target_standard": PQC_STANDARDS["ML_DSA"]["standard"],
    },
    "EdDSA": {
        "family": "EdDSA",
        "category": "public_key",
        "threat_vector": QuantumThreatVector.SHOR.value,
        "shor_vulnerable": True,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "Edwards-curve Digital Signature Algorithm (Ed25519/Ed448) is vulnerable to Shor's algorithm "
            "for elliptic curve discrete logarithms, and will be broken by a CRQC."
        ),
        "target_standard": PQC_STANDARDS["ML_DSA"]["standard"],
    },
    "Diffie-Hellman": {
        "family": "Diffie-Hellman",
        "category": "key_exchange",
        "threat_vector": QuantumThreatVector.SNDL.value,
        "shor_vulnerable": True,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "Classical Diffie-Hellman (DHE/DH) key establishment is broken by Shor's algorithm. "
            "Under 'Store Now, Decrypt Later' (SNDL), recorded ciphertexts can be decrypted retroactively."
        ),
        "target_standard": PQC_STANDARDS["ML_KEM"]["hybrid_target"],
    },
    "ECDHE": {
        "family": "ECC",
        "category": "key_exchange",
        "threat_vector": QuantumThreatVector.SNDL.value,
        "shor_vulnerable": True,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "Ephemeral Elliptic Curve Diffie-Hellman (X25519, P-256) establishes forward-secret session keys "
            "against classical adversaries, but an adversary capturing encrypted sessions today can decrypt them "
            "later using Shor's algorithm on a quantum computer (SNDL attack)."
        ),
        "target_standard": PQC_STANDARDS["ML_KEM"]["hybrid_target"],
    },

    # Symmetric Ciphers (Grover's Algorithm)
    "AES-128": {
        "family": "AES",
        "category": "symmetric_cipher",
        "threat_vector": QuantumThreatVector.GROVER.value,
        "shor_vulnerable": False,
        "grover_vulnerable": True,
        "vulnerability_explanation": (
            "Grover's algorithm provides a quadratic speedup for unstructured brute-force key search, "
            "reducing the effective security of 128-bit symmetric keys to ~64 bits. While not polynomial, "
            "a 64-bit security margin provides inadequate defense against well-resourced quantum adversaries."
        ),
        "target_standard": PQC_STANDARDS["AES_256"]["standard"],
    },
    "AES-256": {
        "family": "AES",
        "category": "symmetric_cipher",
        "threat_vector": QuantumThreatVector.RESISTANT.value,
        "shor_vulnerable": False,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "AES-256 provides 256 bits of classical security. Under Grover's quantum attack, effective "
            "brute-force resistance remains ~128 bits, which exceeds current post-quantum security requirements."
        ),
        "target_standard": "Compliant (NIST CNSA 2.0 approved)",
    },
    "ChaCha20": {
        "family": "ChaCha",
        "category": "symmetric_cipher",
        "threat_vector": QuantumThreatVector.RESISTANT.value,
        "shor_vulnerable": False,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "ChaCha20 uses a 256-bit key. Under Grover's quantum search, effective security remains "
            "~128 bits, providing solid post-quantum symmetric confidentiality."
        ),
        "target_standard": "Compliant (Quantum Resistant)",
    },

    # Hashes & MACs
    "SHA-256": {
        "family": "SHA-2",
        "category": "hash",
        "threat_vector": QuantumThreatVector.RESISTANT.value,
        "shor_vulnerable": False,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "SHA-256 provides 128-bit collision resistance classically. Quantum collision search (BHT algorithm) "
            "theoretically reduces collision search to ~2^85 operations, though quantum memory constraints make "
            "this attack extremely challenging. Suitable for standard security; transition to SHA-384 recommended for CNSA 2.0."
        ),
        "target_standard": PQC_STANDARDS["SHA_384"]["standard"],
    },
    "SHA-384": {
        "family": "SHA-2",
        "category": "hash",
        "threat_vector": QuantumThreatVector.RESISTANT.value,
        "shor_vulnerable": False,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "SHA-384 provides 192 bits of collision resistance classically and ~128 bits under quantum collision attacks, "
            "meeting the requirements of NSA Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)."
        ),
        "target_standard": "Compliant (NIST CNSA 2.0 approved)",
    },
    "SHA-512": {
        "family": "SHA-2",
        "category": "hash",
        "threat_vector": QuantumThreatVector.RESISTANT.value,
        "shor_vulnerable": False,
        "grover_vulnerable": False,
        "vulnerability_explanation": (
            "SHA-512 provides 256 bits of classical collision resistance and ~170 bits under quantum collision attacks, "
            "delivering extensive post-quantum safety margins."
        ),
        "target_standard": "Compliant (Post-Quantum Secure)",
    },
    "SHA-1": {
        "family": "SHA-1",
        "category": "hash",
        "threat_vector": QuantumThreatVector.CLASSICAL_BROKEN.value,
        "shor_vulnerable": False,
        "grover_vulnerable": True,
        "vulnerability_explanation": (
            "SHA-1 is broken classically (collision attacks demonstrated since 2017) and offers zero quantum resilience."
        ),
        "target_standard": PQC_STANDARDS["SHA_384"]["standard"],
    },
    "MD5": {
        "family": "MD5",
        "category": "hash",
        "threat_vector": QuantumThreatVector.CLASSICAL_BROKEN.value,
        "shor_vulnerable": False,
        "grover_vulnerable": True,
        "vulnerability_explanation": (
            "MD5 is severely compromised classically and must not be used in any security context."
        ),
        "target_standard": PQC_STANDARDS["SHA_384"]["standard"],
    },
}

