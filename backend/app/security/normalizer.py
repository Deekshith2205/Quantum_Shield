"""Cryptographic Normalization Engine.
Translates raw observed TLS parameters and X.509 certificate data into
standardized, normalized cryptographic mechanism representations.
Strictly distinguishes between 'OBSERVED', 'INFERRED', and 'NOT_OBSERVABLE'.
"""

from typing import Dict, Any, List, Tuple
from app.schemas.scan import NormalizedCryptoMechanism


def normalize_cryptographic_mechanisms(
    certificate_data: Dict[str, Any],
    tls_data: Dict[str, Any]
) -> Tuple[List[NormalizedCryptoMechanism], List[str]]:
    """
    Normalizes observed certificate and TLS parameters into standardized cryptographic records.
    Every mechanism strictly documents:
    - role: Cryptographic function (e.g. Certificate Public Key, Key Exchange, etc.)
    - value: Concrete algorithm or 'Not observable'
    - source: Observable origin (e.g. TLS Leaf Certificate, TLS Negotiated Cipher Suite)
    - evidence: OBSERVED, INFERRED, or NOT_OBSERVABLE
    """
    mechanisms: List[NormalizedCryptoMechanism] = []

    # -------------------------------------------------------------
    # 1. Certificate Public Key (OBSERVED directly from leaf certificate)
    # -------------------------------------------------------------
    pubkey_algo = certificate_data.get("public_key_algorithm") or "UNKNOWN"
    key_size = certificate_data.get("key_size_bits")
    curve_name = certificate_data.get("curve_name")

    if pubkey_algo == "RSA":
        algo_name = f"RSA-{key_size}" if key_size else "RSA"
        raw_val = f"RSAPublicKey (modulus size: {key_size} bits)"
        mechanisms.append(
            NormalizedCryptoMechanism(
                role="Certificate Public Key",
                value=algo_name,
                source="TLS Leaf Certificate (SubjectPublicKeyInfo)",
                evidence="OBSERVED",
                component="certificate_public_key",
                algorithm_family="RSA",
                algorithm_name=algo_name,
                category="public_key",
                key_size=key_size,
                curve=None,
                observability="OBSERVED",
                evidence_source="TLS Leaf Certificate (SubjectPublicKeyInfo)",
                raw_observed_value=raw_val,
            )
        )
    elif pubkey_algo in ("ECC", "EllipticCurvePublicKey"):
        curve_label = curve_name or "Unknown Curve"
        algo_name = f"ECDSA ({curve_label})"
        raw_val = f"ECPublicKey (curve: {curve_label}, size: {key_size} bits)"
        mechanisms.append(
            NormalizedCryptoMechanism(
                role="Certificate Public Key",
                value=algo_name,
                source="TLS Leaf Certificate (SubjectPublicKeyInfo)",
                evidence="OBSERVED",
                component="certificate_public_key",
                algorithm_family="ECC",
                algorithm_name=algo_name,
                category="public_key",
                key_size=key_size,
                curve=curve_name,
                observability="OBSERVED",
                evidence_source="TLS Leaf Certificate (SubjectPublicKeyInfo)",
                raw_observed_value=raw_val,
            )
        )
    elif pubkey_algo in ("EdDSA", "Ed25519", "Ed448"):
        algo_name = curve_name or pubkey_algo
        raw_val = f"EdDSAPublicKey ({algo_name})"
        mechanisms.append(
            NormalizedCryptoMechanism(
                role="Certificate Public Key",
                value=algo_name,
                source="TLS Leaf Certificate (SubjectPublicKeyInfo)",
                evidence="OBSERVED",
                component="certificate_public_key",
                algorithm_family="EdDSA",
                algorithm_name=algo_name,
                category="public_key",
                key_size=key_size,
                curve=curve_name,
                observability="OBSERVED",
                evidence_source="TLS Leaf Certificate (SubjectPublicKeyInfo)",
                raw_observed_value=raw_val,
            )
        )
    else:
        mechanisms.append(
            NormalizedCryptoMechanism(
                role="Certificate Public Key",
                value=pubkey_algo,
                source="TLS Leaf Certificate (SubjectPublicKeyInfo)",
                evidence="OBSERVED",
                component="certificate_public_key",
                algorithm_family=pubkey_algo,
                algorithm_name=pubkey_algo,
                category="public_key",
                key_size=key_size,
                curve=curve_name,
                observability="OBSERVED",
                evidence_source="TLS Leaf Certificate (SubjectPublicKeyInfo)",
                raw_observed_value=f"{pubkey_algo} (size: {key_size} bits)",
            )
        )

    # -------------------------------------------------------------
    # 2. Certificate Signature Algorithm (OBSERVED directly from certificate)
    # -------------------------------------------------------------
    sig_algo = certificate_data.get("signature_algorithm") or "UNKNOWN"
    sig_family = "RSA" if "rsa" in sig_algo.lower() else ("ECC" if "ecdsa" in sig_algo.lower() else "OTHER")
    mechanisms.append(
        NormalizedCryptoMechanism(
            role="Certificate Signature",
            value=sig_algo,
            source="TLS Leaf Certificate (SignatureAlgorithm OID)",
            evidence="OBSERVED",
            component="certificate_signature",
            algorithm_family=sig_family,
            algorithm_name=sig_algo,
            category="signature",
            key_size=None,
            curve=None,
            observability="OBSERVED",
            evidence_source="TLS Leaf Certificate (SignatureAlgorithm OID)",
            raw_observed_value=sig_algo,
        )
    )

    # -------------------------------------------------------------
    # 3. TLS Key Exchange (Distinguish TLS 1.2 vs TLS 1.3)
    # -------------------------------------------------------------
    cipher_name = tls_data.get("negotiated_cipher") or ""
    protocol = tls_data.get("negotiated_protocol") or ""
    pqc_ev = tls_data.get("pqc_evidence")

    if protocol == "TLSv1.3":
        # In TLS 1.3 (RFC 8446), key exchange is decoupled from cipher suites and negotiated
        # in the KeyShare extension. If OpenSSL telemetry or active probing provided verified group
        # observation, normalize accordingly; otherwise default strictly to NOT_OBSERVABLE.
        pqc_status = "NOT_OBSERVABLE"
        pqc_raw_group = "Not observable"
        is_hybrid = False
        classical_comp = None
        pqc_comp = None
        pqc_source = "TLS 1.3 Handshake (KeyShare group not exposed by client API)"

        if pqc_ev:
            if isinstance(pqc_ev, dict):
                pqc_status = pqc_ev.get("status") or "NOT_OBSERVABLE"
                pqc_raw_group = pqc_ev.get("raw_group") or "Not observable"
                is_hybrid = pqc_ev.get("is_hybrid", False)
                classical_comp = pqc_ev.get("classical_component")
                pqc_comp = pqc_ev.get("pqc_component")
                pqc_source = pqc_ev.get("source") or "OpenSSL TLS 1.3 KeyShare Handshake"
            else:
                pqc_status = getattr(pqc_ev, "status", "NOT_OBSERVABLE")
                pqc_raw_group = getattr(pqc_ev, "raw_group", "Not observable")
                is_hybrid = getattr(pqc_ev, "is_hybrid", False)
                classical_comp = getattr(pqc_ev, "classical_component", None)
                pqc_comp = getattr(pqc_ev, "pqc_component", None)
                pqc_source = getattr(pqc_ev, "source", "OpenSSL TLS 1.3 KeyShare Handshake")

        if pqc_status == "OBSERVED":
            algo_family = "Hybrid ML-KEM" if is_hybrid else ("ECC" if classical_comp in ("X25519", "P-256", "P-384", "P-521") else "Diffie-Hellman")
            mechanisms.append(
                NormalizedCryptoMechanism(
                    role="Key Exchange",
                    value=pqc_raw_group,
                    source=pqc_source,
                    evidence="OBSERVED",
                    component="tls_key_exchange",
                    algorithm_family=algo_family,
                    algorithm_name=pqc_raw_group,
                    category="key_exchange",
                    key_size=None,
                    curve=classical_comp,
                    observability="OBSERVED",
                    evidence_source=pqc_source,
                    raw_observed_value=f"Negotiated TLS 1.3 Group: {pqc_raw_group}",
                )
            )
        elif pqc_status == "CAPABILITY_PROBED":
            mechanisms.append(
                NormalizedCryptoMechanism(
                    role="Key Exchange",
                    value=pqc_raw_group,
                    source=pqc_source,
                    evidence="CAPABILITY_PROBED",
                    component="tls_key_exchange",
                    algorithm_family="Hybrid ML-KEM",
                    algorithm_name=pqc_raw_group,
                    category="key_exchange",
                    key_size=None,
                    curve=classical_comp,
                    observability="CAPABILITY_PROBED",
                    evidence_source=pqc_source,
                    raw_observed_value=f"Probed Hybrid KeyShare: {pqc_raw_group} (Supported)",
                )
            )
        elif pqc_status == "CLASSICAL_ONLY_OBSERVED":
            algo_family = "ECC" if classical_comp in ("X25519", "P-256", "P-384", "P-521") else "Diffie-Hellman"
            mechanisms.append(
                NormalizedCryptoMechanism(
                    role="Key Exchange",
                    value=pqc_raw_group,
                    source=pqc_source,
                    evidence="CLASSICAL_ONLY_OBSERVED",
                    component="tls_key_exchange",
                    algorithm_family=algo_family,
                    algorithm_name=pqc_raw_group,
                    category="key_exchange",
                    key_size=None,
                    curve=classical_comp,
                    observability="CLASSICAL_ONLY_OBSERVED",
                    evidence_source=pqc_source,
                    raw_observed_value=f"Default KeyShare: {pqc_raw_group} (Classical Only)",
                )
            )
        elif pqc_status == "PROBED_UNSUPPORTED":
            algo_family = "ECC" if classical_comp in ("X25519", "P-256", "P-384", "P-521") else "Diffie-Hellman"
            mechanisms.append(
                NormalizedCryptoMechanism(
                    role="Key Exchange",
                    value=pqc_raw_group,
                    source=pqc_source,
                    evidence="PROBED_UNSUPPORTED",
                    component="tls_key_exchange",
                    algorithm_family=algo_family,
                    algorithm_name=pqc_raw_group,
                    category="key_exchange",
                    key_size=None,
                    curve=classical_comp,
                    observability="PROBED_UNSUPPORTED",
                    evidence_source=pqc_source,
                    raw_observed_value=f"Default KeyShare: {pqc_raw_group} (X25519MLKEM768 Probe Rejected)",
                )
            )
        else:
            # Standard client socket TLS API boundary
            mechanisms.append(
                NormalizedCryptoMechanism(
                    role="Key Exchange",
                    value="Not observable",
                    source="TLS 1.3 Handshake (KeyShare group not exposed by client API)",
                    evidence="NOT_OBSERVABLE",
                    component="tls_key_exchange",
                    algorithm_family="UNKNOWN",
                    algorithm_name="Not observable",
                    category="key_exchange",
                    key_size=None,
                    curve=None,
                    observability="NOT_OBSERVABLE",
                    evidence_source="TLS 1.3 Handshake (KeyShare group not exposed by client API)",
                    raw_observed_value="Not observable via standard client TLS API",
                )
            )
    elif "ECDHE" in cipher_name.upper():
        mechanisms.append(
            NormalizedCryptoMechanism(
                role="Key Exchange",
                value="ECDHE",
                source="TLS 1.2 Negotiated Cipher Suite prefix (ECDHE)",
                evidence="OBSERVED",
                component="tls_key_exchange",
                algorithm_family="ECC",
                algorithm_name="ECDHE",
                category="key_exchange",
                key_size=None,
                curve=None,
                observability="OBSERVED",
                evidence_source="TLS 1.2 Negotiated Cipher Suite prefix (ECDHE)",
                raw_observed_value=cipher_name,
            )
        )
    elif "DHE" in cipher_name.upper() or "EDH" in cipher_name.upper():
        mechanisms.append(
            NormalizedCryptoMechanism(
                role="Key Exchange",
                value="DHE",
                source="TLS 1.2 Negotiated Cipher Suite prefix (DHE)",
                evidence="OBSERVED",
                component="tls_key_exchange",
                algorithm_family="Diffie-Hellman",
                algorithm_name="DHE",
                category="key_exchange",
                key_size=None,
                curve=None,
                observability="OBSERVED",
                evidence_source="TLS 1.2 Negotiated Cipher Suite prefix (DHE)",
                raw_observed_value=cipher_name,
            )
        )
    elif cipher_name.upper().startswith("RSA_") or "AES" in cipher_name.upper() and not any(k in cipher_name.upper() for k in ("ECDHE", "DHE")):
        mechanisms.append(
            NormalizedCryptoMechanism(
                role="Key Exchange",
                value="Static RSA",
                source="TLS 1.2 Negotiated Cipher Suite prefix (Static RSA)",
                evidence="OBSERVED",
                component="tls_key_exchange",
                algorithm_family="RSA",
                algorithm_name="Static RSA",
                category="key_exchange",
                key_size=None,
                curve=None,
                observability="OBSERVED",
                evidence_source="TLS 1.2 Negotiated Cipher Suite prefix (Static RSA)",
                raw_observed_value=cipher_name,
            )
        )
    else:
        mechanisms.append(
            NormalizedCryptoMechanism(
                role="Key Exchange",
                value="Not observable",
                source="TLS Handshake (Unrecognized cipher suite key exchange prefix)",
                evidence="NOT_OBSERVABLE",
                component="tls_key_exchange",
                algorithm_family="UNKNOWN",
                algorithm_name="Not observable",
                category="key_exchange",
                key_size=None,
                curve=None,
                observability="NOT_OBSERVABLE",
                evidence_source="TLS Handshake (Unrecognized cipher suite key exchange prefix)",
                raw_observed_value=cipher_name,
            )
        )

    # -------------------------------------------------------------
    # 4. TLS Symmetric Bulk Cipher (OBSERVED from live cipher suite)
    # -------------------------------------------------------------
    cipher_upper = cipher_name.upper()
    if any(k in cipher_upper for k in ("AES_256", "AES-256", "AES256")):
        sym_name = "AES-256-GCM" if "GCM" in cipher_upper else ("AES-256-CCM" if "CCM" in cipher_upper else "AES-256")
        mechanisms.append(
            NormalizedCryptoMechanism(
                role="Symmetric Bulk Cipher",
                value=sym_name,
                source="TLS Negotiated Cipher Suite",
                evidence="OBSERVED",
                component="tls_symmetric_cipher",
                algorithm_family="AES",
                algorithm_name=sym_name,
                category="symmetric_cipher",
                key_size=256,
                curve=None,
                observability="OBSERVED",
                evidence_source="TLS Negotiated Cipher Suite",
                raw_observed_value=cipher_name,
            )
        )
    elif any(k in cipher_upper for k in ("AES_128", "AES-128", "AES128")):
        sym_name = "AES-128-GCM" if "GCM" in cipher_upper else ("AES-128-CCM" if "CCM" in cipher_upper else "AES-128")
        mechanisms.append(
            NormalizedCryptoMechanism(
                role="Symmetric Bulk Cipher",
                value=sym_name,
                source="TLS Negotiated Cipher Suite",
                evidence="OBSERVED",
                component="tls_symmetric_cipher",
                algorithm_family="AES",
                algorithm_name=sym_name,
                category="symmetric_cipher",
                key_size=128,
                curve=None,
                observability="OBSERVED",
                evidence_source="TLS Negotiated Cipher Suite",
                raw_observed_value=cipher_name,
            )
        )
    elif "CHACHA20" in cipher_upper:
        mechanisms.append(
            NormalizedCryptoMechanism(
                role="Symmetric Bulk Cipher",
                value="ChaCha20-Poly1305",
                source="TLS Negotiated Cipher Suite",
                evidence="OBSERVED",
                component="tls_symmetric_cipher",
                algorithm_family="ChaCha",
                algorithm_name="ChaCha20-Poly1305",
                category="symmetric_cipher",
                key_size=256,
                curve=None,
                observability="OBSERVED",
                evidence_source="TLS Negotiated Cipher Suite",
                raw_observed_value=cipher_name,
            )
        )
    else:
        bits = tls_data.get("cipher_bits") or 0
        mechanisms.append(
            NormalizedCryptoMechanism(
                role="Symmetric Bulk Cipher",
                value=cipher_name or "UNKNOWN",
                source="TLS Negotiated Cipher Suite",
                evidence="OBSERVED",
                component="tls_symmetric_cipher",
                algorithm_family="UNKNOWN",
                algorithm_name=cipher_name or "UNKNOWN",
                category="symmetric_cipher",
                key_size=bits if bits > 0 else None,
                curve=None,
                observability="OBSERVED",
                evidence_source="TLS Negotiated Cipher Suite",
                raw_observed_value=cipher_name,
            )
        )

    # -------------------------------------------------------------
    # 5. TLS MAC / PRF Hash (OBSERVED from live cipher suite)
    # -------------------------------------------------------------
    if "SHA384" in cipher_upper:
        mechanisms.append(
            NormalizedCryptoMechanism(
                role="Hash / MAC",
                value="SHA-384",
                source="TLS Negotiated Cipher Suite PRF",
                evidence="OBSERVED",
                component="tls_mac_hash",
                algorithm_family="SHA-2",
                algorithm_name="SHA-384",
                category="hash",
                key_size=384,
                curve=None,
                observability="OBSERVED",
                evidence_source="TLS Negotiated Cipher Suite PRF",
                raw_observed_value=cipher_name,
            )
        )
    elif "SHA256" in cipher_upper:
        mechanisms.append(
            NormalizedCryptoMechanism(
                role="Hash / MAC",
                value="SHA-256",
                source="TLS Negotiated Cipher Suite PRF",
                evidence="OBSERVED",
                component="tls_mac_hash",
                algorithm_family="SHA-2",
                algorithm_name="SHA-256",
                category="hash",
                key_size=256,
                curve=None,
                observability="OBSERVED",
                evidence_source="TLS Negotiated Cipher Suite PRF",
                raw_observed_value=cipher_name,
            )
        )
    elif "SHA" in cipher_upper and "SHA256" not in cipher_upper and "SHA384" not in cipher_upper:
        mechanisms.append(
            NormalizedCryptoMechanism(
                role="Hash / MAC",
                value="SHA-1",
                source="TLS Negotiated Cipher Suite PRF",
                evidence="OBSERVED",
                component="tls_mac_hash",
                algorithm_family="SHA-1",
                algorithm_name="SHA-1",
                category="hash",
                key_size=160,
                curve=None,
                observability="OBSERVED",
                evidence_source="TLS Negotiated Cipher Suite PRF",
                raw_observed_value=cipher_name,
            )
        )

    # -------------------------------------------------------------
    # 6. TLS Protocol Version (OBSERVED from live handshake)
    # -------------------------------------------------------------
    mechanisms.append(
        NormalizedCryptoMechanism(
            role="TLS Protocol Version",
            value=protocol,
            source="TLS Connection Handshake",
            evidence="OBSERVED",
            component="tls_protocol",
            algorithm_family="Protocol",
            algorithm_name=protocol,
            category="protocol",
            key_size=None,
            curve=None,
            observability="OBSERVED",
            evidence_source="TLS Connection Handshake",
            raw_observed_value=protocol,
        )
    )

    # -------------------------------------------------------------
    # 7. Non-Observable Scope Boundaries
    # -------------------------------------------------------------
    not_observable_notes = [
        "Internal database at-rest encryption algorithms and Key Management Services (KMS) cannot be determined externally.",
        "Application-layer token signing, JWT secret algorithms, and password hashing primitives are not observable from the TLS handshake.",
        "Backend microservice-to-microservice mutual TLS (mTLS) configurations are internal and cannot be observed from public perimeter checks.",
        "Hardware Security Module (HSM) seed entropy and quantum readiness cannot be assessed externally."
    ]

    if protocol == "TLSv1.3":
        if pqc_status == "NOT_OBSERVABLE":
            not_observable_notes.insert(0, "TLS 1.3 KeyShare group negotiation cannot be verified via standard client TLS socket APIs.")
        elif pqc_status == "CLASSICAL_ONLY_OBSERVED":
            not_observable_notes.insert(0, f"Default TLS 1.3 handshake negotiated classical group {pqc_raw_group}; active PQC capability probe was not performed.")
        elif pqc_status == "PROBED_UNSUPPORTED":
            not_observable_notes.insert(0, f"Active capability probe offering X25519MLKEM768 was rejected by server; server operates classical group {pqc_raw_group}.")

    return mechanisms, not_observable_notes
