"""X.509 Certificate Parser for QuantumShield.
Extracts cryptographic metadata, public key specifications, signature algorithms,
validity periods, and certificate chain details.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
import hashlib

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa, dh


CURVE_NAME_MAP = {
    "secp256r1": "NIST P-256 (prime256v1)",
    "secp384r1": "NIST P-384",
    "secp521r1": "NIST P-521",
    "secp256k1": "secp256k1 (Koblitz)",
    "prime256v1": "NIST P-256 (prime256v1)",
    "x25519": "X25519",
    "x448": "X448",
    "ed25519": "Ed25519",
    "ed448": "Ed448",
}


def normalize_curve_name(raw_name: Optional[str]) -> Optional[str]:
    if not raw_name:
        return None
    cleaned = raw_name.lower().replace("-", "").replace("_", "")
    for k, v in CURVE_NAME_MAP.items():
        if k.replace("-", "").replace("_", "") == cleaned:
            return v
    return raw_name


def parse_der_certificate(der_bytes: bytes) -> Dict[str, Any]:
    """
    Parses raw DER certificate bytes into a structured dictionary of cryptographic properties.
    """
    cert = x509.load_der_x509_certificate(der_bytes)
    return parse_x509_certificate_object(cert, der_bytes)


def parse_x509_certificate_object(cert: x509.Certificate, raw_der: Optional[bytes] = None) -> Dict[str, Any]:
    """
    Extracts all observable cryptographic and organizational parameters from a cryptography.x509.Certificate.
    """
    # 1. Subject & Issuer extraction
    subject_cn = None
    subject_org = None
    for attr in cert.subject:
        if attr.oid == NameOID.COMMON_NAME:
            subject_cn = attr.value
        elif attr.oid == NameOID.ORGANIZATION_NAME:
            subject_org = attr.value

    issuer_cn = None
    issuer_org = None
    for attr in cert.issuer:
        if attr.oid == NameOID.COMMON_NAME:
            issuer_cn = attr.value
        elif attr.oid == NameOID.ORGANIZATION_NAME:
            issuer_org = attr.value

    # 2. Subject Alternative Names (SANs)
    sans: List[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = [str(name.value) for name in san_ext.value]
    except x509.ExtensionNotFound:
        sans = []

    # 3. Validity & Expiration
    now = datetime.now(timezone.utc)
    # Ensure timezone awareness
    not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)

    is_expired = now > not_after
    days_remaining = (not_after - now).days

    # 4. Fingerprint & Serial
    der_data = raw_der if raw_der is not None else cert.public_bytes(serialization.Encoding.DER)
    sha256_hash = hashlib.sha256(der_data).hexdigest().upper()
    fingerprint_formatted = ":".join(sha256_hash[i:i+2] for i in range(0, len(sha256_hash), 2))
    serial_hex = format(cert.serial_number, "X")

    # 5. Public Key extraction
    pubkey = cert.public_key()
    pubkey_algo, key_size, curve_name = extract_public_key_details(pubkey)

    # 6. Signature Algorithm extraction
    sig_algo_oid = cert.signature_algorithm_oid._name
    sig_hash_name = None
    if cert.signature_hash_algorithm:
        sig_hash_name = cert.signature_hash_algorithm.name.upper()

    return {
        "subject_cn": subject_cn,
        "subject_org": subject_org,
        "subject_alt_names": sans,
        "issuer_cn": issuer_cn,
        "issuer_org": issuer_org,
        "serial_number": serial_hex,
        "fingerprint_sha256": fingerprint_formatted,
        "not_valid_before": not_before.isoformat(),
        "not_valid_after": not_after.isoformat(),
        "days_remaining": days_remaining,
        "is_expired": is_expired,
        "public_key_algorithm": pubkey_algo,
        "key_size_bits": key_size,
        "curve_name": curve_name,
        "signature_algorithm": sig_algo_oid,
        "signature_hash_algorithm": sig_hash_name,
    }


def extract_public_key_details(pubkey: Any) -> Tuple[str, Optional[int], Optional[str]]:
    """
    Extracts (algorithm_family, key_size_bits, curve_name) from asymmetric public key object.
    """
    if isinstance(pubkey, rsa.RSAPublicKey):
        return "RSA", pubkey.key_size, None

    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        raw_curve = pubkey.curve.name
        normalized = normalize_curve_name(raw_curve)
        return "ECC", pubkey.key_size, normalized

    if isinstance(pubkey, ed25519.Ed25519PublicKey):
        return "EdDSA", 256, "Ed25519"

    if isinstance(pubkey, ed448.Ed448PublicKey):
        return "EdDSA", 456, "Ed448"

    if isinstance(pubkey, dsa.DSAPublicKey):
        return "DSA", pubkey.key_size, None

    if isinstance(pubkey, dh.DHPublicKey):
        return "Diffie-Hellman", pubkey.key_size, None

    # Fallback for future PQC or unknown types
    class_name = pubkey.__class__.__name__
    return class_name, getattr(pubkey, "key_size", None), None


def parse_certificate_chain(chain_der_list: List[bytes]) -> List[Dict[str, Any]]:
    """
    Parses a list of DER-encoded certificates representing the trust chain.
    """
    summaries = []
    for der in chain_der_list:
        try:
            parsed = parse_der_certificate(der)
            summaries.append({
                "subject_cn": parsed.get("subject_cn"),
                "issuer_cn": parsed.get("issuer_cn"),
                "public_key_algorithm": parsed.get("public_key_algorithm"),
                "key_size_bits": parsed.get("key_size_bits"),
                "curve_name": parsed.get("curve_name"),
                "signature_algorithm": parsed.get("signature_algorithm"),
                "fingerprint_sha256": parsed.get("fingerprint_sha256"),
                "not_valid_after": parsed.get("not_valid_after"),
            })
        except Exception:
            continue
    return summaries
