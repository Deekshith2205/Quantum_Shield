"""TLS 1.3 Key-Exchange & Hybrid Post-Quantum Cryptography (PQC) Observation Module.
Phase 3B - Production TLS 1.3 PQC Scanner

Provides secure, non-invasive observation and controlled capability probing
of TLS 1.3 KeyShare groups (e.g. X25519MLKEM768, SecP256r1MLKEM768, X25519).

Security Invariants:
- SSRF Immunity: Connects strictly to validated IP addresses, preserving domain for SNI.
- Subprocess Hardening: shell=False, argument lists only, stdin closed immediately, bounded timeout (8s).
- Bounded Probing: probe_pqc is False by default. If True, executes at most ONE probe offering X25519MLKEM768.
- Non-Invasive: No arbitrary group brute forcing, no penetration testing.
- Observability Invariants:
  - NOT_OBSERVABLE != VULNERABLE
  - CLASSICAL_ONLY_OBSERVED != PROVEN_NO_PQC_SUPPORT
  - PROBED_UNSUPPORTED != PROVEN_NO_PQC_SUPPORT
"""

import os
import shutil
import subprocess
import logging
from typing import Optional, Dict, Any, Tuple

from app.schemas.scan import PqcKeyExchangeEvidence

logger = logging.getLogger("quantumshield.pqc")

# Standard hybrid and classical group definitions
HYBRID_GROUPS: Dict[str, Dict[str, str]] = {
    "X25519MLKEM768": {"classical": "X25519", "pqc": "ML-KEM-768"},
    "X25519_MLKEM768": {"classical": "X25519", "pqc": "ML-KEM-768"},
    "X448MLKEM1024": {"classical": "X448", "pqc": "ML-KEM-1024"},
    "X448_MLKEM1024": {"classical": "X448", "pqc": "ML-KEM-1024"},
    "SECP256R1MLKEM768": {"classical": "P-256", "pqc": "ML-KEM-768"},
    "SECP256R1_MLKEM768": {"classical": "P-256", "pqc": "ML-KEM-768"},
    "P-256-MLKEM768": {"classical": "P-256", "pqc": "ML-KEM-768"},
    "SECP384R1MLKEM1024": {"classical": "P-384", "pqc": "ML-KEM-1024"},
    "SECP384R1_MLKEM1024": {"classical": "P-384", "pqc": "ML-KEM-1024"},
    "P-384-MLKEM1024": {"classical": "P-384", "pqc": "ML-KEM-1024"},
}

CLASSICAL_GROUPS: Dict[str, str] = {
    "X25519": "X25519",
    "P-256": "P-256",
    "SECP256R1": "P-256",
    "PRIME256V1": "P-256",
    "P-384": "P-384",
    "SECP384R1": "P-384",
    "P-521": "P-521",
    "SECP521R1": "P-521",
    "X448": "X448",
}


def find_openssl_executable() -> Optional[str]:
    """
    Locates an OpenSSL executable capable of TLS 1.3 KeyShare inspection.
    Follows strict priority:
    1. QUANTUMSHIELD_OPENSSL_PATH or OPENSSL_BIN env var
    2. shutil.which("openssl")
    3. Allowlisted standard binary paths (Windows & Unix)
    """
    env_bin = os.environ.get("QUANTUMSHIELD_OPENSSL_PATH") or os.environ.get("OPENSSL_BIN")
    if env_bin and os.path.isfile(env_bin) and os.access(env_bin, os.X_OK):
        return env_bin

    which_bin = shutil.which("openssl")
    candidate_paths = [
        which_bin,
        r"C:\Program Files\Git\mingw64\bin\openssl.exe",
        r"C:\Program Files\Git\usr\bin\openssl.exe",
        r"C:\OpenSSL-Win64\bin\openssl.exe",
        r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
        "/usr/bin/openssl",
        "/usr/local/bin/openssl",
        "/opt/homebrew/bin/openssl",
    ]

    for path in candidate_paths:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    return None


def parse_group_components(group_name: str) -> Tuple[Optional[str], Optional[str], bool]:
    """
    Deconstructs a TLS 1.3 KeyShare group name into classical and PQC components.
    Returns: (classical_component, pqc_component, is_hybrid)
    """
    if not group_name or group_name.strip() in ("", "Not observable", "UNKNOWN"):
        return None, None, False

    clean = group_name.strip()
    upper = clean.upper()

    # Direct match in hybrid catalog
    if upper in HYBRID_GROUPS:
        entry = HYBRID_GROUPS[upper]
        return entry["classical"], entry["pqc"], True

    # General hybrid pattern check (e.g. custom or novel combinations)
    if any(k in upper for k in ("MLKEM", "ML-KEM", "KYBER")):
        classical = "X25519" if "X25519" in upper else ("P-256" if ("P-256" in upper or "SECP256" in upper) else "Classical ECDHE")
        pqc = "ML-KEM-1024" if ("1024" in upper) else "ML-KEM-768"
        return classical, pqc, True

    # Direct match in classical catalog
    if upper in CLASSICAL_GROUPS:
        return CLASSICAL_GROUPS[upper], None, False

    # Check FFDHE / finite field Diffie-Hellman
    if "FFDHE" in upper:
        return "FFDHE", None, False

    return clean, None, False


def parse_openssl_brief_output(output_text: str) -> Dict[str, Any]:
    """
    Parses `openssl s_client -brief` stdout and stderr.
    Extracts protocol, cipher, negotiated TLS 1.3 group, and error indicators.
    """
    tls_version = "UNKNOWN"
    ciphersuite = "UNKNOWN"
    negotiated_group = "Not observable"
    is_handshake_failure = False

    lower_text = output_text.lower()
    if (
        "handshake failure" in lower_text
        or "alert handshake failure" in lower_text
        or "internal error" in lower_text
        or "no shared cipher" in lower_text
        or "unknown protocol" in lower_text
    ):
        is_handshake_failure = True

    for line in output_text.splitlines():
        line = line.strip()
        if line.startswith("Protocol version:"):
            tls_version = line.split(":", 1)[1].strip()
        elif line.startswith("Ciphersuite:"):
            ciphersuite = line.split(":", 1)[1].strip()
        elif line.startswith("Negotiated TLS1.3 group:"):
            negotiated_group = line.split(":", 1)[1].strip()
        elif line.startswith("Peer Temp Key:") and negotiated_group == "Not observable":
            # In TLS 1.3 / OpenSSL brief output, peer temp key often carries the negotiated curve/group
            key_part = line.split(":", 1)[1].strip()
            # E.g. "X25519, 253 bits" or "ECDH, P-256, 256 bits"
            parts = [p.strip() for p in key_part.split(",")]
            for part in parts:
                if part.upper() in CLASSICAL_GROUPS or part.upper() in HYBRID_GROUPS:
                    negotiated_group = part
                    break
            if negotiated_group == "Not observable" and len(parts) > 0 and not parts[0].isdigit():
                negotiated_group = parts[0]

    return {
        "protocol": tls_version,
        "ciphersuite": ciphersuite,
        "negotiated_group": negotiated_group,
        "is_handshake_failure": is_handshake_failure,
    }


def execute_s_client(
    openssl_bin: str,
    hostname: str,
    target_ip: str,
    port: int,
    groups: Optional[str] = None,
    timeout: float = 8.0
) -> Tuple[int, str]:
    """
    Executes openssl s_client in a hardened subprocess.
    Connects strictly to validated target_ip, domain strictly preserved as SNI.
    shell=False, bounded timeout, stdin closed via input=b"".
    """
    cmd = [
        openssl_bin,
        "s_client",
        "-connect", f"{target_ip}:{port}",
        "-servername", hostname,
        "-brief",
    ]
    if groups:
        cmd.extend(["-groups", groups])

    try:
        proc = subprocess.run(
            cmd,
            input=b"",
            capture_output=True,
            timeout=timeout,
            shell=False,
        )
        stdout_txt = proc.stdout.decode("utf-8", errors="replace")
        stderr_txt = proc.stderr.decode("utf-8", errors="replace")
        return proc.returncode, stdout_txt + "\n" + stderr_txt
    except subprocess.TimeoutExpired:
        logger.warning(f"OpenSSL s_client timed out after {timeout}s for {hostname} ({target_ip})")
        return -1, "TIMEOUT"
    except Exception as e:
        logger.error(f"OpenSSL execution error for {hostname}: {str(e)}")
        return -1, f"ERROR: {str(e)}"


def observe_tls13_key_exchange(
    hostname: str,
    validated_ip: str,
    port: int = 443,
    probe_pqc: bool = False,
    timeout: float = 8.0,
    openssl_path: Optional[str] = None,
) -> PqcKeyExchangeEvidence:
    """
    Observes the negotiated TLS 1.3 KeyShare group and optionally probes
    hybrid post-quantum capability.

    Five explicit evidence states returned:
    - OBSERVED: Group observed passively in default handshake (classical or hybrid).
    - CAPABILITY_PROBED: Hybrid group successfully negotiated during active capability probe.
    - CLASSICAL_ONLY_OBSERVED: Default handshake negotiated a classical group (e.g. X25519) and no probe was requested.
    - PROBED_UNSUPPORTED: Target rejected active probe offering X25519MLKEM768.
    - NOT_OBSERVABLE: Tooling unavailable, timeout, or TLS 1.3 KeyShare unexposed.
    """
    openssl_bin = openssl_path or find_openssl_executable()
    if not openssl_bin:
        return PqcKeyExchangeEvidence(
            raw_group="Not observable",
            status="NOT_OBSERVABLE",
            source="Client TLS API",
            confidence="NONE",
            probe_attempted=False,
            details="OpenSSL binary supporting TLS 1.3 KeyShare inspection not found in environment.",
        )

    # Step 1: Passive Observation Handshake (Default Client Configuration)
    retcode, output = execute_s_client(
        openssl_bin,
        hostname=hostname,
        target_ip=validated_ip,
        port=port,
        groups=None,
        timeout=timeout,
    )

    if output == "TIMEOUT":
        return PqcKeyExchangeEvidence(
            raw_group="Not observable",
            status="NOT_OBSERVABLE",
            source="OpenSSL TLS 1.3 Telemetry",
            confidence="NONE",
            probe_attempted=False,
            details=f"Observation timed out after {timeout} seconds.",
        )

    parsed = parse_openssl_brief_output(output)

    if parsed["is_handshake_failure"] or parsed["negotiated_group"] == "Not observable":
        # If default handshake failed or group was unexposed
        return PqcKeyExchangeEvidence(
            raw_group="Not observable",
            status="NOT_OBSERVABLE",
            source="OpenSSL TLS 1.3 Telemetry",
            confidence="LOW",
            probe_attempted=False,
            details="Handshake did not expose negotiated KeyShare group.",
        )

    raw_group = parsed["negotiated_group"]
    classical_comp, pqc_comp, is_hybrid = parse_group_components(raw_group)

    # If the default negotiation already selected a hybrid PQC group
    if is_hybrid:
        return PqcKeyExchangeEvidence(
            raw_group=raw_group,
            status="OBSERVED",
            classical_component=classical_comp,
            pqc_component=pqc_comp,
            is_hybrid=True,
            source="OpenSSL TLS 1.3 KeyShare Handshake",
            confidence="HIGH",
            probe_attempted=False,
            details=f"Default TLS 1.3 handshake negotiated hybrid group {raw_group} ({classical_comp} + {pqc_comp}).",
        )

    # Server negotiated a classical group by default (e.g. X25519, P-256)
    if not probe_pqc:
        return PqcKeyExchangeEvidence(
            raw_group=raw_group,
            status="CLASSICAL_ONLY_OBSERVED",
            classical_component=classical_comp,
            pqc_component=None,
            is_hybrid=False,
            source="OpenSSL TLS 1.3 KeyShare Handshake",
            confidence="HIGH",
            probe_attempted=False,
            details=(
                f"Default TLS 1.3 handshake negotiated classical group {raw_group}. "
                "Active PQC capability probe was not requested."
            ),
        )

    # Step 2: Controlled Active Capability Probe (Offering X25519MLKEM768)
    probe_group = "X25519MLKEM768"
    probe_retcode, probe_output = execute_s_client(
        openssl_bin,
        hostname=hostname,
        target_ip=validated_ip,
        port=port,
        groups=probe_group,
        timeout=timeout,
    )

    if probe_output == "TIMEOUT":
        return PqcKeyExchangeEvidence(
            raw_group=raw_group,
            status="CLASSICAL_ONLY_OBSERVED",
            classical_component=classical_comp,
            pqc_component=None,
            is_hybrid=False,
            source="OpenSSL TLS 1.3 KeyShare Handshake",
            confidence="MEDIUM",
            probe_attempted=True,
            requested_group=probe_group,
            probe_result="TIMEOUT",
            details="Active PQC capability probe timed out; retaining classical observed group.",
        )

    probe_parsed = parse_openssl_brief_output(probe_output)

    if not probe_parsed["is_handshake_failure"] and (
        "MLKEM" in probe_parsed["negotiated_group"].upper()
        or probe_parsed["negotiated_group"] == probe_group
    ):
        # Target accepted hybrid group!
        pqc_classical, pqc_name, _ = parse_group_components(probe_parsed["negotiated_group"])
        return PqcKeyExchangeEvidence(
            raw_group=probe_parsed["negotiated_group"],
            status="CAPABILITY_PROBED",
            classical_component=pqc_classical or "X25519",
            pqc_component=pqc_name or "ML-KEM-768",
            is_hybrid=True,
            source="Active TLS 1.3 KeyShare Probe",
            confidence="HIGH",
            probe_attempted=True,
            requested_group=probe_group,
            probe_result="ACCEPTED",
            details=f"Target accepted hybrid post-quantum group {probe_group} when offered in ClientHello.",
        )
    else:
        # Target rejected or does not support X25519MLKEM768
        return PqcKeyExchangeEvidence(
            raw_group=raw_group,
            status="PROBED_UNSUPPORTED",
            classical_component=classical_comp,
            pqc_component=None,
            is_hybrid=False,
            source="Active TLS 1.3 KeyShare Probe",
            confidence="HIGH",
            probe_attempted=True,
            requested_group=probe_group,
            probe_result="REJECTED_UNSUPPORTED",
            details=(
                f"Target rejected TLS 1.3 hybrid group {probe_group} (handshake failure). "
                f"Retaining default classical group {raw_group}."
            ),
        )

