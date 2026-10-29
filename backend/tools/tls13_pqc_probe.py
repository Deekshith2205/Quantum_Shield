"""Proof-of-Concept TLS 1.3 Key-Exchange & Hybrid PQC Capability Probe.

Standalone investigation utility verifying whether the local OpenSSL environment can:
1. Passively observe the negotiated TLS 1.3 key-exchange group.
2. Actively probe hybrid Post-Quantum Cryptography (ML-KEM-768 / X25519MLKEM768) support.

Enforces ALL Phase 2C security invariants:
- Strict domain input validation (RFC 1035/1123).
- SSRF prevention (rejects private, loopback, link-local, cloud metadata).
- Single DNS resolution with mixed DNS rejection.
- Direct-IP TCP connection to prevent DNS rebinding.
- Strict preservation of original hostname for TLS SNI (-servername).
- Bounded subprocess execution (shell=False, argument array, 8s timeout).
"""

import sys
import os
import json
import shutil
import subprocess
import argparse
from typing import Dict, Any, Optional

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.scanners.domain_validator import normalize_domain_input, DomainValidationError
from app.security.network import resolve_and_validate_hostname, UnsafeTargetError, DnsResolutionError


def find_openssl_executable() -> Optional[str]:
    """Locates an OpenSSL executable supporting TLS 1.3."""
    candidate_paths = [
        shutil.which("openssl"),
        r"C:\Program Files\Git\mingw64\bin\openssl.exe",
        r"C:\Program Files\Git\usr\bin\openssl.exe",
        r"C:\OpenSSL-Win64\bin\openssl.exe",
        r"/usr/bin/openssl",
        r"/usr/local/bin/openssl",
    ]
    for path in candidate_paths:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def get_openssl_version_info(openssl_bin: str) -> Dict[str, Any]:
    """Inspects the local OpenSSL version and algorithm capabilities."""
    res = subprocess.run([openssl_bin, "version", "-a"], capture_output=True, text=True, timeout=5, shell=False)
    raw_version = res.stdout.splitlines()[0] if res.stdout else "UNKNOWN"

    # Check supported KEM algorithms
    kem_res = subprocess.run([openssl_bin, "list", "-kem-algorithms"], capture_output=True, text=True, timeout=5, shell=False)
    supported_kems = []
    for line in kem_res.stdout.splitlines():
        line = line.strip()
        if "ML-KEM" in line or "MLKEM" in line or "X25519MLKEM" in line:
            supported_kems.append(line.split("@")[0].strip())

    return {
        "executable": openssl_bin,
        "version_string": raw_version,
        "supports_mlkem": len(supported_kems) > 0,
        "supported_hybrid_groups": supported_kems,
    }


def probe_tls13_key_exchange(
    domain_input: str,
    port: int = 443,
    probe_group: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes a security-hardened TLS 1.3 probe against the target domain.
    """
    # 1. Strict Domain Validation (RFC 1035 / Phase 2C)
    hostname, _ = normalize_domain_input(domain_input)

    # 2. Secure DNS Resolution & SSRF Defense (One-time, mixed DNS rejection)
    resolution = resolve_and_validate_hostname(hostname, timeout_seconds=4.0)
    target_ip = resolution.selected_ip

    # 3. Locate OpenSSL Binary
    openssl_bin = find_openssl_executable()
    if not openssl_bin:
        return {
            "target": hostname,
            "target_ip": target_ip,
            "openssl_version": "NOT_FOUND",
            "tls_version": "UNKNOWN",
            "cipher": "UNKNOWN",
            "negotiated_group": "Not observable",
            "group_observation": "NOT_OBSERVABLE",
            "pqc_probe_attempted": probe_group is not None,
            "pqc_probe_result": "NOT_SUPPORTED_BY_CLIENT",
            "evidence": "NOT_SUPPORTED_BY_CLIENT",
            "note": "Local environment does not have a suitable OpenSSL executable."
        }

    version_info = get_openssl_version_info(openssl_bin)

    # 4. Construct Subprocess Arguments (Safe array, No shell=True)
    # Direct TCP connection to validated target_ip, domain strictly preserved as SNI
    cmd = [
        openssl_bin,
        "s_client",
        "-connect", f"{target_ip}:{port}",
        "-servername", hostname,
        "-brief",
    ]

    pqc_attempted = False
    if probe_group:
        pqc_attempted = True
        cmd.extend(["-groups", probe_group])

    try:
        # Pass empty bytes to close stdin immediately upon handshake completion
        proc = subprocess.run(
            cmd,
            input=b"",
            capture_output=True,
            timeout=8.0,
            shell=False
        )
    except subprocess.TimeoutExpired:
        return {
            "target": hostname,
            "target_ip": target_ip,
            "openssl_version": version_info["version_string"],
            "tls_version": "TIMEOUT",
            "cipher": "TIMEOUT",
            "negotiated_group": "TIMEOUT",
            "group_observation": "NOT_OBSERVABLE",
            "pqc_probe_attempted": pqc_attempted,
            "pqc_probe_result": "TIMEOUT",
            "evidence": "NOT_OBSERVABLE",
        }

    stderr_text = proc.stderr.decode("utf-8", errors="replace")
    stdout_text = proc.stdout.decode("utf-8", errors="replace")
    combined = stderr_text + "\n" + stdout_text

    # Parse TLS handshake fields
    tls_version = "UNKNOWN"
    ciphersuite = "UNKNOWN"
    negotiated_group = "Not observable"
    peer_cert = ""
    is_handshake_failure = "handshake failure" in combined or "alert handshake failure" in combined

    for line in combined.splitlines():
        line = line.strip()
        if line.startswith("Protocol version:"):
            tls_version = line.split(":", 1)[1].strip()
        elif line.startswith("Ciphersuite:"):
            ciphersuite = line.split(":", 1)[1].strip()
        elif line.startswith("Negotiated TLS1.3 group:"):
            negotiated_group = line.split(":", 1)[1].strip()
        elif line.startswith("Peer Temp Key:"):
            negotiated_group = line.split(":", 1)[1].strip().split(",")[0].strip()
        elif line.startswith("Peer certificate:"):
            peer_cert = line.split(":", 1)[1].strip()

    # Determine Evidence Classification
    if is_handshake_failure:
        if pqc_attempted:
            pqc_probe_result = "REJECTED_UNSUPPORTED"
            evidence = "CAPABILITY_PROBED"
            group_observation = "NOT_SUPPORTED"
        else:
            pqc_probe_result = "HANDSHAKE_FAILED"
            evidence = "NOT_OBSERVABLE"
            group_observation = "NOT_OBSERVABLE"
    elif negotiated_group != "Not observable":
        group_observation = "OBSERVED"
        if pqc_attempted:
            pqc_probe_result = "ACCEPTED"
            evidence = "CAPABILITY_PROBED"
        else:
            pqc_probe_result = "ACCEPTED_DEFAULT"
            evidence = "OBSERVED"
    else:
        group_observation = "NOT_OBSERVABLE"
        pqc_probe_result = "UNKNOWN"
        evidence = "NOT_OBSERVABLE"

    return {
        "target": hostname,
        "target_ip": target_ip,
        "openssl_executable": openssl_bin,
        "openssl_version": version_info["version_string"],
        "tls_version": tls_version,
        "cipher": ciphersuite,
        "peer_certificate": peer_cert,
        "negotiated_group": negotiated_group,
        "group_observation": group_observation,
        "pqc_probe_attempted": pqc_attempted,
        "requested_group": probe_group,
        "pqc_probe_result": pqc_probe_result,
        "evidence": evidence,
    }


def main():
    parser = argparse.ArgumentParser(description="QuantumShield TLS 1.3 Key-Exchange & Hybrid PQC Capability Probe")
    parser.add_argument("domain", help="Public target domain to probe (e.g. cloudflare.com)")
    parser.add_argument("--port", type=int, default=443, help="Port (defaults to 443)")
    parser.add_argument("--group", default=None, help="Specific TLS group to offer (e.g. X25519MLKEM768)")
    parser.add_argument("--json", action="store_true", help="Print structured JSON output")

    args = parser.parse_args()

    try:
        result = probe_tls13_key_exchange(args.domain, port=args.port, probe_group=args.group)
        print(json.dumps(result, indent=2))
    except (DomainValidationError, UnsafeTargetError, DnsResolutionError) as e:
        print(json.dumps({
            "target": args.domain,
            "error": "SECURITY_VALIDATION_ERROR",
            "detail": str(e)
        }, indent=2))
        sys.exit(1)


if __name__ == "__main__":
    main()

