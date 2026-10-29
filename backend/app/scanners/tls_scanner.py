"""Passive, Non-Invasive TLS Scanner for QuantumShield.
Performs a single standard TLS handshake to inspect publicly observable TLS configuration
and certificates without intrusive probing. Hardened against SSRF and scanner abuse.
"""

import time
import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import logging
import certifi

from app.scanners.domain_validator import normalize_domain_input, DomainValidationError
from app.security.network import resolve_and_validate_hostname, UnsafeTargetError, DnsResolutionError
from app.scanners.certificate_parser import parse_der_certificate, parse_certificate_chain
from app.scanners.tls13_pqc import observe_tls13_key_exchange

logger = logging.getLogger("quantumshield.tls_scanner")


class TlsScanError(Exception):
    """Base exception for TLS scan failures."""
    def __init__(self, message: str, error_code: str = "TLS_ERROR"):
        super().__init__(message)
        self.message = message
        self.error_code = error_code


class TlsTimeoutError(TlsScanError):
    def __init__(self, message: str):
        super().__init__(message, error_code="SCAN_TIMEOUT")


class TlsConnectionError(TlsScanError):
    def __init__(self, message: str):
        super().__init__(message, error_code="CONNECTION_FAILED")


class TlsHandshakeError(TlsScanError):
    def __init__(self, message: str):
        super().__init__(message, error_code="HANDSHAKE_FAILURE")


class TlsScanner:
    """
    Non-invasive TLS scanner executing a single TLS handshake to retrieve
    cryptographic parameters.

    Hardened:
    - Dedicated connect (5.0s) and TLS handshake (8.0s) timeouts.
    - Resolves DNS once through security-aware resolver; validates all returned IPs.
    - Connects directly to verified public IP to prevent DNS rebinding.
    - Preserves target domain strictly for TLS SNI (server_hostname) and certificate validation.
    - Safe socket resource cleanup in finally blocks.
    """

    DEFAULT_CONNECT_TIMEOUT: float = 5.0
    DEFAULT_HANDSHAKE_TIMEOUT: float = 8.0

    def __init__(
        self,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        handshake_timeout: float = DEFAULT_HANDSHAKE_TIMEOUT,
        timeout: Optional[float] = None,
    ):
        if timeout is not None:
            self.connect_timeout = timeout
            self.handshake_timeout = timeout
        else:
            self.connect_timeout = connect_timeout
            self.handshake_timeout = handshake_timeout
        self.timeout = self.connect_timeout + self.handshake_timeout

    def scan(self, domain_input: str, port: int = 443, probe_pqc: bool = False) -> Dict[str, Any]:
        """
        Executes a passive TLS scan against the specified domain.
        Returns a structured dictionary of observed target, TLS, and certificate information.
        If negotiated protocol is TLS 1.3, safely observes the KeyShare group and optionally probes
        hybrid PQC capability when probe_pqc=True.
        """
        start_time = time.perf_counter()

        # Step 1: Validate & normalize domain (strict input validation)
        hostname, _ = normalize_domain_input(domain_input)
        target_port = port if (1 <= port <= 65535) else 443

        # Step 2: Resolve hostname safely (one-time resolution, SSRF defense)
        resolution = resolve_and_validate_hostname(hostname, timeout_seconds=self.connect_timeout)
        resolved_ip = resolution.selected_ip
        ip_version = resolution.ip_version

        # Step 3: Perform TLS handshake connecting to validated IP while preserving SNI
        tls_data = self._perform_handshake(hostname, resolved_ip, target_port)

        # Step 4: If TLS 1.3 was negotiated, observe KeyShare group via hardened OpenSSL telemetry
        pqc_evidence = None
        if tls_data["tls"].get("negotiated_protocol") == "TLSv1.3":
            try:
                pqc_evidence = observe_tls13_key_exchange(
                    hostname=hostname,
                    validated_ip=resolved_ip,
                    port=target_port,
                    probe_pqc=probe_pqc,
                    timeout=self.handshake_timeout,
                )
            except Exception as e:
                logger.warning(f"Failed to observe TLS 1.3 KeyShare for {hostname}: {e}")
                pqc_evidence = None

        tls_data["tls"]["pqc_evidence"] = pqc_evidence.model_dump() if pqc_evidence else None

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        scan_timestamp = datetime.now(timezone.utc).isoformat()

        target_info = {
            "domain": hostname,
            "port": target_port,
            "resolved_ip": resolved_ip,
            "ip_version": ip_version,
            "scan_timestamp": scan_timestamp,
            "connection_time_ms": elapsed_ms,
        }

        return {
            "target": target_info,
            "certificate": tls_data["certificate"],
            "tls": tls_data["tls"],
        }

    def _perform_handshake(self, hostname: str, resolved_ip: str, port: int) -> Dict[str, Any]:
        """
        Attempts a verified TLS handshake first. If certificate verification fails
        (e.g., expired or self-signed), retries with verification disabled solely to extract
        the peer certificate and cryptographic properties for vulnerability analysis.
        """
        is_trusted = True
        verification_status = "Trusted by system root CAs"

        # 1. First attempt: standard verified handshake
        try:
            return self._connect_tls(
                hostname, resolved_ip, port, verify=True, is_trusted=True, verification_status=verification_status
            )
        except ssl.SSLCertVerificationError as e:
            # Verification failed, but the server supports TLS!
            is_trusted = False
            verification_status = f"Certificate verification failed: {e.verify_message}"
        except ssl.SSLError as e:
            # Check if this was a cert verification issue
            if "CERTIFICATE_VERIFY_FAILED" in str(e):
                is_trusted = False
                verification_status = f"Certificate verification failed: {str(e)}"
            else:
                raise TlsHandshakeError(f"TLS handshake failed with {hostname}: {str(e)}")

        # 2. Second attempt if verification failed: unverified to extract the certificate parameters
        try:
            return self._connect_tls(
                hostname, resolved_ip, port, verify=False, is_trusted=is_trusted, verification_status=verification_status
            )
        except Exception as e:
            raise TlsHandshakeError(
                f"Failed to establish TLS connection with {hostname} ({verification_status}): {str(e)}"
            )

    def _connect_tls(
        self,
        hostname: str,
        resolved_ip: str,
        port: int,
        verify: bool,
        is_trusted: bool,
        verification_status: str,
    ) -> Dict[str, Any]:
        """
        Low-level socket creation, direct TCP connection to validated IP,
        and TLS wrapping with SNI preservation.
        """
        if verify:
            ctx = ssl.create_default_context(cafile=certifi.where())
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        # Configure ALPN to advertise HTTP/2 and HTTP/1.1
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except (ssl.SSLError, NotImplementedError):
            pass

        raw_sock = None
        ssl_sock = None

        try:
            # Step A: Create socket with explicit connect timeout
            sock_family = socket.AF_INET6 if ":" in resolved_ip else socket.AF_INET
            raw_sock = socket.socket(sock_family, socket.SOCK_STREAM)
            raw_sock.settimeout(self.connect_timeout)

            # Step B: Connect TCP directly to validated IP (DNS rebinding defense)
            raw_sock.connect((resolved_ip, port))

            # Step C: Set handshake timeout and wrap with TLS
            # Crucial: server_hostname MUST remain the original domain name for SNI
            raw_sock.settimeout(self.handshake_timeout)
            ssl_sock = ctx.wrap_socket(
                raw_sock,
                server_hostname=hostname,
                do_handshake_on_connect=True
            )
            ssl_sock.settimeout(self.handshake_timeout)

            # Handshake completed successfully
            cipher_info = ssl_sock.cipher()  # (cipher_name, protocol_version, secret_bits)
            cipher_name = cipher_info[0] if cipher_info else "UNKNOWN"
            negotiated_version = ssl_sock.version() or (cipher_info[1] if cipher_info else "UNKNOWN")
            cipher_bits = cipher_info[2] if cipher_info and len(cipher_info) > 2 else 0

            alpn = ssl_sock.selected_alpn_protocol()
            session_reused = ssl_sock.session_reused if hasattr(ssl_sock, "session_reused") else False

            # Retrieve DER certificate
            peer_cert_der = ssl_sock.getpeercert(binary_form=True)
            if not peer_cert_der:
                raise TlsHandshakeError(f"Server {hostname} completed TLS handshake but returned no peer certificate.")

            parsed_cert = parse_der_certificate(peer_cert_der)

            # Retrieve certificate chain if available
            chain_summaries = []
            if hasattr(ssl_sock, "get_verified_chain") and verify:
                verified_chain = ssl_sock.get_verified_chain()
                if verified_chain:
                    chain_summaries = parse_certificate_chain(verified_chain[1:])  # exclude leaf cert
            elif hasattr(ssl_sock, "get_unverified_chain"):
                unverified_chain = ssl_sock.get_unverified_chain()
                if unverified_chain:
                    chain_summaries = parse_certificate_chain(unverified_chain[1:])

            parsed_cert["chain_length"] = 1 + len(chain_summaries)
            parsed_cert["chain_certificates"] = chain_summaries
            parsed_cert["is_trusted"] = is_trusted
            parsed_cert["verification_status"] = verification_status

            tls_info = {
                "negotiated_protocol": negotiated_version,
                "negotiated_cipher": cipher_name,
                "cipher_bits": cipher_bits,
                "alpn_protocol": alpn,
                "session_reused": session_reused,
            }

            return {
                "certificate": parsed_cert,
                "tls": tls_info,
            }

        except (socket.timeout, TimeoutError):
            raise TlsTimeoutError(
                f"Connection or TLS handshake with target host timed out."
            )
        except ConnectionRefusedError:
            raise TlsConnectionError(
                f"Connection refused by target on port {port}."
            )
        except ConnectionResetError:
            raise TlsConnectionError(
                f"Connection abruptly reset by target during handshake on port {port}."
            )
        except ssl.SSLError:
            raise
        except OSError as e:
            raise TlsConnectionError(f"Network error while connecting to target: {str(e)}")
        finally:
            if ssl_sock:
                try:
                    ssl_sock.close()
                except Exception:
                    pass
            elif raw_sock:
                try:
                    raw_sock.close()
                except Exception:
                    pass
