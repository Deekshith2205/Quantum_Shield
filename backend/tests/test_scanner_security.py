"""Comprehensive unit and integration tests for Phase 2C - Scanner Security Hardening.

Verifies:
- SSRF prevention across all prohibited IPv4 and IPv6 address ranges (RFC 1918, loopback,
  link-local, cloud metadata, multicast, reserved, documentation, CGNAT).
- Immediate rejection of mixed DNS responses (public IP + private IP).
- DNS rebinding defense (single resolution, direct IP socket connection).
- SNI preservation (original domain passed as server_hostname to wrap_socket).
- Strict input validation (rejection of schemes, paths, queries, credentials, ports, IP literals).
- Bounded timeouts (connect and TLS handshake).
- Rate limiting (sliding window, 10 scans/min per client IP, HTTP 429 with Retry-After).
- Concurrency limiting (semaphore max 5, HTTP 429 on exhaustion).
- Safe error disclosure (no internal IPs, no stack traces).
"""
import socket
import ssl
import dns.exception
import dns.resolver
from unittest.mock import patch, MagicMock
import pytest
from starlette.testclient import TestClient

from app.main import app
from app.scanners.domain_validator import normalize_domain_input, DomainValidationError
from app.security.network import (
    is_safe_public_ip,
    resolve_and_validate_hostname,
    UnsafeTargetError,
    DnsResolutionError,
    SafeResolutionResult,
)
from app.security.rate_limiter import InMemoryRateLimiter, DEFAULT_RATE_LIMITER
from app.scanners.tls_scanner import (
    TlsScanner,
    TlsTimeoutError,
    TlsConnectionError,
    TlsHandshakeError,
)

client = TestClient(app)

def _mock_dns_resolver(records_by_type):
    """Create a mocked dnspython resolver for deterministic DNS security tests."""
    resolver = MagicMock()

    def mock_resolve(hostname, record_type, **kwargs):
        records = records_by_type.get(record_type)

        if isinstance(records, Exception):
            raise records

        if records is None:
            raise dns.resolver.NoAnswer()

        return [MagicMock(address=ip) for ip in records]

    resolver.resolve.side_effect = mock_resolve

    resolver_patcher = patch(
        "app.security.network.dns.resolver.Resolver",
        return_value=resolver,
    )

    return resolver_patcher, resolver

# ============================================================================
# 1. IP CLASSIFICATION & PROHIBITED RANGE TESTS
# ============================================================================

@pytest.mark.parametrize("ip_str", [
    # Loopback
    "127.0.0.1",
    "127.0.0.2",
    "127.255.255.255",
    "::1",
    # RFC 1918 Private space
    "10.0.0.1",
    "10.254.0.1",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.0.1",
    "192.168.1.254",
    # Link-local & Cloud Metadata (AWS, GCP, Azure, OpenStack)
    "169.254.169.254",
    "169.254.0.1",
    "fe80::1",
    "fe80::ec2",
    # IPv6 Unique Local Address (ULA)
    "fc00::1",
    "fd00::1",
    "fd00:ec2::254",
    # Multicast
    "224.0.0.1",
    "239.255.255.250",
    "ff02::1",
    # Unspecified / Broadcast
    "0.0.0.0",
    "::",
    "255.255.255.255",
    # Carrier-grade NAT (RFC 6598)
    "100.64.0.1",
    "100.127.255.254",
    # Documentation & Benchmark ranges
    "192.0.2.1",
    "198.51.100.1",
    "203.0.113.1",
    "198.18.0.1",
    "2001:db8::1",
    # Reserved
    "240.0.0.1",
    # IPv4-mapped IPv6 loopback and private
    "::ffff:127.0.0.1",
    "::ffff:10.0.0.1",
    "::ffff:169.254.169.254",
])
def test_prohibited_ips_rejected(ip_str: str):
    """Verifies that all non-public or prohibited IPv4 and IPv6 addresses are rejected."""
    safe, reason = is_safe_public_ip(ip_str)
    assert not safe, f"Expected {ip_str} to be rejected, but marked safe. Reason: {reason}"
    assert len(reason) > 0


@pytest.mark.parametrize("ip_str", [
    "93.184.216.34",     # example.com
    "142.250.190.46",    # google.com
    "151.101.1.223",     # python.org
    "104.16.132.229",    # cloudflare.com
    "2606:4700::6810:84e5",  # Cloudflare IPv6
    "2001:4860:4860::8888",  # Google Public DNS IPv6
])
def test_legitimate_public_ips_allowed(ip_str: str):
    """Verifies that legitimate globally routable public IPs are allowed."""
    safe, reason = is_safe_public_ip(ip_str)
    assert safe, f"Expected {ip_str} to be allowed, but rejected: {reason}"
    assert reason == ""


# ============================================================================
# 2. SECURE RESOLVER & MIXED DNS TESTS
# ============================================================================

def test_resolve_safe_public_domain():
    resolver_patcher, mock_resolver = _mock_dns_resolver({
        "A": ["93.184.216.34", "93.184.216.35"],
        "AAAA": None,
    })

    with resolver_patcher:
        result = resolve_and_validate_hostname("example.com")

    assert result.hostname == "example.com"
    assert result.selected_ip == "93.184.216.34"
    assert result.all_resolved_ips == ["93.184.216.34", "93.184.216.35"]
    assert result.ip_version == "IPv4"
    assert mock_resolver.resolve.call_count == 2


def test_mixed_dns_response_rejected():
    """Reject mixed public and private DNS answers across record types."""
    resolver_patcher, _ = _mock_dns_resolver({
        "A": ["93.184.216.34"],
        "AAAA": ["::1"],
    })

    with resolver_patcher:
        with pytest.raises(
            UnsafeTargetError,
            match="prohibited, private, or non-public",
        ):
            resolve_and_validate_hostname("attacker-mixed.com")


def test_cloud_metadata_dns_rejected():
    """Reject DNS responses pointing to cloud metadata addresses."""
    resolver_patcher, _ = _mock_dns_resolver({
        "A": ["169.254.169.254"],
        "AAAA": None,
    })

    with resolver_patcher:
        with pytest.raises(
            UnsafeTargetError,
            match="prohibited, private, or non-public",
        ):
            resolve_and_validate_hostname("metadata.evil.com")


def test_ipv6_loopback_dns_rejected():
    resolver_patcher, _ = _mock_dns_resolver({
        "A": None,
        "AAAA": ["::1"],
    })

    with resolver_patcher:
        with pytest.raises(
            UnsafeTargetError,
            match="prohibited, private, or non-public",
        ):
            resolve_and_validate_hostname("loopback6.evil.com")


def test_dns_resolution_failure():
    resolver_patcher, _ = _mock_dns_resolver({
        "A": dns.exception.DNSException("simulated DNS failure"),
        "AAAA": None,
    })

    with resolver_patcher:
        with pytest.raises(DnsResolutionError, match="DNS resolution failed"):
            resolve_and_validate_hostname("nonexistent.invalid")

def test_dns_resolution_timeout():
    """A DNS timeout must fail closed."""
    resolver_patcher, mock_resolver = _mock_dns_resolver({
        "A": dns.exception.Timeout(),
        "AAAA": None,
    })

    with resolver_patcher:
        with pytest.raises(DnsResolutionError, match="DNS resolution timed out"):
            resolve_and_validate_hostname("slow-dns.example", timeout_seconds=1.0)

    mock_resolver.resolve.assert_called_once()


def test_dns_queries_share_one_overall_deadline():
    """The AAAA query must receive only the remaining shared timeout."""
    resolver_patcher, mock_resolver = _mock_dns_resolver({
        "A": ["93.184.216.34"],
        "AAAA": None,
    })

    with patch("app.security.network.time.monotonic", side_effect=[
        100.0,  # Overall deadline initialization
        100.2,  # Before A lookup
        100.7,  # Before AAAA lookup
    ]):
        with resolver_patcher:
            result = resolve_and_validate_hostname(
                "example.com",
                timeout_seconds=1.0,
            )

    assert result.selected_ip == "93.184.216.34"

    calls = mock_resolver.resolve.call_args_list
    assert len(calls) == 2
    assert calls[0].kwargs["lifetime"] == pytest.approx(0.8)
    assert calls[1].kwargs["lifetime"] == pytest.approx(0.3)
    assert calls[0].kwargs["search"] is False
    assert calls[1].kwargs["search"] is False


# ============================================================================
# 3. DNS REBINDING DEFENSE & DIRECT IP SOCKET CONNECT
# ============================================================================

def test_dns_rebinding_prevention_connects_to_validated_ip():
    """
    Verifies that TlsScanner:
    1. Resolves DNS once through resolve_and_validate_hostname.
    2. Calls raw_sock.connect() directly with the validated IP (not hostname).
    3. Calls wrap_socket() with server_hostname set to the domain (SNI preservation).
    """
    scanner = TlsScanner()

    mock_resolution = SafeResolutionResult(
        hostname="example.com",
        selected_ip="93.184.216.34",
        all_resolved_ips=["93.184.216.34"],
        ip_version="IPv4",
    )

    mock_raw_sock = MagicMock()
    mock_ssl_sock = MagicMock()
    mock_ssl_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssl_sock.version.return_value = "TLSv1.3"
    mock_ssl_sock.selected_alpn_protocol.return_value = "h2"
    mock_ssl_sock.getpeercert.return_value = b"\x30\x82\x01..."  # mock DER
    mock_ssl_sock.session_reused = False

    with patch("app.scanners.tls_scanner.resolve_and_validate_hostname", return_value=mock_resolution) as mock_resolve:
        with patch("socket.socket", return_value=mock_raw_sock):
            with patch("ssl.create_default_context") as mock_ctx_factory:
                mock_ctx = MagicMock()
                mock_ctx_factory.return_value = mock_ctx
                mock_ctx.wrap_socket.return_value = mock_ssl_sock
                with patch("app.scanners.tls_scanner.parse_der_certificate", return_value={"public_key_algorithm": "RSA"}):
                    scanner.scan("example.com", 443)

                    # 1. DNS was resolved once
                    mock_resolve.assert_called_once_with("example.com", timeout_seconds=5.0)

                    # 2. Raw socket connected directly to the validated IP tuple ('93.184.216.34', 443)
                    mock_raw_sock.connect.assert_called_once_with(("93.184.216.34", 443))

                    # 3. wrap_socket received the original domain as server_hostname (SNI preserved)
                    mock_ctx.wrap_socket.assert_called_once()
                    _, kwargs = mock_ctx.wrap_socket.call_args
                    assert kwargs.get("server_hostname") == "example.com"
                    assert kwargs.get("do_handshake_on_connect") is True


# ============================================================================
# 4. STRICT INPUT VALIDATION TESTS
# ============================================================================

@pytest.mark.parametrize("valid_domain", [
    "example.com",
    "sub.example.com",
    "deep.sub.domain.co.uk",
    "my-app.service.org",
    "google.com",
    "cloudflare.com",
])
def test_strict_valid_domains_accepted(valid_domain: str):
    hostname, port = normalize_domain_input(valid_domain)
    assert hostname == valid_domain.lower()
    assert port == 443


@pytest.mark.parametrize("invalid_input,err_pattern", [
    # URL schemes
    ("http://example.com", "URL schemes"),
    ("https://example.com", "URL schemes"),
    ("ftp://example.com", "URL schemes"),
    # Paths
    ("example.com/test", "URL paths"),
    ("example.com/api/v1", "URL paths"),
    # Query parameters & fragments
    ("example.com?query=1", "Query parameters"),
    ("example.com#section", "Query parameters"),
    # User credentials
    ("admin:secret@example.com", "User credentials"),
    ("user@example.com", "User credentials"),
    # Inline ports
    ("example.com:443", "Port numbers"),
    ("example.com:8443", "Port numbers"),
    # Direct IP literals (IPv4 and IPv6)
    ("127.0.0.1", "Direct IP addresses are prohibited"),
    ("93.184.216.34", "Direct IP addresses are prohibited"),
    ("10.0.0.1", "Direct IP addresses are prohibited"),
    ("[::1]", "Direct IP addresses are prohibited"),
    ("::1", "Direct IP addresses are prohibited"),
    # Local & internal namespaces
    ("localhost", "strictly prohibited"),
    ("service.local", "strictly prohibited"),
    ("database.internal", "strictly prohibited"),
    ("router.lan", "strictly prohibited"),
    ("test.corp", "strictly prohibited"),
    ("service.home", "strictly prohibited"),
    ("secret.onion", "strictly prohibited"),
    ("intranet", "strictly prohibited"),
    # Malformed labels
    ("bad_domain.com", "invalid characters"),
    ("-invalid.com", "invalid characters"),
    ("invalid-.com", "invalid characters"),
    ("example..com", "consecutive dots"),
    ("a" * 64 + ".com", "exceeds maximum length of 63"),
])
def test_strict_invalid_inputs_rejected(invalid_input: str, err_pattern: str):
    with pytest.raises(DomainValidationError, match=err_pattern):
        normalize_domain_input(invalid_input)


# ============================================================================
# 5. BOUNDED TIMEOUTS & SAFE ERROR HANDLING
# ============================================================================

def test_connect_timeout_handling():
    scanner = TlsScanner(connect_timeout=0.1, handshake_timeout=0.1)
    mock_resolution = SafeResolutionResult(
        hostname="timeout-domain.org",
        selected_ip="93.184.216.34",
        all_resolved_ips=["93.184.216.34"],
        ip_version="IPv4",
    )
    with patch("app.scanners.tls_scanner.resolve_and_validate_hostname", return_value=mock_resolution):
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.connect.side_effect = socket.timeout("Connection timed out")
            mock_sock_cls.return_value = mock_sock

            with pytest.raises(TlsTimeoutError, match="timed out"):
                scanner.scan("timeout-domain.org")


def test_handshake_timeout_handling():
    scanner = TlsScanner(connect_timeout=0.1, handshake_timeout=0.1)
    mock_resolution = SafeResolutionResult(
        hostname="handshake-timeout.org",
        selected_ip="93.184.216.34",
        all_resolved_ips=["93.184.216.34"],
        ip_version="IPv4",
    )
    with patch("app.scanners.tls_scanner.resolve_and_validate_hostname", return_value=mock_resolution):
        with patch("socket.socket"):
            with patch("ssl.create_default_context") as mock_ctx_factory:
                mock_ctx = MagicMock()
                mock_ctx.wrap_socket.side_effect = socket.timeout("TLS handshake timed out")
                mock_ctx_factory.return_value = mock_ctx

                with pytest.raises(TlsTimeoutError, match="timed out"):
                    scanner.scan("handshake-timeout.org")


# ============================================================================
# 6. RATE LIMITING & CONCURRENCY TESTS
# ============================================================================

def test_rate_limiter_allows_up_to_limit():
    limiter = InMemoryRateLimiter(max_requests=5, window_seconds=60.0)
    client_ip = "198.51.100.42"

    for _ in range(5):
        allowed, retry_after = limiter.is_allowed(client_ip)
        assert allowed is True
        assert retry_after == 0

    # 6th request must be rejected
    allowed, retry_after = limiter.is_allowed(client_ip)
    assert allowed is False
    assert retry_after > 0


def test_api_rate_limit_ignores_spoofed_forwarded_for():
    """A caller must not bypass rate limiting by spoofing X-Forwarded-For."""
    DEFAULT_RATE_LIMITER.reset()

    # TestClient's direct connection address is "testclient".
    actual_client_ip = "testclient"
    spoofed_client_ip = "203.0.113.99"

    # Exhaust the limit for the actual connection address.
    for _ in range(10):
        DEFAULT_RATE_LIMITER.is_allowed(actual_client_ip)

    # A forged forwarded header must not change the rate-limit identity.
    response = client.post(
        "/api/scan",
        json={"domain": "example.com"},
        headers={"X-Forwarded-For": spoofed_client_ip},
    )

    assert response.status_code == 429
    data = response.json()
    assert data["error"] == "RATE_LIMIT_EXCEEDED"
    assert "Retry-After" in response.headers

    DEFAULT_RATE_LIMITER.reset()

def test_audit_api_rate_limit_ignores_spoofed_forwarded_for():
    """A caller must not bypass audit rate limiting by spoofing X-Forwarded-For."""
    DEFAULT_RATE_LIMITER.reset()

    # TestClient's direct connection address is "testclient".
    actual_client_ip = "testclient"
    spoofed_client_ip = "203.0.113.99"

    # Exhaust the limit for the actual connection address.
    for _ in range(10):
        DEFAULT_RATE_LIMITER.is_allowed(actual_client_ip)

    # A forged forwarded header must not change the rate-limit identity.
    response = client.post(
        "/api/audit",
        json={"domain": "example.com"},
        headers={"X-Forwarded-For": spoofed_client_ip},
    )

    assert response.status_code == 429
    data = response.json()
    assert data["error"] == "RATE_LIMIT_EXCEEDED"
    assert "Retry-After" in response.headers

    DEFAULT_RATE_LIMITER.reset()

def test_api_unsafe_target_returns_400_without_internal_ip():
    """Verify unsafe DNS targets return HTTP 400 without leaking internal IPs."""
    DEFAULT_RATE_LIMITER.reset()

    resolver_patcher, _ = _mock_dns_resolver({
        "A": ["10.0.0.1"],
        "AAAA": None,
    })

    with resolver_patcher:
        response = client.post(
            "/api/scan",
            json={"domain": "internal-exploit.com"},
        )

    assert response.status_code == 400
    data = response.json()
    assert data["error"] == "UNSAFE_TARGET"
    assert "10.0.0.1" not in data["detail"]
    assert "strictly prohibited" in data["detail"]

    DEFAULT_RATE_LIMITER.reset()


@pytest.mark.asyncio
async def test_api_concurrency_limit():
    """Verifies that exceeding the maximum concurrent scans returns HTTP 429."""
    from app.security.rate_limiter import SCAN_SEMAPHORE
    import httpx
    DEFAULT_RATE_LIMITER.reset()

    # Acquire all 5 semaphore slots
    for _ in range(5):
        await SCAN_SEMAPHORE.acquire()

    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as async_client:
            response = await async_client.post("/api/scan", json={"domain": "example.com"})
            assert response.status_code == 429
            data = response.json()
            assert data["error"] == "CONCURRENCY_LIMIT_EXCEEDED"
            assert "maximum number of concurrent scans" in data["detail"]
    finally:
        for _ in range(5):
            SCAN_SEMAPHORE.release()
        DEFAULT_RATE_LIMITER.reset()
