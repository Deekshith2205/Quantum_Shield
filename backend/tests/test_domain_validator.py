"""Unit tests for domain validation and SSRF prevention.
"""

import pytest
from app.scanners.domain_validator import (
    normalize_domain_input,
    resolve_domain,
    DomainValidationError,
)


def test_normalize_domain_clean():
    hostname, port = normalize_domain_input("example.com")
    assert hostname == "example.com"
    assert port == 443


def test_normalize_domain_with_https_and_port():
    with pytest.raises(DomainValidationError, match="URL schemes"):
        normalize_domain_input("https://sub.example.com:8443/some/path?param=1")


def test_normalize_domain_case_insensitive():
    hostname, port = normalize_domain_input("GOOGLE.COM")
    assert hostname == "google.com"
    assert port == 443


def test_normalize_empty_domain():
    with pytest.raises(DomainValidationError, match="cannot be empty"):
        normalize_domain_input("")


def test_normalize_disallowed_localhost():
    with pytest.raises(DomainValidationError, match="strictly prohibited"):
        normalize_domain_input("localhost")


def test_normalize_disallowed_local_internal():
    with pytest.raises(DomainValidationError, match="strictly prohibited"):
        normalize_domain_input("service.local")


def test_normalize_disallowed_private_ip():
    with pytest.raises(DomainValidationError, match="prohibited"):
        normalize_domain_input("192.168.1.1")


def test_normalize_disallowed_loopback_ip():
    with pytest.raises(DomainValidationError, match="prohibited"):
        normalize_domain_input("127.0.0.1")


def test_normalize_invalid_characters():
    with pytest.raises(DomainValidationError, match="Invalid domain name format"):
        normalize_domain_input("example.com; rm -rf /")


def test_normalize_too_long():
    long_domain = "a" * 260 + ".com"
    with pytest.raises(DomainValidationError, match="exceeds maximum length"):
        normalize_domain_input(long_domain)


def test_resolve_domain_nonexistent():
    with pytest.raises(DomainValidationError, match="DNS resolution failed"):
        resolve_domain("nonexistent-domain-xyz-123456789.org")

