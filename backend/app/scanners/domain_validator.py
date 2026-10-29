"""Domain validation and normalization module.
Enforces strict RFC 1035/1123 domain syntax, rejects IP literals, URL schemes,
paths, query strings, ports, credentials, and internal/local namespaces.
Defends against SSRF and scanner abuse.
"""

import ipaddress
import re
from typing import Tuple


class DomainValidationError(Exception):
    """Raised when domain validation fails."""
    pass


# RFC 1035/1123 regex for individual domain labels
LABEL_REGEX = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")

# Valid TLD pattern (at least 2 alphabetic chars or internationalized punycode xn--)
TLD_REGEX = re.compile(r"^(?:[a-zA-Z]{2,}|xn--[a-zA-Z0-9]+)$")

# Disallowed internal, testing, and private domain suffixes
PROHIBITED_TLDS = (
    ".local",
    ".internal",
    ".lan",
    ".corp",
    ".home",
    ".test",
    ".onion",
    ".invalid",
    ".example",
    ".arpa",
    ".intranet",
    ".localhost",
)

# Disallowed hostnames
PROHIBITED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "broadcasthost",
}


def normalize_domain_input(user_input: str) -> Tuple[str, int]:
    """
    Validates and normalizes user input into a clean FQDN hostname and port 443.
    Strictly accepts only domain names / hostnames.

    Rejects:
    - IP literals (IPv4 and IPv6)
    - URLs with schemes (http://, https://, etc.)
    - URL paths (/test, /login)
    - Query parameters (?x=1) and fragments (#sec)
    - Inline credentials (user:pass@domain)
    - Inline ports (example.com:443)
    - Local, internal, private, or single-label hostnames
    - Invalid characters and malformed labels
    """
    if not user_input or not isinstance(user_input, str):
        raise DomainValidationError("Domain input cannot be empty.")

    cleaned = user_input.strip()

    if not cleaned:
        raise DomainValidationError("Domain input cannot be empty.")

    # Reject unreasonably long inputs early (RFC 1035 max FQDN length is 253 octets)
    if len(cleaned) > 253:
        raise DomainValidationError("Domain name exceeds maximum length of 253 characters (RFC 1035).")

    # Reject whitespace
    if any(c.isspace() for c in cleaned):
        raise DomainValidationError("Invalid domain name format: domain name cannot contain whitespace.")

    # 1. Reject URL schemes
    if "://" in cleaned or cleaned.lower().startswith(("http:", "https:", "ftp:", "ws:", "wss:")):
        raise DomainValidationError(
            "Invalid input format: URL schemes ('http://' or 'https://') are not allowed. "
            "Please enter only a domain name (e.g. example.com)."
        )

    # 2. Reject URL paths
    if "/" in cleaned or "\\" in cleaned:
        raise DomainValidationError(
            "Invalid input format: URL paths are not allowed. "
            "Please enter only a domain name (e.g. example.com)."
        )

    # 3. Reject query parameters and fragments
    if "?" in cleaned or "#" in cleaned:
        raise DomainValidationError(
            "Invalid input format: Query parameters and URL fragments are not allowed."
        )

    # 4. Reject user credentials
    if "@" in cleaned:
        raise DomainValidationError(
            "Invalid input format: User credentials are not permitted in domain names."
        )

    # 5. Reject direct IP literals (IPv4 and IPv6)
    raw_ip_candidate = cleaned.strip("[]")
    try:
        ipaddress.ip_address(raw_ip_candidate)
        raise DomainValidationError(
            f"Direct IP addresses are prohibited ({cleaned}). "
            "Please enter a valid Fully Qualified Domain Name (e.g. example.com)."
        )
    except ValueError:
        pass

    # 6. Reject inline ports
    if ":" in cleaned:
        raise DomainValidationError(
            "Invalid input format: Port numbers cannot be included in domain name. "
            "Use the dedicated port parameter if needed."
        )

    # Normalize casing and strip optional trailing FQDN dot
    fqdn = cleaned.lower().rstrip(".")

    # 7. Check for prohibited local / internal names
    if fqdn in PROHIBITED_HOSTNAMES:
        raise DomainValidationError(
            f"Scanning internal or local domains ({cleaned}) is strictly prohibited."
        )

    for prohibited_tld in PROHIBITED_TLDS:
        if fqdn.endswith(prohibited_tld):
            raise DomainValidationError(
                f"Scanning internal or local domains ({cleaned}) is strictly prohibited."
            )

    # 8. Must be a multi-label domain (at least two labels: name + TLD)
    labels = fqdn.split(".")
    if len(labels) < 2:
        raise DomainValidationError(
            f"Scanning internal or local domains ({cleaned}) is strictly prohibited. "
            "Must be a valid Fully Qualified Domain Name (e.g. example.com)."
        )

    # 9. Validate each label against RFC 1035 / RFC 1123
    for label in labels:
        if not label:
            raise DomainValidationError(
                f"Invalid domain name format: '{cleaned}' contains consecutive dots."
            )
        if len(label) > 63:
            raise DomainValidationError(
                f"Domain label '{label}' exceeds maximum length of 63 characters."
            )
        if not LABEL_REGEX.match(label):
            raise DomainValidationError(
                f"Invalid domain name format: label '{label}' contains invalid characters. "
                "Must contain only alphanumeric characters and hyphens, and cannot start or end with a hyphen."
            )

    # 10. Validate TLD format
    tld = labels[-1]
    if not TLD_REGEX.match(tld):
        raise DomainValidationError(
            f"Invalid top-level domain '{tld}'. Must be a valid TLD or IDN punycode."
        )

    return fqdn, 443


def resolve_domain(hostname: str, timeout_seconds: float = 4.0) -> str:
    """
    Safely resolves a hostname to a verified public IP address.
    Delegates to app.security.network.resolve_and_validate_hostname.
    Returns resolved public IP string.
    """
    from app.security.network import resolve_and_validate_hostname, DnsResolutionError, UnsafeTargetError

    try:
        resolution = resolve_and_validate_hostname(hostname, timeout_seconds=timeout_seconds)
        return resolution.selected_ip
    except (DnsResolutionError, UnsafeTargetError) as e:
        raise DomainValidationError(str(e)) from e
