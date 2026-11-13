"""Network security, secure DNS resolution, and SSRF prevention module.

Ensures that QuantumShield external scans target ONLY legitimate public Internet hosts.
Enforces:
- One-time resolution with validation of ALL returned IPv4 and IPv6 addresses.
- Strict rejection of private, loopback, link-local, multicast, reserved, cloud metadata, and non-global IPs.
- Immediate rejection if ANY address in a mixed DNS response is non-public.
- DNS rebinding prevention by returning validated IP for direct socket connection.
"""

import ipaddress
import logging
import time
from dataclasses import dataclass
from typing import List, Tuple, Set

import dns.exception
import dns.resolver

from app.scanners.domain_validator import DomainValidationError

logger = logging.getLogger("quantumshield.network")


class NetworkSecurityError(DomainValidationError):
    """Base exception for network security and SSRF protection."""
    pass


class UnsafeTargetError(NetworkSecurityError):
    """Raised when target domain resolves to an unsafe, private, or prohibited address."""
    pass


class DnsResolutionError(NetworkSecurityError):
    """Raised when DNS resolution fails or times out."""
    pass


# Explicit list of prohibited IPv4 networks (defense-in-depth)
PROHIBITED_IPV4_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (source-only, RFC 1122)
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 Private space
    ipaddress.ip_network("100.64.0.0/10"),      # RFC 6598 Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),        # RFC 1122 Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # RFC 3927 Link-Local & AWS/Cloud metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Private space
    ipaddress.ip_network("192.0.0.0/24"),       # RFC 6890 IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # RFC 5737 Documentation (TEST-NET-1)
    ipaddress.ip_network("192.88.99.0/24"),     # RFC 7526 6to4 Relay Anycast
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Private space
    ipaddress.ip_network("198.18.0.0/15"),      # RFC 2544 Network Interconnect Device Benchmark
    ipaddress.ip_network("198.51.100.0/24"),    # RFC 5737 Documentation (TEST-NET-2)
    ipaddress.ip_network("203.0.113.0/24"),     # RFC 5737 Documentation (TEST-NET-3)
    ipaddress.ip_network("224.0.0.0/4"),        # RFC 5771 Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # RFC 1112 Reserved for Future Use
    ipaddress.ip_network("255.255.255.255/32"), # Limited Broadcast
]

# Explicit list of prohibited IPv6 networks
PROHIBITED_IPV6_NETWORKS = [
    ipaddress.ip_network("::1/128"),            # RFC 4291 Loopback
    ipaddress.ip_network("::/128"),             # RFC 4291 Unspecified
    ipaddress.ip_network("::ffff:0:0/96"),      # RFC 4291 IPv4-mapped
    ipaddress.ip_network("64:ff9b::/96"),       # RFC 6052 IPv4/IPv6 translation
    ipaddress.ip_network("100::/64"),           # RFC 6666 Discard-Only Prefix
    ipaddress.ip_network("2001:db8::/32"),      # RFC 3849 Documentation
    ipaddress.ip_network("2002::/16"),          # RFC 3056 6to4
    ipaddress.ip_network("fc00::/7"),           # RFC 4193 Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),          # RFC 4291 Link-Local Unicast
    ipaddress.ip_network("ff00::/8"),           # RFC 4291 Multicast
]


@dataclass(frozen=True)
class SafeResolutionResult:
    """Structured result of security-validated DNS resolution."""
    hostname: str
    selected_ip: str
    all_resolved_ips: List[str]
    ip_version: str  # "IPv4" or "IPv6"


def is_safe_public_ip(ip_str: str) -> Tuple[bool, str]:
    """
    Evaluates whether an IP address string is a globally routable, safe public address.
    Rejects private, loopback, link-local, multicast, reserved, unspecified,
    documentation, carrier-grade NAT, or cloud metadata ranges.

    Returns:
        (True, "") if safe and public.
        (False, reason_str) if prohibited or invalid.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False, f"Invalid IP address representation: '{ip_str}'"

    # Handle IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        return is_safe_public_ip(str(ip_obj.ipv4_mapped))

    # General RFC classification checks
    if ip_obj.is_loopback:
        return False, f"Address '{ip_str}' belongs to loopback range."
    if ip_obj.is_private:
        return False, f"Address '{ip_str}' belongs to private network space."
    if ip_obj.is_link_local:
        return False, f"Address '{ip_str}' belongs to link-local / cloud metadata space."
    if ip_obj.is_multicast:
        return False, f"Address '{ip_str}' belongs to multicast range."
    if ip_obj.is_unspecified:
        return False, f"Address '{ip_str}' is unspecified (0.0.0.0 or ::)."
    if ip_obj.is_reserved:
        return False, f"Address '{ip_str}' belongs to reserved network space."
    if not ip_obj.is_global:
        return False, f"Address '{ip_str}' is not globally routable."

    # Check explicit network block lists for defense-in-depth
    if isinstance(ip_obj, ipaddress.IPv4Address):
        for net in PROHIBITED_IPV4_NETWORKS:
            if ip_obj in net:
                return False, f"Address '{ip_str}' is within prohibited range {net}."
    else:
        for net in PROHIBITED_IPV6_NETWORKS:
            if ip_obj in net:
                return False, f"Address '{ip_str}' is within prohibited range {net}."

    return True, ""


def resolve_and_validate_hostname(
    hostname: str, timeout_seconds: float = 4.0
) -> SafeResolutionResult:
    """
    Resolves A and AAAA records within one shared deadline and validates
    EVERY returned IP address.

    Fails closed if either lookup times out or encounters a DNS error.
    A missing record type (NoAnswer) is acceptable.

    Returns a validated IP for direct socket connection, preventing
    DNS rebinding between validation and connection.
    """
    clean_hostname = hostname.strip().lower().rstrip(".")

    if not clean_hostname:
        raise DnsResolutionError("Hostname cannot be empty.")

    if timeout_seconds <= 0:
        raise DnsResolutionError("DNS timeout must be greater than zero.")

    deadline = time.monotonic() + timeout_seconds

    all_resolved_ips: List[str] = []
    seen: Set[str] = set()

    try:
        resolver = dns.resolver.Resolver(configure=True)

        for record_type in ("A", "AAAA"):
            remaining = deadline - time.monotonic()

            if remaining <= 0:
                raise DnsResolutionError(
                    f"DNS resolution timed out for '{clean_hostname}'."
                )

            try:
                answers = resolver.resolve(
                    clean_hostname,
                    record_type,
                    lifetime=remaining,
                    search=False,
                )

                for answer in answers:
                    ip_str = str(answer.address)

                    if ip_str not in seen:
                        seen.add(ip_str)
                        all_resolved_ips.append(ip_str)

            except dns.resolver.NoAnswer:
                # This record type does not exist; the other may still resolve.
                continue

    except dns.exception.Timeout as e:
        logger.warning(
            "DNS lookup timed out for '%s' within %.2fs: %s",
            clean_hostname,
            timeout_seconds,
            e,
        )
        raise DnsResolutionError(
            f"DNS resolution timed out for '{clean_hostname}'."
        ) from e

    except dns.exception.DNSException as e:
        logger.warning(
            "DNS lookup failed for '%s': %s",
            clean_hostname,
            e,
        )
        raise DnsResolutionError(
            f"DNS resolution failed for '{clean_hostname}': {e}"
        ) from e

    except Exception as e:
        logger.warning(
            "Unexpected DNS error for '%s': %s",
            clean_hostname,
            e,
        )
        raise DnsResolutionError(
            f"DNS resolution error for '{clean_hostname}': {e}"
        ) from e

    if not all_resolved_ips:
        raise DnsResolutionError(
            f"No DNS records returned for '{clean_hostname}'."
        )

    # Validate EVERY resolved address. Reject mixed public/private responses.
    for ip_str in all_resolved_ips:
        is_safe, reason = is_safe_public_ip(ip_str)

        if not is_safe:
            logger.warning(
                "Prohibited IP target detected for '%s': %s - %s",
                clean_hostname,
                ip_str,
                reason,
            )
            raise UnsafeTargetError(
                "Target domain resolves to a prohibited, private, or non-public address."
            )

    # Prefer IPv4; otherwise select the first validated IPv6 address.
    ipv4_candidates = [
        ip for ip in all_resolved_ips if ":" not in ip
    ]

    if ipv4_candidates:
        selected_ip = ipv4_candidates[0]
        ip_version = "IPv4"
    else:
        selected_ip = all_resolved_ips[0]
        ip_version = "IPv6"

    logger.info(
        "DNS resolution verified public target '%s' -> %s (%d total records verified)",
        clean_hostname,
        selected_ip,
        len(all_resolved_ips),
    )

    return SafeResolutionResult(
        hostname=clean_hostname,
        selected_ip=selected_ip,
        all_resolved_ips=all_resolved_ips,
        ip_version=ip_version,
    )