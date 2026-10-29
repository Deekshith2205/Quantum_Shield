"""FastAPI API routes for QuantumShield.
Hardened with SSRF defense, rate limiting, bounded concurrency, and safe error disclosure.
"""

import asyncio
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse

from app.schemas.scan import ScanRequest, ScanResponse, ErrorResponse
from app.schemas.audit import AuditRequest, AuditResponse
from app.services.assessment_service import AssessmentService
from app.services.audit_service import AuditService
from app.scanners.domain_validator import DomainValidationError
from app.security.network import UnsafeTargetError, DnsResolutionError
from app.security.rate_limiter import DEFAULT_RATE_LIMITER, SCAN_SEMAPHORE, MAX_CONCURRENT_SCANS
from app.scanners.tls_scanner import TlsScanError, TlsTimeoutError, TlsConnectionError

logger = logging.getLogger("quantumshield.api")
router = APIRouter()
assessment_service = AssessmentService(scanner_timeout=8.0)
audit_service = AuditService(assessment_service=assessment_service)


@router.get("/health", tags=["System"])
def health_check():
    """Health check endpoint for service status verification."""
    return {
        "status": "healthy",
        "service": "QuantumShield Banking Security Audit Platform",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phase": "Phase 0 - Banking Security Audit & Zero-Trust Architecture Refactor",
    }


@router.post(
    "/scan",
    response_model=ScanResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid domain format, prohibited target, or DNS resolution failure"},
        429: {"model": ErrorResponse, "description": "Rate limit or concurrency limit exceeded"},
        502: {"model": ErrorResponse, "description": "Target server connection or TLS error"},
        504: {"model": ErrorResponse, "description": "Target scan timed out"},
        500: {"model": ErrorResponse, "description": "Internal assessment failure"},
    },
    tags=["Assessment"],
)
async def run_scan(request: ScanRequest, http_request: Request):
    """
    Executes a passive, non-invasive TLS post-quantum cryptographic readiness assessment
    for the provided domain.
    """
    domain = request.domain.strip() if request.domain else ""
    port = request.port or 443

    # Fast validation for empty domain before consuming concurrency or rate limiter
    if not domain:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": "DOMAIN_VALIDATION_ERROR",
                "detail": "Domain parameter cannot be empty.",
                "target_domain": domain,
            },
        )

    # Extract client IP for rate limiting
    forwarded = http_request.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
    elif http_request.client:
        client_ip = http_request.client.host
    else:
        client_ip = "127.0.0.1"

    # Enforce in-memory sliding window rate limit (10 scans / min / IP)
    allowed, retry_after = DEFAULT_RATE_LIMITER.is_allowed(client_ip)
    if not allowed:
        logger.warning(f"Rate limit exceeded for client {client_ip} requesting scan of '{domain}'")
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": str(retry_after)},
            content={
                "error": "RATE_LIMIT_EXCEEDED",
                "detail": f"Rate limit exceeded (10 scans per minute). Please try again in {retry_after} seconds.",
                "target_domain": domain,
            },
        )

    # Enforce bounded concurrency limit (5 concurrent scans)
    try:
        await asyncio.wait_for(SCAN_SEMAPHORE.acquire(), timeout=0.5)
    except asyncio.TimeoutError:
        logger.warning(f"Concurrency limit ({MAX_CONCURRENT_SCANS}) reached for scan of '{domain}'")
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": "5"},
            content={
                "error": "CONCURRENCY_LIMIT_EXCEEDED",
                "detail": "Server is currently processing the maximum number of concurrent scans (5). Please try again shortly.",
                "target_domain": domain,
            },
        )

    try:
        # Offload blocking socket connection and TLS handshake to worker thread
        loop = asyncio.get_running_loop()
        probe_pqc = getattr(request, "probe_pqc", False)
        asset_id = getattr(request, "asset_id", None)
        result = await loop.run_in_executor(
            None, assessment_service.assess_domain, domain, port, probe_pqc, asset_id
        )
        return result

    except UnsafeTargetError as e:
        logger.warning(f"SSRF prevention triggered for target '{domain}': {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": "UNSAFE_TARGET",
                "detail": "QuantumShield scans public Internet hosts only. This target resolves to a non-public address and was rejected for security reasons. Scanning internal infrastructure is strictly prohibited.",
                "target_domain": domain,
            },
        )

    except DnsResolutionError as e:
        logger.warning(f"DNS resolution failure for '{domain}': {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": "DNS_RESOLUTION_FAILED",
                "detail": str(e),
                "target_domain": domain,
            },
        )

    except DomainValidationError as e:
        logger.warning(f"Domain validation failed for '{domain}': {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": "DOMAIN_VALIDATION_ERROR",
                "detail": str(e),
                "target_domain": domain,
            },
        )

    except TlsTimeoutError as e:
        logger.warning(f"TLS timeout for '{domain}': {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            content={
                "error": "SCAN_TIMEOUT",
                "detail": str(e),
                "target_domain": domain,
            },
        )

    except TlsConnectionError as e:
        logger.warning(f"TLS connection error for '{domain}': {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={
                "error": "CONNECTION_FAILED",
                "detail": str(e),
                "target_domain": domain,
            },
        )

    except TlsScanError as e:
        logger.warning(f"TLS scan error for '{domain}': {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={
                "error": e.error_code,
                "detail": str(e),
                "target_domain": domain,
            },
        )

    except Exception as e:
        logger.error(f"Unexpected assessment failure for '{domain}': {str(e)}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "INTERNAL_ASSESSMENT_ERROR",
                "detail": "An internal error occurred while processing the cryptographic assessment. Please try again.",
                "target_domain": domain,
            },
        )
    finally:
        SCAN_SEMAPHORE.release()


@router.post(
    "/audit",
    response_model=AuditResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid domain format, prohibited target, or DNS resolution failure"},
        429: {"model": ErrorResponse, "description": "Rate limit or concurrency limit exceeded"},
        502: {"model": ErrorResponse, "description": "Target server connection or TLS error"},
        504: {"model": ErrorResponse, "description": "Target audit timed out"},
        500: {"model": ErrorResponse, "description": "Internal audit failure"},
    },
    tags=["Banking Audit"],
)
async def run_audit(request: AuditRequest, http_request: Request):
    """
    Executes an end-to-end Banking Security Audit integrating:
    Banking Asset Context -> Passive TLS Cryptographic Assessment -> Audit Layer Mapping ->
    Zero Trust Verification -> Multidimensional Risk Separation.
    """
    domain = request.domain.strip() if request.domain else ""
    port = request.port or 443

    if not domain:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": "DOMAIN_VALIDATION_ERROR",
                "detail": "Domain parameter cannot be empty.",
                "target_domain": domain,
            },
        )

    # Extract client IP for rate limiting
    forwarded = http_request.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
    elif http_request.client:
        client_ip = http_request.client.host
    else:
        client_ip = "127.0.0.1"

    # Enforce sliding window rate limit
    allowed, retry_after = DEFAULT_RATE_LIMITER.is_allowed(client_ip)
    if not allowed:
        logger.warning(f"Rate limit exceeded for client {client_ip} requesting audit of '{domain}'")
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": str(retry_after)},
            content={
                "error": "RATE_LIMIT_EXCEEDED",
                "detail": f"Rate limit exceeded (10 scans per minute). Please try again in {retry_after} seconds.",
                "target_domain": domain,
            },
        )

    # Enforce bounded concurrency limit
    try:
        await asyncio.wait_for(SCAN_SEMAPHORE.acquire(), timeout=0.5)
    except asyncio.TimeoutError:
        logger.warning(f"Concurrency limit ({MAX_CONCURRENT_SCANS}) reached for audit of '{domain}'")
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": "5"},
            content={
                "error": "CONCURRENCY_LIMIT_EXCEEDED",
                "detail": "Server is currently processing the maximum number of concurrent scans (5). Please try again shortly.",
                "target_domain": domain,
            },
        )

    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None, audit_service.audit_target, domain, port, request
        )
        return result

    except UnsafeTargetError as e:
        logger.warning(f"SSRF prevention triggered during audit for '{domain}': {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": "UNSAFE_TARGET",
                "detail": "QuantumShield scans public Internet hosts only. This target resolves to a non-public address and was rejected for security reasons. Scanning internal infrastructure is strictly prohibited.",
                "target_domain": domain,
            },
        )

    except DnsResolutionError as e:
        logger.warning(f"DNS resolution failure during audit for '{domain}': {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": "DNS_RESOLUTION_FAILED",
                "detail": str(e),
                "target_domain": domain,
            },
        )

    except DomainValidationError as e:
        logger.warning(f"Domain validation failed during audit for '{domain}': {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": "DOMAIN_VALIDATION_ERROR",
                "detail": str(e),
                "target_domain": domain,
            },
        )

    except TlsTimeoutError as e:
        logger.warning(f"TLS timeout during audit for '{domain}': {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            content={
                "error": "SCAN_TIMEOUT",
                "detail": str(e),
                "target_domain": domain,
            },
        )

    except TlsConnectionError as e:
        logger.warning(f"TLS connection error during audit for '{domain}': {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={
                "error": "CONNECTION_FAILED",
                "detail": str(e),
                "target_domain": domain,
            },
        )

    except TlsScanError as e:
        logger.warning(f"TLS scan error during audit for '{domain}': {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={
                "error": e.error_code,
                "detail": str(e),
                "target_domain": domain,
            },
        )

    except Exception as e:
        logger.error(f"Unexpected audit failure for '{domain}': {str(e)}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "INTERNAL_ASSESSMENT_ERROR",
                "detail": "An internal error occurred while processing the banking security audit. Please try again.",
                "target_domain": domain,
            },
        )
    finally:
        SCAN_SEMAPHORE.release()


@router.get("/banking/profiles", tags=["Banking Profiles"])
def list_banking_profiles():
    """Returns the catalog of representative synthetic banking system profiles."""
    from app.models.profiles import get_synthetic_banking_profiles
    return get_synthetic_banking_profiles()


@router.get("/banking/profiles/{profile_id}", tags=["Banking Profiles"])
def get_banking_profile(profile_id: str):
    """Retrieves a specific representative synthetic banking system profile by identifier."""
    from app.models.profiles import get_synthetic_profile_by_id
    profile = get_synthetic_profile_by_id(profile_id)
    if not profile:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "error": "PROFILE_NOT_FOUND",
                "detail": f"Synthetic banking profile '{profile_id}' not found.",
            },
        )
    return profile
