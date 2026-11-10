"""FastAPI API routes for QuantumShield.
Hardened with SSRF defense, rate limiting, bounded concurrency, and safe error disclosure.
"""
import tempfile
from pathlib import Path
import asyncio
from typing import Dict, List, Any, Optional
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse

from app.schemas.scan import (
    ScanRequest,
    ScanResponse,
    ErrorResponse,
    ConfigScanRequest,
    CodeScanRequest,
    CertificateScanRequest,
)
from app.schemas.audit import AuditRequest, AuditResponse
from app.models.simulation import WhatIfMigrationRequest, WhatIfMigrationResult
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


@router.get("/banking/risk", tags=["Banking Risk Engine"])
def get_banking_risk_rankings():
    """
    Returns migration priority ranking and multidimensional risk assessments
    for all representative synthetic banking systems.
    Answers: 'Which banking systems should be migrated first, and why?'
    """
    from app.services.banking_risk_engine import get_all_synthetic_risk_assessments
    return get_all_synthetic_risk_assessments()


@router.get("/banking/profiles/{profile_id}/risk", tags=["Banking Risk Engine"])
def get_banking_profile_risk(profile_id: str):
    """
    Returns the multidimensional banking risk and key-protection-chain analysis
    for a specific synthetic banking profile.
    """
    from app.services.banking_risk_engine import get_profile_risk_assessment
    assessment = get_profile_risk_assessment(profile_id)
    if not assessment:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "error": "PROFILE_NOT_FOUND",
                "detail": f"Synthetic banking profile '{profile_id}' not found for risk evaluation.",
            },
        )
    return assessment


@router.post(
    "/banking/risk/what-if",
    response_model=WhatIfMigrationResult,
    tags=["What-If Simulator"],
)
def simulate_post_quantum_migration(request: WhatIfMigrationRequest):
    """
    Executes a deterministic What-If Post-Quantum Migration Simulation.
    Evaluates hypothetical cryptographic substitutions without modifying persistent state.
    Returns structured before/after comparisons, score deltas, and resolved/remaining risks.
    """
    from app.services.migration_simulator import (
        simulate_migration,
        MigrationSimulationError,
        ProfileNotFoundError,
    )
    try:
        return simulate_migration(request)
    except ProfileNotFoundError as e:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "PROFILE_NOT_FOUND", "detail": str(e)},
        )
    except MigrationSimulationError as e:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"error": "INVALID_MIGRATION_REQUEST", "detail": str(e)},
        )
    except Exception as e:
        logger.exception("Unexpected error during migration simulation")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "SIMULATION_INTERNAL_ERROR", "detail": str(e)},
        )



@router.get("/banking/upgrade-plan", tags=["Ranked Upgrade Plan"])
def get_banking_upgrade_plan():
    """
    Returns the deterministic prioritized migration roadmap across all representative banking systems.
    Dynamically computes priority scores, migration impact, and ordered queue.
    """
    from app.services.upgrade_planner import generate_ranked_upgrade_plan
    return generate_ranked_upgrade_plan()


@router.get("/banking/systems/{system_id}/cbom", tags=["CBOM Integration"])
@router.post("/banking/systems/{system_id}/cbom", tags=["CBOM Integration"])
def get_system_cbom(system_id: str):
    """
    Generates CycloneDX 1.7 Cryptographic Bill of Materials (CBOM) for a banking system.
    Inventories algorithms, protocols, certificates, keys, and dependencies without exposing secrets.
    """
    from app.services.report_service import generate_system_cbom
    from app.models.profiles import get_synthetic_profile_by_id
    if not get_synthetic_profile_by_id(system_id):
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "PROFILE_NOT_FOUND", "detail": f"Banking system '{system_id}' not found."},
        )
    return generate_system_cbom(system_id)


@router.get("/banking/systems/{system_id}/report/json", tags=["Reports & Auditability"])
def get_system_json_report(system_id: str):
    """
    Returns a comprehensive, machine-readable post-quantum assessment report
    sealed with a cryptographic audit hash chain record.
    """
    from app.services.report_service import build_complete_json_report
    from app.models.profiles import get_synthetic_profile_by_id
    if not get_synthetic_profile_by_id(system_id):
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "PROFILE_NOT_FOUND", "detail": f"Banking system '{system_id}' not found."},
        )
    report = build_complete_json_report(system_id)
    return report.model_dump()


@router.get("/banking/systems/{system_id}/report/pdf", tags=["Reports & Auditability"])
def get_system_pdf_report(system_id: str):
    """
    Generates and returns an executive-grade, professional PDF audit report.
    """
    from app.services.report_service import generate_pdf_report
    from app.models.profiles import get_synthetic_profile_by_id
    from fastapi import Response
    if not get_synthetic_profile_by_id(system_id):
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": "PROFILE_NOT_FOUND", "detail": f"Banking system '{system_id}' not found."},
        )
    pdf_bytes = generate_pdf_report(system_id)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=quantumshield-report-{system_id}.pdf"
        },
    )


@router.post("/audit/verify", tags=["Reports & Auditability"])
def verify_audit_record_endpoint(payload: Dict[str, Any]):
    """
    Verifies the cryptographic integrity of an individual audit record and optional payload.
    Detects any payload tampering or hash corruption.
    """
    from app.models.audit_chain import AuditRecord
    from app.services.audit_chain_service import DEFAULT_AUDIT_CHAIN_SERVICE
    try:
        record_data = payload.get("record", payload)
        record = AuditRecord(**record_data)
        assessment_data = payload.get("assessment_data")
        result = DEFAULT_AUDIT_CHAIN_SERVICE.verify_audit_record(record, assessment_data)
        return result
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"error": "INVALID_AUDIT_RECORD", "detail": str(e)},
        )


@router.post("/audit/verify-chain", tags=["Reports & Auditability"])
def verify_audit_chain_endpoint(records_data: List[Dict[str, Any]]):
    """
    Verifies an entire sequence of chained audit records.
    Detects broken chains, altered sequence history, or corrupted records.
    """
    from app.models.audit_chain import AuditRecord
    from app.services.audit_chain_service import DEFAULT_AUDIT_CHAIN_SERVICE
    try:
        records = [AuditRecord(**r) for r in records_data]
        result = DEFAULT_AUDIT_CHAIN_SERVICE.verify_audit_chain(records)
        return result
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"error": "INVALID_CHAIN_RECORDS", "detail": str(e)},
        )


@router.post("/scan/config", tags=["Configuration Scanning"])
def scan_uploaded_config(payload: ConfigScanRequest):
    """
    Safely scans uploaded configuration files without executing them.
    Files are stored temporarily and removed after scanning.
    """
    from app.scanners.config_scanner import BankingConfigScanner
    from app.services.finding_normalizer import normalize_config_finding
    from app.scanners.crypto_misuse.evidence import is_binary_content

    MAX_FILE_BYTES = 1_048_576
    MAX_TOTAL_BYTES = 5 * 1_048_576

    try:
        total_bytes = 0
        seen_names = set()
        validated_files = []

        with tempfile.TemporaryDirectory(prefix="quantumshield-config-") as temp_dir:
            root = Path(temp_dir).resolve()
            scanner = BankingConfigScanner(root_dir=root)

            supported_extensions = scanner.parser.SUPPORTED_EXTENSIONS

            for uploaded_file in payload.files:
                name = uploaded_file.name

                # Reject path traversal and unsafe filenames.
                if (
                    name in ("", ".", "..")
                    or "/" in name
                    or "\\" in name
                    or "\x00" in name
                    or Path(name).name != name
                ):
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={
                            "error": "INVALID_FILENAME",
                            "detail": "A filename is invalid.",
                        },
                    )

                # Reject duplicate filenames, ignoring case.
                normalized_name = name.casefold()
                if normalized_name in seen_names:
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={
                            "error": "DUPLICATE_FILENAME",
                            "detail": "Duplicate filenames are not allowed.",
                        },
                    )
                seen_names.add(normalized_name)

                # Accept only formats supported by the existing parser.
                extension = Path(name).suffix.lower()
                if (
                    not name.lower().startswith(".env")
                    and extension not in supported_extensions
                ):
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={
                            "error": "UNSUPPORTED_FILE_TYPE",
                            "detail": "One or more files have unsupported extensions.",
                        },
                    )

                # Encode content before checking whether it is binary.
                try:
                    content_bytes = uploaded_file.content.encode("utf-8")
                except UnicodeEncodeError:
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={
                            "error": "INVALID_FILE_ENCODING",
                            "detail": "Files must contain valid UTF-8 text.",
                        },
                    )

                # Reject binary-like content before writing it to disk.
                if is_binary_content(content_bytes):
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={
                            "error": "INVALID_FILE_CONTENT",
                            "detail": "Binary or null-byte content is not accepted.",
                        },
                    )

                file_size = len(content_bytes)

                if file_size > MAX_FILE_BYTES:
                    return JSONResponse(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        content={
                            "error": "FILE_TOO_LARGE",
                            "detail": "Each configuration file must be at most 1 MiB.",
                        },
                    )

                total_bytes += file_size
                if total_bytes > MAX_TOTAL_BYTES:
                    return JSONResponse(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        content={
                            "error": "UPLOAD_TOO_LARGE",
                            "detail": "The combined upload must be at most 5 MiB.",
                        },
                    )

                file_path = root / name
                file_path.write_bytes(content_bytes)
                validated_files.append(file_path)

            findings = []

            for file_path in validated_files:
                # Validate parsing separately so malformed configurations
                # are not silently reported as successful empty scans.
                parsed = scanner.parser.parse_file(
                    file_path,
                    relative_to=root,
                )

                if parsed.errors:
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={
                            "error": "INVALID_CONFIGURATION",
                            "detail": (
                                f"Configuration file '{file_path.name}' "
                                "could not be parsed."
                            ),
                        },
                    )

                observations = scanner.scan_file(
                    file_path,
                    relative_to=root,
                )

                for observation in observations:
                    normalized = normalize_config_finding(observation)
                    findings.append(normalized.model_dump(mode="json"))

            return {
                "scan_status": "SUCCESS",
                "files_scanned": len(validated_files),
                "finding_count": len(findings),
                "findings": findings,
            }

    except Exception:
        logging.exception("Uploaded configuration scan failed.")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "CONFIG_SCAN_FAILED",
                "detail": "The configuration scan could not be completed.",
            },
        )



@router.post("/scan/code", tags=["Code Scanning"])
def scan_uploaded_code(payload: CodeScanRequest):
    """
    Safely scans uploaded source files for cryptographic misuse.
    Source code is analyzed in memory and is never executed.
    """
    from app.scanners.crypto_misuse.scanner import (
        CryptoMisuseScanner,
        EXTENSION_TO_LANGUAGE,
    )
    from app.scanners.crypto_misuse.evidence import is_binary_content
    from app.services.finding_normalizer import (
        normalize_crypto_misuse_finding,
    )

    MAX_FILE_BYTES = 1_048_576
    MAX_TOTAL_BYTES = 5 * 1_048_576

    try:
        total_bytes = 0
        seen_names = set()
        validated_files = []

        # Validate every upload before scanning any file.
        for uploaded_file in payload.files:
            name = uploaded_file.name

            if (
                name in ("", ".", "..")
                or "/" in name
                or "\\" in name
                or "\x00" in name
                or Path(name).name != name
            ):
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={
                        "error": "INVALID_FILENAME",
                        "detail": "A filename is invalid.",
                    },
                )

            normalized_name = name.casefold()
            if normalized_name in seen_names:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={
                        "error": "DUPLICATE_FILENAME",
                        "detail": "Duplicate filenames are not allowed.",
                    },
                )
            seen_names.add(normalized_name)

            extension = Path(name).suffix.lower()
            language = EXTENSION_TO_LANGUAGE.get(extension)

            if not language:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={
                        "error": "UNSUPPORTED_FILE_TYPE",
                        "detail": "One or more files have unsupported source extensions.",
                    },
                )

            # Encode content before checking whether it is binary.
            try:
                content_bytes = uploaded_file.content.encode("utf-8")
            except UnicodeEncodeError:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={
                        "error": "INVALID_FILE_ENCODING",
                        "detail": "Files must contain valid UTF-8 text.",
                    },
                )

            # Reject binary-like content before scanning.
            if is_binary_content(content_bytes):
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={
                        "error": "INVALID_FILE_CONTENT",
                        "detail": "Binary or null-byte content is not accepted.",
                    },
                )

            file_size = len(content_bytes)

            if file_size > MAX_FILE_BYTES:
                return JSONResponse(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    content={
                        "error": "FILE_TOO_LARGE",
                        "detail": "Each source file must be at most 1 MiB.",
                    },
                )

            total_bytes += file_size
            if total_bytes > MAX_TOTAL_BYTES:
                return JSONResponse(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    content={
                        "error": "UPLOAD_TOO_LARGE",
                        "detail": "The combined upload must be at most 5 MiB.",
                    },
                )

            validated_files.append((name, language, uploaded_file.content))

        scanner = CryptoMisuseScanner(
            max_file_size_bytes=MAX_FILE_BYTES
        )

        findings = []

        for name, language, content in validated_files:
            result = scanner.scan_source(
                code=content,
                language=language,
                filename=name,
            )

            for finding in result.findings:
                normalized = normalize_crypto_misuse_finding(finding)
                findings.append(normalized.model_dump(mode="json"))

        return {
            "scan_status": "SUCCESS",
            "files_scanned": len(validated_files),
            "finding_count": len(findings),
            "findings": findings,
        }

    except Exception:
        logging.exception("Uploaded source-code scan failed.")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "CODE_SCAN_FAILED",
                "detail": "The source-code scan could not be completed.",
            },
        )



@router.post("/scan/cert", tags=["Certificate Scanning"])
def scan_uploaded_certificate(payload: CertificateScanRequest):
    """
    Safely parses an uploaded PEM certificate without contacting external systems.
    """
    from app.scanners.certificate_parser import parse_pem_certificate
    from app.scanners.crypto_misuse.evidence import is_binary_content

    MAX_FILE_BYTES = 1_048_576

    try:
        name = payload.name

        if (
            name in ("", ".", "..")
            or "/" in name
            or "\\" in name
            or "\x00" in name
            or Path(name).name != name
        ):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "error": "INVALID_FILENAME",
                    "detail": "The certificate filename is invalid.",
                },
            )

        if Path(name).suffix.lower() not in (".pem", ".crt", ".cer"):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "error": "UNSUPPORTED_FILE_TYPE",
                    "detail": "Upload a PEM certificate with a .pem, .crt, or .cer extension.",
                },
            )

        # Encode the uploaded certificate before binary-content validation.
        try:
            certificate_bytes = payload.content.encode("utf-8")
        except UnicodeEncodeError:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "error": "INVALID_FILE_ENCODING",
                    "detail": "The certificate must contain valid UTF-8 text.",
                },
            )

        # Reject binary-like content.
        if is_binary_content(certificate_bytes):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "error": "INVALID_FILE_CONTENT",
                    "detail": "Binary or null-byte content is not accepted.",
                },
            )

        # Enforce the maximum certificate size.
        if len(certificate_bytes) > MAX_FILE_BYTES:
            return JSONResponse(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                content={
                    "error": "FILE_TOO_LARGE",
                    "detail": "The certificate file must be at most 1 MiB.",
                },
            )

        # Check PEM certificate delimiters.
        if (
            "-----BEGIN CERTIFICATE-----" not in payload.content
            or "-----END CERTIFICATE-----" not in payload.content
        ):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "error": "INVALID_CERTIFICATE",
                    "detail": "The uploaded content is not a valid PEM certificate.",
                },
            )

        # Parse the certificate without contacting external systems.
        try:
            certificate = parse_pem_certificate(certificate_bytes)
        except Exception:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "error": "INVALID_CERTIFICATE",
                    "detail": "The uploaded PEM certificate could not be parsed.",
                },
            )

        return {
            "scan_status": "SUCCESS",
            "source": "UPLOADED_CERTIFICATE",
            "source_file": name,
            "evidence_status": "OBSERVED",
            "certificate": certificate,
        }

    except Exception:
        logging.exception("Uploaded certificate scan failed.")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "CERTIFICATE_SCAN_FAILED",
                "detail": "The certificate scan could not be completed.",
            },
        )
