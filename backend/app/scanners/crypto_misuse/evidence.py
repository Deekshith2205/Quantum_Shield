"""Evidence extraction, masking, and fingerprinting utilities.
Guarantees:
- Safe secret masking (no secret disclosure in reports)
- Safe deterministic SHA-256 key fingerprints for duplicate detection
- Exact line & column tracking
- Pure static text operations (zero code execution)
"""

import hashlib
import re
from typing import Tuple, Dict, Any, List


def calculate_line_col(text: str, char_offset: int) -> Tuple[int, int]:
    """
    Calculate 1-based line number and 1-based column number from a character offset.
    Deterministic and handles any newline format (\n, \r\n, \r).
    """
    if char_offset < 0:
        return 1, 1
    if char_offset > len(text):
        char_offset = len(text)

    # Slice up to offset
    preceding = text[:char_offset]
    lines = preceding.splitlines(keepends=True)
    if not lines:
        return 1, 1

    line_num = len(lines)
    # The last line in preceding gives the column
    last_line = lines[-1]
    if last_line.endswith('\r\n'):
        col_num = len(last_line) - 1
    elif last_line.endswith('\n') or last_line.endswith('\r'):
        col_num = len(last_line)
    else:
        col_num = len(last_line) + 1

    # Special case: if char_offset was right after a newline, the next line begins at col 1
    if char_offset > 0 and text[char_offset - 1] in ('\n', '\r'):
        if text[char_offset - 1] == '\r' and char_offset < len(text) and text[char_offset] == '\n':
            # In the middle of \r\n, stay on current line
            pass
        else:
            line_num += 1
            col_num = 1

    return max(1, line_num), max(1, col_num)


def mask_secret(secret: str) -> str:
    """
    Mask sensitive secret strings to prevent secret leakage in scanner reports.
    Preserves prefix and suffix hints while masking inner characters.
    """
    if not secret:
        return "[EMPTY]"

    # If it's a PEM header block, redact the base64 payload cleanly
    if "-----BEGIN" in secret:
        header_match = re.search(r"-----BEGIN [A-Z0-9 ]+-----", secret)
        header = header_match.group(0) if header_match else "-----BEGIN PRIVATE KEY-----"
        footer_match = re.search(r"-----END [A-Z0-9 ]+-----", secret)
        footer = footer_match.group(0) if footer_match else "-----END PRIVATE KEY-----"
        return f"{header}\n  [REDACTED PRIVATE KEY MATERIAL]\n{footer}"

    clean = secret.strip().strip("'\"`")
    length = len(clean)

    if length <= 4:
        return "****"
    elif length <= 8:
        return clean[:2] + "****" + clean[-2:]
    elif length <= 16:
        return clean[:3] + "****" + clean[-3:]
    else:
        return clean[:4] + "*" * (min(12, length - 8)) + clean[-4:]


def compute_key_fingerprint(material: str) -> str:
    """
    Compute a safe, deterministic SHA-256 fingerprint for cryptographic material.
    Normalizes whitespace and encoding before hashing.
    Used for duplicate key detection without exposing plaintext keys.
    """
    if not material:
        return "sha256:empty"

    # Normalize by stripping surrounding whitespace, quotes, and newlines
    normalized = re.sub(r"\s+", "", material.strip().strip("'\"`"))
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return f"sha256:{digest[:16]}"


def extract_code_context(text: str, target_line: int, window: int = 1) -> Dict[str, Any]:
    """
    Extract a safe window of lines around target_line for contextual evidence.
    Lines are 1-based.
    """
    lines = text.splitlines()
    total = len(lines)
    if total == 0:
        return {"snippet": "", "start_line": 1, "end_line": 1}

    start = max(1, target_line - window)
    end = min(total, target_line + window)

    snippet_lines = []
    for idx in range(start, end + 1):
        line_content = lines[idx - 1]
        snippet_lines.append(f"{idx:4d} | {line_content}")

    return {
        "snippet": "\n".join(snippet_lines),
        "start_line": start,
        "end_line": end,
    }


def is_binary_content(data: bytes) -> bool:
    """
    Detect if byte sequence represents binary data rather than text.
    Checks for null bytes in the initial sample buffer.
    """
    sample = data[:4096]
    return b"\x00" in sample

