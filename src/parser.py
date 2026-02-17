"""IOC parser and validator."""

import re
from pathlib import Path
from typing import Optional

import validators

from src.models import HashAlgorithm, IOC, IOCType

HEX_RE = re.compile(r"^[a-fA-F0-9]+$")


def detect_ioc_type(value: str) -> tuple[IOCType, Optional[HashAlgorithm]] | None:
    """
    Auto-detect IOC type from a raw value.

    Returns (IOCType, HashAlgorithm) tuple for hashes, (IOCType, None) for others.
    Returns None if unrecognized.
    """
    # Order matters: URL > IP > Hashes > Domain
    if validators.url(value):
        return (IOCType.URL, None)

    if validators.ipv4(value):
        return (IOCType.IP, None)

    # Check for hash (hex string with specific lengths)
    if HEX_RE.match(value):
        length = len(value)
        if length == 64 and validators.sha256(value):
            return (IOCType.HASH_SHA256, HashAlgorithm.SHA256)
        if length == 40 and validators.sha1(value):
            return (IOCType.HASH_SHA1, HashAlgorithm.SHA1)
        if length == 32 and validators.md5(value):
            return (IOCType.HASH_MD5, HashAlgorithm.MD5)

    if validators.domain(value):
        return (IOCType.DOMAIN, None)

    return None


def parse_ioc_file(file_path: str) -> tuple[list[IOC], list[tuple[int, str, str]], int]:
    """
    Parse IOC file and return valid IOCs, malformed lines, and duplicate count.

    Args:
        file_path: Path to the IOC input file

    Returns:
        Tuple of (valid_iocs, malformed_lines, duplicates_removed)
        malformed_lines is a list of (line_number, raw_line, error_message) tuples
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"IOC file not found: {file_path}")

    valid_iocs: list[IOC] = []
    malformed_lines: list[tuple[int, str, str]] = []
    seen: set[IOC] = set()
    duplicates_removed = 0

    with path.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            raw_line = line.rstrip("\n")
            stripped = raw_line.strip()

            # Skip empty lines and comments
            if not stripped or stripped.startswith("#"):
                continue

            # Detect IOC type
            detection = detect_ioc_type(stripped)
            if detection is None:
                malformed_lines.append(
                    (
                        line_num,
                        raw_line,
                        "Unrecognized IOC type (expected: IP, domain, URL, or hash)",
                    )
                )
                continue

            ioc_type, hash_algo = detection
            ioc = IOC(
                ioc_type=ioc_type,
                value=stripped,
                raw_line=raw_line,
                line_number=line_num,
                hash_algorithm=hash_algo,
            )

            # Deduplicate (case-insensitive)
            if ioc in seen:
                duplicates_removed += 1
                continue

            seen.add(ioc)
            valid_iocs.append(ioc)

    return valid_iocs, malformed_lines, duplicates_removed
