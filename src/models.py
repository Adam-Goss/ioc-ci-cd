"""Data models for IOC processing."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class IOCType(Enum):
    """Supported IOC types."""

    IP = "ip"
    DOMAIN = "domain"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    URL = "url"


class HashAlgorithm(Enum):
    """Hash algorithm types."""

    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


@dataclass
class IOC:
    """Represents a single Indicator of Compromise."""

    ioc_type: IOCType
    value: str
    raw_line: str
    line_number: int
    hash_algorithm: Optional[HashAlgorithm] = None

    def __hash__(self) -> int:
        """Make IOC hashable for deduplication."""
        return hash((self.ioc_type, self.value.lower()))

    def __eq__(self, other: object) -> bool:
        """Compare IOCs for equality (case-insensitive value)."""
        if not isinstance(other, IOC):
            return NotImplemented
        return self.ioc_type == other.ioc_type and self.value.lower() == other.value.lower()


@dataclass
class SourceScore:
    """Enrichment score from a single TI source."""

    source_name: str
    raw_score: float
    details: dict = field(default_factory=dict)
    available: bool = True
    error: Optional[str] = None


@dataclass
class EnrichmentResult:
    """Aggregated enrichment result for an IOC."""

    ioc: IOC
    scores: list[SourceScore] = field(default_factory=list)
    confidence: float = 0.0
    above_threshold: bool = False
    tags: list[str] = field(default_factory=list)


@dataclass
class ValidationReport:
    """Complete validation report for a batch of IOCs."""

    valid_iocs: list[IOC]
    malformed_lines: list[tuple[int, str, str]]  # (line_number, raw_line, error_message)
    duplicates_removed: int
    enrichment_results: list[EnrichmentResult]
    threshold: float
    override: bool
