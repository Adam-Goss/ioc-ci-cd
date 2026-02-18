"""Tests for data models."""

import pytest

from src.models import (
    ConfidenceLevel,
    EnrichmentResult,
    HuntResult,
    IOC,
    IOCType,
    SourceScore,
    ValidationReport,
    get_confidence_level,
)


class TestConfidenceLevel:
    """Tests for ConfidenceLevel enum and get_confidence_level helper."""

    def test_low_boundary(self):
        """Test low confidence level boundaries."""
        assert get_confidence_level(0.0) == ConfidenceLevel.LOW
        assert get_confidence_level(15.0) == ConfidenceLevel.LOW
        assert get_confidence_level(29.9) == ConfidenceLevel.LOW

    def test_medium_boundary(self):
        """Test medium confidence level boundaries."""
        assert get_confidence_level(30.0) == ConfidenceLevel.MEDIUM
        assert get_confidence_level(50.0) == ConfidenceLevel.MEDIUM
        assert get_confidence_level(69.9) == ConfidenceLevel.MEDIUM

    def test_high_boundary(self):
        """Test high confidence level boundaries."""
        assert get_confidence_level(70.0) == ConfidenceLevel.HIGH
        assert get_confidence_level(85.0) == ConfidenceLevel.HIGH
        assert get_confidence_level(100.0) == ConfidenceLevel.HIGH

    def test_enum_values(self):
        """Test ConfidenceLevel enum values."""
        assert ConfidenceLevel.LOW.value == "low"
        assert ConfidenceLevel.MEDIUM.value == "medium"
        assert ConfidenceLevel.HIGH.value == "high"


class TestIOC:
    """Tests for IOC dataclass."""

    def test_ioc_creation(self):
        """Test IOC object creation."""
        ioc = IOC(
            ioc_type=IOCType.IP,
            value="192.168.1.1",
            raw_line="192.168.1.1",
            line_number=1,
        )

        assert ioc.ioc_type == IOCType.IP
        assert ioc.value == "192.168.1.1"
        assert ioc.line_number == 1

    def test_ioc_equality_case_insensitive(self):
        """Test that IOC equality is case-insensitive."""
        ioc1 = IOC(
            ioc_type=IOCType.DOMAIN,
            value="Evil.Example.Com",
            raw_line="Evil.Example.Com",
            line_number=1,
        )
        ioc2 = IOC(
            ioc_type=IOCType.DOMAIN,
            value="evil.example.com",
            raw_line="evil.example.com",
            line_number=2,
        )

        assert ioc1 == ioc2

    def test_ioc_hash_case_insensitive(self):
        """Test that IOC hash is case-insensitive (for deduplication)."""
        ioc1 = IOC(
            ioc_type=IOCType.DOMAIN,
            value="Evil.Example.Com",
            raw_line="Evil.Example.Com",
            line_number=1,
        )
        ioc2 = IOC(
            ioc_type=IOCType.DOMAIN,
            value="evil.example.com",
            raw_line="evil.example.com",
            line_number=2,
        )

        assert hash(ioc1) == hash(ioc2)

    def test_ioc_set_deduplication(self):
        """Test that IOCs can be deduplicated in a set."""
        ioc1 = IOC(
            ioc_type=IOCType.IP,
            value="192.168.1.1",
            raw_line="192.168.1.1",
            line_number=1,
        )
        ioc2 = IOC(
            ioc_type=IOCType.IP,
            value="192.168.1.1",
            raw_line="192.168.1.1",
            line_number=5,
        )

        ioc_set = {ioc1, ioc2}
        assert len(ioc_set) == 1  # Deduplicated


class TestSourceScore:
    """Tests for SourceScore dataclass."""

    def test_source_score_creation(self):
        """Test SourceScore object creation."""
        score = SourceScore(
            source_name="virustotal",
            raw_score=75.5,
            details={"malicious_count": 45},
            available=True,
        )

        assert score.source_name == "virustotal"
        assert score.raw_score == 75.5
        assert score.available is True
        assert "malicious_count" in score.details

    def test_source_score_unavailable(self):
        """Test SourceScore for unavailable source."""
        score = SourceScore(
            source_name="virustotal",
            raw_score=0.0,
            available=False,
            error="API rate limit exceeded",
        )

        assert score.available is False
        assert score.error is not None


class TestEnrichmentResult:
    """Tests for EnrichmentResult dataclass."""

    def test_enrichment_result_creation(self):
        """Test EnrichmentResult object creation."""
        ioc = IOC(
            ioc_type=IOCType.IP,
            value="192.168.1.1",
            raw_line="192.168.1.1",
            line_number=1,
        )

        scores = [
            SourceScore(source_name="virustotal", raw_score=75.5, available=True),
            SourceScore(source_name="abuseipdb", raw_score=87.0, available=True),
        ]

        result = EnrichmentResult(
            ioc=ioc,
            scores=scores,
            confidence=80.2,
            above_threshold=True,
            tags=["malware", "c2"],
        )

        assert result.confidence == 80.2
        assert result.above_threshold is True
        assert len(result.tags) == 2


class TestValidationReport:
    """Tests for ValidationReport dataclass."""

    def test_validation_report_creation(self):
        """Test ValidationReport object creation."""
        ioc = IOC(
            ioc_type=IOCType.IP,
            value="192.168.1.1",
            raw_line="192.168.1.1",
            line_number=1,
        )

        result = EnrichmentResult(
            ioc=ioc,
            scores=[],
            confidence=75.0,
            above_threshold=True,
        )

        report = ValidationReport(
            valid_iocs=[ioc],
            malformed_lines=[(5, "invalid line", "error message")],
            duplicates_removed=2,
            enrichment_results=[result],
            threshold=70.0,
            override=False,
        )

        assert len(report.valid_iocs) == 1
        assert len(report.malformed_lines) == 1
        assert report.duplicates_removed == 2
        assert report.threshold == 70.0


class TestHuntResult:
    """Tests for HuntResult dataclass."""

    def test_hunt_result_creation(self):
        """Test HuntResult object creation with hits."""
        ioc = IOC(IOCType.IP, "1.2.3.4", "1.2.3.4", 1)
        result = HuntResult(
            ioc=ioc,
            platform="splunk",
            hits_found=42,
            earliest_hit="2026-01-01T00:00:00Z",
            latest_hit="2026-02-01T00:00:00Z",
            query_used='search index=main src_ip="1.2.3.4"',
        )

        assert result.platform == "splunk"
        assert result.hits_found == 42
        assert result.success is True
        assert result.error is None

    def test_hunt_result_failure(self):
        """Test HuntResult for a failed search."""
        ioc = IOC(IOCType.DOMAIN, "evil.com", "evil.com", 1)
        result = HuntResult(
            ioc=ioc,
            platform="elastic",
            hits_found=0,
            error="Connection refused",
            success=False,
        )

        assert result.success is False
        assert result.hits_found == 0
        assert result.error == "Connection refused"

    def test_hunt_result_no_hits(self):
        """Test HuntResult with zero hits (successful search, nothing found)."""
        ioc = IOC(IOCType.IP, "10.0.0.1", "10.0.0.1", 1)
        result = HuntResult(
            ioc=ioc,
            platform="splunk",
            hits_found=0,
        )

        assert result.hits_found == 0
        assert result.success is True
        assert result.sample_events == []
