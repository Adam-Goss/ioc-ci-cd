"""Tests for data models."""

import pytest

from src.models import EnrichmentResult, IOC, IOCType, SourceScore, ValidationReport


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
