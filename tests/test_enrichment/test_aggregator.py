"""Tests for enrichment aggregator."""

import pytest

from src.config import PipelineConfig
from src.enrichment.aggregator import compute_confidence, extract_tags
from src.models import IOC, IOCType, SourceScore


class TestComputeConfidence:
    """Tests for confidence score computation."""

    def test_all_sources_available(self):
        """Test confidence calculation with all sources available."""
        config = PipelineConfig(
            vt_api_key="test",
            abuseipdb_api_key="test",
            otx_api_key="test",
            weight_vt=0.45,
            weight_abuseipdb=0.25,
            weight_otx=0.30,
        )

        scores = [
            SourceScore(source_name="virustotal", raw_score=80.0, available=True),
            SourceScore(source_name="abuseipdb", raw_score=90.0, available=True),
            SourceScore(source_name="otx", raw_score=70.0, available=True),
        ]

        confidence = compute_confidence(scores, config)

        # Expected: (80 * 0.45 + 90 * 0.25 + 70 * 0.30) / (0.45 + 0.25 + 0.30)
        # = (36 + 22.5 + 21) / 1.0 = 79.5
        assert confidence == pytest.approx(79.5, rel=0.01)

    def test_one_source_unavailable(self):
        """Test confidence with one source unavailable (weight renormalization)."""
        config = PipelineConfig(
            vt_api_key="test",
            abuseipdb_api_key="test",
            otx_api_key="test",
            weight_vt=0.45,
            weight_abuseipdb=0.25,
            weight_otx=0.30,
        )

        # AbuseIPDB unavailable (e.g., domain IOC)
        scores = [
            SourceScore(source_name="virustotal", raw_score=80.0, available=True),
            SourceScore(source_name="abuseipdb", raw_score=0.0, available=False),
            SourceScore(source_name="otx", raw_score=70.0, available=True),
        ]

        confidence = compute_confidence(scores, config)

        # Weights renormalized: VT = 0.45/0.75 = 0.6, OTX = 0.30/0.75 = 0.4
        # Expected: (80 * 0.6 + 70 * 0.4) = 48 + 28 = 76
        assert confidence == pytest.approx(76.0, rel=0.01)

    def test_all_sources_unavailable(self):
        """Test confidence when all sources are unavailable."""
        config = PipelineConfig(
            vt_api_key="test",
            abuseipdb_api_key="test",
            otx_api_key="test",
        )

        scores = [
            SourceScore(source_name="virustotal", raw_score=0.0, available=False),
            SourceScore(source_name="abuseipdb", raw_score=0.0, available=False),
            SourceScore(source_name="otx", raw_score=0.0, available=False),
        ]

        confidence = compute_confidence(scores, config)

        # No sources available
        assert confidence == 0.0

    def test_single_source_available(self):
        """Test confidence with only one source available."""
        config = PipelineConfig(
            vt_api_key="test",
            abuseipdb_api_key="test",
            otx_api_key="test",
            weight_vt=0.45,
        )

        scores = [
            SourceScore(source_name="virustotal", raw_score=75.0, available=True),
            SourceScore(source_name="abuseipdb", raw_score=0.0, available=False),
            SourceScore(source_name="otx", raw_score=0.0, available=False),
        ]

        confidence = compute_confidence(scores, config)

        # Only VT available, gets full weight
        assert confidence == 75.0

    def test_zero_scores(self):
        """Test confidence with zero scores (not unavailable, just zero)."""
        config = PipelineConfig(
            vt_api_key="test",
            abuseipdb_api_key="test",
            otx_api_key="test",
            weight_vt=0.45,
            weight_abuseipdb=0.25,
            weight_otx=0.30,
        )

        scores = [
            SourceScore(source_name="virustotal", raw_score=0.0, available=True),
            SourceScore(source_name="abuseipdb", raw_score=0.0, available=True),
            SourceScore(source_name="otx", raw_score=0.0, available=True),
        ]

        confidence = compute_confidence(scores, config)

        # All sources say 0 (benign)
        assert confidence == 0.0


class TestExtractTags:
    """Tests for tag extraction and aggregation."""

    def test_extract_common_tags(self):
        """Test extraction of tags appearing in multiple sources."""
        scores = [
            SourceScore(
                source_name="virustotal",
                raw_score=80.0,
                available=True,
                details={"tags": ["malware", "c2", "botnet"]},
            ),
            SourceScore(
                source_name="otx",
                raw_score=70.0,
                available=True,
                details={"tags": ["malware", "apt29"]},
            ),
        ]

        tags = extract_tags(scores)

        # "malware" appears in both sources, should be promoted
        assert "malware" in tags

    def test_extract_no_common_tags(self):
        """Test extraction when no tags are common."""
        scores = [
            SourceScore(
                source_name="virustotal",
                raw_score=80.0,
                available=True,
                details={"tags": ["malware", "c2"]},
            ),
            SourceScore(
                source_name="otx",
                raw_score=70.0,
                available=True,
                details={"tags": ["botnet", "apt29", "phishing"]},
            ),
        ]

        tags = extract_tags(scores)

        # No common tags, should return top 5 most frequent
        assert len(tags) <= 5

    def test_extract_no_tags(self):
        """Test extraction when sources have no tags."""
        scores = [
            SourceScore(source_name="virustotal", raw_score=80.0, available=True),
            SourceScore(source_name="abuseipdb", raw_score=90.0, available=True),
        ]

        tags = extract_tags(scores)

        # No tags available
        assert tags == []

    def test_extract_tags_unavailable_source(self):
        """Test that unavailable sources are skipped."""
        scores = [
            SourceScore(
                source_name="virustotal",
                raw_score=80.0,
                available=True,
                details={"tags": ["malware"]},
            ),
            SourceScore(
                source_name="abuseipdb",
                raw_score=0.0,
                available=False,
                details={"tags": ["botnet"]},
            ),
        ]

        tags = extract_tags(scores)

        # Only tags from available sources
        assert "malware" in tags
        assert "botnet" not in tags

    def test_extract_tags_case_normalization(self):
        """Test that tags are normalized to lowercase."""
        scores = [
            SourceScore(
                source_name="virustotal",
                raw_score=80.0,
                available=True,
                details={"tags": ["Malware", "C2"]},
            ),
            SourceScore(
                source_name="otx",
                raw_score=70.0,
                available=True,
                details={"tags": ["malware", "c2"]},
            ),
        ]

        tags = extract_tags(scores)

        # All lowercase
        assert all(tag.islower() for tag in tags)
        # "malware" and "c2" should be promoted (appear in both)
        assert "malware" in tags
        assert "c2" in tags
