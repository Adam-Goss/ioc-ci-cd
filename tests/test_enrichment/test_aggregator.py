"""Tests for enrichment aggregator."""

import pytest

from src.config import PipelineConfig
from src.enrichment.aggregator import compute_confidence, enrich_ioc, extract_tags
from src.models import IOC, IOCType, SourceScore


def _make_config(**kwargs):
    """Create a PipelineConfig for testing."""
    defaults = dict(
        vt_api_key="test_vt",
        abuseipdb_api_key="test_abuse",
        otx_api_key="test_otx",
        weight_vt=0.45,
        weight_abuseipdb=0.25,
        weight_otx=0.30,
    )
    defaults.update(kwargs)
    return PipelineConfig(**defaults)


class TestComputeConfidence:
    """Tests for confidence score computation."""

    def test_all_sources_available(self):
        """Test confidence calculation with all sources available."""
        config = _make_config()

        scores = [
            SourceScore(source_name="virustotal", raw_score=80.0, available=True),
            SourceScore(source_name="abuseipdb", raw_score=90.0, available=True),
            SourceScore(source_name="otx", raw_score=70.0, available=True),
        ]

        confidence = compute_confidence(scores, config)

        # Expected: (80 * 0.45 + 90 * 0.25 + 70 * 0.30) / 1.0 = 79.5
        assert confidence == pytest.approx(79.5, rel=0.01)

    def test_one_source_unavailable(self):
        """Test confidence with one source unavailable (weight renormalization)."""
        config = _make_config()

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
        config = _make_config()

        scores = [
            SourceScore(source_name="virustotal", raw_score=0.0, available=False),
            SourceScore(source_name="abuseipdb", raw_score=0.0, available=False),
            SourceScore(source_name="otx", raw_score=0.0, available=False),
        ]

        confidence = compute_confidence(scores, config)
        assert confidence == 0.0

    def test_single_source_available(self):
        """Test confidence with only one source available."""
        config = _make_config(weight_vt=0.45)

        scores = [
            SourceScore(source_name="virustotal", raw_score=75.0, available=True),
            SourceScore(source_name="abuseipdb", raw_score=0.0, available=False),
            SourceScore(source_name="otx", raw_score=0.0, available=False),
        ]

        confidence = compute_confidence(scores, config)
        assert confidence == 75.0

    def test_zero_scores(self):
        """Test confidence with zero scores (not unavailable, just zero)."""
        config = _make_config()

        scores = [
            SourceScore(source_name="virustotal", raw_score=0.0, available=True),
            SourceScore(source_name="abuseipdb", raw_score=0.0, available=True),
            SourceScore(source_name="otx", raw_score=0.0, available=True),
        ]

        confidence = compute_confidence(scores, config)
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
        assert len(tags) <= 5

    def test_extract_no_tags(self):
        """Test extraction when sources have no tags."""
        scores = [
            SourceScore(source_name="virustotal", raw_score=80.0, available=True),
            SourceScore(source_name="abuseipdb", raw_score=90.0, available=True),
        ]

        tags = extract_tags(scores)
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
        assert all(tag.islower() for tag in tags)
        assert "malware" in tags
        assert "c2" in tags


class TestEnrichIocEnabledSources:
    """Tests for modular enrichment source selection."""

    @pytest.mark.asyncio
    async def test_enabled_sources_subset(self):
        """Test that only enabled sources are instantiated."""
        from unittest.mock import AsyncMock, MagicMock, patch

        config = _make_config()
        ioc = IOC(IOCType.IP, "1.2.3.4", "1.2.3.4", 1)

        mock_vt_class = MagicMock()
        vt_instance = AsyncMock()
        vt_instance.enrich.return_value = SourceScore("virustotal", 50.0)
        vt_instance.close = AsyncMock()
        mock_vt_class.return_value = vt_instance

        mock_abuse_class = MagicMock()
        mock_otx_class = MagicMock()

        with patch.dict("src.enrichment.aggregator.ENRICHMENT_REGISTRY", {
            "virustotal": mock_vt_class,
            "abuseipdb": mock_abuse_class,
            "otx": mock_otx_class,
        }):
            result = await enrich_ioc(ioc, config, enabled_sources=["virustotal"])

        # Only VT should have been instantiated
        mock_vt_class.assert_called_once()
        mock_abuse_class.assert_not_called()
        mock_otx_class.assert_not_called()

    @pytest.mark.asyncio
    async def test_enabled_sources_none_uses_config(self):
        """Test that enabled_sources=None uses config.enrichment_sources."""
        from unittest.mock import AsyncMock, MagicMock, patch

        config = _make_config()
        config.enrichment_sources = ["virustotal"]
        ioc = IOC(IOCType.IP, "1.2.3.4", "1.2.3.4", 1)

        mock_vt_class = MagicMock()
        vt_instance = AsyncMock()
        vt_instance.enrich.return_value = SourceScore("virustotal", 50.0)
        vt_instance.close = AsyncMock()
        mock_vt_class.return_value = vt_instance

        mock_abuse_class = MagicMock()
        mock_otx_class = MagicMock()

        with patch.dict("src.enrichment.aggregator.ENRICHMENT_REGISTRY", {
            "virustotal": mock_vt_class,
            "abuseipdb": mock_abuse_class,
            "otx": mock_otx_class,
        }):
            result = await enrich_ioc(ioc, config, enabled_sources=None)

        mock_vt_class.assert_called_once()
        mock_abuse_class.assert_not_called()
        mock_otx_class.assert_not_called()

    @pytest.mark.asyncio
    async def test_unknown_source_is_skipped(self):
        """Test that unknown source names are skipped with a warning."""
        from unittest.mock import AsyncMock, MagicMock, patch

        config = _make_config()
        ioc = IOC(IOCType.IP, "1.2.3.4", "1.2.3.4", 1)

        mock_vt_class = MagicMock()
        vt_instance = AsyncMock()
        vt_instance.enrich.return_value = SourceScore("virustotal", 50.0)
        vt_instance.close = AsyncMock()
        mock_vt_class.return_value = vt_instance

        mock_abuse_class = MagicMock()
        mock_otx_class = MagicMock()

        with patch.dict("src.enrichment.aggregator.ENRICHMENT_REGISTRY", {
            "virustotal": mock_vt_class,
            "abuseipdb": mock_abuse_class,
            "otx": mock_otx_class,
        }):
            # "greynoise" is not in ENRICHMENT_REGISTRY
            result = await enrich_ioc(ioc, config, enabled_sources=["virustotal", "greynoise"])

        mock_vt_class.assert_called_once()
        mock_abuse_class.assert_not_called()
        mock_otx_class.assert_not_called()
