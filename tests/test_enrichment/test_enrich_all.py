"""Tests for enrich_ioc and enrich_all aggregation functions."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.config import PipelineConfig
from src.models import IOC, IOCType, SourceScore


class TestEnrichIOC:
    """Tests for single-IOC enrichment pipeline."""

    def _make_config(self):
        return PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
        )

    @pytest.mark.asyncio
    async def test_enrich_ioc_calls_all_sources(self):
        """Test that enrich_ioc calls all three TI sources."""
        config = self._make_config()
        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)

        mock_vt_score = SourceScore("virustotal", 80.0, available=True)
        mock_abuse_score = SourceScore("abuseipdb", 90.0, available=True)
        mock_otx_score = SourceScore("otx", 70.0, available=True)

        mock_vt_class = MagicMock()
        mock_vt = AsyncMock()
        mock_vt.enrich.return_value = mock_vt_score
        mock_vt.close = AsyncMock()
        mock_vt_class.return_value = mock_vt

        mock_abuse_class = MagicMock()
        mock_abuse = AsyncMock()
        mock_abuse.enrich.return_value = mock_abuse_score
        mock_abuse.close = AsyncMock()
        mock_abuse_class.return_value = mock_abuse

        mock_otx_class = MagicMock()
        mock_otx = AsyncMock()
        mock_otx.enrich.return_value = mock_otx_score
        mock_otx_class.return_value = mock_otx

        from src.enrichment.aggregator import enrich_ioc

        with patch.dict("src.enrichment.aggregator.ENRICHMENT_REGISTRY", {
            "virustotal": mock_vt_class,
            "abuseipdb": mock_abuse_class,
            "otx": mock_otx_class,
        }):
            result = await enrich_ioc(ioc, config)

        assert result.ioc == ioc
        assert len(result.scores) == 3
        assert result.confidence > 0

        # All clients should have been called
        mock_vt.enrich.assert_called_once_with(ioc)
        mock_abuse.enrich.assert_called_once_with(ioc)
        mock_otx.enrich.assert_called_once_with(ioc)

        # Clients should be cleaned up
        mock_vt.close.assert_called_once()
        mock_abuse.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_enrich_ioc_with_unavailable_source(self):
        """Test enrich_ioc handles unavailable source gracefully."""
        config = self._make_config()
        ioc = IOC(IOCType.DOMAIN, "evil.com", "evil.com", 1)

        mock_vt_score = SourceScore("virustotal", 80.0, available=True)
        mock_abuse_score = SourceScore("abuseipdb", 0.0, available=False, error="Not supported")
        mock_otx_score = SourceScore("otx", 70.0, available=True)

        mock_vt_class = MagicMock()
        mock_vt = AsyncMock()
        mock_vt.enrich.return_value = mock_vt_score
        mock_vt.close = AsyncMock()
        mock_vt_class.return_value = mock_vt

        mock_abuse_class = MagicMock()
        mock_abuse = AsyncMock()
        mock_abuse.enrich.return_value = mock_abuse_score
        mock_abuse.close = AsyncMock()
        mock_abuse_class.return_value = mock_abuse

        mock_otx_class = MagicMock()
        mock_otx = AsyncMock()
        mock_otx.enrich.return_value = mock_otx_score
        mock_otx_class.return_value = mock_otx

        from src.enrichment.aggregator import enrich_ioc

        with patch.dict("src.enrichment.aggregator.ENRICHMENT_REGISTRY", {
            "virustotal": mock_vt_class,
            "abuseipdb": mock_abuse_class,
            "otx": mock_otx_class,
        }):
            result = await enrich_ioc(ioc, config)

        # Should still have 3 scores (one unavailable)
        assert len(result.scores) == 3
        # Confidence should be renormalized across available sources only
        assert result.confidence > 0

    @pytest.mark.asyncio
    async def test_enrich_ioc_cleans_up_on_error(self):
        """Test that clients are cleaned up even when enrichment fails."""
        config = self._make_config()
        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)

        mock_vt_class = MagicMock()
        mock_vt = AsyncMock()
        mock_vt.enrich.side_effect = Exception("VT exploded")
        mock_vt.close = AsyncMock()
        mock_vt_class.return_value = mock_vt

        mock_abuse_class = MagicMock()
        mock_abuse = AsyncMock()
        mock_abuse.close = AsyncMock()
        mock_abuse_class.return_value = mock_abuse

        mock_otx_class = MagicMock()
        mock_otx = AsyncMock()
        mock_otx_class.return_value = mock_otx

        from src.enrichment.aggregator import enrich_ioc

        with patch.dict("src.enrichment.aggregator.ENRICHMENT_REGISTRY", {
            "virustotal": mock_vt_class,
            "abuseipdb": mock_abuse_class,
            "otx": mock_otx_class,
        }):
            with pytest.raises(Exception):
                await enrich_ioc(ioc, config)

        # Clients should still be cleaned up
        mock_vt.close.assert_called_once()
        mock_abuse.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_enrich_ioc_with_custom_rate_limits(self):
        """Test enrich_ioc uses custom rate limits from config."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            vt_rate_limit=10,
            abuseipdb_rate_limit=5,
            otx_rate_limit=50,
        )
        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)

        mock_score = SourceScore("test", 50.0, available=True)

        with patch("src.enrichment.aggregator.VirusTotalClient") as mock_vt_class, \
             patch("src.enrichment.aggregator.AbuseIPDBClient") as mock_abuse_class, \
             patch("src.enrichment.aggregator.OTXClient") as mock_otx_class, \
             patch("src.enrichment.aggregator.TokenBucketRateLimiter") as mock_limiter_class:

            for cls in [mock_vt_class, mock_abuse_class, mock_otx_class]:
                mock_client = AsyncMock()
                mock_client.enrich.return_value = mock_score
                mock_client.close = AsyncMock()
                cls.return_value = mock_client

            from src.enrichment.aggregator import enrich_ioc

            await enrich_ioc(ioc, config)

            # Rate limiter should have been created for each source
            assert mock_limiter_class.call_count == 3


class TestEnrichAll:
    """Tests for batch IOC enrichment."""

    @pytest.mark.asyncio
    async def test_enrich_all_multiple_iocs(self):
        """Test enriching multiple IOCs concurrently."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
        )

        iocs = [
            IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1),
            IOC(IOCType.DOMAIN, "evil.com", "evil.com", 2),
        ]

        mock_score = SourceScore("test", 50.0, available=True)

        with patch("src.enrichment.aggregator.VirusTotalClient") as mock_vt_class, \
             patch("src.enrichment.aggregator.AbuseIPDBClient") as mock_abuse_class, \
             patch("src.enrichment.aggregator.OTXClient") as mock_otx_class, \
             patch("src.enrichment.aggregator.TokenBucketRateLimiter"):

            for cls in [mock_vt_class, mock_abuse_class, mock_otx_class]:
                mock_client = AsyncMock()
                mock_client.enrich.return_value = mock_score
                mock_client.close = AsyncMock()
                cls.return_value = mock_client

            from src.enrichment.aggregator import enrich_all

            results = await enrich_all(iocs, config)

        assert len(results) == 2
        assert results[0].ioc == iocs[0]
        assert results[1].ioc == iocs[1]

    @pytest.mark.asyncio
    async def test_enrich_all_empty_list(self):
        """Test enriching empty IOC list."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
        )

        from src.enrichment.aggregator import enrich_all

        results = await enrich_all([], config)

        assert len(results) == 0
