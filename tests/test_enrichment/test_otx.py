"""Tests for OTX AlienVault enrichment client."""

import math
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.models import IOC, IOCType
from src.rate_limiter import RateLimiterConfig, TokenBucketRateLimiter


class TestOTXClient:
    """Tests for OTXClient."""

    def _make_limiter(self):
        config = RateLimiterConfig(requests_per_minute=100, name="otx-test")
        return TokenBucketRateLimiter(config)

    def _make_client(self, limiter=None):
        from src.enrichment.otx import OTXClient

        limiter = limiter or self._make_limiter()
        with patch("src.enrichment.otx.OTXv2"):
            client = OTXClient("fake-api-key", limiter)
        return client

    def test_supports_all_ioc_types(self):
        """Test that OTX supports all IOC types."""
        client = self._make_client()
        for ioc_type in IOCType:
            ioc = IOC(ioc_type, "test", "test", 1)
            assert client.supports(ioc) is True

    @pytest.mark.asyncio
    async def test_enrich_ip_with_pulses_and_malware(self):
        """Test enriching an IP with pulses and malware data."""
        client = self._make_client()

        mock_result = {
            "general": {"reputation": -2},
            "pulse_info": {
                "pulses": [
                    {"name": "APT29 Infrastructure"},
                    {"name": "Known C2 Servers"},
                    {"name": "Botnet IPs"},
                ]
            },
            "malware": {"data": [{"hash": "abc123"}, {"hash": "def456"}]},
        }

        with patch("asyncio.get_event_loop") as mock_loop_fn:
            mock_loop = MagicMock()
            mock_loop_fn.return_value = mock_loop
            mock_loop.run_in_executor = AsyncMock(return_value=mock_result)

            ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
            score = await client.enrich(ioc)

        assert score.source_name == "otx"
        assert score.available is True

        # 3 pulses: log2(4) * 15 = 30, malware bonus = 20, total = 50
        expected = min(100, math.log2(3 + 1) * 15 + 20)
        assert score.raw_score == pytest.approx(expected, abs=0.1)

        assert score.details["pulse_count"] == 3
        assert score.details["malware_samples"] == 2
        assert "APT29 Infrastructure" in score.details["pulse_names"]

    @pytest.mark.asyncio
    async def test_enrich_ip_no_pulses(self):
        """Test enriching an IP with no pulses."""
        client = self._make_client()

        mock_result = {
            "general": {},
            "pulse_info": {"pulses": []},
            "malware": {"data": []},
        }

        with patch("asyncio.get_event_loop") as mock_loop_fn:
            mock_loop = MagicMock()
            mock_loop_fn.return_value = mock_loop
            mock_loop.run_in_executor = AsyncMock(return_value=mock_result)

            ioc = IOC(IOCType.IP, "10.0.0.1", "10.0.0.1", 1)
            score = await client.enrich(ioc)

        assert score.available is True
        assert score.raw_score == 0.0
        assert score.details["pulse_count"] == 0

    @pytest.mark.asyncio
    async def test_enrich_domain(self):
        """Test enriching a domain."""
        from OTXv2 import IndicatorTypes

        client = self._make_client()

        mock_result = {
            "general": {"reputation": -5},
            "pulse_info": {"pulses": [{"name": "Phishing domains"}]},
            "malware": {"data": []},
        }

        with patch("asyncio.get_event_loop") as mock_loop_fn:
            mock_loop = MagicMock()
            mock_loop_fn.return_value = mock_loop
            mock_loop.run_in_executor = AsyncMock(return_value=mock_result)

            ioc = IOC(IOCType.DOMAIN, "evil.com", "evil.com", 1)
            score = await client.enrich(ioc)

            # Verify correct indicator type was used
            call_args = mock_loop.run_in_executor.call_args
            assert call_args[0][2] == IndicatorTypes.DOMAIN

        assert score.available is True
        assert score.details["pulse_count"] == 1

    @pytest.mark.asyncio
    async def test_enrich_url(self):
        """Test enriching a URL."""
        from OTXv2 import IndicatorTypes

        client = self._make_client()

        mock_result = {
            "general": {},
            "pulse_info": {"pulses": [{"name": "Malicious URLs"}]},
            "malware": {"data": []},
        }

        with patch("asyncio.get_event_loop") as mock_loop_fn:
            mock_loop = MagicMock()
            mock_loop_fn.return_value = mock_loop
            mock_loop.run_in_executor = AsyncMock(return_value=mock_result)

            ioc = IOC(IOCType.URL, "http://evil.com/bad", "http://evil.com/bad", 1)
            await client.enrich(ioc)

            call_args = mock_loop.run_in_executor.call_args
            assert call_args[0][2] == IndicatorTypes.URL

    @pytest.mark.asyncio
    async def test_enrich_hash_md5(self):
        """Test enriching an MD5 hash."""
        from OTXv2 import IndicatorTypes

        client = self._make_client()

        mock_result = {
            "general": {},
            "pulse_info": {"pulses": []},
            "malware": {"data": [{"hash": "abc"}]},
        }

        with patch("asyncio.get_event_loop") as mock_loop_fn:
            mock_loop = MagicMock()
            mock_loop_fn.return_value = mock_loop
            mock_loop.run_in_executor = AsyncMock(return_value=mock_result)

            ioc = IOC(IOCType.HASH_MD5, "d41d8cd98f00b204e9800998ecf8427e", "...", 1)
            score = await client.enrich(ioc)

            call_args = mock_loop.run_in_executor.call_args
            assert call_args[0][2] == IndicatorTypes.FILE_HASH_MD5

        # No pulses but has malware: bonus only = 20
        assert score.raw_score == 20.0

    @pytest.mark.asyncio
    async def test_enrich_hash_sha1(self):
        """Test enriching a SHA-1 hash."""
        from OTXv2 import IndicatorTypes

        client = self._make_client()

        mock_result = {
            "general": {},
            "pulse_info": {"pulses": []},
            "malware": {"data": []},
        }

        with patch("asyncio.get_event_loop") as mock_loop_fn:
            mock_loop = MagicMock()
            mock_loop_fn.return_value = mock_loop
            mock_loop.run_in_executor = AsyncMock(return_value=mock_result)

            ioc = IOC(IOCType.HASH_SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709", "...", 1)
            await client.enrich(ioc)

            call_args = mock_loop.run_in_executor.call_args
            assert call_args[0][2] == IndicatorTypes.FILE_HASH_SHA1

    @pytest.mark.asyncio
    async def test_enrich_hash_sha256(self):
        """Test enriching a SHA-256 hash."""
        from OTXv2 import IndicatorTypes

        client = self._make_client()

        mock_result = {
            "general": {},
            "pulse_info": {"pulses": []},
            "malware": {"data": []},
        }

        with patch("asyncio.get_event_loop") as mock_loop_fn:
            mock_loop = MagicMock()
            mock_loop_fn.return_value = mock_loop
            mock_loop.run_in_executor = AsyncMock(return_value=mock_result)

            hash_val = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ioc = IOC(IOCType.HASH_SHA256, hash_val, "...", 1)
            await client.enrich(ioc)

            call_args = mock_loop.run_in_executor.call_args
            assert call_args[0][2] == IndicatorTypes.FILE_HASH_SHA256

    @pytest.mark.asyncio
    async def test_enrich_many_pulses_caps_at_100(self):
        """Test that score is capped at 100 even with many pulses."""
        client = self._make_client()

        # Create 1000 pulses
        mock_result = {
            "general": {},
            "pulse_info": {"pulses": [{"name": f"pulse-{i}"} for i in range(1000)]},
            "malware": {"data": [{"hash": "abc"}]},
        }

        with patch("asyncio.get_event_loop") as mock_loop_fn:
            mock_loop = MagicMock()
            mock_loop_fn.return_value = mock_loop
            mock_loop.run_in_executor = AsyncMock(return_value=mock_result)

            ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
            score = await client.enrich(ioc)

        assert score.raw_score == 100.0

    @pytest.mark.asyncio
    async def test_enrich_error_returns_unavailable(self):
        """Test that exceptions result in unavailable score."""
        client = self._make_client()

        with patch("asyncio.get_event_loop") as mock_loop_fn:
            mock_loop = MagicMock()
            mock_loop_fn.return_value = mock_loop
            mock_loop.run_in_executor = AsyncMock(side_effect=Exception("Network error"))

            ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
            score = await client.enrich(ioc)

        assert score.available is False
        assert "Error" in score.error

    @pytest.mark.asyncio
    async def test_enrich_includes_reputation(self):
        """Test that reputation is included in details when available."""
        client = self._make_client()

        mock_result = {
            "general": {"reputation": -10},
            "pulse_info": {"pulses": [{"name": "test"}]},
            "malware": {"data": []},
        }

        with patch("asyncio.get_event_loop") as mock_loop_fn:
            mock_loop = MagicMock()
            mock_loop_fn.return_value = mock_loop
            mock_loop.run_in_executor = AsyncMock(return_value=mock_result)

            ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
            score = await client.enrich(ioc)

        assert score.details["reputation"] == -10
