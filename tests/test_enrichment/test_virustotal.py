"""Tests for VirusTotal enrichment client."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.models import IOC, IOCType
from src.rate_limiter import RateLimiterConfig, TokenBucketRateLimiter


class TestVirusTotalClient:
    """Tests for VirusTotalClient."""

    def _make_limiter(self):
        config = RateLimiterConfig(requests_per_minute=100, name="vt-test")
        return TokenBucketRateLimiter(config)

    def _make_client(self, limiter=None):
        from src.enrichment.virustotal import VirusTotalClient

        limiter = limiter or self._make_limiter()
        with patch("src.enrichment.virustotal.vt.Client"):
            client = VirusTotalClient("fake-api-key", limiter)
        return client

    def test_supports_all_ioc_types(self):
        """Test that VT supports all IOC types."""
        client = self._make_client()
        for ioc_type in IOCType:
            ioc = IOC(ioc_type, "test", "test", 1)
            assert client.supports(ioc) is True

    @pytest.mark.asyncio
    async def test_enrich_ip_success(self):
        """Test enriching an IP address successfully."""
        client = self._make_client()

        mock_obj = MagicMock()
        mock_obj.last_analysis_stats = {
            "malicious": 10,
            "suspicious": 2,
            "undetected": 50,
            "harmless": 8,
        }
        mock_obj.reputation = -50
        mock_obj.tags = ["malware", "c2"]

        client.client.get_object_async = AsyncMock(return_value=mock_obj)

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        score = await client.enrich(ioc)

        assert score.source_name == "virustotal"
        assert score.available is True
        # (10 * 1.0 + 2 * 0.5) / 70 * 100 = 15.71
        assert score.raw_score == pytest.approx(15.71, abs=0.1)
        assert score.details["malicious_count"] == 10
        assert score.details["tags"] == ["malware", "c2"]

        client.client.get_object_async.assert_called_once_with("/ip_addresses/192.168.1.1")

    @pytest.mark.asyncio
    async def test_enrich_domain_success(self):
        """Test enriching a domain."""
        client = self._make_client()

        mock_obj = MagicMock()
        mock_obj.last_analysis_stats = {
            "malicious": 45,
            "suspicious": 3,
            "undetected": 20,
            "harmless": 2,
        }
        mock_obj.reputation = -75
        mock_obj.tags = ["phishing"]

        client.client.get_object_async = AsyncMock(return_value=mock_obj)

        ioc = IOC(IOCType.DOMAIN, "evil.com", "evil.com", 1)
        score = await client.enrich(ioc)

        assert score.available is True
        assert score.raw_score > 0

        client.client.get_object_async.assert_called_once_with("/domains/evil.com")

    @pytest.mark.asyncio
    async def test_enrich_hash_success(self):
        """Test enriching a file hash."""
        client = self._make_client()

        mock_obj = MagicMock()
        mock_obj.last_analysis_stats = {"malicious": 30, "suspicious": 0, "undetected": 30, "harmless": 0}
        mock_obj.reputation = 0
        mock_obj.tags = []

        client.client.get_object_async = AsyncMock(return_value=mock_obj)

        ioc = IOC(IOCType.HASH_MD5, "d41d8cd98f00b204e9800998ecf8427e", "...", 1)
        score = await client.enrich(ioc)

        assert score.available is True
        # 30/60 * 100 = 50
        assert score.raw_score == 50.0

        client.client.get_object_async.assert_called_once_with(
            "/files/d41d8cd98f00b204e9800998ecf8427e"
        )

    @pytest.mark.asyncio
    async def test_enrich_sha1_hash(self):
        """Test enriching a SHA1 hash."""
        client = self._make_client()

        mock_obj = MagicMock()
        mock_obj.last_analysis_stats = {"malicious": 5, "suspicious": 0, "undetected": 45, "harmless": 0}
        mock_obj.reputation = 0
        mock_obj.tags = []

        client.client.get_object_async = AsyncMock(return_value=mock_obj)

        ioc = IOC(IOCType.HASH_SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709", "...", 1)
        await client.enrich(ioc)

        client.client.get_object_async.assert_called_once_with(
            "/files/da39a3ee5e6b4b0d3255bfef95601890afd80709"
        )

    @pytest.mark.asyncio
    async def test_enrich_sha256_hash(self):
        """Test enriching a SHA256 hash."""
        client = self._make_client()

        mock_obj = MagicMock()
        mock_obj.last_analysis_stats = {"malicious": 5, "suspicious": 0, "undetected": 45, "harmless": 0}
        mock_obj.reputation = 0
        mock_obj.tags = []

        client.client.get_object_async = AsyncMock(return_value=mock_obj)

        hash_val = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ioc = IOC(IOCType.HASH_SHA256, hash_val, "...", 1)
        await client.enrich(ioc)

        client.client.get_object_async.assert_called_once_with(f"/files/{hash_val}")

    @pytest.mark.asyncio
    async def test_enrich_url_encodes_base64(self):
        """Test that URL IOCs are base64url-encoded."""
        client = self._make_client()

        mock_obj = MagicMock()
        mock_obj.last_analysis_stats = {"malicious": 5, "suspicious": 0, "undetected": 55, "harmless": 0}
        mock_obj.reputation = 0
        mock_obj.tags = []

        client.client.get_object_async = AsyncMock(return_value=mock_obj)

        ioc = IOC(IOCType.URL, "http://evil.com/bad", "http://evil.com/bad", 1)
        score = await client.enrich(ioc)

        assert score.available is True
        # Should have called with /urls/<base64url>
        call_path = client.client.get_object_async.call_args[0][0]
        assert call_path.startswith("/urls/")

    @pytest.mark.asyncio
    async def test_enrich_zero_total_engines(self):
        """Test handling when total engines is zero."""
        client = self._make_client()

        mock_obj = MagicMock()
        mock_obj.last_analysis_stats = {}
        mock_obj.reputation = 0
        mock_obj.tags = []

        client.client.get_object_async = AsyncMock(return_value=mock_obj)

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        score = await client.enrich(ioc)

        assert score.available is True
        assert score.raw_score == 0.0

    @pytest.mark.asyncio
    async def test_enrich_api_error(self):
        """Test handling VirusTotal API error."""
        import vt

        client = self._make_client()
        client.client.get_object_async = AsyncMock(
            side_effect=vt.APIError("NotFoundError", "Resource not found")
        )

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        score = await client.enrich(ioc)

        assert score.available is False
        assert "API error" in score.error

    @pytest.mark.asyncio
    async def test_enrich_unexpected_error(self):
        """Test handling unexpected exceptions."""
        client = self._make_client()
        client.client.get_object_async = AsyncMock(side_effect=RuntimeError("Timeout"))

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        score = await client.enrich(ioc)

        assert score.available is False
        assert "Unexpected error" in score.error

    @pytest.mark.asyncio
    async def test_enrich_no_tags_attribute(self):
        """Test handling when object has no tags."""
        client = self._make_client()

        mock_obj = MagicMock(spec=[])  # Empty spec = no attributes
        mock_obj.last_analysis_stats = {"malicious": 5, "suspicious": 0, "undetected": 45, "harmless": 0}
        # Simulate getattr returning default for missing attributes
        type(mock_obj).reputation = property(lambda self: 0)
        delattr(type(mock_obj), "reputation")

        client.client.get_object_async = AsyncMock(return_value=mock_obj)

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        score = await client.enrich(ioc)

        assert score.available is True

    @pytest.mark.asyncio
    async def test_close_calls_client_close(self):
        """Test that close properly closes the VT client."""
        client = self._make_client()
        client.client.close_async = AsyncMock()

        await client.close()

        client.client.close_async.assert_called_once()
