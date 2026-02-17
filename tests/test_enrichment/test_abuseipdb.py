"""Tests for AbuseIPDB enrichment client."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.models import IOC, IOCType
from src.rate_limiter import RateLimiterConfig, TokenBucketRateLimiter


class TestAbuseIPDBClient:
    """Tests for AbuseIPDBClient."""

    def _make_limiter(self):
        config = RateLimiterConfig(requests_per_minute=100, name="abuseipdb-test")
        return TokenBucketRateLimiter(config)

    def _make_client(self, limiter=None):
        from src.enrichment.abuseipdb import AbuseIPDBClient

        limiter = limiter or self._make_limiter()
        return AbuseIPDBClient("fake-api-key", limiter)

    def test_supports_only_ip(self):
        """Test that AbuseIPDB only supports IP addresses."""
        client = self._make_client()

        assert client.supports(IOC(IOCType.IP, "1.2.3.4", "1.2.3.4", 1)) is True
        assert client.supports(IOC(IOCType.DOMAIN, "evil.com", "evil.com", 1)) is False
        assert client.supports(IOC(IOCType.URL, "http://evil.com", "http://evil.com", 1)) is False
        assert client.supports(IOC(IOCType.HASH_MD5, "abc" * 10 + "de", "...", 1)) is False

    @pytest.mark.asyncio
    async def test_enrich_unsupported_type(self):
        """Test enriching a non-IP IOC returns unavailable."""
        client = self._make_client()

        ioc = IOC(IOCType.DOMAIN, "evil.com", "evil.com", 1)
        score = await client.enrich(ioc)

        assert score.source_name == "abuseipdb"
        assert score.available is False
        assert "Only IP addresses supported" in score.error

    @pytest.mark.asyncio
    async def test_enrich_ip_success(self):
        """Test successful IP enrichment."""
        client = self._make_client()

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json = AsyncMock(return_value={
            "data": {
                "ipAddress": "192.168.1.1",
                "abuseConfidenceScore": 87,
                "totalReports": 1432,
                "numDistinctUsers": 89,
                "countryCode": "CN",
                "isp": "China Telecom",
                "usageType": "Data Center/Web Hosting/Transit",
                "isTor": False,
                "isWhitelisted": False,
            }
        })

        mock_session = MagicMock()
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_response)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_session.get.return_value = mock_ctx
        client.session = mock_session

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        score = await client.enrich(ioc)

        assert score.source_name == "abuseipdb"
        assert score.available is True
        assert score.raw_score == 87.0
        assert score.details["abuse_confidence_score"] == 87
        assert score.details["total_reports"] == 1432
        assert score.details["country_code"] == "CN"
        assert score.details["is_tor"] is False

    @pytest.mark.asyncio
    async def test_enrich_rate_limit_429(self):
        """Test handling 429 rate limit response."""
        client = self._make_client()

        mock_response = AsyncMock()
        mock_response.status = 429

        mock_session = MagicMock()
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_response)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_session.get.return_value = mock_ctx
        client.session = mock_session

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        score = await client.enrich(ioc)

        assert score.available is False
        assert "Rate limit exceeded" in score.error

    @pytest.mark.asyncio
    async def test_enrich_http_error(self):
        """Test handling HTTP client errors."""
        import aiohttp

        client = self._make_client()

        mock_session = MagicMock()
        mock_session.get.side_effect = aiohttp.ClientError("Connection refused")
        client.session = mock_session

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        score = await client.enrich(ioc)

        assert score.available is False
        assert "HTTP error" in score.error

    @pytest.mark.asyncio
    async def test_enrich_unexpected_error(self):
        """Test handling unexpected exceptions."""
        client = self._make_client()

        mock_session = MagicMock()
        mock_session.get.side_effect = RuntimeError("Something weird")
        client.session = mock_session

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        score = await client.enrich(ioc)

        assert score.available is False
        assert "Unexpected error" in score.error

    @pytest.mark.asyncio
    async def test_ensure_session_creates_session(self):
        """Test that _ensure_session creates a new session if none exists."""
        client = self._make_client()
        assert client.session is None

        with patch("src.enrichment.abuseipdb.aiohttp.ClientSession") as mock_session_class:
            mock_session_class.return_value = MagicMock()
            session = await client._ensure_session()
            assert session is not None
            assert client.session is not None

    @pytest.mark.asyncio
    async def test_ensure_session_reuses_existing(self):
        """Test that _ensure_session reuses existing session."""
        client = self._make_client()
        existing_session = MagicMock()
        client.session = existing_session

        session = await client._ensure_session()
        assert session is existing_session

    @pytest.mark.asyncio
    async def test_close_closes_session(self):
        """Test closing the aiohttp session."""
        client = self._make_client()
        mock_session = AsyncMock()
        client.session = mock_session

        await client.close()
        mock_session.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_no_session(self):
        """Test closing when no session exists."""
        client = self._make_client()
        assert client.session is None

        # Should not raise
        await client.close()
