"""AbuseIPDB enrichment client."""

import logging
from typing import Any

import aiohttp

from src.enrichment.base import TIEnrichmentClient
from src.models import IOC, IOCType, SourceScore
from src.rate_limiter import TokenBucketRateLimiter

logger = logging.getLogger("ioc_pipeline.abuseipdb")


class AbuseIPDBClient(TIEnrichmentClient):
    """AbuseIPDB API v2 enrichment client."""

    API_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str, rate_limiter: TokenBucketRateLimiter):
        """Initialize the AbuseIPDB client."""
        self.api_key = api_key
        self.rate_limiter = rate_limiter
        self.session: aiohttp.ClientSession | None = None

    async def _ensure_session(self) -> aiohttp.ClientSession:
        """Ensure aiohttp session exists."""
        if self.session is None:
            self.session = aiohttp.ClientSession()
        return self.session

    async def enrich(self, ioc: IOC) -> SourceScore:
        """Enrich IOC against AbuseIPDB."""
        if not self.supports(ioc):
            return SourceScore(
                source_name="abuseipdb",
                raw_score=0.0,
                available=False,
                error="Only IP addresses supported",
            )

        try:
            await self.rate_limiter.acquire()
            session = await self._ensure_session()

            headers = {"Key": self.api_key, "Accept": "application/json"}
            params = {"ipAddress": ioc.value, "maxAgeInDays": "90"}

            async with session.get(
                self.API_ENDPOINT, headers=headers, params=params
            ) as response:
                if response.status == 429:
                    logger.warning(f"AbuseIPDB rate limit hit for {ioc.value}")
                    return SourceScore(
                        source_name="abuseipdb",
                        raw_score=0.0,
                        available=False,
                        error="Rate limit exceeded",
                    )

                response.raise_for_status()
                data = await response.json()

            result = data.get("data", {})
            score = result.get("abuseConfidenceScore", 0)

            # Extract metadata
            details: dict[str, Any] = {
                "abuse_confidence_score": score,
                "total_reports": result.get("totalReports", 0),
                "distinct_reporters": result.get("numDistinctUsers", 0),
                "country_code": result.get("countryCode"),
                "isp": result.get("isp"),
                "usage_type": result.get("usageType"),
                "is_tor": result.get("isTor", False),
                "is_whitelisted": result.get("isWhitelisted", False),
            }

            logger.debug(f"AbuseIPDB: {ioc.value} scored {score}")

            return SourceScore(source_name="abuseipdb", raw_score=float(score), details=details)

        except aiohttp.ClientError as e:
            logger.warning(f"AbuseIPDB HTTP error for {ioc.value}: {e}")
            return SourceScore(
                source_name="abuseipdb",
                raw_score=0.0,
                available=False,
                error=f"HTTP error: {str(e)}",
            )
        except Exception as e:
            logger.error(f"AbuseIPDB unexpected error for {ioc.value}: {e}")
            return SourceScore(
                source_name="abuseipdb",
                raw_score=0.0,
                available=False,
                error=f"Unexpected error: {str(e)}",
            )

    def supports(self, ioc: IOC) -> bool:
        """Check if AbuseIPDB supports this IOC type."""
        return ioc.ioc_type == IOCType.IP

    async def close(self) -> None:
        """Close the aiohttp session."""
        if self.session:
            await self.session.close()
