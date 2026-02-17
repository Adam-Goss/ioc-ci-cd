"""VirusTotal enrichment client."""

import base64
import logging
from typing import Any

import vt

from src.enrichment.base import TIEnrichmentClient
from src.models import IOC, IOCType, SourceScore
from src.rate_limiter import TokenBucketRateLimiter

logger = logging.getLogger("ioc_pipeline.virustotal")


class VirusTotalClient(TIEnrichmentClient):
    """VirusTotal API v3 enrichment client."""

    def __init__(self, api_key: str, rate_limiter: TokenBucketRateLimiter):
        """Initialize the VirusTotal client."""
        self.api_key = api_key
        self.rate_limiter = rate_limiter
        self.client = vt.Client(api_key)

    async def enrich(self, ioc: IOC) -> SourceScore:
        """Enrich IOC against VirusTotal."""
        if not self.supports(ioc):
            return SourceScore(
                source_name="virustotal",
                raw_score=0.0,
                available=False,
                error="IOC type not supported",
            )

        try:
            await self.rate_limiter.acquire()

            if ioc.ioc_type == IOCType.IP:
                obj = await self.client.get_object_async(f"/ip_addresses/{ioc.value}")
            elif ioc.ioc_type == IOCType.DOMAIN:
                obj = await self.client.get_object_async(f"/domains/{ioc.value}")
            elif ioc.ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256):
                obj = await self.client.get_object_async(f"/files/{ioc.value}")
            elif ioc.ioc_type == IOCType.URL:
                # URLs need to be base64url-encoded without padding
                url_id = base64.urlsafe_b64encode(ioc.value.encode()).decode().rstrip("=")
                obj = await self.client.get_object_async(f"/urls/{url_id}")
            else:
                return SourceScore(
                    source_name="virustotal",
                    raw_score=0.0,
                    available=False,
                    error="Unknown IOC type",
                )

            # Extract last_analysis_stats
            stats = obj.last_analysis_stats
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())

            if total == 0:
                score = 0.0
            else:
                score = ((malicious * 1.0 + suspicious * 0.5) / total) * 100

            # Extract metadata
            details: dict[str, Any] = {
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "total_engines": total,
                "reputation": getattr(obj, "reputation", 0),
            }

            # Add tags if available
            tags = getattr(obj, "tags", [])
            if tags:
                details["tags"] = tags[:5]  # Top 5 tags

            logger.debug(
                f"VirusTotal: {ioc.value} scored {score:.2f} "
                f"({malicious}/{total} malicious)"
            )

            return SourceScore(
                source_name="virustotal", raw_score=round(score, 2), details=details
            )

        except vt.APIError as e:
            logger.warning(f"VirusTotal API error for {ioc.value}: {e}")
            return SourceScore(
                source_name="virustotal",
                raw_score=0.0,
                available=False,
                error=f"API error: {str(e)}",
            )
        except Exception as e:
            logger.error(f"VirusTotal unexpected error for {ioc.value}: {e}")
            return SourceScore(
                source_name="virustotal",
                raw_score=0.0,
                available=False,
                error=f"Unexpected error: {str(e)}",
            )

    def supports(self, ioc: IOC) -> bool:
        """Check if VirusTotal supports this IOC type."""
        return ioc.ioc_type in (
            IOCType.IP,
            IOCType.DOMAIN,
            IOCType.HASH_MD5,
            IOCType.HASH_SHA1,
            IOCType.HASH_SHA256,
            IOCType.URL,
        )

    async def close(self) -> None:
        """Close the VT client."""
        await self.client.close_async()
