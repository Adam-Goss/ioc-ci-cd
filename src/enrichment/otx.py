"""OTX AlienVault enrichment client."""

import asyncio
import logging
import math
from typing import Any

from OTXv2 import OTXv2, IndicatorTypes

from src.enrichment.base import TIEnrichmentClient
from src.models import IOC, IOCType, SourceScore
from src.rate_limiter import TokenBucketRateLimiter

logger = logging.getLogger("ioc_pipeline.otx")


class OTXClient(TIEnrichmentClient):
    """OTX AlienVault enrichment client."""

    def __init__(self, api_key: str, rate_limiter: TokenBucketRateLimiter):
        """Initialize the OTX client."""
        self.api_key = api_key
        self.rate_limiter = rate_limiter
        self.client = OTXv2(api_key)

    async def enrich(self, ioc: IOC) -> SourceScore:
        """Enrich IOC against OTX."""
        if not self.supports(ioc):
            return SourceScore(
                source_name="otx",
                raw_score=0.0,
                available=False,
                error="IOC type not supported",
            )

        try:
            await self.rate_limiter.acquire()

            # Determine indicator type
            if ioc.ioc_type == IOCType.IP:
                indicator_type = IndicatorTypes.IPv4
            elif ioc.ioc_type == IOCType.DOMAIN:
                indicator_type = IndicatorTypes.DOMAIN
            elif ioc.ioc_type == IOCType.HASH_MD5:
                indicator_type = IndicatorTypes.FILE_HASH_MD5
            elif ioc.ioc_type == IOCType.HASH_SHA1:
                indicator_type = IndicatorTypes.FILE_HASH_SHA1
            elif ioc.ioc_type == IOCType.HASH_SHA256:
                indicator_type = IndicatorTypes.FILE_HASH_SHA256
            elif ioc.ioc_type == IOCType.URL:
                indicator_type = IndicatorTypes.URL
            else:
                return SourceScore(
                    source_name="otx",
                    raw_score=0.0,
                    available=False,
                    error="Unknown IOC type",
                )

            # OTX SDK is synchronous, run in executor
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, self.client.get_indicator_details_full, indicator_type, ioc.value
            )

            # Calculate score based on pulse count and malware data
            pulse_info = result.get("pulse_info", {})
            pulses = pulse_info.get("pulses", [])
            pulse_count = len(pulses)

            malware_data = result.get("malware", {}).get("data", [])
            has_malware = len(malware_data) > 0

            # Logarithmic scoring for pulses to avoid over-weighting prolific indicators
            pulse_score = min(100, math.log2(pulse_count + 1) * 15) if pulse_count > 0 else 0
            malware_bonus = 20 if has_malware else 0
            score = min(100, pulse_score + malware_bonus)

            # Extract metadata
            details: dict[str, Any] = {
                "pulse_count": pulse_count,
                "pulse_names": [p.get("name") for p in pulses[:5]],  # Top 5
                "malware_samples": len(malware_data),
            }

            # Add reputation if available
            general = result.get("general", {})
            if "reputation" in general:
                details["reputation"] = general["reputation"]

            logger.debug(
                f"OTX: {ioc.value} scored {score:.2f} ({pulse_count} pulses, "
                f"malware={has_malware})"
            )

            return SourceScore(source_name="otx", raw_score=round(score, 2), details=details)

        except Exception as e:
            logger.error(f"OTX error for {ioc.value}: {e}")
            return SourceScore(
                source_name="otx",
                raw_score=0.0,
                available=False,
                error=f"Error: {str(e)}",
            )

    def supports(self, ioc: IOC) -> bool:
        """Check if OTX supports this IOC type."""
        return ioc.ioc_type in (
            IOCType.IP,
            IOCType.DOMAIN,
            IOCType.HASH_MD5,
            IOCType.HASH_SHA1,
            IOCType.HASH_SHA256,
            IOCType.URL,
        )
