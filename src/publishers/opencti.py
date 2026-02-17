"""OpenCTI publisher implementation."""

import asyncio
import logging
from typing import Any

from pycti import OpenCTIApiClient

from src.config import PipelineConfig
from src.models import EnrichmentResult, IOCType
from src.publishers.base import Publisher

logger = logging.getLogger("ioc_pipeline.opencti")

# IOC type mapping to OpenCTI STIX observable types
OPENCTI_OBSERVABLE_MAP = {
    IOCType.IP: {"type": "IPv4-Addr", "value_key": "value"},
    IOCType.DOMAIN: {"type": "Domain-Name", "value_key": "value"},
    IOCType.HASH_MD5: {"type": "StixFile", "hash_type": "MD5"},
    IOCType.HASH_SHA1: {"type": "StixFile", "hash_type": "SHA-1"},
    IOCType.HASH_SHA256: {"type": "StixFile", "hash_type": "SHA-256"},
    IOCType.URL: {"type": "Url", "value_key": "value"},
}


class OpenCTIPublisher(Publisher):
    """Publisher for OpenCTI threat intelligence platform."""

    def __init__(self, config: PipelineConfig):
        """Initialize the OpenCTI publisher."""
        self.config = config
        if not config.opencti_url or not config.opencti_token:
            raise ValueError(
                "OPENCTI_URL and OPENCTI_TOKEN must be set for OpenCTI publishing"
            )

        self.client = OpenCTIApiClient(url=config.opencti_url, token=config.opencti_token)

    async def publish(self, results: list[EnrichmentResult]) -> None:
        """
        Publish enrichment results to OpenCTI.

        Creates STIX Cyber Observables and promotes them to indicators.

        Args:
            results: List of enrichment results to publish
        """
        if not results:
            logger.info("No results to publish to OpenCTI")
            return

        # Run in executor since pycti is synchronous
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._publish_sync, results)

    def _publish_sync(self, results: list[EnrichmentResult]) -> None:
        """Synchronous publishing logic (run in executor)."""
        success_count = 0
        failure_count = 0
        failures: list[tuple[str, str]] = []

        for result in results:
            try:
                self._publish_single_ioc(result)
                success_count += 1
            except Exception as e:
                failure_count += 1
                failures.append((result.ioc.value, str(e)))
                logger.error(f"Failed to publish {result.ioc.value} to OpenCTI: {e}")

        logger.info(
            f"OpenCTI publishing complete: {success_count} succeeded, {failure_count} failed"
        )

        if failures:
            logger.warning("Failed IOCs:")
            for ioc_value, error in failures:
                logger.warning(f"  - {ioc_value}: {error}")

    def _publish_single_ioc(self, result: EnrichmentResult) -> None:
        """
        Publish a single IOC to OpenCTI.

        Args:
            result: Enrichment result for one IOC
        """
        ioc = result.ioc
        mapping = OPENCTI_OBSERVABLE_MAP.get(ioc.ioc_type)

        if not mapping:
            raise ValueError(f"Unknown IOC type for OpenCTI: {ioc.ioc_type}")

        # Build enrichment description
        available_scores = [s for s in result.scores if s.available]
        score_details = ", ".join(f"{s.source_name}={s.raw_score:.1f}" for s in available_scores)
        description = f"Confidence: {result.confidence:.1f} ({score_details})"

        # Prepare observable data based on type
        if ioc.ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256):
            # File hash observable
            observable_data = {
                "type": mapping["type"],
                "hashes": {mapping["hash_type"]: ioc.value},
            }
        else:
            # Simple value-based observable (IP, domain, URL)
            observable_data = {
                "type": mapping["type"],
                mapping["value_key"]: ioc.value,
            }

        # Create the observable
        logger.debug(f"Creating OpenCTI observable: {observable_data}")

        observable = self.client.stix_cyber_observable.create(
            observableData=observable_data,
            x_opencti_description=description,
            x_opencti_score=int(result.confidence),
        )

        observable_id = observable["id"]
        logger.info(f"Created OpenCTI observable: {ioc.value} (ID: {observable_id})")

        # Promote to indicator
        try:
            self.client.stix_cyber_observable.promote_to_indicator(id=observable_id)
            logger.debug(f"Promoted {ioc.value} to indicator")
        except Exception as e:
            logger.warning(f"Failed to promote {ioc.value} to indicator: {e}")
            # Non-fatal - observable still created

        # Add labels from enrichment tags
        for tag in result.tags[:5]:  # Limit to top 5 tags
            try:
                self.client.stix_cyber_observable.add_label(id=observable_id, label_name=tag)
                logger.debug(f"Added label '{tag}' to {ioc.value}")
            except Exception as e:
                logger.warning(f"Failed to add label '{tag}' to {ioc.value}: {e}")
                # Non-fatal
