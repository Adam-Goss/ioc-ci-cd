"""MISP publisher implementation."""

import asyncio
import logging
import os
from datetime import datetime
from typing import Any

from pymisp import MISPAttribute, MISPEvent, PyMISP

from src.config import PipelineConfig
from src.models import EnrichmentResult, IOCType
from src.publishers.base import Publisher

logger = logging.getLogger("ioc_pipeline.misp")

# IOC type mapping to MISP attribute types
MISP_TYPE_MAP = {
    IOCType.IP: "ip-dst",
    IOCType.DOMAIN: "domain",
    IOCType.HASH_MD5: "md5",
    IOCType.HASH_SHA1: "sha1",
    IOCType.HASH_SHA256: "sha256",
    IOCType.URL: "url",
}


class MISPPublisher(Publisher):
    """Publisher for MISP threat intelligence platform."""

    def __init__(self, config: PipelineConfig):
        """Initialize the MISP publisher."""
        self.config = config
        if not config.misp_url or not config.misp_api_key:
            raise ValueError("MISP_URL and MISP_API_KEY must be set for MISP publishing")

        self.misp = PyMISP(
            url=config.misp_url, key=config.misp_api_key, ssl=config.misp_verify_ssl
        )

    async def publish(self, results: list[EnrichmentResult]) -> None:
        """
        Publish enrichment results to MISP.

        Creates one MISP event per pipeline run with all IOCs as attributes.

        Args:
            results: List of enrichment results to publish

        Raises:
            Exception: If MISP connection or event creation fails
        """
        if not results:
            logger.info("No results to publish to MISP")
            return

        # Get commit SHA from environment (GitHub Actions sets this)
        commit_sha = os.environ.get("GITHUB_SHA", "unknown")[:8]
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")

        # Run in executor since PyMISP is synchronous
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._publish_sync, results, commit_sha, timestamp)

    def _publish_sync(
        self, results: list[EnrichmentResult], commit_sha: str, timestamp: str
    ) -> None:
        """Synchronous publishing logic (run in executor)."""
        # Create MISP event
        event = MISPEvent()
        event.info = f"IOC Pipeline Import - {timestamp} - {commit_sha}"
        event.distribution = self.config.misp_distribution
        event.threat_level_id = self.config.misp_threat_level
        event.analysis = 2  # Completed

        # Add TLP tag
        event.add_tag("tlp:amber")

        logger.info(f"Creating MISP event: {event.info}")

        # Add each IOC as an attribute
        for result in results:
            ioc = result.ioc
            misp_type = MISP_TYPE_MAP.get(ioc.ioc_type)

            if not misp_type:
                logger.warning(f"Unknown IOC type for MISP: {ioc.ioc_type}, skipping")
                continue

            # Create enrichment summary for comment
            available_scores = [s for s in result.scores if s.available]
            score_summary = ", ".join(
                f"{s.source_name}={s.raw_score:.1f}" for s in available_scores
            )
            comment = f"Confidence: {result.confidence:.1f} ({score_summary})"

            # Add attribute to event
            attr = event.add_attribute(
                type=misp_type, value=ioc.value, to_ids=True, comment=comment
            )

            # Add confidence tag
            confidence_tag = f"confidence:{int(result.confidence)}"
            attr.add_tag(confidence_tag)

            # Add other tags from enrichment
            for tag in result.tags[:5]:  # Limit to top 5 tags
                attr.add_tag(tag)

            logger.debug(f"Added MISP attribute: {misp_type}={ioc.value}")

        # Retry logic for adding event
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                response = self.misp.add_event(event, pythonify=True)

                if isinstance(response, dict) and "errors" in response:
                    raise Exception(f"MISP API error: {response['errors']}")

                event_id = response.id if hasattr(response, "id") else "unknown"
                logger.info(f"MISP event created successfully: ID={event_id}")

                # Optionally publish the event
                if self.config.misp_auto_publish:
                    self.misp.publish(response)
                    logger.info(f"MISP event {event_id} published")

                break  # Success

            except Exception as e:
                if attempt < max_attempts:
                    wait_time = 2**attempt  # Exponential backoff: 2s, 4s, 8s
                    logger.warning(
                        f"MISP event creation failed (attempt {attempt}/{max_attempts}): {e}. "
                        f"Retrying in {wait_time}s..."
                    )
                    import time

                    time.sleep(wait_time)
                else:
                    logger.error(f"MISP event creation failed after {max_attempts} attempts: {e}")
                    raise
