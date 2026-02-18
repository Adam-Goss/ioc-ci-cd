"""Confidence score aggregation from multiple TI sources."""

import asyncio
import logging
from collections import Counter

from src.config import PipelineConfig
from src.enrichment.abuseipdb import AbuseIPDBClient
from src.enrichment.base import TIEnrichmentClient
from src.enrichment.otx import OTXClient
from src.enrichment.virustotal import VirusTotalClient
from src.models import EnrichmentResult, IOC, SourceScore
from src.rate_limiter import RATE_LIMITS, RateLimiterConfig, TokenBucketRateLimiter

logger = logging.getLogger("ioc_pipeline.aggregator")

# Registry of available enrichment clients
ENRICHMENT_REGISTRY: dict[str, type[TIEnrichmentClient]] = {
    "virustotal": VirusTotalClient,
    "abuseipdb": AbuseIPDBClient,
    "otx": OTXClient,
}


def compute_confidence(scores: list[SourceScore], config: PipelineConfig) -> float:
    """
    Compute weighted confidence score from available sources.

    Args:
        scores: List of source scores
        config: Pipeline configuration with weights

    Returns:
        Weighted confidence score (0-100)
    """
    available = [s for s in scores if s.available]
    if not available:
        return 0.0

    # Source weights from config
    weights = {
        "virustotal": config.weight_vt,
        "abuseipdb": config.weight_abuseipdb,
        "otx": config.weight_otx,
    }

    # Calculate total weight of available sources
    total_weight = sum(weights.get(s.source_name, 0) for s in available)
    if total_weight == 0:
        return 0.0

    # Weighted average, renormalizing for available sources
    weighted_sum = sum(
        s.raw_score * (weights.get(s.source_name, 0) / total_weight) for s in available
    )

    return round(weighted_sum, 2)


def extract_tags(scores: list[SourceScore]) -> list[str]:
    """
    Extract and aggregate tags from source details.

    Tags appearing in 2+ sources are promoted to primary tags.

    Args:
        scores: List of source scores

    Returns:
        Sorted list of unique tags
    """
    all_tags: list[str] = []

    for score in scores:
        if not score.available:
            continue

        # Extract tags from details
        tags = score.details.get("tags", [])
        if isinstance(tags, list):
            all_tags.extend(str(t).lower() for t in tags)

    # Count occurrences
    tag_counts = Counter(all_tags)

    # Promote tags that appear in multiple sources
    primary_tags = [tag for tag, count in tag_counts.items() if count >= 2]

    # If no common tags, take top 5 most frequent
    if not primary_tags:
        primary_tags = [tag for tag, _ in tag_counts.most_common(5)]

    return sorted(set(primary_tags))


def _make_limiter(source: str, config: PipelineConfig) -> TokenBucketRateLimiter:
    """Build a rate limiter for the given source, using config overrides if set."""
    base = RATE_LIMITS[source]
    rate_override = getattr(config, f"{source}_rate_limit", None)
    if rate_override is not None:
        cfg = RateLimiterConfig(
            requests_per_minute=rate_override,
            daily_budget=base.daily_budget,
            name=source,
        )
    else:
        cfg = base
    return TokenBucketRateLimiter(cfg)


def _get_api_key(source: str, config: PipelineConfig) -> str:
    """Retrieve the API key for the given source from config."""
    key_field = {"virustotal": "vt_api_key", "abuseipdb": "abuseipdb_api_key", "otx": "otx_api_key"}
    return getattr(config, key_field[source], "") or ""


async def enrich_ioc(
    ioc: IOC,
    config: PipelineConfig,
    enabled_sources: list[str] | None = None,
) -> EnrichmentResult:
    """
    Enrich a single IOC against the enabled TI sources.

    Args:
        ioc: The IOC to enrich
        config: Pipeline configuration
        enabled_sources: Which sources to use (None = use config.enrichment_sources)

    Returns:
        Aggregated enrichment result
    """
    sources = enabled_sources if enabled_sources is not None else config.enrichment_sources

    # Build clients for enabled sources only
    clients: list[TIEnrichmentClient] = []
    for source in sources:
        client_class = ENRICHMENT_REGISTRY.get(source)
        if client_class is None:
            logger.warning(f"Unknown enrichment source: {source!r}, skipping")
            continue
        limiter = _make_limiter(source, config)
        api_key = _get_api_key(source, config)
        clients.append(client_class(api_key, limiter))

    try:
        # Enrich concurrently across all enabled sources
        scores = await asyncio.gather(*[c.enrich(ioc) for c in clients])

        # Compute aggregated confidence
        confidence = compute_confidence(list(scores), config)

        # Extract tags
        tags = extract_tags(list(scores))

        result = EnrichmentResult(
            ioc=ioc, scores=list(scores), confidence=confidence, tags=tags
        )

        logger.info(
            f"Enriched {ioc.ioc_type.value} {ioc.value}: confidence={confidence:.2f}"
        )

        return result

    finally:
        # Clean up clients that have a close method
        for client in clients:
            if hasattr(client, "close"):
                await client.close()


async def enrich_all(
    iocs: list[IOC],
    config: PipelineConfig,
    enabled_sources: list[str] | None = None,
) -> list[EnrichmentResult]:
    """
    Enrich all IOCs concurrently.

    Args:
        iocs: List of IOCs to enrich
        config: Pipeline configuration
        enabled_sources: Which sources to use (None = use config.enrichment_sources)

    Returns:
        List of enrichment results
    """
    logger.info(f"Enriching {len(iocs)} IOCs...")

    results = await asyncio.gather(
        *[enrich_ioc(ioc, config, enabled_sources) for ioc in iocs]
    )

    logger.info(f"Enrichment complete. {len(results)} results.")

    return list(results)
