"""Confidence score aggregation from multiple TI sources."""

import asyncio
import logging
from collections import Counter

from src.config import PipelineConfig
from src.enrichment.abuseipdb import AbuseIPDBClient
from src.enrichment.otx import OTXClient
from src.enrichment.virustotal import VirusTotalClient
from src.models import EnrichmentResult, IOC, SourceScore
from src.rate_limiter import RATE_LIMITS, TokenBucketRateLimiter

logger = logging.getLogger("ioc_pipeline.aggregator")


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


async def enrich_ioc(ioc: IOC, config: PipelineConfig) -> EnrichmentResult:
    """
    Enrich a single IOC against all TI sources.

    Args:
        ioc: The IOC to enrich
        config: Pipeline configuration

    Returns:
        Aggregated enrichment result
    """
    # Create rate limiters
    vt_limiter = TokenBucketRateLimiter(
        RATE_LIMITS["virustotal"]
        if config.vt_rate_limit is None
        else RATE_LIMITS["virustotal"].__class__(
            requests_per_minute=config.vt_rate_limit,
            daily_budget=RATE_LIMITS["virustotal"].daily_budget,
            name="virustotal",
        )
    )

    abuseipdb_limiter = TokenBucketRateLimiter(
        RATE_LIMITS["abuseipdb"]
        if config.abuseipdb_rate_limit is None
        else RATE_LIMITS["abuseipdb"].__class__(
            requests_per_minute=config.abuseipdb_rate_limit,
            daily_budget=RATE_LIMITS["abuseipdb"].daily_budget,
            name="abuseipdb",
        )
    )

    otx_limiter = TokenBucketRateLimiter(
        RATE_LIMITS["otx"]
        if config.otx_rate_limit is None
        else RATE_LIMITS["otx"].__class__(
            requests_per_minute=config.otx_rate_limit,
            daily_budget=RATE_LIMITS["otx"].daily_budget,
            name="otx",
        )
    )

    # Create clients
    vt_client = VirusTotalClient(config.vt_api_key, vt_limiter)
    abuseipdb_client = AbuseIPDBClient(config.abuseipdb_api_key, abuseipdb_limiter)
    otx_client = OTXClient(config.otx_api_key, otx_limiter)

    try:
        # Enrich concurrently across all sources
        scores = await asyncio.gather(
            vt_client.enrich(ioc), abuseipdb_client.enrich(ioc), otx_client.enrich(ioc)
        )

        # Compute aggregated confidence
        confidence = compute_confidence(scores, config)

        # Extract tags
        tags = extract_tags(scores)

        result = EnrichmentResult(
            ioc=ioc, scores=list(scores), confidence=confidence, tags=tags
        )

        logger.info(
            f"Enriched {ioc.ioc_type.value} {ioc.value}: confidence={confidence:.2f}"
        )

        return result

    finally:
        # Clean up clients
        await vt_client.close()
        await abuseipdb_client.close()


async def enrich_all(iocs: list[IOC], config: PipelineConfig) -> list[EnrichmentResult]:
    """
    Enrich all IOCs concurrently.

    Args:
        iocs: List of IOCs to enrich
        config: Pipeline configuration

    Returns:
        List of enrichment results
    """
    logger.info(f"Enriching {len(iocs)} IOCs...")

    # Enrich all IOCs concurrently
    results = await asyncio.gather(*[enrich_ioc(ioc, config) for ioc in iocs])

    logger.info(f"Enrichment complete. {len(results)} results.")

    return list(results)
