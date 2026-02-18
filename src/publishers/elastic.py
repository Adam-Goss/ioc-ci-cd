"""Elastic hunting publisher — searches for IOCs in Elasticsearch log data."""

import asyncio
import logging
from typing import TYPE_CHECKING, Any

import aiohttp

from src.models import EnrichmentResult, HuntResult, IOCType
from src.publishers.base import HuntPublisher

if TYPE_CHECKING:
    from src.config import PipelineConfig

logger = logging.getLogger("ioc_pipeline.elastic")

# ECS field mappings per IOC type (list of fields to check with a should clause)
_ECS_FIELDS: dict[IOCType, list[str]] = {
    IOCType.IP: ["source.ip", "destination.ip", "client.ip", "server.ip", "host.ip"],
    IOCType.DOMAIN: [
        "dns.question.name",
        "url.domain",
        "destination.domain",
        "source.domain",
    ],
    IOCType.URL: ["url.full", "url.original"],
    IOCType.HASH_MD5: ["file.hash.md5", "process.hash.md5"],
    IOCType.HASH_SHA1: ["file.hash.sha1", "process.hash.sha1"],
    IOCType.HASH_SHA256: ["file.hash.sha256", "process.hash.sha256"],
}


def _build_query(
    ioc_type: IOCType, value: str, age_days: int
) -> dict[str, Any]:
    """Build an Elasticsearch bool query for the given IOC."""
    fields = _ECS_FIELDS[ioc_type]
    should_clauses = [{"term": {field: {"value": value}}} for field in fields]

    return {
        "query": {
            "bool": {
                "should": should_clauses,
                "minimum_should_match": 1,
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{age_days}d"}}}
                ],
            }
        },
        "size": 3,  # sample events
        "sort": [{"@timestamp": {"order": "desc"}}],
    }


class ElasticHunter(HuntPublisher):
    """Hunts for IOCs in Elasticsearch using the REST API."""

    def __init__(self, config: "PipelineConfig") -> None:
        if not config.elastic_url:
            raise ValueError("ELASTIC_URL is required for Elastic hunting")
        if not config.elastic_api_key:
            raise ValueError("ELASTIC_API_KEY is required for Elastic hunting")
        self._url = config.elastic_url.rstrip("/")
        self._api_key = config.elastic_api_key
        self._index = config.elastic_index
        self._age_days = config.max_ioc_age_days
        self._verify_ssl = config.elastic_verify_ssl
        self._session: aiohttp.ClientSession | None = None

    def name(self) -> str:
        return "elastic"

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                headers={
                    "Authorization": f"ApiKey {self._api_key}",
                    "Content-Type": "application/json",
                }
            )
        return self._session

    async def _run_search(
        self, ioc_type: IOCType, value: str
    ) -> tuple[int, str | None, str | None, list[dict]]:
        """Run an Elasticsearch search and return (count, earliest, latest, samples)."""
        session = await self._get_session()
        query = _build_query(ioc_type, value, self._age_days)
        search_url = f"{self._url}/{self._index}/_search"

        async with session.post(
            search_url, json=query, ssl=self._verify_ssl
        ) as resp:
            resp.raise_for_status()
            body = await resp.json()

        hits = body.get("hits", {})
        total = hits.get("total", {})
        count = total.get("value", 0) if isinstance(total, dict) else int(total)

        samples = [h.get("_source", {}) for h in hits.get("hits", [])]

        # Determine time range from sample events
        timestamps = [
            s.get("@timestamp") for s in samples if s.get("@timestamp")
        ]
        earliest = min(timestamps) if timestamps else None
        latest = max(timestamps) if timestamps else None

        return count, earliest, latest, samples

    async def _hunt_one(self, result: EnrichmentResult) -> HuntResult:
        """Hunt for a single IOC."""
        ioc = result.ioc
        query = _build_query(ioc.ioc_type, ioc.value, self._age_days)
        query_str = str(query)
        try:
            count, earliest, latest, samples = await self._run_search(
                ioc.ioc_type, ioc.value
            )
            return HuntResult(
                ioc=ioc,
                platform=self.name(),
                hits_found=count,
                earliest_hit=earliest,
                latest_hit=latest,
                sample_events=samples,
                query_used=query_str,
            )
        except Exception as e:
            logger.warning(f"Elastic hunt failed for {ioc.value}: {e}")
            return HuntResult(
                ioc=ioc,
                platform=self.name(),
                hits_found=0,
                query_used=query_str,
                error=str(e),
                success=False,
            )

    async def hunt(self, results: list[EnrichmentResult]) -> list[HuntResult]:
        """Hunt for all IOCs concurrently."""
        hunt_results = await asyncio.gather(*[self._hunt_one(r) for r in results])
        if self._session and not self._session.closed:
            await self._session.close()
        return list(hunt_results)
