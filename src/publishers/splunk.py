"""Splunk hunting publisher — searches for IOCs in Splunk log data."""

import asyncio
import logging
from typing import TYPE_CHECKING

import aiohttp

from src.models import EnrichmentResult, HuntResult, IOCType
from src.publishers.base import HuntPublisher

if TYPE_CHECKING:
    from src.config import PipelineConfig

logger = logging.getLogger("ioc_pipeline.splunk")

# SPL query templates per IOC type
_SPL_TEMPLATES: dict[IOCType, str] = {
    IOCType.IP: (
        'search index={index} earliest_time=-{age}d '
        '(src_ip="{value}" OR dest_ip="{value}" OR src="{value}" OR dst="{value}") '
        '| stats count earliest(_time) as earliest latest(_time) as latest '
        '| eval earliest=strftime(earliest,"%Y-%m-%dT%H:%M:%SZ"), '
        'latest=strftime(latest,"%Y-%m-%dT%H:%M:%SZ")'
    ),
    IOCType.DOMAIN: (
        'search index={index} earliest_time=-{age}d '
        '(query="{value}" OR dest="{value}" OR url="*{value}*" OR hostname="{value}") '
        '| stats count earliest(_time) as earliest latest(_time) as latest '
        '| eval earliest=strftime(earliest,"%Y-%m-%dT%H:%M:%SZ"), '
        'latest=strftime(latest,"%Y-%m-%dT%H:%M:%SZ")'
    ),
    IOCType.URL: (
        'search index={index} earliest_time=-{age}d '
        '(url="{value}" OR http_referrer="{value}") '
        '| stats count earliest(_time) as earliest latest(_time) as latest '
        '| eval earliest=strftime(earliest,"%Y-%m-%dT%H:%M:%SZ"), '
        'latest=strftime(latest,"%Y-%m-%dT%H:%M:%SZ")'
    ),
    IOCType.HASH_MD5: (
        'search index={index} earliest_time=-{age}d '
        '(file_hash="{value}" OR md5="{value}" OR hash="{value}") '
        '| stats count earliest(_time) as earliest latest(_time) as latest '
        '| eval earliest=strftime(earliest,"%Y-%m-%dT%H:%M:%SZ"), '
        'latest=strftime(latest,"%Y-%m-%dT%H:%M:%SZ")'
    ),
    IOCType.HASH_SHA1: (
        'search index={index} earliest_time=-{age}d '
        '(file_hash="{value}" OR sha1="{value}" OR hash="{value}") '
        '| stats count earliest(_time) as earliest latest(_time) as latest '
        '| eval earliest=strftime(earliest,"%Y-%m-%dT%H:%M:%SZ"), '
        'latest=strftime(latest,"%Y-%m-%dT%H:%M:%SZ")'
    ),
    IOCType.HASH_SHA256: (
        'search index={index} earliest_time=-{age}d '
        '(file_hash="{value}" OR sha256="{value}" OR hash="{value}") '
        '| stats count earliest(_time) as earliest latest(_time) as latest '
        '| eval earliest=strftime(earliest,"%Y-%m-%dT%H:%M:%SZ"), '
        'latest=strftime(latest,"%Y-%m-%dT%H:%M:%SZ")'
    ),
}


def _build_spl(ioc_type: IOCType, value: str, index: str, age_days: int) -> str:
    """Build an SPL query for the given IOC."""
    template = _SPL_TEMPLATES[ioc_type]
    return template.format(index=index, value=value, age=age_days)


class SplunkHunter(HuntPublisher):
    """Hunts for IOCs in Splunk using the Splunk REST API."""

    def __init__(self, config: "PipelineConfig") -> None:
        if not config.splunk_url:
            raise ValueError("SPLUNK_URL is required for Splunk hunting")
        if not config.splunk_token:
            raise ValueError("SPLUNK_TOKEN is required for Splunk hunting")
        self._url = config.splunk_url.rstrip("/")
        self._token = config.splunk_token
        self._index = config.splunk_index
        self._age_days = config.max_ioc_age_days
        self._session: aiohttp.ClientSession | None = None

    def name(self) -> str:
        return "splunk"

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/x-www-form-urlencoded",
                }
            )
        return self._session

    async def _run_search(self, spl: str) -> tuple[int, str | None, str | None]:
        """Submit a Splunk search job and return (hit_count, earliest, latest)."""
        session = await self._get_session()

        # Create search job
        create_url = f"{self._url}/services/search/jobs"
        data = {"search": spl, "output_mode": "json", "exec_mode": "normal"}
        async with session.post(create_url, data=data, ssl=False) as resp:
            resp.raise_for_status()
            body = await resp.json()
            sid = body["sid"]

        # Poll until done
        status_url = f"{self._url}/services/search/jobs/{sid}"
        for _ in range(30):  # max 30 polls (~30s)
            await asyncio.sleep(1)
            async with session.get(
                status_url, params={"output_mode": "json"}, ssl=False
            ) as resp:
                resp.raise_for_status()
                body = await resp.json()
                state = body["entry"][0]["content"]["dispatchState"]
                if state in ("DONE", "FAILED"):
                    break

        if state == "FAILED":
            raise RuntimeError(f"Splunk search job failed: {sid}")

        # Fetch results
        results_url = f"{self._url}/services/search/jobs/{sid}/results"
        async with session.get(
            results_url, params={"output_mode": "json", "count": 1}, ssl=False
        ) as resp:
            resp.raise_for_status()
            body = await resp.json()

        results = body.get("results", [])
        if not results:
            return 0, None, None

        row = results[0]
        count = int(row.get("count", 0))
        earliest = row.get("earliest") or None
        latest = row.get("latest") or None
        return count, earliest, latest

    async def _hunt_one(self, result: EnrichmentResult) -> HuntResult:
        """Hunt for a single IOC."""
        ioc = result.ioc
        spl = _build_spl(ioc.ioc_type, ioc.value, self._index, self._age_days)
        try:
            count, earliest, latest = await self._run_search(spl)
            return HuntResult(
                ioc=ioc,
                platform=self.name(),
                hits_found=count,
                earliest_hit=earliest,
                latest_hit=latest,
                query_used=spl,
            )
        except Exception as e:
            logger.warning(f"Splunk hunt failed for {ioc.value}: {e}")
            return HuntResult(
                ioc=ioc,
                platform=self.name(),
                hits_found=0,
                query_used=spl,
                error=str(e),
                success=False,
            )

    async def hunt(self, results: list[EnrichmentResult]) -> list[HuntResult]:
        """Hunt for all IOCs concurrently."""
        hunt_results = await asyncio.gather(*[self._hunt_one(r) for r in results])
        if self._session and not self._session.closed:
            await self._session.close()
        return list(hunt_results)
