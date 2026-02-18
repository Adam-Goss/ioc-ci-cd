"""Tests for Splunk hunting publisher."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aioresponses import aioresponses

from src.config import PipelineConfig
from src.models import EnrichmentResult, IOC, IOCType
from src.publishers.splunk import SplunkHunter, _build_spl


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(**kwargs):
    """Create a PipelineConfig with Splunk credentials."""
    defaults = dict(
        splunk_url="https://splunk.example.com:8089",
        splunk_token="test-splunk-token",
        splunk_index="main",
        max_ioc_age_days=30,
    )
    defaults.update(kwargs)
    return PipelineConfig(**defaults)


def _make_result(ioc_type: IOCType, value: str, confidence: float = 75.0) -> EnrichmentResult:
    ioc = IOC(ioc_type, value, value, 1)
    return EnrichmentResult(ioc, [], confidence=confidence, above_threshold=True)


def _splunk_job_response(sid: str = "test_sid_123") -> dict:
    return {"sid": sid}


def _splunk_status_response(state: str = "DONE") -> dict:
    return {"entry": [{"content": {"dispatchState": state}}]}


def _splunk_results_response(count: int, earliest: str | None = None, latest: str | None = None) -> dict:
    if count == 0:
        return {"results": []}
    return {
        "results": [
            {
                "count": str(count),
                "earliest": earliest or "2026-01-01T00:00:00Z",
                "latest": latest or "2026-02-01T00:00:00Z",
            }
        ]
    }


# ---------------------------------------------------------------------------
# SPL Query Generation
# ---------------------------------------------------------------------------

class TestBuildSpl:
    """Tests for SPL query generation."""

    def test_ip_query(self):
        """Test SPL query for IP IOC."""
        spl = _build_spl(IOCType.IP, "1.2.3.4", "main", 30)
        assert "src_ip" in spl
        assert "dest_ip" in spl
        assert '"1.2.3.4"' in spl
        assert "index=main" in spl
        assert "earliest_time=-30d" in spl

    def test_domain_query(self):
        """Test SPL query for domain IOC."""
        spl = _build_spl(IOCType.DOMAIN, "evil.com", "security", 7)
        assert "query" in spl
        assert '"evil.com"' in spl
        assert "index=security" in spl
        assert "earliest_time=-7d" in spl

    def test_url_query(self):
        """Test SPL query for URL IOC."""
        spl = _build_spl(IOCType.URL, "http://evil.com/malware", "main", 30)
        assert "url" in spl
        assert '"http://evil.com/malware"' in spl

    def test_md5_query(self):
        """Test SPL query for MD5 hash IOC."""
        spl = _build_spl(IOCType.HASH_MD5, "d41d8cd98f00b204e9800998ecf8427e", "main", 30)
        assert "file_hash" in spl or "md5" in spl
        assert "d41d8cd98f00b204e9800998ecf8427e" in spl

    def test_sha1_query(self):
        """Test SPL query for SHA1 hash IOC."""
        spl = _build_spl(IOCType.HASH_SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709", "main", 30)
        assert "sha1" in spl or "file_hash" in spl

    def test_sha256_query(self):
        """Test SPL query for SHA256 hash IOC."""
        spl = _build_spl(
            IOCType.HASH_SHA256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "main",
            30,
        )
        assert "sha256" in spl or "file_hash" in spl

    def test_stats_and_time_format(self):
        """Test that SPL query includes stats and time formatting."""
        spl = _build_spl(IOCType.IP, "1.2.3.4", "main", 30)
        assert "stats count" in spl
        assert "earliest" in spl
        assert "latest" in spl


# ---------------------------------------------------------------------------
# SplunkHunter initialization
# ---------------------------------------------------------------------------

class TestSplunkHunterInit:
    """Tests for SplunkHunter initialization."""

    def test_init_success(self):
        """Test successful initialization with valid config."""
        config = _make_config()
        hunter = SplunkHunter(config)
        assert hunter.name() == "splunk"

    def test_init_missing_url_raises(self):
        """Test that missing SPLUNK_URL raises ValueError."""
        config = _make_config(splunk_url=None)
        with pytest.raises(ValueError, match="SPLUNK_URL"):
            SplunkHunter(config)

    def test_init_missing_token_raises(self):
        """Test that missing SPLUNK_TOKEN raises ValueError."""
        config = _make_config(splunk_token=None)
        with pytest.raises(ValueError, match="SPLUNK_TOKEN"):
            SplunkHunter(config)

    def test_trailing_slash_stripped(self):
        """Test that trailing slash is stripped from URL."""
        config = _make_config(splunk_url="https://splunk.example.com:8089/")
        hunter = SplunkHunter(config)
        assert not hunter._url.endswith("/")


# ---------------------------------------------------------------------------
# SplunkHunter search flow (mocked HTTP)
# ---------------------------------------------------------------------------

class TestSplunkHunterSearch:
    """Tests for SplunkHunter HTTP interaction."""

    # aioresponses matches the full URL including query params that aiohttp appends.
    # Splunk GET requests use params={"output_mode": "json"} → appended to URL.
    _STATUS_PARAMS = "?output_mode=json"
    _RESULTS_PARAMS = "?output_mode=json&count=1"

    @pytest.mark.asyncio
    async def test_hunt_success_with_hits(self):
        """Test successful hunt that finds hits."""
        config = _make_config()
        hunter = SplunkHunter(config)
        result = _make_result(IOCType.IP, "1.2.3.4")
        base = "https://splunk.example.com:8089"

        with aioresponses() as m:
            # Create job (POST)
            m.post(f"{base}/services/search/jobs", payload=_splunk_job_response("sid_001"))
            # Poll status (GET with output_mode param)
            m.get(
                f"{base}/services/search/jobs/sid_001{self._STATUS_PARAMS}",
                payload=_splunk_status_response("DONE"),
            )
            # Fetch results (GET with output_mode + count params)
            m.get(
                f"{base}/services/search/jobs/sid_001/results{self._RESULTS_PARAMS}",
                payload=_splunk_results_response(
                    42, "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z"
                ),
            )

            hunt_results = await hunter.hunt([result])

        assert len(hunt_results) == 1
        hr = hunt_results[0]
        assert hr.hits_found == 42
        assert hr.success is True
        assert hr.platform == "splunk"
        assert hr.earliest_hit == "2026-01-01T00:00:00Z"
        assert hr.latest_hit == "2026-02-01T00:00:00Z"
        assert hr.ioc.value == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_hunt_zero_hits(self):
        """Test hunt that finds no hits."""
        config = _make_config()
        hunter = SplunkHunter(config)
        result = _make_result(IOCType.DOMAIN, "safe.example.com")
        base = "https://splunk.example.com:8089"

        with aioresponses() as m:
            m.post(f"{base}/services/search/jobs", payload=_splunk_job_response("sid_002"))
            m.get(
                f"{base}/services/search/jobs/sid_002{self._STATUS_PARAMS}",
                payload=_splunk_status_response("DONE"),
            )
            m.get(
                f"{base}/services/search/jobs/sid_002/results{self._RESULTS_PARAMS}",
                payload=_splunk_results_response(0),
            )

            hunt_results = await hunter.hunt([result])

        assert len(hunt_results) == 1
        hr = hunt_results[0]
        assert hr.hits_found == 0
        assert hr.success is True
        assert hr.earliest_hit is None
        assert hr.latest_hit is None

    @pytest.mark.asyncio
    async def test_hunt_connection_error_returns_failure(self):
        """Test that connection errors produce failed HuntResult (not exception)."""
        config = _make_config()
        hunter = SplunkHunter(config)
        result = _make_result(IOCType.IP, "1.2.3.4")

        with aioresponses() as m:
            m.post(
                "https://splunk.example.com:8089/services/search/jobs",
                exception=Exception("Connection refused"),
            )

            hunt_results = await hunter.hunt([result])

        assert len(hunt_results) == 1
        hr = hunt_results[0]
        assert hr.success is False
        assert hr.hits_found == 0
        assert "Connection refused" in hr.error

    @pytest.mark.asyncio
    async def test_hunt_includes_query_used(self):
        """Test that hunt result includes the SPL query that was used."""
        config = _make_config()
        hunter = SplunkHunter(config)
        result = _make_result(IOCType.IP, "192.168.1.1")
        base = "https://splunk.example.com:8089"

        with aioresponses() as m:
            m.post(f"{base}/services/search/jobs", payload=_splunk_job_response("sid_003"))
            m.get(
                f"{base}/services/search/jobs/sid_003{self._STATUS_PARAMS}",
                payload=_splunk_status_response("DONE"),
            )
            m.get(
                f"{base}/services/search/jobs/sid_003/results{self._RESULTS_PARAMS}",
                payload=_splunk_results_response(5),
            )

            hunt_results = await hunter.hunt([result])

        assert "192.168.1.1" in hunt_results[0].query_used

    @pytest.mark.asyncio
    async def test_hunt_multiple_iocs(self):
        """Test hunting multiple IOCs concurrently."""
        config = _make_config()
        hunter = SplunkHunter(config)
        results = [
            _make_result(IOCType.IP, "1.2.3.4"),
            _make_result(IOCType.DOMAIN, "evil.com"),
        ]
        base = "https://splunk.example.com:8089"

        with aioresponses() as m:
            for sid, count in [("sid_a", 5), ("sid_b", 0)]:
                m.post(f"{base}/services/search/jobs", payload=_splunk_job_response(sid))
                m.get(
                    f"{base}/services/search/jobs/{sid}{self._STATUS_PARAMS}",
                    payload=_splunk_status_response("DONE"),
                )
                m.get(
                    f"{base}/services/search/jobs/{sid}/results{self._RESULTS_PARAMS}",
                    payload=_splunk_results_response(count),
                )

            hunt_results = await hunter.hunt(results)

        assert len(hunt_results) == 2
        # Both should be successful even if hits differ
        assert all(hr.success for hr in hunt_results)

    @pytest.mark.asyncio
    async def test_hunt_empty_list_returns_empty(self):
        """Test that hunting empty list returns empty results."""
        config = _make_config()
        hunter = SplunkHunter(config)

        hunt_results = await hunter.hunt([])
        assert hunt_results == []
