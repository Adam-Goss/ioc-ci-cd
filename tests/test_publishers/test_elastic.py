"""Tests for Elastic hunting publisher."""

import pytest
from aioresponses import aioresponses

from src.config import PipelineConfig
from src.models import EnrichmentResult, IOC, IOCType
from src.publishers.elastic import ElasticHunter, _build_query


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(**kwargs):
    """Create a PipelineConfig with Elastic credentials."""
    defaults = dict(
        elastic_url="https://elastic.example.com:9200",
        elastic_api_key="test-elastic-api-key",
        elastic_index="*",
        max_ioc_age_days=30,
        elastic_verify_ssl=False,
    )
    defaults.update(kwargs)
    return PipelineConfig(**defaults)


def _make_result(ioc_type: IOCType, value: str, confidence: float = 75.0) -> EnrichmentResult:
    ioc = IOC(ioc_type, value, value, 1)
    return EnrichmentResult(ioc, [], confidence=confidence, above_threshold=True)


def _elastic_hits_response(count: int, samples: list[dict] | None = None) -> dict:
    """Build a mock Elasticsearch hits response."""
    hits = samples or []
    return {
        "hits": {
            "total": {"value": count, "relation": "eq"},
            "hits": [{"_source": s} for s in hits],
        }
    }


# ---------------------------------------------------------------------------
# Query Generation
# ---------------------------------------------------------------------------

class TestBuildQuery:
    """Tests for Elasticsearch query generation."""

    def test_ip_query_uses_ecs_fields(self):
        """Test that IP query uses ECS source/destination IP fields."""
        query = _build_query(IOCType.IP, "1.2.3.4", 30)
        should = query["query"]["bool"]["should"]
        fields = {clause["term"].popitem()[0] for clause in should}
        assert "source.ip" in fields
        assert "destination.ip" in fields

    def test_domain_query_uses_ecs_fields(self):
        """Test that domain query uses ECS DNS/URL fields."""
        query = _build_query(IOCType.DOMAIN, "evil.com", 30)
        should = query["query"]["bool"]["should"]
        fields = {clause["term"].popitem()[0] for clause in should}
        assert "dns.question.name" in fields or "url.domain" in fields

    def test_url_query_uses_url_full(self):
        """Test that URL query uses url.full field."""
        query = _build_query(IOCType.URL, "http://evil.com/malware", 30)
        should = query["query"]["bool"]["should"]
        fields = {clause["term"].popitem()[0] for clause in should}
        assert "url.full" in fields

    def test_md5_query_uses_file_hash_fields(self):
        """Test that MD5 query uses file.hash.md5 field."""
        query = _build_query(IOCType.HASH_MD5, "d41d8cd98f00b204e9800998ecf8427e", 30)
        should = query["query"]["bool"]["should"]
        fields = {clause["term"].popitem()[0] for clause in should}
        assert "file.hash.md5" in fields

    def test_sha256_query_uses_file_hash_sha256(self):
        """Test that SHA256 query uses file.hash.sha256 field."""
        query = _build_query(
            IOCType.HASH_SHA256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            30,
        )
        should = query["query"]["bool"]["should"]
        fields = {clause["term"].popitem()[0] for clause in should}
        assert "file.hash.sha256" in fields

    def test_query_includes_timestamp_range(self):
        """Test that query includes @timestamp range filter."""
        query = _build_query(IOCType.IP, "1.2.3.4", 14)
        filters = query["query"]["bool"]["filter"]
        range_filters = [f for f in filters if "range" in f]
        assert len(range_filters) == 1
        assert "now-14d" in range_filters[0]["range"]["@timestamp"]["gte"]

    def test_query_minimum_should_match(self):
        """Test that query requires at least one should clause to match."""
        query = _build_query(IOCType.IP, "1.2.3.4", 30)
        assert query["query"]["bool"]["minimum_should_match"] == 1

    def test_query_requests_sample_events(self):
        """Test that query requests sample events (size > 0)."""
        query = _build_query(IOCType.IP, "1.2.3.4", 30)
        assert query["size"] > 0


# ---------------------------------------------------------------------------
# ElasticHunter initialization
# ---------------------------------------------------------------------------

class TestElasticHunterInit:
    """Tests for ElasticHunter initialization."""

    def test_init_success(self):
        """Test successful initialization with valid config."""
        config = _make_config()
        hunter = ElasticHunter(config)
        assert hunter.name() == "elastic"

    def test_init_missing_url_raises(self):
        """Test that missing ELASTIC_URL raises ValueError."""
        config = _make_config(elastic_url=None)
        with pytest.raises(ValueError, match="ELASTIC_URL"):
            ElasticHunter(config)

    def test_init_missing_api_key_raises(self):
        """Test that missing ELASTIC_API_KEY raises ValueError."""
        config = _make_config(elastic_api_key=None)
        with pytest.raises(ValueError, match="ELASTIC_API_KEY"):
            ElasticHunter(config)

    def test_trailing_slash_stripped(self):
        """Test that trailing slash is stripped from URL."""
        config = _make_config(elastic_url="https://elastic.example.com:9200/")
        hunter = ElasticHunter(config)
        assert not hunter._url.endswith("/")


# ---------------------------------------------------------------------------
# ElasticHunter search flow (mocked HTTP)
# ---------------------------------------------------------------------------

class TestElasticHunterSearch:
    """Tests for ElasticHunter HTTP interaction."""

    @pytest.mark.asyncio
    async def test_hunt_success_with_hits(self):
        """Test successful hunt that finds hits."""
        config = _make_config()
        hunter = ElasticHunter(config)
        result = _make_result(IOCType.IP, "1.2.3.4")

        samples = [
            {"@timestamp": "2026-01-15T10:00:00Z", "source.ip": "1.2.3.4"},
            {"@timestamp": "2026-02-01T12:00:00Z", "source.ip": "1.2.3.4"},
        ]

        with aioresponses() as m:
            m.post(
                "https://elastic.example.com:9200/*/_search",
                payload=_elastic_hits_response(15, samples),
            )

            hunt_results = await hunter.hunt([result])

        assert len(hunt_results) == 1
        hr = hunt_results[0]
        assert hr.hits_found == 15
        assert hr.success is True
        assert hr.platform == "elastic"
        assert hr.ioc.value == "1.2.3.4"
        assert len(hr.sample_events) == 2

    @pytest.mark.asyncio
    async def test_hunt_zero_hits(self):
        """Test hunt that finds no hits."""
        config = _make_config()
        hunter = ElasticHunter(config)
        result = _make_result(IOCType.DOMAIN, "safe.example.com")

        with aioresponses() as m:
            m.post(
                "https://elastic.example.com:9200/*/_search",
                payload=_elastic_hits_response(0),
            )

            hunt_results = await hunter.hunt([result])

        assert len(hunt_results) == 1
        hr = hunt_results[0]
        assert hr.hits_found == 0
        assert hr.success is True
        assert hr.sample_events == []
        assert hr.earliest_hit is None
        assert hr.latest_hit is None

    @pytest.mark.asyncio
    async def test_hunt_connection_error_returns_failure(self):
        """Test that connection errors produce failed HuntResult (not exception)."""
        config = _make_config()
        hunter = ElasticHunter(config)
        result = _make_result(IOCType.IP, "1.2.3.4")

        with aioresponses() as m:
            m.post(
                "https://elastic.example.com:9200/*/_search",
                exception=Exception("Connection refused"),
            )

            hunt_results = await hunter.hunt([result])

        assert len(hunt_results) == 1
        hr = hunt_results[0]
        assert hr.success is False
        assert hr.hits_found == 0
        assert "Connection refused" in hr.error

    @pytest.mark.asyncio
    async def test_hunt_extracts_timestamps(self):
        """Test that earliest and latest timestamps are extracted from sample events."""
        config = _make_config()
        hunter = ElasticHunter(config)
        result = _make_result(IOCType.IP, "10.0.0.1")

        samples = [
            {"@timestamp": "2026-02-01T00:00:00Z"},
            {"@timestamp": "2026-01-01T00:00:00Z"},
        ]

        with aioresponses() as m:
            m.post(
                "https://elastic.example.com:9200/*/_search",
                payload=_elastic_hits_response(2, samples),
            )

            hunt_results = await hunter.hunt([result])

        hr = hunt_results[0]
        assert hr.earliest_hit == "2026-01-01T00:00:00Z"
        assert hr.latest_hit == "2026-02-01T00:00:00Z"

    @pytest.mark.asyncio
    async def test_hunt_multiple_iocs(self):
        """Test hunting multiple IOCs concurrently."""
        config = _make_config()
        hunter = ElasticHunter(config)
        results = [
            _make_result(IOCType.IP, "1.2.3.4"),
            _make_result(IOCType.DOMAIN, "evil.com"),
        ]

        with aioresponses() as m:
            m.post(
                "https://elastic.example.com:9200/*/_search",
                payload=_elastic_hits_response(10),
            )
            m.post(
                "https://elastic.example.com:9200/*/_search",
                payload=_elastic_hits_response(0),
            )

            hunt_results = await hunter.hunt(results)

        assert len(hunt_results) == 2
        assert all(hr.success for hr in hunt_results)

    @pytest.mark.asyncio
    async def test_hunt_includes_query_used(self):
        """Test that hunt result includes the query that was used."""
        config = _make_config()
        hunter = ElasticHunter(config)
        result = _make_result(IOCType.DOMAIN, "evil.com")

        with aioresponses() as m:
            m.post(
                "https://elastic.example.com:9200/*/_search",
                payload=_elastic_hits_response(1),
            )

            hunt_results = await hunter.hunt([result])

        assert hunt_results[0].query_used != ""

    @pytest.mark.asyncio
    async def test_hunt_empty_list_returns_empty(self):
        """Test that hunting empty list returns empty results."""
        config = _make_config()
        hunter = ElasticHunter(config)

        hunt_results = await hunter.hunt([])
        assert hunt_results == []

    @pytest.mark.asyncio
    async def test_hunt_uses_configured_index(self):
        """Test that hunt uses the configured index."""
        config = _make_config(elastic_index="logs-*")
        hunter = ElasticHunter(config)
        result = _make_result(IOCType.IP, "1.2.3.4")

        with aioresponses() as m:
            m.post(
                "https://elastic.example.com:9200/logs-*/_search",
                payload=_elastic_hits_response(5),
            )

            hunt_results = await hunter.hunt([result])

        assert hunt_results[0].success is True
