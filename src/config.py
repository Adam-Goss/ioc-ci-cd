"""Configuration loader for the IOC pipeline."""

import os
from dataclasses import dataclass, field
from typing import Optional


def _int_or_none(value: Optional[str]) -> Optional[int]:
    """Convert string to int or return None."""
    return int(value) if value else None


def _bool_from_str(value: str, default: bool = False) -> bool:
    """Convert string to boolean."""
    return value.lower() in ("true", "1", "yes") if value else default


def _parse_csv_list(value: Optional[str], default: list[str]) -> list[str]:
    """Parse a comma-separated string into a list, stripping whitespace."""
    if not value:
        return default
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass
class PipelineConfig:
    """Pipeline configuration from environment variables."""

    # TI Source API keys (Optional — only required if source is in enrichment_sources)
    vt_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    otx_api_key: Optional[str] = None

    # TI Source rate limits (override defaults)
    vt_rate_limit: Optional[int] = None
    abuseipdb_rate_limit: Optional[int] = None
    otx_rate_limit: Optional[int] = None

    # Scoring weights
    weight_vt: float = 0.45
    weight_abuseipdb: float = 0.25
    weight_otx: float = 0.30

    # Modular source/publisher selection
    enrichment_sources: list[str] = field(
        default_factory=lambda: ["virustotal", "abuseipdb", "otx"]
    )
    publishers: list[str] = field(default_factory=lambda: ["splunk", "elastic"])

    # Age-based IOC selection for hunting
    max_ioc_age_days: int = 30

    # Per-publisher minimum confidence levels ("low", "medium", "high")
    publisher_min_confidence: dict[str, str] = field(
        default_factory=lambda: {"splunk": "low", "elastic": "low"}
    )

    # Splunk config
    splunk_url: Optional[str] = None
    splunk_token: Optional[str] = None
    splunk_index: str = "main"

    # Elastic config
    elastic_url: Optional[str] = None
    elastic_api_key: Optional[str] = None
    elastic_index: str = "*"
    elastic_verify_ssl: bool = True


VALID_CONFIDENCE_LEVELS = ("low", "medium", "high")

_ENRICHMENT_SOURCE_KEY_MAP = {
    "virustotal": "VT_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "otx": "OTX_API_KEY",
}

_PUBLISHER_REQUIRED_VARS: dict[str, list[str]] = {
    "splunk": ["SPLUNK_URL", "SPLUNK_TOKEN"],
    "elastic": ["ELASTIC_URL", "ELASTIC_API_KEY"],
}


def _validate_confidence_level(value: str, name: str) -> str:
    """Validate a confidence level string."""
    level = value.lower()
    if level not in VALID_CONFIDENCE_LEVELS:
        raise ValueError(
            f"Invalid {name}: '{value}'. Must be one of {VALID_CONFIDENCE_LEVELS}"
        )
    return level


def load_config() -> PipelineConfig:
    """Load configuration from environment variables."""
    enrichment_sources = _parse_csv_list(
        os.environ.get("ENRICHMENT_SOURCES"), ["virustotal", "abuseipdb", "otx"]
    )
    publishers = _parse_csv_list(
        os.environ.get("PUBLISHERS"), ["splunk", "elastic"]
    )

    # Validate that required API keys exist for enabled enrichment sources
    for source in enrichment_sources:
        env_var = _ENRICHMENT_SOURCE_KEY_MAP.get(source)
        if env_var and not os.environ.get(env_var):
            raise KeyError(
                f"{env_var} is required because '{source}' is in ENRICHMENT_SOURCES"
            )

    # Validate that required URLs/tokens exist for enabled publishers
    for publisher in publishers:
        required = _PUBLISHER_REQUIRED_VARS.get(publisher, [])
        for var in required:
            if not os.environ.get(var):
                raise KeyError(
                    f"{var} is required because '{publisher}' is in PUBLISHERS"
                )

    # Per-publisher confidence levels from env vars
    publisher_min_confidence: dict[str, str] = {}
    for pub in publishers:
        env_key = f"{pub.upper()}_MIN_CONFIDENCE_LEVEL"
        raw = os.environ.get(env_key, "low")
        publisher_min_confidence[pub] = _validate_confidence_level(raw, env_key)

    return PipelineConfig(
        vt_api_key=os.environ.get("VT_API_KEY"),
        abuseipdb_api_key=os.environ.get("ABUSEIPDB_API_KEY"),
        otx_api_key=os.environ.get("OTX_API_KEY"),
        vt_rate_limit=_int_or_none(os.environ.get("VT_RATE_LIMIT")),
        abuseipdb_rate_limit=_int_or_none(os.environ.get("ABUSEIPDB_RATE_LIMIT")),
        otx_rate_limit=_int_or_none(os.environ.get("OTX_RATE_LIMIT")),
        weight_vt=float(os.environ.get("WEIGHT_VT", "0.45")),
        weight_abuseipdb=float(os.environ.get("WEIGHT_ABUSEIPDB", "0.25")),
        weight_otx=float(os.environ.get("WEIGHT_OTX", "0.30")),
        enrichment_sources=enrichment_sources,
        publishers=publishers,
        max_ioc_age_days=int(os.environ.get("MAX_IOC_AGE_DAYS", "30")),
        publisher_min_confidence=publisher_min_confidence,
        splunk_url=os.environ.get("SPLUNK_URL"),
        splunk_token=os.environ.get("SPLUNK_TOKEN"),
        splunk_index=os.environ.get("SPLUNK_INDEX", "main"),
        elastic_url=os.environ.get("ELASTIC_URL"),
        elastic_api_key=os.environ.get("ELASTIC_API_KEY"),
        elastic_index=os.environ.get("ELASTIC_INDEX", "*"),
        elastic_verify_ssl=_bool_from_str(
            os.environ.get("ELASTIC_VERIFY_SSL", ""), default=True
        ),
    )
