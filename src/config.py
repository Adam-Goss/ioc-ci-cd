"""Configuration loader for the IOC pipeline."""

import os
from dataclasses import dataclass
from typing import Optional


def _int_or_none(value: Optional[str]) -> Optional[int]:
    """Convert string to int or return None."""
    return int(value) if value else None


def _bool_from_str(value: str, default: bool = False) -> bool:
    """Convert string to boolean."""
    return value.lower() in ("true", "1", "yes") if value else default


@dataclass
class PipelineConfig:
    """Pipeline configuration from environment variables."""

    # TI Source API keys
    vt_api_key: str
    abuseipdb_api_key: str
    otx_api_key: str

    # TI Source rate limits (override defaults)
    vt_rate_limit: Optional[int] = None
    abuseipdb_rate_limit: Optional[int] = None
    otx_rate_limit: Optional[int] = None

    # Downstream targets
    misp_url: Optional[str] = None
    misp_api_key: Optional[str] = None
    misp_verify_ssl: bool = True
    misp_distribution: int = 0
    misp_threat_level: int = 2
    misp_auto_publish: bool = False

    opencti_url: Optional[str] = None
    opencti_token: Optional[str] = None

    # Scoring weights
    weight_vt: float = 0.45
    weight_abuseipdb: float = 0.25
    weight_otx: float = 0.30

    # Per-publisher minimum confidence levels ("low", "medium", "high")
    misp_min_confidence_level: str = "medium"
    opencti_min_confidence_level: str = "high"


VALID_CONFIDENCE_LEVELS = ("low", "medium", "high")


def _validate_confidence_level(value: str, name: str) -> str:
    """Validate a confidence level string.

    Args:
        value: The level string to validate.
        name: Name of the config field (for error messages).

    Returns:
        Lowercased valid level string.

    Raises:
        ValueError: If level is not one of low, medium, high.
    """
    level = value.lower()
    if level not in VALID_CONFIDENCE_LEVELS:
        raise ValueError(
            f"Invalid {name}: '{value}'. Must be one of {VALID_CONFIDENCE_LEVELS}"
        )
    return level


def load_config() -> PipelineConfig:
    """Load configuration from environment variables."""
    misp_level = _validate_confidence_level(
        os.environ.get("MISP_MIN_CONFIDENCE_LEVEL", "medium"),
        "MISP_MIN_CONFIDENCE_LEVEL",
    )
    opencti_level = _validate_confidence_level(
        os.environ.get("OPENCTI_MIN_CONFIDENCE_LEVEL", "high"),
        "OPENCTI_MIN_CONFIDENCE_LEVEL",
    )

    return PipelineConfig(
        vt_api_key=os.environ["VT_API_KEY"],
        abuseipdb_api_key=os.environ["ABUSEIPDB_API_KEY"],
        otx_api_key=os.environ["OTX_API_KEY"],
        vt_rate_limit=_int_or_none(os.environ.get("VT_RATE_LIMIT")),
        abuseipdb_rate_limit=_int_or_none(os.environ.get("ABUSEIPDB_RATE_LIMIT")),
        otx_rate_limit=_int_or_none(os.environ.get("OTX_RATE_LIMIT")),
        misp_url=os.environ.get("MISP_URL"),
        misp_api_key=os.environ.get("MISP_API_KEY"),
        misp_verify_ssl=_bool_from_str(os.environ.get("MISP_VERIFY_SSL", ""), default=True),
        misp_distribution=int(os.environ.get("MISP_DISTRIBUTION", "0")),
        misp_threat_level=int(os.environ.get("MISP_THREAT_LEVEL", "2")),
        misp_auto_publish=_bool_from_str(os.environ.get("MISP_AUTO_PUBLISH", ""), default=False),
        opencti_url=os.environ.get("OPENCTI_URL"),
        opencti_token=os.environ.get("OPENCTI_TOKEN"),
        weight_vt=float(os.environ.get("WEIGHT_VT", "0.45")),
        weight_abuseipdb=float(os.environ.get("WEIGHT_ABUSEIPDB", "0.25")),
        weight_otx=float(os.environ.get("WEIGHT_OTX", "0.30")),
        misp_min_confidence_level=misp_level,
        opencti_min_confidence_level=opencti_level,
    )
