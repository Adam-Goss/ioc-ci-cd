"""Tests for configuration loading."""

import pytest

from src.config import VALID_CONFIDENCE_LEVELS, _validate_confidence_level, load_config


class TestValidateConfidenceLevel:
    """Tests for confidence level validation."""

    def test_valid_levels(self):
        """Test that valid levels are accepted and lowercased."""
        assert _validate_confidence_level("low", "test") == "low"
        assert _validate_confidence_level("medium", "test") == "medium"
        assert _validate_confidence_level("high", "test") == "high"

    def test_case_insensitive(self):
        """Test that validation is case-insensitive."""
        assert _validate_confidence_level("LOW", "test") == "low"
        assert _validate_confidence_level("Medium", "test") == "medium"
        assert _validate_confidence_level("HIGH", "test") == "high"

    def test_invalid_level_raises(self):
        """Test that invalid levels raise ValueError."""
        with pytest.raises(ValueError, match="Invalid"):
            _validate_confidence_level("invalid", "test")

        with pytest.raises(ValueError, match="Invalid"):
            _validate_confidence_level("", "test")

        with pytest.raises(ValueError, match="Invalid"):
            _validate_confidence_level("critical", "test")


class TestLoadConfig:
    """Tests for load_config function."""

    def test_default_sources_and_no_publishers(self, monkeypatch):
        """Test config loads with default enrichment sources and empty publishers list."""
        monkeypatch.setenv("VT_API_KEY", "test_vt")
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "test_abuse")
        monkeypatch.setenv("OTX_API_KEY", "test_otx")
        # A single space forces _parse_csv_list to return [] (no publishers needed)
        monkeypatch.setenv("PUBLISHERS", " ")

        config = load_config()

        assert config.enrichment_sources == ["virustotal", "abuseipdb", "otx"]
        assert config.publishers == []
        assert config.max_ioc_age_days == 30

    def test_custom_publisher_confidence(self, monkeypatch):
        """Test config loads custom per-publisher confidence levels."""
        # A single space forces _parse_csv_list to return [] (no API keys needed)
        monkeypatch.setenv("ENRICHMENT_SOURCES", " ")
        monkeypatch.setenv("PUBLISHERS", "splunk")
        monkeypatch.setenv("SPLUNK_URL", "https://splunk.example.com")
        monkeypatch.setenv("SPLUNK_TOKEN", "test-token")
        monkeypatch.setenv("SPLUNK_MIN_CONFIDENCE_LEVEL", "high")

        config = load_config()

        assert config.publisher_min_confidence["splunk"] == "high"
        assert config.splunk_url == "https://splunk.example.com"
        assert config.splunk_token == "test-token"

    def test_invalid_confidence_level_raises(self, monkeypatch):
        """Test that invalid confidence level in env var raises ValueError."""
        monkeypatch.setenv("ENRICHMENT_SOURCES", " ")
        monkeypatch.setenv("PUBLISHERS", "splunk")
        monkeypatch.setenv("SPLUNK_URL", "https://splunk.example.com")
        monkeypatch.setenv("SPLUNK_TOKEN", "test-token")
        monkeypatch.setenv("SPLUNK_MIN_CONFIDENCE_LEVEL", "invalid")

        with pytest.raises(ValueError, match="Invalid"):
            load_config()
