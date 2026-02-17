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

    def test_default_confidence_levels(self, monkeypatch):
        """Test config loads with default per-publisher confidence levels."""
        monkeypatch.setenv("VT_API_KEY", "test_vt")
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "test_abuse")
        monkeypatch.setenv("OTX_API_KEY", "test_otx")

        config = load_config()

        assert config.misp_min_confidence_level == "medium"
        assert config.opencti_min_confidence_level == "high"

    def test_custom_confidence_levels(self, monkeypatch):
        """Test config loads custom per-publisher confidence levels."""
        monkeypatch.setenv("VT_API_KEY", "test_vt")
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "test_abuse")
        monkeypatch.setenv("OTX_API_KEY", "test_otx")
        monkeypatch.setenv("MISP_MIN_CONFIDENCE_LEVEL", "low")
        monkeypatch.setenv("OPENCTI_MIN_CONFIDENCE_LEVEL", "medium")

        config = load_config()

        assert config.misp_min_confidence_level == "low"
        assert config.opencti_min_confidence_level == "medium"

    def test_invalid_confidence_level_raises(self, monkeypatch):
        """Test that invalid confidence level in env var raises ValueError."""
        monkeypatch.setenv("VT_API_KEY", "test_vt")
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "test_abuse")
        monkeypatch.setenv("OTX_API_KEY", "test_otx")
        monkeypatch.setenv("MISP_MIN_CONFIDENCE_LEVEL", "invalid")

        with pytest.raises(ValueError, match="Invalid"):
            load_config()
