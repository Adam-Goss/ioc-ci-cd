"""Tests for CLI commands."""

import argparse
import csv
import os
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.cli import (
    append_to_master_inventory,
    build_validation_report,
    filter_by_publisher_confidence,
    inventory_command,
    publish_command,
    read_iocs_by_age,
    update_csv_last_hunted,
    validate_command,
)
from src.models import EnrichmentResult, HuntResult, IOC, IOCType, ValidationReport


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(ioc_type, value, confidence, line=1):
    """Create an EnrichmentResult for testing."""
    ioc = IOC(ioc_type, value, value, line)
    return EnrichmentResult(ioc, [], confidence=confidence, above_threshold=False)


def _write_master_csv(path, rows, header=None):
    """Write a master CSV with the given rows."""
    if header is None:
        header = [
            "ioc_type", "ioc_value", "confidence_score", "confidence_level",
            "added_date", "last_hunted_date", "commit_sha",
        ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for row in rows:
            writer.writerow(row)


def _read_master_csv(path):
    """Read master CSV and return list of dicts."""
    with open(path, "r", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _recent_date(days_ago=1):
    """Return a timestamp string for N days ago."""
    return (datetime.now() - timedelta(days=days_ago)).strftime("%Y-%m-%d %H:%M:%S")


def _old_date(days_ago=60):
    """Return a timestamp string for N days ago (default: old enough to be stale)."""
    return (datetime.now() - timedelta(days=days_ago)).strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# TestBuildValidationReport
# ---------------------------------------------------------------------------

class TestBuildValidationReport:
    """Tests for building validation report."""

    def test_build_validation_report(self, mock_enrichment_result):
        """Test building a validation report with above threshold results."""
        ioc = mock_enrichment_result.ioc
        report = build_validation_report(
            valid_iocs=[ioc],
            malformed_lines=[],
            duplicates_removed=0,
            enrichment_results=[mock_enrichment_result],
            threshold=70.0,
            override=False,
        )

        assert isinstance(report, ValidationReport)
        assert len(report.valid_iocs) == 1
        assert len(report.enrichment_results) == 1
        assert report.threshold == 70.0
        assert report.override is False
        assert report.enrichment_results[0].above_threshold is True

    def test_build_validation_report_below_threshold(self):
        """Test building a report with below threshold results."""
        result = _make_result(IOCType.IP, "192.168.1.1", 45.0)

        report = build_validation_report(
            valid_iocs=[result.ioc],
            malformed_lines=[],
            duplicates_removed=0,
            enrichment_results=[result],
            threshold=70.0,
            override=False,
        )

        assert report.enrichment_results[0].above_threshold is False


# ---------------------------------------------------------------------------
# TestAppendToMasterInventory
# ---------------------------------------------------------------------------

class TestAppendToMasterInventory:
    """Tests for appending to master inventory CSV."""

    def test_append_to_new_file(self, tmp_path, monkeypatch):
        """Test creating new master inventory CSV with new schema."""
        master_csv = tmp_path / "master-indicators.csv"
        monkeypatch.setenv("GITHUB_SHA", "abc123def456789")

        result = _make_result(IOCType.IP, "192.168.1.1", 85.0)
        append_to_master_inventory([result], master_csv_path=str(master_csv))

        rows = _read_master_csv(master_csv)
        assert len(rows) == 1
        row = rows[0]
        assert row["ioc_type"] == "ip"
        assert row["ioc_value"] == "192.168.1.1"
        assert row["confidence_score"] == "85.00"
        assert row["confidence_level"] == "high"
        assert row["commit_sha"] == "abc123de"
        # No status/deployed_to columns
        assert "status" not in row
        assert "deployed_to" not in row
        # New columns present
        assert "added_date" in row
        assert row["last_hunted_date"] == ""

    def test_append_below_threshold_no_status(self, tmp_path):
        """Test that appended IOCs have no status/deployed_to columns."""
        master_csv = tmp_path / "master-indicators.csv"
        result = _make_result(IOCType.IP, "10.0.0.1", 15.0)
        append_to_master_inventory([result], master_csv_path=str(master_csv))

        rows = _read_master_csv(master_csv)
        assert len(rows) == 1
        assert "status" not in rows[0]
        assert "deployed_to" not in rows[0]

    def test_append_to_existing_file(self, tmp_path):
        """Test appending to existing master inventory CSV."""
        master_csv = tmp_path / "master-indicators.csv"

        _write_master_csv(master_csv, [
            ["domain", "evil.com", "90.00", "high", "2024-01-01 12:00:00", "", "old123"],
        ])

        result = _make_result(IOCType.IP, "192.168.1.1", 85.0)
        append_to_master_inventory([result], master_csv_path=str(master_csv))

        rows = _read_master_csv(master_csv)
        assert len(rows) == 2
        assert rows[0]["ioc_value"] == "evil.com"
        assert rows[1]["ioc_value"] == "192.168.1.1"

    def test_append_skips_duplicates(self, tmp_path):
        """Test that duplicate IOCs are not appended."""
        master_csv = tmp_path / "master-indicators.csv"

        _write_master_csv(master_csv, [
            ["ip", "192.168.1.1", "80.00", "high", "2024-01-01 12:00:00", "", "old123"],
        ])

        result = _make_result(IOCType.IP, "192.168.1.1", 85.0)
        append_to_master_inventory([result], master_csv_path=str(master_csv))

        rows = _read_master_csv(master_csv)
        assert len(rows) == 1

    def test_append_multiple_iocs(self, tmp_path):
        """Test appending multiple IOCs at once."""
        master_csv = tmp_path / "master-indicators.csv"

        results = [
            _make_result(IOCType.IP, "192.168.1.1", 85.0, 1),
            _make_result(IOCType.DOMAIN, "evil.com", 90.0, 2),
            _make_result(IOCType.URL, "http://bad.com", 25.0, 3),
        ]

        append_to_master_inventory(results, master_csv_path=str(master_csv))

        rows = _read_master_csv(master_csv)
        assert len(rows) == 3
        assert rows[0]["ioc_value"] == "192.168.1.1"
        assert rows[1]["ioc_value"] == "evil.com"
        assert rows[2]["ioc_value"] == "http://bad.com"

    def test_append_all_ioc_types(self, tmp_path):
        """Test that all IOC types are correctly recorded."""
        master_csv = tmp_path / "master-indicators.csv"

        iocs = [
            _make_result(IOCType.IP, "192.168.1.1", 75.0, 1),
            _make_result(IOCType.DOMAIN, "evil.com", 75.0, 2),
            _make_result(IOCType.URL, "http://bad.com", 75.0, 3),
            _make_result(IOCType.HASH_MD5, "d41d8cd98f00b204e9800998ecf8427e", 75.0, 4),
            _make_result(IOCType.HASH_SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709", 75.0, 5),
            _make_result(IOCType.HASH_SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 75.0, 6),
        ]

        append_to_master_inventory(iocs, master_csv_path=str(master_csv))

        rows = _read_master_csv(master_csv)
        assert len(rows) == 6
        assert rows[0]["ioc_type"] == "ip"
        assert rows[1]["ioc_type"] == "domain"
        assert rows[2]["ioc_type"] == "url"
        assert rows[3]["ioc_type"] == "hash_md5"
        assert rows[4]["ioc_type"] == "hash_sha1"
        assert rows[5]["ioc_type"] == "hash_sha256"


# ---------------------------------------------------------------------------
# TestReadIocsByAge
# ---------------------------------------------------------------------------

class TestReadIocsByAge:
    """Tests for reading IOCs from master CSV by age."""

    def test_read_within_window(self, tmp_path):
        """Test that IOCs within the age window are returned."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [
            ["ip", "10.0.0.1", "85.00", "high", _recent_date(1), "", "aaa"],
            ["ip", "10.0.0.2", "50.00", "medium", _recent_date(5), "", "bbb"],
        ])

        results = read_iocs_by_age(str(master_csv), max_age_days=30)
        assert len(results) == 2
        values = {r.ioc.value for r in results}
        assert values == {"10.0.0.1", "10.0.0.2"}

    def test_read_excludes_old_iocs(self, tmp_path):
        """Test that IOCs older than max_age_days are excluded."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [
            ["ip", "10.0.0.1", "85.00", "high", _recent_date(5), "", "aaa"],
            ["ip", "10.0.0.2", "50.00", "medium", _old_date(60), "", "bbb"],
        ])

        results = read_iocs_by_age(str(master_csv), max_age_days=30)
        assert len(results) == 1
        assert results[0].ioc.value == "10.0.0.1"

    def test_read_empty_csv(self, tmp_path):
        """Test reading from CSV with only header."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [])

        results = read_iocs_by_age(str(master_csv))
        assert results == []

    def test_read_nonexistent_csv(self, tmp_path):
        """Test reading from nonexistent CSV returns empty list."""
        results = read_iocs_by_age(str(tmp_path / "nope.csv"))
        assert results == []

    def test_read_reconstructs_enrichment_result(self, tmp_path):
        """Test that EnrichmentResult is properly reconstructed from CSV."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [
            ["domain", "evil.com", "72.50", "high", _recent_date(1), "", "abc"],
        ])

        results = read_iocs_by_age(str(master_csv))
        assert len(results) == 1
        result = results[0]
        assert result.ioc.ioc_type == IOCType.DOMAIN
        assert result.ioc.value == "evil.com"
        assert result.confidence == 72.50
        assert result.scores == []


# ---------------------------------------------------------------------------
# TestUpdateCsvLastHunted
# ---------------------------------------------------------------------------

class TestUpdateCsvLastHunted:
    """Tests for updating last_hunted_date in master CSV."""

    def test_update_hunted_iocs(self, tmp_path):
        """Test that last_hunted_date is updated for hunted IOCs."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [
            ["ip", "10.0.0.1", "85.00", "high", _recent_date(1), "", "aaa"],
            ["ip", "10.0.0.2", "50.00", "medium", _recent_date(1), "", "bbb"],
        ])

        update_csv_last_hunted(str(master_csv), {"10.0.0.1"})

        rows = _read_master_csv(master_csv)
        assert rows[0]["last_hunted_date"] != ""
        assert rows[1]["last_hunted_date"] == ""

    def test_update_multiple_iocs(self, tmp_path):
        """Test updating multiple IOCs at once."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [
            ["ip", "10.0.0.1", "85.00", "high", _recent_date(1), "", "aaa"],
            ["ip", "10.0.0.2", "50.00", "medium", _recent_date(1), "", "bbb"],
            ["domain", "evil.com", "75.00", "high", _recent_date(1), "", "ccc"],
        ])

        update_csv_last_hunted(str(master_csv), {"10.0.0.1", "10.0.0.2"})

        rows = _read_master_csv(master_csv)
        assert rows[0]["last_hunted_date"] != ""
        assert rows[1]["last_hunted_date"] != ""
        assert rows[2]["last_hunted_date"] == ""

    def test_update_nonexistent_csv(self, tmp_path):
        """Test that updating a nonexistent CSV logs error but doesn't raise."""
        # Should not raise
        update_csv_last_hunted(str(tmp_path / "nope.csv"), {"10.0.0.1"})


# ---------------------------------------------------------------------------
# TestFilterByPublisherConfidence
# ---------------------------------------------------------------------------

class TestFilterByPublisherConfidence:
    """Tests for filtering by publisher confidence level."""

    def test_filter_high_only(self):
        """Test filtering for high confidence only."""
        results = [
            _make_result(IOCType.IP, "10.0.0.1", 15.0),
            _make_result(IOCType.IP, "10.0.0.2", 50.0),
            _make_result(IOCType.IP, "10.0.0.3", 85.0),
        ]

        filtered = filter_by_publisher_confidence(results, "high")
        assert len(filtered) == 1
        assert filtered[0].ioc.value == "10.0.0.3"

    def test_filter_medium_and_above(self):
        """Test filtering for medium and above."""
        results = [
            _make_result(IOCType.IP, "10.0.0.1", 15.0),
            _make_result(IOCType.IP, "10.0.0.2", 50.0),
            _make_result(IOCType.IP, "10.0.0.3", 85.0),
        ]

        filtered = filter_by_publisher_confidence(results, "medium")
        assert len(filtered) == 2
        values = {r.ioc.value for r in filtered}
        assert values == {"10.0.0.2", "10.0.0.3"}

    def test_filter_low_returns_all(self):
        """Test filtering for low returns everything."""
        results = [
            _make_result(IOCType.IP, "10.0.0.1", 15.0),
            _make_result(IOCType.IP, "10.0.0.2", 50.0),
            _make_result(IOCType.IP, "10.0.0.3", 85.0),
        ]

        filtered = filter_by_publisher_confidence(results, "low")
        assert len(filtered) == 3

    def test_filter_boundary_values(self):
        """Test filtering at exact boundary values."""
        results = [
            _make_result(IOCType.IP, "10.0.0.1", 29.9),
            _make_result(IOCType.IP, "10.0.0.2", 30.0),
            _make_result(IOCType.IP, "10.0.0.3", 69.9),
            _make_result(IOCType.IP, "10.0.0.4", 70.0),
        ]

        medium_up = filter_by_publisher_confidence(results, "medium")
        assert len(medium_up) == 3  # 30.0, 69.9, 70.0

        high_only = filter_by_publisher_confidence(results, "high")
        assert len(high_only) == 1  # 70.0

    def test_filter_empty_results(self):
        """Test filtering empty list."""
        filtered = filter_by_publisher_confidence([], "high")
        assert filtered == []


# ---------------------------------------------------------------------------
# TestValidateCommand
# ---------------------------------------------------------------------------

class TestValidateCommand:
    """Tests for validate command."""

    @pytest.mark.asyncio
    async def test_validate_success(self, tmp_path, valid_ioc_file):
        """Test successful validation."""
        args = argparse.Namespace(
            ioc_file=valid_ioc_file,
            threshold=70.0,
            override=False,
        )

        with patch("src.cli.load_config") as mock_config, \
             patch("src.cli.enrich_all") as mock_enrich, \
             patch("src.cli.format_report"), \
             patch("src.cli.write_report") as mock_write, \
             patch("src.cli.set_github_outputs") as mock_outputs:

            mock_config.return_value = MagicMock(enrichment_sources=["virustotal"])
            mock_enrich.return_value = []

            exit_code = await validate_command(args)

            assert exit_code == 0
            mock_enrich.assert_called_once()
            mock_write.assert_called_once()
            mock_outputs.assert_called_once()

    @pytest.mark.asyncio
    async def test_validate_file_not_found(self):
        """Test validation with non-existent file."""
        args = argparse.Namespace(
            ioc_file="/nonexistent/file.txt",
            threshold=70.0,
            override=False,
        )

        with patch("src.cli.load_config"):
            exit_code = await validate_command(args)
            assert exit_code == 2

    @pytest.mark.asyncio
    async def test_validate_with_malformed_iocs(self, tmp_path):
        """Test validation with malformed IOCs returns exit code 0 (outputs drive failure)."""
        ioc_file = tmp_path / "bad_iocs.txt"
        ioc_file.write_text("999.999.999.999\n")

        args = argparse.Namespace(
            ioc_file=str(ioc_file),
            threshold=70.0,
            override=False,
        )

        with patch("src.cli.load_config") as mock_config, \
             patch("src.cli.enrich_all") as mock_enrich, \
             patch("src.cli.format_report"), \
             patch("src.cli.write_report"), \
             patch("src.cli.set_github_outputs"):

            mock_config.return_value = MagicMock(enrichment_sources=["virustotal"])
            mock_enrich.return_value = []

            exit_code = await validate_command(args)
            # Returns 0; workflow uses outputs to fail the check
            assert exit_code == 0

    @pytest.mark.asyncio
    async def test_validate_no_enrichment_when_no_valid_iocs(self, tmp_path):
        """Test that enrichment is skipped when there are no valid IOCs."""
        ioc_file = tmp_path / "bad_iocs.txt"
        ioc_file.write_text("999.999.999.999\nnot-an-ioc\n")

        args = argparse.Namespace(
            ioc_file=str(ioc_file),
            threshold=70.0,
            override=False,
        )

        with patch("src.cli.load_config") as mock_config, \
             patch("src.cli.enrich_all") as mock_enrich, \
             patch("src.cli.format_report"), \
             patch("src.cli.write_report"), \
             patch("src.cli.set_github_outputs"):

            mock_config.return_value = MagicMock(enrichment_sources=["virustotal"])

            exit_code = await validate_command(args)
            mock_enrich.assert_not_called()
            assert exit_code == 0


# ---------------------------------------------------------------------------
# TestInventoryCommand
# ---------------------------------------------------------------------------

class TestInventoryCommand:
    """Tests for inventory command."""

    @pytest.mark.asyncio
    async def test_inventory_success(self, valid_ioc_file, tmp_path):
        """Test successful inventory adds IOCs to CSV."""
        master_csv = tmp_path / "master-indicators.csv"

        args = argparse.Namespace(
            ioc_file=valid_ioc_file,
            master_csv=str(master_csv),
        )

        result = _make_result(IOCType.IP, "192.168.1.1", 85.0)

        with patch("src.cli.load_config") as mock_config, \
             patch("src.cli.enrich_all") as mock_enrich:

            mock_config.return_value = MagicMock(enrichment_sources=["virustotal"])
            mock_enrich.return_value = [result]

            exit_code = await inventory_command(args)

            assert exit_code == 0
            assert master_csv.exists()

            rows = _read_master_csv(master_csv)
            assert len(rows) == 1
            assert rows[0]["ioc_value"] == "192.168.1.1"

    @pytest.mark.asyncio
    async def test_inventory_file_not_found(self):
        """Test inventory with non-existent file."""
        args = argparse.Namespace(
            ioc_file="/nonexistent/file.txt",
            master_csv="master.csv",
        )

        with patch("src.cli.load_config"):
            exit_code = await inventory_command(args)
            assert exit_code == 2

    @pytest.mark.asyncio
    async def test_inventory_skips_malformed(self, tmp_path):
        """Test inventory skips malformed IOCs but succeeds."""
        ioc_file = tmp_path / "bad.txt"
        ioc_file.write_text("999.999.999.999\n")

        args = argparse.Namespace(
            ioc_file=str(ioc_file),
            master_csv=str(tmp_path / "master.csv"),
        )

        with patch("src.cli.load_config") as mock_config:
            mock_config.return_value = MagicMock(enrichment_sources=["virustotal"])
            exit_code = await inventory_command(args)
            assert exit_code == 0

    @pytest.mark.asyncio
    async def test_inventory_processes_valid_and_skips_malformed(self, tmp_path):
        """Test inventory processes valid IOCs and skips malformed ones."""
        ioc_file = tmp_path / "mixed.txt"
        ioc_file.write_text("192.168.1.1\n999.999.999.999\n")
        master_csv = tmp_path / "master.csv"

        args = argparse.Namespace(
            ioc_file=str(ioc_file),
            master_csv=str(master_csv),
        )

        result = _make_result(IOCType.IP, "192.168.1.1", 85.0)

        with patch("src.cli.load_config") as mock_config, \
             patch("src.cli.enrich_all") as mock_enrich:

            mock_config.return_value = MagicMock(enrichment_sources=["virustotal"])
            mock_enrich.return_value = [result]

            exit_code = await inventory_command(args)

            assert exit_code == 0
            rows = _read_master_csv(master_csv)
            assert len(rows) == 1
            assert rows[0]["ioc_value"] == "192.168.1.1"

    @pytest.mark.asyncio
    async def test_inventory_empty_file(self, tmp_path):
        """Test inventory with empty file."""
        ioc_file = tmp_path / "empty.txt"
        ioc_file.write_text("")

        args = argparse.Namespace(
            ioc_file=str(ioc_file),
            master_csv=str(tmp_path / "master.csv"),
        )

        with patch("src.cli.load_config") as mock_config:
            mock_config.return_value = MagicMock(enrichment_sources=["virustotal"])
            exit_code = await inventory_command(args)
            assert exit_code == 0


# ---------------------------------------------------------------------------
# TestPublishCommand
# ---------------------------------------------------------------------------

class TestPublishCommand:
    """Tests for publish command (age-based IOC selection, hunting publishers)."""

    def _make_config(self, publishers=None, min_confidence=None):
        """Helper to build a mock config for publish tests."""
        mock_config = MagicMock()
        mock_config.publishers = publishers or ["splunk", "elastic"]
        mock_config.max_ioc_age_days = 30
        mock_config.publisher_min_confidence = {
            p: (min_confidence or "low") for p in (publishers or ["splunk", "elastic"])
        }
        return mock_config

    @pytest.mark.asyncio
    async def test_publish_success(self, tmp_path):
        """Test successful hunting from master CSV."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [
            ["ip", "10.0.0.1", "85.00", "high", _recent_date(1), "", "aaa"],
        ])

        args = argparse.Namespace(master_csv=str(master_csv))
        mock_config = self._make_config()

        mock_hunt_results = [
            HuntResult(
                ioc=IOC(IOCType.IP, "10.0.0.1", "10.0.0.1", 1),
                platform="splunk",
                hits_found=3,
            )
        ]

        mock_splunk_class = MagicMock()
        mock_splunk = AsyncMock()
        mock_splunk.hunt.return_value = mock_hunt_results
        mock_splunk_class.return_value = mock_splunk

        mock_elastic_class = MagicMock()
        mock_elastic = AsyncMock()
        mock_elastic.hunt.return_value = []
        mock_elastic_class.return_value = mock_elastic

        with patch("src.cli.load_config", return_value=mock_config), \
             patch.dict("src.cli.PUBLISHER_REGISTRY", {
                 "splunk": mock_splunk_class,
                 "elastic": mock_elastic_class,
             }):

            exit_code = await publish_command(args)

            assert exit_code == 0
            mock_splunk.hunt.assert_called_once()
            mock_elastic.hunt.assert_called_once()

    @pytest.mark.asyncio
    async def test_publish_file_not_found(self, tmp_path):
        """Test publish with nonexistent master CSV returns success (nothing to hunt)."""
        args = argparse.Namespace(master_csv=str(tmp_path / "nope.csv"))

        with patch("src.cli.load_config", return_value=self._make_config()):
            exit_code = await publish_command(args)
            assert exit_code == 0

    @pytest.mark.asyncio
    async def test_publish_rejects_old_iocs(self, tmp_path):
        """Test that IOCs older than max_age_days are not hunted."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [
            ["ip", "10.0.0.1", "85.00", "high", _old_date(60), "", "aaa"],
        ])

        args = argparse.Namespace(master_csv=str(master_csv))

        mock_splunk_class = MagicMock()
        mock_elastic_class = MagicMock()

        with patch("src.cli.load_config", return_value=self._make_config()), \
             patch.dict("src.cli.PUBLISHER_REGISTRY", {
                 "splunk": mock_splunk_class,
                 "elastic": mock_elastic_class,
             }):

            exit_code = await publish_command(args)

            # No IOCs in window — hunt is never called
            assert exit_code == 0
            mock_splunk_class.assert_not_called()
            mock_elastic_class.assert_not_called()

    @pytest.mark.asyncio
    async def test_publish_empty_file_returns_zero(self, tmp_path):
        """Test publish with empty CSV returns success."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [])

        args = argparse.Namespace(master_csv=str(master_csv))

        with patch("src.cli.load_config", return_value=self._make_config()):
            exit_code = await publish_command(args)
            assert exit_code == 0

    @pytest.mark.asyncio
    async def test_publish_filters_below_threshold(self, tmp_path):
        """Test that IOCs below publisher min confidence are filtered out."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [
            ["ip", "10.0.0.1", "85.00", "high", _recent_date(1), "", "aaa"],
            ["ip", "10.0.0.2", "15.00", "low", _recent_date(1), "", "bbb"],
        ])

        args = argparse.Namespace(master_csv=str(master_csv))
        mock_config = self._make_config(publishers=["splunk"], min_confidence="medium")

        mock_splunk_class = MagicMock()
        mock_splunk = AsyncMock()
        mock_splunk.hunt.return_value = []
        mock_splunk_class.return_value = mock_splunk

        with patch("src.cli.load_config", return_value=mock_config), \
             patch.dict("src.cli.PUBLISHER_REGISTRY", {"splunk": mock_splunk_class}):

            exit_code = await publish_command(args)

            assert exit_code == 0
            # Only the high confidence IOC should be hunted
            call_args = mock_splunk.hunt.call_args[0][0]
            assert len(call_args) == 1
            assert call_args[0].ioc.value == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_publish_appends_last_hunted_date(self, tmp_path):
        """Test that last_hunted_date is updated after successful hunt."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [
            ["ip", "10.0.0.1", "85.00", "high", _recent_date(1), "", "aaa"],
        ])

        args = argparse.Namespace(master_csv=str(master_csv))
        mock_config = self._make_config(publishers=["splunk"])
        mock_config.publisher_min_confidence = {"splunk": "low"}

        hunt_result = HuntResult(
            ioc=IOC(IOCType.IP, "10.0.0.1", "10.0.0.1", 1),
            platform="splunk",
            hits_found=1,
            success=True,
        )

        mock_splunk_class = MagicMock()
        mock_splunk = AsyncMock()
        mock_splunk.hunt.return_value = [hunt_result]
        mock_splunk_class.return_value = mock_splunk

        with patch("src.cli.load_config", return_value=mock_config), \
             patch.dict("src.cli.PUBLISHER_REGISTRY", {"splunk": mock_splunk_class}):

            exit_code = await publish_command(args)

            assert exit_code == 0
            rows = _read_master_csv(master_csv)
            assert rows[0]["last_hunted_date"] != ""

    @pytest.mark.asyncio
    async def test_publish_misp_failure_returns_exit_0(self, tmp_path):
        """Test that hunter failure is non-fatal (returns 0)."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [
            ["ip", "10.0.0.1", "85.00", "high", _recent_date(1), "", "aaa"],
        ])

        args = argparse.Namespace(master_csv=str(master_csv))
        mock_config = self._make_config(publishers=["splunk"])
        mock_config.publisher_min_confidence = {"splunk": "low"}

        mock_splunk_class = MagicMock()
        mock_splunk = AsyncMock()
        mock_splunk.hunt.side_effect = Exception("Splunk connection failed")
        mock_splunk_class.return_value = mock_splunk

        with patch("src.cli.load_config", return_value=mock_config), \
             patch.dict("src.cli.PUBLISHER_REGISTRY", {"splunk": mock_splunk_class}):

            exit_code = await publish_command(args)
            assert exit_code == 0

    @pytest.mark.asyncio
    async def test_publish_opencti_failure_returns_exit_0(self, tmp_path):
        """Test that Elastic hunter failure is non-fatal (returns 0)."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [
            ["ip", "10.0.0.1", "85.00", "high", _recent_date(1), "", "aaa"],
        ])

        args = argparse.Namespace(master_csv=str(master_csv))
        mock_config = self._make_config(publishers=["elastic"])
        mock_config.publisher_min_confidence = {"elastic": "low"}

        mock_elastic_class = MagicMock()
        mock_elastic = AsyncMock()
        mock_elastic.hunt.side_effect = Exception("Elastic connection failed")
        mock_elastic_class.return_value = mock_elastic

        with patch("src.cli.load_config", return_value=mock_config), \
             patch.dict("src.cli.PUBLISHER_REGISTRY", {"elastic": mock_elastic_class}):

            exit_code = await publish_command(args)
            assert exit_code == 0
