"""Tests for CLI commands."""

import argparse
import csv
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.cli import (
    append_to_master_inventory,
    build_validation_report,
    filter_by_publisher_confidence,
    inventory_command,
    publish_command,
    read_pending_iocs_from_csv,
    update_csv_deployment_status,
    validate_command,
)
from src.models import EnrichmentResult, IOC, IOCType, ValidationReport


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
            "status", "deployed_to", "added_date", "commit_sha",
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
        """Test creating new master inventory CSV with header and new columns."""
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
        assert row["status"] == "pending"
        assert row["deployed_to"] == "N/A"
        assert row["commit_sha"] == "abc123de"

    def test_append_confidence_levels(self, tmp_path):
        """Test that confidence levels are correctly assigned."""
        master_csv = tmp_path / "master-indicators.csv"

        results = [
            _make_result(IOCType.IP, "10.0.0.1", 15.0, 1),    # low
            _make_result(IOCType.IP, "10.0.0.2", 29.9, 2),    # low
            _make_result(IOCType.IP, "10.0.0.3", 30.0, 3),    # medium
            _make_result(IOCType.IP, "10.0.0.4", 69.9, 4),    # medium
            _make_result(IOCType.IP, "10.0.0.5", 70.0, 5),    # high
            _make_result(IOCType.IP, "10.0.0.6", 100.0, 6),   # high
        ]

        append_to_master_inventory(results, master_csv_path=str(master_csv))

        rows = _read_master_csv(master_csv)
        assert len(rows) == 6
        assert rows[0]["confidence_level"] == "low"
        assert rows[1]["confidence_level"] == "low"
        assert rows[2]["confidence_level"] == "medium"
        assert rows[3]["confidence_level"] == "medium"
        assert rows[4]["confidence_level"] == "high"
        assert rows[5]["confidence_level"] == "high"

    def test_append_all_have_pending_status(self, tmp_path):
        """Test that all appended IOCs have pending status and N/A deployed_to."""
        master_csv = tmp_path / "master-indicators.csv"

        results = [
            _make_result(IOCType.IP, "10.0.0.1", 85.0),
            _make_result(IOCType.DOMAIN, "evil.com", 45.0),
            _make_result(IOCType.URL, "http://bad.com", 10.0),
        ]

        append_to_master_inventory(results, master_csv_path=str(master_csv))

        rows = _read_master_csv(master_csv)
        for row in rows:
            assert row["status"] == "pending"
            assert row["deployed_to"] == "N/A"

    def test_append_to_existing_file(self, tmp_path):
        """Test appending to existing master inventory CSV."""
        master_csv = tmp_path / "master-indicators.csv"

        _write_master_csv(master_csv, [
            ["domain", "evil.com", "90.00", "high", "deployed", "MISP,OpenCTI", "2024-01-01 12:00:00", "old123"],
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
            ["ip", "192.168.1.1", "80.00", "high", "deployed", "MISP", "2024-01-01", "old123"],
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
# TestReadPendingIocsFromCsv
# ---------------------------------------------------------------------------

class TestReadPendingIocsFromCsv:
    """Tests for reading pending IOCs from master CSV."""

    def test_read_pending_only(self, tmp_path):
        """Test that only pending rows are returned."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [
            ["ip", "10.0.0.1", "85.00", "high", "deployed", "MISP", "2024-01-01", "aaa"],
            ["ip", "10.0.0.2", "50.00", "medium", "pending", "N/A", "2024-01-01", "bbb"],
            ["domain", "evil.com", "75.00", "high", "pending", "N/A", "2024-01-01", "ccc"],
        ])

        pending = read_pending_iocs_from_csv(str(master_csv))
        assert len(pending) == 2
        assert pending[0][0].ioc.value == "10.0.0.2"
        assert pending[1][0].ioc.value == "evil.com"

    def test_read_empty_csv(self, tmp_path):
        """Test reading from CSV with only header."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [])

        pending = read_pending_iocs_from_csv(str(master_csv))
        assert len(pending) == 0

    def test_read_nonexistent_csv(self, tmp_path):
        """Test reading from nonexistent CSV."""
        pending = read_pending_iocs_from_csv(str(tmp_path / "nope.csv"))
        assert len(pending) == 0

    def test_read_preserves_row_indices(self, tmp_path):
        """Test that row indices are correctly tracked."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [
            ["ip", "10.0.0.1", "85.00", "high", "deployed", "MISP", "2024-01-01", "aaa"],
            ["ip", "10.0.0.2", "50.00", "medium", "pending", "N/A", "2024-01-01", "bbb"],
            ["domain", "evil.com", "75.00", "high", "pending", "N/A", "2024-01-01", "ccc"],
        ])

        pending = read_pending_iocs_from_csv(str(master_csv))
        # Header is line 1, data starts at line 2
        # Row 1 (deployed) = line 2, Row 2 (pending) = line 3, Row 3 (pending) = line 4
        assert pending[0][1] == 3  # second data row
        assert pending[1][1] == 4  # third data row

    def test_read_reconstructs_enrichment_result(self, tmp_path):
        """Test that EnrichmentResult is properly reconstructed from CSV."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [
            ["domain", "evil.com", "72.50", "high", "pending", "N/A", "2024-01-01", "abc"],
        ])

        pending = read_pending_iocs_from_csv(str(master_csv))
        result, _ = pending[0]
        assert result.ioc.ioc_type == IOCType.DOMAIN
        assert result.ioc.value == "evil.com"
        assert result.confidence == 72.50
        assert result.scores == []


# ---------------------------------------------------------------------------
# TestUpdateCsvDeploymentStatus
# ---------------------------------------------------------------------------

class TestUpdateCsvDeploymentStatus:
    """Tests for updating deployment status in CSV."""

    def test_update_single_row(self, tmp_path):
        """Test updating a single row's deployment status."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [
            ["ip", "10.0.0.1", "85.00", "high", "pending", "N/A", "2024-01-01", "aaa"],
        ])

        update_csv_deployment_status(str(master_csv), {2: "MISP,OpenCTI"})

        rows = _read_master_csv(master_csv)
        assert rows[0]["deployed_to"] == "MISP,OpenCTI"
        assert rows[0]["status"] == "deployed"

    def test_update_multiple_rows(self, tmp_path):
        """Test updating multiple rows with different statuses."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [
            ["ip", "10.0.0.1", "85.00", "high", "pending", "N/A", "2024-01-01", "aaa"],
            ["ip", "10.0.0.2", "50.00", "medium", "pending", "N/A", "2024-01-01", "bbb"],
            ["ip", "10.0.0.3", "15.00", "low", "pending", "N/A", "2024-01-01", "ccc"],
        ])

        update_csv_deployment_status(str(master_csv), {
            2: "MISP,OpenCTI",
            3: "MISP",
            4: "N/A",
        })

        rows = _read_master_csv(master_csv)
        assert rows[0]["deployed_to"] == "MISP,OpenCTI"
        assert rows[0]["status"] == "deployed"
        assert rows[1]["deployed_to"] == "MISP"
        assert rows[1]["status"] == "deployed"
        assert rows[2]["deployed_to"] == "N/A"
        assert rows[2]["status"] == "pending"  # N/A keeps pending

    def test_update_preserves_other_rows(self, tmp_path):
        """Test that updating some rows doesn't affect others."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [
            ["ip", "10.0.0.1", "85.00", "high", "deployed", "MISP", "2024-01-01", "old"],
            ["ip", "10.0.0.2", "50.00", "medium", "pending", "N/A", "2024-01-01", "new"],
        ])

        update_csv_deployment_status(str(master_csv), {3: "MISP"})

        rows = _read_master_csv(master_csv)
        assert rows[0]["status"] == "deployed"  # unchanged
        assert rows[0]["deployed_to"] == "MISP"  # unchanged
        assert rows[1]["deployed_to"] == "MISP"  # updated
        assert rows[1]["status"] == "deployed"  # updated


# ---------------------------------------------------------------------------
# TestFilterByPublisherConfidence
# ---------------------------------------------------------------------------

class TestFilterByPublisherConfidence:
    """Tests for filtering by publisher confidence level."""

    def test_filter_high_only(self):
        """Test filtering for high confidence only."""
        results = [
            _make_result(IOCType.IP, "10.0.0.1", 15.0),   # low
            _make_result(IOCType.IP, "10.0.0.2", 50.0),   # medium
            _make_result(IOCType.IP, "10.0.0.3", 85.0),   # high
        ]

        filtered = filter_by_publisher_confidence(results, "high")
        assert len(filtered) == 1
        assert filtered[0].ioc.value == "10.0.0.3"

    def test_filter_medium_and_above(self):
        """Test filtering for medium and above."""
        results = [
            _make_result(IOCType.IP, "10.0.0.1", 15.0),   # low
            _make_result(IOCType.IP, "10.0.0.2", 50.0),   # medium
            _make_result(IOCType.IP, "10.0.0.3", 85.0),   # high
        ]

        filtered = filter_by_publisher_confidence(results, "medium")
        assert len(filtered) == 2
        values = {r.ioc.value for r in filtered}
        assert values == {"10.0.0.2", "10.0.0.3"}

    def test_filter_low_returns_all(self):
        """Test filtering for low returns everything."""
        results = [
            _make_result(IOCType.IP, "10.0.0.1", 15.0),   # low
            _make_result(IOCType.IP, "10.0.0.2", 50.0),   # medium
            _make_result(IOCType.IP, "10.0.0.3", 85.0),   # high
        ]

        filtered = filter_by_publisher_confidence(results, "low")
        assert len(filtered) == 3

    def test_filter_boundary_values(self):
        """Test filtering at exact boundary values."""
        results = [
            _make_result(IOCType.IP, "10.0.0.1", 29.9),   # low
            _make_result(IOCType.IP, "10.0.0.2", 30.0),   # medium
            _make_result(IOCType.IP, "10.0.0.3", 69.9),   # medium
            _make_result(IOCType.IP, "10.0.0.4", 70.0),   # high
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
        """Test successful validation with no malformed IOCs."""
        args = argparse.Namespace(
            ioc_file=valid_ioc_file,
            threshold=70.0,
            override=False,
        )

        with patch("src.cli.load_config") as mock_config, \
             patch("src.cli.enrich_all") as mock_enrich, \
             patch("src.cli.format_report") as mock_format, \
             patch("src.cli.write_report") as mock_write, \
             patch("src.cli.set_github_outputs") as mock_outputs:

            mock_config.return_value = MagicMock()
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
        """Test validation with malformed IOCs returns exit code 0."""
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

            mock_config.return_value = MagicMock()
            mock_enrich.return_value = []

            exit_code = await validate_command(args)
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

            mock_config.return_value = MagicMock()

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
        """Test successful inventory adds IOCs as pending."""
        master_csv = tmp_path / "master-indicators.csv"

        args = argparse.Namespace(
            ioc_file=valid_ioc_file,
            master_csv=str(master_csv),
        )

        result = _make_result(IOCType.IP, "192.168.1.1", 85.0)

        with patch("src.cli.load_config") as mock_config, \
             patch("src.cli.enrich_all") as mock_enrich:

            mock_config.return_value = MagicMock()
            mock_enrich.return_value = [result]

            exit_code = await inventory_command(args)

            assert exit_code == 0
            assert master_csv.exists()

            rows = _read_master_csv(master_csv)
            assert len(rows) == 1
            assert rows[0]["status"] == "pending"
            assert rows[0]["deployed_to"] == "N/A"

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
    async def test_inventory_rejects_malformed(self, tmp_path):
        """Test inventory rejects files with malformed IOCs."""
        ioc_file = tmp_path / "bad.txt"
        ioc_file.write_text("999.999.999.999\n")

        args = argparse.Namespace(
            ioc_file=str(ioc_file),
            master_csv=str(tmp_path / "master.csv"),
        )

        with patch("src.cli.load_config"):
            exit_code = await inventory_command(args)
            assert exit_code == 1

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
            mock_config.return_value = MagicMock()
            exit_code = await inventory_command(args)
            assert exit_code == 0


# ---------------------------------------------------------------------------
# TestPublishCommand
# ---------------------------------------------------------------------------

class TestPublishCommand:
    """Tests for publish command (reads from CSV, filters per publisher)."""

    @pytest.mark.asyncio
    async def test_publish_from_csv_success(self, tmp_path):
        """Test successful publishing from master CSV."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [
            ["ip", "10.0.0.1", "85.00", "high", "pending", "N/A", "2024-01-01", "aaa"],
        ])

        args = argparse.Namespace(master_csv=str(master_csv))

        mock_config = MagicMock()
        mock_config.misp_min_confidence_level = "medium"
        mock_config.opencti_min_confidence_level = "high"

        with patch("src.cli.load_config", return_value=mock_config), \
             patch("src.cli.MISPPublisher") as mock_misp_class, \
             patch("src.cli.OpenCTIPublisher") as mock_opencti_class:

            mock_misp = AsyncMock()
            mock_misp_class.return_value = mock_misp
            mock_opencti = AsyncMock()
            mock_opencti_class.return_value = mock_opencti

            exit_code = await publish_command(args)

            assert exit_code == 0
            mock_misp.publish.assert_called_once()
            mock_opencti.publish.assert_called_once()

            # CSV should be updated
            rows = _read_master_csv(master_csv)
            assert rows[0]["status"] == "deployed"
            assert rows[0]["deployed_to"] == "MISP,OpenCTI"

    @pytest.mark.asyncio
    async def test_publish_filters_by_publisher_level(self, tmp_path):
        """Test that each publisher gets only IOCs at its confidence level."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [
            ["ip", "10.0.0.1", "85.00", "high", "pending", "N/A", "2024-01-01", "aaa"],
            ["ip", "10.0.0.2", "50.00", "medium", "pending", "N/A", "2024-01-01", "bbb"],
            ["ip", "10.0.0.3", "15.00", "low", "pending", "N/A", "2024-01-01", "ccc"],
        ])

        args = argparse.Namespace(master_csv=str(master_csv))

        mock_config = MagicMock()
        mock_config.misp_min_confidence_level = "medium"
        mock_config.opencti_min_confidence_level = "high"

        with patch("src.cli.load_config", return_value=mock_config), \
             patch("src.cli.MISPPublisher") as mock_misp_class, \
             patch("src.cli.OpenCTIPublisher") as mock_opencti_class:

            mock_misp = AsyncMock()
            mock_misp_class.return_value = mock_misp
            mock_opencti = AsyncMock()
            mock_opencti_class.return_value = mock_opencti

            exit_code = await publish_command(args)
            assert exit_code == 0

            # MISP should get medium + high (2 IOCs)
            misp_published = mock_misp.publish.call_args[0][0]
            assert len(misp_published) == 2

            # OpenCTI should get high only (1 IOC)
            opencti_published = mock_opencti.publish.call_args[0][0]
            assert len(opencti_published) == 1
            assert opencti_published[0].ioc.value == "10.0.0.1"

            # CSV should reflect what was deployed where
            rows = _read_master_csv(master_csv)
            assert rows[0]["deployed_to"] == "MISP,OpenCTI"
            assert rows[0]["status"] == "deployed"
            assert rows[1]["deployed_to"] == "MISP"
            assert rows[1]["status"] == "deployed"
            assert rows[2]["deployed_to"] == "N/A"
            assert rows[2]["status"] == "pending"

    @pytest.mark.asyncio
    async def test_publish_no_pending_iocs(self, tmp_path):
        """Test publish when no pending IOCs exist."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [
            ["ip", "10.0.0.1", "85.00", "high", "deployed", "MISP", "2024-01-01", "aaa"],
        ])

        args = argparse.Namespace(master_csv=str(master_csv))

        mock_config = MagicMock()
        mock_config.misp_min_confidence_level = "medium"
        mock_config.opencti_min_confidence_level = "high"

        with patch("src.cli.load_config", return_value=mock_config):
            exit_code = await publish_command(args)
            assert exit_code == 0

    @pytest.mark.asyncio
    async def test_publish_misp_failure_returns_exit_3(self, tmp_path):
        """Test that MISP publishing failure returns exit code 3."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [
            ["ip", "10.0.0.1", "85.00", "high", "pending", "N/A", "2024-01-01", "aaa"],
        ])

        args = argparse.Namespace(master_csv=str(master_csv))

        mock_config = MagicMock()
        mock_config.misp_min_confidence_level = "medium"
        mock_config.opencti_min_confidence_level = "high"

        with patch("src.cli.load_config", return_value=mock_config), \
             patch("src.cli.MISPPublisher") as mock_misp_class:

            mock_misp = AsyncMock()
            mock_misp.publish.side_effect = Exception("MISP connection failed")
            mock_misp_class.return_value = mock_misp

            exit_code = await publish_command(args)
            assert exit_code == 3

    @pytest.mark.asyncio
    async def test_publish_opencti_failure_returns_exit_4(self, tmp_path):
        """Test that OpenCTI publishing failure returns exit code 4."""
        master_csv = tmp_path / "master.csv"
        _write_master_csv(master_csv, [
            ["ip", "10.0.0.1", "85.00", "high", "pending", "N/A", "2024-01-01", "aaa"],
        ])

        args = argparse.Namespace(master_csv=str(master_csv))

        mock_config = MagicMock()
        mock_config.misp_min_confidence_level = "medium"
        mock_config.opencti_min_confidence_level = "high"

        with patch("src.cli.load_config", return_value=mock_config), \
             patch("src.cli.MISPPublisher") as mock_misp_class, \
             patch("src.cli.OpenCTIPublisher") as mock_opencti_class:

            mock_misp = AsyncMock()
            mock_misp_class.return_value = mock_misp

            mock_opencti = AsyncMock()
            mock_opencti.publish.side_effect = Exception("OpenCTI connection failed")
            mock_opencti_class.return_value = mock_opencti

            exit_code = await publish_command(args)
            assert exit_code == 4

    @pytest.mark.asyncio
    async def test_publish_nonexistent_csv(self, tmp_path):
        """Test publish with nonexistent master CSV."""
        args = argparse.Namespace(master_csv=str(tmp_path / "nope.csv"))

        mock_config = MagicMock()
        mock_config.misp_min_confidence_level = "medium"
        mock_config.opencti_min_confidence_level = "high"

        with patch("src.cli.load_config", return_value=mock_config):
            exit_code = await publish_command(args)
            assert exit_code == 0  # No pending = success
