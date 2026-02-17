"""Tests for CLI commands."""

import argparse
import csv
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from src.cli import append_to_master_inventory, build_validation_report, publish_command, validate_command
from src.models import EnrichmentResult, IOC, IOCType, ValidationReport


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

        # Result should be marked as above threshold (74.8 >= 70.0)
        assert report.enrichment_results[0].above_threshold is True

    def test_build_validation_report_below_threshold(self):
        """Test building a report with below threshold results."""
        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        result = EnrichmentResult(ioc, [], confidence=45.0, above_threshold=False)

        report = build_validation_report(
            valid_iocs=[ioc],
            malformed_lines=[],
            duplicates_removed=0,
            enrichment_results=[result],
            threshold=70.0,
            override=False,
        )

        # Result should be marked as below threshold (45.0 < 70.0)
        assert report.enrichment_results[0].above_threshold is False


class TestAppendToMasterInventory:
    """Tests for appending to master inventory CSV."""

    def test_append_to_new_file(self, tmp_path, monkeypatch):
        """Test creating new master inventory CSV with header."""
        master_csv = tmp_path / "master-indicators.csv"
        monkeypatch.setenv("GITHUB_SHA", "abc123def456789")

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        result = EnrichmentResult(ioc, [], confidence=85.0, above_threshold=True)

        append_to_master_inventory([result], threshold=70.0, master_csv_path=str(master_csv))

        # File should exist
        assert master_csv.exists()

        # Read and verify contents
        with master_csv.open("r") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 1
        row = rows[0]
        assert row["ioc_type"] == "ip"
        assert row["ioc_value"] == "192.168.1.1"
        assert row["confidence_score"] == "85.00"
        assert row["deployed_to"] == "MISP,OpenCTI"  # Above threshold
        assert row["commit_sha"] == "abc123de"  # First 8 chars

    def test_append_below_threshold_marked_as_na(self, tmp_path):
        """Test that below threshold IOCs are marked as N/A in deployed_to."""
        master_csv = tmp_path / "master-indicators.csv"

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        result = EnrichmentResult(ioc, [], confidence=45.0, above_threshold=False)

        append_to_master_inventory([result], threshold=70.0, master_csv_path=str(master_csv))

        with master_csv.open("r") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert rows[0]["deployed_to"] == "N/A"  # Below threshold

    def test_append_to_existing_file(self, tmp_path):
        """Test appending to existing master inventory CSV."""
        master_csv = tmp_path / "master-indicators.csv"

        # Create existing CSV with one entry
        with master_csv.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["ioc_type", "ioc_value", "confidence_score", "deployed_to", "added_date", "commit_sha"])
            writer.writerow(["domain", "evil.com", "90.00", "MISP,OpenCTI", "2024-01-01 12:00:00", "old123"])

        # Append new IOC
        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        result = EnrichmentResult(ioc, [], confidence=85.0, above_threshold=True)

        append_to_master_inventory([result], threshold=70.0, master_csv_path=str(master_csv))

        # Read and verify
        with master_csv.open("r") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        # Should have 2 rows now
        assert len(rows) == 2
        assert rows[0]["ioc_value"] == "evil.com"  # Original
        assert rows[1]["ioc_value"] == "192.168.1.1"  # New

    def test_append_skips_duplicates(self, tmp_path):
        """Test that duplicate IOCs are not appended."""
        master_csv = tmp_path / "master-indicators.csv"

        # Create existing CSV with one IP
        with master_csv.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["ioc_type", "ioc_value", "confidence_score", "deployed_to", "added_date", "commit_sha"])
            writer.writerow(["ip", "192.168.1.1", "80.00", "MISP,OpenCTI", "2024-01-01 12:00:00", "old123"])

        # Try to append same IP
        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        result = EnrichmentResult(ioc, [], confidence=85.0, above_threshold=True)

        append_to_master_inventory([result], threshold=70.0, master_csv_path=str(master_csv))

        # Read and verify - should still be only 1 row
        with master_csv.open("r") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 1  # No duplicate added

    def test_append_multiple_iocs(self, tmp_path):
        """Test appending multiple IOCs at once."""
        master_csv = tmp_path / "master-indicators.csv"

        iocs_and_results = [
            (IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1), 85.0, True),
            (IOC(IOCType.DOMAIN, "evil.com", "evil.com", 2), 90.0, True),
            (IOC(IOCType.URL, "http://bad.com", "http://bad.com", 3), 45.0, False),
        ]

        results = [
            EnrichmentResult(ioc, [], confidence=conf, above_threshold=above)
            for ioc, conf, above in iocs_and_results
        ]

        append_to_master_inventory(results, threshold=70.0, master_csv_path=str(master_csv))

        with master_csv.open("r") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 3
        assert rows[0]["ioc_value"] == "192.168.1.1"
        assert rows[1]["ioc_value"] == "evil.com"
        assert rows[2]["ioc_value"] == "http://bad.com"
        assert rows[2]["deployed_to"] == "N/A"  # Below threshold

    def test_append_all_ioc_types(self, tmp_path):
        """Test that all IOC types are correctly recorded."""
        master_csv = tmp_path / "master-indicators.csv"

        iocs = [
            IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1),
            IOC(IOCType.DOMAIN, "evil.com", "evil.com", 2),
            IOC(IOCType.URL, "http://bad.com", "http://bad.com", 3),
            IOC(IOCType.HASH_MD5, "d41d8cd98f00b204e9800998ecf8427e", "...", 4),
            IOC(IOCType.HASH_SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709", "...", 5),
            IOC(IOCType.HASH_SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "...", 6),
        ]

        results = [EnrichmentResult(ioc, [], confidence=75.0, above_threshold=True) for ioc in iocs]

        append_to_master_inventory(results, threshold=70.0, master_csv_path=str(master_csv))

        with master_csv.open("r") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 6
        assert rows[0]["ioc_type"] == "ip"
        assert rows[1]["ioc_type"] == "domain"
        assert rows[2]["ioc_type"] == "url"
        assert rows[3]["ioc_type"] == "hash_md5"
        assert rows[4]["ioc_type"] == "hash_sha1"
        assert rows[5]["ioc_type"] == "hash_sha256"


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
            mock_enrich.return_value = []  # No enrichment results for simplicity

            exit_code = await validate_command(args)

            # Should succeed
            assert exit_code == 0

            # Should have called enrichment
            mock_enrich.assert_called_once()

            # Should have written report
            mock_write.assert_called_once()
            assert "/tmp/enrichment_report.md" in mock_write.call_args[0]

            # Should have set GitHub outputs
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

            # Should return exit code 2 for file not found
            assert exit_code == 2

    @pytest.mark.asyncio
    async def test_validate_with_malformed_iocs(self, tmp_path):
        """Test validation with malformed IOCs returns exit code 1."""
        # Create file with invalid IOC
        ioc_file = tmp_path / "bad_iocs.txt"
        ioc_file.write_text("999.999.999.999\n")

        args = argparse.Namespace(
            ioc_file=str(ioc_file),
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

            # Should fail with exit code 1 due to malformed IOCs
            assert exit_code == 1

    @pytest.mark.asyncio
    async def test_validate_no_enrichment_when_no_valid_iocs(self, tmp_path):
        """Test that enrichment is skipped when there are no valid IOCs."""
        # Create file with only malformed IOCs
        ioc_file = tmp_path / "bad_iocs.txt"
        ioc_file.write_text("999.999.999.999\nnot-an-ioc\n")

        args = argparse.Namespace(
            ioc_file=str(ioc_file),
            threshold=70.0,
            override=False,
        )

        with patch("src.cli.load_config") as mock_config, \
             patch("src.cli.enrich_all") as mock_enrich, \
             patch("src.cli.format_report") as mock_format, \
             patch("src.cli.write_report") as mock_write, \
             patch("src.cli.set_github_outputs") as mock_outputs:

            mock_config.return_value = MagicMock()

            exit_code = await validate_command(args)

            # Should NOT have called enrichment (no valid IOCs)
            mock_enrich.assert_not_called()

            # Should still fail due to malformed IOCs
            assert exit_code == 1


class TestPublishCommand:
    """Tests for publish command."""

    @pytest.mark.asyncio
    async def test_publish_success(self, valid_ioc_file, tmp_path):
        """Test successful publishing to MISP and OpenCTI."""
        master_csv = tmp_path / "master-indicators.csv"

        args = argparse.Namespace(
            ioc_file=valid_ioc_file,
            threshold=70.0,
            master_csv=str(master_csv),
        )

        # Create mock enrichment results above threshold
        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        result = EnrichmentResult(ioc, [], confidence=85.0, above_threshold=True)

        with patch("src.cli.load_config") as mock_config, \
             patch("src.cli.enrich_all") as mock_enrich, \
             patch("src.cli.MISPPublisher") as mock_misp_class, \
             patch("src.cli.OpenCTIPublisher") as mock_opencti_class:

            mock_config.return_value = MagicMock()
            mock_enrich.return_value = [result]

            # Mock publishers
            mock_misp = AsyncMock()
            mock_misp_class.return_value = mock_misp

            mock_opencti = AsyncMock()
            mock_opencti_class.return_value = mock_opencti

            exit_code = await publish_command(args)

            # Should succeed
            assert exit_code == 0

            # Should have published to both platforms
            mock_misp.publish.assert_called_once()
            mock_opencti.publish.assert_called_once()

            # Should have appended to master CSV
            assert master_csv.exists()

    @pytest.mark.asyncio
    async def test_publish_file_not_found(self, tmp_path):
        """Test publish with non-existent file."""
        args = argparse.Namespace(
            ioc_file="/nonexistent/file.txt",
            threshold=70.0,
            master_csv=str(tmp_path / "master.csv"),
        )

        with patch("src.cli.load_config"):
            exit_code = await publish_command(args)

            # Should return exit code 2 for file not found
            assert exit_code == 2

    @pytest.mark.asyncio
    async def test_publish_rejects_malformed_iocs(self, tmp_path):
        """Test publish rejects files with malformed IOCs."""
        # Create file with invalid IOC
        ioc_file = tmp_path / "bad_iocs.txt"
        ioc_file.write_text("999.999.999.999\n")

        args = argparse.Namespace(
            ioc_file=str(ioc_file),
            threshold=70.0,
            master_csv=str(tmp_path / "master.csv"),
        )

        with patch("src.cli.load_config"):
            exit_code = await publish_command(args)

            # Should fail with exit code 1 due to malformed IOCs
            assert exit_code == 1

    @pytest.mark.asyncio
    async def test_publish_empty_file_returns_zero(self, tmp_path):
        """Test publish with empty file returns success."""
        ioc_file = tmp_path / "empty.txt"
        ioc_file.write_text("")

        args = argparse.Namespace(
            ioc_file=str(ioc_file),
            threshold=70.0,
            master_csv=str(tmp_path / "master.csv"),
        )

        with patch("src.cli.load_config") as mock_config:
            mock_config.return_value = MagicMock()

            exit_code = await publish_command(args)

            # No IOCs to publish, but should still succeed
            assert exit_code == 0

    @pytest.mark.asyncio
    async def test_publish_filters_below_threshold(self, valid_ioc_file, tmp_path):
        """Test that publish only publishes IOCs above threshold."""
        master_csv = tmp_path / "master-indicators.csv"

        args = argparse.Namespace(
            ioc_file=valid_ioc_file,
            threshold=70.0,
            master_csv=str(master_csv),
        )

        # Create results both above and below threshold
        ioc1 = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        ioc2 = IOC(IOCType.DOMAIN, "evil.com", "evil.com", 2)
        result1 = EnrichmentResult(ioc1, [], confidence=85.0, above_threshold=True)  # Above
        result2 = EnrichmentResult(ioc2, [], confidence=45.0, above_threshold=False)  # Below

        with patch("src.cli.load_config") as mock_config, \
             patch("src.cli.enrich_all") as mock_enrich, \
             patch("src.cli.MISPPublisher") as mock_misp_class, \
             patch("src.cli.OpenCTIPublisher") as mock_opencti_class:

            mock_config.return_value = MagicMock()
            mock_enrich.return_value = [result1, result2]

            mock_misp = AsyncMock()
            mock_misp_class.return_value = mock_misp

            mock_opencti = AsyncMock()
            mock_opencti_class.return_value = mock_opencti

            exit_code = await publish_command(args)

            # Should succeed
            assert exit_code == 0

            # Should only publish the one above threshold
            published_results = mock_misp.publish.call_args[0][0]
            assert len(published_results) == 1
            assert published_results[0].confidence == 85.0

    @pytest.mark.asyncio
    async def test_publish_appends_all_results_to_master(self, valid_ioc_file, tmp_path):
        """Test that ALL results (passed and failed) are appended to master CSV."""
        master_csv = tmp_path / "master-indicators.csv"

        args = argparse.Namespace(
            ioc_file=valid_ioc_file,
            threshold=70.0,
            master_csv=str(master_csv),
        )

        # Create results both above and below threshold
        ioc1 = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        ioc2 = IOC(IOCType.DOMAIN, "evil.com", "evil.com", 2)
        result1 = EnrichmentResult(ioc1, [], confidence=85.0, above_threshold=True)
        result2 = EnrichmentResult(ioc2, [], confidence=45.0, above_threshold=False)

        with patch("src.cli.load_config") as mock_config, \
             patch("src.cli.enrich_all") as mock_enrich, \
             patch("src.cli.MISPPublisher") as mock_misp_class, \
             patch("src.cli.OpenCTIPublisher") as mock_opencti_class:

            mock_config.return_value = MagicMock()
            mock_enrich.return_value = [result1, result2]

            mock_misp = AsyncMock()
            mock_misp_class.return_value = mock_misp
            mock_opencti = AsyncMock()
            mock_opencti_class.return_value = mock_opencti

            await publish_command(args)

            # Master CSV should have BOTH results
            with master_csv.open("r") as f:
                reader = csv.DictReader(f)
                rows = list(reader)

            assert len(rows) == 2
            assert rows[0]["deployed_to"] == "MISP,OpenCTI"  # Above threshold
            assert rows[1]["deployed_to"] == "N/A"  # Below threshold

    @pytest.mark.asyncio
    async def test_publish_no_iocs_above_threshold(self, valid_ioc_file, tmp_path):
        """Test publish when no IOCs pass threshold still records them."""
        master_csv = tmp_path / "master-indicators.csv"

        args = argparse.Namespace(
            ioc_file=valid_ioc_file,
            threshold=70.0,
            master_csv=str(master_csv),
        )

        # All results below threshold
        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        result = EnrichmentResult(ioc, [], confidence=45.0, above_threshold=False)

        with patch("src.cli.load_config") as mock_config, \
             patch("src.cli.enrich_all") as mock_enrich, \
             patch("src.cli.MISPPublisher") as mock_misp_class, \
             patch("src.cli.OpenCTIPublisher") as mock_opencti_class:

            mock_config.return_value = MagicMock()
            mock_enrich.return_value = [result]

            mock_misp = AsyncMock()
            mock_misp_class.return_value = mock_misp
            mock_opencti = AsyncMock()
            mock_opencti_class.return_value = mock_opencti

            exit_code = await publish_command(args)

            # Should still succeed (we recorded it)
            assert exit_code == 0

            # Should NOT have published to platforms
            mock_misp.publish.assert_not_called()
            mock_opencti.publish.assert_not_called()

            # Should have appended to master CSV
            assert master_csv.exists()
            with master_csv.open("r") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            assert len(rows) == 1
            assert rows[0]["deployed_to"] == "N/A"

    @pytest.mark.asyncio
    async def test_publish_misp_failure_returns_exit_3(self, valid_ioc_file, tmp_path):
        """Test that MISP publishing failure returns exit code 3."""
        master_csv = tmp_path / "master-indicators.csv"

        args = argparse.Namespace(
            ioc_file=valid_ioc_file,
            threshold=70.0,
            master_csv=str(master_csv),
        )

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        result = EnrichmentResult(ioc, [], confidence=85.0, above_threshold=True)

        with patch("src.cli.load_config") as mock_config, \
             patch("src.cli.enrich_all") as mock_enrich, \
             patch("src.cli.MISPPublisher") as mock_misp_class:

            mock_config.return_value = MagicMock()
            mock_enrich.return_value = [result]

            # MISP publisher raises exception
            mock_misp = AsyncMock()
            mock_misp.publish.side_effect = Exception("MISP connection failed")
            mock_misp_class.return_value = mock_misp

            exit_code = await publish_command(args)

            # Should return exit code 3 for MISP failure
            assert exit_code == 3

    @pytest.mark.asyncio
    async def test_publish_opencti_failure_returns_exit_4(self, valid_ioc_file, tmp_path):
        """Test that OpenCTI publishing failure returns exit code 4."""
        master_csv = tmp_path / "master-indicators.csv"

        args = argparse.Namespace(
            ioc_file=valid_ioc_file,
            threshold=70.0,
            master_csv=str(master_csv),
        )

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        result = EnrichmentResult(ioc, [], confidence=85.0, above_threshold=True)

        with patch("src.cli.load_config") as mock_config, \
             patch("src.cli.enrich_all") as mock_enrich, \
             patch("src.cli.MISPPublisher") as mock_misp_class, \
             patch("src.cli.OpenCTIPublisher") as mock_opencti_class:

            mock_config.return_value = MagicMock()
            mock_enrich.return_value = [result]

            # MISP succeeds
            mock_misp = AsyncMock()
            mock_misp_class.return_value = mock_misp

            # OpenCTI fails
            mock_opencti = AsyncMock()
            mock_opencti.publish.side_effect = Exception("OpenCTI connection failed")
            mock_opencti_class.return_value = mock_opencti

            exit_code = await publish_command(args)

            # Should return exit code 4 for OpenCTI failure
            assert exit_code == 4
