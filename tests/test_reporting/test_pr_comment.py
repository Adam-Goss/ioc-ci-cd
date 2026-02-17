"""Tests for PR comment formatter."""

import os

import pytest

from src.models import EnrichmentResult, IOC, IOCType, SourceScore, ValidationReport
from src.reporting.pr_comment import format_report, set_github_outputs, write_report


class TestFormatReport:
    """Tests for PR comment Markdown formatting."""

    def test_format_empty_report(self):
        """Test formatting a report with no IOCs."""
        report = ValidationReport(
            valid_iocs=[],
            malformed_lines=[],
            duplicates_removed=0,
            enrichment_results=[],
            threshold=70.0,
            override=False,
        )

        markdown = format_report(report)

        assert "## IOC Enrichment Report" in markdown
        assert "Analyzed**: 0" in markdown
        assert "Passed**: 0" in markdown

    def test_format_malformed_iocs(self):
        """Test formatting a report with malformed IOCs."""
        report = ValidationReport(
            valid_iocs=[],
            malformed_lines=[
                (5, "999.999.999.999", "Invalid IP address"),
                (7, "bad hash", "Unrecognized IOC type"),
            ],
            duplicates_removed=0,
            enrichment_results=[],
            threshold=70.0,
            override=False,
        )

        markdown = format_report(report)

        assert "⚠️ Malformed IOCs" in markdown
        assert "999.999.999.999" in markdown
        assert "Invalid IP address" in markdown
        assert "bad hash" in markdown

    def test_format_below_threshold(self, mock_enrichment_result):
        """Test formatting IOCs below threshold."""
        # Mark as below threshold
        mock_enrichment_result.confidence = 45.0
        mock_enrichment_result.above_threshold = False

        report = ValidationReport(
            valid_iocs=[mock_enrichment_result.ioc],
            malformed_lines=[],
            duplicates_removed=0,
            enrichment_results=[mock_enrichment_result],
            threshold=70.0,
            override=False,
        )

        markdown = format_report(report)

        assert "⚠️ Below Threshold" in markdown
        assert "45.0" in markdown  # Confidence score
        assert ":warning:" in markdown

    def test_format_passed_validation(self, mock_enrichment_result):
        """Test formatting IOCs that passed validation."""
        report = ValidationReport(
            valid_iocs=[mock_enrichment_result.ioc],
            malformed_lines=[],
            duplicates_removed=0,
            enrichment_results=[mock_enrichment_result],
            threshold=70.0,
            override=False,
        )

        markdown = format_report(report)

        assert "✅ Passed Validation" in markdown
        assert "<details>" in markdown  # Collapsible section
        assert "192.168.1.1" in markdown
        assert "74.8" in markdown  # Confidence

    def test_format_source_availability(self, mock_enrichment_result):
        """Test formatting source availability table."""
        report = ValidationReport(
            valid_iocs=[mock_enrichment_result.ioc],
            malformed_lines=[],
            duplicates_removed=0,
            enrichment_results=[mock_enrichment_result],
            threshold=70.0,
            override=False,
        )

        markdown = format_report(report)

        assert "📊 Source Availability" in markdown
        assert "Virustotal" in markdown
        assert "Abuseipdb" in markdown
        assert "Otx" in markdown

    def test_format_with_duplicates(self, mock_enrichment_result):
        """Test formatting report with duplicates removed."""
        report = ValidationReport(
            valid_iocs=[mock_enrichment_result.ioc],
            malformed_lines=[],
            duplicates_removed=3,
            enrichment_results=[mock_enrichment_result],
            threshold=70.0,
            override=False,
        )

        markdown = format_report(report)

        assert "Duplicates removed**: 3" in markdown

    def test_format_with_override(self, mock_enrichment_result):
        """Test formatting report with override enabled."""
        report = ValidationReport(
            valid_iocs=[mock_enrichment_result.ioc],
            malformed_lines=[],
            duplicates_removed=0,
            enrichment_results=[mock_enrichment_result],
            threshold=70.0,
            override=True,
        )

        markdown = format_report(report)

        assert "Override**: Yes" in markdown

    def test_format_escapes_pipe_characters(self):
        """Test that pipe characters in IOC values are escaped."""
        ioc = IOC(
            ioc_type=IOCType.DOMAIN,
            value="test|pipe.com",
            raw_line="test|pipe.com",
            line_number=1,
        )

        report = ValidationReport(
            valid_iocs=[],
            malformed_lines=[(1, "test|pipe", "error with | pipe")],
            duplicates_removed=0,
            enrichment_results=[],
            threshold=70.0,
            override=False,
        )

        markdown = format_report(report)

        # Pipes should be escaped in table
        assert "\\|" in markdown


class TestWriteReport:
    """Tests for writing report to file."""

    def test_write_report(self, tmp_path):
        """Test writing report to file."""
        markdown = "# Test Report\nContent here"
        output_path = tmp_path / "report.md"

        write_report(markdown, str(output_path))

        assert output_path.exists()
        assert output_path.read_text() == markdown

    def test_write_report_creates_directory(self, tmp_path):
        """Test that write_report creates parent directories."""
        output_path = tmp_path / "subdir" / "report.md"

        write_report("test content", str(output_path))

        assert output_path.exists()


class TestSetGitHubOutputs:
    """Tests for setting GitHub Actions outputs."""

    def test_set_github_outputs_with_file(self, tmp_path, monkeypatch):
        """Test setting outputs when GITHUB_OUTPUT is set."""
        output_file = tmp_path / "github_output.txt"
        monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

        ioc = IOC(
            ioc_type=IOCType.IP,
            value="192.168.1.1",
            raw_line="192.168.1.1",
            line_number=1,
        )

        report = ValidationReport(
            valid_iocs=[ioc],
            malformed_lines=[(5, "bad ioc", "error")],
            duplicates_removed=0,
            enrichment_results=[],
            threshold=70.0,
            override=False,
        )

        set_github_outputs(report)

        content = output_file.read_text()
        assert "has_malformed=true" in content
        assert "report_path=/tmp/enrichment_report.md" in content

    def test_set_github_outputs_no_env(self, monkeypatch):
        """Test that set_github_outputs handles missing GITHUB_OUTPUT gracefully."""
        # Remove GITHUB_OUTPUT env var if it exists
        monkeypatch.delenv("GITHUB_OUTPUT", raising=False)

        report = ValidationReport(
            valid_iocs=[],
            malformed_lines=[],
            duplicates_removed=0,
            enrichment_results=[],
            threshold=70.0,
            override=False,
        )

        # Should not raise exception
        set_github_outputs(report)

    def test_set_github_outputs_below_threshold(self, tmp_path, monkeypatch):
        """Test outputs when IOCs are below threshold."""
        output_file = tmp_path / "github_output.txt"
        monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

        ioc = IOC(
            ioc_type=IOCType.IP,
            value="192.168.1.1",
            raw_line="192.168.1.1",
            line_number=1,
        )

        result = EnrichmentResult(
            ioc=ioc,
            scores=[],
            confidence=45.0,
            above_threshold=False,
        )

        report = ValidationReport(
            valid_iocs=[ioc],
            malformed_lines=[],
            duplicates_removed=0,
            enrichment_results=[result],
            threshold=70.0,
            override=False,
        )

        set_github_outputs(report)

        content = output_file.read_text()
        assert "has_below_threshold=true" in content
