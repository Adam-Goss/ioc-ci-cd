"""Tests for MISP publisher."""

import os
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from src.config import PipelineConfig
from src.models import EnrichmentResult, IOC, IOCType, SourceScore
from src.publishers.misp import MISP_TYPE_MAP, MISPPublisher


class TestMISPTypeMapping:
    """Tests for IOC type to MISP attribute type mapping."""

    def test_all_ioc_types_mapped(self):
        """Test that all IOC types have MISP mappings."""
        # Every IOCType should have a mapping
        for ioc_type in IOCType:
            assert ioc_type in MISP_TYPE_MAP

    def test_misp_type_values(self):
        """Test that MISP type mappings are correct."""
        assert MISP_TYPE_MAP[IOCType.IP] == "ip-dst"
        assert MISP_TYPE_MAP[IOCType.DOMAIN] == "domain"
        assert MISP_TYPE_MAP[IOCType.HASH_MD5] == "md5"
        assert MISP_TYPE_MAP[IOCType.HASH_SHA1] == "sha1"
        assert MISP_TYPE_MAP[IOCType.HASH_SHA256] == "sha256"
        assert MISP_TYPE_MAP[IOCType.URL] == "url"


class TestMISPPublisherInit:
    """Tests for MISPPublisher initialization."""

    def test_init_with_valid_config(self):
        """Test initialization with valid MISP credentials."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            misp_url="https://misp.example.com",
            misp_api_key="test-api-key-12345",
        )

        with patch("src.publishers.misp.PyMISP") as mock_pymisp:
            publisher = MISPPublisher(config)

            # Should have created PyMISP client
            mock_pymisp.assert_called_once_with(
                url="https://misp.example.com",
                key="test-api-key-12345",
                ssl=True,  # Default
            )
            assert publisher.config == config

    def test_init_with_ssl_disabled(self):
        """Test initialization with SSL verification disabled."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            misp_url="https://misp.example.com",
            misp_api_key="test-api-key",
            misp_verify_ssl=False,
        )

        with patch("src.publishers.misp.PyMISP") as mock_pymisp:
            MISPPublisher(config)

            mock_pymisp.assert_called_once_with(
                url="https://misp.example.com", key="test-api-key", ssl=False
            )

    def test_init_missing_url(self):
        """Test that initialization fails without MISP_URL."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            misp_url=None,  # Missing
            misp_api_key="test-key",
        )

        with pytest.raises(ValueError, match="MISP_URL and MISP_API_KEY must be set"):
            MISPPublisher(config)

    def test_init_missing_api_key(self):
        """Test that initialization fails without MISP_API_KEY."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            misp_url="https://misp.example.com",
            misp_api_key=None,  # Missing
        )

        with pytest.raises(ValueError, match="MISP_URL and MISP_API_KEY must be set"):
            MISPPublisher(config)


class TestMISPPublish:
    """Tests for MISP publishing logic."""

    @pytest.mark.asyncio
    async def test_publish_empty_results(self):
        """Test publishing with no results does nothing."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            misp_url="https://misp.example.com", misp_api_key="test-key"
        )

        with patch("src.publishers.misp.PyMISP"):
            publisher = MISPPublisher(config)
            # Should not raise exception
            await publisher.publish([])

    @pytest.mark.asyncio
    async def test_publish_creates_event_with_correct_metadata(self, monkeypatch):
        """Test that MISP event is created with correct info and metadata."""
        monkeypatch.setenv("GITHUB_SHA", "abc123def456789")

        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            misp_url="https://misp.example.com",
            misp_api_key="test-key",
            misp_distribution=2,
            misp_threat_level=3,
        )

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        result = EnrichmentResult(ioc, [], 75.0, True)

        with patch("src.publishers.misp.PyMISP") as mock_pymisp_class:
            mock_misp = MagicMock()
            mock_pymisp_class.return_value = mock_misp

            # Mock successful event creation
            mock_event = MagicMock()
            mock_event.id = "event-123"
            mock_misp.add_event.return_value = mock_event

            publisher = MISPPublisher(config)
            await publisher.publish([result])

            # Verify add_event was called
            assert mock_misp.add_event.called

            # Get the event that was passed to add_event
            call_args = mock_misp.add_event.call_args
            event = call_args[0][0]

            # Event should have correct metadata
            assert "IOC Pipeline Import" in event.info
            assert "abc123de" in event.info  # First 8 chars of SHA
            assert event.distribution == 2
            assert event.threat_level_id == 3
            assert event.analysis == 2  # Completed

    @pytest.mark.asyncio
    async def test_publish_adds_tlp_tag(self):
        """Test that TLP:AMBER tag is added to event."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            misp_url="https://misp.example.com", misp_api_key="test-key"
        )

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        result = EnrichmentResult(ioc, [], 75.0, True)

        with patch("src.publishers.misp.PyMISP") as mock_pymisp_class, \
             patch("src.publishers.misp.MISPEvent") as mock_event_class:
            mock_misp = MagicMock()
            mock_pymisp_class.return_value = mock_misp

            # Mock the event instance
            mock_event_instance = MagicMock()
            mock_event_instance.id = "event-123"
            mock_event_class.return_value = mock_event_instance
            mock_misp.add_event.return_value = mock_event_instance

            publisher = MISPPublisher(config)
            await publisher.publish([result])

            # Should have called add_tag with tlp:amber
            mock_event_instance.add_tag.assert_called()
            tags_added = [call[0][0] for call in mock_event_instance.add_tag.call_args_list]
            assert "tlp:amber" in tags_added

    @pytest.mark.asyncio
    async def test_publish_adds_attributes_with_correct_types(self):
        """Test that IOCs are added as attributes with correct MISP types."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            misp_url="https://misp.example.com", misp_api_key="test-key"
        )

        # Create multiple IOCs of different types
        iocs_and_types = [
            (IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1), "ip-dst"),
            (IOC(IOCType.DOMAIN, "evil.com", "evil.com", 2), "domain"),
            (IOC(IOCType.URL, "http://evil.com/bad", "http://evil.com/bad", 3), "url"),
            (IOC(IOCType.HASH_MD5, "d41d8cd98f00b204e9800998ecf8427e", "...", 4), "md5"),
        ]

        results = [EnrichmentResult(ioc, [], 75.0, True) for ioc, _ in iocs_and_types]

        with patch("src.publishers.misp.PyMISP") as mock_pymisp_class, \
             patch("src.publishers.misp.MISPEvent") as mock_event_class:
            mock_misp = MagicMock()
            mock_pymisp_class.return_value = mock_misp

            mock_event_instance = MagicMock()
            mock_event_instance.id = "event-123"
            mock_event_class.return_value = mock_event_instance
            mock_misp.add_event.return_value = mock_event_instance

            publisher = MISPPublisher(config)
            await publisher.publish(results)

            # Should have called add_attribute for each IOC
            assert mock_event_instance.add_attribute.call_count == 4

            # Check each attribute call
            for idx, (ioc, expected_type) in enumerate(iocs_and_types):
                attr_call = mock_event_instance.add_attribute.call_args_list[idx]
                kwargs = attr_call[1]

                assert kwargs["type"] == expected_type
                assert kwargs["value"] == ioc.value
                assert kwargs["to_ids"] is True
                assert "Confidence" in kwargs["comment"]

    @pytest.mark.asyncio
    async def test_publish_adds_confidence_tags(self):
        """Test that confidence tags are added to attributes."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            misp_url="https://misp.example.com", misp_api_key="test-key"
        )

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        result = EnrichmentResult(ioc, [], 87.5, True)

        with patch("src.publishers.misp.PyMISP") as mock_pymisp_class, \
             patch("src.publishers.misp.MISPEvent") as mock_event_class:
            mock_misp = MagicMock()
            mock_pymisp_class.return_value = mock_misp

            # Mock the event and attribute
            mock_event_instance = MagicMock()
            mock_event_instance.id = "event-123"
            mock_event_class.return_value = mock_event_instance
            mock_misp.add_event.return_value = mock_event_instance

            mock_attr = MagicMock()
            mock_event_instance.add_attribute.return_value = mock_attr

            publisher = MISPPublisher(config)
            await publisher.publish([result])

            # Confidence tag should be added (87.5 → 87)
            tags_added = [call[0][0] for call in mock_attr.add_tag.call_args_list]
            assert "confidence:87" in tags_added

    @pytest.mark.asyncio
    async def test_publish_adds_enrichment_tags(self):
        """Test that enrichment tags are added to attributes."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            misp_url="https://misp.example.com", misp_api_key="test-key"
        )

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        result = EnrichmentResult(ioc, [], 75.0, True, tags=["malware", "c2", "botnet"])

        with patch("src.publishers.misp.PyMISP") as mock_pymisp_class, \
             patch("src.publishers.misp.MISPEvent") as mock_event_class:
            mock_misp = MagicMock()
            mock_pymisp_class.return_value = mock_misp

            mock_event_instance = MagicMock()
            mock_event_instance.id = "event-123"
            mock_event_class.return_value = mock_event_instance
            mock_misp.add_event.return_value = mock_event_instance

            mock_attr = MagicMock()
            mock_event_instance.add_attribute.return_value = mock_attr

            publisher = MISPPublisher(config)
            await publisher.publish([result])

            # All enrichment tags should be added
            tags_added = [call[0][0] for call in mock_attr.add_tag.call_args_list]
            assert "malware" in tags_added
            assert "c2" in tags_added
            assert "botnet" in tags_added

    @pytest.mark.asyncio
    async def test_publish_limits_tags_to_five(self):
        """Test that only top 5 enrichment tags are added."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            misp_url="https://misp.example.com", misp_api_key="test-key"
        )

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        result = EnrichmentResult(
            ioc, [], 75.0, True, tags=["tag1", "tag2", "tag3", "tag4", "tag5", "tag6", "tag7"]
        )

        with patch("src.publishers.misp.PyMISP") as mock_pymisp_class, \
             patch("src.publishers.misp.MISPEvent") as mock_event_class:
            mock_misp = MagicMock()
            mock_pymisp_class.return_value = mock_misp

            mock_event_instance = MagicMock()
            mock_event_instance.id = "event-123"
            mock_event_class.return_value = mock_event_instance
            mock_misp.add_event.return_value = mock_event_instance

            mock_attr = MagicMock()
            mock_event_instance.add_attribute.return_value = mock_attr

            publisher = MISPPublisher(config)
            await publisher.publish([result])

            # Only 5 enrichment tags + 1 confidence tag = 6 total
            assert mock_attr.add_tag.call_count == 6

    @pytest.mark.asyncio
    async def test_publish_includes_score_summary_in_comment(self):
        """Test that attribute comments include source score summary."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            misp_url="https://misp.example.com", misp_api_key="test-key"
        )

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        scores = [
            SourceScore("virustotal", 80.0, available=True),
            SourceScore("abuseipdb", 90.0, available=True),
            SourceScore("otx", 0.0, available=False),  # Should be excluded
        ]
        result = EnrichmentResult(ioc, scores, 85.0, True)

        with patch("src.publishers.misp.PyMISP") as mock_pymisp_class, \
             patch("src.publishers.misp.MISPEvent") as mock_event_class:
            mock_misp = MagicMock()
            mock_pymisp_class.return_value = mock_misp

            mock_event_instance = MagicMock()
            mock_event_instance.id = "event-123"
            mock_event_class.return_value = mock_event_instance
            mock_misp.add_event.return_value = mock_event_instance

            publisher = MISPPublisher(config)
            await publisher.publish([result])

            # Get attribute comment
            attr_call = mock_event_instance.add_attribute.call_args
            comment = attr_call[1]["comment"]

            # Should contain confidence and available scores
            assert "85.0" in comment
            assert "virustotal=80.0" in comment
            assert "abuseipdb=90.0" in comment
            assert "otx" not in comment  # Unavailable, should be excluded

    @pytest.mark.asyncio
    async def test_publish_auto_publish_enabled(self):
        """Test that event is published when auto-publish is enabled."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            misp_url="https://misp.example.com",
            misp_api_key="test-key",
            misp_auto_publish=True,
        )

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        result = EnrichmentResult(ioc, [], 75.0, True)

        with patch("src.publishers.misp.PyMISP") as mock_pymisp_class:
            mock_misp = MagicMock()
            mock_pymisp_class.return_value = mock_misp

            mock_event = MagicMock()
            mock_event.id = "event-123"
            mock_misp.add_event.return_value = mock_event

            publisher = MISPPublisher(config)
            await publisher.publish([result])

            # Should have called publish
            mock_misp.publish.assert_called_once_with(mock_event)

    @pytest.mark.asyncio
    async def test_publish_auto_publish_disabled(self):
        """Test that event is NOT published when auto-publish is disabled."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            misp_url="https://misp.example.com",
            misp_api_key="test-key",
            misp_auto_publish=False,  # Disabled
        )

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        result = EnrichmentResult(ioc, [], 75.0, True)

        with patch("src.publishers.misp.PyMISP") as mock_pymisp_class:
            mock_misp = MagicMock()
            mock_pymisp_class.return_value = mock_misp

            mock_event = MagicMock()
            mock_event.id = "event-123"
            mock_misp.add_event.return_value = mock_event

            publisher = MISPPublisher(config)
            await publisher.publish([result])

            # Should NOT have called publish
            mock_misp.publish.assert_not_called()

    @pytest.mark.asyncio
    async def test_publish_retry_on_failure(self):
        """Test retry logic with exponential backoff."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            misp_url="https://misp.example.com", misp_api_key="test-key"
        )

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        result = EnrichmentResult(ioc, [], 75.0, True)

        with patch("src.publishers.misp.PyMISP") as mock_pymisp_class:
            mock_misp = MagicMock()
            mock_pymisp_class.return_value = mock_misp

            # Fail twice, succeed on third attempt
            mock_event = MagicMock()
            mock_event.id = "event-123"
            mock_misp.add_event.side_effect = [
                Exception("Connection error"),
                Exception("Timeout"),
                mock_event,  # Success on 3rd attempt
            ]

            publisher = MISPPublisher(config)

            with patch("time.sleep"):  # Skip actual sleeping in tests
                await publisher.publish([result])

            # Should have called add_event 3 times
            assert mock_misp.add_event.call_count == 3

    @pytest.mark.asyncio
    async def test_publish_raises_after_max_retries(self):
        """Test that exception is raised after max retries exhausted."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            misp_url="https://misp.example.com", misp_api_key="test-key"
        )

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        result = EnrichmentResult(ioc, [], 75.0, True)

        with patch("src.publishers.misp.PyMISP") as mock_pymisp_class:
            mock_misp = MagicMock()
            mock_pymisp_class.return_value = mock_misp

            # Fail all 3 attempts
            mock_misp.add_event.side_effect = Exception("Persistent error")

            publisher = MISPPublisher(config)

            with patch("time.sleep"):
                with pytest.raises(Exception, match="Persistent error"):
                    await publisher.publish([result])

            # Should have attempted 3 times
            assert mock_misp.add_event.call_count == 3

    @pytest.mark.asyncio
    async def test_publish_handles_api_error_response(self):
        """Test handling of MISP API error responses."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            misp_url="https://misp.example.com", misp_api_key="test-key"
        )

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        result = EnrichmentResult(ioc, [], 75.0, True)

        with patch("src.publishers.misp.PyMISP") as mock_pymisp_class:
            mock_misp = MagicMock()
            mock_pymisp_class.return_value = mock_misp

            # Return error dict instead of exception
            mock_misp.add_event.return_value = {"errors": ["Invalid attribute"]}

            publisher = MISPPublisher(config)

            with patch("time.sleep"):
                with pytest.raises(Exception, match="MISP API error"):
                    await publisher.publish([result])
