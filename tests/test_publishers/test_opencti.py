"""Tests for OpenCTI publisher."""

from unittest.mock import MagicMock, patch

import pytest

from src.config import PipelineConfig
from src.models import EnrichmentResult, IOC, IOCType, SourceScore
from src.publishers.opencti import OPENCTI_OBSERVABLE_MAP, OpenCTIPublisher


class TestOpenCTIObservableMapping:
    """Tests for IOC type to OpenCTI observable type mapping."""

    def test_all_ioc_types_mapped(self):
        """Test that all IOC types have OpenCTI mappings."""
        for ioc_type in IOCType:
            assert ioc_type in OPENCTI_OBSERVABLE_MAP

    def test_observable_type_values(self):
        """Test that OpenCTI type mappings are correct."""
        assert OPENCTI_OBSERVABLE_MAP[IOCType.IP]["type"] == "IPv4-Addr"
        assert OPENCTI_OBSERVABLE_MAP[IOCType.DOMAIN]["type"] == "Domain-Name"
        assert OPENCTI_OBSERVABLE_MAP[IOCType.URL]["type"] == "Url"
        assert OPENCTI_OBSERVABLE_MAP[IOCType.HASH_MD5]["type"] == "StixFile"
        assert OPENCTI_OBSERVABLE_MAP[IOCType.HASH_SHA1]["type"] == "StixFile"
        assert OPENCTI_OBSERVABLE_MAP[IOCType.HASH_SHA256]["type"] == "StixFile"

    def test_hash_type_mappings(self):
        """Test that hash types have correct hash_type field."""
        assert OPENCTI_OBSERVABLE_MAP[IOCType.HASH_MD5]["hash_type"] == "MD5"
        assert OPENCTI_OBSERVABLE_MAP[IOCType.HASH_SHA1]["hash_type"] == "SHA-1"
        assert OPENCTI_OBSERVABLE_MAP[IOCType.HASH_SHA256]["hash_type"] == "SHA-256"

    def test_value_key_mappings(self):
        """Test that non-hash types have value_key field."""
        assert OPENCTI_OBSERVABLE_MAP[IOCType.IP]["value_key"] == "value"
        assert OPENCTI_OBSERVABLE_MAP[IOCType.DOMAIN]["value_key"] == "value"
        assert OPENCTI_OBSERVABLE_MAP[IOCType.URL]["value_key"] == "value"


class TestOpenCTIPublisherInit:
    """Tests for OpenCTIPublisher initialization."""

    def test_init_with_valid_config(self):
        """Test initialization with valid OpenCTI credentials."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            opencti_url="https://opencti.example.com",
            opencti_token="test-token-12345",
        )

        with patch("src.publishers.opencti.OpenCTIApiClient") as mock_client_class:
            publisher = OpenCTIPublisher(config)

            # Should have created OpenCTI client
            mock_client_class.assert_called_once_with(
                url="https://opencti.example.com", token="test-token-12345"
            )
            assert publisher.config == config

    def test_init_missing_url(self):
        """Test that initialization fails without OPENCTI_URL."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            opencti_url=None,  # Missing
            opencti_token="test-token",
        )

        with pytest.raises(ValueError, match="OPENCTI_URL and OPENCTI_TOKEN must be set"):
            OpenCTIPublisher(config)

    def test_init_missing_token(self):
        """Test that initialization fails without OPENCTI_TOKEN."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            opencti_url="https://opencti.example.com",
            opencti_token=None,  # Missing
        )

        with pytest.raises(ValueError, match="OPENCTI_URL and OPENCTI_TOKEN must be set"):
            OpenCTIPublisher(config)


class TestOpenCTIPublish:
    """Tests for OpenCTI publishing logic."""

    @pytest.mark.asyncio
    async def test_publish_empty_results(self):
        """Test publishing with no results does nothing."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            opencti_url="https://opencti.example.com", opencti_token="test-token"
        )

        with patch("src.publishers.opencti.OpenCTIApiClient"):
            publisher = OpenCTIPublisher(config)
            # Should not raise exception
            await publisher.publish([])

    @pytest.mark.asyncio
    async def test_publish_ip_observable(self):
        """Test creating an IP address observable."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            opencti_url="https://opencti.example.com", opencti_token="test-token"
        )

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        scores = [SourceScore("virustotal", 80.0, available=True)]
        result = EnrichmentResult(ioc, scores, 80.0, True)

        with patch("src.publishers.opencti.OpenCTIApiClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client

            # Mock observable creation
            mock_client.stix_cyber_observable.create.return_value = {"id": "obs-123"}

            publisher = OpenCTIPublisher(config)
            await publisher.publish([result])

            # Verify observable was created with correct data
            call_kwargs = mock_client.stix_cyber_observable.create.call_args[1]
            observable_data = call_kwargs["observableData"]

            assert observable_data["type"] == "IPv4-Addr"
            assert observable_data["value"] == "192.168.1.1"
            assert call_kwargs["x_opencti_score"] == 80
            assert "Confidence: 80.0" in call_kwargs["x_opencti_description"]

    @pytest.mark.asyncio
    async def test_publish_domain_observable(self):
        """Test creating a domain observable."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            opencti_url="https://opencti.example.com", opencti_token="test-token"
        )

        ioc = IOC(IOCType.DOMAIN, "evil.example.com", "evil.example.com", 1)
        result = EnrichmentResult(ioc, [], 75.0, True)

        with patch("src.publishers.opencti.OpenCTIApiClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client

            mock_client.stix_cyber_observable.create.return_value = {"id": "obs-123"}

            publisher = OpenCTIPublisher(config)
            await publisher.publish([result])

            call_kwargs = mock_client.stix_cyber_observable.create.call_args[1]
            observable_data = call_kwargs["observableData"]

            assert observable_data["type"] == "Domain-Name"
            assert observable_data["value"] == "evil.example.com"

    @pytest.mark.asyncio
    async def test_publish_url_observable(self):
        """Test creating a URL observable."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            opencti_url="https://opencti.example.com", opencti_token="test-token"
        )

        ioc = IOC(IOCType.URL, "http://evil.com/malware.exe", "http://evil.com/malware.exe", 1)
        result = EnrichmentResult(ioc, [], 75.0, True)

        with patch("src.publishers.opencti.OpenCTIApiClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client

            mock_client.stix_cyber_observable.create.return_value = {"id": "obs-123"}

            publisher = OpenCTIPublisher(config)
            await publisher.publish([result])

            call_kwargs = mock_client.stix_cyber_observable.create.call_args[1]
            observable_data = call_kwargs["observableData"]

            assert observable_data["type"] == "Url"
            assert observable_data["value"] == "http://evil.com/malware.exe"

    @pytest.mark.asyncio
    async def test_publish_md5_hash_observable(self):
        """Test creating an MD5 hash observable."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            opencti_url="https://opencti.example.com", opencti_token="test-token"
        )

        ioc = IOC(IOCType.HASH_MD5, "d41d8cd98f00b204e9800998ecf8427e", "...", 1)
        result = EnrichmentResult(ioc, [], 75.0, True)

        with patch("src.publishers.opencti.OpenCTIApiClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client

            mock_client.stix_cyber_observable.create.return_value = {"id": "obs-123"}

            publisher = OpenCTIPublisher(config)
            await publisher.publish([result])

            call_kwargs = mock_client.stix_cyber_observable.create.call_args[1]
            observable_data = call_kwargs["observableData"]

            assert observable_data["type"] == "StixFile"
            assert observable_data["hashes"]["MD5"] == "d41d8cd98f00b204e9800998ecf8427e"

    @pytest.mark.asyncio
    async def test_publish_sha1_hash_observable(self):
        """Test creating a SHA-1 hash observable."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            opencti_url="https://opencti.example.com", opencti_token="test-token"
        )

        ioc = IOC(IOCType.HASH_SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709", "...", 1)
        result = EnrichmentResult(ioc, [], 75.0, True)

        with patch("src.publishers.opencti.OpenCTIApiClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client

            mock_client.stix_cyber_observable.create.return_value = {"id": "obs-123"}

            publisher = OpenCTIPublisher(config)
            await publisher.publish([result])

            call_kwargs = mock_client.stix_cyber_observable.create.call_args[1]
            observable_data = call_kwargs["observableData"]

            assert observable_data["type"] == "StixFile"
            assert observable_data["hashes"]["SHA-1"] == "da39a3ee5e6b4b0d3255bfef95601890afd80709"

    @pytest.mark.asyncio
    async def test_publish_sha256_hash_observable(self):
        """Test creating a SHA-256 hash observable."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            opencti_url="https://opencti.example.com", opencti_token="test-token"
        )

        hash_val = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ioc = IOC(IOCType.HASH_SHA256, hash_val, "...", 1)
        result = EnrichmentResult(ioc, [], 75.0, True)

        with patch("src.publishers.opencti.OpenCTIApiClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client

            mock_client.stix_cyber_observable.create.return_value = {"id": "obs-123"}

            publisher = OpenCTIPublisher(config)
            await publisher.publish([result])

            call_kwargs = mock_client.stix_cyber_observable.create.call_args[1]
            observable_data = call_kwargs["observableData"]

            assert observable_data["type"] == "StixFile"
            assert observable_data["hashes"]["SHA-256"] == hash_val

    @pytest.mark.asyncio
    async def test_publish_includes_score_in_description(self):
        """Test that observable description includes confidence and source scores."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            opencti_url="https://opencti.example.com", opencti_token="test-token"
        )

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        scores = [
            SourceScore("virustotal", 80.0, available=True),
            SourceScore("abuseipdb", 90.0, available=True),
            SourceScore("otx", 0.0, available=False),  # Should be excluded
        ]
        result = EnrichmentResult(ioc, scores, 85.0, True)

        with patch("src.publishers.opencti.OpenCTIApiClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client

            mock_client.stix_cyber_observable.create.return_value = {"id": "obs-123"}

            publisher = OpenCTIPublisher(config)
            await publisher.publish([result])

            call_kwargs = mock_client.stix_cyber_observable.create.call_args[1]
            description = call_kwargs["x_opencti_description"]

            assert "85.0" in description
            assert "virustotal=80.0" in description
            assert "abuseipdb=90.0" in description
            assert "otx" not in description  # Unavailable

    @pytest.mark.asyncio
    async def test_publish_promotes_to_indicator(self):
        """Test that observable is promoted to indicator."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            opencti_url="https://opencti.example.com", opencti_token="test-token"
        )

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        result = EnrichmentResult(ioc, [], 75.0, True)

        with patch("src.publishers.opencti.OpenCTIApiClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client

            mock_client.stix_cyber_observable.create.return_value = {"id": "obs-123"}

            publisher = OpenCTIPublisher(config)
            await publisher.publish([result])

            # Should have called promote_to_indicator
            mock_client.stix_cyber_observable.promote_to_indicator.assert_called_once_with(
                id="obs-123"
            )

    @pytest.mark.asyncio
    async def test_publish_adds_labels_from_tags(self):
        """Test that labels are added from enrichment tags."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            opencti_url="https://opencti.example.com", opencti_token="test-token"
        )

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        result = EnrichmentResult(ioc, [], 75.0, True, tags=["malware", "c2", "botnet"])

        with patch("src.publishers.opencti.OpenCTIApiClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client

            mock_client.stix_cyber_observable.create.return_value = {"id": "obs-123"}

            publisher = OpenCTIPublisher(config)
            await publisher.publish([result])

            # Should have called add_label for each tag
            assert mock_client.stix_cyber_observable.add_label.call_count == 3

            # Check all labels were added
            calls = mock_client.stix_cyber_observable.add_label.call_args_list
            labels_added = [call[1]["label_name"] for call in calls]
            assert "malware" in labels_added
            assert "c2" in labels_added
            assert "botnet" in labels_added

    @pytest.mark.asyncio
    async def test_publish_limits_labels_to_five(self):
        """Test that only top 5 enrichment tags are added as labels."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            opencti_url="https://opencti.example.com", opencti_token="test-token"
        )

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        result = EnrichmentResult(
            ioc, [], 75.0, True, tags=["tag1", "tag2", "tag3", "tag4", "tag5", "tag6", "tag7"]
        )

        with patch("src.publishers.opencti.OpenCTIApiClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client

            mock_client.stix_cyber_observable.create.return_value = {"id": "obs-123"}

            publisher = OpenCTIPublisher(config)
            await publisher.publish([result])

            # Should only add 5 labels
            assert mock_client.stix_cyber_observable.add_label.call_count == 5

    @pytest.mark.asyncio
    async def test_publish_continues_on_single_ioc_failure(self):
        """Test that failure on one IOC doesn't stop processing of others."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            opencti_url="https://opencti.example.com", opencti_token="test-token"
        )

        ioc1 = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        ioc2 = IOC(IOCType.DOMAIN, "evil.com", "evil.com", 2)
        ioc3 = IOC(IOCType.URL, "http://bad.com", "http://bad.com", 3)

        results = [
            EnrichmentResult(ioc1, [], 75.0, True),
            EnrichmentResult(ioc2, [], 80.0, True),
            EnrichmentResult(ioc3, [], 85.0, True),
        ]

        with patch("src.publishers.opencti.OpenCTIApiClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client

            # Fail on second IOC, succeed on others
            mock_client.stix_cyber_observable.create.side_effect = [
                {"id": "obs-1"},
                Exception("Network error"),  # Failure
                {"id": "obs-3"},
            ]

            publisher = OpenCTIPublisher(config)
            await publisher.publish(results)

            # Should have attempted all 3
            assert mock_client.stix_cyber_observable.create.call_count == 3

            # Should have promoted the successful ones (1 and 3)
            assert mock_client.stix_cyber_observable.promote_to_indicator.call_count == 2

    @pytest.mark.asyncio
    async def test_publish_promotion_failure_is_non_fatal(self):
        """Test that promotion failure doesn't fail the entire operation."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            opencti_url="https://opencti.example.com", opencti_token="test-token"
        )

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        result = EnrichmentResult(ioc, [], 75.0, True)

        with patch("src.publishers.opencti.OpenCTIApiClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client

            mock_client.stix_cyber_observable.create.return_value = {"id": "obs-123"}
            mock_client.stix_cyber_observable.promote_to_indicator.side_effect = Exception(
                "Promotion failed"
            )

            publisher = OpenCTIPublisher(config)

            # Should not raise exception
            await publisher.publish([result])

            # Observable was created
            assert mock_client.stix_cyber_observable.create.called

    @pytest.mark.asyncio
    async def test_publish_label_failure_is_non_fatal(self):
        """Test that label addition failure doesn't fail the entire operation."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            opencti_url="https://opencti.example.com", opencti_token="test-token"
        )

        ioc = IOC(IOCType.IP, "192.168.1.1", "192.168.1.1", 1)
        result = EnrichmentResult(ioc, [], 75.0, True, tags=["malware", "c2"])

        with patch("src.publishers.opencti.OpenCTIApiClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client

            mock_client.stix_cyber_observable.create.return_value = {"id": "obs-123"}
            mock_client.stix_cyber_observable.add_label.side_effect = Exception("Label failed")

            publisher = OpenCTIPublisher(config)

            # Should not raise exception
            await publisher.publish([result])

            # Observable was created and promoted
            assert mock_client.stix_cyber_observable.create.called
            assert mock_client.stix_cyber_observable.promote_to_indicator.called

    @pytest.mark.asyncio
    async def test_publish_multiple_iocs_success_count(self):
        """Test that success/failure counts are correctly tracked."""
        config = PipelineConfig(
            vt_api_key="test-vt",
            abuseipdb_api_key="test-abuse",
            otx_api_key="test-otx",
            opencti_url="https://opencti.example.com", opencti_token="test-token"
        )

        results = [
            EnrichmentResult(IOC(IOCType.IP, f"192.168.1.{i}", f"192.168.1.{i}", i), [], 75.0, True)
            for i in range(1, 6)
        ]

        with patch("src.publishers.opencti.OpenCTIApiClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client

            # Succeed on 3, fail on 2
            mock_client.stix_cyber_observable.create.side_effect = [
                {"id": "obs-1"},
                {"id": "obs-2"},
                Exception("Error"),  # Fail
                {"id": "obs-4"},
                Exception("Error"),  # Fail
            ]

            publisher = OpenCTIPublisher(config)
            await publisher.publish(results)

            # All 5 should have been attempted
            assert mock_client.stix_cyber_observable.create.call_count == 5

            # Only 3 successful promotions
            assert mock_client.stix_cyber_observable.promote_to_indicator.call_count == 3
