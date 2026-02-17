"""Pytest configuration and shared fixtures."""

import json
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir():
    """Return the fixtures directory path."""
    return FIXTURES_DIR


@pytest.fixture
def valid_ioc_file(tmp_path):
    """Create a temporary file with valid IOCs of all types."""
    content = """# Test IOCs - All valid types
# IPv4
192.168.1.1
10.0.0.1

# Domains
evil.example.com
malware-c2.net

# URLs
http://malware.site/payload.exe
https://phishing-site.com/login

# MD5 hashes
d41d8cd98f00b204e9800998ecf8427e
5d41402abc4b2a76b9719d911017c592

# SHA1 hashes
da39a3ee5e6b4b0d3255bfef95601890afd80709
356a192b7913b04c54574d18c28d46e6395428ab

# SHA256 hashes
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3
"""
    f = tmp_path / "valid_iocs.txt"
    f.write_text(content)
    return str(f)


@pytest.fixture
def invalid_ioc_file(tmp_path):
    """Create a temporary file with malformed IOCs."""
    content = """# Malformed IOCs
999.999.999.999
not-a-domain
invalid hash
abc123
http://
just some text
"""
    f = tmp_path / "invalid_iocs.txt"
    f.write_text(content)
    return str(f)


@pytest.fixture
def mixed_ioc_file(tmp_path):
    """Create a temporary file with mixed valid/invalid IOCs and duplicates."""
    content = """# Mixed IOCs with comments and duplicates
192.168.1.1
evil.example.com

# Duplicate (should be removed)
192.168.1.1

# Malformed
999.999.999.999

# Valid URL
http://malware.site/test.exe

# Case-insensitive duplicate (should be removed)
EVIL.EXAMPLE.COM

# Valid hash
d41d8cd98f00b204e9800998ecf8427e

# Empty lines above are ignored
"""
    f = tmp_path / "mixed_iocs.txt"
    f.write_text(content)
    return str(f)


@pytest.fixture
def vt_ip_response():
    """Mock VirusTotal response for IP lookup."""
    return {
        "data": {
            "id": "192.168.1.1",
            "type": "ip_address",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 10,
                    "suspicious": 2,
                    "undetected": 50,
                    "harmless": 8,
                },
                "reputation": -50,
                "tags": ["malware", "c2"],
            },
        }
    }


@pytest.fixture
def vt_domain_response():
    """Mock VirusTotal response for domain lookup."""
    return {
        "data": {
            "id": "evil.example.com",
            "type": "domain",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 45,
                    "suspicious": 3,
                    "undetected": 20,
                    "harmless": 2,
                },
                "reputation": -75,
                "tags": ["phishing", "malware"],
            },
        }
    }


@pytest.fixture
def abuseipdb_response():
    """Mock AbuseIPDB response."""
    return {
        "data": {
            "ipAddress": "192.168.1.1",
            "abuseConfidenceScore": 87,
            "totalReports": 1432,
            "numDistinctUsers": 89,
            "countryCode": "CN",
            "isp": "China Telecom",
            "usageType": "Data Center/Web Hosting/Transit",
            "isTor": False,
            "isWhitelisted": False,
        }
    }


@pytest.fixture
def otx_ip_response():
    """Mock OTX response for IP lookup."""
    return {
        "general": {"reputation": -2},
        "pulse_info": {
            "pulses": [
                {"name": "APT29 Infrastructure"},
                {"name": "Known C2 Servers"},
                {"name": "Botnet IPs"},
            ]
        },
        "malware": {"data": [{"hash": "abc123"}, {"hash": "def456"}]},
    }


@pytest.fixture
def mock_enrichment_result():
    """Mock enrichment result for testing."""
    from src.models import EnrichmentResult, IOC, IOCType, SourceScore

    ioc = IOC(
        ioc_type=IOCType.IP,
        value="192.168.1.1",
        raw_line="192.168.1.1",
        line_number=1,
    )

    scores = [
        SourceScore(source_name="virustotal", raw_score=75.5, available=True),
        SourceScore(source_name="abuseipdb", raw_score=87.0, available=True),
        SourceScore(source_name="otx", raw_score=65.2, available=True),
    ]

    return EnrichmentResult(
        ioc=ioc,
        scores=scores,
        confidence=74.8,
        above_threshold=True,
        tags=["malware", "c2"],
    )
