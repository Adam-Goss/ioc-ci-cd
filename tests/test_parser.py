"""Tests for IOC parser."""

import pytest

from src.models import IOCType
from src.parser import detect_ioc_type, parse_ioc_file


class TestDetectIOCType:
    """Tests for IOC type auto-detection."""

    def test_detect_ipv4(self):
        """Test IPv4 detection."""
        ioc_type, hash_algo = detect_ioc_type("192.168.1.1")
        assert ioc_type == IOCType.IP
        assert hash_algo is None

    def test_detect_domain(self):
        """Test domain detection."""
        ioc_type, hash_algo = detect_ioc_type("evil.example.com")
        assert ioc_type == IOCType.DOMAIN
        assert hash_algo is None

    def test_detect_url(self):
        """Test URL detection (takes precedence over domain)."""
        ioc_type, hash_algo = detect_ioc_type("http://malware.site/payload.exe")
        assert ioc_type == IOCType.URL
        assert hash_algo is None

        ioc_type, hash_algo = detect_ioc_type("https://phishing.com/login")
        assert ioc_type == IOCType.URL
        assert hash_algo is None

    def test_detect_md5(self):
        """Test MD5 hash detection."""
        ioc_type, hash_algo = detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e")
        assert ioc_type == IOCType.HASH_MD5
        assert hash_algo is not None

    def test_detect_sha1(self):
        """Test SHA1 hash detection."""
        ioc_type, hash_algo = detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        assert ioc_type == IOCType.HASH_SHA1
        assert hash_algo is not None

    def test_detect_sha256(self):
        """Test SHA256 hash detection."""
        hash_val = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ioc_type, hash_algo = detect_ioc_type(hash_val)
        assert ioc_type == IOCType.HASH_SHA256
        assert hash_algo is not None

    def test_invalid_ip(self):
        """Test invalid IP addresses."""
        assert detect_ioc_type("999.999.999.999") is None
        assert detect_ioc_type("256.1.1.1") is None

    def test_invalid_hash_length(self):
        """Test hash with wrong length."""
        assert detect_ioc_type("abc123") is None  # Too short
        assert detect_ioc_type("z" * 32) is None  # Not hex

    def test_invalid_url(self):
        """Test invalid URL."""
        assert detect_ioc_type("http://") is None
        assert detect_ioc_type("not-a-url") is None

    def test_case_insensitive_hash(self):
        """Test that hash detection works with uppercase."""
        # Uppercase MD5
        ioc_type, _ = detect_ioc_type("D41D8CD98F00B204E9800998ECF8427E")
        assert ioc_type == IOCType.HASH_MD5


class TestParseIOCFile:
    """Tests for IOC file parsing."""

    def test_parse_valid_iocs(self, valid_ioc_file):
        """Test parsing file with all valid IOC types."""
        valid_iocs, malformed, dupes = parse_ioc_file(valid_ioc_file)

        assert len(valid_iocs) == 12  # 2 IPs + 2 domains + 2 URLs + 2 MD5 + 2 SHA1 + 2 SHA256
        assert len(malformed) == 0
        assert dupes == 0

        # Verify each type is present
        types_found = {ioc.ioc_type for ioc in valid_iocs}
        assert IOCType.IP in types_found
        assert IOCType.DOMAIN in types_found
        assert IOCType.URL in types_found
        assert IOCType.HASH_MD5 in types_found
        assert IOCType.HASH_SHA1 in types_found
        assert IOCType.HASH_SHA256 in types_found

    def test_parse_invalid_iocs(self, invalid_ioc_file):
        """Test parsing file with malformed IOCs."""
        valid_iocs, malformed, dupes = parse_ioc_file(invalid_ioc_file)

        assert len(valid_iocs) == 0
        assert len(malformed) > 0  # All lines are malformed
        assert dupes == 0

        # Check that malformed lines have error messages
        for line_num, raw_line, error in malformed:
            assert line_num > 0
            assert len(raw_line) > 0
            assert "Unrecognized IOC type" in error

    def test_parse_mixed_iocs(self, mixed_ioc_file):
        """Test parsing file with mix of valid/invalid IOCs and duplicates."""
        valid_iocs, malformed, dupes = parse_ioc_file(mixed_ioc_file)

        # Should have valid IOCs
        assert len(valid_iocs) > 0

        # Should have malformed IOCs
        assert len(malformed) > 0

        # Should have detected duplicates (case-insensitive)
        assert dupes > 0

    def test_deduplication_case_insensitive(self, tmp_path):
        """Test that deduplication is case-insensitive."""
        content = """evil.example.com
EVIL.EXAMPLE.COM
Evil.Example.Com
"""
        f = tmp_path / "dupes.txt"
        f.write_text(content)

        valid_iocs, malformed, dupes = parse_ioc_file(str(f))

        assert len(valid_iocs) == 1  # Only first occurrence kept
        assert dupes == 2  # Two duplicates removed
        assert malformed == []

    def test_comments_and_empty_lines(self, tmp_path):
        """Test that comments and empty lines are ignored."""
        content = """# This is a comment
192.168.1.1

# Another comment

evil.example.com
"""
        f = tmp_path / "with_comments.txt"
        f.write_text(content)

        valid_iocs, malformed, dupes = parse_ioc_file(str(f))

        assert len(valid_iocs) == 2  # Only the two IOCs
        assert malformed == []

    def test_file_not_found(self):
        """Test parsing non-existent file."""
        with pytest.raises(FileNotFoundError):
            parse_ioc_file("/nonexistent/path/file.txt")

    def test_empty_file(self, tmp_path):
        """Test parsing empty file."""
        f = tmp_path / "empty.txt"
        f.write_text("")

        valid_iocs, malformed, dupes = parse_ioc_file(str(f))

        assert len(valid_iocs) == 0
        assert len(malformed) == 0
        assert dupes == 0

    def test_line_numbers_preserved(self, tmp_path):
        """Test that line numbers are correctly preserved."""
        content = """# Comment on line 1
192.168.1.1
# Comment on line 3
evil.example.com
999.999.999.999
"""
        f = tmp_path / "line_nums.txt"
        f.write_text(content)

        valid_iocs, malformed, dupes = parse_ioc_file(str(f))

        # Check line numbers of valid IOCs
        assert valid_iocs[0].line_number == 2
        assert valid_iocs[1].line_number == 4

        # Check line number of malformed IOC
        assert malformed[0][0] == 5  # Line number
