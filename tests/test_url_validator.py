"""
Tests for URL validation, SSRF protection, and defanging.
"""

import pytest
from modules.url_validator import defang_url, is_safe_for_network, is_valid_url, refang_url


def test_is_valid_url_basic():
    valid, res = is_valid_url("https://example.com/login")
    assert valid is True
    assert "https://example.com/login" in res

    # URL without scheme should be normalized
    valid, res = is_valid_url("example.com/test")
    assert valid is True
    assert res.startswith("http://")

    # Empty or malformed URL
    valid, err = is_valid_url("")
    assert valid is False

    valid, err = is_valid_url("ftp://example.com/file")
    assert valid is False
    assert "Unsupported scheme" in err


def test_ssrf_protection():
    # Loopback IP
    safe, msg = is_safe_for_network("http://127.0.0.1/admin")
    assert safe is False
    assert "SSRF" in msg

    # Localhost hostname
    safe, msg = is_safe_for_network("http://localhost:8080/secret")
    assert safe is False
    assert "SSRF" in msg

    # Private RFC1918 IPs
    safe, msg = is_safe_for_network("http://10.0.0.1/status")
    assert safe is False
    assert "SSRF" in msg

    safe, msg = is_safe_for_network("http://192.168.1.1/router")
    assert safe is False
    assert "SSRF" in msg

    # Metadata service
    safe, msg = is_safe_for_network("http://169.254.169.254/latest/meta-data")
    assert safe is False
    assert "SSRF" in msg

    # Public domain
    safe, msg = is_safe_for_network("https://www.google.com")
    assert safe is True


def test_defanging_and_refanging():
    original = "https://malicious.evil.com/payload.exe"
    defanged = defang_url(original)
    assert "hxxps://" in defanged
    assert "[.]" in defanged
    assert "https://" not in defanged

    refanged = refang_url(defanged)
    assert refanged == original
