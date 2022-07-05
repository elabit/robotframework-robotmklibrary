from pathlib import Path

from CheckmkLibrary import CheckmkLibrary
import pytest


cmk = CheckmkLibrary()


class TestCheckHTTP:
    def test_no_url(self):
        """Test that URL is required"""
        with pytest.raises(ValueError):
            cmk.check_http(url=None)

    def test_url_not_string(self):
        """Test invalid URL as int"""
        with pytest.raises(ValueError):
            cmk.check_http(url=123)

    def test_url_not_http(self):
        """Test invalid URL protocol"""
        with pytest.raises(ValueError):
            cmk.check_http(url="ftp://example.com")

    def test_pagesize_invalid_format(self):
        """Test invalid pagesize format"""
        with pytest.raises(ValueError):
            cmk.check_http(url="http://example.com", pagesize="123")

    def test_onredirect_invalid_arg(self):
        """Test invalid onredirect arg"""
        with pytest.raises(ValueError):
            cmk.check_http(url="http://example.com", onredirect="123")

    def test_threshold_size(self):
        with pytest.raises(Exception):
            cmk.check_http(url="http://example.com", warning=5, critical=3)
