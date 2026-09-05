import pytest
import typer

from websec_audit.cli import normalize_target


def test_adds_https_when_scheme_is_missing():
    result = normalize_target("example.com")
    assert result == "https://example.com"


def test_keeps_https():
    result = normalize_target("https://example.com")
    assert result == "https://example.com"


def test_keeps_http():
    result = normalize_target("http://example.com")
    assert result == "http://example.com"


def test_removes_trailing_slash():
    result = normalize_target("https://example.com/")
    assert result == "https://example.com"


def test_strips_whitespace():
    result = normalize_target("  example.com  ")
    assert result == "https://example.com"


def test_rejects_unsupported_scheme():
    with pytest.raises(typer.BadParameter):
        normalize_target("ftp://example.com")


def test_rejects_empty_target():
    with pytest.raises(typer.BadParameter):
        normalize_target("   ")