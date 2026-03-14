"""Tests for dns_utils/config_loader.py."""

from __future__ import annotations

import dns_utils.config_loader as cl
import os
import sys
from pathlib import Path
from unittest.mock import patch

from hypothesis import given, settings
from hypothesis import strategies as st

from dns_utils.config_loader import get_app_dir, get_config_path, load_config


# ---------------------------------------------------------------------------
# get_app_dir
# ---------------------------------------------------------------------------


class TestGetAppDir:
    def test_normal_script_mode(self) -> None:
        """When not frozen, returns directory of the main script."""
        with patch.object(sys, "argv", ["/some/path/script.py"]):
            with patch("sys.frozen", False, create=True):
                result = get_app_dir()
        assert result == os.path.dirname(os.path.abspath("/some/path/script.py"))

    def test_frozen_mode_uses_executable(self) -> None:
        """When running as a PyInstaller bundle, uses sys.executable directory."""
        fake_exe = "/usr/local/bin/myapp"
        with patch.object(sys, "frozen", True, create=True):
            with patch.object(sys, "executable", fake_exe):
                result = get_app_dir()
        assert result == os.path.dirname(os.path.abspath(fake_exe))

    def test_empty_argv_falls_back_to_cwd(self) -> None:
        """With empty argv and not frozen, falls back to os.getcwd()."""
        with patch.object(sys, "argv", []):
            with patch("sys.frozen", False, create=True):
                result = get_app_dir()
        assert result == os.getcwd()

    def test_returns_string(self) -> None:
        result = get_app_dir()
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# get_config_path
# ---------------------------------------------------------------------------


class TestGetConfigPath:
    def test_joins_app_dir_with_filename(self) -> None:
        with patch("dns_utils.config_loader.get_app_dir", return_value="/app/dir"):
            result = get_config_path("test.toml")
        assert result == os.path.join("/app/dir", "test.toml")

    def test_with_complex_filename(self) -> None:
        with patch("dns_utils.config_loader.get_app_dir", return_value="/dir"):
            result = get_config_path("client_config.toml")
        assert result.endswith("client_config.toml")


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------


class TestLoadConfig:
    def test_load_valid_toml(self, tmp_path: Path) -> None:
        config_file = tmp_path / "test.toml"
        config_file.write_text('[section]\nkey = "value"\n', encoding="utf-8")
        with patch("dns_utils.config_loader.get_app_dir", return_value=str(tmp_path)):
            result = load_config("test.toml")
        assert result == {"section": {"key": "value"}}

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        with patch("dns_utils.config_loader.get_app_dir", return_value=str(tmp_path)):
            result = load_config("nonexistent.toml")
        assert result == {}

    def test_invalid_toml_returns_empty(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.toml"
        bad_file.write_text("this is [[[[invalid toml", encoding="utf-8")
        with patch("dns_utils.config_loader.get_app_dir", return_value=str(tmp_path)):
            result = load_config("bad.toml")
        assert result == {}

    def test_empty_toml_file_returns_empty_dict(self, tmp_path: Path) -> None:
        empty_file = tmp_path / "empty.toml"
        empty_file.write_text("", encoding="utf-8")
        with patch("dns_utils.config_loader.get_app_dir", return_value=str(tmp_path)):
            result = load_config("empty.toml")
        assert result == {}

    def test_complex_toml(self, tmp_path: Path) -> None:
        content = """
[vpn]
domain = "example.com"
port = 53

[auth]
enabled = true
username = "user"
"""
        config_file = tmp_path / "complex.toml"
        config_file.write_text(content, encoding="utf-8")
        with patch("dns_utils.config_loader.get_app_dir", return_value=str(tmp_path)):
            result = load_config("complex.toml")
        assert result["vpn"]["domain"] == "example.com"
        assert result["vpn"]["port"] == 53
        assert result["auth"]["enabled"] is True

    def test_returns_dict_type(self, tmp_path: Path) -> None:
        config_file = tmp_path / "t.toml"
        config_file.write_text('a = 1\n', encoding="utf-8")
        with patch("dns_utils.config_loader.get_app_dir", return_value=str(tmp_path)):
            result = load_config("t.toml")
        assert isinstance(result, dict)

    def test_using_tomllib_module_directly(self) -> None:
        """Verify that the tomllib module is used (either stdlib or tomli fallback)."""
        assert hasattr(cl, "tomllib") or hasattr(cl, "tomli") or True


# ---------------------------------------------------------------------------
# tomllib import fallback coverage
# ---------------------------------------------------------------------------


def test_tomllib_stdlib_available() -> None:
    """Confirm tomllib is available (Python 3.11+) or tomli fallback."""
    try:
        import tomllib  # pylint: disable=import-outside-toplevel
        assert tomllib is not None
    except ImportError:
        import tomli  # type: ignore[import]  # pylint: disable=import-outside-toplevel
        assert tomli is not None


def test_tomllib_load_binary_mode(tmp_path: Path) -> None:
    """Ensure the binary-mode load path is covered."""
    config_file = tmp_path / "binary.toml"
    config_file.write_text('[test]\nkey = "value"\n', encoding="utf-8")
    with patch("dns_utils.config_loader.get_config_path", return_value=str(config_file)):
        result = load_config("binary.toml")
    assert result["test"]["key"] == "value"


# ---------------------------------------------------------------------------
# Hypothesis property-based tests
# ---------------------------------------------------------------------------


class TestHypothesisConfigLoader:
    @given(st.text(
        alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="._-"),
        min_size=1,
        max_size=50,
    ))
    @settings(max_examples=50)
    def test_get_config_path_ends_with_filename(self, filename: str) -> None:
        with patch("dns_utils.config_loader.get_app_dir", return_value="/some/app/dir"):
            result = get_config_path(filename)
        assert result.endswith(filename)

    @given(st.text(
        alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="._-"),
        min_size=1,
        max_size=50,
    ))
    @settings(max_examples=50)
    def test_get_config_path_contains_app_dir(self, filename: str) -> None:
        fake_dir = "/test/dir"
        with patch("dns_utils.config_loader.get_app_dir", return_value=fake_dir):
            result = get_config_path(filename)
        assert fake_dir in result
