"""Shared test fixtures for MasterDnsVPN test suite."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from dns_utils.DnsPacketParser import DnsPacketParser


# ---------------------------------------------------------------------------
# Logger fixtures
# ---------------------------------------------------------------------------


class MockLogger:
    """Simple logger that records calls for assertion."""

    def __init__(self) -> None:
        self.debug_calls: list[str] = []
        self.info_calls: list[str] = []
        self.warning_calls: list[str] = []
        self.error_calls: list[str] = []

    def debug(self, msg: Any, *args: Any, **kwargs: Any) -> None:
        self.debug_calls.append(str(msg))

    def info(self, msg: Any, *args: Any, **kwargs: Any) -> None:
        self.info_calls.append(str(msg))

    def warning(self, msg: Any, *args: Any, **kwargs: Any) -> None:
        self.warning_calls.append(str(msg))

    def error(self, msg: Any, *args: Any, **kwargs: Any) -> None:
        self.error_calls.append(str(msg))

    def opt(self, **kwargs: Any) -> "MockLogger":
        return self


@pytest.fixture
def mock_logger() -> MockLogger:
    return MockLogger()


# ---------------------------------------------------------------------------
# DnsPacketParser fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def parser_no_crypto(mock_logger: MockLogger) -> DnsPacketParser:
    """DnsPacketParser with encryption disabled (method 0)."""
    return DnsPacketParser(
        logger=mock_logger,
        encryption_key="testkey",
        encryption_method=0,
    )


@pytest.fixture
def parser_xor(mock_logger: MockLogger) -> DnsPacketParser:
    """DnsPacketParser with XOR encryption (method 1)."""
    return DnsPacketParser(
        logger=mock_logger,
        encryption_key="testkey",
        encryption_method=1,
    )


@pytest.fixture
def parser_chacha20(mock_logger: MockLogger) -> DnsPacketParser:
    """DnsPacketParser with ChaCha20 encryption (method 2)."""
    return DnsPacketParser(
        logger=mock_logger,
        encryption_key="testkey1234567890",
        encryption_method=2,
    )


@pytest.fixture
def parser_aes128(mock_logger: MockLogger) -> DnsPacketParser:
    """DnsPacketParser with AES-128-GCM (method 3)."""
    return DnsPacketParser(
        logger=mock_logger,
        encryption_key="testkey1234567890",
        encryption_method=3,
    )


@pytest.fixture
def parser_aes192(mock_logger: MockLogger) -> DnsPacketParser:
    """DnsPacketParser with AES-192-GCM (method 4)."""
    return DnsPacketParser(
        logger=mock_logger,
        encryption_key="testkey1234567890abcdef",
        encryption_method=4,
    )


@pytest.fixture
def parser_aes256(mock_logger: MockLogger) -> DnsPacketParser:
    """DnsPacketParser with AES-256-GCM (method 5)."""
    return DnsPacketParser(
        logger=mock_logger,
        encryption_key="testkey1234567890abcdef01",
        encryption_method=5,
    )


# ---------------------------------------------------------------------------
# Temp file fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_dir(tmp_path: Any) -> str:
    return str(tmp_path)


@pytest.fixture
def tmp_toml_file(tmp_path: Any) -> str:
    """Write a minimal valid TOML config and return the path."""
    content = """
[server]
host = "127.0.0.1"
port = 53

[logging]
level = "DEBUG"
"""
    p = tmp_path / "test_config.toml"
    p.write_text(content, encoding="utf-8")
    return str(p)


@pytest.fixture
def invalid_toml_file(tmp_path: Any) -> str:
    """Write an invalid TOML file and return the path."""
    p = tmp_path / "bad_config.toml"
    p.write_text("this is [not valid toml ]]", encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# Asyncio mock reader/writer
# ---------------------------------------------------------------------------


def make_mock_writer() -> MagicMock:
    """Create a mock asyncio StreamWriter."""
    writer = MagicMock()
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()
    writer.is_closing = MagicMock(return_value=False)
    writer.can_write_eof = MagicMock(return_value=False)
    writer.get_extra_info = MagicMock(return_value=None)
    return writer


def make_mock_reader(data: bytes = b"") -> MagicMock:
    """Create a mock asyncio StreamReader that yields data then EOF."""
    reader = MagicMock()
    chunks = [data] if data else []
    chunks.append(b"")  # EOF sentinel

    async def _read(n: int = -1) -> bytes:
        if chunks:
            return chunks.pop(0)
        return b""

    reader.read = _read
    return reader


@pytest.fixture
def mock_writer() -> MagicMock:
    return make_mock_writer()


@pytest.fixture
def mock_reader() -> MagicMock:
    return make_mock_reader(b"test payload data")


# ---------------------------------------------------------------------------
# Mock socket fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_udp_socket() -> MagicMock:
    """Create a mock non-blocking UDP socket."""
    sock = MagicMock()
    sock.fileno = MagicMock(return_value=5)
    sock.setblocking = MagicMock()
    sock.sendto = MagicMock(return_value=10)
    sock.recvfrom = MagicMock(return_value=(b"response", ("127.0.0.1", 53)))
    return sock


# ---------------------------------------------------------------------------
# Event loop fixture override (ensure clean loop per test)
# ---------------------------------------------------------------------------


@pytest.fixture
def event_loop():
    """Create a new event loop for each test."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
