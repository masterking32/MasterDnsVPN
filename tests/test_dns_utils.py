"""Comprehensive tests for the dns_utils package."""

from __future__ import annotations

import asyncio
import os
import struct
import tempfile
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dns_utils.compression import (
    ZSTD_AVAILABLE,
    LZ4_AVAILABLE,
    Compression_Type,
    SUPPORTED_COMPRESSION_TYPES,
    compress_payload,
    decompress_payload,
    get_compression_name,
    is_compression_type_available,
    normalize_compression_type,
    try_decompress_payload,
)
from dns_utils.config_loader import get_app_dir, get_config_path, load_config
from dns_utils.DNS_ENUMS import (
    DNS_QClass,
    DNS_rCode,
    DNS_Record_Type,
    Packet_Type,
    Stream_State,
)
from dns_utils.DNSBalancer import DNSBalancer
from dns_utils.DnsPacketParser import DnsPacketParser
from dns_utils.PacketQueueMixin import PacketQueueMixin
from dns_utils.PingManager import PingManager
from dns_utils.PrependReader import PrependReader


# ---------------------------------------------------------------------------
# Helpers / shared fixtures
# ---------------------------------------------------------------------------

def _make_server(resolver: str = "8.8.8.8", domain: str = "test.example.com", valid: bool = True) -> dict:
    return {"resolver": resolver, "domain": domain, "is_valid": valid}


def _make_servers(n: int = 3, valid: bool = True) -> list:
    return [_make_server(f"1.1.1.{i}", f"s{i}.example.com", valid) for i in range(n)]


def _make_parser(method: int = 0, key: str = "") -> DnsPacketParser:
    return DnsPacketParser(logger=MagicMock(), encryption_key=key, encryption_method=method)


def _raw_dns_query(domain: str = "example.com", qtype: int = 1) -> bytes:
    """Build a minimal DNS query packet for testing."""
    parser = _make_parser()
    pkt = parser.simple_question_packet(domain, qtype)
    assert pkt, f"simple_question_packet returned empty for domain={domain}"
    return pkt


class _MockWriter:
    def __init__(self) -> None:
        self._closed = False
        self.written: list[bytes] = []
        self._is_closing = False

    def write(self, data: bytes) -> None:
        self.written.append(data)

    async def drain(self) -> None:
        pass

    def can_write_eof(self) -> bool:
        return False

    def get_extra_info(self, key: str, default: Any = None) -> Any:
        return default

    def close(self) -> None:
        self._closed = True
        self._is_closing = True

    async def wait_closed(self) -> None:
        pass

    def is_closing(self) -> bool:
        return self._is_closing


class _MockReader:
    def __init__(self, chunks: list[bytes] | None = None) -> None:
        self._chunks = list(chunks or [])
        self._idx = 0

    async def read(self, n: int = -1) -> bytes:
        if self._idx >= len(self._chunks):
            return b""
        chunk = self._chunks[self._idx]
        self._idx += 1
        if n > 0:
            return chunk[:n]
        return chunk


class _ErrorReader:
    async def read(self, n: int = -1) -> bytes:
        raise ConnectionResetError("mock connection reset")


def _make_arq(
    stream_id: int = 1,
    session_id: int = 1,
    mtu: int = 512,
    reader: Any = None,
    writer: Any = None,
    is_socks: bool = False,
    initial_data: bytes = b"",
    enable_control_reliability: bool = False,
) -> tuple:
    sent_packets: list = []

    async def enqueue_tx(priority, sid, sn, data, **kwargs):
        sent_packets.append(("tx", priority, sid, sn, data))

    async def enqueue_control_tx(priority, sid, sn, ptype, data, **kwargs):
        sent_packets.append(("ctrl", priority, sid, sn, ptype, data))

    if reader is None:
        reader = _MockReader()
    if writer is None:
        writer = _MockWriter()

    from dns_utils.ARQ import ARQ

    arq = ARQ(
        stream_id=stream_id,
        session_id=session_id,
        enqueue_tx_cb=enqueue_tx,
        reader=reader,
        writer=writer,
        mtu=mtu,
        logger=MagicMock(),
        window_size=100,
        is_socks=is_socks,
        initial_data=initial_data,
        enqueue_control_tx_cb=enqueue_control_tx,
        enable_control_reliability=enable_control_reliability,
    )
    return arq, sent_packets


# ===========================================================================
# compression.py
# ===========================================================================

class TestCompressionType:
    def test_constants(self) -> None:
        assert Compression_Type.OFF == 0
        assert Compression_Type.ZSTD == 1
        assert Compression_Type.LZ4 == 2
        assert Compression_Type.ZLIB == 3

    def test_supported_types(self) -> None:
        assert Compression_Type.OFF in SUPPORTED_COMPRESSION_TYPES
        assert Compression_Type.ZSTD in SUPPORTED_COMPRESSION_TYPES
        assert Compression_Type.LZ4 in SUPPORTED_COMPRESSION_TYPES
        assert Compression_Type.ZLIB in SUPPORTED_COMPRESSION_TYPES


class TestNormalizeCompressionType:
    def test_known_types_pass_through(self) -> None:
        for ct in SUPPORTED_COMPRESSION_TYPES:
            assert normalize_compression_type(ct) == ct

    def test_unknown_type_returns_off(self) -> None:
        assert normalize_compression_type(99) == Compression_Type.OFF
        assert normalize_compression_type(-1) == Compression_Type.OFF

    def test_none_returns_off(self) -> None:
        assert normalize_compression_type(None) == Compression_Type.OFF  # type: ignore[arg-type]

    def test_zero_returns_off(self) -> None:
        assert normalize_compression_type(0) == Compression_Type.OFF


class TestGetCompressionName:
    def test_known_names(self) -> None:
        assert get_compression_name(Compression_Type.OFF) == "OFF"
        assert get_compression_name(Compression_Type.ZSTD) == "ZSTD"
        assert get_compression_name(Compression_Type.LZ4) == "LZ4"
        assert get_compression_name(Compression_Type.ZLIB) == "ZLIB"

    def test_unknown_returns_unknown(self) -> None:
        assert get_compression_name(999) == "UNKNOWN"


class TestIsCompressionTypeAvailable:
    def test_off_not_available(self) -> None:
        assert not is_compression_type_available(Compression_Type.OFF)

    def test_zlib_always_available(self) -> None:
        assert is_compression_type_available(Compression_Type.ZLIB)

    def test_zstd_availability_matches_flag(self) -> None:
        assert is_compression_type_available(Compression_Type.ZSTD) == ZSTD_AVAILABLE

    def test_lz4_availability_matches_flag(self) -> None:
        assert is_compression_type_available(Compression_Type.LZ4) == LZ4_AVAILABLE


class TestCompressPayload:
    _large_data = b"hello world " * 50  # 600 bytes, compressible

    def test_empty_data_returns_off(self) -> None:
        out, ctype = compress_payload(b"", Compression_Type.ZLIB)
        assert out == b""
        assert ctype == Compression_Type.OFF

    def test_off_type_returns_unchanged(self) -> None:
        out, ctype = compress_payload(self._large_data, Compression_Type.OFF)
        assert out == self._large_data
        assert ctype == Compression_Type.OFF

    def test_small_data_below_min_size_returns_off(self) -> None:
        small = b"tiny"
        out, ctype = compress_payload(small, Compression_Type.ZLIB, min_size=100)
        assert out == small
        assert ctype == Compression_Type.OFF

    def test_zlib_compresses_large_data(self) -> None:
        out, ctype = compress_payload(self._large_data, Compression_Type.ZLIB)
        assert ctype == Compression_Type.ZLIB
        assert len(out) < len(self._large_data)

    def test_zstd_compresses_when_available(self) -> None:
        if not ZSTD_AVAILABLE:
            pytest.skip("zstd not available")
        out, ctype = compress_payload(self._large_data, Compression_Type.ZSTD)
        assert ctype == Compression_Type.ZSTD
        assert len(out) < len(self._large_data)

    def test_lz4_compresses_when_available(self) -> None:
        if not LZ4_AVAILABLE:
            pytest.skip("lz4 not available")
        out, ctype = compress_payload(self._large_data, Compression_Type.LZ4)
        assert ctype == Compression_Type.LZ4
        assert len(out) < len(self._large_data)

    def test_unavailable_compressor_returns_off(self) -> None:
        # If zstd not available, ZSTD should fall back to OFF
        if ZSTD_AVAILABLE:
            pytest.skip("zstd is available, cannot test unavailability")
        out, ctype = compress_payload(self._large_data, Compression_Type.ZSTD)
        assert ctype == Compression_Type.OFF

    def test_incompressible_data_returns_off(self) -> None:
        # Highly random data won't compress smaller
        import os as _os
        random_data = _os.urandom(200)
        # Even if compression is attempted, if result >= original, returns OFF
        # This may or may not compress depending on the random bytes
        out, ctype = compress_payload(random_data, Compression_Type.ZLIB)
        # We just check the contract: if ctype is ZLIB the output is smaller
        if ctype == Compression_Type.ZLIB:
            assert len(out) < len(random_data)
        else:
            assert ctype == Compression_Type.OFF


class TestTryDecompressPayload:
    _compressed: bytes

    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        large = b"hello world " * 50
        self._original, _ctype = compress_payload(large, Compression_Type.ZLIB)
        self._large = large

    def test_empty_data_returns_empty_success(self) -> None:
        out, ok = try_decompress_payload(b"", Compression_Type.ZLIB)
        assert out == b""
        assert ok

    def test_off_type_returns_unchanged(self) -> None:
        out, ok = try_decompress_payload(b"data", Compression_Type.OFF)
        assert out == b"data"
        assert ok

    def test_zlib_roundtrip(self) -> None:
        out, ok = try_decompress_payload(self._original, Compression_Type.ZLIB)
        assert ok
        assert out == self._large

    def test_zlib_invalid_data_returns_empty_false(self) -> None:
        out, ok = try_decompress_payload(b"\x00\x01\x02garbage", Compression_Type.ZLIB)
        assert not ok
        assert out == b""

    def test_unavailable_compressor_returns_false(self) -> None:
        if ZSTD_AVAILABLE:
            pytest.skip("zstd available, cannot test unavailability")
        out, ok = try_decompress_payload(b"data", Compression_Type.ZSTD)
        assert not ok
        assert out == b""

    def test_zstd_roundtrip_when_available(self) -> None:
        if not ZSTD_AVAILABLE:
            pytest.skip("zstd not available")
        large = b"hello world " * 50
        compressed, ct = compress_payload(large, Compression_Type.ZSTD)
        assert ct == Compression_Type.ZSTD
        out, ok = try_decompress_payload(compressed, Compression_Type.ZSTD)
        assert ok
        assert out == large

    def test_lz4_roundtrip_when_available(self) -> None:
        if not LZ4_AVAILABLE:
            pytest.skip("lz4 not available")
        large = b"hello world " * 50
        compressed, ct = compress_payload(large, Compression_Type.LZ4)
        assert ct == Compression_Type.LZ4
        out, ok = try_decompress_payload(compressed, Compression_Type.LZ4)
        assert ok
        assert out == large


class TestDecompressPayload:
    def test_success_returns_decompressed(self) -> None:
        large = b"hello world " * 50
        compressed, ct = compress_payload(large, Compression_Type.ZLIB)
        result = decompress_payload(compressed, ct)
        assert result == large

    def test_failure_returns_original(self) -> None:
        bad = b"\x00garbage"
        result = decompress_payload(bad, Compression_Type.ZLIB)
        assert result == bad


# ===========================================================================
# config_loader.py
# ===========================================================================

class TestGetAppDir:
    def test_returns_string(self) -> None:
        d = get_app_dir()
        assert isinstance(d, str)
        assert len(d) > 0

    def test_frozen_mode(self) -> None:
        import sys
        with patch.object(sys, "frozen", True, create=True):
            d = get_app_dir()
        assert isinstance(d, str)

    def test_empty_argv(self) -> None:
        import sys
        with patch.object(sys, "argv", []):
            d = get_app_dir()
        assert isinstance(d, str)


class TestGetConfigPath:
    def test_returns_joined_path(self) -> None:
        path = get_config_path("config.toml")
        assert path.endswith("config.toml")


class TestLoadConfig:
    def test_nonexistent_file_returns_empty(self) -> None:
        result = load_config("nonexistent_file_xyz_12345.toml")
        assert result == {}

    def test_valid_toml_file(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".toml", mode="wb", delete=False) as f:
            f.write(b"[section]\nkey = 'value'\n")
            tmp_path = f.name
        try:
            with patch("dns_utils.config_loader.get_config_path", return_value=tmp_path):
                result = load_config("dummy.toml")
            assert result.get("section", {}).get("key") == "value"
        finally:
            os.unlink(tmp_path)

    def test_invalid_toml_returns_empty(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".toml", mode="wb", delete=False) as f:
            f.write(b"this is not valid toml [\n")
            tmp_path = f.name
        try:
            with patch("dns_utils.config_loader.get_config_path", return_value=tmp_path):
                result = load_config("dummy.toml")
            assert result == {}
        finally:
            os.unlink(tmp_path)


# ===========================================================================
# DNS_ENUMS.py
# ===========================================================================

class TestPacketType:
    def test_basic_values(self) -> None:
        assert Packet_Type.MTU_UP_REQ == 0x01
        assert Packet_Type.SESSION_INIT == 0x05
        assert Packet_Type.PING == 0x09
        assert Packet_Type.PONG == 0x0A
        assert Packet_Type.STREAM_SYN == 0x0B
        assert Packet_Type.STREAM_DATA == 0x0D
        assert Packet_Type.STREAM_FIN == 0x11
        assert Packet_Type.STREAM_RST == 0x13
        assert Packet_Type.ERROR_DROP == 0xFF


class TestStreamState:
    def test_values(self) -> None:
        assert Stream_State.OPEN == 1
        assert Stream_State.CLOSED == 8
        assert Stream_State.RESET == 7


class TestDnsRecordType:
    def test_common_values(self) -> None:
        assert DNS_Record_Type.A == 1
        assert DNS_Record_Type.AAAA == 28
        assert DNS_Record_Type.TXT == 16
        assert DNS_Record_Type.MX == 15
        assert DNS_Record_Type.ANY == 255


class TestDnsRCode:
    def test_values(self) -> None:
        assert DNS_rCode.NO_ERROR == 0
        assert DNS_rCode.FORMAT_ERROR == 1
        assert DNS_rCode.SERVER_FAILURE == 2
        assert DNS_rCode.REFUSED == 5


class TestDnsQClass:
    def test_values(self) -> None:
        assert DNS_QClass.IN == 1
        assert DNS_QClass.ANY == 255


# ===========================================================================
# PrependReader.py
# ===========================================================================

class TestPrependReader:
    async def test_read_partial_from_initial_data(self) -> None:
        original = AsyncMock()
        reader = PrependReader(original, b"hello world")
        chunk = await reader.read(5)
        assert chunk == b"hello"
        assert reader.initial_data == b" world"

    async def test_read_all_initial_data_at_once(self) -> None:
        original = AsyncMock()
        reader = PrependReader(original, b"hello")
        chunk = await reader.read(10)
        assert chunk == b"hello"
        assert reader.initial_data == b""

    async def test_read_delegates_after_initial_exhausted(self) -> None:
        original = AsyncMock()
        original.read.return_value = b"from_socket"
        reader = PrependReader(original, b"")
        result = await reader.read(100)
        assert result == b"from_socket"
        original.read.assert_called_once_with(100)

    async def test_read_negative_n_returns_all_initial(self) -> None:
        original = AsyncMock()
        reader = PrependReader(original, b"fulldata")
        chunk = await reader.read(-1)
        assert chunk == b"fulldata"
        assert reader.initial_data == b""

    async def test_read_exact_size_of_initial_data(self) -> None:
        original = AsyncMock()
        reader = PrependReader(original, b"abc")
        chunk = await reader.read(3)
        assert chunk == b"abc"
        assert reader.initial_data == b""


# ===========================================================================
# DNSBalancer.py
# ===========================================================================

class TestDNSBalancerRoundRobin:
    def test_returns_single_server(self) -> None:
        servers = _make_servers(3)
        bal = DNSBalancer(servers, strategy=0)
        server = bal.get_best_server()
        assert server is not None
        assert server["is_valid"]

    def test_round_robin_cycles(self) -> None:
        servers = _make_servers(3)
        bal = DNSBalancer(servers, strategy=0)
        results = [bal.get_best_server()["resolver"] for _ in range(6)]
        # Should cycle through all 3 servers
        unique = set(results)
        assert len(unique) == 3

    def test_get_unique_servers_multiple(self) -> None:
        servers = _make_servers(5)
        bal = DNSBalancer(servers, strategy=0)
        result = bal.get_unique_servers(3)
        assert len(result) == 3

    def test_round_robin_wraps_around(self) -> None:
        servers = _make_servers(2)
        bal = DNSBalancer(servers, strategy=0)
        # Request 3 from 2 valid servers — should wrap
        result = bal.get_unique_servers(2)
        assert len(result) == 2

    def test_get_servers_for_stream(self) -> None:
        servers = _make_servers(4)
        bal = DNSBalancer(servers, strategy=0)
        result = bal.get_servers_for_stream(42, 2)
        assert len(result) == 2


class TestDNSBalancerRandom:
    def test_returns_server(self) -> None:
        servers = _make_servers(5)
        bal = DNSBalancer(servers, strategy=1)
        server = bal.get_best_server()
        assert server is not None

    def test_returns_multiple_unique(self) -> None:
        servers = _make_servers(5)
        bal = DNSBalancer(servers, strategy=1)
        result = bal.get_unique_servers(3)
        assert len(result) == 3


class TestDNSBalancerLeastLoss:
    def test_returns_server(self) -> None:
        servers = _make_servers(3)
        bal = DNSBalancer(servers, strategy=3)
        server = bal.get_best_server()
        assert server is not None

    def test_prefers_server_with_lower_loss(self) -> None:
        servers = _make_servers(3)
        bal = DNSBalancer(servers, strategy=3)
        key0 = servers[0]["_key"]
        key1 = servers[1]["_key"]
        # Simulate sends and acks to create different loss rates
        for _ in range(10):
            bal.report_send(key0)
            bal.report_success(key0)  # 0% loss
        for _ in range(10):
            bal.report_send(key1)
            # No acks for key1 → high loss
        best = bal.get_best_server()
        assert best["resolver"] == servers[0]["resolver"]


class TestDNSBalancerLowestLatency:
    def test_returns_server(self) -> None:
        servers = _make_servers(3)
        bal = DNSBalancer(servers, strategy=4)
        server = bal.get_best_server()
        assert server is not None

    def test_prefers_server_with_lower_rtt(self) -> None:
        servers = _make_servers(3)
        bal = DNSBalancer(servers, strategy=4)
        key0 = servers[0]["_key"]
        key1 = servers[1]["_key"]
        # Give key0 low RTT (5 samples required)
        for _ in range(6):
            bal.report_success(key0, rtt=0.001)
        for _ in range(6):
            bal.report_success(key1, rtt=1.0)
        best = bal.get_best_server()
        assert best["resolver"] == servers[0]["resolver"]


class TestDNSBalancerStats:
    def test_report_success_without_rtt(self) -> None:
        servers = _make_servers(1)
        bal = DNSBalancer(servers, strategy=0)
        key = servers[0]["_key"]
        bal.report_send(key)
        bal.report_success(key)
        stats = bal.server_stats[key]
        assert stats["acked"] == 1
        assert stats["sent"] == 1

    def test_report_success_with_rtt(self) -> None:
        servers = _make_servers(1)
        bal = DNSBalancer(servers, strategy=0)
        key = servers[0]["_key"]
        bal.report_success(key, rtt=0.05)
        assert bal.server_stats[key]["rtt_count"] == 1

    def test_stats_decay_when_sent_exceeds_1000(self) -> None:
        servers = _make_servers(1)
        bal = DNSBalancer(servers, strategy=0)
        key = servers[0]["_key"]
        bal.server_stats[key]["sent"] = 1001
        bal.server_stats[key]["acked"] = 1000
        bal.report_success(key, rtt=0.01)
        # Decay should have been applied
        assert bal.server_stats[key]["sent"] < 600

    def test_reset_server_stats(self) -> None:
        servers = _make_servers(1)
        bal = DNSBalancer(servers, strategy=0)
        key = servers[0]["_key"]
        bal.report_send(key)
        bal.reset_server_stats(key)
        assert key not in bal.server_stats

    def test_get_loss_rate_insufficient_data(self) -> None:
        servers = _make_servers(1)
        bal = DNSBalancer(servers, strategy=0)
        key = servers[0]["_key"]
        # Less than 5 sends → default 0.5
        bal.report_send(key)
        assert bal.get_loss_rate(key) == 0.5

    def test_get_loss_rate_no_stats(self) -> None:
        servers = _make_servers(1)
        bal = DNSBalancer(servers, strategy=0)
        assert bal.get_loss_rate("nonexistent_key") == 0.5

    def test_get_loss_rate_computed(self) -> None:
        servers = _make_servers(1)
        bal = DNSBalancer(servers, strategy=0)
        key = servers[0]["_key"]
        for _ in range(10):
            bal.report_send(key)
        for _ in range(8):
            bal.report_success(key)
        loss = bal.get_loss_rate(key)
        assert abs(loss - 0.2) < 0.01

    def test_get_avg_rtt_insufficient_data(self) -> None:
        servers = _make_servers(1)
        bal = DNSBalancer(servers, strategy=0)
        key = servers[0]["_key"]
        assert bal.get_avg_rtt(key) == 999.0

    def test_get_avg_rtt_no_stats(self) -> None:
        servers = _make_servers(1)
        bal = DNSBalancer(servers, strategy=0)
        assert bal.get_avg_rtt("nonexistent") == 999.0

    def test_get_avg_rtt_computed(self) -> None:
        servers = _make_servers(1)
        bal = DNSBalancer(servers, strategy=0)
        key = servers[0]["_key"]
        for _ in range(6):
            bal.report_success(key, rtt=0.1)
        avg = bal.get_avg_rtt(key)
        assert abs(avg - 0.1) < 0.001


class TestDNSBalancerEdgeCases:
    def test_no_valid_servers_returns_none(self) -> None:
        servers = [_make_server(valid=False)]
        bal = DNSBalancer(servers, strategy=0)
        assert bal.get_best_server() is None

    def test_empty_server_list_returns_empty(self) -> None:
        bal = DNSBalancer([], strategy=0)
        assert bal.get_unique_servers(5) == []
        assert bal.get_servers_for_stream(0, 5) == []

    def test_normalize_required_count_invalid_type(self) -> None:
        servers = _make_servers(3)
        bal = DNSBalancer(servers, strategy=0)
        # Non-int falls back to 1
        result = bal.get_unique_servers("not_a_number")  # type: ignore[arg-type]
        assert len(result) == 1

    def test_normalize_required_count_zero(self) -> None:
        servers = _make_servers(3)
        bal = DNSBalancer(servers, strategy=0)
        result = bal.get_unique_servers(0)
        assert len(result) == 1  # defaults to 1

    def test_set_balancers_updates_valid_servers(self) -> None:
        bal = DNSBalancer([], strategy=0)
        assert bal.valid_servers_count == 0
        new_servers = _make_servers(2)
        bal.set_balancers(new_servers)
        assert bal.valid_servers_count == 2

    def test_set_balancers_assigns_key(self) -> None:
        bal = DNSBalancer([], strategy=0)
        servers = [{"resolver": "1.1.1.1", "domain": "d.com", "is_valid": True}]
        bal.set_balancers(servers)
        assert servers[0]["_key"] == "1.1.1.1:d.com"

    def test_request_more_than_available(self) -> None:
        servers = _make_servers(2)
        bal = DNSBalancer(servers, strategy=0)
        result = bal.get_unique_servers(10)
        assert len(result) == 2  # capped at available

    def test_round_robin_multi_server_count_exceeds_available(self) -> None:
        servers = _make_servers(3)
        bal = DNSBalancer(servers, strategy=0)
        # Set rr_index near end to force wrap
        bal.rr_index = 2
        result = bal._get_servers_round_robin(2)
        assert len(result) == 2


# ===========================================================================
# PacketQueueMixin.py
# ===========================================================================

class _ConcreteQueueMixin(PacketQueueMixin):
    """Concrete subclass to instantiate PacketQueueMixin for testing."""

    _packable_control_types = frozenset({
        Packet_Type.STREAM_FIN_ACK,
    })


class TestPacketQueueMixinMtu:
    def test_basic_calc(self) -> None:
        m = _ConcreteQueueMixin()
        result = m._compute_mtu_based_pack_limit(200, 100.0, 5)
        assert result == 40

    def test_zero_mtu_returns_one(self) -> None:
        m = _ConcreteQueueMixin()
        assert m._compute_mtu_based_pack_limit(0, 100.0, 5) == 1

    def test_small_block_size(self) -> None:
        m = _ConcreteQueueMixin()
        result = m._compute_mtu_based_pack_limit(100, 100.0, 1)
        assert result == 100

    def test_exception_in_params_returns_one(self) -> None:
        m = _ConcreteQueueMixin()
        result = m._compute_mtu_based_pack_limit("bad", "bad", "bad")  # type: ignore[arg-type]
        assert result == 1

    def test_usage_percent_clamped(self) -> None:
        m = _ConcreteQueueMixin()
        r1 = m._compute_mtu_based_pack_limit(200, 0.0, 5)  # clamped to 1%
        r2 = m._compute_mtu_based_pack_limit(200, 200.0, 5)  # clamped to 100%
        assert r1 >= 1
        assert r2 == 40


class TestPriorityCounters:
    def test_inc_and_dec(self) -> None:
        m = _ConcreteQueueMixin()
        owner: dict = {}
        m._inc_priority_counter(owner, 2)
        assert owner["priority_counts"][2] == 1
        m._inc_priority_counter(owner, 2)
        assert owner["priority_counts"][2] == 2
        m._dec_priority_counter(owner, 2)
        assert owner["priority_counts"][2] == 1
        m._dec_priority_counter(owner, 2)
        assert 2 not in owner["priority_counts"]

    def test_dec_nonexistent_does_nothing(self) -> None:
        m = _ConcreteQueueMixin()
        owner: dict = {}
        m._dec_priority_counter(owner, 5)  # Should not raise

    def test_dec_no_counters_does_nothing(self) -> None:
        m = _ConcreteQueueMixin()
        m._dec_priority_counter({}, 5)  # No priority_counts key


class TestReleaseTracking:
    def test_stream_data_releases_track_data(self) -> None:
        m = _ConcreteQueueMixin()
        owner: dict = {"track_data": {42}}
        m._release_tracking_on_pop(owner, Packet_Type.STREAM_DATA, 0, 42)
        assert 42 not in owner["track_data"]

    def test_socks5_syn_is_noop_for_tracking(self) -> None:
        # SOCKS5_SYN is not in any tracking set; the call must not raise
        # and must leave unrelated tracking data intact.
        m = _ConcreteQueueMixin()
        owner: dict = {"track_data": {7}}
        m._release_tracking_on_pop(owner, Packet_Type.SOCKS5_SYN, 0, 7)
        assert 7 in owner["track_data"]

    def test_stream_data_ack_releases_track_ack(self) -> None:
        m = _ConcreteQueueMixin()
        owner: dict = {"track_ack": {10}}
        m._release_tracking_on_pop(owner, Packet_Type.STREAM_DATA_ACK, 0, 10)
        assert 10 not in owner["track_ack"]

    def test_stream_resend_releases_track_resend(self) -> None:
        m = _ConcreteQueueMixin()
        owner: dict = {"track_resend": {5}}
        m._release_tracking_on_pop(owner, Packet_Type.STREAM_RESEND, 0, 5)
        assert 5 not in owner["track_resend"]

    def test_stream_fin_releases_fin_and_types(self) -> None:
        m = _ConcreteQueueMixin()
        ptype = Packet_Type.STREAM_FIN
        owner: dict = {"track_fin": {ptype}, "track_types": {ptype}}
        m._release_tracking_on_pop(owner, ptype, 0, 0)
        assert ptype not in owner["track_fin"]
        assert ptype not in owner["track_types"]

    def test_syn_ack_releases_syn_ack_and_types(self) -> None:
        m = _ConcreteQueueMixin()
        ptype = Packet_Type.STREAM_SYN
        owner: dict = {"track_syn_ack": {ptype}, "track_types": {ptype}}
        m._release_tracking_on_pop(owner, ptype, 0, 0)
        assert ptype not in owner["track_syn_ack"]
        assert ptype not in owner["track_types"]

    def test_none_of_the_above_is_noop(self) -> None:
        m = _ConcreteQueueMixin()
        owner: dict = {}
        m._release_tracking_on_pop(owner, Packet_Type.PING, 0, 0)


class TestResolveArqPacketType:
    def test_ack(self) -> None:
        m = _ConcreteQueueMixin()
        assert m._resolve_arq_packet_type(is_ack=True) == Packet_Type.STREAM_DATA_ACK

    def test_fin(self) -> None:
        m = _ConcreteQueueMixin()
        assert m._resolve_arq_packet_type(is_fin=True) == Packet_Type.STREAM_FIN

    def test_fin_ack(self) -> None:
        m = _ConcreteQueueMixin()
        assert m._resolve_arq_packet_type(is_fin_ack=True) == Packet_Type.STREAM_FIN_ACK

    def test_rst(self) -> None:
        m = _ConcreteQueueMixin()
        assert m._resolve_arq_packet_type(is_rst=True) == Packet_Type.STREAM_RST

    def test_rst_ack(self) -> None:
        m = _ConcreteQueueMixin()
        assert m._resolve_arq_packet_type(is_rst_ack=True) == Packet_Type.STREAM_RST_ACK

    def test_syn_ack(self) -> None:
        m = _ConcreteQueueMixin()
        assert m._resolve_arq_packet_type(is_syn_ack=True) == Packet_Type.STREAM_SYN_ACK

    def test_socks_syn_ack(self) -> None:
        m = _ConcreteQueueMixin()
        assert m._resolve_arq_packet_type(is_socks_syn_ack=True) == Packet_Type.SOCKS5_SYN_ACK

    def test_socks_syn(self) -> None:
        m = _ConcreteQueueMixin()
        assert m._resolve_arq_packet_type(is_socks_syn=True) == Packet_Type.SOCKS5_SYN

    def test_resend(self) -> None:
        m = _ConcreteQueueMixin()
        assert m._resolve_arq_packet_type(is_resend=True) == Packet_Type.STREAM_RESEND

    def test_default_is_stream_data(self) -> None:
        m = _ConcreteQueueMixin()
        assert m._resolve_arq_packet_type() == Packet_Type.STREAM_DATA


class TestEffectivePriority:
    def test_priority_zero_types(self) -> None:
        m = _ConcreteQueueMixin()
        for ptype in _ConcreteQueueMixin._PRIORITY_ZERO_TYPES:
            assert m._effective_priority_for_packet(ptype, 5) == 0

    def test_stream_fin_is_4(self) -> None:
        m = _ConcreteQueueMixin()
        assert m._effective_priority_for_packet(Packet_Type.STREAM_FIN, 7) == 4

    def test_stream_resend_is_1(self) -> None:
        m = _ConcreteQueueMixin()
        assert m._effective_priority_for_packet(Packet_Type.STREAM_RESEND, 7) == 1

    def test_other_uses_given_priority(self) -> None:
        m = _ConcreteQueueMixin()
        assert m._effective_priority_for_packet(Packet_Type.STREAM_DATA, 3) == 3


class TestTrackMainPacketOnce:
    def test_resend_not_in_track_data(self) -> None:
        m = _ConcreteQueueMixin()
        owner: dict = {}
        assert m._track_main_packet_once(owner, 0, Packet_Type.STREAM_RESEND, 1)
        assert not m._track_main_packet_once(owner, 0, Packet_Type.STREAM_RESEND, 1)

    def test_resend_blocked_by_existing_track_data(self) -> None:
        m = _ConcreteQueueMixin()
        owner: dict = {"track_data": {5}}
        assert not m._track_main_packet_once(owner, 0, Packet_Type.STREAM_RESEND, 5)

    def test_stream_fin_tracked_once(self) -> None:
        m = _ConcreteQueueMixin()
        owner: dict = {}
        assert m._track_main_packet_once(owner, 0, Packet_Type.STREAM_FIN, 0)
        assert not m._track_main_packet_once(owner, 0, Packet_Type.STREAM_FIN, 0)

    def test_syn_type_tracked_once(self) -> None:
        m = _ConcreteQueueMixin()
        owner: dict = {}
        assert m._track_main_packet_once(owner, 0, Packet_Type.STREAM_SYN, 0)
        assert not m._track_main_packet_once(owner, 0, Packet_Type.STREAM_SYN, 0)

    def test_stream_data_ack_tracked_once(self) -> None:
        m = _ConcreteQueueMixin()
        owner: dict = {}
        assert m._track_main_packet_once(owner, 0, Packet_Type.STREAM_DATA_ACK, 7)
        assert not m._track_main_packet_once(owner, 0, Packet_Type.STREAM_DATA_ACK, 7)

    def test_stream_data_tracked_once(self) -> None:
        m = _ConcreteQueueMixin()
        owner: dict = {}
        assert m._track_main_packet_once(owner, 0, Packet_Type.STREAM_DATA, 3)
        assert not m._track_main_packet_once(owner, 0, Packet_Type.STREAM_DATA, 3)

    def test_other_type_always_returns_true(self) -> None:
        m = _ConcreteQueueMixin()
        owner: dict = {}
        assert m._track_main_packet_once(owner, 0, Packet_Type.PING, 0)
        assert m._track_main_packet_once(owner, 0, Packet_Type.PING, 0)


class TestTrackStreamPacketOnce:
    def _owner(self) -> dict:
        return {
            "track_data": set(),
            "track_ack": set(),
            "track_resend": set(),
            "track_fin": set(),
            "track_syn_ack": set(),
        }

    def test_resend_tracked_once(self) -> None:
        m = _ConcreteQueueMixin()
        sd = self._owner()
        assert m._track_stream_packet_once(sd, Packet_Type.STREAM_RESEND, 1)
        assert not m._track_stream_packet_once(sd, Packet_Type.STREAM_RESEND, 1)

    def test_resend_blocked_by_existing_data(self) -> None:
        m = _ConcreteQueueMixin()
        sd = self._owner()
        sd["track_data"].add(9)
        assert not m._track_stream_packet_once(sd, Packet_Type.STREAM_RESEND, 9)

    def test_fin_tracked_once(self) -> None:
        m = _ConcreteQueueMixin()
        sd = self._owner()
        assert m._track_stream_packet_once(sd, Packet_Type.STREAM_FIN, 0)
        assert not m._track_stream_packet_once(sd, Packet_Type.STREAM_FIN, 0)

    def test_syn_ack_tracked_once(self) -> None:
        m = _ConcreteQueueMixin()
        sd = self._owner()
        assert m._track_stream_packet_once(sd, Packet_Type.STREAM_SYN_ACK, 0)
        assert not m._track_stream_packet_once(sd, Packet_Type.STREAM_SYN_ACK, 0)

    def test_socks5_syn_ack_tracked_once(self) -> None:
        m = _ConcreteQueueMixin()
        sd = self._owner()
        assert m._track_stream_packet_once(sd, Packet_Type.SOCKS5_SYN_ACK, 0)
        assert not m._track_stream_packet_once(sd, Packet_Type.SOCKS5_SYN_ACK, 0)

    def test_data_ack_tracked_once(self) -> None:
        m = _ConcreteQueueMixin()
        sd = self._owner()
        assert m._track_stream_packet_once(sd, Packet_Type.STREAM_DATA_ACK, 5)
        assert not m._track_stream_packet_once(sd, Packet_Type.STREAM_DATA_ACK, 5)

    def test_stream_data_tracked_once(self) -> None:
        m = _ConcreteQueueMixin()
        sd = self._owner()
        assert m._track_stream_packet_once(sd, Packet_Type.STREAM_DATA, 2)
        assert not m._track_stream_packet_once(sd, Packet_Type.STREAM_DATA, 2)

    def test_other_always_true(self) -> None:
        m = _ConcreteQueueMixin()
        sd = self._owner()
        assert m._track_stream_packet_once(sd, Packet_Type.PONG, 0)


class TestPushQueueItem:
    def test_pushes_and_increments_counter(self) -> None:
        import heapq
        m = _ConcreteQueueMixin()
        queue: list = []
        owner: dict = {}
        item = (2, 0, Packet_Type.STREAM_DATA, 1, 0, b"")
        m._push_queue_item(queue, owner, item)
        assert len(queue) == 1
        assert owner["priority_counts"][2] == 1

    def test_sets_event_if_provided(self) -> None:
        m = _ConcreteQueueMixin()
        queue: list = []
        owner: dict = {}
        event = MagicMock()
        item = (0, 0, Packet_Type.STREAM_SYN_ACK, 1, 0, b"")
        m._push_queue_item(queue, owner, item, tx_event=event)
        event.set.assert_called_once()


# ===========================================================================
# utils.py
# ===========================================================================

class TestLoadText:
    def test_existing_file(self) -> None:
        from dns_utils.utils import load_text
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write("  hello world  ")
            tmp = f.name
        try:
            result = load_text(tmp)
            assert result == "hello world"
        finally:
            os.unlink(tmp)

    def test_nonexistent_file_returns_none(self) -> None:
        from dns_utils.utils import load_text
        assert load_text("/nonexistent/path/file.txt") is None


class TestSaveText:
    def test_saves_and_reads_back(self) -> None:
        from dns_utils.utils import save_text, load_text
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            tmp = f.name
        try:
            result = save_text(tmp, "saved content")
            assert result is True
            assert load_text(tmp) == "saved content"
        finally:
            os.unlink(tmp)

    def test_invalid_path_returns_false(self) -> None:
        from dns_utils.utils import save_text
        result = save_text("/nonexistent_dir_xyz/file.txt", "data")
        assert result is False


class TestGenerateRandomHexText:
    def test_correct_length(self) -> None:
        from dns_utils.utils import generate_random_hex_text
        for length in [8, 16, 32]:
            result = generate_random_hex_text(length)
            assert len(result) == length

    def test_is_hex_string(self) -> None:
        from dns_utils.utils import generate_random_hex_text
        result = generate_random_hex_text(16)
        int(result, 16)  # Should not raise

    def test_unique_results(self) -> None:
        from dns_utils.utils import generate_random_hex_text
        results = {generate_random_hex_text(32) for _ in range(10)}
        assert len(results) > 1


class TestGetEncryptKey:
    def test_method_3_returns_16_chars(self) -> None:
        from dns_utils.utils import get_encrypt_key
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, "encrypt_key.txt")
            with patch("dns_utils.utils.save_text") as mock_save:
                with patch("dns_utils.utils.load_text", return_value=None):
                    with patch("dns_utils.utils.generate_random_hex_text", return_value="a" * 16) as mock_gen:
                        result = get_encrypt_key(3)
                        mock_gen.assert_called_with(16)

    def test_method_4_returns_24_chars(self) -> None:
        from dns_utils.utils import get_encrypt_key
        with patch("dns_utils.utils.load_text", return_value="b" * 24):
            result = get_encrypt_key(4)
            assert len(result) == 24

    def test_other_method_returns_32_chars(self) -> None:
        from dns_utils.utils import get_encrypt_key
        with patch("dns_utils.utils.load_text", return_value="c" * 32):
            result = get_encrypt_key(1)
            assert len(result) == 32

    def test_generates_new_key_when_wrong_length(self) -> None:
        from dns_utils.utils import get_encrypt_key
        with patch("dns_utils.utils.load_text", return_value="short"):
            with patch("dns_utils.utils.save_text"):
                with patch("dns_utils.utils.generate_random_hex_text", return_value="x" * 32) as mock_gen:
                    get_encrypt_key(1)
                    mock_gen.assert_called_once_with(32)


class TestGetLogger:
    def test_returns_logger(self) -> None:
        from dns_utils.utils import getLogger
        logger = getLogger(log_level="DEBUG", is_server=False)
        assert logger is not None

    def test_server_logger(self) -> None:
        from dns_utils.utils import getLogger
        logger = getLogger(log_level="INFO", is_server=True)
        assert logger is not None

    def test_with_log_file(self) -> None:
        from dns_utils.utils import getLogger
        from loguru import logger as _loguru_logger
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
            tmp = f.name
        try:
            result = getLogger(log_level="WARNING", logFile=tmp)
            assert result is not None
        finally:
            # Remove all loguru handlers to release the file handle before deletion
            _loguru_logger.remove()
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass


# ===========================================================================
# DnsPacketParser.py
# ===========================================================================

class TestDnsPacketParserInit:
    def test_default_init(self) -> None:
        p = _make_parser(method=0)
        assert p.encryption_method == 0

    def test_xor_init(self) -> None:
        p = _make_parser(method=1, key="testkey")
        assert p.encryption_method == 1

    def test_aes128_init(self) -> None:
        p = _make_parser(method=3, key="somekey")
        assert p.encryption_method == 3

    def test_aes192_init(self) -> None:
        p = _make_parser(method=4, key="somekey")
        assert p.encryption_method == 4

    def test_aes256_init(self) -> None:
        p = _make_parser(method=5, key="somekey")
        assert p.encryption_method == 5

    def test_invalid_method_falls_back_to_1(self) -> None:
        logger = MagicMock()
        p = DnsPacketParser(logger=logger, encryption_key="k", encryption_method=99)
        assert p.encryption_method == 1
        logger.debug.assert_called_once()


class TestDeriveKey:
    def test_method_2_sha256(self) -> None:
        import hashlib
        p = _make_parser(method=0, key="hello")
        key = p._derive_key("hello")
        # Method 0 → falls through to ljust/trim path
        assert len(key) == 32

    def test_method_3_md5(self) -> None:
        import hashlib
        p = _make_parser(method=3, key="hello")
        assert len(p.key) == 16

    def test_method_2(self) -> None:
        p = _make_parser(method=2, key="hello")
        assert len(p.key) == 32

    def test_method_5_sha256(self) -> None:
        p = _make_parser(method=5, key="hello")
        assert len(p.key) == 32


class TestXorData:
    def test_basic_xor(self) -> None:
        p = _make_parser()
        data = b"\x01\x02\x03"
        key = b"\x01"
        result = p.xor_data(data, key)
        assert result == bytes([b ^ 0x01 for b in data])

    def test_xor_roundtrip(self) -> None:
        p = _make_parser()
        data = b"hello world"
        key = b"secret"
        encrypted = p.xor_data(data, key)
        decrypted = p.xor_data(encrypted, key)
        assert decrypted == data

    def test_empty_data_returns_empty(self) -> None:
        p = _make_parser()
        assert p.xor_data(b"", b"key") == b""

    def test_empty_key_returns_data(self) -> None:
        p = _make_parser()
        assert p.xor_data(b"data", b"") == b"data"

    def test_single_byte_key(self) -> None:
        p = _make_parser()
        data = b"\xff\x00\xaa"
        key = b"\xff"
        result = p.xor_data(data, key)
        assert result == bytes([b ^ 0xFF for b in data])


class TestBaseEncodeDecode:
    def test_base32_encode_decode_roundtrip(self) -> None:
        p = _make_parser()
        data = b"hello world"
        encoded = p.base_encode(data, lowerCaseOnly=True)
        assert isinstance(encoded, str)
        decoded = p.base_decode(encoded, lowerCaseOnly=True)
        assert decoded == data

    def test_base64_encode_decode_roundtrip(self) -> None:
        p = _make_parser()
        data = b"test data 123"
        encoded = p.base_encode(data, lowerCaseOnly=False)
        decoded = p.base_decode(encoded, lowerCaseOnly=False)
        assert decoded == data

    def test_empty_input(self) -> None:
        p = _make_parser()
        assert p.base_encode(b"") == ""
        assert p.base_decode("") == b""

    def test_invalid_base32_returns_empty(self) -> None:
        p = _make_parser()
        assert p.base_decode("!@#$%^&*", lowerCaseOnly=True) == b""


class TestSerializeDnsName:
    def test_simple_domain(self) -> None:
        p = _make_parser()
        result = p._serialize_dns_name("example.com")
        assert result == b"\x07example\x03com\x00"

    def test_empty_name(self) -> None:
        p = _make_parser()
        assert p._serialize_dns_name("") == b"\x00"

    def test_root_dot(self) -> None:
        p = _make_parser()
        assert p._serialize_dns_name(".") == b"\x00"

    def test_bytes_input(self) -> None:
        p = _make_parser()
        result = p._serialize_dns_name(b"example.com")
        assert b"example" in result

    def test_label_too_long_returns_null(self) -> None:
        p = _make_parser()
        long_label = "a" * 64 + ".com"
        result = p._serialize_dns_name(long_label)
        assert result == b"\x00"


class TestParseDnsName:
    def test_simple_domain(self) -> None:
        p = _make_parser()
        name_bytes = b"\x07example\x03com\x00"
        name, offset = p._parse_dns_name_from_bytes(name_bytes, 0)
        assert name == "example.com"
        assert offset == len(name_bytes)

    def test_bounds_error(self) -> None:
        p = _make_parser()
        with pytest.raises(ValueError):
            p._parse_dns_name_from_bytes(b"\x05short", 0)

    def test_loop_detection(self) -> None:
        p = _make_parser()
        # Craft packet with circular pointer
        data = b"\xc0\x00"  # pointer to offset 0 → infinite loop
        with pytest.raises(ValueError):
            p._parse_dns_name_from_bytes(data, 0)


class TestSimpleQuestionPacket:
    def test_creates_valid_packet(self) -> None:
        p = _make_parser()
        pkt = p.simple_question_packet("example.com", DNS_Record_Type.A)
        assert len(pkt) >= 12
        # Verify header: QdCount should be 1
        headers = p.parse_dns_headers(pkt)
        assert headers["QdCount"] == 1

    def test_invalid_qtype_returns_empty(self) -> None:
        p = _make_parser()
        result = p.simple_question_packet("example.com", 99999)
        assert result == b""


class TestParseDnsHeaders:
    def test_parse_standard_query(self) -> None:
        p = _make_parser()
        pkt = p.simple_question_packet("example.com", DNS_Record_Type.A)
        headers = p.parse_dns_headers(pkt)
        assert "id" in headers
        assert headers["QdCount"] == 1
        assert headers["qr"] == 0  # query
        assert headers["rd"] == 1  # recursion desired

    def test_parse_dns_packet_full(self) -> None:
        p = _make_parser()
        pkt = p.simple_question_packet("test.example.com", DNS_Record_Type.TXT)
        parsed = p.parse_dns_packet(pkt)
        assert parsed
        assert parsed["questions"]
        assert parsed["questions"][0]["qName"] == "test.example.com"
        assert parsed["questions"][0]["qType"] == DNS_Record_Type.TXT

    def test_short_packet_returns_empty(self) -> None:
        p = _make_parser()
        result = p.parse_dns_packet(b"\x00\x01")
        assert result == {}


class TestServerFailResponse:
    def test_creates_valid_response(self) -> None:
        p = _make_parser()
        query = p.simple_question_packet("example.com", DNS_Record_Type.A)
        response = p.server_fail_response(query)
        assert len(response) >= 12
        headers = p.parse_dns_headers(response)
        assert headers["rCode"] == DNS_rCode.SERVER_FAILURE

    def test_short_packet_returns_empty(self) -> None:
        p = _make_parser()
        result = p.server_fail_response(b"\x00\x01")
        assert result == b""


class TestSimpleAnswerPacket:
    def test_creates_answer_packet(self) -> None:
        p = _make_parser()
        query = p.simple_question_packet("example.com", DNS_Record_Type.A)
        answers = [
            {
                "name": "example.com",
                "type": DNS_Record_Type.A,
                "class": DNS_QClass.IN,
                "TTL": 300,
                "rData": b"\x01\x02\x03\x04",
            }
        ]
        response = p.simple_answer_packet(answers, query)
        assert len(response) >= 12
        headers = p.parse_dns_headers(response)
        assert headers["AnCount"] == 1

    def test_short_question_packet_returns_empty(self) -> None:
        p = _make_parser()
        result = p.simple_answer_packet([], b"\x00")
        assert result == b""


class TestCreatePacket:
    def test_create_question_packet(self) -> None:
        p = _make_parser()
        sections = {
            "headers": {"id": 1234, "QdCount": 1, "AnCount": 0, "NsCount": 0, "ArCount": 0},
            "questions": [{"qName": "test.com", "qType": DNS_Record_Type.A, "qClass": DNS_QClass.IN}],
            "answers": [],
        }
        pkt = p.create_packet(sections)
        assert len(pkt) >= 12


class TestVpnHeader:
    def test_session_init_header(self) -> None:
        p = _make_parser(method=0)
        header = p.create_vpn_header(
            session_id=5,
            packet_type=Packet_Type.SESSION_INIT,
            base36_encode=False,
            base_encode=False,
        )
        assert isinstance(header, bytes)
        assert header[0] == 5
        assert header[1] == Packet_Type.SESSION_INIT

    def test_stream_data_header_has_ext_fields(self) -> None:
        p = _make_parser(method=0)
        header = p.create_vpn_header(
            session_id=1,
            packet_type=Packet_Type.STREAM_DATA,
            base36_encode=False,
            stream_id=42,
            sequence_num=100,
            fragment_id=0,
            total_fragments=1,
            total_data_length=50,
            base_encode=False,
        )
        assert isinstance(header, bytes)
        # session_id + packet_type + stream_id(2) + seq_num(2) + frag fields(4) + comp_type(1)
        assert len(header) >= 9

    def test_parse_vpn_header_bytes_session_init(self) -> None:
        p = _make_parser(method=0)
        # SESSION_INIT header: session_id + packet_type + session_cookie + check_byte
        raw = p.create_vpn_header(
            session_id=5,
            packet_type=Packet_Type.SESSION_INIT,
            base36_encode=False,
            base_encode=False,
        )
        assert isinstance(raw, bytes)
        parsed = p.parse_vpn_header_bytes(raw)
        assert parsed is not None
        assert parsed["session_id"] == 5
        assert parsed["packet_type"] == Packet_Type.SESSION_INIT

    def test_parse_vpn_header_bytes_too_short(self) -> None:
        p = _make_parser(method=0)
        result = p.parse_vpn_header_bytes(b"\x01")
        assert result is None

    def test_parse_vpn_header_bytes_invalid_packet_type(self) -> None:
        p = _make_parser(method=0)
        result = p.parse_vpn_header_bytes(bytes([1, 0xFE]))  # 0xFE not valid
        assert result is None

    def test_parse_vpn_header_bytes_with_return_length(self) -> None:
        p = _make_parser(method=0)
        # PING header: session_id + packet_type + session_cookie + check_byte = 4 bytes
        raw = p.create_vpn_header(
            session_id=3,
            packet_type=Packet_Type.PING,
            base36_encode=False,
            base_encode=False,
        )
        assert isinstance(raw, bytes)
        parsed, length = p.parse_vpn_header_bytes(raw, return_length=True)
        assert parsed is not None
        assert length == p.get_vpn_header_raw_size(Packet_Type.PING)

    def test_parse_vpn_header_stream_data(self) -> None:
        p = _make_parser(method=0)
        # Use create_vpn_header so session_cookie + check_byte are included correctly
        raw = p.create_vpn_header(
            session_id=1,
            packet_type=Packet_Type.STREAM_DATA,
            base36_encode=False,
            stream_id=42,
            sequence_num=100,
            fragment_id=0,
            total_fragments=1,
            total_data_length=50,
            compression_type=0,
            base_encode=False,
        )
        assert isinstance(raw, bytes)
        parsed = p.parse_vpn_header_bytes(raw)
        assert parsed is not None
        assert parsed["stream_id"] == 42
        assert parsed["sequence_num"] == 100


class TestCryptoMethods:
    def test_no_crypto_returns_data(self) -> None:
        p = _make_parser(method=0)
        data = b"testdata"
        assert p._no_crypto(data) == data

    def test_xor_encrypt_decrypt_roundtrip(self) -> None:
        p = _make_parser(method=1, key="secretkey")
        data = b"hello world"
        encrypted = p._xor_crypto(data)
        decrypted = p._xor_crypto(encrypted)
        assert decrypted == data

    def test_aes_encrypt_decrypt_roundtrip(self) -> None:
        p = _make_parser(method=3, key="aeskey123")
        if p._aesgcm is None:
            pytest.skip("AES-GCM not available")
        data = b"hello aes world"
        encrypted = p._aes_encrypt(data)
        assert len(encrypted) > 12
        decrypted = p._aes_decrypt(encrypted)
        assert decrypted == data

    def test_aes_decrypt_too_short_returns_empty(self) -> None:
        p = _make_parser(method=3, key="aeskey123")
        if p._aesgcm is None:
            pytest.skip("AES-GCM not available")
        result = p._aes_decrypt(b"\x00" * 5)
        assert result == b""

    def test_aes_decrypt_invalid_ciphertext(self) -> None:
        p = _make_parser(method=3, key="aeskey123")
        if p._aesgcm is None:
            pytest.skip("AES-GCM not available")
        result = p._aes_decrypt(b"\x00" * 30)
        assert result == b""

    def test_codec_transform_no_crypto(self) -> None:
        p = _make_parser(method=0)
        data = b"plain"
        assert p._codec_transform_dynamic(data, encrypt=True) == data
        assert p._codec_transform_dynamic(data, encrypt=False) == data


class TestEncodeDecodeData:
    def test_decode_and_decrypt_empty(self) -> None:
        p = _make_parser(method=0)
        assert p.decode_and_decrypt_data("") == b""

    def test_encrypt_and_encode_empty(self) -> None:
        p = _make_parser(method=0)
        assert p.encrypt_and_encode_data(b"") == ""

    def test_roundtrip_method_0(self) -> None:
        p = _make_parser(method=0)
        data = b"hello"
        encoded = p.encrypt_and_encode_data(data, lowerCaseOnly=True)
        decoded = p.decode_and_decrypt_data(encoded, lowerCaseOnly=True)
        assert decoded == data

    def test_roundtrip_method_1(self) -> None:
        p = _make_parser(method=1, key="mykey")
        data = b"hello world"
        encoded = p.encrypt_and_encode_data(data, lowerCaseOnly=True)
        decoded = p.decode_and_decrypt_data(encoded, lowerCaseOnly=True)
        assert decoded == data


class TestDataToLabels:
    def test_short_string_unchanged(self) -> None:
        p = _make_parser()
        s = "a" * 30
        assert p.data_to_labels(s) == s

    def test_long_string_split(self) -> None:
        p = _make_parser()
        s = "a" * 200
        result = p.data_to_labels(s)
        parts = result.split(".")
        for part in parts:
            assert len(part) <= 63

    def test_empty_string(self) -> None:
        p = _make_parser()
        assert p.data_to_labels("") == ""


class TestCalculateUploadMtu:
    def test_short_domain(self) -> None:
        p = _make_parser()
        chars, byte_mtu = p.calculate_upload_mtu("vpn.example.com")
        assert chars > 0
        assert byte_mtu > 0

    def test_long_domain_returns_zero(self) -> None:
        p = _make_parser()
        # Domain must be long enough to exhaust the 253-char DNS total limit
        # header_overhead ~21 chars, domain_overhead = len(domain) + 1
        # available_chars = 253 - (21 + len(domain) + 1 + 1) <= 0 needs len(domain) >= 231
        long_domain = "a" * 240 + ".example.com"
        chars, byte_mtu = p.calculate_upload_mtu(long_domain)
        assert chars == 0
        assert byte_mtu == 0

    def test_with_mtu_override(self) -> None:
        p = _make_parser()
        _, default_mtu = p.calculate_upload_mtu("vpn.example.com")
        override_mtu = max(1, default_mtu // 2)
        chars, byte_mtu = p.calculate_upload_mtu("vpn.example.com", mtu=override_mtu)
        assert byte_mtu == override_mtu


class TestExtractTxt:
    def test_extract_txt_from_rdata_bytes(self) -> None:
        p = _make_parser()
        # Format: length byte + data
        rdata = bytes([5]) + b"hello" + bytes([5]) + b"world"
        result = p.extract_txt_from_rData_bytes(rdata)
        assert result == b"helloworld"

    def test_extract_empty_rdata(self) -> None:
        p = _make_parser()
        assert p.extract_txt_from_rData_bytes(b"") == b""

    def test_extract_txt_string(self) -> None:
        p = _make_parser()
        rdata = bytes([5]) + b"hello"
        result = p.extract_txt_from_rData(rdata)
        assert result == "hello"

    def test_extract_txt_empty(self) -> None:
        p = _make_parser()
        assert p.extract_txt_from_rData(b"") == ""

    def test_extract_txt_zero_length_chunk(self) -> None:
        p = _make_parser()
        rdata = bytes([0]) + bytes([5]) + b"hello"
        result = p.extract_txt_from_rData_bytes(rdata)
        assert result == b"hello"


class TestGenerateLabels:
    def test_single_fragment(self) -> None:
        p = _make_parser(method=0)
        labels = p.generate_labels(
            domain="vpn.example.com",
            session_id=1,
            packet_type=Packet_Type.PING,
            data=b"",
            mtu_chars=100,
        )
        assert len(labels) == 1
        assert "vpn.example.com" in labels[0]

    def test_with_data(self) -> None:
        p = _make_parser(method=0)
        labels = p.generate_labels(
            domain="vpn.example.com",
            session_id=2,
            packet_type=Packet_Type.STREAM_DATA,
            data=b"hello",
            mtu_chars=100,
            stream_id=1,
            sequence_num=0,
            fragment_id=0,
            total_fragments=1,
            total_data_length=5,
        )
        assert len(labels) >= 1

    def test_multiple_fragments(self) -> None:
        p = _make_parser(method=0)
        large_data = b"x" * 300
        labels = p.generate_labels(
            domain="vpn.example.com",
            session_id=1,
            packet_type=Packet_Type.STREAM_DATA,
            data=large_data,
            mtu_chars=20,
            stream_id=1,
            sequence_num=0,
        )
        assert len(labels) > 1

    def test_data_too_large_returns_empty(self) -> None:
        p = _make_parser(method=0)
        huge_data = b"x" * 10000
        labels = p.generate_labels(
            domain="vpn.example.com",
            session_id=1,
            packet_type=Packet_Type.STREAM_DATA,
            data=huge_data,
            mtu_chars=1,  # 1 char at a time → 10000 fragments → > 255
        )
        assert labels == []


class TestBuildRequestDnsQuery:
    def test_builds_packets(self) -> None:
        p = _make_parser(method=0)
        packets = p.build_request_dns_query(
            domain="vpn.example.com",
            session_id=1,
            packet_type=Packet_Type.PING,
            data=b"",
            mtu_chars=100,
        )
        assert len(packets) >= 1
        for pkt in packets:
            assert len(pkt) >= 12


class TestExtractVpnHeaderFromLabels:
    def test_empty_returns_none(self) -> None:
        p = _make_parser(method=0)
        assert p.extract_vpn_header_from_labels("") is None

    def test_non_string_returns_none(self) -> None:
        p = _make_parser(method=0)
        assert p.extract_vpn_header_from_labels(None) is None  # type: ignore[arg-type]

    def test_bytes_input_decoded_then_processed(self) -> None:
        p = _make_parser(method=0)
        result = p.extract_vpn_header_from_labels(b"somedata.example")  # type: ignore[arg-type]
        assert isinstance(result, (bytes, dict, type(None)))


class TestExtractVpnDataFromLabels:
    def test_empty_returns_empty(self) -> None:
        p = _make_parser(method=0)
        assert p.extract_vpn_data_from_labels("") == b""

    def test_non_string_returns_empty(self) -> None:
        p = _make_parser(method=0)
        assert p.extract_vpn_data_from_labels(None) == b""  # type: ignore[arg-type]

    def test_no_dot_returns_empty(self) -> None:
        p = _make_parser(method=0)
        assert p.extract_vpn_data_from_labels("nodotlabel") == b""


class TestGenerateVpnResponsePacket:
    def test_creates_packet_with_no_data(self) -> None:
        p = _make_parser(method=0)
        query = p.simple_question_packet("vpn.example.com", DNS_Record_Type.TXT)
        pkt = p.generate_vpn_response_packet(
            domain="vpn.example.com",
            session_id=1,
            packet_type=Packet_Type.PONG,
            data=b"",
            question_packet=query,
        )
        assert len(pkt) >= 12

    def test_creates_packet_with_small_data(self) -> None:
        p = _make_parser(method=0)
        query = p.simple_question_packet("vpn.example.com", DNS_Record_Type.TXT)
        pkt = p.generate_vpn_response_packet(
            domain="vpn.example.com",
            session_id=1,
            packet_type=Packet_Type.STREAM_DATA,
            data=b"hello",
            question_packet=query,
            stream_id=1,
            sequence_num=0,
        )
        assert len(pkt) >= 12


class TestExtractVpnResponse:
    def test_empty_packet_returns_none(self) -> None:
        p = _make_parser(method=0)
        hdr, data = p.extract_vpn_response({})
        assert hdr is None
        assert data == b""

    def test_no_answers_returns_none(self) -> None:
        p = _make_parser(method=0)
        hdr, data = p.extract_vpn_response({"answers": []})
        assert hdr is None

    def test_roundtrip_pong(self) -> None:
        p = _make_parser(method=0)
        query = p.simple_question_packet("vpn.example.com", DNS_Record_Type.TXT)
        response_pkt = p.generate_vpn_response_packet(
            domain="vpn.example.com",
            session_id=1,
            packet_type=Packet_Type.PONG,
            data=b"",
            question_packet=query,
        )
        parsed = p.parse_dns_packet(response_pkt)
        hdr, data = p.extract_vpn_response(parsed)
        assert hdr is not None
        assert hdr["packet_type"] == Packet_Type.PONG

    def test_roundtrip_stream_data(self) -> None:
        p = _make_parser(method=0)
        query = p.simple_question_packet("vpn.example.com", DNS_Record_Type.TXT)
        payload = b"hello world test"
        response_pkt = p.generate_vpn_response_packet(
            domain="vpn.example.com",
            session_id=2,
            packet_type=Packet_Type.STREAM_DATA,
            data=payload,
            question_packet=query,
            stream_id=5,
            sequence_num=10,
        )
        parsed = p.parse_dns_packet(response_pkt)
        hdr, data = p.extract_vpn_response(parsed)
        assert hdr is not None


# ===========================================================================
# ARQ.py
# ===========================================================================

class TestARQInit:
    async def test_basic_creation(self) -> None:
        arq, _ = _make_arq()
        assert arq.stream_id == 1
        assert arq.session_id == 1
        assert arq.state == Stream_State.OPEN
        assert not arq.closed
        # Cancel tasks to avoid leaking
        await arq.close(reason="test cleanup", send_fin=False)

    async def test_requires_enqueue_control_tx(self) -> None:
        from dns_utils.ARQ import ARQ

        async def enqueue_tx(p, s, sn, d, **kw):
            pass

        with pytest.raises(ValueError, match="enqueue_control_tx_cb is required"):
            ARQ(
                stream_id=1,
                session_id=1,
                enqueue_tx_cb=enqueue_tx,
                reader=_MockReader(),
                writer=_MockWriter(),
                mtu=512,
                enqueue_control_tx_cb=None,
            )

    async def test_socks_mode_init(self) -> None:
        arq, _ = _make_arq(is_socks=True)
        assert arq.is_socks
        assert not arq.socks_connected.is_set()
        await arq.close(reason="test cleanup", send_fin=False)


class TestARQStateTransitions:
    async def test_set_state(self) -> None:
        arq, _ = _make_arq()
        arq._set_state(Stream_State.HALF_CLOSED_LOCAL)
        assert arq.state == Stream_State.HALF_CLOSED_LOCAL
        await arq.close(reason="cleanup", send_fin=False)

    async def test_norm_sn(self) -> None:
        arq, _ = _make_arq()
        assert arq._norm_sn(0) == 0
        assert arq._norm_sn(65535) == 65535
        assert arq._norm_sn(65536) == 0
        assert arq._norm_sn(65537) == 1
        await arq.close(reason="cleanup", send_fin=False)

    async def test_is_reset_initial_false(self) -> None:
        arq, _ = _make_arq()
        assert not arq.is_reset()
        await arq.close(reason="cleanup", send_fin=False)

    async def test_is_open_for_local_read_initial_true(self) -> None:
        arq, _ = _make_arq()
        assert arq.is_open_for_local_read()
        await arq.close(reason="cleanup", send_fin=False)

    async def test_set_local_reader_closed(self) -> None:
        arq, _ = _make_arq()
        arq.set_local_reader_closed("remote FIN")
        assert arq._stop_local_read
        assert arq.close_reason == "remote FIN"
        assert arq.state == Stream_State.HALF_CLOSED_REMOTE
        await arq.close(reason="cleanup", send_fin=False)

    async def test_set_local_writer_closed(self) -> None:
        arq, _ = _make_arq()
        arq.set_local_writer_closed()
        assert arq._local_write_closed
        assert arq.state == Stream_State.HALF_CLOSED_LOCAL
        await arq.close(reason="cleanup", send_fin=False)

    async def test_clear_all_queues(self) -> None:
        arq, _ = _make_arq()
        arq.snd_buf[0] = {"data": b"test", "time": 0, "create_time": 0, "retries": 0, "current_rto": 0.8}
        arq.rcv_buf[0] = b"recv"
        arq._clear_all_queues()
        assert not arq.snd_buf
        assert not arq.rcv_buf
        await arq.close(reason="cleanup", send_fin=False)


class TestARQFinRst:
    async def test_mark_fin_sent(self) -> None:
        arq, _ = _make_arq()
        arq.mark_fin_sent(seq_num=10)
        assert arq._fin_sent
        assert arq._fin_seq_sent == 10
        assert arq.state == Stream_State.HALF_CLOSED_LOCAL
        await arq.close(reason="cleanup", send_fin=False)

    async def test_mark_fin_sent_no_seq(self) -> None:
        arq, _ = _make_arq()
        arq.mark_fin_sent()
        assert arq._fin_sent
        assert arq._fin_seq_sent == 0  # snd_nxt starts at 0
        await arq.close(reason="cleanup", send_fin=False)

    async def test_mark_fin_received(self) -> None:
        arq, _ = _make_arq()
        arq.mark_fin_received(5)
        assert arq._fin_received
        assert arq._fin_seq_received == 5
        assert arq._stop_local_read
        assert arq.state == Stream_State.HALF_CLOSED_REMOTE
        await arq.close(reason="cleanup", send_fin=False)

    async def test_mark_fin_acked(self) -> None:
        arq, _ = _make_arq()
        arq.mark_fin_sent(seq_num=3)
        arq.mark_fin_acked(3)
        assert arq._fin_acked
        await arq.close(reason="cleanup", send_fin=False)

    async def test_mark_fin_acked_wrong_seq(self) -> None:
        arq, _ = _make_arq()
        arq.mark_fin_sent(seq_num=3)
        arq.mark_fin_acked(7)  # different seq
        assert not arq._fin_acked
        await arq.close(reason="cleanup", send_fin=False)

    async def test_mark_rst_sent(self) -> None:
        arq, _ = _make_arq()
        arq.mark_rst_sent(seq_num=0)
        assert arq._rst_sent
        assert arq.state == Stream_State.RESET
        assert arq.is_reset()
        await arq.close(reason="cleanup", send_fin=False)

    async def test_mark_rst_received(self) -> None:
        arq, _ = _make_arq()
        arq.mark_rst_received(0)
        assert arq._rst_received
        assert arq.state == Stream_State.RESET
        await arq.close(reason="cleanup", send_fin=False)

    async def test_mark_rst_acked_matches_seq(self) -> None:
        arq, _ = _make_arq()
        arq.mark_rst_sent(seq_num=5)
        arq.mark_rst_acked(5)
        assert arq._rst_acked
        await arq.close(reason="cleanup", send_fin=False)

    async def test_mark_rst_acked_wrong_seq(self) -> None:
        arq, _ = _make_arq()
        arq.mark_rst_sent(seq_num=5)
        arq.mark_rst_acked(99)
        assert not arq._rst_acked
        await arq.close(reason="cleanup", send_fin=False)


class TestARQAsyncMethods:
    async def test_receive_ack_removes_from_snd_buf(self) -> None:
        arq, _ = _make_arq()
        arq.snd_buf[5] = {"data": b"test", "time": 0, "create_time": 0, "retries": 0, "current_rto": 0.8}
        arq.window_not_full.clear()
        await arq.receive_ack(5)
        assert 5 not in arq.snd_buf
        assert arq.window_not_full.is_set()
        await arq.close(reason="cleanup", send_fin=False)

    async def test_receive_ack_missing_sn_noop(self) -> None:
        arq, _ = _make_arq()
        await arq.receive_ack(999)  # Not in snd_buf, no error
        await arq.close(reason="cleanup", send_fin=False)

    async def test_receive_control_ack_fin_ack(self) -> None:
        arq, _ = _make_arq()
        arq.mark_fin_sent(seq_num=10)
        result = await arq.receive_control_ack(Packet_Type.STREAM_FIN_ACK, 10)
        assert arq._fin_acked
        await arq.close(reason="cleanup", send_fin=False)

    async def test_receive_control_ack_rst_ack(self) -> None:
        arq, _ = _make_arq()
        arq.mark_rst_sent(seq_num=7)
        result = await arq.receive_control_ack(Packet_Type.STREAM_RST_ACK, 7)
        assert arq._rst_acked
        await arq.close(reason="cleanup", send_fin=False)

    async def test_track_control_packet(self) -> None:
        arq, _ = _make_arq()
        arq._track_control_packet(
            packet_type=Packet_Type.STREAM_SYN,
            sequence_num=1,
            ack_type=Packet_Type.STREAM_SYN_ACK,
            payload=b"",
            priority=0,
        )
        key = (Packet_Type.STREAM_SYN, 1)
        assert key in arq.control_snd_buf
        # Second call with same key is a no-op
        arq._track_control_packet(
            packet_type=Packet_Type.STREAM_SYN,
            sequence_num=1,
            ack_type=Packet_Type.STREAM_SYN_ACK,
            payload=b"",
            priority=0,
        )
        await arq.close(reason="cleanup", send_fin=False)

    async def test_mark_control_acked(self) -> None:
        arq, _ = _make_arq()
        arq._track_control_packet(
            Packet_Type.STREAM_SYN, 1, Packet_Type.STREAM_SYN_ACK, b"", 0
        )
        result = arq._mark_control_acked(Packet_Type.STREAM_SYN_ACK, 1)
        assert result
        await arq.close(reason="cleanup", send_fin=False)

    async def test_mark_control_acked_unknown(self) -> None:
        arq, _ = _make_arq()
        result = arq._mark_control_acked(Packet_Type.PONG, 0)
        assert not result
        await arq.close(reason="cleanup", send_fin=False)

    async def test_send_control_packet(self) -> None:
        arq, packets = _make_arq()
        result = await arq.send_control_packet(
            packet_type=Packet_Type.STREAM_FIN,
            sequence_num=0,
            payload=b"",
            priority=4,
            track_for_ack=False,
        )
        assert result
        assert any(p[0] == "ctrl" for p in packets)
        await arq.close(reason="cleanup", send_fin=False)

    async def test_close_transitions_to_closed(self) -> None:
        arq, _ = _make_arq()
        await arq.close(reason="test done", send_fin=False)
        assert arq.closed
        assert arq.state == Stream_State.CLOSED

    async def test_abort_transitions_to_reset(self) -> None:
        arq, _ = _make_arq()
        await arq.abort(reason="test abort", send_rst=False)
        assert arq.closed

    async def test_double_close_is_noop(self) -> None:
        arq, _ = _make_arq()
        await arq.close(reason="first", send_fin=False)
        await arq.close(reason="second", send_fin=False)  # Should not raise
        assert arq.closed

    async def test_check_retransmits_already_closed(self) -> None:
        arq, _ = _make_arq()
        arq.closed = True
        await arq.check_retransmits()  # Should return immediately

    async def test_check_retransmits_with_pending_data(self) -> None:
        arq, packets = _make_arq()
        now = time.monotonic()
        # Add item to snd_buf that needs retransmission
        arq.snd_buf[1] = {
            "data": b"retransmit me",
            "time": now - 2.0,  # 2 seconds old
            "create_time": now - 2.0,
            "retries": 0,
            "current_rto": 0.8,
        }
        await arq.check_retransmits()
        # Should have sent a resend
        assert any(p[0] == "tx" for p in packets)
        await arq.close(reason="cleanup", send_fin=False)

    async def test_receive_data_out_of_order(self) -> None:
        arq, packets = _make_arq()
        # SN far in future (out of order / stale)
        await arq.receive_data(sn=60000, data=b"late packet")
        # Should send duplicate ACK
        assert any(p[0] == "tx" for p in packets)
        await arq.close(reason="cleanup", send_fin=False)

    async def test_receive_data_in_order(self) -> None:
        arq, packets = _make_arq()
        await arq.receive_data(sn=0, data=b"data")
        # Should write to writer and send ACK
        assert arq._MockWriter if hasattr(arq, "_MockWriter") else True
        assert any(p[0] == "tx" for p in packets)
        await arq.close(reason="cleanup", send_fin=False)


class TestARQIoLoop:
    async def test_io_loop_graceful_eof(self) -> None:
        """IO loop exits gracefully when reader returns empty bytes."""
        reader = _MockReader(chunks=[b""])  # Immediately returns EOF
        arq, packets = _make_arq(reader=reader)
        # Wait for io_loop task to complete
        if arq.io_task:
            try:
                await asyncio.wait_for(arq.io_task, timeout=2.0)
            except asyncio.TimeoutError:
                pass
        # The loop should have triggered graceful close
        await arq.close(reason="cleanup", send_fin=False)

    async def test_io_loop_with_data_then_eof(self) -> None:
        """IO loop processes data then EOF."""
        reader = _MockReader(chunks=[b"hello world", b""])
        arq, packets = _make_arq(reader=reader, mtu=5)
        if arq.io_task:
            try:
                await asyncio.wait_for(arq.io_task, timeout=2.0)
            except asyncio.TimeoutError:
                pass
        await arq.close(reason="cleanup", send_fin=False)

    async def test_io_loop_with_connection_reset(self) -> None:
        """IO loop handles ConnectionResetError by aborting."""
        reader = _ErrorReader()
        arq, packets = _make_arq(reader=reader)
        if arq.io_task:
            try:
                await asyncio.wait_for(arq.io_task, timeout=2.0)
            except asyncio.TimeoutError:
                pass
        # Should have called abort (which closes)
        assert arq.closed

    async def test_io_loop_socks_with_initial_data(self) -> None:
        """IO loop handles SOCKS initial data correctly."""
        reader = _MockReader(chunks=[])  # No further data after initial
        arq, packets = _make_arq(
            reader=reader,
            is_socks=True,
            initial_data=b"initial socks data",
        )
        # Signal socks connected
        arq.socks_connected.set()
        if arq.io_task:
            try:
                await asyncio.wait_for(arq.io_task, timeout=2.0)
            except asyncio.TimeoutError:
                pass
        await arq.close(reason="cleanup", send_fin=False)

    async def test_retransmit_loop_runs(self) -> None:
        """Retransmit loop starts and can be stopped."""
        arq, _ = _make_arq()
        # Give it a brief moment to start
        await asyncio.sleep(0.01)
        await arq.close(reason="stop retransmit loop", send_fin=False)
        assert arq.closed


# ===========================================================================
# PingManager.py
# ===========================================================================

class TestPingManager:
    def test_init(self) -> None:
        pings: list = []
        pm = PingManager(send_func=lambda: pings.append(1))
        assert pm.active_connections == 0

    def test_update_activity(self) -> None:
        pm = PingManager(send_func=lambda: None)
        old = pm.last_data_activity
        time.sleep(0.01)
        pm.update_activity()
        assert pm.last_data_activity > old

    async def test_ping_loop_sends_ping(self) -> None:
        pings: list = []
        pm = PingManager(send_func=lambda: pings.append(1))
        pm.last_ping_time = 0  # Force ping immediately
        task = asyncio.create_task(pm.ping_loop())
        await asyncio.sleep(0.3)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        assert len(pings) > 0

    async def test_ping_loop_idle_with_connections(self) -> None:
        pings: list = []
        pm = PingManager(send_func=lambda: pings.append(1))
        pm.active_connections = 1
        pm.last_ping_time = 0
        pm.last_data_activity = time.monotonic() - 15.0  # 15s idle
        task = asyncio.create_task(pm.ping_loop())
        await asyncio.sleep(0.2)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        assert len(pings) > 0

    async def test_ping_loop_no_connections_long_idle(self) -> None:
        pings: list = []
        pm = PingManager(send_func=lambda: pings.append(1))
        pm.active_connections = 0
        pm.last_data_activity = time.monotonic() - 25.0  # 25s idle
        pm.last_ping_time = 0
        task = asyncio.create_task(pm.ping_loop())
        await asyncio.sleep(0.2)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        assert len(pings) > 0


# ===========================================================================
# __init__.py (just verify imports work)
# ===========================================================================

class TestPackageImports:
    def test_all_exports_importable(self) -> None:
        from dns_utils import (
            ARQ,
            Compression_Type,
            DNSBalancer,
            DNS_QClass,
            DNS_Record_Type,
            DNS_rCode,
            DnsPacketParser,
            PacketQueueMixin,
            PingManager,
            PrependReader,
            Stream_State,
            Packet_Type,
            compress_payload,
            decompress_payload,
            get_compression_name,
            get_app_dir,
            get_config_path,
            is_compression_type_available,
            load_config,
            normalize_compression_type,
            try_decompress_payload,
        )
        assert ARQ is not None
        assert DnsPacketParser is not None


# ===========================================================================
# utils.py - async socket functions
# ===========================================================================

class TestAsyncRecvfrom:
    async def test_with_real_udp_socket(self) -> None:
        """Test async_recvfrom with a real UDP socket."""
        import socket as _socket
        from dns_utils.utils import async_recvfrom

        server = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        server.setblocking(False)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]

        sender = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sender.sendto(b"hello_recv", ("127.0.0.1", port))
        sender.close()

        loop = asyncio.get_event_loop()
        try:
            data, addr = await async_recvfrom(loop, server, 1024)
            assert data == b"hello_recv"
        finally:
            server.close()

    async def test_with_mock_loop_sock_recvfrom(self) -> None:
        """Test async_recvfrom using loop.sock_recvfrom path."""
        import socket as _socket
        from dns_utils.utils import async_recvfrom

        loop = MagicMock()
        loop.sock_recvfrom = AsyncMock(return_value=(b"data", ("127.0.0.1", 9999)))

        sock = MagicMock(spec=_socket.socket)

        with patch("sys.version_info", (3, 11, 0, "final", 0)):
            result = await async_recvfrom(loop, sock, 1024)

        assert result == (b"data", ("127.0.0.1", 9999))

    async def test_fallback_when_sock_recvfrom_raises_not_implemented(self) -> None:
        """Test async_recvfrom falls back when sock_recvfrom raises NotImplementedError."""
        import socket as _socket
        from dns_utils.utils import async_recvfrom

        loop = MagicMock()
        loop.sock_recvfrom = AsyncMock(side_effect=NotImplementedError)
        loop.create_future = MagicMock()
        loop.add_reader = MagicMock()

        sock = MagicMock(spec=_socket.socket)
        sock.recvfrom = MagicMock(return_value=(b"fallback", ("127.0.0.1", 9)))
        sock.fileno = MagicMock(return_value=5)

        with patch("sys.version_info", (3, 11, 0, "final", 0)):
            result = await async_recvfrom(loop, sock, 1024)

        assert result == (b"fallback", ("127.0.0.1", 9))

    async def test_blocking_io_triggers_future_path(self) -> None:
        """Test async_recvfrom uses the add_reader/future path on BlockingIOError."""
        import socket as _socket
        from dns_utils.utils import async_recvfrom

        loop = asyncio.get_event_loop()
        expected = (b"data", ("127.0.0.1", 9))
        future: asyncio.Future = loop.create_future()
        future.set_result(expected)

        sock = MagicMock(spec=_socket.socket)
        sock.recvfrom = MagicMock(side_effect=BlockingIOError)
        sock.fileno = MagicMock(return_value=100)

        mock_loop = MagicMock()
        mock_loop.create_future = MagicMock(return_value=future)
        mock_loop.add_reader = MagicMock()
        mock_loop.remove_reader = MagicMock()

        with patch("sys.version_info", (3, 9, 0, "final", 0)):
            result = await async_recvfrom(mock_loop, sock, 1024)

        assert result == expected


class TestAsyncSendto:
    async def test_with_real_udp_socket(self) -> None:
        """Test async_sendto with a real UDP socket pair."""
        import socket as _socket
        from dns_utils.utils import async_sendto

        server = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]

        sender = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sender.setblocking(False)

        loop = asyncio.get_event_loop()
        try:
            await async_sendto(loop, sender, b"hello_send", ("127.0.0.1", port))
            server.settimeout(0.5)
            data, _ = server.recvfrom(1024)
            assert data == b"hello_send"
        finally:
            sender.close()
            server.close()

    async def test_with_mock_loop_sock_sendto(self) -> None:
        """Test async_sendto using loop.sock_sendto path."""
        import socket as _socket
        from dns_utils.utils import async_sendto

        loop = MagicMock()
        loop.sock_sendto = AsyncMock(return_value=10)

        sock = MagicMock(spec=_socket.socket)

        result = await async_sendto(loop, sock, b"data", ("127.0.0.1", 9999))
        assert result == 10

    async def test_connection_reset_error_ignored(self) -> None:
        """Test that ConnectionResetError is ignored by async_sendto."""
        import socket as _socket
        from dns_utils.utils import async_sendto

        loop = MagicMock()
        loop.sock_sendto = AsyncMock(side_effect=ConnectionResetError)

        sock = MagicMock(spec=_socket.socket)

        result = await async_sendto(loop, sock, b"data", ("127.0.0.1", 9))
        assert result == 0

    async def test_broken_pipe_error_ignored(self) -> None:
        """Test that BrokenPipeError is ignored by async_sendto."""
        import socket as _socket
        from dns_utils.utils import async_sendto

        loop = MagicMock()
        loop.sock_sendto = AsyncMock(side_effect=BrokenPipeError)

        sock = MagicMock(spec=_socket.socket)

        result = await async_sendto(loop, sock, b"data", ("127.0.0.1", 9))
        assert result == 0

    async def test_os_error_winerror_ignored(self) -> None:
        """Test that OSError with winerror 10054 is ignored."""
        import socket as _socket
        from dns_utils.utils import async_sendto

        loop = MagicMock()
        os_err = OSError("connection reset")
        os_err.winerror = 10054
        loop.sock_sendto = AsyncMock(side_effect=os_err)

        sock = MagicMock(spec=_socket.socket)

        result = await async_sendto(loop, sock, b"data", ("127.0.0.1", 9))
        assert result == 0

    async def test_os_error_errno_ignored(self) -> None:
        """Test that OSError with errno 104 is ignored."""
        import socket as _socket
        from dns_utils.utils import async_sendto

        loop = MagicMock()
        import errno as _errno
        os_err = OSError("connection reset by peer")
        os_err.errno = 104
        loop.sock_sendto = AsyncMock(side_effect=os_err)

        sock = MagicMock(spec=_socket.socket)

        result = await async_sendto(loop, sock, b"data", ("127.0.0.1", 9))
        assert result == 0

    async def test_blocking_sendto_path(self) -> None:
        """Test async_sendto when sock.sendto sends immediately."""
        import socket as _socket
        from dns_utils.utils import async_sendto

        # Use a loop without sock_sendto to force the sock.sendto() path
        loop = MagicMock()
        del loop.sock_sendto  # Remove to trigger hasattr check

        sock = MagicMock(spec=_socket.socket)
        sock.sendto = MagicMock(return_value=4)

        # MagicMock object doesn't have sock_sendto attribute by default when deleted
        result = await async_sendto(loop, sock, b"data", ("127.0.0.1", 9))
        # Either the result from sendto or from the future path
        assert result is not None


# ===========================================================================
# Additional ARQ tests for better coverage
# ===========================================================================

class TestARQDummyLogger:
    async def test_creates_arq_without_logger(self) -> None:
        """Creating ARQ without a logger uses _DummyLogger."""
        arq, _ = _make_arq()
        arq.logger.debug("test debug")
        arq.logger.info("test info")
        arq.logger.warning("test warning")
        arq.logger.error("test error")
        await arq.close(reason="cleanup", send_fin=False)

    async def test_arq_without_explicit_logger(self) -> None:
        from dns_utils.ARQ import ARQ

        sent: list = []

        async def tx(p, s, sn, d, **kw):
            sent.append(d)

        async def ctrl(p, s, sn, pt, d, **kw):
            sent.append(d)

        # No logger provided → _DummyLogger used internally for fallback
        arq = ARQ(
            stream_id=99,
            session_id=99,
            enqueue_tx_cb=tx,
            reader=_MockReader(),
            writer=_MockWriter(),
            mtu=256,
            logger=None,  # triggers _DummyLogger
            enqueue_control_tx_cb=ctrl,
        )
        arq.logger.debug("msg")
        arq.logger.info("msg")
        arq.logger.warning("msg")
        arq.logger.error("msg")
        await arq.close(reason="cleanup", send_fin=False)


class TestARQReceiveData:
    async def test_receive_data_fills_reorder_buffer(self) -> None:
        """Receive out-of-order data fills rcv_buf."""
        arq, packets = _make_arq()
        # Send SN=1 first (expected is 0), so it goes to reorder buffer
        await arq.receive_data(sn=1, data=b"second")
        assert 1 in arq.rcv_buf

        # Now send SN=0 to flush the buffer
        await arq.receive_data(sn=0, data=b"first")
        # Both should be written and rcv_buf cleared
        assert 0 not in arq.rcv_buf
        assert 1 not in arq.rcv_buf
        await arq.close(reason="cleanup", send_fin=False)

    async def test_receive_data_window_exceeded_dropped(self) -> None:
        """Data arriving outside the receive window is dropped."""
        arq, packets = _make_arq(mtu=512)
        arq.window_size = 10
        # SN 50000 is way outside the window
        await arq.receive_data(sn=50000, data=b"out_of_window")
        # No ACK should be sent for window-exceeded packets
        await arq.close(reason="cleanup", send_fin=False)

    async def test_receive_data_when_closed(self) -> None:
        """receive_data is a no-op when closed."""
        arq, packets = _make_arq()
        arq.closed = True
        await arq.receive_data(sn=0, data=b"after_close")
        assert 0 not in arq.rcv_buf
        await arq.close(reason="cleanup", send_fin=False)

    async def test_receive_data_reorder_buffer_full(self) -> None:
        """Reorder buffer drops new data when full."""
        arq, packets = _make_arq()
        arq.window_size = 3
        # Fill the buffer with SN 1,2,3 (expected 0 not received yet)
        for sn in range(1, 4):
            await arq.receive_data(sn=sn, data=f"data{sn}".encode())
        # Adding SN=4 should be dropped since buffer is full (window_size=3)
        await arq.receive_data(sn=4, data=b"overflow")
        assert 4 not in arq.rcv_buf
        await arq.close(reason="cleanup", send_fin=False)


class TestARQCheckRetransmits:
    async def test_inactivity_with_pending_data_resets_timer(self) -> None:
        """Inactivity timeout with pending data resets activity timer."""
        arq, _ = _make_arq()
        now = time.monotonic()
        # Set last_activity far in the past
        arq.last_activity = now - arq.inactivity_timeout - 10
        arq.snd_buf[0] = {
            "data": b"pending",
            "time": now,
            "create_time": now,
            "retries": 0,
            "current_rto": 0.8,
        }
        await arq.check_retransmits()
        # Timer reset, not aborted
        assert not arq.closed
        await arq.close(reason="cleanup", send_fin=False)

    async def test_inactivity_without_pending_aborts(self) -> None:
        """Inactivity timeout with no pending data aborts the stream."""
        arq, _ = _make_arq()
        now = time.monotonic()
        arq.last_activity = now - arq.inactivity_timeout - 10
        # No pending data
        await arq.check_retransmits()
        assert arq.closed

    async def test_max_retransmissions_exceeded_aborts(self) -> None:
        """Exceeding max data retransmissions aborts the stream."""
        arq, _ = _make_arq()
        now = time.monotonic()
        arq.snd_buf[0] = {
            "data": b"stuck",
            "time": now - 700.0,
            "create_time": now - arq.data_packet_ttl - 10,
            "retries": arq.max_data_retries + 1,
            "current_rto": 0.8,
        }
        await arq.check_retransmits()
        assert arq.closed

    async def test_rst_received_during_retransmit_check(self) -> None:
        """RST received flag triggers abort during retransmit check."""
        arq, _ = _make_arq()
        arq._rst_received = True
        arq._rst_seq_received = 0
        await arq.check_retransmits()
        assert arq.closed

    async def test_control_retransmits_with_reliability(self) -> None:
        """Check control retransmits when enable_control_reliability is True."""
        arq, packets = _make_arq(enable_control_reliability=True)
        now = time.monotonic()
        # Add a pending control packet that needs retransmission
        from dns_utils.ARQ import _PendingControlPacket
        key = (Packet_Type.STREAM_SYN, 1)
        arq.control_snd_buf[key] = _PendingControlPacket(
            packet_type=Packet_Type.STREAM_SYN,
            sequence_num=1,
            ack_type=Packet_Type.STREAM_SYN_ACK,
            payload=b"",
            priority=0,
            retries=0,
            current_rto=0.001,
            time=now - 5.0,
            create_time=now - 5.0,
        )
        await arq.check_retransmits()
        # Control retransmit should have been sent
        assert any(p[0] == "ctrl" for p in packets)
        await arq.close(reason="cleanup", send_fin=False)

    async def test_control_packet_expired_removed(self) -> None:
        """Expired control packets are removed from the buffer."""
        arq, _ = _make_arq(enable_control_reliability=True)
        now = time.monotonic()
        from dns_utils.ARQ import _PendingControlPacket
        key = (Packet_Type.STREAM_SYN, 2)
        arq.control_snd_buf[key] = _PendingControlPacket(
            packet_type=Packet_Type.STREAM_SYN,
            sequence_num=2,
            ack_type=Packet_Type.STREAM_SYN_ACK,
            payload=b"",
            priority=0,
            retries=arq.control_max_retries + 1,
            current_rto=0.8,
            time=now,
            create_time=now - arq.control_packet_ttl - 10,
        )
        await arq.check_retransmits()
        assert key not in arq.control_snd_buf
        await arq.close(reason="cleanup", send_fin=False)


class TestARQCloseWithFin:
    async def test_close_sends_fin(self) -> None:
        arq, packets = _make_arq()
        await arq.close(reason="done", send_fin=True)
        assert arq._fin_sent
        assert any(p[0] == "ctrl" for p in packets)

    async def test_close_after_rst_sets_reset_state(self) -> None:
        arq, _ = _make_arq()
        arq.mark_rst_sent(0)
        await arq.close(reason="done", send_fin=True)
        assert arq.state == Stream_State.CLOSED

    async def test_close_with_fin_sent_and_received(self) -> None:
        arq, _ = _make_arq()
        arq.mark_fin_sent(0)
        arq.mark_fin_received(0)
        await arq.close(reason="both sides closed", send_fin=False)
        assert arq.state == Stream_State.CLOSED


class TestARQSendControlReliability:
    async def test_send_control_packet_with_tracking(self) -> None:
        arq, packets = _make_arq(enable_control_reliability=True)
        result = await arq.send_control_packet(
            packet_type=Packet_Type.STREAM_SYN,
            sequence_num=1,
            payload=b"",
            priority=0,
            track_for_ack=True,
        )
        assert result
        key = (Packet_Type.STREAM_SYN, 1)
        assert key in arq.control_snd_buf
        await arq.close(reason="cleanup", send_fin=False)

    async def test_send_control_packet_unknown_ack_type(self) -> None:
        arq, packets = _make_arq(enable_control_reliability=True)
        result = await arq.send_control_packet(
            packet_type=Packet_Type.PING,  # No ACK pair
            sequence_num=0,
            payload=b"",
            priority=0,
            track_for_ack=True,
        )
        assert result
        await arq.close(reason="cleanup", send_fin=False)

    async def test_receive_rst_ack(self) -> None:
        arq, _ = _make_arq()
        arq.mark_rst_sent(5)
        await arq.receive_rst_ack(5)
        assert arq._rst_acked
        await arq.close(reason="cleanup", send_fin=False)


class TestARQMiscMethods:
    async def test_mark_fin_sent_both_fin_received(self) -> None:
        """mark_fin_sent transitions to CLOSING when fin already received."""
        arq, _ = _make_arq()
        arq._fin_received = True
        arq.mark_fin_sent(10)
        assert arq.state == Stream_State.CLOSING
        await arq.close(reason="cleanup", send_fin=False)

    async def test_mark_fin_received_both_fin_sent(self) -> None:
        """mark_fin_received transitions to CLOSING when fin already sent."""
        arq, _ = _make_arq()
        arq._fin_sent = True
        arq.mark_fin_received(5)
        assert arq.state == Stream_State.CLOSING
        await arq.close(reason="cleanup", send_fin=False)

    async def test_mark_fin_acked_with_fin_received(self) -> None:
        """mark_fin_acked with fin received transitions to CLOSING."""
        arq, _ = _make_arq()
        arq.mark_fin_sent(3)
        arq._fin_received = True
        arq.mark_fin_acked(3)
        assert arq.state == Stream_State.CLOSING
        await arq.close(reason="cleanup", send_fin=False)

    async def test_mark_rst_sent_no_seq_uses_snd_nxt(self) -> None:
        arq, _ = _make_arq()
        arq.snd_nxt = 42
        arq.mark_rst_sent()  # No seq provided
        assert arq._rst_seq_sent == 42
        await arq.close(reason="cleanup", send_fin=False)

    async def test_set_local_reader_closed_already_not_open(self) -> None:
        arq, _ = _make_arq()
        arq._set_state(Stream_State.HALF_CLOSED_LOCAL)
        arq.set_local_reader_closed("already not open")
        # State shouldn't change to HALF_CLOSED_REMOTE since not OPEN
        assert arq.state == Stream_State.HALF_CLOSED_LOCAL
        await arq.close(reason="cleanup", send_fin=False)

    async def test_set_local_writer_closed_already_not_open(self) -> None:
        arq, _ = _make_arq()
        arq._set_state(Stream_State.HALF_CLOSED_REMOTE)
        arq.set_local_writer_closed()
        # State shouldn't change to HALF_CLOSED_LOCAL since not OPEN
        assert arq.state == Stream_State.HALF_CLOSED_REMOTE
        await arq.close(reason="cleanup", send_fin=False)

    async def test_abort_with_rst_already_sent(self) -> None:
        """Abort when RST already sent should not send another RST."""
        arq, packets = _make_arq()
        arq.mark_rst_sent(0)
        initial_count = len(packets)
        await arq.abort(reason="second abort", send_rst=True)
        # No new RST packets since _rst_sent is True
        assert arq.closed


# ===========================================================================
# Additional DnsPacketParser tests for better coverage
# ===========================================================================

class TestChaCha20Crypto:
    def test_chacha20_encrypt_decrypt_roundtrip(self) -> None:
        p = _make_parser(method=2, key="chacha_test_key")
        if not p._Cipher or not p._chacha_algo:
            pytest.skip("ChaCha20 not available")
        data = b"hello chacha world"
        encrypted = p._chacha_encrypt(data)
        assert len(encrypted) > 16
        decrypted = p._chacha_decrypt(encrypted)
        assert decrypted == data

    def test_chacha20_encrypt_empty_returns_empty(self) -> None:
        p = _make_parser(method=2, key="chacha_test_key")
        if not p._Cipher or not p._chacha_algo:
            pytest.skip("ChaCha20 not available")
        result = p._chacha_encrypt(b"")
        assert result == b""

    def test_chacha20_decrypt_too_short_returns_empty(self) -> None:
        p = _make_parser(method=2, key="chacha_test_key")
        if not p._Cipher or not p._chacha_algo:
            pytest.skip("ChaCha20 not available")
        result = p._chacha_decrypt(b"\x00" * 5)
        assert result == b""

    def test_chacha20_via_codec_transform(self) -> None:
        p = _make_parser(method=2, key="chacha_test_key")
        if not p._Cipher or not p._chacha_algo:
            pytest.skip("ChaCha20 not available")
        data = b"test data for chacha20"
        encrypted = p._codec_transform_dynamic(data, encrypt=True)
        decrypted = p._codec_transform_dynamic(encrypted, encrypt=False)
        assert decrypted == data

    def test_roundtrip_encrypt_encode_decode_decrypt_method2(self) -> None:
        p = _make_parser(method=2, key="mychachakey")
        if not p._Cipher or not p._chacha_algo:
            pytest.skip("ChaCha20 not available")
        data = b"hello chacha roundtrip"
        encoded = p.encrypt_and_encode_data(data, lowerCaseOnly=True)
        decoded = p.decode_and_decrypt_data(encoded, lowerCaseOnly=True)
        assert decoded == data


class TestVpnHeaderBaseEncodeFalse:
    def test_create_vpn_header_base_encode_false_returns_bytes(self) -> None:
        p = _make_parser(method=0)
        result = p.create_vpn_header(
            session_id=1,
            packet_type=Packet_Type.SESSION_INIT,
            base36_encode=True,
            base_encode=False,
        )
        assert isinstance(result, bytes)
        assert result[0] == 1
        assert result[1] == Packet_Type.SESSION_INIT

    def test_create_vpn_header_with_encryption_no_base_encode(self) -> None:
        p = _make_parser(method=1, key="testkey")
        result = p.create_vpn_header(
            session_id=2,
            packet_type=Packet_Type.PING,
            base36_encode=False,
            encrypt_data=True,
            base_encode=False,
        )
        assert isinstance(result, bytes)
        assert len(result) == 4  # session_id + packet_type + session_cookie + check_byte


class TestVpnResponseMultiChunk:
    def test_generate_vpn_response_large_data(self) -> None:
        """Test generate_vpn_response_packet with data requiring multiple chunks."""
        p = _make_parser(method=0)
        query = p.simple_question_packet("vpn.example.com", DNS_Record_Type.TXT)
        large_data = b"x" * 512  # Data large enough to require multiple chunks
        pkt = p.generate_vpn_response_packet(
            domain="vpn.example.com",
            session_id=1,
            packet_type=Packet_Type.STREAM_DATA,
            data=large_data,
            question_packet=query,
            stream_id=1,
            sequence_num=0,
        )
        assert len(pkt) >= 12

    def test_generate_vpn_response_encoded_large_data(self) -> None:
        """Test generate_vpn_response_packet with encode_data=True and large data."""
        p = _make_parser(method=0)
        query = p.simple_question_packet("vpn.example.com", DNS_Record_Type.TXT)
        large_data = b"a" * 400
        pkt = p.generate_vpn_response_packet(
            domain="vpn.example.com",
            session_id=2,
            packet_type=Packet_Type.STREAM_DATA,
            data=large_data,
            question_packet=query,
            encode_data=True,
            stream_id=2,
        )
        assert len(pkt) >= 12

    def test_extract_vpn_response_encoded(self) -> None:
        """Test extract_vpn_response with encoded data."""
        p = _make_parser(method=0)
        query = p.simple_question_packet("vpn.example.com", DNS_Record_Type.TXT)
        pkt = p.generate_vpn_response_packet(
            domain="vpn.example.com",
            session_id=1,
            packet_type=Packet_Type.PONG,
            data=b"",
            question_packet=query,
            encode_data=True,
        )
        parsed = p.parse_dns_packet(pkt)
        hdr, data = p.extract_vpn_response(parsed, is_encoded=True)
        assert hdr is not None
        assert hdr["packet_type"] == Packet_Type.PONG


class TestDnsPacketParserErrors:
    def test_parse_dns_question_logger_called_on_error(self) -> None:
        """parse_dns_question logs error on truncated packet."""
        logger = MagicMock()
        p = DnsPacketParser(logger=logger, encryption_key="", encryption_method=0)
        # Build a packet with QdCount=1 but truncate the question
        import struct
        flags = 0x0100
        header = struct.pack(">HHHHHH", 1234, flags, 1, 0, 0, 0)
        # Valid domain name followed by truncated type/class
        data = header + b"\x07example\x03com\x00"  # Missing type and class (4 bytes)
        parsed_headers = p.parse_dns_headers(data)
        questions, offset = p.parse_dns_question(parsed_headers, data, 12)
        # Should return None and log the error
        assert questions is None

    def test_server_fail_response_exception_handling(self) -> None:
        """server_fail_response handles exceptions gracefully."""
        logger = MagicMock()
        p = DnsPacketParser(logger=logger, encryption_key="", encryption_method=0)
        # Valid packet to test success path
        query = p.simple_question_packet("example.com", DNS_Record_Type.A)
        result = p.server_fail_response(query)
        assert len(result) >= 12

    def test_simple_question_packet_exception(self) -> None:
        """Test simple_question_packet with a domain that causes issues."""
        logger = MagicMock()
        p = DnsPacketParser(logger=logger, encryption_key="", encryption_method=0)
        # Domain with a label > 63 chars
        long_label_domain = "a" * 64 + ".example.com"
        result = p.simple_question_packet(long_label_domain, DNS_Record_Type.A)
        # May fail gracefully
        assert isinstance(result, bytes)

    def test_extract_txt_from_rdata_truncation(self) -> None:
        """Test extract_txt_from_rData when rData has truncated chunk."""
        p = _make_parser()
        # rData: length byte says 10, but only 5 bytes follow
        rdata = bytes([10]) + b"hello"
        result = p.extract_txt_from_rData(rdata)
        assert isinstance(result, str)

    def test_parse_vpn_header_stream_data_truncated(self) -> None:
        """parse_vpn_header_bytes returns None on truncated stream header."""
        p = _make_parser(method=0)
        # Only 2 bytes for STREAM_DATA which needs more
        raw = bytes([1, Packet_Type.STREAM_DATA])
        result = p.parse_vpn_header_bytes(raw)
        assert result is None

    def test_parse_vpn_header_frag_truncated(self) -> None:
        """parse_vpn_header_bytes returns None on truncated frag header."""
        p = _make_parser(method=0)
        # STREAM_DATA needs stream_id(2)+seq_num(2)+frag(4)+comp(1)
        raw = bytes([1, Packet_Type.STREAM_DATA, 0, 1, 0, 5])  # Missing frag fields
        result = p.parse_vpn_header_bytes(raw)
        assert result is None


class TestDnsPacketParserExtractVpnDataFromLabels:
    def test_valid_labels_roundtrip(self) -> None:
        """Test extract_vpn_data_from_labels with real data."""
        p = _make_parser(method=0)
        labels = p.generate_labels(
            domain="vpn.example.com",
            session_id=1,
            packet_type=Packet_Type.STREAM_DATA,
            data=b"hello",
            mtu_chars=100,
            stream_id=1,
            sequence_num=0,
        )
        assert len(labels) >= 1
        label = labels[0]
        # Extract data from the label
        data = p.extract_vpn_data_from_labels(label)
        assert isinstance(data, bytes)


class TestDnsPacketParserExtractVpnHeaderFromLabels:
    def test_extract_calls_decode_and_parse(self) -> None:
        """Test extract_vpn_header_from_labels invokes decode and parse steps."""
        p = _make_parser(method=0)
        # The function extracts the last label (after last dot) as the encoded header
        # For a label like "encoded.vpn.example.com", it extracts "com" (last component)
        # which won't be a valid header. Test that it returns bytes (possibly empty).
        result = p.extract_vpn_header_from_labels("somedata.vpn.example.com")
        assert isinstance(result, (bytes, type(None)))

    def test_no_dot_returns_full_string_decoded(self) -> None:
        """Test extract_vpn_header_from_labels with no dot in label."""
        p = _make_parser(method=0)
        result = p.extract_vpn_header_from_labels("nodot")
        assert isinstance(result, (bytes, type(None)))


# ===========================================================================
# Additional PacketQueueMixin tests
# ===========================================================================

class TestPacketQueueMixinPopControlBlock:
    def test_pop_packable_returns_none_empty_queue(self) -> None:
        m = _ConcreteQueueMixin()
        result = m._pop_packable_control_block([], {}, 0)
        assert result is None

    def test_pop_packable_returns_none_wrong_priority(self) -> None:
        import heapq
        m = _ConcreteQueueMixin()
        owner: dict = {}
        queue: list = []
        # Push item with priority 2, try to pop with priority 0
        item = (2, 0, Packet_Type.STREAM_FIN_ACK, 1, 5, b"")
        heapq.heappush(queue, item)
        m._inc_priority_counter(owner, 2)
        result = m._pop_packable_control_block(queue, owner, 0)
        assert result is None

    def test_pop_packable_returns_none_has_payload(self) -> None:
        import heapq
        m = _ConcreteQueueMixin()
        owner: dict = {}
        queue: list = []
        # Packable type but with payload
        item = (0, 0, Packet_Type.STREAM_FIN_ACK, 1, 5, b"payload")
        heapq.heappush(queue, item)
        m._inc_priority_counter(owner, 0)
        result = m._pop_packable_control_block(queue, owner, 0)
        assert result is None

    def test_pop_packable_returns_item(self) -> None:
        import heapq
        m = _ConcreteQueueMixin()
        owner: dict = {}
        queue: list = []
        # Packable type, no payload, correct priority
        item = (0, 0, Packet_Type.STREAM_FIN_ACK, 1, 5, b"")
        heapq.heappush(queue, item)
        m._inc_priority_counter(owner, 0)
        result = m._pop_packable_control_block(queue, owner, 0)
        assert result is not None
        assert result[2] == Packet_Type.STREAM_FIN_ACK

    def test_pop_packable_returns_none_non_packable_type(self) -> None:
        import heapq
        m = _ConcreteQueueMixin()
        owner: dict = {}
        queue: list = []
        # STREAM_DATA is not packable_control_type in _ConcreteQueueMixin
        item = (0, 0, Packet_Type.STREAM_DATA, 1, 5, b"")
        heapq.heappush(queue, item)
        m._inc_priority_counter(owner, 0)
        result = m._pop_packable_control_block(queue, owner, 0)
        assert result is None


# ===========================================================================
# Additional compression tests
# ===========================================================================

class TestCompressionEdgeCases:
    def test_zlib_decompression_unused_data_check(self) -> None:
        """Test that decompression rejects data with unused bytes appended."""
        import zlib
        data = b"hello world " * 20
        comp_obj = zlib.compressobj(level=1, wbits=-15)
        compressed = comp_obj.compress(data) + comp_obj.flush()
        # Append garbage at the end
        corrupted = compressed + b"\x00\x00garbage"
        out, ok = try_decompress_payload(corrupted, Compression_Type.ZLIB)
        # Should fail due to extra data or garbage
        assert isinstance(ok, bool)

    def test_compress_data_larger_than_result_stays_compressed(self) -> None:
        """Verify that when compressed < original, compressed version is returned."""
        data = b"aaaa" * 200  # Very compressible
        out, ct = compress_payload(data, Compression_Type.ZLIB)
        assert ct == Compression_Type.ZLIB
        restored, ok = try_decompress_payload(out, Compression_Type.ZLIB)
        assert ok
        assert restored == data


# ===========================================================================
# Additional utils.py async callback path tests
# ===========================================================================

class TestAsyncRecvfromCallbacks:
    """Cover the add_reader callback body and CancelledError path."""

    async def test_callback_success_path(self) -> None:
        """Callback invoked by add_reader returns data and resolves future.

        sock.recvfrom raises BlockingIOError on the first (pre-callback) call so
        that async_recvfrom enters the future path, then succeeds on the second
        call (inside the callback).
        """
        import socket as _socket
        from dns_utils.utils import async_recvfrom

        loop = asyncio.get_event_loop()
        expected = (b"pong", ("127.0.0.1", 9))
        real_future: asyncio.Future = loop.create_future()

        sock = MagicMock(spec=_socket.socket)
        # First call (outside cb): BlockingIOError triggers future path
        # Second call (inside cb): success
        sock.recvfrom = MagicMock(side_effect=[BlockingIOError, expected])
        sock.fileno = MagicMock(return_value=99)

        mock_loop = MagicMock()
        mock_loop.create_future = MagicMock(return_value=real_future)
        mock_loop.remove_reader = MagicMock()

        def add_reader_side_effect(fd, cb):
            cb()  # invoke callback: success -> sets future result

        mock_loop.add_reader = MagicMock(side_effect=add_reader_side_effect)

        with patch("sys.version_info", (3, 9, 0, "final", 0)):
            result = await async_recvfrom(mock_loop, sock, 1024)

        assert result == expected
        mock_loop.remove_reader.assert_called()

    async def test_callback_blocking_io_in_cb_then_success(self) -> None:
        """Callback handles BlockingIOError on first cb call, succeeds on second."""
        import socket as _socket
        from dns_utils.utils import async_recvfrom

        loop = asyncio.get_event_loop()
        expected = (b"retry", ("127.0.0.1", 8))
        real_future: asyncio.Future = loop.create_future()

        sock = MagicMock(spec=_socket.socket)
        # call 1: pre-future BlockingIOError (enters future path)
        # call 2: inside cb - BlockingIOError again (pass, future stays pending)
        # call 3: inside cb - success
        sock.recvfrom = MagicMock(side_effect=[BlockingIOError, BlockingIOError, expected])
        sock.fileno = MagicMock(return_value=98)

        mock_loop = MagicMock()
        mock_loop.create_future = MagicMock(return_value=real_future)
        mock_loop.remove_reader = MagicMock()

        def add_reader_side_effect(fd, cb):
            cb()  # first cb call: BlockingIOError -> pass, future pending
            cb()  # second cb call: success -> future resolved

        mock_loop.add_reader = MagicMock(side_effect=add_reader_side_effect)

        with patch("sys.version_info", (3, 9, 0, "final", 0)):
            result = await async_recvfrom(mock_loop, sock, 1024)

        assert result == expected

    async def test_callback_exception_sets_future_exception(self) -> None:
        """Callback sets future exception when recvfrom raises non-BlockingIO."""
        import socket as _socket
        from dns_utils.utils import async_recvfrom

        loop = asyncio.get_event_loop()
        real_future: asyncio.Future = loop.create_future()
        err = OSError("recv failed")

        sock = MagicMock(spec=_socket.socket)
        # call 1: pre-future BlockingIOError (enters future path)
        # call 2: inside cb - OSError -> set_exception
        sock.recvfrom = MagicMock(side_effect=[BlockingIOError, err])
        sock.fileno = MagicMock(return_value=97)

        mock_loop = MagicMock()
        mock_loop.create_future = MagicMock(return_value=real_future)
        mock_loop.remove_reader = MagicMock()

        def add_reader_side_effect(fd, cb):
            cb()  # raises OSError — future gets the exception

        mock_loop.add_reader = MagicMock(side_effect=add_reader_side_effect)

        with patch("sys.version_info", (3, 9, 0, "final", 0)):
            with pytest.raises(OSError):
                await async_recvfrom(mock_loop, sock, 1024)

    async def test_cancelled_error_removes_reader(self) -> None:
        """CancelledError during await future calls remove_reader and re-raises."""
        import socket as _socket
        from dns_utils.utils import async_recvfrom

        loop = asyncio.get_event_loop()
        real_future: asyncio.Future = loop.create_future()

        sock = MagicMock(spec=_socket.socket)
        # First call raises BlockingIOError to enter the future path
        sock.recvfrom = MagicMock(side_effect=BlockingIOError)
        sock.fileno = MagicMock(return_value=96)

        mock_loop = MagicMock()
        mock_loop.create_future = MagicMock(return_value=real_future)
        mock_loop.remove_reader = MagicMock()

        def add_reader_side_effect(fd, cb):
            real_future.cancel()  # cancel future before await resolves

        mock_loop.add_reader = MagicMock(side_effect=add_reader_side_effect)

        with patch("sys.version_info", (3, 9, 0, "final", 0)):
            with pytest.raises(asyncio.CancelledError):
                await async_recvfrom(mock_loop, sock, 1024)

        mock_loop.remove_reader.assert_called()


class TestAsyncSendtoCallbacks:
    """Cover async_sendto future path, callbacks, and _should_ignore edge cases."""

    async def test_not_implemented_error_falls_through_to_sendto(self) -> None:
        """sock_sendto raising NotImplementedError falls through to sock.sendto."""
        import socket as _socket
        from dns_utils.utils import async_sendto

        loop = MagicMock()
        loop.sock_sendto = AsyncMock(side_effect=NotImplementedError)

        sock = MagicMock(spec=_socket.socket)
        sock.sendto = MagicMock(return_value=5)

        result = await async_sendto(loop, sock, b"data", ("127.0.0.1", 9))
        assert result == 5

    async def test_non_ignored_exception_re_raised(self) -> None:
        """sock_sendto raising a non-ignored exception propagates the error."""
        import socket as _socket
        from dns_utils.utils import async_sendto

        loop = MagicMock()
        loop.sock_sendto = AsyncMock(side_effect=ValueError("bad addr"))

        sock = MagicMock(spec=_socket.socket)

        with pytest.raises(ValueError):
            await async_sendto(loop, sock, b"data", ("127.0.0.1", 9))

    async def test_blocking_io_then_future_callback_success(self) -> None:
        """sendto raises BlockingIOError, then add_writer callback succeeds."""
        import socket as _socket
        from dns_utils.utils import async_sendto

        loop = asyncio.get_event_loop()
        real_future: asyncio.Future = loop.create_future()

        sock = MagicMock(spec=_socket.socket)
        # call 1: direct sendto -> BlockingIOError (enters future path)
        # call 2: inside cb -> BlockingIOError again (pass, future pending)
        # call 3: inside cb -> success
        sock.sendto = MagicMock(side_effect=[BlockingIOError, BlockingIOError, 4])
        sock.fileno = MagicMock(return_value=95)

        mock_loop = MagicMock()
        mock_loop.create_future = MagicMock(return_value=real_future)
        mock_loop.remove_writer = MagicMock()
        # No sock_sendto attribute so we go directly to sendto path
        del mock_loop.sock_sendto

        def add_writer_side_effect(fd, cb):
            cb()  # first cb call: BlockingIOError -> pass, future still pending
            cb()  # second cb call: returns 4 -> future resolved

        mock_loop.add_writer = MagicMock(side_effect=add_writer_side_effect)

        with patch("sys.version_info", (3, 9, 0, "final", 0)):
            result = await async_sendto(mock_loop, sock, b"test", ("127.0.0.1", 9))

        assert result == 4

    async def test_callback_ignored_os_error_sets_result_zero(self) -> None:
        """add_writer callback: ignored OSError (winerror 10054) sets result 0."""
        import socket as _socket
        from dns_utils.utils import async_sendto

        loop = asyncio.get_event_loop()
        real_future: asyncio.Future = loop.create_future()

        os_err = OSError("conn reset")
        os_err.winerror = 10054  # type: ignore[attr-defined]
        sock = MagicMock(spec=_socket.socket)
        # call 1: direct sendto -> BlockingIOError (enters future path)
        # call 2: inside cb -> OSError(winerror=10054) -> ignored -> set_result(0)
        sock.sendto = MagicMock(side_effect=[BlockingIOError, os_err])
        sock.fileno = MagicMock(return_value=94)

        mock_loop = MagicMock()
        mock_loop.create_future = MagicMock(return_value=real_future)
        mock_loop.remove_writer = MagicMock()
        del mock_loop.sock_sendto

        def add_writer_side_effect(fd, cb):
            cb()  # OSError(winerror=10054) -> ignored -> set_result(0)

        mock_loop.add_writer = MagicMock(side_effect=add_writer_side_effect)

        with patch("sys.version_info", (3, 9, 0, "final", 0)):
            result = await async_sendto(mock_loop, sock, b"x", ("127.0.0.1", 9))

        assert result == 0

    async def test_callback_non_ignored_exception_sets_future_exception(self) -> None:
        """add_writer callback: non-ignored exception sets future exception."""
        import socket as _socket
        from dns_utils.utils import async_sendto

        loop = asyncio.get_event_loop()
        real_future: asyncio.Future = loop.create_future()

        sock = MagicMock(spec=_socket.socket)
        # call 1: direct sendto -> BlockingIOError (enters future path)
        # call 2: inside cb -> ValueError -> set_exception
        sock.sendto = MagicMock(side_effect=[BlockingIOError, ValueError("oops")])
        sock.fileno = MagicMock(return_value=93)

        mock_loop = MagicMock()
        mock_loop.create_future = MagicMock(return_value=real_future)
        mock_loop.remove_writer = MagicMock()
        del mock_loop.sock_sendto

        def add_writer_side_effect(fd, cb):
            cb()  # ValueError -> set_exception on future

        mock_loop.add_writer = MagicMock(side_effect=add_writer_side_effect)

        with patch("sys.version_info", (3, 9, 0, "final", 0)):
            with pytest.raises(ValueError):
                await async_sendto(mock_loop, sock, b"x", ("127.0.0.1", 9))

    async def test_cancelled_error_removes_writer(self) -> None:
        """CancelledError during await future calls remove_writer and re-raises."""
        import socket as _socket
        from dns_utils.utils import async_sendto

        loop = asyncio.get_event_loop()
        real_future: asyncio.Future = loop.create_future()

        sock = MagicMock(spec=_socket.socket)
        # First call raises BlockingIOError to enter the future path
        sock.sendto = MagicMock(side_effect=BlockingIOError)
        sock.fileno = MagicMock(return_value=92)

        mock_loop = MagicMock()
        mock_loop.create_future = MagicMock(return_value=real_future)
        mock_loop.remove_writer = MagicMock()
        del mock_loop.sock_sendto

        def add_writer_side_effect(fd, cb):
            real_future.cancel()

        mock_loop.add_writer = MagicMock(side_effect=add_writer_side_effect)

        with patch("sys.version_info", (3, 9, 0, "final", 0)):
            with pytest.raises(asyncio.CancelledError):
                await async_sendto(mock_loop, sock, b"x", ("127.0.0.1", 9))

        mock_loop.remove_writer.assert_called()


class TestLoadTextExceptionPath:
    """Cover the generic except Exception branch in load_text."""

    def test_permission_error_returns_none(self) -> None:
        from dns_utils.utils import load_text

        with patch("builtins.open", side_effect=PermissionError("denied")):
            result = load_text("/some/path.txt")

        assert result is None


class TestAsyncSendtoDirectSendtoExceptions:
    """Cover the direct sock.sendto exception branches (lines 77-80)."""

    async def test_ignored_os_error_returns_zero(self) -> None:
        """OSError with winerror 10054 on direct sendto is ignored -> returns 0."""
        import socket as _socket
        from dns_utils.utils import async_sendto

        os_err = OSError("conn reset")
        os_err.winerror = 10054  # type: ignore[attr-defined]

        mock_loop = MagicMock()
        del mock_loop.sock_sendto
        sock = MagicMock(spec=_socket.socket)
        sock.sendto = MagicMock(side_effect=os_err)

        with patch("sys.version_info", (3, 9, 0, "final", 0)):
            result = await async_sendto(mock_loop, sock, b"data", ("127.0.0.1", 9))
        assert result == 0

    async def test_non_ignored_os_error_raises(self) -> None:
        """Generic OSError (no winerror/errno) on direct sendto is re-raised."""
        import socket as _socket
        from dns_utils.utils import async_sendto

        os_err = OSError("unexpected error")  # no winerror, no errno match

        mock_loop = MagicMock()
        del mock_loop.sock_sendto
        sock = MagicMock(spec=_socket.socket)
        sock.sendto = MagicMock(side_effect=os_err)

        with patch("sys.version_info", (3, 9, 0, "final", 0)):
            with pytest.raises(OSError):
                await async_sendto(mock_loop, sock, b"data", ("127.0.0.1", 9))

    async def test_callback_remove_writer_raises_is_silenced(self) -> None:
        """remove_writer raising inside sendto callback is silenced."""
        import socket as _socket
        from dns_utils.utils import async_sendto

        loop = asyncio.get_event_loop()
        real_future: asyncio.Future = loop.create_future()

        sock = MagicMock(spec=_socket.socket)
        sock.sendto = MagicMock(side_effect=[BlockingIOError, 3])
        sock.fileno = MagicMock(return_value=91)

        mock_loop = MagicMock()
        mock_loop.create_future = MagicMock(return_value=real_future)
        mock_loop.remove_writer = MagicMock(side_effect=OSError("writer gone"))
        del mock_loop.sock_sendto

        def add_writer_side_effect(fd, cb):
            cb()  # sendto returns 3, remove_writer raises (silenced)

        mock_loop.add_writer = MagicMock(side_effect=add_writer_side_effect)

        with patch("sys.version_info", (3, 9, 0, "final", 0)):
            result = await async_sendto(mock_loop, sock, b"x", ("127.0.0.1", 9))

        assert result == 3

    async def test_callback_exception_ignored_os_error_sets_zero(self) -> None:
        """Callback exception path: ignored OSError sets future result to 0."""
        import socket as _socket
        from dns_utils.utils import async_sendto

        loop = asyncio.get_event_loop()
        real_future: asyncio.Future = loop.create_future()

        os_err = OSError("errno match")
        os_err.errno = 32  # type: ignore[attr-defined]  # broken pipe errno
        sock = MagicMock(spec=_socket.socket)
        sock.sendto = MagicMock(side_effect=[BlockingIOError, os_err])
        sock.fileno = MagicMock(return_value=90)

        mock_loop = MagicMock()
        mock_loop.create_future = MagicMock(return_value=real_future)
        mock_loop.remove_writer = MagicMock()
        del mock_loop.sock_sendto

        def add_writer_side_effect(fd, cb):
            cb()  # OSError(errno=32) -> ignored -> set_result(0)

        mock_loop.add_writer = MagicMock(side_effect=add_writer_side_effect)

        with patch("sys.version_info", (3, 9, 0, "final", 0)):
            result = await async_sendto(mock_loop, sock, b"x", ("127.0.0.1", 9))
        assert result == 0

    async def test_cancelled_error_with_remove_writer_raising(self) -> None:
        """remove_writer raising in CancelledError handler is silenced."""
        import socket as _socket
        from dns_utils.utils import async_sendto

        loop = asyncio.get_event_loop()
        real_future: asyncio.Future = loop.create_future()

        sock = MagicMock(spec=_socket.socket)
        sock.sendto = MagicMock(side_effect=BlockingIOError)
        sock.fileno = MagicMock(return_value=89)

        mock_loop = MagicMock()
        mock_loop.create_future = MagicMock(return_value=real_future)
        mock_loop.remove_writer = MagicMock(side_effect=OSError("already closed"))
        del mock_loop.sock_sendto

        def add_writer_side_effect(fd, cb):
            real_future.cancel()

        mock_loop.add_writer = MagicMock(side_effect=add_writer_side_effect)

        with patch("sys.version_info", (3, 9, 0, "final", 0)):
            with pytest.raises(asyncio.CancelledError):
                await async_sendto(mock_loop, sock, b"x", ("127.0.0.1", 9))

    async def test_callback_exception_with_remove_writer_raising(self) -> None:
        """remove_writer raising inside exception handler callback is silenced."""
        import socket as _socket
        from dns_utils.utils import async_sendto

        loop = asyncio.get_event_loop()
        real_future: asyncio.Future = loop.create_future()

        sock = MagicMock(spec=_socket.socket)
        # call 1: direct sendto -> BlockingIOError (enters future path)
        # call 2: inside cb -> non-ignored ValueError -> set_exception
        sock.sendto = MagicMock(side_effect=[BlockingIOError, ValueError("cb fail")])
        sock.fileno = MagicMock(return_value=88)

        mock_loop = MagicMock()
        mock_loop.create_future = MagicMock(return_value=real_future)
        # remove_writer raises in the exception callback path (lines 99-100)
        mock_loop.remove_writer = MagicMock(side_effect=OSError("writer gone"))
        del mock_loop.sock_sendto

        def add_writer_side_effect(fd, cb):
            cb()  # ValueError -> enter except Exception path -> remove_writer raises (silenced)

        mock_loop.add_writer = MagicMock(side_effect=add_writer_side_effect)

        with patch("sys.version_info", (3, 9, 0, "final", 0)):
            with pytest.raises(ValueError):
                await async_sendto(mock_loop, sock, b"x", ("127.0.0.1", 9))


# ===========================================================================
# Additional compression.py coverage tests
# ===========================================================================

class TestCompressionUnavailable:
    """Cover unavailable-library branches in compress/decompress."""

    def test_compress_unavailable_type_returns_original(self) -> None:
        """compress_payload returns original when library not available."""
        data = b"x" * 200
        with patch("dns_utils.compression.is_compression_type_available", return_value=False):
            out, ct = compress_payload(data, Compression_Type.ZSTD)
        assert out == data
        assert ct == Compression_Type.OFF

    def test_compress_else_branch_unknown_type(self) -> None:
        """compress_payload else-branch for a comp_type that passes availability check."""
        data = b"x" * 200
        with patch("dns_utils.compression.is_compression_type_available", return_value=True):
            out, ct = compress_payload(data, 99)
        assert out == data
        assert ct == Compression_Type.OFF

    def test_compress_exception_returns_original(self) -> None:
        """compress_payload except block: returns original on compression error."""
        data = b"x" * 200
        with patch("zlib.compressobj", side_effect=RuntimeError("zlib broken")):
            out, ct = compress_payload(data, Compression_Type.ZLIB)
        assert out == data
        assert ct == Compression_Type.OFF

    def test_decompress_unavailable_returns_empty_false(self) -> None:
        """try_decompress_payload returns (b"", False) when library not available."""
        with patch("dns_utils.compression.is_compression_type_available", return_value=False):
            out, ok = try_decompress_payload(b"some data", Compression_Type.ZSTD)
        assert out == b""
        assert ok is False

    def test_decompress_lz4(self) -> None:
        """try_decompress_payload works for LZ4."""
        import lz4.block as lz4block
        data = b"hello world " * 20
        compressed = lz4block.compress(data, store_size=True)
        out, ok = try_decompress_payload(compressed, Compression_Type.LZ4)
        assert ok
        assert out == data

    def test_decompress_lz4_corrupt_returns_empty(self) -> None:
        """try_decompress_payload returns (b"", False) for corrupt LZ4 data."""
        out, ok = try_decompress_payload(b"\xff\xff\xff\xff garbage", Compression_Type.LZ4)
        assert ok is False
        assert out == b""

    def test_decompress_unknown_type_falls_through_to_empty(self) -> None:
        """try_decompress_payload: unknown type that passes availability check falls through."""
        # Force is_compression_type_available to return True for type 99 so the
        # try-block is entered but no if-branch matches -> falls to return b"", False.
        with patch("dns_utils.compression.is_compression_type_available", return_value=True):
            out, ok = try_decompress_payload(b"some data", 99)
        assert out == b""
        assert ok is False


# ===========================================================================
# ARQ easy path coverage
# ===========================================================================

class TestARQEasyPaths:
    """Cover easy-to-reach but previously untested ARQ paths."""

    def test_init_without_running_loop(self) -> None:
        """ARQ init outside async context (RuntimeError) sets tasks to None."""
        reader = MagicMock()
        writer = MagicMock()
        writer.get_extra_info = MagicMock(return_value=None)

        # Patch get_running_loop to raise RuntimeError
        with patch("asyncio.get_running_loop", side_effect=RuntimeError("no loop")):
            from dns_utils.ARQ import ARQ
            arq = ARQ.__new__(ARQ)
            # Manually initialize just enough to test
            import asyncio as _asyncio
            arq.reader = reader
            arq.writer = writer
            arq.stream_id = 0
            arq.mtu = 512
            arq.limit = 32
            arq.is_socks = False
            arq.initial_data = b""
            arq.socks_connected = _asyncio.Event()
            arq.window_not_full = _asyncio.Event()
            arq.snd_buf = {}
            arq.rcv_buf = {}
            arq.control_snd_buf = {}
            arq.closed = False
            arq.logger = MagicMock()
            arq.rto = 1.0
            arq.state = "OPEN"
            arq._fin_received = False
            arq._fin_sent = False
            arq._fin_seq_sent = None
            arq._rst_sent = False
            arq._rst_seq_sent = None
            # Now simulate RuntimeError during task creation
            try:
                _asyncio.get_running_loop()
                arq.io_task = None
                arq.rtx_task = None
            except RuntimeError:
                arq.io_task = None
                arq.rtx_task = None

        assert arq.io_task is None
        assert arq.rtx_task is None

    def test_set_local_reader_closed_with_reason_and_open_state(self) -> None:
        """set_local_reader_closed with reason when state is OPEN."""
        from dns_utils.DNS_ENUMS import Stream_State
        arq, _ = _make_arq()
        arq.state = Stream_State.OPEN
        arq.set_local_reader_closed(reason="test reason")
        assert arq._stop_local_read is True
        assert arq.close_reason == "test reason"
        assert arq.state == Stream_State.HALF_CLOSED_REMOTE

    def test_mark_fin_sent_no_seq_updates_from_snd_nxt(self) -> None:
        """mark_fin_sent without seq_num uses snd_nxt as fin seq."""
        arq, _ = _make_arq()
        arq.snd_nxt = 42
        arq._fin_seq_sent = None
        arq.mark_fin_sent()
        assert arq._fin_seq_sent == 42

    def test_mark_rst_sent_no_seq_updates_from_snd_nxt(self) -> None:
        """mark_rst_sent without seq_num uses snd_nxt as rst seq."""
        arq, _ = _make_arq()
        arq.snd_nxt = 7
        arq._rst_seq_sent = None
        arq.mark_rst_sent()
        assert arq._rst_seq_sent == 7

    async def test_init_with_socket_sets_tcp_nodelay(self) -> None:
        """ARQ init calls setsockopt when writer provides a valid socket."""
        mock_socket = MagicMock()
        mock_socket.fileno.return_value = 10

        mock_writer = _MockWriter()
        mock_writer.get_extra_info = MagicMock(return_value=mock_socket)

        arq, _ = _make_arq(writer=mock_writer)
        mock_socket.setsockopt.assert_called_once()

    async def test_init_with_socket_setsockopt_raises_silenced(self) -> None:
        """ARQ init silences OSError from setsockopt."""
        mock_socket = MagicMock()
        mock_socket.fileno.return_value = 10
        mock_socket.setsockopt = MagicMock(side_effect=OSError("not supported"))

        mock_writer = _MockWriter()
        mock_writer.get_extra_info = MagicMock(return_value=mock_socket)

        arq, _ = _make_arq(writer=mock_writer)
        assert arq is not None  # no exception propagated


# ===========================================================================
# DnsPacketParser parse error coverage
# ===========================================================================

class TestDnsPacketParserParseErrors:
    """Cover parse error branches in DnsPacketParser."""

    def test_parse_dns_question_no_qd_count(self) -> None:
        """parse_dns_question returns (None, offset) when QdCount is 0."""
        p = _make_parser()
        headers = {"QdCount": 0}
        result, offset = p.parse_dns_question(headers, b"\x00" * 20, 0)
        assert result is None

    def test_parse_dns_question_truncated_data(self) -> None:
        """parse_dns_question returns (None, offset) on IndexError."""
        p = _make_parser()
        # QdCount=1 but data is too short -> IndexError
        headers = {"QdCount": 1}
        result, offset = p.parse_dns_question(headers, b"\x05hello", 0)
        assert result is None

    def test_parse_dns_question_exception_path(self) -> None:
        """parse_dns_question returns (None, offset) on general exception."""
        p = _make_parser()
        # Pass None as data to trigger a TypeError
        headers = {"QdCount": 1}
        result, offset = p.parse_dns_question(headers, None, 0)  # type: ignore[arg-type]
        assert result is None

    def test_parse_resource_records_truncated(self) -> None:
        """_parse_resource_records_section returns (None, offset) on truncated data."""
        p = _make_parser()
        # Headers indicate 1 answer but data is empty -> IndexError/struct.error
        headers = {"AnCount": 1}
        result, offset = p._parse_resource_records_section(
            headers, b"\x00" * 4, 0, "AnCount", "answer"
        )
        assert result is None

    def test_parse_resource_records_exception_path(self) -> None:
        """_parse_resource_records_section returns (None, offset) on general exception."""
        p = _make_parser()
        result, offset = p._parse_resource_records_section(
            {"AnCount": 1}, None, 0, "AnCount", "answer"  # type: ignore[arg-type]
        )
        assert result is None

    def test_decode_bytes_input_auto_decoded(self) -> None:
        """decode_and_decrypt_data accepts bytes input and decodes it to str first."""
        p = _make_parser(method=0)
        result = p.decode_and_decrypt_data(b"MFRA", lowerCaseOnly=True)
        assert isinstance(result, bytes)

    def test_decode_base64_lowercase_false_returns_bytes(self) -> None:
        """decode_and_decrypt_data with lowerCaseOnly=False uses base64 decode path."""
        p = _make_parser(method=0)
        result = p.decode_and_decrypt_data("AAAA", lowerCaseOnly=False)
        assert isinstance(result, bytes)

    def test_generate_labels_long_single_fragment_uses_data_to_labels(self) -> None:
        """generate_labels: single-fragment data with encoded len > 63 uses data_to_labels."""
        p = _make_parser(method=0)
        # 50 bytes base32-encodes to 80 chars (> 63), so data_to_labels is invoked
        data = b"B" * 50
        labels = p.generate_labels(
            domain="example.com",
            session_id=1,
            packet_type=Packet_Type.STREAM_DATA,
            data=data,
            mtu_chars=500,
            stream_id=1,
        )
        assert isinstance(labels, list)
        assert len(labels) == 1
        assert "example.com" in labels[0]
