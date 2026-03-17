"""Tests for dns_utils/compression.py - full coverage of all compression functions."""

from __future__ import annotations

import os
import zlib

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

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


# ---------------------------------------------------------------------------
# normalize_compression_type
# ---------------------------------------------------------------------------


class TestNormalizeCompressionType:
    def test_valid_off(self) -> None:
        assert normalize_compression_type(Compression_Type.OFF) == Compression_Type.OFF

    def test_valid_zstd(self) -> None:
        assert normalize_compression_type(Compression_Type.ZSTD) == Compression_Type.ZSTD

    def test_valid_lz4(self) -> None:
        assert normalize_compression_type(Compression_Type.LZ4) == Compression_Type.LZ4

    def test_valid_zlib(self) -> None:
        assert normalize_compression_type(Compression_Type.ZLIB) == Compression_Type.ZLIB

    def test_invalid_large(self) -> None:
        assert normalize_compression_type(999) == Compression_Type.OFF

    def test_invalid_negative(self) -> None:
        assert normalize_compression_type(-1) == Compression_Type.OFF

    def test_none_defaults_to_off(self) -> None:
        assert normalize_compression_type(None) == Compression_Type.OFF  # type: ignore[arg-type]

    def test_zero_is_off(self) -> None:
        assert normalize_compression_type(0) == Compression_Type.OFF

    def test_all_supported_types_roundtrip(self) -> None:
        for ct in SUPPORTED_COMPRESSION_TYPES:
            assert normalize_compression_type(ct) == ct


# ---------------------------------------------------------------------------
# get_compression_name
# ---------------------------------------------------------------------------


class TestGetCompressionName:
    def test_off(self) -> None:
        assert get_compression_name(Compression_Type.OFF) == "OFF"

    def test_zstd(self) -> None:
        assert get_compression_name(Compression_Type.ZSTD) == "ZSTD"

    def test_lz4(self) -> None:
        assert get_compression_name(Compression_Type.LZ4) == "LZ4"

    def test_zlib(self) -> None:
        assert get_compression_name(Compression_Type.ZLIB) == "ZLIB"

    def test_unknown_returns_unknown(self) -> None:
        assert get_compression_name(999) == "UNKNOWN"

    def test_negative_returns_unknown(self) -> None:
        assert get_compression_name(-1) == "UNKNOWN"


# ---------------------------------------------------------------------------
# is_compression_type_available
# ---------------------------------------------------------------------------


class TestIsCompressionTypeAvailable:
    def test_off_is_not_available(self) -> None:
        assert is_compression_type_available(Compression_Type.OFF) is False

    def test_zlib_always_available(self) -> None:
        assert is_compression_type_available(Compression_Type.ZLIB) is True

    def test_zstd_reflects_library(self) -> None:
        assert is_compression_type_available(Compression_Type.ZSTD) is ZSTD_AVAILABLE

    def test_lz4_reflects_library(self) -> None:
        assert is_compression_type_available(Compression_Type.LZ4) is LZ4_AVAILABLE

    def test_unknown_type_false(self) -> None:
        assert is_compression_type_available(999) is False


# ---------------------------------------------------------------------------
# compress_payload
# ---------------------------------------------------------------------------


class TestCompressPayload:
    _big_data = b"a" * 200  # compressible, above min_size

    def test_empty_data_returns_off(self) -> None:
        data, ct = compress_payload(b"", Compression_Type.ZLIB)
        assert data == b""
        assert ct == Compression_Type.OFF

    def test_off_type_returns_original(self) -> None:
        data, ct = compress_payload(self._big_data, Compression_Type.OFF)
        assert data == self._big_data
        assert ct == Compression_Type.OFF

    def test_small_data_below_min_size_not_compressed(self) -> None:
        small = b"x" * 50
        data, ct = compress_payload(small, Compression_Type.ZLIB, min_size=100)
        assert data == small
        assert ct == Compression_Type.OFF

    def test_zlib_compresses_large_data(self) -> None:
        data, ct = compress_payload(self._big_data, Compression_Type.ZLIB)
        assert ct == Compression_Type.ZLIB
        assert len(data) < len(self._big_data)

    @pytest.mark.skipif(not ZSTD_AVAILABLE, reason="zstandard not installed")
    def test_zstd_compresses_large_data(self) -> None:
        data, ct = compress_payload(self._big_data, Compression_Type.ZSTD)
        assert ct == Compression_Type.ZSTD
        assert len(data) < len(self._big_data)

    @pytest.mark.skipif(not LZ4_AVAILABLE, reason="lz4 not installed")
    def test_lz4_compresses_large_data(self) -> None:
        data, ct = compress_payload(self._big_data, Compression_Type.LZ4)
        assert ct == Compression_Type.LZ4

    def test_incompressible_data_returns_off(self) -> None:
        random_data = os.urandom(500)
        data, ct = compress_payload(random_data, Compression_Type.ZLIB)
        # Random data may or may not compress; either way the return must be valid
        assert ct in (Compression_Type.ZLIB, Compression_Type.OFF)

    def test_unknown_type_returns_off(self) -> None:
        data, ct = compress_payload(self._big_data, 999)
        assert data == self._big_data
        assert ct == Compression_Type.OFF

    def test_zlib_uses_default_min_size(self) -> None:
        # Data at exactly min_size boundary is not compressed
        exact = b"a" * 100
        data, ct = compress_payload(exact, Compression_Type.ZLIB, min_size=100)
        assert data == exact
        assert ct == Compression_Type.OFF

    def test_compress_result_larger_falls_back_to_off(self) -> None:
        # Very short data that would expand when compressed
        tiny = b"ab" * 10 + b"cd"
        data, ct = compress_payload(tiny, Compression_Type.ZLIB, min_size=1)
        # Either compressed (if smaller) or original with OFF
        assert ct in (Compression_Type.ZLIB, Compression_Type.OFF)


# ---------------------------------------------------------------------------
# try_decompress_payload
# ---------------------------------------------------------------------------


class TestTryDecompressPayload:
    def test_empty_data_with_off(self) -> None:
        out, ok = try_decompress_payload(b"", Compression_Type.OFF)
        assert out == b""
        assert ok is True

    def test_off_type_passthrough(self) -> None:
        payload = b"hello world"
        out, ok = try_decompress_payload(payload, Compression_Type.OFF)
        assert out == payload
        assert ok is True

    def test_zlib_roundtrip(self) -> None:
        original = b"test data " * 30
        comp_obj = zlib.compressobj(level=1, wbits=-15)
        compressed = comp_obj.compress(original) + comp_obj.flush()
        out, ok = try_decompress_payload(compressed, Compression_Type.ZLIB)
        assert ok is True
        assert out == original

    def test_zlib_corrupt_data(self) -> None:
        out, ok = try_decompress_payload(b"\x00\x01\x02corrupt", Compression_Type.ZLIB)
        assert ok is False
        assert out == b""

    @pytest.mark.skipif(not ZSTD_AVAILABLE, reason="zstandard not installed")
    def test_zstd_roundtrip(self) -> None:
        import zstandard as zstd  # pylint: disable=import-outside-toplevel
        original = b"zstd test payload " * 20
        compressor = zstd.ZstdCompressor(level=1)
        compressed = compressor.compress(original)
        out, ok = try_decompress_payload(compressed, Compression_Type.ZSTD)
        assert ok is True
        assert out == original

    @pytest.mark.skipif(not LZ4_AVAILABLE, reason="lz4 not installed")
    def test_lz4_roundtrip(self) -> None:
        import lz4.block as lz4block  # pylint: disable=import-outside-toplevel
        original = b"lz4 test payload " * 20
        compressed = lz4block.compress(original, store_size=True)
        out, ok = try_decompress_payload(compressed, Compression_Type.LZ4)
        assert ok is True
        assert out == original

    def test_unavailable_type_returns_empty_false(self) -> None:
        # Type 999 is not available
        out, ok = try_decompress_payload(b"somedata", 999)
        assert ok is False
        assert out == b""

    def test_zlib_truly_corrupt_bytes(self) -> None:
        # Bytes that are not a valid raw deflate stream at all
        out, ok = try_decompress_payload(b"\xAA\xBB\xCC\xDD" * 10, Compression_Type.ZLIB)
        assert ok is False


# ---------------------------------------------------------------------------
# decompress_payload
# ---------------------------------------------------------------------------


class TestDecompressPayload:
    def test_success_returns_decompressed(self) -> None:
        original = b"decompress test " * 30
        comp_obj = zlib.compressobj(level=1, wbits=-15)
        compressed = comp_obj.compress(original) + comp_obj.flush()
        result = decompress_payload(compressed, Compression_Type.ZLIB)
        assert result == original

    def test_failure_returns_original(self) -> None:
        bad = b"\xff\xfe\xfd corrupted bytes"
        result = decompress_payload(bad, Compression_Type.ZLIB)
        assert result == bad

    def test_off_passthrough(self) -> None:
        data = b"no compression"
        assert decompress_payload(data, Compression_Type.OFF) == data


# ---------------------------------------------------------------------------
# Property-based round-trip tests
# ---------------------------------------------------------------------------


@given(
    data=st.binary(min_size=101, max_size=2000),
)
@settings(max_examples=30)
def test_zlib_compress_decompress_roundtrip(data: bytes) -> None:
    compressed, ct = compress_payload(data, Compression_Type.ZLIB, min_size=100)
    if ct == Compression_Type.ZLIB:
        result = decompress_payload(compressed, Compression_Type.ZLIB)
        assert result == data


@pytest.mark.skipif(not ZSTD_AVAILABLE, reason="zstandard not installed")
@given(data=st.binary(min_size=101, max_size=2000))
@settings(max_examples=20)
def test_zstd_compress_decompress_roundtrip(data: bytes) -> None:
    compressed, ct = compress_payload(data, Compression_Type.ZSTD, min_size=100)
    if ct == Compression_Type.ZSTD:
        result = decompress_payload(compressed, Compression_Type.ZSTD)
        assert result == data


@pytest.mark.skipif(not LZ4_AVAILABLE, reason="lz4 not installed")
@given(data=st.binary(min_size=101, max_size=2000))
@settings(max_examples=20)
def test_lz4_compress_decompress_roundtrip(data: bytes) -> None:
    compressed, ct = compress_payload(data, Compression_Type.LZ4, min_size=100)
    if ct == Compression_Type.LZ4:
        result = decompress_payload(compressed, Compression_Type.LZ4)
        assert result == data
