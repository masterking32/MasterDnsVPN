"""Tests for dns_utils/PrependReader.py."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from dns_utils.PrependReader import PrependReader


def make_stream_reader(chunks: list[bytes]) -> MagicMock:
    """Create a mock StreamReader that returns chunks in order."""
    reader = MagicMock()
    remaining = list(chunks)

    async def _read(n: int = -1) -> bytes:
        if remaining:
            return remaining.pop(0)
        return b""

    reader.read = _read
    return reader


class TestPrependReader:
    @pytest.mark.asyncio
    async def test_initial_data_smaller_than_n(self) -> None:
        inner = make_stream_reader([b"inner_data"])
        pr = PrependReader(inner, b"pre")

        result = await pr.read(100)
        assert result == b"pre"
        assert pr.initial_data == b""

    @pytest.mark.asyncio
    async def test_initial_data_larger_than_n(self) -> None:
        inner = make_stream_reader([])
        pr = PrependReader(inner, b"0123456789")

        result = await pr.read(4)
        assert result == b"0123"
        assert pr.initial_data == b"456789"

    @pytest.mark.asyncio
    async def test_initial_data_exact_size(self) -> None:
        inner = make_stream_reader([])
        pr = PrependReader(inner, b"exact")

        result = await pr.read(5)
        assert result == b"exact"
        assert pr.initial_data == b""

    @pytest.mark.asyncio
    async def test_after_initial_data_exhausted_reads_inner(self) -> None:
        inner = make_stream_reader([b"from_inner"])
        pr = PrependReader(inner, b"pre")

        await pr.read(100)  # Consume initial data
        result = await pr.read(100)
        assert result == b"from_inner"

    @pytest.mark.asyncio
    async def test_read_minus_one_returns_all_initial(self) -> None:
        inner = make_stream_reader([])
        pr = PrependReader(inner, b"alldata")

        result = await pr.read(-1)
        assert result == b"alldata"
        assert pr.initial_data == b""

    @pytest.mark.asyncio
    async def test_sequential_reads_drain_initial_data(self) -> None:
        inner = make_stream_reader([b"rest"])
        pr = PrependReader(inner, b"ABCDE")

        r1 = await pr.read(2)
        assert r1 == b"AB"
        r2 = await pr.read(2)
        assert r2 == b"CD"
        r3 = await pr.read(2)
        assert r3 == b"E"
        r4 = await pr.read(2)
        assert r4 == b"rest"

    @pytest.mark.asyncio
    async def test_empty_initial_data_delegates_to_inner(self) -> None:
        inner = make_stream_reader([b"inner_only"])
        pr = PrependReader(inner, b"")

        result = await pr.read(100)
        assert result == b"inner_only"

    @pytest.mark.asyncio
    async def test_n_zero_with_initial_data(self) -> None:
        inner = make_stream_reader([])
        pr = PrependReader(inner, b"data")

        # n=0 means take up to 0 bytes, but n <= 0 triggers the "take all" branch
        result = await pr.read(0)
        # n <= 0 is treated as "take all initial data"
        assert result == b"data"

    @pytest.mark.asyncio
    async def test_multiple_sequential_small_reads(self) -> None:
        inner = make_stream_reader([])
        pr = PrependReader(inner, b"hello")

        chunks = []
        for _ in range(5):
            chunks.append(await pr.read(1))
        assert b"".join(chunks) == b"hello"


# ---------------------------------------------------------------------------
# Hypothesis property-based tests
# ---------------------------------------------------------------------------


class TestHypothesisPrependReader:
    @given(st.binary(min_size=1, max_size=256))
    @settings(max_examples=50)
    def test_full_read_returns_all_initial_data(self, initial: bytes) -> None:
        # With non-empty initial data, a large read should return exactly initial
        inner = make_stream_reader([])
        pr = PrependReader(inner, initial)

        async def run():
            result = await pr.read(len(initial) + 100)
            return result

        result = asyncio.run(run())
        assert result == initial

    @given(
        st.binary(min_size=1, max_size=128),
        st.integers(min_value=1, max_value=64),
    )
    @settings(max_examples=50)
    def test_chunked_reads_reconstruct_initial_data(self, initial: bytes, chunk_size: int) -> None:
        inner = make_stream_reader([])
        pr = PrependReader(inner, initial)

        async def run():
            collected = b""
            while len(collected) < len(initial):
                chunk = await pr.read(chunk_size)
                if not chunk:
                    break
                collected += chunk
            return collected

        result = asyncio.run(run())
        assert result == initial
