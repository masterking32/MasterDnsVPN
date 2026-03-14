"""Tests for dns_utils/PingManager.py."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import MagicMock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from dns_utils.PingManager import PingManager


class TestPingManagerInit:
    def test_initialization(self) -> None:
        send_func = MagicMock()
        pm = PingManager(send_func)
        assert pm.send_func is send_func
        assert pm.active_connections == 0
        assert pm.last_data_activity <= time.monotonic()
        assert pm.last_ping_time <= time.monotonic()


class TestUpdateActivity:
    def test_update_activity_refreshes_timestamp(self) -> None:
        pm = PingManager(MagicMock())
        before = pm.last_data_activity
        time.sleep(0.01)
        pm.update_activity()
        assert pm.last_data_activity > before


class TestPingLoop:
    @pytest.mark.asyncio
    async def test_ping_loop_calls_send_func(self) -> None:
        """Ping loop should call send_func and can be cancelled."""
        call_count = 0

        def send():
            nonlocal call_count
            call_count += 1

        pm = PingManager(send)
        pm.last_data_activity = time.monotonic() - 1.0  # Make idle
        pm.last_ping_time = time.monotonic() - 10.0  # Long since last ping

        task = asyncio.create_task(pm.ping_loop())
        await asyncio.sleep(0.3)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        assert call_count > 0

    @pytest.mark.asyncio
    async def test_ping_loop_no_connections_slow_interval(self) -> None:
        """With 0 active connections and long idle time, ping interval is slow."""
        send = MagicMock()
        pm = PingManager(send)
        pm.active_connections = 0
        pm.last_data_activity = time.monotonic() - 25.0  # idle > 20s
        pm.last_ping_time = time.monotonic() - 15.0  # long since last ping (> 10s interval)

        task = asyncio.create_task(pm.ping_loop())
        await asyncio.sleep(0.15)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        # Should have been called at least once
        assert send.call_count >= 1

    @pytest.mark.asyncio
    async def test_ping_loop_active_connections_fast_interval(self) -> None:
        """With active connections and recent data, uses fast interval."""
        send = MagicMock()
        pm = PingManager(send)
        pm.active_connections = 1
        pm.last_data_activity = time.monotonic()  # very recent
        pm.last_ping_time = time.monotonic() - 1.0  # 1 second since last ping (> 0.2s interval)

        task = asyncio.create_task(pm.ping_loop())
        await asyncio.sleep(0.5)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        assert send.call_count > 0

    @pytest.mark.asyncio
    async def test_ping_loop_idle_10_seconds(self) -> None:
        """With idle_time >= 10s, ping interval is 3s."""
        send = MagicMock()
        pm = PingManager(send)
        pm.active_connections = 1
        pm.last_data_activity = time.monotonic() - 12.0  # idle 12s
        pm.last_ping_time = time.monotonic() - 5.0  # 5s since last ping (> 3s interval)

        task = asyncio.create_task(pm.ping_loop())
        await asyncio.sleep(0.2)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        assert send.call_count >= 1

    @pytest.mark.asyncio
    async def test_ping_loop_idle_5_seconds(self) -> None:
        """With idle_time >= 5s, ping interval is 1s."""
        send = MagicMock()
        pm = PingManager(send)
        pm.active_connections = 1
        pm.last_data_activity = time.monotonic() - 7.0  # idle 7s
        pm.last_ping_time = time.monotonic() - 2.0  # 2s since last ping (> 1s interval)

        task = asyncio.create_task(pm.ping_loop())
        await asyncio.sleep(0.2)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        assert send.call_count >= 1


# ---------------------------------------------------------------------------
# Hypothesis property-based tests
# ---------------------------------------------------------------------------


class TestHypothesisPingManager:
    @given(st.floats(min_value=0.0, max_value=1.0))
    @settings(max_examples=50)
    def test_update_activity_always_advances_timestamp(self, sleep_amount: float) -> None:
        pm = PingManager(MagicMock())
        before = pm.last_data_activity
        time.sleep(sleep_amount * 0.01)  # very small sleep to avoid test slowness
        pm.update_activity()
        assert pm.last_data_activity >= before

    @given(st.integers(min_value=0, max_value=100))
    @settings(max_examples=30)
    def test_active_connections_tracking(self, count: int) -> None:
        pm = PingManager(MagicMock())
        pm.active_connections = count
        assert pm.active_connections == count
