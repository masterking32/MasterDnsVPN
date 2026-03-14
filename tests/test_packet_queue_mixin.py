"""Tests for dns_utils/PacketQueueMixin.py."""

from __future__ import annotations

import asyncio
import heapq
from unittest.mock import MagicMock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from dns_utils.DNS_ENUMS import Packet_Type
from dns_utils.PacketQueueMixin import PacketQueueMixin


class ConcreteQueue(PacketQueueMixin):
    """Concrete subclass for testing the mixin."""

    _packable_control_types: set[int] = {
        Packet_Type.STREAM_FIN,
        Packet_Type.STREAM_RST,
        Packet_Type.STREAM_SYN,
    }


@pytest.fixture
def mixin() -> ConcreteQueue:
    return ConcreteQueue()


# ---------------------------------------------------------------------------
# _compute_mtu_based_pack_limit
# ---------------------------------------------------------------------------


class TestComputeMtuBasedPackLimit:
    def test_basic_calculation(self, mixin: ConcreteQueue) -> None:
        # mtu=200, percent=100, block_size=5 -> 200//5 = 40
        result = mixin._compute_mtu_based_pack_limit(200, 100.0, 5)
        assert result == 40

    def test_min_is_one(self, mixin: ConcreteQueue) -> None:
        result = mixin._compute_mtu_based_pack_limit(1, 1.0, 100)
        assert result == 1

    def test_percent_clamped_to_100(self, mixin: ConcreteQueue) -> None:
        result = mixin._compute_mtu_based_pack_limit(100, 200.0, 5)
        assert result == 20

    def test_percent_clamped_to_min(self, mixin: ConcreteQueue) -> None:
        result = mixin._compute_mtu_based_pack_limit(100, 0.0, 5)
        assert result >= 1

    def test_zero_mtu(self, mixin: ConcreteQueue) -> None:
        result = mixin._compute_mtu_based_pack_limit(0, 100.0, 5)
        assert result == 1

    def test_invalid_args_return_one(self, mixin: ConcreteQueue) -> None:
        result = mixin._compute_mtu_based_pack_limit("bad", "also_bad", "nope")  # type: ignore[arg-type]
        assert result == 1

    def test_50_percent_usage(self, mixin: ConcreteQueue) -> None:
        result = mixin._compute_mtu_based_pack_limit(200, 50.0, 5)
        assert result == 20  # 200*0.5=100, 100//5=20


# ---------------------------------------------------------------------------
# Priority counter increment/decrement
# ---------------------------------------------------------------------------


class TestPriorityCounters:
    def test_inc_creates_counter(self, mixin: ConcreteQueue) -> None:
        owner: dict = {}
        mixin._inc_priority_counter(owner, 2)
        assert owner["priority_counts"][2] == 1

    def test_inc_increments_existing(self, mixin: ConcreteQueue) -> None:
        owner: dict = {"priority_counts": {2: 3}}
        mixin._inc_priority_counter(owner, 2)
        assert owner["priority_counts"][2] == 4

    def test_dec_decrements(self, mixin: ConcreteQueue) -> None:
        owner: dict = {"priority_counts": {2: 3}}
        mixin._dec_priority_counter(owner, 2)
        assert owner["priority_counts"][2] == 2

    def test_dec_removes_when_last(self, mixin: ConcreteQueue) -> None:
        owner: dict = {"priority_counts": {2: 1}}
        mixin._dec_priority_counter(owner, 2)
        assert 2 not in owner["priority_counts"]

    def test_dec_no_counters_is_noop(self, mixin: ConcreteQueue) -> None:
        owner: dict = {}
        mixin._dec_priority_counter(owner, 2)  # Should not raise

    def test_dec_missing_priority_is_noop(self, mixin: ConcreteQueue) -> None:
        owner: dict = {"priority_counts": {3: 1}}
        mixin._dec_priority_counter(owner, 2)  # Priority 2 doesn't exist


# ---------------------------------------------------------------------------
# _resolve_arq_packet_type
# ---------------------------------------------------------------------------


class TestResolveArqPacketType:
    def test_is_ack(self, mixin: ConcreteQueue) -> None:
        assert mixin._resolve_arq_packet_type(is_ack=True) == Packet_Type.STREAM_DATA_ACK

    def test_is_fin(self, mixin: ConcreteQueue) -> None:
        assert mixin._resolve_arq_packet_type(is_fin=True) == Packet_Type.STREAM_FIN

    def test_is_fin_ack(self, mixin: ConcreteQueue) -> None:
        assert mixin._resolve_arq_packet_type(is_fin_ack=True) == Packet_Type.STREAM_FIN_ACK

    def test_is_rst(self, mixin: ConcreteQueue) -> None:
        assert mixin._resolve_arq_packet_type(is_rst=True) == Packet_Type.STREAM_RST

    def test_is_rst_ack(self, mixin: ConcreteQueue) -> None:
        assert mixin._resolve_arq_packet_type(is_rst_ack=True) == Packet_Type.STREAM_RST_ACK

    def test_is_syn_ack(self, mixin: ConcreteQueue) -> None:
        assert mixin._resolve_arq_packet_type(is_syn_ack=True) == Packet_Type.STREAM_SYN_ACK

    def test_is_socks_syn_ack(self, mixin: ConcreteQueue) -> None:
        assert mixin._resolve_arq_packet_type(is_socks_syn_ack=True) == Packet_Type.SOCKS5_SYN_ACK

    def test_is_socks_syn(self, mixin: ConcreteQueue) -> None:
        assert mixin._resolve_arq_packet_type(is_socks_syn=True) == Packet_Type.SOCKS5_SYN

    def test_is_resend(self, mixin: ConcreteQueue) -> None:
        assert mixin._resolve_arq_packet_type(is_resend=True) == Packet_Type.STREAM_RESEND

    def test_default_is_stream_data(self, mixin: ConcreteQueue) -> None:
        assert mixin._resolve_arq_packet_type() == Packet_Type.STREAM_DATA

    def test_no_flags_is_stream_data(self, mixin: ConcreteQueue) -> None:
        assert mixin._resolve_arq_packet_type(something=True) == Packet_Type.STREAM_DATA


# ---------------------------------------------------------------------------
# _effective_priority_for_packet
# ---------------------------------------------------------------------------


class TestEffectivePriority:
    def test_stream_data_ack_is_zero(self, mixin: ConcreteQueue) -> None:
        assert mixin._effective_priority_for_packet(Packet_Type.STREAM_DATA_ACK, 5) == 0

    def test_stream_rst_is_zero(self, mixin: ConcreteQueue) -> None:
        assert mixin._effective_priority_for_packet(Packet_Type.STREAM_RST, 5) == 0

    def test_stream_rst_ack_is_zero(self, mixin: ConcreteQueue) -> None:
        assert mixin._effective_priority_for_packet(Packet_Type.STREAM_RST_ACK, 5) == 0

    def test_stream_fin_ack_is_zero(self, mixin: ConcreteQueue) -> None:
        assert mixin._effective_priority_for_packet(Packet_Type.STREAM_FIN_ACK, 5) == 0

    def test_stream_syn_ack_is_zero(self, mixin: ConcreteQueue) -> None:
        assert mixin._effective_priority_for_packet(Packet_Type.STREAM_SYN_ACK, 5) == 0

    def test_socks5_syn_ack_is_zero(self, mixin: ConcreteQueue) -> None:
        assert mixin._effective_priority_for_packet(Packet_Type.SOCKS5_SYN_ACK, 5) == 0

    def test_stream_fin_is_4(self, mixin: ConcreteQueue) -> None:
        assert mixin._effective_priority_for_packet(Packet_Type.STREAM_FIN, 5) == 4

    def test_stream_resend_is_1(self, mixin: ConcreteQueue) -> None:
        assert mixin._effective_priority_for_packet(Packet_Type.STREAM_RESEND, 5) == 1

    def test_stream_data_uses_provided_priority(self, mixin: ConcreteQueue) -> None:
        assert mixin._effective_priority_for_packet(Packet_Type.STREAM_DATA, 3) == 3


# ---------------------------------------------------------------------------
# _track_main_packet_once
# ---------------------------------------------------------------------------


class TestTrackMainPacketOnce:
    def test_stream_data_tracks_first(self, mixin: ConcreteQueue) -> None:
        owner: dict = {}
        result = mixin._track_main_packet_once(owner, Packet_Type.STREAM_DATA, 42)
        assert result is True
        assert 42 in owner["track_data"]

    def test_stream_data_deduplicates(self, mixin: ConcreteQueue) -> None:
        owner: dict = {}
        mixin._track_main_packet_once(owner, Packet_Type.STREAM_DATA, 42)
        result = mixin._track_main_packet_once(owner, Packet_Type.STREAM_DATA, 42)
        assert result is False

    def test_stream_data_ack_tracks_first(self, mixin: ConcreteQueue) -> None:
        owner: dict = {}
        result = mixin._track_main_packet_once(owner, Packet_Type.STREAM_DATA_ACK, 10)
        assert result is True

    def test_stream_data_ack_deduplicates(self, mixin: ConcreteQueue) -> None:
        owner: dict = {}
        mixin._track_main_packet_once(owner, Packet_Type.STREAM_DATA_ACK, 10)
        result = mixin._track_main_packet_once(owner, Packet_Type.STREAM_DATA_ACK, 10)
        assert result is False

    def test_stream_resend_tracks_once(self, mixin: ConcreteQueue) -> None:
        owner: dict = {}
        r1 = mixin._track_main_packet_once(owner, Packet_Type.STREAM_RESEND, 5)
        r2 = mixin._track_main_packet_once(owner, Packet_Type.STREAM_RESEND, 5)
        assert r1 is True
        assert r2 is False

    def test_stream_resend_blocked_by_existing_data(self, mixin: ConcreteQueue) -> None:
        owner: dict = {"track_data": {5}}
        result = mixin._track_main_packet_once(owner, Packet_Type.STREAM_RESEND, 5)
        assert result is False

    def test_stream_fin_tracks_once(self, mixin: ConcreteQueue) -> None:
        owner: dict = {}
        r1 = mixin._track_main_packet_once(owner, Packet_Type.STREAM_FIN, 0)
        r2 = mixin._track_main_packet_once(owner, Packet_Type.STREAM_FIN, 0)
        assert r1 is True
        assert r2 is False

    def test_stream_syn_tracks_once(self, mixin: ConcreteQueue) -> None:
        owner: dict = {}
        r1 = mixin._track_main_packet_once(owner, Packet_Type.STREAM_SYN, 0)
        r2 = mixin._track_main_packet_once(owner, Packet_Type.STREAM_SYN, 0)
        assert r1 is True
        assert r2 is False

    def test_other_packet_type_always_true(self, mixin: ConcreteQueue) -> None:
        owner: dict = {}
        result = mixin._track_main_packet_once(owner, Packet_Type.PING, 0)
        assert result is True


# ---------------------------------------------------------------------------
# _track_stream_packet_once
# ---------------------------------------------------------------------------


class TestTrackStreamPacketOnce:
    def _make_stream_data(self) -> dict:
        return {
            "track_data": set(),
            "track_resend": set(),
            "track_ack": set(),
            "track_fin": set(),
            "track_syn_ack": set(),
            "track_types": set(),
        }

    def test_stream_data_tracks(self, mixin: ConcreteQueue) -> None:
        sd = self._make_stream_data()
        r = mixin._track_stream_packet_once(sd, Packet_Type.STREAM_DATA, 1)
        assert r is True
        assert 1 in sd["track_data"]

    def test_stream_data_dedup(self, mixin: ConcreteQueue) -> None:
        sd = self._make_stream_data()
        mixin._track_stream_packet_once(sd, Packet_Type.STREAM_DATA, 1)
        r = mixin._track_stream_packet_once(sd, Packet_Type.STREAM_DATA, 1)
        assert r is False

    def test_stream_resend_blocked_by_data(self, mixin: ConcreteQueue) -> None:
        sd = self._make_stream_data()
        sd["track_data"].add(3)
        r = mixin._track_stream_packet_once(sd, Packet_Type.STREAM_RESEND, 3)
        assert r is False

    def test_stream_fin_dedup(self, mixin: ConcreteQueue) -> None:
        sd = self._make_stream_data()
        mixin._track_stream_packet_once(sd, Packet_Type.STREAM_FIN, 0)
        r = mixin._track_stream_packet_once(sd, Packet_Type.STREAM_FIN, 0)
        assert r is False

    def test_stream_syn_ack_dedup(self, mixin: ConcreteQueue) -> None:
        sd = self._make_stream_data()
        mixin._track_stream_packet_once(sd, Packet_Type.STREAM_SYN_ACK, 0)
        r = mixin._track_stream_packet_once(sd, Packet_Type.STREAM_SYN_ACK, 0)
        assert r is False

    def test_socks5_syn_ack_dedup(self, mixin: ConcreteQueue) -> None:
        sd = self._make_stream_data()
        mixin._track_stream_packet_once(sd, Packet_Type.SOCKS5_SYN_ACK, 0)
        r = mixin._track_stream_packet_once(sd, Packet_Type.SOCKS5_SYN_ACK, 0)
        assert r is False

    def test_data_ack_dedup(self, mixin: ConcreteQueue) -> None:
        sd = self._make_stream_data()
        mixin._track_stream_packet_once(sd, Packet_Type.STREAM_DATA_ACK, 7)
        r = mixin._track_stream_packet_once(sd, Packet_Type.STREAM_DATA_ACK, 7)
        assert r is False


# ---------------------------------------------------------------------------
# _release_tracking_on_pop
# ---------------------------------------------------------------------------


class TestReleaseTrackingOnPop:
    def test_releases_stream_data(self, mixin: ConcreteQueue) -> None:
        owner: dict = {"track_data": {5, 6, 7}}
        mixin._release_tracking_on_pop(owner, Packet_Type.STREAM_DATA, 5)
        assert 5 not in owner["track_data"]

    def test_releases_socks5_syn(self, mixin: ConcreteQueue) -> None:
        owner: dict = {"track_data": {1}}
        mixin._release_tracking_on_pop(owner, Packet_Type.SOCKS5_SYN, 1)
        assert 1 not in owner["track_data"]

    def test_releases_stream_data_ack(self, mixin: ConcreteQueue) -> None:
        owner: dict = {"track_ack": {3}}
        mixin._release_tracking_on_pop(owner, Packet_Type.STREAM_DATA_ACK, 3)
        assert 3 not in owner["track_ack"]

    def test_releases_stream_resend(self, mixin: ConcreteQueue) -> None:
        owner: dict = {"track_resend": {9}}
        mixin._release_tracking_on_pop(owner, Packet_Type.STREAM_RESEND, 9)
        assert 9 not in owner["track_resend"]

    def test_releases_stream_fin(self, mixin: ConcreteQueue) -> None:
        ptype = Packet_Type.STREAM_FIN
        owner: dict = {"track_fin": {ptype}, "track_types": {ptype}}
        mixin._release_tracking_on_pop(owner, ptype, 0)
        assert ptype not in owner["track_fin"]

    def test_releases_stream_syn(self, mixin: ConcreteQueue) -> None:
        ptype = Packet_Type.STREAM_SYN
        owner: dict = {"track_syn_ack": {ptype}, "track_types": {ptype}}
        mixin._release_tracking_on_pop(owner, ptype, 0)
        assert ptype not in owner["track_syn_ack"]


# ---------------------------------------------------------------------------
# _push_queue_item and _on_queue_pop
# ---------------------------------------------------------------------------


class TestPushAndPop:
    def test_push_adds_to_heap(self, mixin: ConcreteQueue) -> None:
        queue: list = []
        owner: dict = {}
        item = (0, 1, Packet_Type.STREAM_DATA, "session", 10, b"")
        mixin._push_queue_item(queue, owner, item)
        assert len(queue) == 1
        assert owner["priority_counts"][0] == 1

    def test_push_sets_event(self, mixin: ConcreteQueue) -> None:
        loop = asyncio.new_event_loop()
        try:
            event = loop.run_until_complete(asyncio.coroutine(lambda: asyncio.Event())())
        except Exception:
            event = MagicMock()
            event.set = MagicMock()

        queue: list = []
        owner: dict = {}
        item = (0, 1, Packet_Type.STREAM_DATA, "session", 10, b"")
        mixin._push_queue_item(queue, owner, item, tx_event=event)
        event.set.assert_called_once()

    def test_on_queue_pop_decrements_counter(self, mixin: ConcreteQueue) -> None:
        owner: dict = {"priority_counts": {0: 1}}
        item = (0, 1, Packet_Type.STREAM_DATA, "session", 10, b"")
        mixin._on_queue_pop(owner, item)
        assert 0 not in owner["priority_counts"]


# ---------------------------------------------------------------------------
# _pop_packable_control_block
# ---------------------------------------------------------------------------


class TestPopPackableControlBlock:
    def test_returns_none_when_empty(self, mixin: ConcreteQueue) -> None:
        owner: dict = {}
        result = mixin._pop_packable_control_block([], owner, 0)
        assert result is None

    def test_returns_none_when_wrong_priority(self, mixin: ConcreteQueue) -> None:
        queue: list = []
        owner: dict = {}
        item = (1, 1, Packet_Type.STREAM_FIN, "session", 0, b"")  # priority=1
        heapq.heappush(queue, item)
        owner.setdefault("priority_counts", {})[1] = 1
        result = mixin._pop_packable_control_block(queue, owner, 0)  # looking for priority=0
        assert result is None

    def test_returns_none_when_has_payload(self, mixin: ConcreteQueue) -> None:
        queue: list = []
        owner: dict = {}
        item = (0, 1, Packet_Type.STREAM_FIN, "session", 0, b"payload")  # has payload
        heapq.heappush(queue, item)
        owner.setdefault("priority_counts", {})[0] = 1
        result = mixin._pop_packable_control_block(queue, owner, 0)
        assert result is None

    def test_pops_valid_packable(self, mixin: ConcreteQueue) -> None:
        queue: list = []
        owner: dict = {}
        item = (0, 1, Packet_Type.STREAM_FIN, "session", 0, b"")  # STREAM_FIN is packable
        heapq.heappush(queue, item)
        owner.setdefault("priority_counts", {})[0] = 1
        result = mixin._pop_packable_control_block(queue, owner, 0)
        assert result == item
        assert len(queue) == 0

    def test_returns_none_when_not_packable_type(self, mixin: ConcreteQueue) -> None:
        queue: list = []
        owner: dict = {}
        item = (0, 1, Packet_Type.STREAM_DATA, "session", 0, b"")  # STREAM_DATA not packable
        heapq.heappush(queue, item)
        owner.setdefault("priority_counts", {})[0] = 1
        result = mixin._pop_packable_control_block(queue, owner, 0)
        assert result is None


# ---------------------------------------------------------------------------
# Hypothesis property-based tests
# ---------------------------------------------------------------------------


class TestHypothesisPacketQueueMixin:
    @given(
        st.integers(min_value=1, max_value=65535),
        st.floats(min_value=0.01, max_value=100.0),
        st.integers(min_value=1, max_value=512),
    )
    @settings(max_examples=50)
    def test_compute_mtu_pack_limit_non_negative(
        self, mtu: int, percent: float, block_size: int
    ) -> None:
        mixin = ConcreteQueue()
        result = mixin._compute_mtu_based_pack_limit(mtu, percent, block_size)
        assert result >= 1

    @given(st.integers(min_value=0, max_value=10))
    @settings(max_examples=30)
    def test_inc_dec_priority_is_balanced(self, count: int) -> None:
        mixin = ConcreteQueue()
        owner: dict = {"priority_counts": {}}
        for _ in range(count):
            mixin._inc_priority_counter(owner, 0)
        for _ in range(count):
            mixin._dec_priority_counter(owner, 0)
        assert owner["priority_counts"].get(0, 0) == 0

    @given(st.integers(min_value=0, max_value=100))
    @settings(max_examples=30)
    def test_priority_count_never_negative(self, inc_count: int) -> None:
        mixin = ConcreteQueue()
        owner: dict = {"priority_counts": {}}
        for _ in range(inc_count):
            mixin._inc_priority_counter(owner, 0)
        extra_decs = inc_count + 5
        for _ in range(extra_decs):
            mixin._dec_priority_counter(owner, 0)
        assert owner["priority_counts"].get(0, 0) >= 0
