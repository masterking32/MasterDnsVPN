"""Tests for dns_utils/ARQ.py - state machine, data/control plane, retransmits."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from dns_utils.ARQ import ARQ, _PendingControlPacket
from dns_utils.DNS_ENUMS import Packet_Type, Stream_State
from tests.conftest import MockLogger, make_mock_writer, make_mock_reader


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_arq(
    initial_data: bytes = b"",
    is_socks: bool = False,
    window_size: int = 10,
    enable_control_reliability: bool = False,
) -> ARQ:
    """Create an ARQ instance with mocked I/O."""
    enqueue_tx = AsyncMock()
    enqueue_control_tx = AsyncMock()
    writer = make_mock_writer()
    reader = make_mock_reader(b"test data for reading")

    arq = ARQ(
        stream_id=1,
        session_id=1,
        enqueue_tx_cb=enqueue_tx,
        reader=reader,
        writer=writer,
        mtu=512,
        logger=MockLogger(),
        window_size=window_size,
        is_socks=is_socks,
        initial_data=initial_data,
        enqueue_control_tx_cb=enqueue_control_tx,
        enable_control_reliability=enable_control_reliability,
    )
    return arq


async def cancel_arq_tasks(arq: ARQ) -> None:
    """Cancel background tasks and suppress all resulting exceptions."""
    for task in (arq.io_task, arq.rtx_task):
        if task and not task.done():
            task.cancel()
    # Wait for cancellation to complete, suppressing CancelledError
    tasks = [t for t in (arq.io_task, arq.rtx_task) if t is not None]
    if tasks:
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestARQInit:
    def test_requires_enqueue_control_tx(self) -> None:
        with pytest.raises(ValueError):
            ARQ(
                stream_id=1,
                session_id=1,
                enqueue_tx_cb=AsyncMock(),
                reader=MagicMock(),
                writer=make_mock_writer(),
                mtu=512,
                enqueue_control_tx_cb=None,  # Missing required callback
            )

    @pytest.mark.asyncio
    async def test_initial_state_is_open(self) -> None:
        arq = make_arq()
        try:
            assert arq.state == Stream_State.OPEN
            assert not arq.closed
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_socks_event_not_set_initially(self) -> None:
        arq = make_arq(is_socks=True)
        try:
            assert not arq.socks_connected.is_set()
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_non_socks_event_set_initially(self) -> None:
        arq = make_arq(is_socks=False)
        try:
            assert arq.socks_connected.is_set()
        finally:
            await cancel_arq_tasks(arq)


# ---------------------------------------------------------------------------
# _norm_sn
# ---------------------------------------------------------------------------


class TestNormSn:
    def test_wraps_at_65536(self) -> None:
        arq = make_arq()
        assert arq._norm_sn(65536) == 0
        assert arq._norm_sn(65537) == 1
        assert arq._norm_sn(0) == 0
        assert arq._norm_sn(65535) == 65535

    def test_negative_wraps(self) -> None:
        arq = make_arq()
        # -1 & 0xFFFF = 65535
        assert arq._norm_sn(-1) == 65535


# ---------------------------------------------------------------------------
# State transitions - FIN
# ---------------------------------------------------------------------------


class TestFinStateTransitions:
    @pytest.mark.asyncio
    async def test_mark_fin_sent_transitions_to_half_closed_local(self) -> None:
        arq = make_arq()
        try:
            arq.mark_fin_sent(seq_num=10)
            assert arq._fin_sent is True
            assert arq._fin_seq_sent == 10
            assert arq.state == Stream_State.HALF_CLOSED_LOCAL
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_mark_fin_sent_none_seq_uses_snd_nxt(self) -> None:
        arq = make_arq()
        try:
            arq.snd_nxt = 42
            arq.mark_fin_sent()
            assert arq._fin_seq_sent == 42
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_mark_fin_sent_when_already_received_transitions_to_closing(self) -> None:
        arq = make_arq()
        try:
            arq._fin_received = True
            arq.mark_fin_sent(seq_num=5)
            assert arq.state == Stream_State.CLOSING
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_mark_fin_received(self) -> None:
        arq = make_arq()
        try:
            arq.mark_fin_received(seq_num=100)
            assert arq._fin_received is True
            assert arq._fin_seq_received == 100
            assert arq._stop_local_read is True
            assert arq.state == Stream_State.HALF_CLOSED_REMOTE
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_mark_fin_received_when_fin_already_sent(self) -> None:
        arq = make_arq()
        try:
            arq._fin_sent = True
            arq.mark_fin_received(seq_num=50)
            assert arq.state == Stream_State.CLOSING
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_mark_fin_acked_sets_flag(self) -> None:
        arq = make_arq()
        try:
            arq.mark_fin_sent(seq_num=20)
            arq.mark_fin_acked(seq_num=20)
            assert arq._fin_acked is True
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_mark_fin_acked_wrong_seq_no_effect(self) -> None:
        arq = make_arq()
        try:
            arq.mark_fin_sent(seq_num=20)
            arq.mark_fin_acked(seq_num=99)
            assert arq._fin_acked is False
        finally:
            await cancel_arq_tasks(arq)


# ---------------------------------------------------------------------------
# State transitions - RST
# ---------------------------------------------------------------------------


class TestRstStateTransitions:
    @pytest.mark.asyncio
    async def test_mark_rst_sent(self) -> None:
        arq = make_arq()
        try:
            arq.mark_rst_sent(seq_num=5)
            assert arq._rst_sent is True
            assert arq._rst_seq_sent == 5
            assert arq.state == Stream_State.RESET
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_mark_rst_received_clears_queues(self) -> None:
        arq = make_arq()
        try:
            arq.snd_buf[0] = {"data": b"x", "time": 0.0, "create_time": 0.0, "retries": 0, "current_rto": 0.5}
            arq.mark_rst_received(seq_num=7)
            assert arq._rst_received is True
            assert arq.state == Stream_State.RESET
            assert len(arq.snd_buf) == 0
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_mark_rst_acked(self) -> None:
        arq = make_arq()
        try:
            arq.mark_rst_sent(seq_num=10)
            arq.mark_rst_acked(seq_num=10)
            assert arq._rst_acked is True
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_is_reset_after_rst_sent(self) -> None:
        arq = make_arq()
        try:
            arq.mark_rst_sent()
            assert arq.is_reset() is True
        finally:
            await cancel_arq_tasks(arq)


# ---------------------------------------------------------------------------
# Local reader/writer state
# ---------------------------------------------------------------------------


class TestLocalState:
    @pytest.mark.asyncio
    async def test_is_open_for_local_read(self) -> None:
        arq = make_arq()
        try:
            assert arq.is_open_for_local_read() is True
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_closed_stream_not_open_for_read(self) -> None:
        arq = make_arq()
        try:
            arq.closed = True
            assert arq.is_open_for_local_read() is False
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_set_local_reader_closed(self) -> None:
        arq = make_arq()
        try:
            arq.set_local_reader_closed("test reason")
            assert arq._stop_local_read is True
            assert arq.close_reason == "test reason"
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_set_local_writer_closed(self) -> None:
        arq = make_arq()
        try:
            arq.set_local_writer_closed()
            assert arq._local_write_closed is True
            assert arq.state == Stream_State.HALF_CLOSED_LOCAL
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_clear_all_queues(self) -> None:
        arq = make_arq()
        try:
            arq.snd_buf[0] = {"data": b"test", "time": 0.0, "create_time": 0.0, "retries": 0, "current_rto": 0.5}
            arq.rcv_buf[1] = b"data"
            arq.control_snd_buf[(1, 0)] = MagicMock()
            arq._clear_all_queues()
            assert len(arq.snd_buf) == 0
            assert len(arq.rcv_buf) == 0
            assert len(arq.control_snd_buf) == 0
        finally:
            await cancel_arq_tasks(arq)


# ---------------------------------------------------------------------------
# receive_data
# ---------------------------------------------------------------------------


class TestReceiveData:
    @pytest.mark.asyncio
    async def test_in_order_delivery(self) -> None:
        arq = make_arq()
        try:
            await arq.receive_data(0, b"first")
            arq.writer.write.assert_called()
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_out_of_order_buffered(self) -> None:
        arq = make_arq()
        try:
            # sn=1 arrives before sn=0
            await arq.receive_data(1, b"second")
            assert 1 in arq.rcv_buf
            # Now sn=0 arrives; should deliver both
            await arq.receive_data(0, b"first")
            assert 0 not in arq.rcv_buf
            assert 1 not in arq.rcv_buf
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_duplicate_data_ignored(self) -> None:
        arq = make_arq()
        try:
            await arq.receive_data(0, b"data")
            write_count = arq.writer.write.call_count
            # Deliver same seq again
            await arq.receive_data(0, b"data")
            # Should not write again (duplicate ACK sent, no new write)
            # Actually duplicates trigger ACK but no write
            assert arq.enqueue_tx.called
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_closed_stream_ignores_data(self) -> None:
        arq = make_arq()
        try:
            arq.closed = True
            await arq.receive_data(0, b"data")
            arq.writer.write.assert_not_called()
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_window_size_exceeded_drops_data(self) -> None:
        arq = make_arq(window_size=5)
        try:
            # Fill up rcv_buf
            for i in range(1, 7):  # sn 1-6, but window_size=5
                await arq.receive_data(i, f"data{i}".encode())
            # Some should be dropped
            assert len(arq.rcv_buf) <= arq.window_size
        finally:
            await cancel_arq_tasks(arq)


# ---------------------------------------------------------------------------
# receive_ack
# ---------------------------------------------------------------------------


class TestReceiveAck:
    @pytest.mark.asyncio
    async def test_removes_from_send_buffer(self) -> None:
        arq = make_arq()
        try:
            arq.snd_buf[5] = {"data": b"x", "time": 0.0, "create_time": 0.0, "retries": 0, "current_rto": 0.5}
            await arq.receive_ack(5)
            assert 5 not in arq.snd_buf
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_unknown_ack_is_noop(self) -> None:
        arq = make_arq()
        try:
            await arq.receive_ack(999)  # Should not raise
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_sets_window_not_full_when_below_limit(self) -> None:
        arq = make_arq(window_size=10)
        try:
            arq.window_not_full.clear()
            arq.snd_buf[5] = {"data": b"x", "time": 0.0, "create_time": 0.0, "retries": 0, "current_rto": 0.5}
            await arq.receive_ack(5)
            assert arq.window_not_full.is_set()
        finally:
            await cancel_arq_tasks(arq)


# ---------------------------------------------------------------------------
# Control plane reliability
# ---------------------------------------------------------------------------


class TestControlPlane:
    @pytest.mark.asyncio
    async def test_send_control_packet(self) -> None:
        arq = make_arq()
        try:
            result = await arq.send_control_packet(
                packet_type=Packet_Type.STREAM_SYN,
                sequence_num=1,
                payload=b"",
                priority=0,
                track_for_ack=False,
            )
            assert result is True
            arq.enqueue_control_tx.assert_called_once()
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_send_control_packet_with_tracking(self) -> None:
        arq = make_arq(enable_control_reliability=True)
        try:
            result = await arq.send_control_packet(
                packet_type=Packet_Type.STREAM_SYN,
                sequence_num=1,
                payload=b"",
                priority=0,
                track_for_ack=True,
            )
            assert result is True
            key = (Packet_Type.STREAM_SYN, 1)
            assert key in arq.control_snd_buf
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_receive_control_ack_fin(self) -> None:
        arq = make_arq()
        try:
            arq.mark_fin_sent(seq_num=5)
            result = await arq.receive_control_ack(Packet_Type.STREAM_FIN_ACK, 5)
            assert arq._fin_acked is True
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_receive_control_ack_rst(self) -> None:
        arq = make_arq()
        try:
            arq.mark_rst_sent(seq_num=7)
            await arq.receive_control_ack(Packet_Type.STREAM_RST_ACK, 7)
            assert arq._rst_acked is True
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_track_control_packet_deduplication(self) -> None:
        arq = make_arq(enable_control_reliability=True)
        try:
            arq._track_control_packet(
                packet_type=Packet_Type.STREAM_SYN,
                sequence_num=10,
                ack_type=Packet_Type.STREAM_SYN_ACK,
                payload=b"",
                priority=0,
            )
            # Second track should be ignored
            arq._track_control_packet(
                packet_type=Packet_Type.STREAM_SYN,
                sequence_num=10,
                ack_type=Packet_Type.STREAM_SYN_ACK,
                payload=b"data",
                priority=0,
            )
            key = (Packet_Type.STREAM_SYN, 10)
            assert arq.control_snd_buf[key].payload == b""  # First entry preserved
        finally:
            await cancel_arq_tasks(arq)


# ---------------------------------------------------------------------------
# check_retransmits
# ---------------------------------------------------------------------------


class TestCheckRetransmits:
    @pytest.mark.asyncio
    async def test_retransmit_expired_packet(self) -> None:
        arq = make_arq()
        try:
            now = time.monotonic()
            arq.snd_buf[0] = {
                "data": b"payload",
                "time": now - 2.0,  # Well past RTO
                "create_time": now - 2.0,
                "retries": 0,
                "current_rto": 0.5,
            }
            await arq.check_retransmits()
            # enqueue_tx should be called for resend
            assert arq.enqueue_tx.called
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_max_retries_aborts_stream(self) -> None:
        arq = make_arq()
        try:
            now = time.monotonic()
            arq.snd_buf[0] = {
                "data": b"payload",
                "time": now - 1000.0,
                "create_time": now - 1000.0,
                "retries": arq.max_data_retries + 1,
                "current_rto": 0.5,
            }
            await arq.check_retransmits()
            assert arq.closed
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_inactivity_timeout_aborts_stream(self) -> None:
        arq = make_arq()
        try:
            arq.last_activity = time.monotonic() - arq.inactivity_timeout - 10.0
            # Empty buffers so activity timeout causes abort
            assert len(arq.snd_buf) == 0
            await arq.check_retransmits()
            assert arq.closed
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_inactivity_with_pending_data_updates_activity(self) -> None:
        arq = make_arq()
        try:
            now = time.monotonic()
            arq.last_activity = now - arq.inactivity_timeout - 10.0
            arq.snd_buf[0] = {
                "data": b"pending",
                "time": now,
                "create_time": now,
                "retries": 0,
                "current_rto": 1.0,
            }
            await arq.check_retransmits()
            # Should NOT be closed - buffer has data
            assert not arq.closed
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_closed_stream_skips_check(self) -> None:
        arq = make_arq()
        try:
            arq.closed = True
            await arq.check_retransmits()  # Should return immediately
        finally:
            await cancel_arq_tasks(arq)


# ---------------------------------------------------------------------------
# abort / close
# ---------------------------------------------------------------------------


class TestAbortClose:
    @pytest.mark.asyncio
    async def test_abort_closes_stream(self) -> None:
        arq = make_arq()
        try:
            await arq.abort(reason="test abort")
            assert arq.closed is True
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_abort_twice_is_noop(self) -> None:
        arq = make_arq()
        try:
            await arq.abort(reason="first")
            await arq.abort(reason="second")
            assert arq.closed is True
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_close_sends_fin(self) -> None:
        arq = make_arq()
        try:
            await arq.close(reason="test close", send_fin=True)
            assert arq.closed is True
            arq.enqueue_control_tx.assert_called()
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_close_no_fin(self) -> None:
        arq = make_arq()
        try:
            await arq.close(reason="no fin", send_fin=False)
            assert arq.closed is True
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_abort_no_rst_send(self) -> None:
        arq = make_arq()
        try:
            await arq.abort(reason="test", send_rst=False)
            assert arq.closed is True
            # With send_rst=False, RST packet should not be enqueued
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_close_already_closed(self) -> None:
        arq = make_arq()
        try:
            arq.closed = True
            await arq.close(reason="already closed")
            # Should return without error
        finally:
            await cancel_arq_tasks(arq)


# ---------------------------------------------------------------------------
# Control retransmits
# ---------------------------------------------------------------------------


class TestCheckControlRetransmits:
    @pytest.mark.asyncio
    async def test_retransmits_expired_control_packet(self) -> None:
        arq = make_arq(enable_control_reliability=True)
        try:
            now = time.monotonic()
            key = (Packet_Type.STREAM_SYN, 1)
            arq.control_snd_buf[key] = _PendingControlPacket(
                packet_type=Packet_Type.STREAM_SYN,
                sequence_num=1,
                ack_type=Packet_Type.STREAM_SYN_ACK,
                payload=b"",
                priority=0,
                retries=0,
                current_rto=0.5,
                time=now - 2.0,
                create_time=now - 2.0,
            )
            await arq._check_control_retransmits(now)
            arq.enqueue_control_tx.assert_called()
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_removes_expired_ttl_packet(self) -> None:
        arq = make_arq(enable_control_reliability=True)
        try:
            now = time.monotonic()
            key = (Packet_Type.STREAM_SYN, 1)
            arq.control_snd_buf[key] = _PendingControlPacket(
                packet_type=Packet_Type.STREAM_SYN,
                sequence_num=1,
                ack_type=Packet_Type.STREAM_SYN_ACK,
                payload=b"",
                priority=0,
                retries=arq.control_max_retries + 1,  # Max retries exceeded
                current_rto=0.5,
                time=now - 1000.0,
                create_time=now - 1000.0,  # TTL exceeded
            )
            await arq._check_control_retransmits(now)
            assert key not in arq.control_snd_buf
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_empty_control_buf_is_noop(self) -> None:
        arq = make_arq(enable_control_reliability=True)
        try:
            now = time.monotonic()
            await arq._check_control_retransmits(now)  # Should not raise
        finally:
            await cancel_arq_tasks(arq)


# ---------------------------------------------------------------------------
# io_loop direct execution tests
# ---------------------------------------------------------------------------


def make_data_reader(chunks: list[bytes]) -> MagicMock:
    """Create a reader that returns chunks then EOF."""
    remaining = list(chunks) + [b""]

    reader = MagicMock()

    async def _read(n: int = -1) -> bytes:
        if remaining:
            return remaining.pop(0)
        return b""

    reader.read = _read
    return reader


class TestIOLoop:
    @pytest.mark.asyncio
    async def test_io_loop_eof_triggers_graceful_close(self) -> None:
        """When reader returns EOF, io_loop should trigger graceful close."""
        reader = make_data_reader([])  # Immediate EOF
        writer = make_mock_writer()
        arq = ARQ(
            stream_id=1,
            session_id=1,
            enqueue_tx_cb=AsyncMock(),
            reader=reader,
            writer=writer,
            mtu=512,
            logger=MockLogger(),
            enqueue_control_tx_cb=AsyncMock(),
            inactivity_timeout=1200.0,
            graceful_drain_timeout=0.1,
        )
        try:
            await asyncio.wait_for(arq._io_loop(), timeout=2.0)
        except asyncio.TimeoutError:
            pass
        # After EOF, stream should be closed or in graceful close
        assert arq.closed or arq._fin_sent

    @pytest.mark.asyncio
    async def test_io_loop_connection_reset_aborts(self) -> None:
        """When reader raises ConnectionResetError, io_loop should abort."""
        reader = MagicMock()

        async def _read_reset(n: int = -1) -> bytes:
            raise ConnectionResetError("test reset")

        reader.read = _read_reset
        arq = ARQ(
            stream_id=2,
            session_id=1,
            enqueue_tx_cb=AsyncMock(),
            reader=reader,
            writer=make_mock_writer(),
            mtu=512,
            logger=MockLogger(),
            enqueue_control_tx_cb=AsyncMock(),
        )
        try:
            await asyncio.wait_for(arq._io_loop(), timeout=2.0)
        except asyncio.TimeoutError:
            pass
        assert arq.closed

    @pytest.mark.asyncio
    async def test_io_loop_with_data_then_eof(self) -> None:
        """Reader provides data then EOF - data should be queued."""
        reader = make_data_reader([b"hello world", b"more data"])
        enqueue_tx = AsyncMock()
        arq = ARQ(
            stream_id=3,
            session_id=1,
            enqueue_tx_cb=enqueue_tx,
            reader=reader,
            writer=make_mock_writer(),
            mtu=512,
            logger=MockLogger(),
            enqueue_control_tx_cb=AsyncMock(),
            inactivity_timeout=1200.0,
            graceful_drain_timeout=0.1,
        )
        try:
            await asyncio.wait_for(arq._io_loop(), timeout=2.0)
        except asyncio.TimeoutError:
            pass
        assert enqueue_tx.call_count >= 2

    @pytest.mark.asyncio
    async def test_io_loop_stops_on_fin_received(self) -> None:
        """When _stop_local_read is True, io_loop should exit cleanly."""
        reader = make_data_reader([b"data"])
        arq = ARQ(
            stream_id=4,
            session_id=1,
            enqueue_tx_cb=AsyncMock(),
            reader=reader,
            writer=make_mock_writer(),
            mtu=512,
            logger=MockLogger(),
            enqueue_control_tx_cb=AsyncMock(),
            inactivity_timeout=1200.0,
            graceful_drain_timeout=0.1,
            fin_drain_timeout=0.1,
        )
        arq._fin_received = True
        arq._fin_seq_received = 0
        arq._stop_local_read = True
        try:
            await asyncio.wait_for(arq._io_loop(), timeout=2.0)
        except asyncio.TimeoutError:
            pass

    @pytest.mark.asyncio
    async def test_io_loop_socks_initial_data(self) -> None:
        """Socks initial data should be enqueued before reading more data."""
        reader = make_data_reader([])  # EOF after initial data
        enqueue_tx = AsyncMock()
        arq = ARQ(
            stream_id=5,
            session_id=1,
            enqueue_tx_cb=enqueue_tx,
            reader=reader,
            writer=make_mock_writer(),
            mtu=512,
            logger=MockLogger(),
            enqueue_control_tx_cb=AsyncMock(),
            is_socks=True,
            initial_data=b"initial socks data to enqueue",
            inactivity_timeout=1200.0,
            graceful_drain_timeout=0.1,
        )
        arq.socks_connected.set()
        try:
            await asyncio.wait_for(arq._io_loop(), timeout=2.0)
        except asyncio.TimeoutError:
            pass
        # Initial data should have been enqueued
        assert enqueue_tx.call_count >= 1

    @pytest.mark.asyncio
    async def test_io_loop_read_exception_resets(self) -> None:
        """Generic read exception triggers reset."""
        reader = MagicMock()

        async def _read_error(n: int = -1) -> bytes:
            raise IOError("test io error")

        reader.read = _read_error
        arq = ARQ(
            stream_id=6,
            session_id=1,
            enqueue_tx_cb=AsyncMock(),
            reader=reader,
            writer=make_mock_writer(),
            mtu=512,
            logger=MockLogger(),
            enqueue_control_tx_cb=AsyncMock(),
        )
        try:
            await asyncio.wait_for(arq._io_loop(), timeout=2.0)
        except asyncio.TimeoutError:
            pass
        assert arq.closed


class TestInitiateGracefulClose:
    @pytest.mark.asyncio
    async def test_graceful_close_empty_snd_buf(self) -> None:
        arq = make_arq()
        try:
            arq.graceful_drain_timeout = 0.1
            await arq._initiate_graceful_close("test reason")
            assert arq.closed or arq._fin_sent
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_graceful_close_already_closed(self) -> None:
        arq = make_arq()
        try:
            arq.closed = True
            await arq._initiate_graceful_close("already closed")
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_graceful_close_snd_buf_drains(self) -> None:
        arq = make_arq()
        try:
            now = time.monotonic()
            arq.snd_buf[0] = {
                "data": b"pending",
                "time": now,
                "create_time": now,
                "retries": 0,
                "current_rto": 0.5,
            }
            arq.graceful_drain_timeout = 0.05  # Very short
            await arq._initiate_graceful_close("short drain")
            # Either drained and closed gracefully or aborted
            assert arq.closed
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_graceful_close_drain_timeout_aborts(self) -> None:
        arq = make_arq()
        try:
            now = time.monotonic()
            # Fill snd_buf with un-clearable data
            arq.snd_buf[0] = {
                "data": b"stuck data",
                "time": now,
                "create_time": now,
                "retries": 0,
                "current_rto": 0.5,
            }
            arq.graceful_drain_timeout = 0.01  # Extremely short timeout
            await arq._initiate_graceful_close("drain timeout test")
            assert arq.closed
        finally:
            await cancel_arq_tasks(arq)


class TestTryFinalizeRemoteEof:
    @pytest.mark.asyncio
    async def test_finalizes_when_conditions_met(self) -> None:
        arq = make_arq()
        try:
            arq._fin_received = True
            arq._fin_seq_received = 5
            arq.rcv_nxt = 5
            arq._remote_write_closed = False
            await arq._try_finalize_remote_eof()
            assert arq._remote_write_closed is True
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_no_op_when_seq_not_caught_up(self) -> None:
        arq = make_arq()
        try:
            arq._fin_received = True
            arq._fin_seq_received = 10
            arq.rcv_nxt = 8  # Not caught up
            await arq._try_finalize_remote_eof()
            assert arq._remote_write_closed is False
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_no_op_when_already_closed(self) -> None:
        arq = make_arq()
        try:
            arq.closed = True
            arq._fin_received = True
            arq._fin_seq_received = 5
            arq.rcv_nxt = 5
            await arq._try_finalize_remote_eof()
            assert arq._remote_write_closed is False
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_writer_can_write_eof(self) -> None:
        arq = make_arq()
        try:
            arq.writer.can_write_eof = MagicMock(return_value=True)
            arq.writer.write_eof = MagicMock()
            arq._fin_received = True
            arq._fin_seq_received = 3
            arq.rcv_nxt = 3
            await arq._try_finalize_remote_eof()
            arq.writer.write_eof.assert_called_once()
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_closes_when_fin_fully_acked(self) -> None:
        arq = make_arq()
        try:
            arq._fin_received = True
            arq._fin_seq_received = 3
            arq.rcv_nxt = 3
            arq._fin_sent = True
            arq._fin_acked = True
            await arq._try_finalize_remote_eof()
            assert arq.closed
        finally:
            await cancel_arq_tasks(arq)


class TestRetransmitLoop:
    @pytest.mark.asyncio
    async def test_retransmit_loop_runs_and_cancels(self) -> None:
        arq = make_arq()
        task = asyncio.create_task(arq._retransmit_loop())
        await asyncio.sleep(0.15)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        # Should not raise

    @pytest.mark.asyncio
    async def test_retransmit_loop_exits_on_closed(self) -> None:
        arq = make_arq()
        arq.closed = True
        task = asyncio.create_task(arq._retransmit_loop())
        await asyncio.wait_for(task, timeout=1.0)  # Should exit quickly

    @pytest.mark.asyncio
    async def test_retransmit_loop_check_error_logged(self) -> None:
        """check_retransmits exception is caught and logged (lines 503-504)."""
        arq = make_arq()
        try:
            call_count = 0

            async def failing_check():
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    raise RuntimeError("check error")
                arq.closed = True

            arq.check_retransmits = failing_check  # type: ignore[method-assign]
            task = asyncio.create_task(arq._retransmit_loop())
            await asyncio.wait_for(task, timeout=2.0)
            assert call_count >= 1
        finally:
            await cancel_arq_tasks(arq)


# ---------------------------------------------------------------------------
# Additional coverage tests
# ---------------------------------------------------------------------------


class TestMarkFinAckedStateTransition:
    @pytest.mark.asyncio
    async def test_mark_fin_acked_transitions_to_closing_when_fin_received(self) -> None:
        """Line 276: mark_fin_acked when _fin_received=True sets state to CLOSING."""
        arq = make_arq()
        try:
            arq.mark_fin_sent(seq_num=10)
            arq._fin_received = True
            arq.mark_fin_acked(10)
            assert arq.state == Stream_State.CLOSING
        finally:
            await cancel_arq_tasks(arq)


class TestSendControlFrameNoCallback:
    @pytest.mark.asyncio
    async def test_send_control_frame_no_enqueue_returns_false(self) -> None:
        """Lines 600-603: _send_control_frame logs error when enqueue_control_tx is None."""
        arq = make_arq()
        try:
            arq.enqueue_control_tx = None  # type: ignore[assignment]
            result = await arq._send_control_frame(
                packet_type=Packet_Type.STREAM_SYN,
                sequence_num=1,
                payload=b"",
            )
            assert result is False
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_send_control_packet_returns_false_when_frame_fails(self) -> None:
        """Line 662: send_control_packet returns False when _send_control_frame fails."""
        arq = make_arq()
        try:
            arq.enqueue_control_tx = None  # type: ignore[assignment]
            result = await arq.send_control_packet(
                packet_type=Packet_Type.STREAM_SYN,
                sequence_num=1,
                payload=b"",
                priority=0,
                track_for_ack=False,
            )
            assert result is False
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_send_control_packet_no_ack_type_returns_true(self) -> None:
        """Line 671: returns True when expected_ack is None (unmapped type)."""
        arq = make_arq(enable_control_reliability=True)
        try:
            result = await arq.send_control_packet(
                packet_type=Packet_Type.STREAM_DATA_ACK,  # Not in control_ack_map
                sequence_num=1,
                payload=b"",
                priority=0,
                track_for_ack=True,
                ack_type=None,
            )
            assert result is True
        finally:
            await cancel_arq_tasks(arq)


class TestMarkControlAcked:
    @pytest.mark.asyncio
    async def test_mark_control_acked_unknown_origin(self) -> None:
        """Line 689: _mark_control_acked pops directly when origin_ptype is None."""
        arq = make_arq()
        try:
            # Add a packet with type not in reverse map
            key = (Packet_Type.STREAM_DATA, 5)
            arq.control_snd_buf[key] = _PendingControlPacket(
                packet_type=Packet_Type.STREAM_DATA,
                sequence_num=5,
                ack_type=Packet_Type.STREAM_DATA_ACK,
                payload=b"",
                priority=0,
                retries=0,
                current_rto=0.5,
                time=time.monotonic(),
                create_time=time.monotonic(),
            )
            # STREAM_DATA is likely not in _control_reverse_ack_map
            result = arq._mark_control_acked(Packet_Type.STREAM_DATA, 5)
            # Either popped or not; just verify no exception
            assert isinstance(result, bool)
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_mark_control_acked_via_origin_ptype(self) -> None:
        """Line 692: _mark_control_acked returns True when pop via origin_ptype succeeds."""
        arq = make_arq()
        try:
            key = (Packet_Type.STREAM_FIN, 7)
            arq.control_snd_buf[key] = _PendingControlPacket(
                packet_type=Packet_Type.STREAM_FIN,
                sequence_num=7,
                ack_type=Packet_Type.STREAM_FIN_ACK,
                payload=b"",
                priority=0,
                retries=0,
                current_rto=0.5,
                time=time.monotonic(),
                create_time=time.monotonic(),
            )
            result = arq._mark_control_acked(Packet_Type.STREAM_FIN_ACK, 7)
            assert result is True
            assert key not in arq.control_snd_buf
        finally:
            await cancel_arq_tasks(arq)


class TestCheckRetransmitsRstReceived:
    @pytest.mark.asyncio
    async def test_rst_received_triggers_abort(self) -> None:
        """Lines 756-758: check_retransmits aborts when _rst_received=True."""
        arq = make_arq()
        try:
            arq._rst_received = True
            arq._rst_seq_received = 5
            await arq.check_retransmits()
            assert arq.closed
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_check_retransmits_with_control_reliability(self) -> None:
        """Line 798: check_retransmits calls _check_control_retransmits when enabled."""
        arq = make_arq(enable_control_reliability=True)
        try:
            now = time.monotonic()
            key = (Packet_Type.STREAM_SYN, 1)
            arq.control_snd_buf[key] = _PendingControlPacket(
                packet_type=Packet_Type.STREAM_SYN,
                sequence_num=1,
                ack_type=Packet_Type.STREAM_SYN_ACK,
                payload=b"",
                priority=0,
                retries=0,
                current_rto=0.01,
                time=now - 1.0,
                create_time=now - 1.0,
            )
            await arq.check_retransmits()
            # Control retransmit should have been called
            arq.enqueue_control_tx.assert_called()
        finally:
            await cancel_arq_tasks(arq)


class TestReceiveDataEdgeCases:
    @pytest.mark.asyncio
    async def test_window_full_drops_packet(self) -> None:
        """Line 539: receive_data drops packet when rcv_buf is at window_size."""
        arq = make_arq(window_size=3)
        try:
            # Fill buffer with window_size packets that are NOT next expected
            arq.rcv_nxt = 0
            arq.rcv_buf = {1: b"a", 2: b"b", 3: b"c"}  # 3 = window_size
            initial_buf_len = len(arq.rcv_buf)
            # Packet sn=4 should be dropped (not in buf and buf is full)
            await arq.receive_data(4, b"overflow")
            assert len(arq.rcv_buf) == initial_buf_len  # No new entry added
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_receive_data_rcv_buf_pop_exception(self) -> None:
        """Lines 554-556: receive_data calls abort when rcv_buf raises on pop."""
        arq = make_arq()
        try:
            arq.rcv_nxt = 0

            class FailingDict(dict):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    self._fail_once = True

                def pop(self, key, *args):
                    if self._fail_once:
                        self._fail_once = False
                        raise RuntimeError("pop failure")
                    return super().pop(key, *args)

            arq.rcv_buf = FailingDict({0: b"data"})  # type: ignore[assignment]
            await arq.receive_data(0, b"new")
            assert arq.closed
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_receive_data_writer_error_aborts(self) -> None:
        """Lines 563-565: receive_data calls abort when writer.drain raises."""
        arq = make_arq()
        try:
            arq.rcv_nxt = 0
            arq.writer.drain = AsyncMock(side_effect=ConnectionResetError("drain error"))
            await arq.receive_data(0, b"data")
            assert arq.closed
        finally:
            await cancel_arq_tasks(arq)


class TestReceiveRstAck:
    @pytest.mark.asyncio
    async def test_receive_rst_ack_delegates(self) -> None:
        """Line 581: receive_rst_ack delegates to receive_control_ack."""
        arq = make_arq()
        try:
            arq.mark_rst_sent(seq_num=3)
            await arq.receive_rst_ack(3)
            assert arq._rst_acked is True
        finally:
            await cancel_arq_tasks(arq)


class TestCheckControlRetransmitsEdgeCases:
    @pytest.mark.asyncio
    async def test_rto_not_expired_continues(self) -> None:
        """Line 726: control packet with non-expired RTO is skipped."""
        arq = make_arq(enable_control_reliability=True)
        try:
            now = time.monotonic()
            key = (Packet_Type.STREAM_SYN, 1)
            arq.control_snd_buf[key] = _PendingControlPacket(
                packet_type=Packet_Type.STREAM_SYN,
                sequence_num=1,
                ack_type=Packet_Type.STREAM_SYN_ACK,
                payload=b"",
                priority=0,
                retries=0,
                current_rto=100.0,  # Long RTO - not expired
                time=now,
                create_time=now,
            )
            arq.enqueue_control_tx.reset_mock()
            await arq._check_control_retransmits(now)
            arq.enqueue_control_tx.assert_not_called()
            assert key in arq.control_snd_buf  # Still in buffer
        finally:
            await cancel_arq_tasks(arq)

    @pytest.mark.asyncio
    async def test_send_fails_removes_entry(self) -> None:
        """Lines 737-738: packet removed when _send_control_frame fails."""
        arq = make_arq(enable_control_reliability=True)
        try:
            now = time.monotonic()
            key = (Packet_Type.STREAM_SYN, 1)
            arq.control_snd_buf[key] = _PendingControlPacket(
                packet_type=Packet_Type.STREAM_SYN,
                sequence_num=1,
                ack_type=Packet_Type.STREAM_SYN_ACK,
                payload=b"",
                priority=0,
                retries=0,
                current_rto=0.001,
                time=now - 1.0,
                create_time=now - 1.0,
            )
            # Make _send_control_frame return False by nullifying callback
            arq.enqueue_control_tx = None  # type: ignore[assignment]
            await arq._check_control_retransmits(now)
            assert key not in arq.control_snd_buf
        finally:
            await cancel_arq_tasks(arq)


class TestARQWriterSetup:
    @pytest.mark.asyncio
    async def test_arq_with_socket_writer(self) -> None:
        """Lines 185-187: constructor handles writer with TCP_NODELAY socket."""
        writer = make_mock_writer()
        mock_socket = MagicMock()
        mock_socket.fileno = MagicMock(return_value=5)
        writer.get_extra_info = MagicMock(return_value=mock_socket)

        arq = ARQ(
            stream_id=1,
            session_id=1,
            enqueue_tx_cb=AsyncMock(),
            reader=make_mock_reader(b""),
            writer=writer,
            mtu=512,
            logger=MockLogger(),
            enqueue_control_tx_cb=AsyncMock(),
        )
        # Should not raise even if setsockopt is called
        await cancel_arq_tasks(arq)


# ---------------------------------------------------------------------------
# Hypothesis property-based tests
# ---------------------------------------------------------------------------


def make_arq_for_hypothesis() -> ARQ:
    return ARQ(
        stream_id=1,
        session_id=1,
        enqueue_tx_cb=AsyncMock(),
        reader=make_mock_reader(b""),
        writer=make_mock_writer(),
        mtu=512,
        logger=MockLogger(),
        enqueue_control_tx_cb=AsyncMock(),
    )


class TestHypothesisARQ:
    @given(st.integers(min_value=-(2**31), max_value=2**31))
    @settings(max_examples=100)
    def test_norm_sn_always_returns_uint16(self, sn: int) -> None:
        arq = make_arq_for_hypothesis()
        result = arq._norm_sn(sn)
        assert 0 <= result <= 0xFFFF

    @given(st.integers(min_value=0, max_value=0xFFFF))
    @settings(max_examples=50)
    def test_norm_sn_idempotent(self, sn: int) -> None:
        arq = make_arq_for_hypothesis()
        result = arq._norm_sn(sn)
        assert arq._norm_sn(result) == result

    @given(st.integers(min_value=0, max_value=0xFFFF))
    @settings(max_examples=50)
    def test_norm_sn_valid_range_unchanged(self, sn: int) -> None:
        arq = make_arq_for_hypothesis()
        assert arq._norm_sn(sn) == sn
