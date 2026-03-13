# MasterDnsVPN
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import asyncio
import socket
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from .DNS_ENUMS import Packet_Type, Stream_State


@dataclass
class _PendingControlPacket:
    packet_type: int
    sequence_num: int
    ack_type: int
    payload: bytes
    priority: int
    retries: int = 0
    current_rto: float = 0.8
    time: float = 0.0
    create_time: float = 0.0


class ARQ:
    _active_tasks = set()

    CONTROL_ACK_PAIRS = {
        Packet_Type.STREAM_SYN: Packet_Type.STREAM_SYN_ACK,
        Packet_Type.STREAM_FIN: Packet_Type.STREAM_FIN_ACK,
        Packet_Type.STREAM_RST: Packet_Type.STREAM_RST_ACK,
        Packet_Type.SOCKS5_SYN: Packet_Type.SOCKS5_SYN_ACK,
        Packet_Type.STREAM_KEEPALIVE: Packet_Type.STREAM_KEEPALIVE_ACK,
        Packet_Type.STREAM_WINDOW_UPDATE: Packet_Type.STREAM_WINDOW_UPDATE_ACK,
        Packet_Type.STREAM_PROBE: Packet_Type.STREAM_PROBE_ACK,
        Packet_Type.SOCKS5_CONNECT_FAIL: Packet_Type.SOCKS5_CONNECT_FAIL_ACK,
        Packet_Type.SOCKS5_RULESET_DENIED: Packet_Type.SOCKS5_RULESET_DENIED_ACK,
        Packet_Type.SOCKS5_NETWORK_UNREACHABLE: Packet_Type.SOCKS5_NETWORK_UNREACHABLE_ACK,
        Packet_Type.SOCKS5_HOST_UNREACHABLE: Packet_Type.SOCKS5_HOST_UNREACHABLE_ACK,
        Packet_Type.SOCKS5_CONNECTION_REFUSED: Packet_Type.SOCKS5_CONNECTION_REFUSED_ACK,
        Packet_Type.SOCKS5_TTL_EXPIRED: Packet_Type.SOCKS5_TTL_EXPIRED_ACK,
        Packet_Type.SOCKS5_COMMAND_UNSUPPORTED: Packet_Type.SOCKS5_COMMAND_UNSUPPORTED_ACK,
        Packet_Type.SOCKS5_ADDRESS_TYPE_UNSUPPORTED: Packet_Type.SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
        Packet_Type.SOCKS5_AUTH_FAILED: Packet_Type.SOCKS5_AUTH_FAILED_ACK,
        Packet_Type.SOCKS5_UPSTREAM_UNAVAILABLE: Packet_Type.SOCKS5_UPSTREAM_UNAVAILABLE_ACK,
    }

    class _DummyLogger:
        def debug(self, *args, **kwargs):
            pass

        def info(self, *args, **kwargs):
            pass

        def warning(self, *args, **kwargs):
            pass

        def error(self, *args, **kwargs):
            pass

    def __init__(
        self,
        stream_id,
        session_id,
        enqueue_tx_cb,
        reader,
        writer,
        mtu,
        logger=None,
        window_size: int = 600,
        rto: float = 0.8,
        max_rto: float = 1.5,
        is_socks: bool = False,
        initial_data: bytes = b"",
        enqueue_control_tx_cb=None,
        enable_control_reliability: bool = False,
        control_rto: float = 0.8,
        control_max_rto: float = 2.5,
        control_max_retries: int = 15,
        inactivity_timeout: float = 1200.0,
        data_packet_ttl: float = 600.0,
        max_data_retries: int = 400,
        control_packet_ttl: float = 600.0,
        fin_drain_timeout: float = 300.0,
        graceful_drain_timeout: float = 600.0,
    ):
        # -----------------------------------------------------------------
        # Identity and I/O handles
        # -----------------------------------------------------------------
        self.stream_id = stream_id
        self.session_id = session_id
        self.enqueue_tx = enqueue_tx_cb
        self.enqueue_control_tx = enqueue_control_tx_cb
        if not self.enqueue_control_tx:
            raise ValueError(
                "enqueue_control_tx_cb is required for ARQ control-plane packets"
            )
        self.reader = reader
        self.writer = writer
        self.mtu = int(mtu)
        self.logger = logger or self._DummyLogger()

        # -----------------------------------------------------------------
        # Sequence and buffers
        # -----------------------------------------------------------------
        self.snd_nxt = 0
        self.rcv_nxt = 0
        self.snd_buf: Dict[int, Dict[str, object]] = {}
        self.rcv_buf: Dict[int, bytes] = {}
        self.control_snd_buf: Dict[Tuple[int, int], _PendingControlPacket] = {}

        # -----------------------------------------------------------------
        # Stream lifecycle and TCP-like control flags
        # -----------------------------------------------------------------
        self.state = Stream_State.OPEN
        self.closed = False
        self.close_reason = "Unknown"
        self.last_activity = time.monotonic()

        self._fin_sent = False
        self._fin_received = False
        self._fin_acked = False
        self._fin_seq_sent: Optional[int] = None
        self._fin_seq_received: Optional[int] = None

        self._rst_received = False
        self._rst_sent = False
        self._rst_acked = False
        self._rst_seq_sent: Optional[int] = None
        self._rst_seq_received: Optional[int] = None

        self._local_write_closed = False
        self._remote_write_closed = False
        # FIN-from-remote means stop local reader, but DO NOT drop queues.
        self._stop_local_read = False

        # -----------------------------------------------------------------
        # Data-plane ARQ profile (aggressive but capped by user max)
        # -----------------------------------------------------------------
        self.window_size = max(1, int(window_size))
        self.limit = max(50, int(self.window_size * 0.8))
        self.window_not_full = asyncio.Event()
        self.window_not_full.set()
        self._write_lock = asyncio.Lock()

        user_max_rto = max(0.05, float(max_rto))
        self.max_rto = user_max_rto
        self.rto = min(max(0.05, float(rto)), self.max_rto)

        self.inactivity_timeout = max(120.0, float(inactivity_timeout))
        self.data_packet_ttl = max(120.0, float(data_packet_ttl))
        self.max_data_retries = max(20, int(max_data_retries))
        self.fin_drain_timeout = max(30.0, float(fin_drain_timeout))
        self.graceful_drain_timeout = max(60.0, float(graceful_drain_timeout))

        # -----------------------------------------------------------------
        # Optional SOCKS pre-connection payload handling
        # -----------------------------------------------------------------
        self.is_socks = bool(is_socks)
        self.initial_data = initial_data
        self.socks_connected = asyncio.Event()
        if not self.is_socks:
            self.socks_connected.set()

        # -----------------------------------------------------------------
        # Control-plane ARQ profile (for SYN/FIN/RST/SOCKS control packets)
        # -----------------------------------------------------------------
        self.enable_control_reliability = bool(enable_control_reliability)
        user_control_max_rto = max(0.05, float(control_max_rto))
        self.control_max_rto = user_control_max_rto
        self.control_rto = min(max(0.05, float(control_rto)), self.control_max_rto)
        self.control_max_retries = max(5, int(control_max_retries))
        self.control_packet_ttl = max(120.0, float(control_packet_ttl))

        self._control_ack_map = dict(self.CONTROL_ACK_PAIRS)
        self._control_reverse_ack_map = {v: k for k, v in self._control_ack_map.items()}
        self._last_dup_ack_sn: Optional[int] = None
        self._last_dup_ack_time: float = 0.0

        try:
            sock = writer.get_extra_info("socket")
            if sock and sock.fileno() != -1:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except (OSError, AttributeError, Exception):
            pass

        try:
            loop = asyncio.get_running_loop()
            self.io_task = loop.create_task(self._io_loop())
            self.rtx_task = loop.create_task(self._retransmit_loop())

            ARQ._active_tasks.add(self.io_task)
            ARQ._active_tasks.add(self.rtx_task)
            self.io_task.add_done_callback(ARQ._active_tasks.discard)
            self.rtx_task.add_done_callback(ARQ._active_tasks.discard)
        except RuntimeError:
            self.io_task = None
            self.rtx_task = None

    # Set stream lifecycle state (uses Stream_State enum).
    def _set_state(self, new_state: str) -> None:
        self.state = new_state

    # Normalize sequence number to uint16 (0..65535).
    def _norm_sn(self, sn: int) -> int:
        return int(sn) & 0xFFFF

    # Check whether stream is in reset path.
    def is_reset(self) -> bool:
        return self.state == Stream_State.RESET or self._rst_received or self._rst_sent

    # Return True when local app side can continue reading.
    def is_open_for_local_read(self) -> bool:
        return (
            (not self.closed)
            and (not self._stop_local_read)
            and (not self._local_write_closed)
        )

    # Stop local reader after peer FIN; keep queues for draining.
    def set_local_reader_closed(self, reason: str = "") -> None:
        self._stop_local_read = True
        if reason:
            self.close_reason = reason
        if self.state == Stream_State.OPEN:
            self._set_state(Stream_State.HALF_CLOSED_REMOTE)

    # Mark local writer as closed (half-close local).
    def set_local_writer_closed(self) -> None:
        self._local_write_closed = True
        if self.state == Stream_State.OPEN:
            self._set_state(Stream_State.HALF_CLOSED_LOCAL)

    # Clear all buffers immediately (RST/abort semantics).
    def _clear_all_queues(self) -> None:
        self.snd_buf.clear()
        self.rcv_buf.clear()
        self.control_snd_buf.clear()
        self.window_not_full.set()

    # ---------------------------------------------------------------------
    # External transition hooks for client/server integration
    # ---------------------------------------------------------------------
    # Register outbound FIN and transition state.
    def mark_fin_sent(self, seq_num: Optional[int] = None) -> None:
        self._fin_sent = True
        if seq_num is not None:
            self._fin_seq_sent = self._norm_sn(seq_num)
        elif self._fin_seq_sent is None:
            self._fin_seq_sent = self._norm_sn(self.snd_nxt)

        if self._fin_received:
            self._set_state(Stream_State.CLOSING)
        else:
            self._set_state(Stream_State.HALF_CLOSED_LOCAL)

    # Register inbound FIN and stop local read side.
    def mark_fin_received(self, seq_num: int) -> None:
        self._fin_received = True
        self._fin_seq_received = self._norm_sn(seq_num)
        self._stop_local_read = True

        if self._fin_sent:
            self._set_state(Stream_State.CLOSING)
        else:
            self._set_state(Stream_State.HALF_CLOSED_REMOTE)

    # Register ACK for our FIN.
    def mark_fin_acked(self, seq_num: int) -> None:
        sn = self._norm_sn(seq_num)
        if self._fin_seq_sent is not None and sn == self._fin_seq_sent:
            self._fin_acked = True
        if self._fin_received:
            self._set_state(Stream_State.CLOSING)

    # Register outbound RST and move to RESET state.
    def mark_rst_sent(self, seq_num: Optional[int] = None) -> None:
        self._rst_sent = True
        if seq_num is not None:
            self._rst_seq_sent = self._norm_sn(seq_num)
        elif self._rst_seq_sent is None:
            self._rst_seq_sent = self._norm_sn(self.snd_nxt)
        self._set_state(Stream_State.RESET)

    # Register inbound RST and drop all buffers.
    def mark_rst_received(self, seq_num: int) -> None:
        self._rst_received = True
        self._rst_seq_received = self._norm_sn(seq_num)
        self._set_state(Stream_State.RESET)
        self._clear_all_queues()

    # Register ACK for our RST.
    def mark_rst_acked(self, seq_num: int) -> None:
        sn = self._norm_sn(seq_num)
        if self._rst_seq_sent is not None and sn == self._rst_seq_sent:
            self._rst_acked = True
        self._set_state(Stream_State.RESET)

    # ---------------------------------------------------------------------
    # Core loops
    # ---------------------------------------------------------------------
    # Read local socket data and enqueue reliable outbound packets.
    async def _io_loop(self):
        _read = self.reader.read
        _enqueue = self.enqueue_tx
        _monotonic = time.monotonic
        _mtu = self.mtu
        _limit = self.limit

        reset_required = False
        graceful_eof = False
        error_reason = None

        try:
            if self.is_socks and self.initial_data:
                offset = 0
                total_len = len(self.initial_data)
                while offset < total_len and not self.closed:
                    chunk = self.initial_data[offset : offset + _mtu]
                    sn = self.snd_nxt
                    self.snd_nxt = (sn + 1) % 65536

                    self.snd_buf[sn] = {
                        "data": chunk,
                        "time": _monotonic(),
                        "create_time": _monotonic(),
                        "retries": 0,
                        "current_rto": self.rto,
                    }
                    await _enqueue(3, self.stream_id, sn, chunk)
                    offset += _mtu

            await self.socks_connected.wait()

            while not self.closed:
                await self.window_not_full.wait()

                if self._fin_received and not self._stop_local_read:
                    self.set_local_reader_closed(
                        "Remote FIN received; local reader stopped"
                    )

                if self._stop_local_read:
                    self.close_reason = "Remote FIN received; local reader stopped"
                    break

                try:
                    raw_data = await _read(_mtu)
                except ConnectionResetError:
                    error_reason = "Local App Reset Connection (Dropped)"
                    reset_required = True
                    break
                except Exception as e:
                    error_reason = f"Read Error: {e}"
                    reset_required = True
                    break

                if not raw_data:
                    error_reason = "Local App Closed Connection (EOF)"
                    graceful_eof = True
                    break

                self.last_activity = _monotonic()
                sn = self.snd_nxt
                self.snd_nxt = (sn + 1) % 65536

                self.snd_buf[sn] = {
                    "data": raw_data,
                    "time": self.last_activity,
                    "create_time": _monotonic(),
                    "retries": 0,
                    "current_rto": self.rto,
                }

                if len(self.snd_buf) >= _limit:
                    self.window_not_full.clear()

                await _enqueue(3, self.stream_id, sn, raw_data)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.debug(f"Stream {self.stream_id} IO loop error: {e}")
        finally:
            if self.closed:
                return

            if reset_required:
                await self.abort(reason=error_reason or "Local reset/error")
                return

            if self._fin_received:
                # Do not drop outbound queue. Drain and then graceful close.
                wait_deadline = time.monotonic() + self.fin_drain_timeout
                while (
                    self.snd_buf
                    and time.monotonic() < wait_deadline
                    and not self.closed
                ):
                    await asyncio.sleep(0.05)

                if self.snd_buf and not self.closed:
                    await self.abort(
                        reason="Remote FIN received but local send buffer did not drain"
                    )
                    return

                if not self.closed:
                    await self._initiate_graceful_close(
                        reason="Remote FIN fully handled"
                    )
                return

            if graceful_eof:
                await self._initiate_graceful_close(reason=error_reason or "Local EOF")

    # Drain outstanding sends and then close with FIN.
    async def _initiate_graceful_close(self, reason="Graceful close"):
        if self.closed:
            return

        self.close_reason = reason
        if self.state not in (Stream_State.RESET, Stream_State.CLOSED):
            self._set_state(Stream_State.DRAINING)

        deadline = time.monotonic() + self.graceful_drain_timeout
        while self.snd_buf and time.monotonic() < deadline and not self.closed:
            await asyncio.sleep(0.05)

        if self.closed:
            return

        if self.snd_buf:
            await self.abort(reason=f"{reason} but send buffer did not drain")
            return

        await self.close(reason=reason, send_fin=True)

    # Complete remote FIN handling when receive sequence catches up.
    async def _try_finalize_remote_eof(self):
        if (
            self.closed
            or self._remote_write_closed
            or not self._fin_received
            or self._fin_seq_received is None
            or self.rcv_nxt != self._fin_seq_received
        ):
            return

        self._remote_write_closed = True

        try:
            if (
                self.writer
                and hasattr(self.writer, "can_write_eof")
                and self.writer.can_write_eof()
            ):
                self.writer.write_eof()
                try:
                    await self.writer.drain()
                except Exception:
                    pass
        except Exception:
            pass

        try:
            await self.send_control_packet(
                packet_type=Packet_Type.STREAM_FIN_ACK,
                sequence_num=self._fin_seq_received,
                payload=b"",
                priority=0,
                track_for_ack=False,
            )
        except Exception:
            pass

        if self._fin_sent and self._fin_acked and not self.snd_buf:
            await self.close(reason="Both FIN sides fully acknowledged")

    # Periodic scheduler that triggers data/control retransmission checks.
    async def _retransmit_loop(self):
        _sleep = asyncio.sleep
        try:
            while not self.closed:
                base_interval = max(
                    0.05,
                    min(
                        self.rto,
                        self.control_rto
                        if self.enable_control_reliability
                        else self.rto,
                    )
                    / 3.0,
                )
                has_pending = bool(self.snd_buf) or (
                    self.enable_control_reliability and bool(self.control_snd_buf)
                )

                interval = (
                    base_interval if has_pending else max(0.2, base_interval * 4.0)
                )
                await _sleep(interval)
                if self.closed:
                    break
                try:
                    await self.check_retransmits()
                except Exception as e:
                    self.logger.debug(
                        f"Retransmit check error on stream {self.stream_id}: {e}"
                    )
        except asyncio.CancelledError:
            pass

    # ---------------------------------------------------------------------
    # Data plane
    # ---------------------------------------------------------------------
    # Handle inbound STREAM_DATA and emit STREAM_DATA_ACK.
    async def receive_data(self, sn, data):
        if self.closed or self.is_reset():
            return

        now = time.monotonic()
        self.last_activity = now
        sn = self._norm_sn(sn)

        diff = (sn - self.rcv_nxt) % 65536
        if diff >= 32768:
            ack_throttle = max(0.05, min(self.rto, 0.3))
            if not (
                self._last_dup_ack_sn == sn
                and (now - self._last_dup_ack_time) < ack_throttle
            ):
                self._last_dup_ack_sn = sn
                self._last_dup_ack_time = now
                await self.enqueue_tx(0, self.stream_id, sn, b"", is_ack=True)
            return

        if diff > self.window_size:
            return

        # Hard cap reordering buffer to prevent unbounded growth under extreme loss.
        if sn not in self.rcv_buf and len(self.rcv_buf) >= self.window_size:
            return

        if sn not in self.rcv_buf:
            self.rcv_buf[sn] = data

        has_written = False
        _write = self.writer.write
        _pop = self.rcv_buf.pop
        data_to_write = []

        while self.rcv_nxt in self.rcv_buf:
            try:
                data_to_write.append(_pop(self.rcv_nxt))
                has_written = True
                self.rcv_nxt = (self.rcv_nxt + 1) % 65536
            except Exception as e:
                await self.abort(reason=f"RCV Buffer Error: {e}")
                return

        if has_written:
            try:
                async with self._write_lock:
                    _write(b"".join(data_to_write))
                    await self.writer.drain()
            except Exception as e:
                await self.abort(reason=f"Writer Error: {e}")
                return

        await self.enqueue_tx(0, self.stream_id, sn, b"", is_ack=True)
        await self._try_finalize_remote_eof()

    # Handle inbound STREAM_DATA_ACK and free send-window entries.
    async def receive_ack(self, sn):
        self.last_activity = time.monotonic()
        sn = self._norm_sn(sn)

        if self.snd_buf.pop(sn, None) is not None:
            if len(self.snd_buf) < self.limit:
                self.window_not_full.set()

    # Handle inbound STREAM_RST_ACK and resolve reset tracking.
    async def receive_rst_ack(self, sn):
        await self.receive_control_ack(Packet_Type.STREAM_RST_ACK, sn)

    # ---------------------------------------------------------------------
    # Control plane reliability helpers
    # ---------------------------------------------------------------------
    # Send control frame through dedicated control callback.
    async def _send_control_frame(
        self,
        packet_type: int,
        sequence_num: int,
        payload: bytes = b"",
        priority: int = 0,
        is_retransmit: bool = False,
    ) -> bool:
        ptype = int(packet_type)
        sn = self._norm_sn(sequence_num)
        data = payload or b""

        if not self.enqueue_control_tx:
            self.logger.error(
                f"Stream {self.stream_id}: enqueue_control_tx callback is required for control packets"
            )
            return False

        await self.enqueue_control_tx(
            int(priority),
            self.stream_id,
            sn,
            ptype,
            data,
            is_retransmit=is_retransmit,
        )
        return True

    # Track control packet until expected ACK arrives.
    def _track_control_packet(
        self,
        packet_type: int,
        sequence_num: int,
        ack_type: int,
        payload: bytes,
        priority: int,
    ) -> None:
        key = (int(packet_type), self._norm_sn(sequence_num))
        if key in self.control_snd_buf:
            return

        now = time.monotonic()
        self.control_snd_buf[key] = _PendingControlPacket(
            packet_type=int(packet_type),
            sequence_num=self._norm_sn(sequence_num),
            ack_type=int(ack_type),
            payload=payload or b"",
            priority=int(priority),
            retries=0,
            current_rto=self.control_rto,
            time=now,
            create_time=now,
        )

    # Send control packet and optionally enable ACK tracking.
    async def send_control_packet(
        self,
        packet_type: int,
        sequence_num: int,
        payload: bytes = b"",
        priority: int = 0,
        track_for_ack: bool = True,
        ack_type: Optional[int] = None,
    ) -> bool:
        ptype = int(packet_type)
        sn = self._norm_sn(sequence_num)

        sent = await self._send_control_frame(
            packet_type=ptype,
            sequence_num=sn,
            payload=payload,
            priority=priority,
            is_retransmit=False,
        )
        if not sent:
            return False

        if not (self.enable_control_reliability and track_for_ack):
            return True

        expected_ack = (
            int(ack_type) if ack_type is not None else self._control_ack_map.get(ptype)
        )
        if expected_ack is None:
            return True

        self._track_control_packet(
            packet_type=ptype,
            sequence_num=sn,
            ack_type=expected_ack,
            payload=payload,
            priority=priority,
        )
        return True

    # Mark tracked control packet as ACKed by ack_type + sequence.
    def _mark_control_acked(self, ack_packet_type: int, sequence_num: int) -> bool:
        ack_ptype = int(ack_packet_type)
        sn = self._norm_sn(sequence_num)

        origin_ptype = self._control_reverse_ack_map.get(ack_ptype)
        if origin_ptype is None:
            return self.control_snd_buf.pop((ack_ptype, sn), None) is not None

        if self.control_snd_buf.pop((origin_ptype, sn), None) is not None:
            return True

        return False

    # Process inbound control ACK and update FIN/RST state hooks.
    async def receive_control_ack(
        self, ack_packet_type: int, sequence_num: int
    ) -> bool:
        self.last_activity = time.monotonic()

        ack_ptype = int(ack_packet_type)
        sn = self._norm_sn(sequence_num)

        if ack_ptype == Packet_Type.STREAM_FIN_ACK:
            self.mark_fin_acked(sn)
        elif ack_ptype == Packet_Type.STREAM_RST_ACK:
            self.mark_rst_acked(sn)

        return self._mark_control_acked(ack_ptype, sn)

    # Retransmit pending control packets with aggressive capped RTO.
    async def _check_control_retransmits(self, now: float) -> None:
        if not self.control_snd_buf:
            return

        for key, info in list(self.control_snd_buf.items()):
            if (
                info.create_time + self.control_packet_ttl <= now
                or info.retries >= self.control_max_retries
            ):
                self.control_snd_buf.pop(key, None)
                continue

            if now - info.time < info.current_rto:
                continue

            sent = await self._send_control_frame(
                packet_type=info.packet_type,
                sequence_num=info.sequence_num,
                payload=info.payload,
                priority=info.priority,
                is_retransmit=True,
            )

            if not sent:
                self.control_snd_buf.pop(key, None)
                continue

            info.time = now
            info.retries += 1
            # Aggressive backoff but always capped by user max.
            info.current_rto = min(
                self.control_max_rto, max(self.control_rto, info.current_rto * 1.2)
            )

    # ---------------------------------------------------------------------
    # Retransmit / shutdown
    # ---------------------------------------------------------------------
    # Retransmit pending data/control packets and enforce lifetimes.
    async def check_retransmits(self):
        if self.closed:
            return

        if self._rst_received and self.state != Stream_State.RESET:
            self.mark_rst_received(self._rst_seq_received or 0)
            await self.abort(reason="Peer reset signaled", send_rst=False)
            return

        now = time.monotonic()

        # In high-loss / slow-resolver paths, do not kill active retransmit queues.
        if now - self.last_activity > self.inactivity_timeout:
            if self.snd_buf or (
                self.enable_control_reliability and self.control_snd_buf
            ):
                self.last_activity = now
            else:
                await self.abort(reason="Stream Inactivity Timeout (Dead)")
                return

        items_to_resend = []

        for sn, info in list(self.snd_buf.items()):
            if (
                info["create_time"] + self.data_packet_ttl <= now
                and info["retries"] >= self.max_data_retries
            ):
                await self.abort(reason=f"Max retransmissions exceeded for sn={sn}")
                return

            if now - info["time"] >= info["current_rto"]:
                items_to_resend.append((sn, info["data"]))
                info["time"] = now
                info["retries"] += 1
                # Aggressive and capped by max_rto from user config.
                info["current_rto"] = min(
                    self.max_rto, max(self.rto, info["current_rto"] * 1.2)
                )

        _enqueue = self.enqueue_tx
        _sid = self.stream_id

        for sn, data in items_to_resend:
            await _enqueue(1, _sid, sn, data, is_resend=True)

        if self.enable_control_reliability:
            await self._check_control_retransmits(now)

    # Abort stream immediately (RST behavior) and clear queues.
    async def abort(self, reason="Abort", send_rst=True):
        if self.closed:
            return

        self.close_reason = reason
        self._set_state(Stream_State.RESET)
        if send_rst and not self._rst_sent and not self._rst_received:
            self.mark_rst_sent(self.snd_nxt)
            try:
                await self.send_control_packet(
                    packet_type=Packet_Type.STREAM_RST,
                    sequence_num=self._rst_seq_sent,
                    payload=b"",
                    priority=0,
                    track_for_ack=self.enable_control_reliability,
                    ack_type=Packet_Type.STREAM_RST_ACK,
                )
            except Exception:
                pass
        # TCP RST behavior: drop all queued data immediately.
        self._clear_all_queues()
        await self.close(reason=reason, send_fin=False)

    # Close stream gracefully (or directly) and finalize resources.
    async def close(self, reason="Unknown", send_fin=True):
        if self.closed:
            return

        self.close_reason = reason
        if (
            send_fin
            and not self._fin_sent
            and not self._rst_sent
            and not self._rst_received
        ):
            self.mark_fin_sent(self.snd_nxt)
            try:
                await self.send_control_packet(
                    packet_type=Packet_Type.STREAM_FIN,
                    sequence_num=self._fin_seq_sent,
                    payload=b"",
                    priority=4,
                    track_for_ack=self.enable_control_reliability,
                    ack_type=Packet_Type.STREAM_FIN_ACK,
                )
            except Exception:
                pass
        if self.is_reset():
            self._set_state(Stream_State.RESET)
        elif self._fin_sent and self._fin_received:
            self._set_state(Stream_State.TIME_WAIT)
        else:
            self._set_state(Stream_State.CLOSING)

        self.closed = True

        current_task = asyncio.current_task()
        for task in (getattr(self, "io_task", None), getattr(self, "rtx_task", None)):
            if task and not task.done() and task is not current_task:
                task.cancel()
                try:
                    await asyncio.wait_for(task, timeout=0.2)
                except Exception:
                    pass

        try:
            if (
                self.writer
                and hasattr(self.writer, "is_closing")
                and not self.writer.is_closing()
            ):
                self.writer.close()
                try:
                    await asyncio.wait_for(self.writer.wait_closed(), timeout=0.5)
                except Exception:
                    pass
        except Exception:
            pass

        self._clear_all_queues()
        self._set_state(Stream_State.CLOSED)
