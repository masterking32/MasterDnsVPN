# MasterDnsVPN
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import asyncio
import socket
import time


class ARQ:
    _active_tasks = set()

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
    ):
        self.stream_id = stream_id
        self.session_id = session_id
        self.enqueue_tx = enqueue_tx_cb
        self.reader = reader
        self.writer = writer
        self.mtu = mtu

        self.snd_nxt = 0
        self.rcv_nxt = 0
        self.snd_buf = {}
        self.rcv_buf = {}

        self.last_activity = time.monotonic()
        self.closed = False
        self.close_reason = "Unknown"
        self.logger = logger or self._DummyLogger()

        self._fin_sent = False
        self._fin_received = False
        self._fin_acked = False
        self._fin_seq_sent = None
        self._fin_seq_received = None

        self._rst_received = False
        self._rst_sent = False
        self._close_time = None

        self._local_write_closed = False
        self._remote_write_closed = False

        self.rto = rto
        self.max_rto = max_rto

        self.window_size = window_size
        self.limit = max(50, int(self.window_size * 0.8))
        self.window_not_full = asyncio.Event()
        self.window_not_full.set()
        self._write_lock = asyncio.Lock()

        self.is_socks = is_socks
        self.initial_data = initial_data
        self.socks_connected = asyncio.Event()
        if not self.is_socks:
            self.socks_connected.set()

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
                while offset < total_len:
                    chunk = self.initial_data[offset : offset + _mtu]
                    sn = self.snd_nxt
                    self.snd_nxt = (sn + 1) % 65536

                    self.snd_buf[sn] = {
                        "data": chunk,
                        "time": _monotonic(),
                        "create_time": _monotonic(),
                        "retries": 0,
                        "current_rto": self.rto,
                        "is_socks_syn": True,
                    }
                    await _enqueue(3, self.stream_id, sn, chunk, is_socks_syn=True)
                    offset += _mtu

            await self.socks_connected.wait()

            while not self.closed:
                await self.window_not_full.wait()

                if self._fin_received:
                    self.close_reason = "FIN Received, No More Data to Send"
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
                    "time": self.last_activity,,
                    "create_time": _monotonic(),
                    "retries": 0,
                    "current_rto": self.rto,
                    "is_socks_syn": False,
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
                wait_deadline = time.monotonic() + 180.0
                while (
                    self.snd_buf
                    and time.monotonic() < wait_deadline
                    and not self.closed
                ):
                    await asyncio.sleep(0.05)

                if self.snd_buf and not self.closed:
                    await self.abort(
                        reason="Remote FIN but local send buffer did not drain"
                    )
                    return

                if not self.closed:
                    await self._initiate_graceful_close(
                        reason="Remote FIN fully handled"
                    )
                return

            if graceful_eof:
                await self._initiate_graceful_close(reason=error_reason or "Local EOF")

    async def _initiate_graceful_close(self, reason="Graceful close"):
        if self.closed:
            return

        self.close_reason = reason

        deadline = time.monotonic() + 300.0
        while self.snd_buf and time.monotonic() < deadline and not self.closed:
            await asyncio.sleep(0.05)

        if self.closed:
            return

        if self.snd_buf:
            await self.abort(reason=f"{reason} but send buffer did not drain")
            return

        await self.close(reason=reason, send_fin=True)

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
            await self.enqueue_tx(
                0,
                self.stream_id,
                self._fin_seq_received,
                b"",
                is_fin_ack=True,
            )
        except Exception:
            pass

        if self._fin_sent and self._fin_acked and not self.snd_buf:
            await self.close(reason="Both FINs fully acknowledged")

    async def _retransmit_loop(self):
        """Separate lightweight task for RTO checks."""
        _sleep = asyncio.sleep
        try:
            while not self.closed:
                await _sleep(self.rto / 2.0)
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

    async def receive_data(self, sn, data):
        if self.closed:
            return

        self.last_activity = time.monotonic()

        diff = (sn - self.rcv_nxt) % 65536
        if diff >= 32768:
            await self.enqueue_tx(0, self.stream_id, sn, b"", is_ack=True)
            return

        if diff > self.window_size:
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

    async def receive_ack(self, sn):
        self.last_activity = time.monotonic()

        if self.snd_buf.pop(sn, None) is not None:
            if len(self.snd_buf) < self.limit:
                self.window_not_full.set()

    async def check_retransmits(self):
        if self.closed:
            return

        now = time.monotonic()

        if now - self.last_activity > 300.0:
            await self.abort(reason="Stream Inactivity Timeout (Dead)")
            return

        items_to_resend = []
        _append = items_to_resend.append

        for sn, info in list(self.snd_buf.items()):
            if info["create_time"] + 120.0 >= now:
                await self.abort(reason=f"Max retransmissions exceeded for sn={sn}")
                return

            if now - info["time"] >= info["current_rto"]:
                items_to_resend.append(
                    (sn, info["data"], info.get("is_socks_syn", False))
                )
                info["time"] = now
                info["retries"] += 1
                dynamic_max = max(
                    self.max_rto, 15.0 if info["retries"] > 10 else self.max_rto
                )
                info["current_rto"] = min(dynamic_max, info["current_rto"] * 1.5)

        _enqueue = self.enqueue_tx
        _sid = self.stream_id

        for sn, data, is_socks_syn in items_to_resend:
            if is_socks_syn:
                await _enqueue(1, _sid, sn, data, is_socks_syn=True)
            else:
                await _enqueue(1, _sid, sn, data, is_resend=True)

    async def abort(self, reason="Abort"):
        if self.closed:
            return

        self._rst_sent = True

        try:
            await self.enqueue_tx(
                0,
                self.stream_id,
                self.snd_nxt,
                b"",
                is_rst=True,
            )
        except Exception:
            pass

        await self.close(reason=reason, send_fin=False)

    async def close(self, reason="Unknown", send_fin=True):
        if self.closed:
            return

        self.closed = True
        self.close_reason = reason
        self._close_time = time.monotonic()

        if (
            send_fin
            and not self._fin_sent
            and not self._rst_sent
            and not self._rst_received
        ):
            self._fin_sent = True
            if self._fin_seq_sent is None:
                self._fin_seq_sent = self.snd_nxt
            try:
                await self.enqueue_tx(
                    4,
                    self.stream_id,
                    self._fin_seq_sent,
                    b"",
                    is_fin=True,
                )
            except Exception:
                pass

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
