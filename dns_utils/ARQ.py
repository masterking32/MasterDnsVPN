# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import asyncio
import socket
import time


class ARQStream:
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
        self.rto = 1.0
        self.closed = False
        self.close_reason = "Unknown"
        self.logger = logger or self._DummyLogger()
        self._fin_sent = False

        self.window_size = window_size
        self.limit = max(50, int(self.window_size * 0.8))
        self.window_not_full = asyncio.Event()
        self.window_not_full.set()

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

            ARQStream._active_tasks.add(self.io_task)
            ARQStream._active_tasks.add(self.rtx_task)
            self.io_task.add_done_callback(ARQStream._active_tasks.discard)
            self.rtx_task.add_done_callback(ARQStream._active_tasks.discard)
        except RuntimeError:
            self.io_task = None
            self.rtx_task = None

    async def _io_loop(self):
        _read = self.reader.read
        _enqueue = self.enqueue_tx
        _monotonic = time.monotonic
        _mtu = self.mtu
        _limit = self.limit

        try:
            while not self.closed:
                await self.window_not_full.wait()

                try:
                    raw_data = await _read(_mtu)
                except ConnectionResetError:
                    self.close_reason = "Local App Reset Connection (Dropped)"
                    break
                except Exception as e:
                    self.close_reason = f"Read Error: {e}"
                    break

                if not raw_data:
                    self.close_reason = "Local App Closed Connection (EOF)"
                    break

                self.last_activity = _monotonic()
                sn = self.snd_nxt
                self.snd_nxt = (sn + 1) % 65536

                self.snd_buf[sn] = {
                    "data": raw_data,
                    "time": self.last_activity,
                    "retries": 0,
                }

                if len(self.snd_buf) >= _limit:
                    self.window_not_full.clear()

                await _enqueue(3, self.stream_id, sn, raw_data)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.debug(f"Stream {self.stream_id} IO loop error: {e}")
        finally:
            if not self.closed:
                asyncio.create_task(self.close(reason="IO Loop Exit"))

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
            await self.enqueue_tx(4, self.stream_id, sn, b"", is_ack=True)
            return

        if diff > self.window_size:
            return

        if sn not in self.rcv_buf:
            self.rcv_buf[sn] = data

        has_written = False
        _write = self.writer.write
        _pop = self.rcv_buf.pop

        while self.rcv_nxt in self.rcv_buf:
            try:
                _write(_pop(self.rcv_nxt))
                has_written = True
            except Exception as e:
                await self.close(reason=f"Writer Error: {e}")
                return
            self.rcv_nxt = (self.rcv_nxt + 1) % 65536

        if has_written:
            try:
                await self.writer.drain()
            except Exception:
                pass

        await self.enqueue_tx(0, self.stream_id, sn, b"", is_ack=True)

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
            await self.close(reason="Stream Inactivity Timeout (Dead)")
            return

        items_to_resend = []
        _append = items_to_resend.append
        _rto = self.rto

        for sn, info in list(self.snd_buf.items()):
            if now - info["time"] >= _rto:
                _append((sn, info["data"]))
                info["time"] = now
                info["retries"] += 1

        _enqueue = self.enqueue_tx
        _sid = self.stream_id
        for sn, data in items_to_resend:
            await _enqueue(1, _sid, sn, data, is_resend=True)

    async def close(self, reason="Unknown"):
        if self.closed:
            return

        self.closed = True
        self.close_reason = reason

        if not self._fin_sent:
            self._fin_sent = True
            try:
                await self.enqueue_tx(0, self.stream_id, 0, b"", is_fin=True)
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
