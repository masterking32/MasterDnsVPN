# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import asyncio
import socket
import time


class ARQStream:
    _active_tasks = set()

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

        self.last_activity = time.time()
        self.rto = 1.0
        self.closed = False
        self.close_reason = "Unknown"
        self.logger = logger
        self._fin_sent = False
        self._write_lock = asyncio.Lock()
        self._snd_lock = asyncio.Lock()

        self.window_size = window_size
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
            ARQStream._active_tasks.add(self.io_task)
            self.io_task.add_done_callback(ARQStream._active_tasks.discard)
        except RuntimeError:
            self.io_task = None

    async def _io_loop(self):
        try:
            while not self.closed:
                try:
                    await asyncio.wait_for(self.window_not_full.wait(), timeout=0.2)
                except asyncio.TimeoutError:
                    await self.check_retransmits()
                    continue

                try:
                    raw_data = await asyncio.wait_for(
                        self.reader.read(self.mtu), timeout=0.5
                    )
                except asyncio.TimeoutError:
                    continue
                except ConnectionResetError:
                    self.close_reason = "Local App Reset Connection (Dropped)"
                    break
                except Exception as e:
                    self.close_reason = f"Read Error: {e}"
                    break

                if not raw_data:
                    self.close_reason = "Local App Closed Connection (EOF)"
                    break

                limit = max(50, int(self.window_size * 0.8))
                while len(self.snd_buf) > limit:
                    await asyncio.sleep(0.05)
                    if self.closed:
                        return

                self.last_activity = time.time()
                sn = self.snd_nxt
                self.snd_nxt = (self.snd_nxt + 1) % 65536

                async with self._snd_lock:
                    self.snd_buf[sn] = {
                        "data": raw_data,
                        "time": time.time(),
                        "first_sent": time.time(),
                        "retries": 0,
                    }

                    if len(self.snd_buf) >= self.window_size:
                        self.window_not_full.clear()

                await self.enqueue_tx(3, self.stream_id, sn, raw_data)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.debug(f"Stream {self.stream_id} IO loop error: {e}")
        finally:
            if not self.closed:
                loop = asyncio.get_running_loop()
                loop.create_task(self.close(reason="IO Loop Exit"))

    async def receive_data(self, sn, data):
        if self.closed:
            return

        self.last_activity = time.time()

        diff = (sn - self.rcv_nxt) % 65536
        if diff >= 32768:
            await self.enqueue_tx(4, self.stream_id, sn, b"", is_ack=True)
            return

        if diff > self.window_size:
            return

        if sn not in self.rcv_buf:
            self.rcv_buf[sn] = data

        has_written = False
        while self.rcv_nxt in self.rcv_buf:
            ordered_data = self.rcv_buf.pop(self.rcv_nxt)
            try:
                self.writer.write(ordered_data)
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

        # ack last received sn
        await self.enqueue_tx(0, self.stream_id, sn, b"", is_ack=True)

    async def receive_ack(self, sn):
        self.last_activity = time.time()
        async with self._snd_lock:
            if sn not in self.snd_buf:
                return
            self.snd_buf.pop(sn, None)

            if len(self.snd_buf) < self.window_size:
                self.window_not_full.set()

    async def check_retransmits(self):
        if self.closed or not self.snd_buf:
            return

        now = time.time()

        if now - self.last_activity > 300:
            await self.close(reason="Inactivity Timeout")
            return

        items_to_resend = []
        stream_dead = False
        async with self._snd_lock:
            for sn, info in self.snd_buf.items():
                if now - info["time"] >= self.rto:
                    if now - info.get("first_sent", info["time"]) > 120.0:
                        stream_dead = True
                        break

                    items_to_resend.append((sn, info["data"]))
                    info["time"] = now
                    info["retries"] += 1

        if stream_dead:
            await self.close(reason="Max ARQ retries reached (Stream Dead)")
            return

        for sn, data in items_to_resend:
            await self.enqueue_tx(1, self.stream_id, sn, data, is_resend=True)

    async def close(self, reason="Unknown"):
        if self.closed:
            return

        self.closed = True
        self.close_reason = reason
        # self.logger.info(f"Stream {self.stream_id} closing. Reason: {reason}")

        if not self._fin_sent:
            self._fin_sent = True
            try:
                await self.enqueue_tx(0, self.stream_id, 0, b"", is_fin=True)
            except Exception:
                pass

        current_task = asyncio.current_task()
        if hasattr(self, "io_task") and self.io_task and not self.io_task.done():
            if self.io_task is not current_task:
                self.io_task.cancel()
                try:
                    await asyncio.wait_for(self.io_task, timeout=0.5)
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
