# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import asyncio
import socket
import time


class ARQStream:
    def __init__(
        self,
        stream_id,
        session_id,
        enqueue_tx_cb,
        reader,
        writer,
        mtu,
        logger=None,
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
        self.rto = 2.0
        self.closed = False
        self.logger = logger
        self._fin_sent = False
        self._write_lock = asyncio.Lock()
        self._snd_lock = asyncio.Lock()

        self.window_size = 600
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
                    raw_data = await self.reader.read(self.mtu)
                except Exception:
                    break

                if not raw_data:
                    break

                while len(self.snd_buf) > 2000:
                    await asyncio.sleep(0.1)
                    if self.closed:
                        return

                self.last_activity = time.time()
                sn = self.snd_nxt
                self.snd_nxt = (self.snd_nxt + 1) % 65536

                async with self._snd_lock:
                    self.snd_buf[sn] = {
                        "data": raw_data,
                        "time": time.time(),
                        "retries": 0,
                    }

                    if len(self.snd_buf) >= self.window_size:
                        self.window_not_full.clear()

                await self.enqueue_tx(3, self.stream_id, sn, raw_data)
        finally:
            if not self.closed:
                await self.close(reason="IO Loop Exit")

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

        while self.rcv_nxt in self.rcv_buf:
            ordered_data = self.rcv_buf.pop(self.rcv_nxt)
            try:
                self.writer.write(ordered_data)
                await self.writer.drain()
            except Exception as e:
                await self.close(reason=f"Writer Error: {e}")
                return
            self.rcv_nxt = (self.rcv_nxt + 1) % 65536

        # ack last received sn
        await self.enqueue_tx(4, self.stream_id, sn, b"", is_ack=True)

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

        if now - self.last_activity > 120:
            await self.close(reason="Inactivity Timeout")
            return

        async with self._snd_lock:
            items = list(self.snd_buf.items())

        for sn, info in items:
            if now - info["time"] < self.rto:
                continue

            await self.enqueue_tx(3, self.stream_id, sn, info["data"], is_resend=True)
            async with self._snd_lock:
                if sn in self.snd_buf:
                    self.snd_buf[sn]["time"] = now
                    self.snd_buf[sn]["retries"] += 1

    async def close(self, reason="Unknown"):
        if self.closed:
            return

        self.closed = True
        if self.logger:
            self.logger.info(f"Stream {self.stream_id} closing. Reason: {reason}")

        if not self._fin_sent:
            self._fin_sent = True
            try:
                await self.enqueue_tx(1, self.stream_id, 0, b"", is_fin=True)
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
                    await asyncio.wait_for(self.writer.wait_closed(), timeout=3.0)
                except Exception:
                    pass
        except Exception:
            pass
