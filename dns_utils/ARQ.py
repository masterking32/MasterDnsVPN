import asyncio
import time


class ARQStream:
    def __init__(
        self, stream_id, session_id, enqueue_tx_cb, reader, writer, mtu, logger=None
    ):
        self.stream_id = stream_id
        self.session_id = session_id
        self.enqueue_tx = enqueue_tx_cb
        self.reader = reader
        self.writer = writer
        self.mtu = max(mtu - 16, 32)

        self.snd_nxt = 0
        self.rcv_nxt = 0
        self.snd_buf = {}
        self.rcv_buf = {}

        self.last_activity = time.time()
        self.rto = 15.0
        self.closed = False
        self.logger = logger
        self.io_task = asyncio.create_task(self._io_loop())

    async def _io_loop(self):
        try:
            while not self.closed:
                try:
                    raw_data = await self.reader.read(self.mtu)
                except (asyncio.CancelledError, Exception):
                    break

                if not raw_data:
                    break

                self.last_activity = time.time()
                sn = self.snd_nxt
                self.snd_nxt = (self.snd_nxt + 1) % 65536

                self.snd_buf[sn] = {
                    "data": raw_data,
                    "time": time.time(),
                    "retries": 0,
                }
                await self.enqueue_tx(3, self.stream_id, sn, raw_data)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            if self.logger:
                self.logger.debug(f"ARQ IO Error: {e}")
        finally:
            if not self.closed:
                asyncio.create_task(self.close(reason="IO Loop Exit"))

    async def receive_data(self, sn, data):
        if self.closed:
            return
        self.last_activity = time.time()

        diff = (sn - self.rcv_nxt + 32768) % 65536 - 32768
        if diff < 0:
            await self.enqueue_tx(4, self.stream_id, sn, b"", is_ack=True)
            return

        self.rcv_buf[sn] = data
        while self.rcv_nxt in self.rcv_buf:
            chunk = self.rcv_buf.pop(self.rcv_nxt)
            try:
                self.writer.write(chunk)
                await self.writer.drain()
                await self.enqueue_tx(4, self.stream_id, self.rcv_nxt, b"", is_ack=True)
                self.rcv_nxt = (self.rcv_nxt + 1) % 65536
            except Exception:
                await self.close(reason="Local TCP Write Error")
                break

    async def receive_ack(self, sn):
        self.last_activity = time.time()
        keys = list(self.snd_buf.keys())
        for k in keys:
            diff = (sn - k + 32768) % 65536 - 32768
            if diff >= 0:
                self.snd_buf.pop(k, None)

    async def check_retransmits(self):
        if self.closed or not self.snd_buf:
            return
        now = time.time()

        if now - self.last_activity > 300:
            await self.close(reason="Inactivity Timeout")
            return

        for sn, pkt in list(self.snd_buf.items()):
            if now - pkt["time"] > self.rto:
                pkt["time"] = now
                pkt["retries"] += 1
                await self.enqueue_tx(
                    1, self.stream_id, sn, pkt["data"], is_resend=True
                )

    async def close(self, reason="Unknown"):
        if self.closed:
            return
        self.closed = True

        if self.logger:
            self.logger.info(f"Stream {self.stream_id} closing. Reason: {reason}")

        if hasattr(self, "io_task") and self.io_task and not self.io_task.done():
            self.io_task.cancel()
            try:
                await asyncio.wait_for(self.io_task, timeout=0.1)
            except Exception:
                pass

        try:
            if not self.writer.is_closing():
                self.writer.close()
                await self.writer.wait_closed()
        except Exception:
            pass
