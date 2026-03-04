# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import asyncio
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
        self.stream_id = stream_id  # Unique stream identifier (0-65535)
        self.session_id = session_id  # Parent session identifier
        self.enqueue_tx = enqueue_tx_cb  # Callback to enqueue outgoing packets
        self.reader = reader  # asyncio StreamReader for incoming data
        self.writer = writer  # asyncio StreamWriter for outgoing data
        self.mtu = mtu  # Maximum Transmission Unit for this stream

        self.snd_nxt = 0  # Next SN to send
        self.rcv_nxt = 0  # Next SN expected to receive
        self.snd_buf = {}  # SN -> {"data": bytes, "time": timestamp, "retries": int}
        self.rcv_buf = {}  # SN -> bytes (out-of-order received data)

        self.last_activity = time.time()  # Timestamp of last send/receive activity
        self.rto = 2.0  # Retransmission Timeout (initially 1 second)
        self.closed = False  # Stream closed flag
        self.logger = logger  # Optional logger for debug/info messages
        self._write_lock = asyncio.Lock()  # Ensure ordered writes to the TCP stream
        self._snd_lock = asyncio.Lock()  # Lock for snd_buf access

        self.window_size = (
            256  # Maximum number of unacknowledged packets allowed in flight
        )
        self.window_not_full = asyncio.Event()
        self.window_not_full.set()

        try:
            loop = asyncio.get_running_loop()
            self.io_task = loop.create_task(self._io_loop())
        except RuntimeError:
            # not in running loop yet; caller must start io loop later
            self.io_task = None

    async def _io_loop(self):
        try:
            while not self.closed:
                await self.window_not_full.wait()

                try:
                    raw_data = await self.reader.read(self.mtu)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    if self.logger:
                        self.logger.error(
                            f"<red>[ARQ-{self.stream_id}] Reader Error: {e}</red>"
                        )
                    break

                if not raw_data:
                    break

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
        except asyncio.CancelledError:
            pass
        except Exception as e:
            if self.logger:
                self.logger.debug(f"ARQ IO Error: {e}")
        finally:
            if not self.closed:
                try:
                    asyncio.create_task(self.close(reason="IO Loop Exit"))
                except Exception:
                    pass

    async def receive_data(self, sn, data):
        if self.closed:
            return

        self.last_activity = time.time()

        diff = (self.rcv_nxt - sn) % 65536
        if diff < 32768 and sn != self.rcv_nxt:
            await self.enqueue_tx(4, self.stream_id, sn, b"", is_ack=True)
            return

        if sn not in self.rcv_buf:
            self.rcv_buf[sn] = data

        while self.rcv_nxt in self.rcv_buf:
            ordered_data = self.rcv_buf.pop(self.rcv_nxt)
            try:
                self.writer.write(ordered_data)
                await self.writer.drain()
            except Exception as e:
                self.logger.error(f"[ARQ-{self.stream_id}] Writer Error: {e}")
                await self.close(reason="Writer Error")
                break

            self.rcv_nxt = (self.rcv_nxt + 1) % 65536

        await self.enqueue_tx(4, self.stream_id, sn, b"", is_ack=True)

    async def receive_ack(self, sn):
        self.last_activity = time.time()
        async with self._snd_lock:
            if sn not in self.snd_buf:
                return
            _ = self.snd_buf.pop(sn)

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

        if not items:
            return

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

        if hasattr(self, "io_task") and self.io_task and not self.io_task.done():
            self.io_task.cancel()
            try:
                await asyncio.wait_for(self.io_task, timeout=0.1)
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
