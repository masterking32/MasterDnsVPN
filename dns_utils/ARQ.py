# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import asyncio
import time


class ARQStream:
    def __init__(self, stream_id, session_id, enqueue_tx_cb, reader, writer, mtu):
        self.stream_id = stream_id
        self.session_id = session_id
        self.enqueue_tx = enqueue_tx_cb
        self.reader = reader
        self.writer = writer
        self.mtu = max(mtu - 16, 32)  # Reserve 16 bytes for headers overhead

        self.snd_nxt = 0
        self.rcv_nxt = 0
        self.snd_buf = {}
        self.rcv_buf = {}

        self.rto = 2.0  # Retransmission Timeout (2 seconds)
        self.closed = False
        self.io_task = asyncio.create_task(self._io_loop())

    async def _io_loop(self):
        """Read from local TCP socket and chunk it to VPN tunnel"""
        try:
            while not self.closed and not self.reader.at_eof():
                while len(self.snd_buf) > 100 and not self.closed:
                    await asyncio.sleep(0.05)

                if self.closed:
                    break

                data = await self.reader.read(self.mtu)
                if not data:
                    break
                sn = self.snd_nxt
                self.snd_nxt += 1
                self.snd_buf[sn] = {"data": data, "time": time.time(), "retries": 0}

                # Priority 3 for normal data
                await self.enqueue_tx(3, self.stream_id, sn, data)
        except Exception:
            pass
        finally:
            await self.close()

    async def receive_data(self, sn, data):
        """Handle incoming VPN data packets"""
        if self.closed:
            return
        if sn < self.rcv_nxt:
            # Already received, resend ACK
            await self.enqueue_tx(4, self.stream_id, sn, b"", is_ack=True)
            return

        self.rcv_buf[sn] = data
        # Drain in-order packets to TCP socket
        while self.rcv_nxt in self.rcv_buf:
            chunk = self.rcv_buf.pop(self.rcv_nxt)
            try:
                self.writer.write(chunk)
                await self.writer.drain()
            except Exception:
                await self.close()
                break
            # Priority 4 for ACK
            await self.enqueue_tx(4, self.stream_id, self.rcv_nxt, b"", is_ack=True)
            self.rcv_nxt += 1

    async def receive_ack(self, sn):
        """Clear from send buffer when ACK is received"""
        if sn in self.snd_buf:
            del self.snd_buf[sn]

    async def close(self):
        """Gracefully close the TCP connection and stream"""
        if self.closed:
            return
        self.closed = True
        if self.io_task:
            self.io_task.cancel()
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass
        # Priority 2 for FIN
        await self.enqueue_tx(2, self.stream_id, 0, b"", is_fin=True)

    async def check_retransmits(self):
        """Check for unacked packets and resend them"""
        if self.closed:
            return
        now = time.time()
        for sn, pkt in list(self.snd_buf.items()):
            if now - pkt["time"] > self.rto:
                pkt["time"] = now
                pkt["retries"] += 1
                if pkt["retries"] > 10:  # Dead connection after 10 retries
                    await self.close()
                    break
                # Priority 1 for RESEND
                await self.enqueue_tx(
                    1, self.stream_id, sn, pkt["data"], is_resend=True
                )
