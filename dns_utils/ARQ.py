# MasterDnsVPN Server / Client
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
        self.mtu = max(mtu - 16, 32)  # Reserve bytes for headers

        self.snd_nxt = 0
        self.rcv_nxt = 0
        self.snd_buf = {}
        self.rcv_buf = {}

        self.srtt = 0.0  # Smoothed Round Trip Time
        self.rttval = 0.0  # RTT Variance

        # 1. Flow Control (Congestion Window)
        self.cwnd = 20
        self.ssthresh = 100

        # 2. Fast Retransmit Tracking
        self.dup_acks = {}

        self.last_activity = time.time()

        self.rto = 2.0  # Base Retransmission Timeout
        self.closed = False
        self.io_task = asyncio.create_task(self._io_loop())

    async def _io_loop(self):
        """Read from local TCP socket and chunk it to VPN tunnel"""
        try:
            while not self.closed and not self.reader.at_eof():
                # 1. Flow Control: اگر از سقف مجاز رد شدیم، منتظر می‌مانیم
                while len(self.snd_buf) >= self.cwnd and not self.closed:
                    await asyncio.sleep(0.01)

                if self.closed:
                    break

                raw_data = await self.reader.read(self.mtu)
                if not raw_data:
                    break

                self.last_activity = time.time()

                for i in range(0, len(raw_data), self.mtu):
                    chunk = raw_data[i : i + self.mtu]
                    sn = self.snd_nxt
                    self.snd_nxt = (self.snd_nxt + 1) % 65536
                    self.snd_buf[sn] = {
                        "data": chunk,
                        "time": time.time(),
                        "retries": 0,
                    }
                    await self.enqueue_tx(3, self.stream_id, sn, chunk)

        except Exception:
            pass
        finally:
            await self.close()

    async def receive_data(self, sn, data):
        """Handle incoming VPN data packets"""
        if self.closed:
            return

        self.last_activity = time.time()
        diff = (sn - self.rcv_nxt + 32768) % 65536 - 32768

        if diff < 0:
            await self.enqueue_tx(4, self.stream_id, sn, b"", is_ack=True)
            return
        elif diff > 0:
            if len(self.rcv_buf) > 1000:
                self.logger.warning(
                    "Receiver buffer full! Dropping out-of-order packet."
                )
                return

            expected_sn = (self.rcv_nxt - 1) % 65536
            await self.enqueue_tx(4, self.stream_id, expected_sn, b"", is_ack=True)
            self.rcv_buf[sn] = data
            return

        self.rcv_buf[sn] = data

        while self.rcv_nxt in self.rcv_buf:
            chunk = self.rcv_buf.pop(self.rcv_nxt)
            try:
                self.writer.write(chunk)
                await self.writer.drain()
            except Exception:
                await self.close()
                break

            await self.enqueue_tx(4, self.stream_id, self.rcv_nxt, b"", is_ack=True)
            self.rcv_nxt = (self.rcv_nxt + 1) % 65536

    async def receive_ack(self, sn):
        """Clear from send buffer when ACK is received"""
        self.last_activity = time.time()

        if sn in self.snd_buf:
            rtt = time.time() - self.snd_buf[sn]["time"]
            if self.srtt == 0.0:
                self.srtt = rtt
                self.rttval = rtt / 2
            else:
                self.rttval = 0.75 * self.rttval + 0.25 * abs(self.srtt - rtt)
                self.srtt = 0.875 * self.srtt + 0.125 * rtt

            self.rto = max(0.5, min(self.srtt + max(0.1, 4 * self.rttval), 10.0))

            del self.snd_buf[sn]
            if self.cwnd < self.ssthresh:
                self.cwnd += 1  # Slow Start
            else:
                self.cwnd += 1 / self.cwnd  # Congestion Avoidance
            self.cwnd = min(self.cwnd, 500)

            if sn in self.dup_acks:
                del self.dup_acks[sn]
        else:
            lost_sn = (sn + 1) % 65536
            if lost_sn in self.snd_buf:
                self.dup_acks[lost_sn] = self.dup_acks.get(lost_sn, 0) + 1
                if self.dup_acks[lost_sn] == 3:
                    self.ssthresh = max(int(self.cwnd / 2), 10)
                    self.cwnd = self.ssthresh
                    self.dup_acks[lost_sn] = 0

                    pkt = self.snd_buf[lost_sn]
                    pkt["time"] = time.time()
                    await self.enqueue_tx(
                        1, self.stream_id, lost_sn, pkt["data"], is_resend=True
                    )

    async def check_retransmits(self):
        """Check for unacked packets and resend them with Dynamic Backoff"""
        if self.closed:
            return

        now = time.time()

        if now - self.last_activity > 120:  # 2 Minutes Idle Timeout
            await self.close()
            return

        for sn, pkt in list(self.snd_buf.items()):
            current_rto = min(self.rto * (1.5 ** pkt["retries"]), 10.0)

            if now - pkt["time"] > current_rto:
                pkt["time"] = now
                pkt["retries"] += 1

                if pkt["retries"] > 10:  # Dead connection
                    await self.close()
                    break

                self.ssthresh = max(int(self.cwnd / 2), 10)
                self.cwnd = 1

                # Priority 1 for RESEND
                await self.enqueue_tx(
                    1, self.stream_id, sn, pkt["data"], is_resend=True
                )

    async def close(self):
        """Gracefully close the TCP connection and stream"""
        if self.closed:
            return
        self.closed = True

        try:
            await self.enqueue_tx(2, self.stream_id, 0, b"", is_fin=True)
        except Exception:
            pass

        try:
            if not self.writer.is_closing():
                self.writer.close()
        except Exception:
            pass

        try:
            current_task = asyncio.current_task()
            if getattr(self, "io_task", None) and self.io_task != current_task:
                self.io_task.cancel()
        except Exception:
            pass
