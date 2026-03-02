# MasterDnsVPN Server / Client
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

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
        self.mtu = max(mtu - 16, 32)  # Reserve bytes for headers

        self.snd_nxt = 0
        self.rcv_nxt = 0
        self.snd_buf = {}
        self.rcv_buf = {}

        self.srtt = 0.0  # Smoothed Round Trip Time
        self.rttval = 0.0  # RTT Variance

        # 1. Flow Control (Congestion Window)
        self.cwnd = 100
        self.ssthresh = 200

        # 2. Fast Retransmit Tracking
        self.dup_acks = {}

        self.last_activity = time.time()

        self.rto = 2.0  # Base Retransmission Timeout
        self.closed = False
        self.io_task = asyncio.create_task(self._io_loop())
        self.logger = logger

    async def _io_loop(self):
        """Read from local TCP socket and chunk it to VPN tunnel"""
        try:
            while not self.closed and not self.reader.at_eof():
                # 1. Flow Control
                while len(self.snd_buf) >= self.cwnd and not self.closed:
                    await asyncio.sleep(0.05)

                if self.closed:
                    if self.logger:
                        self.logger.debug(
                            f"[DEBUG-ARQ] Stream {self.stream_id} IO Loop breaking because stream was marked closed."
                        )
                    break

                raw_data = await self.reader.read(self.mtu)
                if not raw_data:
                    if self.logger:
                        self.logger.debug(
                            f"[DEBUG-ARQ] Stream {self.stream_id} EOF (End of File) received from local TCP! Application closed the connection."
                        )
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

        except asyncio.CancelledError:
            raise
        except ConnectionResetError:
            if self.logger:
                self.logger.debug(
                    f"[DEBUG-ARQ] Stream {self.stream_id} Connection Reset by peer (TCP RST)."
                )
        except Exception as e:
            if self.logger:
                self.logger.debug(
                    f"[DEBUG-ARQ] Stream {self.stream_id} IO Loop Exception: {e}"
                )
        finally:
            if not self.closed:
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(self.close(reason="IO Loop Ended"))
                except Exception:
                    pass

    async def receive_data(self, sn, data):
        """Handle incoming VPN data packets"""
        if self.closed:
            return

        self.last_activity = time.time()
        diff = (sn - self.rcv_nxt + 32768) % 65536 - 32768

        if diff < 0:
            # Duplicate packet
            await self.enqueue_tx(4, self.stream_id, sn, b"", is_ack=True)
            return
        elif diff > 0:
            if len(self.rcv_buf) > 1000:
                if self.logger:
                    self.logger.debug(
                        f"[DEBUG-ARQ] Stream {self.stream_id} Drop Data! Receive buffer full (>1000 out of order packets)."
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
            except Exception as e:
                if self.logger:
                    self.logger.debug(
                        f"[DEBUG-ARQ] Stream {self.stream_id} Failed to write to TCP socket: {e}. Closing stream."
                    )
                await self.close(reason="TCP Write Failed")
                break

            await self.enqueue_tx(4, self.stream_id, self.rcv_nxt, b"", is_ack=True)
            self.rcv_nxt = (self.rcv_nxt + 1) % 65536

    async def receive_ack(self, sn):
        """Clear from send buffer when ACK is received (Cumulative)"""
        self.last_activity = time.time()

        acked_keys = []
        for k in list(self.snd_buf.keys()):
            diff = (sn - k + 32768) % 65536 - 32768
            if diff >= 0:
                acked_keys.append(k)

        if acked_keys:
            for k in acked_keys:
                pkt = self.snd_buf[k]
                if k == sn and pkt["retries"] == 0:
                    rtt = time.time() - pkt["time"]
                    if self.srtt == 0.0:
                        self.srtt = rtt
                        self.rttval = rtt / 2
                    else:
                        self.rttval = 0.75 * self.rttval + 0.25 * abs(self.srtt - rtt)
                        self.srtt = 0.875 * self.srtt + 0.125 * rtt

                    self.rto = max(1.0, min(self.srtt + max(0.1, 4 * self.rttval), 5.0))

                del self.snd_buf[k]

            if self.cwnd < self.ssthresh:
                self.cwnd += len(acked_keys)
            else:
                self.cwnd += len(acked_keys) / self.cwnd
            self.cwnd = min(self.cwnd, 500)

            if sn in self.dup_acks:
                del self.dup_acks[sn]
        else:
            # Fast Retransmit
            lost_sn = (sn + 1) % 65536
            if lost_sn in self.snd_buf:
                self.dup_acks[lost_sn] = self.dup_acks.get(lost_sn, 0) + 1

                if self.dup_acks[lost_sn] == 3:
                    self.ssthresh = max(int(self.cwnd * 0.8), 50)
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

        if now - self.last_activity > 3600:
            await self.close()
            return

        for sn, pkt in list(self.snd_buf.items()):
            current_rto = min(self.rto * (1.5 ** pkt["retries"]), 3.0)

            if now - pkt["time"] > current_rto:
                pkt["time"] = now
                pkt["retries"] += 1

                self.ssthresh = max(int(self.cwnd * 0.5), 50)
                self.cwnd = max(self.cwnd, 50)

                # Priority 1 for RESEND
                await self.enqueue_tx(
                    1, self.stream_id, sn, pkt["data"], is_resend=True
                )

    async def close(self, reason="Unknown"):
        """Gracefully close the TCP connection and stream"""
        if self.closed:
            return

        if self.logger:
            self.logger.debug(
                f"[DEBUG-ARQ] Stream {self.stream_id} is closing. Reason: {reason}"
            )
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
                if not self.io_task.done():
                    self.io_task.cancel()
                    try:
                        await self.io_task
                    except asyncio.CancelledError:
                        pass
                    except Exception:
                        pass
        except Exception as e:
            if self.logger:
                self.logger.debug(f"Error closing IO task: {e}")
