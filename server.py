# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026


import asyncio
import ctypes
import os
import random
import signal
import socket
import sys
import time
from ctypes import wintypes
from typing import Any, Optional
from collections import deque
import heapq

from dns_utils.ARQ import ARQStream
from dns_utils.DNS_ENUMS import DNS_Record_Type, Packet_Type
from dns_utils.DnsPacketParser import DnsPacketParser
from dns_utils.utils import async_recvfrom, async_sendto, get_encrypt_key, getLogger
from dns_utils.config_loader import load_config, get_config_path

# Ensure UTF-8 output for consistent logging
try:
    if sys.stdout.encoding is not None and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


class MasterDnsVPNServer:
    """MasterDnsVPN Server class to handle DNS requests over UDP."""

    def __init__(self) -> None:
        """Initialize the MasterDnsVPNServer with configuration and logger."""
        self.udp_sock: Optional[socket.socket] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.should_stop = asyncio.Event()
        self.max_concurrent_requests = asyncio.Semaphore(5000)

        self.config = load_config("server_config.toml")
        if not os.path.isfile(get_config_path("server_config.toml")):
            self.logger = getLogger(
                log_level=self.config.get("LOG_LEVEL", "DEBUG"), is_server=True
            )
            self.logger.error(
                "Config file '<cyan>server_config.toml</cyan>' not found."
            )
            self.logger.error(
                "Please place it in the same directory as the executable and restart."
            )
            input("Press Enter to exit...")
            sys.exit(1)

        self.logger = getLogger(
            log_level=self.config.get("LOG_LEVEL", "INFO"), is_server=True
        )
        self.allowed_domains = self.config.get("DOMAIN", [])
        self.allowed_domains_lower = tuple(d.lower() for d in self.allowed_domains)
        self.encryption_method: int = self.config.get("DATA_ENCRYPTION_METHOD", 1)

        self.sessions = {}
        self._max_sessions = 255
        self.free_session_ids = deque(range(1, self._max_sessions + 1))

        self.encrypt_key = get_encrypt_key(self.encryption_method)
        self.logger.warning(f"Using encryption key: <green>{self.encrypt_key}</green>")

        self.dns_parser = DnsPacketParser(
            logger=self.logger,
            encryption_method=self.encryption_method,
            encryption_key=self.encrypt_key,
        )

        self._dns_task = None
        self._session_cleanup_task = None
        self._background_tasks = set()
        self._session_expiry_heap = []
        try:
            self._valid_packet_types = set(
                v for k, v in Packet_Type.__dict__.items() if not k.startswith("__")
            )
        except Exception:
            self._valid_packet_types = set()

    # ---------------------------------------------------------
    # Session Management
    # ---------------------------------------------------------
    async def new_session(self) -> Optional[int]:
        """
        Create a new session and return its session ID.
        """
        try:
            if not self.free_session_ids:
                self.logger.error("All 255 session slots are full!")
                return None

            session_id = self.free_session_ids.popleft()
            now = time.monotonic()
            self.sessions[session_id] = {
                "last_packet_time": now,
                "streams": {},
                "session_queue": asyncio.PriorityQueue(),
                "stream_queues": {},
                "round_robin_index": 0,
                "pending_resends": set(),
                "canceled_streams": set(),
                "enqueue_seq": 0,
            }

            session_timeout = int(self.config.get("SESSION_TIMEOUT", 300))
            heapq.heappush(
                self._session_expiry_heap, (now + session_timeout, session_id)
            )
            self.logger.info(f"Created new session with ID: {session_id}")
            return session_id
        except Exception as e:
            self.logger.error(f"Error creating new session: {e}")
            return None

    async def _close_session(self, session_id: int) -> None:
        session = self.sessions.get(session_id)
        if not session:
            return

        self.logger.debug(f"Closing Session {session_id} and all its streams...")

        stream_ids = list(session.get("streams", {}).keys())
        close_tasks = [
            self.close_stream(session_id, sid, reason="Session Closing")
            for sid in stream_ids
        ]

        if close_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*close_tasks, return_exceptions=True), timeout=2.0
                )
            except Exception:
                pass

        if "session_queue" in session:
            session["session_queue"] = asyncio.PriorityQueue()

        if "stream_queues" in session:
            session["stream_queues"] = {}

        session.pop("queue_meta", None)
        session.setdefault("pending_resends", set()).clear()
        session.setdefault("canceled_streams", set()).clear()

        del self.sessions[session_id]
        try:
            if 1 <= session_id <= getattr(self, "_max_sessions", 255):
                self.free_session_ids.appendleft(session_id)
        except Exception:
            pass

        self.logger.info(f"Closed session with ID: {session_id}")

    def _touch_session(self, session_id: int) -> None:
        """
        Update a session's last_packet_time and push a new expiry into the heap.
        Using a heap avoids scanning all sessions in the cleanup pass.
        """
        try:
            session = self.sessions.get(session_id)
            if not session:
                return
            now = time.monotonic()
            session["last_packet_time"] = now
            session_timeout = int(self.config.get("SESSION_TIMEOUT", 300))
            heapq.heappush(
                self._session_expiry_heap, (now + session_timeout, session_id)
            )
        except Exception:
            pass

    async def close_inactive_sessions(self, timeout: int = 300) -> None:
        now = time.monotonic()
        while self._session_expiry_heap and self._session_expiry_heap[0][0] <= now:
            try:
                expiry, session_id = heapq.heappop(self._session_expiry_heap)
                session = self.sessions.get(session_id)
                if not session:
                    continue
                if now - session.get("last_packet_time", 0) > timeout:
                    try:
                        await self._close_session(session_id)
                        self.logger.info(
                            f"Closed inactive session with ID: {session_id}"
                        )
                    except Exception as e:
                        self.logger.debug(f"Error closing session {session_id}: {e}")
                        continue
            except Exception:
                break

    async def _handle_session_init(
        self,
        data=None,
        labels=None,
        request_domain=None,
        addr=None,
        parsed_packet=None,
        session_id=None,
        extracted_header=None,
    ) -> Optional[bytes]:
        """Handle NEW_SESSION VPN packet."""

        client_token = self.dns_parser.extract_vpn_data_from_labels(labels)
        if not client_token:
            return None

        new_session_id = await self.new_session()
        if new_session_id is None:
            self.logger.debug(
                f"Failed to create new session for NEW_SESSION packet from {addr}"
            )
            return None

        response_bytes = (
            client_token + b":" + str(new_session_id).encode("ascii", errors="ignore")
        )
        data_bytes = self.dns_parser.codec_transform(response_bytes, encrypt=True)

        response_packet = self.dns_parser.generate_vpn_response_packet(
            domain=request_domain,
            session_id=new_session_id,
            packet_type=Packet_Type.SESSION_ACCEPT,
            data=data_bytes,
            question_packet=data,
        )

        return response_packet

    async def _session_cleanup_loop(self) -> None:
        """Background task to periodically cleanup inactive sessions."""
        try:
            session_cleanup_interval = float(
                self.config.get("SESSION_CLEANUP_INTERVAL", 30)
            )
            session_timeout = int(self.config.get("SESSION_TIMEOUT", 300))
            while not self.should_stop.is_set():
                try:
                    now = time.monotonic()
                    if self._session_expiry_heap:
                        next_expiry = max(0.0, self._session_expiry_heap[0][0] - now)
                        timeout = min(session_cleanup_interval, next_expiry)
                    else:
                        timeout = session_cleanup_interval

                    try:
                        await asyncio.wait_for(self.should_stop.wait(), timeout=timeout)
                        break
                    except asyncio.TimeoutError:
                        pass

                    await self.close_inactive_sessions(session_timeout)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    self.logger.error(f"Error during session cleanup: {e}")
        finally:
            self.logger.debug("Session cleanup loop stopped.")

    # ---------------------------------------------------------
    # Network I/O & Packet Processing
    # ---------------------------------------------------------
    async def send_udp_response(self, response: bytes, addr) -> bool:
        """Async send helper to write UDP response to addr using the server socket."""
        if not response or addr is None:
            return False

        sock = self.udp_sock
        if sock is None:
            self.logger.error("UDP socket is not initialized for sending response.")
            return False

        loop = self.loop or asyncio.get_running_loop()

        try:
            await async_sendto(loop, sock, response, addr)
            return True
        except (BlockingIOError, OSError) as e:
            try:
                self.logger.debug(f"Failed to send DNS response to {addr}: {e}")
            except Exception:
                pass
            return False
        except asyncio.CancelledError:
            raise
        except Exception:
            return False

    async def handle_vpn_packet(
        self,
        packet_type: int,
        session_id: int,
        data: bytes = b"",
        labels: str = "",
        parsed_packet: dict = None,
        addr=None,
        request_domain: str = "",
        extracted_header: dict = None,
    ) -> Optional[bytes]:

        if session_id in self.sessions:
            self._touch_session(session_id)

        if packet_type == Packet_Type.MTU_UP_REQ:
            return await self._handle_mtu_up(
                request_domain=request_domain, session_id=session_id, data=data
            )
        elif packet_type == Packet_Type.MTU_DOWN_REQ:
            return await self._handle_mtu_down(
                request_domain=request_domain,
                session_id=session_id,
                labels=labels,
                data=data,
            )
        elif packet_type == Packet_Type.SESSION_INIT:
            return await self._handle_session_init(
                request_domain=request_domain,
                data=data,
                labels=labels,
            )
        elif packet_type == Packet_Type.SET_MTU_REQ:
            return await self._handle_set_mtu(
                request_domain=request_domain,
                session_id=session_id,
                labels=labels,
                data=data,
            )

        if session_id not in self.sessions:
            self.logger.warning(
                f"Packet received for expired/invalid session {session_id} from {addr}. Dropping."
            )
            response_packet = self.dns_parser.generate_vpn_response_packet(
                domain=request_domain,
                session_id=session_id,
                packet_type=Packet_Type.ERROR_DROP,
                data=b"INVALID",
                question_packet=data,
            )
            return response_packet

        if not extracted_header:
            extracted_header = {}

        stream_id = extracted_header.get("stream_id", 0)
        sn = extracted_header.get("sequence_num", 0)
        session = self.sessions[session_id]
        streams = session.setdefault("streams", {})

        if packet_type == Packet_Type.STREAM_SYN:
            await self._handle_stream_syn(session_id, stream_id)
        elif packet_type in (Packet_Type.STREAM_DATA, Packet_Type.STREAM_RESEND):
            stream = streams.get(stream_id)
            if stream and stream != "PENDING":
                diff = (sn - stream.rcv_nxt) % 65536
                if diff >= 32768:
                    await self._server_enqueue_tx(
                        session_id, 1, stream_id, sn, b"", is_ack=True
                    )
                else:
                    extracted_data = self.dns_parser.extract_vpn_data_from_labels(
                        labels
                    )
                    if extracted_data:
                        await stream.receive_data(sn, extracted_data)
        elif packet_type == Packet_Type.STREAM_DATA_ACK:
            stream = streams.get(stream_id)
            if stream and stream != "PENDING":
                await stream.receive_ack(sn)
        elif packet_type == Packet_Type.STREAM_FIN:
            await self.close_stream(session_id, stream_id, reason="Client sent FIN")

        session_queue = session.get("session_queue")
        stream_queues = session.get("stream_queues", {})
        canceled = session.get("canceled_streams", set())

        res_data = None
        res_stream_id = 0
        res_sn = 0
        res_ptype = Packet_Type.PONG

        active_streams = [sid for sid, q in stream_queues.items() if not q.empty()]

        if active_streams:
            rr_index = session.get("round_robin_index", 0)
            if rr_index >= len(active_streams):
                rr_index = 0

            selected_sid = active_streams[rr_index]
            target_queue = stream_queues[selected_sid]

            session["round_robin_index"] = (rr_index + 1) % len(active_streams)

            try:
                while not target_queue.empty():
                    item = target_queue.get_nowait()
                    q_ptype, q_stream_id, q_sn = item[3], item[4], item[5]

                    if q_stream_id in canceled and q_ptype not in (
                        Packet_Type.STREAM_FIN,
                        Packet_Type.STREAM_SYN_ACK,
                    ):
                        continue

                    if q_ptype == Packet_Type.STREAM_RESEND:
                        session.get("pending_resends", set()).discard(
                            (q_stream_id, q_sn)
                        )

                    if q_ptype in (Packet_Type.STREAM_DATA, Packet_Type.STREAM_RESEND):
                        arq = session.get("streams", {}).get(q_stream_id)
                        if arq and arq != "PENDING":
                            if q_sn not in arq.snd_buf:
                                continue

                    res_ptype, res_stream_id, res_sn, res_data = (
                        q_ptype,
                        q_stream_id,
                        q_sn,
                        item[6],
                    )
                    # update queue meta to reflect dequeue
                    try:
                        qkey = f"stream:{selected_sid}"
                        qmeta = session.get("queue_meta", {}).get(qkey)
                        if qmeta:
                            if q_ptype in (
                                Packet_Type.STREAM_FIN,
                                Packet_Type.STREAM_SYN,
                                Packet_Type.STREAM_SYN_ACK,
                            ):
                                qmeta["types"].discard(q_ptype)
                            if q_ptype == Packet_Type.STREAM_DATA_ACK:
                                qmeta["acks"].discard((q_ptype, q_sn))
                            if q_ptype == Packet_Type.STREAM_RESEND:
                                qmeta["resends"].discard((q_stream_id, q_sn))
                            # decrement counts
                            try:
                                if (
                                    "counts" in qmeta
                                    and qmeta["counts"].get(q_ptype, 0) > 0
                                ):
                                    qmeta["counts"][q_ptype] -= 1
                            except Exception:
                                pass
                    except Exception:
                        pass
                    break
            except Exception:
                pass

        if not res_data and session_queue and not session_queue.empty():
            try:
                while not session_queue.empty():
                    item = session_queue.get_nowait()
                    q_ptype, q_stream_id, q_sn = item[3], item[4], item[5]
                    res_ptype, res_stream_id, res_sn, res_data = (
                        q_ptype,
                        q_stream_id,
                        q_sn,
                        item[6],
                    )
                    # update session queue meta
                    try:
                        qmeta = session.get("queue_meta", {}).get("session")
                        if qmeta:
                            if q_ptype in (
                                Packet_Type.STREAM_FIN,
                                Packet_Type.STREAM_SYN,
                                Packet_Type.STREAM_SYN_ACK,
                            ):
                                qmeta["types"].discard(q_ptype)
                            if q_ptype == Packet_Type.STREAM_DATA_ACK:
                                qmeta["acks"].discard((q_ptype, q_sn))
                            if q_ptype == Packet_Type.STREAM_RESEND:
                                qmeta["resends"].discard((q_stream_id, q_sn))
                            # decrement counts
                            try:
                                if (
                                    "counts" in qmeta
                                    and qmeta["counts"].get(q_ptype, 0) > 0
                                ):
                                    qmeta["counts"][q_ptype] -= 1
                            except Exception:
                                pass
                    except Exception:
                        pass
                    break
            except Exception:
                pass

        if not res_data:
            pong_data = (
                f"PO:{int(time.time()) % 10000}:{random.randint(1000, 9999)}".encode()
            )
            res_ptype, res_stream_id, res_sn, res_data = (
                Packet_Type.PONG,
                0,
                0,
                pong_data,
            )

        res_encrypted_data = (
            self.dns_parser.codec_transform(res_data, encrypt=True) if res_data else b""
        )

        return self.dns_parser.generate_vpn_response_packet(
            domain=request_domain,
            session_id=session_id,
            packet_type=res_ptype,
            data=res_encrypted_data,
            question_packet=data,
            stream_id=res_stream_id,
            sequence_num=res_sn,
        )

    async def handle_single_request(self, data, addr):
        """
        Handle a single DNS request in its own task.
        """
        if data is None or addr is None:
            self.logger.debug("Invalid data or address in DNS request.")
            return

        dns_parser = self.dns_parser
        loop = self.loop or asyncio.get_running_loop()
        create_task = loop.create_task
        bg_tasks = self._background_tasks
        allowed_domains_lower = self.allowed_domains_lower
        valid_packet_types = getattr(self, "_valid_packet_types", set())

        parsed_packet = dns_parser.parse_dns_packet(data)
        if not parsed_packet:
            return

        questions = parsed_packet.get("questions")
        if not questions:
            return

        q0 = questions[0]
        request_domain = q0.get("qName")
        if not request_domain:
            return

        packet_domain = request_domain.lower()

        packet_main_domain = ""
        for d in allowed_domains_lower:
            if packet_domain.endswith(d):
                packet_main_domain = d
                break

        vpn_response = None
        if (
            q0.get("qType") == DNS_Record_Type.TXT
            and packet_main_domain
            and packet_domain.count(".") >= 3
        ):
            labels = (
                packet_domain[: -len("." + packet_main_domain)]
                if packet_main_domain
                else packet_domain
            )
            try:
                extracted_header = dns_parser.extract_vpn_header_from_labels(labels)
            except Exception:
                extracted_header = None

            if extracted_header:
                packet_type = extracted_header.get("packet_type")
                session_id = extracted_header.get("session_id")
                if packet_type in valid_packet_types:
                    try:
                        vpn_response = await self.handle_vpn_packet(
                            packet_type=packet_type,
                            session_id=session_id,
                            data=data,
                            labels=labels,
                            parsed_packet=parsed_packet,
                            addr=addr,
                            request_domain=request_domain,
                            extracted_header=extracted_header,
                        )
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        vpn_response = None

        if vpn_response:
            try:
                t = create_task(self.send_udp_response(vpn_response, addr))
                bg_tasks.add(t)
                t.add_done_callback(bg_tasks.discard)
            except Exception:
                await self.send_udp_response(vpn_response, addr)
            return

        response = dns_parser.server_fail_response(data)
        if not response:
            return

        try:
            t = create_task(self.send_udp_response(response, addr))
            bg_tasks.add(t)
            t.add_done_callback(bg_tasks.discard)
        except Exception:
            await self.send_udp_response(response, addr)

    async def _bounded_handle_request(self, data, addr):
        async with self.max_concurrent_requests:
            await self.handle_single_request(data, addr)

    async def handle_dns_requests(self) -> None:
        """
        Asynchronously handle incoming DNS requests and spawn a new task for each.
        """
        assert self.udp_sock is not None, "UDP socket is not initialized."
        assert self.loop is not None, "Event loop is not initialized."
        self.udp_sock.setblocking(False)
        while not self.should_stop.is_set():
            try:
                try:
                    data, addr = await asyncio.wait_for(
                        async_recvfrom(self.loop, self.udp_sock, 65536), timeout=1.0
                    )

                    if len(data) < 12:
                        continue
                except asyncio.TimeoutError:
                    continue
            except OSError as e:
                if getattr(e, "winerror", None) == 10054:
                    continue

                self.logger.error(f"Socket error: {e}. Exiting DNS request handler.")
                await asyncio.sleep(0.1)
                continue
            except Exception as e:
                self.logger.exception(f"Unexpected error receiving DNS request: {e}")
                await asyncio.sleep(0.1)
                continue
            try:
                task = self.loop.create_task(self._bounded_handle_request(data, addr))
                self._background_tasks.add(task)
                task.add_done_callback(self._background_tasks.discard)
            except Exception as e:
                self.logger.error(f"Failed to create task for request from {addr}: {e}")

    # ---------------------------------------------------------
    # MTU Testing Logic
    # ---------------------------------------------------------
    async def _handle_set_mtu(
        self,
        data=None,
        labels=None,
        request_domain=None,
        addr=None,
        parsed_packet=None,
        session_id=None,
        extracted_header=None,
    ) -> Optional[bytes]:
        """Handle SET_MTU_REQ VPN packet and save it to the session."""
        session = self.sessions.get(session_id)
        if not session:
            self.logger.warning(
                f"SET_MTU_REQ received for invalid session_id: {session_id} from {addr}"
            )
            return None

        extracted_data = self.dns_parser.extract_vpn_data_from_labels(labels)

        if not extracted_data or len(extracted_data) < 8:
            self.logger.warning(f"Invalid or missing SET_MTU_REQ data from {addr}")
            return None

        upload_mtu = int.from_bytes(extracted_data[:4], "big")
        download_mtu = int.from_bytes(extracted_data[4:8], "big")
        sync_token = extracted_data[8:] if len(extracted_data) > 8 else b"OK"

        session["upload_mtu"] = upload_mtu
        session["download_mtu"] = download_mtu

        self._touch_session(session_id)

        self.logger.info(
            f"Session {session_id} MTU synced - UP: {upload_mtu}B, DOWN: {download_mtu}B"
        )

        return self.dns_parser.generate_vpn_response_packet(
            domain=request_domain,
            session_id=session_id,
            packet_type=Packet_Type.SET_MTU_RES,
            data=self.dns_parser.codec_transform(sync_token, encrypt=True),
            question_packet=data,
        )

    async def _handle_mtu_down(
        self,
        data=None,
        labels=None,
        request_domain=None,
        addr=None,
        parsed_packet=None,
        session_id=None,
        extracted_header=None,
    ) -> Optional[bytes]:
        """Handle SERVER_UPLOAD_TEST VPN packet."""

        dot_idx = labels.find(".")
        if dot_idx <= 0:
            self.logger.warning(
                f"Invalid or empty SERVER_DOWNLOAD_TEST packet format from {addr}"
            )
            return None

        first_part_of_data = labels[:dot_idx]

        download_size_bytes = self.dns_parser.decode_and_decrypt_data(
            first_part_of_data, lowerCaseOnly=True
        )

        if not download_size_bytes:
            self.logger.warning(
                f"Failed to decode download size in SERVER_DOWNLOAD_TEST packet from {addr}"
            )
            return None

        download_size = int.from_bytes(download_size_bytes, "big")

        if download_size < 29:
            self.logger.warning(
                f"Download size too small in packet from {addr}: {download_size}"
            )
            return None

        data_bytes = (
            self.dns_parser.codec_transform(download_size_bytes, encrypt=True) + b":"
        )

        padding_len = download_size - len(data_bytes)
        if padding_len > 0:
            data_bytes += os.urandom(padding_len)
        else:
            data_bytes = data_bytes[:download_size]

        return self.dns_parser.generate_vpn_response_packet(
            domain=request_domain,
            session_id=session_id if session_id is not None else 255,
            packet_type=Packet_Type.MTU_DOWN_RES,
            data=data_bytes,
            question_packet=data,
        )

    async def _handle_mtu_up(
        self,
        data=None,
        labels=None,
        request_domain=None,
        addr=None,
        parsed_packet=None,
        session_id=None,
        extracted_header=None,
    ) -> Optional[bytes]:
        """Handle SERVER_UPLOAD_TEST VPN packet."""
        return self.dns_parser.generate_vpn_response_packet(
            domain=request_domain,
            session_id=session_id if session_id is not None else 255,
            packet_type=Packet_Type.MTU_UP_RES,
            data=self.dns_parser.codec_transform(b"1", encrypt=True),
            question_packet=data,
        )

    # ---------------------------------------------------------
    # TCP Forwarding Logic & Server Retransmits
    # ---------------------------------------------------------
    async def close_stream(
        self, session_id: int, stream_id: int, reason: str = "Unknown"
    ) -> None:
        """Safely and fully close a specific stream within a session."""
        session = self.sessions.get(session_id)
        if not session:
            return

        streams = session.get("streams", {})
        stream = streams.get(stream_id)

        if not stream:
            return

        self.logger.info(
            f"Closing Stream {stream_id} in Session {session_id}. Reason: {reason}"
        )

        await self._clear_session_stream_queue(session_id, stream_id)

        if stream == "PENDING":
            fin_data = (
                f"FIN:{int(time.time()) % 10000}:{random.randint(1000, 9999)}".encode()
            )
            await self._server_enqueue_tx(
                session_id, 1, stream_id, 0, fin_data, is_fin=True
            )
        else:
            await stream.close(reason=reason)

        streams.pop(stream_id, None)

    async def _server_enqueue_tx(
        self,
        session_id,
        priority,
        stream_id,
        sn,
        data,
        is_ack=False,
        is_fin=False,
        is_syn_ack=False,
        is_resend=False,
    ):
        if session_id not in self.sessions:
            return

        session = self.sessions[session_id]

        if stream_id == 0:
            target_queue = session.setdefault("session_queue", asyncio.PriorityQueue())
        else:
            stream_queues = session.setdefault("stream_queues", {})
            target_queue = stream_queues.setdefault(stream_id, asyncio.PriorityQueue())

        pending_resends = session.setdefault("pending_resends", set())
        # queue_meta maps queue_key -> {"types": set(), "acks": set(), "resends": set(), "counts": {}}
        queue_meta = session.setdefault("queue_meta", {})
        queue_key = "session" if stream_id == 0 else f"stream:{stream_id}"
        qm = queue_meta.setdefault(
            queue_key, {"types": set(), "acks": set(), "resends": set(), "counts": {}}
        )

        ptype = Packet_Type.STREAM_DATA
        effective_priority = priority

        if is_ack:
            ptype = Packet_Type.STREAM_DATA_ACK
            effective_priority = 0
        elif is_fin:
            ptype = Packet_Type.STREAM_FIN
            effective_priority = 0
        elif is_syn_ack:
            ptype = Packet_Type.STREAM_SYN_ACK
            effective_priority = 0
        elif is_resend:
            ptype = Packet_Type.STREAM_RESEND
            effective_priority = 1

        if is_resend:
            resend_key = (stream_id, sn)
            if resend_key in pending_resends or (stream_id, sn) in qm["resends"]:
                return
            pending_resends.add(resend_key)
            qm["resends"].add((stream_id, sn))

        # Use metadata to avoid scanning the internal queue deque
        if ptype in (
            Packet_Type.STREAM_FIN,
            Packet_Type.STREAM_SYN,
            Packet_Type.STREAM_SYN_ACK,
        ):
            if ptype in qm["types"]:
                return

        if ptype == Packet_Type.STREAM_DATA_ACK:
            if (ptype, sn) in qm["acks"]:
                return

        session["enqueue_seq"] = (session.get("enqueue_seq", 0) + 1) & 0x7FFFFFFF
        seq = session["enqueue_seq"]

        await target_queue.put(
            (effective_priority, seq, time.time(), ptype, stream_id, sn, data)
        )
        # update meta after enqueue
        if ptype in (
            Packet_Type.STREAM_FIN,
            Packet_Type.STREAM_SYN,
            Packet_Type.STREAM_SYN_ACK,
        ):
            qm["types"].add(ptype)
        if ptype == Packet_Type.STREAM_DATA_ACK:
            qm["acks"].add((ptype, sn))
        # increment counts
        try:
            qm["counts"][ptype] = qm["counts"].get(ptype, 0) + 1
        except Exception:
            pass

    async def _handle_stream_syn(self, session_id, stream_id):
        if stream_id in self.sessions[session_id]["streams"]:
            # Duplicate packet
            await self._server_enqueue_tx(
                session_id, 2, stream_id, 0, b"", is_syn_ack=True
            )
            return

        self.sessions[session_id]["streams"][stream_id] = "PENDING"
        self.sessions[session_id]["canceled_streams"].discard(stream_id)

        try:
            reader, writer = await asyncio.open_connection(
                self.config["FORWARD_IP"], int(self.config["FORWARD_PORT"])
            )

            crypto_overhead = 0
            enc_method = self.encryption_method
            if enc_method == 2:
                crypto_overhead = 16
            elif enc_method in (3, 4, 5):
                crypto_overhead = 28

            safe_downlink_mtu = max(
                64,
                self.sessions[session_id].get("download_mtu", 512)
                - crypto_overhead
                - 8,
            )

            stream = ARQStream(
                stream_id=stream_id,
                session_id=session_id,
                enqueue_tx_cb=lambda p, sid, sn, d, **kw: self._server_enqueue_tx(
                    session_id, p, sid, sn, d, **kw
                ),
                reader=reader,
                writer=writer,
                mtu=safe_downlink_mtu,
                logger=self.logger,
                window_size=self.config.get("ARQ_WINDOW_SIZE", 600),
            )

            self.sessions[session_id]["streams"][stream_id] = stream

            # Send SYN_ACK
            syn_data = (
                f"SYA:{int(time.time()) % 10000}:{random.randint(1000, 9999)}".encode()
            )
            await self._server_enqueue_tx(
                session_id, 2, stream_id, 0, syn_data, is_syn_ack=True
            )
            self.logger.info(
                f"Stream {stream_id} connected to Forward Target: {self.config['FORWARD_IP']}"
            )
        except Exception as e:
            self.logger.error(
                f"Failed to connect to forward target for stream {stream_id}: {e}"
            )

            await self.close_stream(
                session_id, stream_id, reason=f"Connection Error: {e}"
            )

    async def _clear_session_stream_queue(self, session_id: int, stream_id: int):
        session = self.sessions.get(session_id)
        if not session:
            return

        session.setdefault("canceled_streams", set()).add(stream_id)
        self.logger.debug(
            f"Stream {stream_id} marked as canceled in queue for Session {session_id}"
        )

        pending_resends = session.get("pending_resends", set())
        to_remove = [item for item in pending_resends if item[0] == stream_id]
        for item in to_remove:
            pending_resends.discard(item)
        # remove queue_meta for this stream
        try:
            session.get("queue_meta", {}).pop(f"stream:{stream_id}", None)
        except Exception:
            pass

    async def _server_retransmit_loop(self):
        while not self.should_stop.is_set():
            await asyncio.sleep(0.5)
            for session_id, session in list(self.sessions.items()):
                stream_queues = session.get("stream_queues", {})
                canceled = session.get("canceled_streams", set())

                for sid in list(stream_queues.keys()):
                    if stream_queues[sid].empty() and sid in canceled:
                        del stream_queues[sid]
                        canceled.discard(sid)
                        # remove any queue_meta for this stream
                        try:
                            session.get("queue_meta", {}).pop(f"stream:{sid}", None)
                        except Exception:
                            pass

                to_remove_canceled = [
                    sid for sid in canceled if sid not in stream_queues
                ]
                for sid in to_remove_canceled:
                    canceled.discard(sid)

                streams = session.get("streams", {})
                if not streams:
                    continue

                closed_ids = [
                    sid for sid, s in streams.items() if s != "PENDING" and s.closed
                ]

                for sid in closed_ids:
                    await self.close_stream(
                        session_id, sid, reason="Marked Closed by ARQStream"
                    )

                for stream in list(streams.values()):
                    if stream != "PENDING":
                        try:
                            await stream.check_retransmits()
                        except Exception as e:
                            self.logger.error(
                                f"Error in retransmit sid {stream.stream_id}: {e}"
                            )

    # ---------------------------------------------------------
    # App Lifecycle
    # ---------------------------------------------------------
    async def start(self) -> None:
        """Initialize sockets, start background tasks, and wait for shutdown signal."""
        try:
            self.logger.info("MasterDnsVPN Server starting ...")
            self.loop = asyncio.get_running_loop()

            host = self.config.get("UDP_HOST", "0.0.0.0")
            port = int(self.config.get("UDP_PORT", 53))

            self.logger.info("Binding UDP socket ...")
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                self.udp_sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024
                )
                self.udp_sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024
                )
            except Exception as e:
                self.logger.debug(f"Failed to increase server socket buffer: {e}")

            try:
                self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except Exception:
                pass

            self.udp_sock.bind((host, port))

            self.logger.info(f"UDP socket bound on {host}:{port}")

            if sys.platform == "win32":
                try:
                    SIO_UDP_CONNRESET = -1744830452
                    self.udp_sock.ioctl(SIO_UDP_CONNRESET, False)
                except Exception as e:
                    self.logger.debug(f"Failed to set SIO_UDP_CONNRESET: {e}")

            self._dns_task = self.loop.create_task(self.handle_dns_requests())
            self._session_cleanup_task = self.loop.create_task(
                self._session_cleanup_loop()
            )

            self._retransmit_task = self.loop.create_task(
                self._server_retransmit_loop()
            )
            self.logger.info("MasterDnsVPN Server started successfully.")
            try:
                await self.should_stop.wait()
            except asyncio.CancelledError:
                pass

            await self.stop()
        except Exception as e:
            self.logger.exception(f"Failed to start MasterDnsVPN Server: {e}")
            await self.stop()

    async def stop(self) -> None:
        """Signal the server to stop."""
        self.should_stop.set()

        for task in list(self._background_tasks):
            if not task.done():
                task.cancel()

        for task_name in ["_retransmit_task", "_dns_task", "_session_cleanup_task"]:
            task = getattr(self, task_name, None)
            if task and not task.done():
                task.cancel()

        session_ids = list(self.sessions.keys())
        close_tasks = [self._close_session(sid) for sid in session_ids]
        if close_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*close_tasks, return_exceptions=True), timeout=3.0
                )
            except Exception:
                pass

        if self.udp_sock:
            try:
                self.udp_sock.close()
            except Exception:
                pass

        self.logger.info("MasterDnsVPN Server stopped.")
        os._exit(0)

    def _signal_handler(self, signum: int, frame: Any = None) -> None:
        """
        Handle termination signals for graceful shutdown.
        """
        self.logger.info(
            f"Received signal {signum}, shutting down MasterDnsVPN Server ..."
        )

        try:
            if self.loop:
                asyncio.run_coroutine_threadsafe(self.stop(), self.loop)
            else:
                asyncio.run(self.stop())
        except Exception:
            os._exit(0)
            pass

        self.logger.info("Shutdown signalled.")


def main():
    server = MasterDnsVPNServer()
    try:
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        def custom_exception_handler(loop, context):
            msg = context.get("message", "")
            if (
                "socket.send() raised exception" in msg
                or "Connection reset by peer" in msg
            ):
                return

            loop.default_exception_handler(context)

        loop.set_exception_handler(custom_exception_handler)

        try:
            loop.add_signal_handler(
                signal.SIGINT, lambda: server._signal_handler(signal.SIGINT, None)
            )
        except Exception:
            try:
                signal.signal(signal.SIGINT, server._signal_handler)
            except Exception:
                pass

        try:
            loop.add_signal_handler(
                signal.SIGTERM, lambda: server._signal_handler(signal.SIGTERM, None)
            )
        except Exception:
            try:
                signal.signal(signal.SIGTERM, server._signal_handler)
            except Exception:
                pass

        try:
            loop.run_until_complete(server.start())
        except KeyboardInterrupt:
            try:
                server._signal_handler(signal.SIGINT, None)
            except Exception:
                pass
            print("\nServer stopped by user (Ctrl+C). Goodbye!")
            return
        if sys.platform == "win32":
            try:
                HandlerRoutine = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)

                def _console_handler(dwCtrlType):
                    # CTRL_C_EVENT == 0, CTRL_BREAK_EVENT == 1, others ignored
                    try:
                        server._signal_handler(dwCtrlType, None)
                    except Exception:
                        pass
                    return True

                c_handler = HandlerRoutine(_console_handler)
                ctypes.windll.kernel32.SetConsoleCtrlHandler(c_handler, True)
            except Exception:
                pass
    except KeyboardInterrupt:
        print("\nServer stopped by user (Ctrl+C). Goodbye!")
    except Exception as e:
        print(f"{e}")

    try:
        os._exit(0)
    except Exception as e:
        print(f"Error while stopping the server: {e}")
        exit()


if __name__ == "__main__":
    main()
