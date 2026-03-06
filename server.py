# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026


import asyncio
import ctypes
import heapq
import os
import signal
import socket
import sys
import time
from collections import deque
from ctypes import wintypes
from typing import Any, Optional

from dns_utils.ARQ import ARQStream
from dns_utils.config_loader import get_config_path, load_config
from dns_utils.DNS_ENUMS import DNS_Record_Type, Packet_Type
from dns_utils.DnsPacketParser import DnsPacketParser
from dns_utils.utils import async_recvfrom, async_sendto, get_encrypt_key, getLogger

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
        self.logger.warning("=" * 60)
        self.logger.warning(
            "<yellow>MasterDnsVPN Server Starting with Configuration:</yellow>"
        )
        self.logger.warning("-" * 60)
        self.logger.warning(
            f"<red>Using encryption key: <green>{self.encrypt_key}</green></red>"
        )
        self.logger.warning(
            f"<red>Encryption method: <green>{self.encryption_method}</green></red>"
        )
        self.logger.warning(
            f"<yellow>Allowed domains: <cyan>{', '.join(self.allowed_domains)}</cyan></yellow>"
        )
        self.logger.warning("=" * 60)

        self.dns_parser = DnsPacketParser(
            logger=self.logger,
            encryption_method=self.encryption_method,
            encryption_key=self.encrypt_key,
        )

        self.crypto_overhead = 0
        if self.encryption_method == 2:
            self.crypto_overhead = 16
        elif self.encryption_method in (3, 4, 5):
            self.crypto_overhead = 28

        self.forward_ip = self.config["FORWARD_IP"]
        self.forward_port = int(self.config["FORWARD_PORT"])

        self.arq_window_size = int(self.config.get("ARQ_WINDOW_SIZE", 300))
        self.session_timeout = int(self.config.get("SESSION_TIMEOUT", 300))
        self.session_cleanup_interval = int(
            self.config.get("SESSION_CLEANUP_INTERVAL", 30)
        )

        self.max_concurrent_requests = asyncio.Semaphore(
            int(self.config.get("MAX_CONCURRENT_REQUESTS", 1000))
        )

        self._dns_task = None
        self._session_cleanup_task = None
        self._background_tasks = set()
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
                "created_at": now,
                "last_packet_time": now,
                "streams": {},
                "main_queue": [],
                "round_robin_index": 0,
                "enqueue_seq": 0,
                "count_ack": 0,
                "count_data": 0,
                "count_resend": 0,
                "track_ack": set(),
                "track_resend": set(),
                "track_types": set(),
                "track_data": set(),
                "upload_mtu": 512,
                "download_mtu": 512,
            }

            self.logger.info(
                f"<green>Created new session with ID: <cyan>{session_id}</cyan></green>"
            )
            return session_id
        except Exception as e:
            self.logger.error(f"Error creating new session: {e}")
            return None

    async def _close_session(self, session_id: int) -> None:
        session = self.sessions.pop(session_id, None)
        if not session:
            return

        self.logger.debug(
            f"<yellow>Closing Session <cyan>{session_id}</cyan> and all its streams...</yellow>"
        )

        stream_ids = list(session.get("streams", {}).keys())

        if stream_ids:
            close_tasks = [
                self.close_stream(session_id, sid, reason="Session Closing")
                for sid in stream_ids
            ]
            try:
                await asyncio.wait_for(
                    asyncio.gather(*close_tasks, return_exceptions=True), timeout=2.0
                )
            except Exception:
                pass

        try:
            session.get("main_queue", []).clear()
            session.get("track_ack", set()).clear()
            session.get("track_resend", set()).clear()
            session.get("track_types", set()).clear()
            session.get("streams", {}).clear()
        except Exception:
            pass

        self.sessions.pop(session_id, None)

        try:
            if 1 <= session_id <= getattr(self, "_max_sessions", 255):
                self.free_session_ids.appendleft(session_id)
        except Exception:
            pass

        self.logger.info(
            f"<yellow>Closed session with ID: <cyan>{session_id}</cyan></yellow>"
        )

    def _touch_session(self, session_id: int) -> None:
        """Update a session's last activity flatly and fast."""
        try:
            session = self.sessions.get(session_id)
            if session:
                session["last_packet_time"] = time.monotonic()
        except Exception:
            pass

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
                f"<red>Failed to create new session for NEW_SESSION packet from {addr}</red>"
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
        """Background task to periodically cleanup inactive sessions (Crash-Proof)."""
        cleanup_interval = float(self.session_cleanup_interval)
        timeout_limit = self.session_timeout

        while not self.should_stop.is_set():
            try:
                await asyncio.sleep(cleanup_interval)
                now = time.monotonic()

                expired_sessions = [
                    sid
                    for sid, sess in self.sessions.items()
                    if now - sess.get("last_packet_time", 0) > timeout_limit
                ]

                for sid in expired_sessions:
                    try:
                        await self._close_session(sid)
                        self.logger.info(
                            f"<yellow>Closed inactive session ID: <cyan>{sid}</cyan></yellow>"
                        )
                    except Exception as e:
                        self.logger.debug(
                            f"<red>Error closing session <cyan>{sid}</cyan>: {e}</red>"
                        )
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Unexpected error in session cleanup loop: {e}")
                await asyncio.sleep(1)

    # ---------------------------------------------------------
    # Network I/O & Packet Processing
    # ---------------------------------------------------------
    async def send_udp_response(self, response: bytes, addr) -> bool:
        """Async send helper to write UDP response to addr using the server socket."""
        if not response or addr is None:
            return False

        sock = self.udp_sock
        if sock is None:
            self.logger.error(
                "<red>UDP socket is not initialized for sending response.</red>"
            )
            return False

        loop = self.loop or asyncio.get_running_loop()

        try:
            await async_sendto(loop, sock, response, addr)
            return True
        except (BlockingIOError, OSError) as e:
            try:
                self.logger.debug(
                    f"<red>Failed to send DNS response to {addr}: {e}</red>"
                )
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

        if packet_type == Packet_Type.SESSION_INIT:
            return await self._handle_session_init(
                request_domain=request_domain, data=data, labels=labels
            )
        elif packet_type == Packet_Type.MTU_UP_REQ:
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
        elif packet_type == Packet_Type.SET_MTU_REQ:
            return await self._handle_set_mtu(
                request_domain=request_domain,
                session_id=session_id,
                labels=labels,
                data=data,
            )

        session = self.sessions.get(session_id)
        if not session:
            self.logger.warning(
                f"<yellow>Packet received for expired/invalid session <cyan>{session_id}</cyan> from <cyan>{addr}</cyan>. Dropping.</yellow>"
            )
            return self.dns_parser.generate_vpn_response_packet(
                domain=request_domain,
                session_id=session_id,
                packet_type=Packet_Type.ERROR_DROP,
                data=b"INVALID",
                question_packet=data,
            )

        now_mono = time.monotonic()
        self._touch_session(session_id)

        stream_id = extracted_header.get("stream_id", 0) if extracted_header else 0
        sn = extracted_header.get("sequence_num", 0) if extracted_header else 0

        streams = session.get("streams")
        if streams is None:
            session["streams"] = {}
            streams = session["streams"]

        if (
            packet_type == Packet_Type.STREAM_DATA
            or packet_type == Packet_Type.STREAM_RESEND
        ):
            stream_data = streams.get(stream_id)
            if stream_data and stream_data.get("status") == "CONNECTED":
                stream_data["last_activity"] = now_mono
                arq = stream_data.get("arq_obj")
                if arq:
                    diff = (sn - arq.rcv_nxt) & 65535
                    if diff >= 32768:
                        await self._server_enqueue_tx(
                            session_id, 1, stream_id, sn, b"", is_ack=True
                        )
                    else:
                        extracted_data = self.dns_parser.extract_vpn_data_from_labels(
                            labels
                        )
                        if extracted_data:
                            await arq.receive_data(sn, extracted_data)

        elif packet_type == Packet_Type.STREAM_DATA_ACK:
            stream_data = streams.get(stream_id)
            if stream_data and stream_data.get("status") == "CONNECTED":
                stream_data["last_activity"] = now_mono
                arq = stream_data.get("arq_obj")
                if arq:
                    await arq.receive_ack(sn)

        elif packet_type == Packet_Type.STREAM_SYN:
            await self._handle_stream_syn(session_id, stream_id)

        elif packet_type == Packet_Type.STREAM_FIN:
            await self.close_stream(session_id, stream_id, reason="Client sent FIN")

        res_data = None
        res_stream_id = 0
        res_sn = 0
        res_ptype = Packet_Type.PONG

        target_queue = None
        is_main = False
        selected_stream_data = None

        main_queue = session.get("main_queue")
        active_streams = [
            sid for sid, sdata in streams.items() if sdata.get("tx_queue")
        ]

        if active_streams:
            num_active = len(active_streams)
            rr_index = session.get("round_robin_index", 0)
            if rr_index >= num_active:
                rr_index = 0

            selected_sid = active_streams[rr_index]
            selected_stream_data = streams[selected_sid]
            t_queue = selected_stream_data["tx_queue"]

            if main_queue and main_queue[0][0] < t_queue[0][0]:
                target_queue = main_queue
                is_main = True
            else:
                target_queue = t_queue
                session["round_robin_index"] = (rr_index + 1) % num_active
        elif main_queue:
            target_queue = main_queue
            is_main = True

        if target_queue:
            item = heapq.heappop(target_queue)
            q_ptype, q_stream_id, q_sn = item[2], item[3], item[4]

            if is_main:
                if q_ptype == Packet_Type.STREAM_DATA:
                    session["track_data"].discard(q_sn)
                    if session["count_data"] > 0:
                        session["count_data"] -= 1
                elif q_ptype == Packet_Type.STREAM_DATA_ACK:
                    session["track_ack"].discard(q_sn)
                    if session["count_ack"] > 0:
                        session["count_ack"] -= 1
                elif q_ptype == Packet_Type.STREAM_RESEND:
                    session["track_resend"].discard(q_sn)
                    if session["count_resend"] > 0:
                        session["count_resend"] -= 1
                elif q_ptype in (
                    Packet_Type.STREAM_FIN,
                    Packet_Type.STREAM_SYN,
                    Packet_Type.STREAM_SYN_ACK,
                ):
                    session["track_types"].discard(q_ptype)
            else:
                if q_ptype == Packet_Type.STREAM_DATA:
                    selected_stream_data["track_data"].discard(q_sn)
                    if selected_stream_data["count_data"] > 0:
                        selected_stream_data["count_data"] -= 1
                elif q_ptype == Packet_Type.STREAM_DATA_ACK:
                    selected_stream_data["track_ack"].discard(q_sn)
                    if selected_stream_data["count_ack"] > 0:
                        selected_stream_data["count_ack"] -= 1
                elif q_ptype == Packet_Type.STREAM_RESEND:
                    selected_stream_data["track_resend"].discard(q_sn)
                    if selected_stream_data["count_resend"] > 0:
                        selected_stream_data["count_resend"] -= 1
                elif q_ptype == Packet_Type.STREAM_FIN:
                    selected_stream_data["track_fin"].discard(q_ptype)
                    if selected_stream_data["count_fin"] > 0:
                        selected_stream_data["count_fin"] -= 1
                elif q_ptype == Packet_Type.STREAM_SYN_ACK:
                    selected_stream_data["track_syn_ack"].discard(q_ptype)
                    if selected_stream_data["count_syn_ack"] > 0:
                        selected_stream_data["count_syn_ack"] -= 1

            res_ptype, res_stream_id, res_sn, res_data = (
                q_ptype,
                q_stream_id,
                q_sn,
                item[5],
            )

        if res_ptype == Packet_Type.PONG:
            res_data = b"PO:" + os.urandom(4)

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
        """Handle a single DNS request efficiently."""
        if not data or not addr:
            return

        parsed_packet = self.dns_parser.parse_dns_packet(data)
        if not parsed_packet or not parsed_packet.get("questions"):
            return

        q0 = parsed_packet["questions"][0]
        request_domain = q0.get("qName")
        if not request_domain:
            return

        packet_domain = request_domain.lower()

        if not packet_domain.endswith(self.allowed_domains_lower):
            return

        packet_main_domain = ""
        for d in self.allowed_domains_lower:
            if packet_domain.endswith(d):
                packet_main_domain = d
                break

        vpn_response = None
        if q0.get("qType") == DNS_Record_Type.TXT and packet_domain.count(".") >= 3:
            labels = (
                packet_domain[: -len("." + packet_main_domain)]
                if packet_main_domain
                else packet_domain
            )

            try:
                extracted_header = self.dns_parser.extract_vpn_header_from_labels(
                    labels
                )
            except Exception:
                extracted_header = None

            if extracted_header:
                packet_type = extracted_header.get("packet_type")
                session_id = extracted_header.get("session_id")

                if packet_type in self._valid_packet_types:
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
            await self.send_udp_response(vpn_response, addr)
            return

        response = self.dns_parser.server_fail_response(data)
        if response:
            await self.send_udp_response(response, addr)

    async def handle_dns_requests(self) -> None:
        """Asynchronously handle incoming DNS requests and spawn a new task for each."""
        assert self.udp_sock is not None, "UDP socket is not initialized."
        assert self.loop is not None, "Event loop is not initialized."
        self.udp_sock.setblocking(False)

        loop = self.loop
        sock = self.udp_sock
        bg_tasks = self._background_tasks
        handle_req = self.handle_single_request
        semaphore = self.max_concurrent_requests

        async def _task_wrapper(d, a):
            async with semaphore:
                await handle_req(d, a)

        while not self.should_stop.is_set():
            try:
                data, addr = await async_recvfrom(loop, sock, 65536)

                if len(data) < 12:
                    continue

                task = loop.create_task(_task_wrapper(data, addr))
                bg_tasks.add(task)
                task.add_done_callback(bg_tasks.discard)

            except asyncio.CancelledError:
                break
            except OSError as e:
                if getattr(e, "winerror", None) == 10054:
                    continue
                self.logger.error(f"Socket error: {e}")
                await asyncio.sleep(0.1)
            except Exception as e:
                self.logger.exception(f"Unexpected error receiving DNS request: {e}")
                await asyncio.sleep(0.1)

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

        safe_upload_mtu = min(upload_mtu, 4096)
        safe_download_mtu = min(download_mtu, 4096)

        session["upload_mtu"] = safe_upload_mtu - self.crypto_overhead
        session["download_mtu"] = safe_download_mtu - self.crypto_overhead

        self._touch_session(session_id)

        self.logger.info(
            f"<green>Session <cyan>{session_id}</cyan> MTU synced - Upload: <cyan>{safe_upload_mtu}</cyan>, Download: <cyan>{safe_download_mtu}</cyan></green>"
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
        """Safely and fully close a specific stream, salvage pending FIN/ACKs, and free resources."""
        session = self.sessions.get(session_id)
        if not session:
            return

        session_streams = session.get("streams", {})
        stream_data = session_streams.get(stream_id)

        if not stream_data:
            return

        self.logger.info(
            f"<yellow>Closing Stream <cyan>{stream_id}</cyan> in Session <cyan>{session_id}</cyan>. Reason: <red>{reason}</red></yellow>"
        )

        arq_obj = stream_data.get("arq_obj")
        if arq_obj:
            try:
                await arq_obj.close(reason=reason)
            except Exception as e:
                self.logger.debug(f"Error closing ARQStream {stream_id}: {e}")
        else:
            fin_data = b"FIN:" + os.urandom(4)
            await self._server_enqueue_tx(
                session_id, 1, stream_id, 0, fin_data, is_fin=True
            )

        try:
            stream_data["tx_queue"].clear()
            stream_data["track_ack"].clear()
            stream_data["track_resend"].clear()
            stream_data["track_data"].clear()
            stream_data["status"] = "CLOSED"
        except Exception:
            pass

        # ۳. پاک کردن امن استریم
        session_streams.pop(stream_id, None)

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
        session = self.sessions.get(session_id)
        if not session:
            return

        ptype = Packet_Type.STREAM_DATA
        eff_priority = priority

        if is_ack:
            ptype = Packet_Type.STREAM_DATA_ACK
            eff_priority = 0
        elif is_fin:
            ptype = Packet_Type.STREAM_FIN
            eff_priority = 0
        elif is_syn_ack:
            ptype = Packet_Type.STREAM_SYN_ACK
            eff_priority = 0
        elif is_resend:
            ptype = Packet_Type.STREAM_RESEND
            eff_priority = 1

        session["enqueue_seq"] = (session.get("enqueue_seq", 0) + 1) & 0x7FFFFFFF
        seq = session["enqueue_seq"]
        queue_item = (eff_priority, seq, ptype, stream_id, sn, data)

        if stream_id == 0:
            if is_resend:
                if sn in session.get("track_data", set()):
                    return
                if sn in session["track_resend"]:
                    return
                session["track_resend"].add(sn)
                session["count_resend"] += 1

            elif ptype in (
                Packet_Type.STREAM_FIN,
                Packet_Type.STREAM_SYN,
                Packet_Type.STREAM_SYN_ACK,
            ):
                if ptype in session["track_types"]:
                    return
                session["track_types"].add(ptype)

            elif ptype == Packet_Type.STREAM_DATA_ACK:
                if sn in session["track_ack"]:
                    return
                session["track_ack"].add(sn)
                session["count_ack"] += 1

            elif ptype == Packet_Type.STREAM_DATA:
                if sn in session.setdefault("track_data", set()):
                    return
                session["track_data"].add(sn)
                session["count_data"] += 1

            heapq.heappush(session["main_queue"], queue_item)

        else:
            stream_data = session.get("streams", {}).get(stream_id)
            if not stream_data:
                return

            if is_resend:
                if sn in stream_data["track_data"]:
                    return
                if sn in stream_data["track_resend"]:
                    return
                stream_data["track_resend"].add(sn)
                stream_data["count_resend"] += 1

            elif ptype == Packet_Type.STREAM_FIN:
                if ptype in stream_data["track_fin"]:
                    return
                stream_data["track_fin"].add(ptype)
                stream_data["count_fin"] += 1

            elif ptype == Packet_Type.STREAM_SYN_ACK:
                if ptype in stream_data["track_syn_ack"]:
                    return
                stream_data["track_syn_ack"].add(ptype)
                stream_data["count_syn_ack"] += 1

            elif ptype == Packet_Type.STREAM_DATA_ACK:
                if sn in stream_data["track_ack"]:
                    return
                stream_data["track_ack"].add(sn)
                stream_data["count_ack"] += 1

            elif ptype == Packet_Type.STREAM_DATA:
                if sn in stream_data["track_data"]:
                    return
                stream_data["track_data"].add(sn)
                stream_data["count_data"] += 1

            heapq.heappush(stream_data["tx_queue"], queue_item)

    async def _handle_stream_syn(self, session_id, stream_id):
        session = self.sessions.get(session_id)
        if not session:
            return

        session_streams = session["streams"]

        if stream_id in session_streams:
            await self._server_enqueue_tx(
                session_id, 2, stream_id, 0, b"", is_syn_ack=True
            )
            return

        now = time.monotonic()
        stream_data = {
            "stream_id": stream_id,
            "created_at": now,
            "last_activity": now,
            "status": "PENDING",
            "arq_obj": None,
            "tx_queue": [],  # heapq
            "count_ack": 0,
            "count_fin": 0,
            "count_syn_ack": 0,
            "count_data": 0,
            "count_resend": 0,
            "track_ack": set(),
            "track_fin": set(),
            "track_syn_ack": set(),
            "track_data": set(),
            "track_resend": set(),
        }

        session_streams[stream_id] = stream_data

        try:
            reader, writer = await asyncio.open_connection(
                self.forward_ip, self.forward_port
            )

            stream = ARQStream(
                stream_id=stream_id,
                session_id=session_id,
                enqueue_tx_cb=lambda p, sid, sn, d, **kw: self._server_enqueue_tx(
                    session_id, p, sid, sn, d, **kw
                ),
                reader=reader,
                writer=writer,
                mtu=session.get("download_mtu", 150),
                logger=self.logger,
                window_size=self.arq_window_size,
            )

            stream_data["arq_obj"] = stream
            stream_data["status"] = "CONNECTED"

            syn_data = b"SYA:" + os.urandom(4)

            await self._server_enqueue_tx(
                session_id, 2, stream_id, 0, syn_data, is_syn_ack=True
            )
            self.logger.info(
                f"<green>Stream <cyan>{stream_id}</cyan> connected to Forward Target: <blue>{self.forward_ip}:{self.forward_port}</blue></green>"
            )
        except Exception as e:
            self.logger.error(
                f"<red>Failed to connect to forward target for stream <cyan>{stream_id}</cyan>: {e}</red>"
            )
            await self.close_stream(
                session_id, stream_id, reason=f"Connection Error: {e}"
            )

    async def _server_retransmit_loop(self):
        """Background task to handle ARQ retransmissions for all active streams (Crash-Proof)."""
        while not self.should_stop.is_set():
            try:
                await asyncio.sleep(0.5)
                for session_id, session in list(self.sessions.items()):
                    streams = session.get("streams", {})
                    if not streams:
                        continue

                    closed_ids = []
                    for sid, stream_data in streams.items():
                        arq_obj = stream_data.get("arq_obj")
                        if arq_obj and getattr(arq_obj, "closed", False):
                            closed_ids.append(sid)

                    for sid in closed_ids:
                        try:
                            await self.close_stream(
                                session_id, sid, reason="Marked Closed by ARQStream"
                            )
                        except Exception as e:
                            self.logger.debug(
                                f"Error closing stream {sid} during retransmit check: {e}"
                            )

                    for sid, stream_data in list(streams.items()):
                        arq_obj = stream_data.get("arq_obj")
                        if arq_obj:
                            try:
                                await arq_obj.check_retransmits()
                            except Exception as e:
                                self.logger.error(f"Error in retransmit sid {sid}: {e}")
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Unexpected error in retransmit loop: {e}")
                await asyncio.sleep(0.5)

    # ---------------------------------------------------------
    # App Lifecycle
    # ---------------------------------------------------------
    async def start(self) -> None:
        """Initialize sockets, start background tasks, and wait for shutdown signal."""
        try:
            self.logger.info("<magenta>MasterDnsVPN Server starting ...</magenta>")
            self.loop = asyncio.get_running_loop()

            host = self.config.get("UDP_HOST", "0.0.0.0")
            port = int(self.config.get("UDP_PORT", 53))

            self.logger.debug("Binding UDP socket ...")
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

            self.logger.info(
                f"<green>UDP socket bound on <blue>{host}:{port}</blue></green>"
            )

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
            self.logger.info("<green>MasterDnsVPN Server started successfully.</green>")
            try:
                await self.should_stop.wait()
            except asyncio.CancelledError:
                pass

            await self.stop()
        except Exception as e:
            self.logger.exception(
                f"<red>Failed to start MasterDnsVPN Server: {e}</red>"
            )
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

        self.logger.info("<magenta>MasterDnsVPN Server stopped.</magenta>")
        os._exit(0)

    def _signal_handler(self, signum: int, frame: Any = None) -> None:
        """
        Handle termination signals for graceful shutdown.
        """
        self.logger.info(
            f"<red>Received signal {signum}, shutting down MasterDnsVPN Server ...</red>"
        )

        try:
            if self.loop:
                asyncio.run_coroutine_threadsafe(self.stop(), self.loop)
            else:
                asyncio.run(self.stop())
        except Exception:
            os._exit(0)
            pass

        self.logger.info("<yellow>Shutdown signalled.</yellow>")


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
