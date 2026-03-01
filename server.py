# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026


import sys
import os
import socket
import asyncio
import signal
import random
from typing import Optional, Any
import ctypes
from ctypes import wintypes
import kcp
import time

from server_config import master_dns_vpn_config

from dns_utils.utils import getLogger, get_encrypt_key
from dns_utils.DnsPacketParser import DnsPacketParser
from dns_utils.DNS_ENUMS import Packet_Type, DNS_Record_Type

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

        self.config = master_dns_vpn_config.__dict__
        self.logger = getLogger(log_level=self.config.get("LOG_LEVEL", "INFO"))
        self.allowed_domains = self.config.get("DOMAIN", [])

        self.recv_data_cache = {}
        self.send_data_cache = {}

        self.sessions = {}

        self.encrypt_key = get_encrypt_key(self.config.get("DATA_ENCRYPTION_METHOD", 1))
        self.logger.warning(f"Using encryption key: <green>{self.encrypt_key}</green>")

        self.dns_parser = DnsPacketParser(
            logger=self.logger,
            encryption_method=self.config.get("DATA_ENCRYPTION_METHOD", 1),
            encryption_key=self.encrypt_key,
        )

        self._dns_task = None
        self._session_cleanup_task = None

    async def new_session(self) -> int:
        """
        Create a new session and return its session ID.
        """
        for session_id in range(1, 256):
            if session_id not in self.sessions:
                self.sessions[session_id] = {
                    "last_packet_time": asyncio.get_event_loop().time()
                }
                self.logger.info(f"Created new session with ID: {session_id}")
                return session_id

    async def is_session_valid(self, session_id: int) -> bool:
        """
        Check if a session ID is valid.
        """
        return session_id in self.sessions

    async def close_inactive_sessions(self, timeout: int = 300) -> None:
        """
        Close sessions that have been inactive for a specified timeout (seconds).
        """
        current_time = asyncio.get_event_loop().time()
        inactive_sessions = [
            session_id
            for session_id, session_info in self.sessions.items()
            if current_time - session_info["last_packet_time"] > timeout
        ]
        for session_id in inactive_sessions:
            del self.sessions[session_id]
            self.logger.info(f"Closed inactive session with ID: {session_id}")

    async def send_udp_response(self, response: bytes, addr) -> bool:
        """Async send helper to write UDP response to addr using the server socket."""
        if not response or addr is None:
            return False
        try:
            if self.udp_sock is None:
                self.logger.error("UDP socket is not initialized for sending response.")
                return False

            if self.loop is None:
                self.loop = asyncio.get_running_loop()
            await self.loop.sock_sendto(self.udp_sock, response, addr)
            self.logger.debug(f"Sent DNS response to {addr}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to send DNS response to {addr}: {e}")
            return False

    async def handle_vpn_packet(
        self,
        packet_type: int,
        session_id: int,
        data: bytes = b"",
        labels: dict = {},
        parsed_packet: dict = None,
        addr=None,
        request_domain: str = "",
    ) -> Optional[bytes]:
        """Handle VPN packet based on its type."""

        handlers = {
            Packet_Type.MTU_UP_REQ: self._handle_mtu_up,
            Packet_Type.MTU_DOWN_REQ: self._handle_mtu_down,
            Packet_Type.SESSION_INIT: self._handle_session_init,
            Packet_Type.SET_MTU_REQ: self._handle_set_mtu,
            Packet_Type.DATA_KCP: self._handle_data_kcp,
        }

        handler = handlers.get(packet_type, self._handle_unknown)
        return await handler(
            data=data,
            labels=labels,
            request_domain=request_domain,
            addr=addr,
            parsed_packet=parsed_packet,
            session_id=session_id,
        )

    async def _handle_set_mtu(
        self,
        data=None,
        labels=None,
        request_domain=None,
        addr=None,
        parsed_packet=None,
        session_id=None,
    ) -> Optional[bytes]:
        """Handle SET_MTU_REQ VPN packet and save it to the session."""

        if session_id not in self.sessions:
            self.logger.warning(
                f"SET_MTU_REQ received for invalid session_id: {session_id} from {addr}"
            )
            return None

        # Extract and decrypt data directly from the labels
        extracted_data = self.dns_parser.extract_vpn_data_from_labels(labels)

        if not extracted_data or len(extracted_data) < 8:
            self.logger.warning(f"Invalid or missing SET_MTU_REQ data from {addr}")
            return None

        # Unpack the 8 bytes (4 bytes UP, 4 bytes DOWN)
        upload_mtu = int.from_bytes(extracted_data[0:4], byteorder="big")
        download_mtu = int.from_bytes(extracted_data[4:8], byteorder="big")

        # Save to session map
        self.sessions[session_id]["upload_mtu"] = upload_mtu
        self.sessions[session_id]["download_mtu"] = download_mtu
        self.sessions[session_id]["last_packet_time"] = asyncio.get_event_loop().time()

        self.logger.info(
            f"Session {session_id} MTU synced - UP: {upload_mtu}B, DOWN: {download_mtu}B"
        )

        # Prepare response (Acknowledge)
        response_data = b"OK"
        data_bytes = self.dns_parser.codec_transform(response_data, encrypt=True)

        response_packet = await self.dns_parser.generate_vpn_response_packet(
            domain=request_domain,
            session_id=session_id,
            packet_type=Packet_Type.SET_MTU_RES,
            data=data_bytes,
            question_packet=data,
        )

        return response_packet

    async def _handle_unknown(
        self,
        data=None,
        labels=None,
        request_domain=None,
        addr=None,
        parsed_packet=None,
        session_id=None,
    ) -> Optional[bytes]:
        self.logger.info(
            f"Received unknown packet type from {addr}. No handler available."
        )

        return None

    async def _handle_session_init(
        self,
        data=None,
        labels=None,
        request_domain=None,
        addr=None,
        parsed_packet=None,
        session_id=None,
    ) -> Optional[bytes]:
        """Handle NEW_SESSION VPN packet."""

        new_session_id = await self.new_session()
        if new_session_id is None:
            self.logger.error(
                f"Failed to create new session for NEW_SESSION packet from {addr}"
            )
            return None

        txt_str = str(new_session_id)
        data_bytes = self.dns_parser.codec_transform(txt_str.encode(), encrypt=True)

        response_packet = await self.dns_parser.generate_vpn_response_packet(
            domain=request_domain,
            session_id=new_session_id,
            packet_type=Packet_Type.SESSION_ACCEPT,
            data=data_bytes,
            question_packet=data,
        )

        # Ensure KCP engine is created for this session immediately so the first
        # DATA_KCP packets won't be rejected due to missing session state.
        try:
            self._get_or_create_kcp(new_session_id)
        except Exception:
            pass

        return response_packet

    async def _handle_mtu_down(
        self,
        data=None,
        labels=None,
        request_domain=None,
        addr=None,
        parsed_packet=None,
        session_id=None,
    ) -> Optional[bytes]:
        """Handle SERVER_UPLOAD_TEST VPN packet."""

        if "." not in labels:
            self.logger.warning(
                f"Invalid SERVER_DOWNLOAD_TEST packet format from {addr}: {labels}"
            )
            return None

        first_part_of_data = labels.split(".")[0]
        if not first_part_of_data:
            self.logger.warning(
                f"Empty data in SERVER_DOWNLOAD_TEST packet from {addr}"
            )
            return None

        download_size_bytes = self.dns_parser.decode_and_decrypt_data(
            first_part_of_data, lowerCaseOnly=True
        )

        if download_size_bytes is None:
            self.logger.warning(
                f"Failed to decode download size in SERVER_DOWNLOAD_TEST packet from {addr}"
            )
            return None

        download_size = int.from_bytes(download_size_bytes, byteorder="big")

        if download_size < 29:
            self.logger.warning(
                f"Download size too small in SERVER_DOWNLOAD_TEST packet from {addr}: {download_size}"
            )
            return None

        data_bytes = self.dns_parser.codec_transform(download_size_bytes, encrypt=True)
        data_bytes = data_bytes + ":".encode()
        data_bytes = data_bytes + random.randbytes(download_size - len(data_bytes))

        if len(data_bytes) != download_size:
            self.logger.error(
                f"Prepared download data size mismatch for packet from {addr}: expected {download_size}, got {len(data_bytes)}"
            )
            return None

        response_packet = await self.dns_parser.generate_vpn_response_packet(
            domain=request_domain,
            session_id=session_id if session_id is not None else 255,
            packet_type=Packet_Type.MTU_DOWN_RES,
            data=data_bytes,
            question_packet=data,
        )

        return response_packet

    async def _handle_mtu_up(
        self,
        data=None,
        labels=None,
        request_domain=None,
        addr=None,
        parsed_packet=None,
        session_id=None,
    ) -> Optional[bytes]:
        """Handle SERVER_UPLOAD_TEST VPN packet."""

        txt_str = "1"
        data_bytes = self.dns_parser.codec_transform(txt_str.encode(), encrypt=True)

        response_packet = await self.dns_parser.generate_vpn_response_packet(
            domain=request_domain,
            session_id=session_id if session_id is not None else 255,
            packet_type=Packet_Type.MTU_UP_RES,
            data=data_bytes,
            question_packet=data,
        )

        return response_packet

    async def validate_vpn_packet(
        self, data: bytes, parsed_packet: dict, addr
    ) -> Optional[bytes]:
        """
        Handle VPN packet logic and return (is_vpn_packet, response_bytes).
        """
        try:
            self.logger.debug(f"Handling VPN packet from {addr}")

            questions = parsed_packet.get("questions")
            if not questions:
                self.logger.error(f"No questions found in VPN packet from {addr}")
                return None

            request_domain = questions[0]["qName"]
            packet_domain = questions[0]["qName"].lower()
            packet_main_domain = next(
                (
                    domain
                    for domain in self.allowed_domains
                    if packet_domain.endswith(domain)
                ),
                "",
            )

            if questions[0]["qType"] != DNS_Record_Type.TXT:
                self.logger.warning(
                    f"Invalid DNS query type for VPN packet from {addr}: {questions[0]['qType']}"
                )
                return None

            if not packet_main_domain:
                self.logger.warning(
                    f"Domain {packet_domain} not allowed for VPN packets from {addr}"
                )
                return None

            if packet_domain.count(".") < 3:
                self.logger.warning(
                    f"Invalid domain format for VPN packet from {addr}: {packet_domain}"
                )
                return None

            labels = packet_domain.replace("." + packet_main_domain, "")

            self.logger.debug(
                f"Extracted VPN data from domain {packet_main_domain}: {labels}"
            )

            extracted_header = self.dns_parser.extract_vpn_header_from_labels(labels)
            if not extracted_header:
                self.logger.warning(
                    f"Failed to extract VPN header from labels for packet from {addr}"
                )
                return None

            if len(extracted_header) != 2:
                self.logger.warning(
                    f"Invalid VPN header length from labels for packet from {addr}: {len(extracted_header)}"
                )
                return None

            packet_type = extracted_header[1]
            if packet_type not in DNS_Record_Type.__dict__.values():
                self.logger.warning(
                    f"Invalid VPN packet type from labels for packet from {addr}: {packet_type}"
                )
                return None

            session_id = extracted_header[0]

            response = await self.handle_vpn_packet(
                packet_type=packet_type,
                session_id=session_id,
                data=data,
                labels=labels,
                parsed_packet=parsed_packet,
                addr=addr,
                request_domain=request_domain,
            )

            if response:
                return response
        except Exception as e:
            self.logger.error(f"Error handling VPN packet from {addr}: {e}")

        return None

    async def handle_single_request(self, data, addr):
        """
        Handle a single DNS request in its own task.
        """
        if data is None or addr is None:
            self.logger.error("Invalid data or address in DNS request.")
            return
        self.logger.debug(f"Received DNS request from {addr}")

        parsed_packet = await self.dns_parser.parse_dns_packet(data)
        self.logger.debug(f"Parsed DNS packet from {addr}: {parsed_packet}")

        # Check for VPN packet
        vpn_response = await self.validate_vpn_packet(data, parsed_packet, addr)
        if vpn_response:
            await self.send_udp_response(vpn_response, addr)
            return
        else:
            response = await self.dns_parser.server_fail_response(data)
            if not response:
                self.logger.error(
                    f"Failed to generate Server Failure response for DNS request from {addr}"
                )
                return

        await self.send_udp_response(response, addr)

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
                        self.loop.sock_recvfrom(self.udp_sock, 512), timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
            except OSError as e:
                self.logger.error(f"Socket error: {e}. Exiting DNS request handler.")
                continue
            except Exception as e:
                self.logger.exception(f"Unexpected error receiving DNS request: {e}")
                continue

            try:
                self.loop.create_task(self.handle_single_request(data, addr))
            except Exception as e:
                self.logger.error(f"Failed to create task for request from {addr}: {e}")

    async def _session_cleanup_loop(self) -> None:
        """Background task to periodically cleanup inactive sessions."""
        try:
            while not self.should_stop.is_set():
                try:
                    await asyncio.sleep(self.config.get("SESSION_CLEANUP_INTERVAL", 30))
                    await self.close_inactive_sessions(
                        self.config.get("SESSION_TIMEOUT", 300)
                    )
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    self.logger.error(f"Error during session cleanup: {e}")
        finally:
            self.logger.debug("Session cleanup loop stopped.")

    # ---------------------------------------------------------
    # KCP & TCP Forwarding Logic
    # ---------------------------------------------------------
    def _send_server_kcp_mux(
        self, session_id: int, conn_id: int, cmd: int, data: bytes = b""
    ):
        """Pack and send data via KCP Engine with Length Header"""
        if session_id not in self.sessions or "kcp" not in self.sessions[session_id]:
            return

        kcp_obj = self.sessions[session_id]["kcp"]
        header = (
            conn_id.to_bytes(2, byteorder="big")
            + bytes([cmd])
            + len(data).to_bytes(2, byteorder="big")
        )
        packet = header + data

        if hasattr(kcp_obj, "enqueue"):
            kcp_obj.enqueue(packet)
            if hasattr(kcp_obj, "flush"):
                kcp_obj.flush()
        elif hasattr(kcp_obj, "send"):
            kcp_obj.send(packet)

    def _get_or_create_kcp(self, session_id: int) -> tuple:
        """Initialize KCP for a session safely."""
        session_info = self.sessions[session_id]
        if "kcp" not in session_info:
            session_info["tcp_connections"] = {}
            session_info["downlink_queue"] = asyncio.Queue()
            session_info["rx_buffer"] = bytearray()

            kcp_obj = kcp.KCP(conv_id=int(session_id))

            @kcp_obj.outbound_handler
            def kcp_out(_, data: bytes):
                if self.loop and not self.should_stop.is_set():
                    self.loop.call_soon_threadsafe(
                        session_info["downlink_queue"].put_nowait, data
                    )

            if hasattr(kcp_obj, "set_performance_options"):
                kcp_obj.set_performance_options(True, 10, 2, True)
            elif hasattr(kcp_obj, "nodelay"):
                kcp_obj.nodelay(1, 10, 2, 1)

            kcp_mtu = int(max(session_info.get("download_mtu", 512) - 50, 100))
            try:
                kcp_obj.mtu = kcp_mtu  # Property for RealistikDash KCP
            except Exception:
                pass
            if hasattr(kcp_obj, "setmtu"):
                try:
                    kcp_obj.setmtu(kcp_mtu)
                except Exception:
                    pass
            elif hasattr(kcp_obj, "set_mtu"):
                try:
                    kcp_obj.set_mtu(kcp_mtu)
                except Exception:
                    pass

            try:
                kcp_obj.snd_wnd = 128  # Property for RealistikDash KCP
                kcp_obj.rcv_wnd = 128
            except Exception:
                pass
            if hasattr(kcp_obj, "set_window_size"):
                try:
                    kcp_obj.set_window_size(128, 128)
                except Exception:
                    pass
            elif hasattr(kcp_obj, "wndsize"):
                try:
                    kcp_obj.wndsize(128, 128)
                except Exception:
                    pass

            session_info["kcp"] = kcp_obj
            self.logger.info(f"Initialized KCP engine for Session {session_id}")

        return (
            session_info["kcp"],
            session_info["downlink_queue"],
            session_info["tcp_connections"],
            session_info["rx_buffer"],
        )

    async def _kcp_update_loop(self):
        """Global ticker for all active KCP sessions."""
        while not self.should_stop.is_set():
            for sid, sinfo in list(self.sessions.items()):
                if "kcp" in sinfo:
                    kcp_obj = sinfo["kcp"]
                    rx_buffer = sinfo["rx_buffer"]
                    tcp_conns = sinfo["tcp_connections"]

                    try:
                        try:
                            kcp_obj.update()
                        except Exception:
                            current_ms = int(time.time() * 1000) & 0xFFFFFFFF
                            kcp_obj.update(current_ms)

                        # Retrieve data
                        if hasattr(kcp_obj, "get_received"):
                            data = kcp_obj.get_received()
                        else:
                            try:
                                data = kcp_obj.recv()
                            except Exception:
                                data = b""

                        if data:
                            rx_buffer.extend(data)
                            await self._process_server_rx_buffer(
                                sid, rx_buffer, tcp_conns
                            )

                    except Exception as e:
                        self.logger.debug(f"Server KCP update error: {e}")
            await asyncio.sleep(0.01)

    async def _process_server_rx_buffer(
        self, session_id: int, rx_buffer: bytearray, tcp_conns: dict
    ):
        while len(rx_buffer) >= 5:
            conn_id = int.from_bytes(rx_buffer[0:2], byteorder="big")
            cmd = rx_buffer[2]
            payload_len = int.from_bytes(rx_buffer[3:5], byteorder="big")

            total_len = 5 + payload_len
            if len(rx_buffer) < total_len:
                break

            payload = rx_buffer[5:total_len]
            del rx_buffer[:total_len]

            await self._handle_server_mux_command(
                session_id, conn_id, cmd, payload, tcp_conns
            )

    async def _handle_server_mux_command(
        self, session_id: int, conn_id: int, cmd: int, data: bytes, tcp_conns: dict
    ):
        if cmd == 0x01:  # SYN
            self.logger.info(f"Session {session_id} - Opening TCP {conn_id} to remote")
            try:
                forward_ip = self.config.get("FORWARD_IP", "127.0.0.1")
                forward_port = int(self.config.get("FORWARD_PORT", 8080))
                reader, writer = await asyncio.open_connection(forward_ip, forward_port)
                tcp_conns[conn_id] = (reader, writer)
                self.loop.create_task(
                    self._forward_tcp_to_kcp(session_id, conn_id, reader)
                )
            except Exception as e:
                self.logger.error(f"Failed to connect conn {conn_id} to remote: {e}")
        elif cmd == 0x02:  # DAT
            if conn_id in tcp_conns:
                _, writer = tcp_conns[conn_id]
                if not writer.is_closing():
                    writer.write(data)
                    await writer.drain()
        elif cmd == 0x03:  # FIN
            await self._close_server_tcp_conn(tcp_conns, conn_id)

    async def _forward_tcp_to_kcp(
        self, session_id: int, conn_id: int, reader: asyncio.StreamReader
    ):
        """Read data from Target Server and send to Client via MUX KCP."""
        try:
            while not self.should_stop.is_set():
                if session_id not in self.sessions:
                    break
                data = await reader.read(4096)
                if not data:
                    break
                self._send_server_kcp_mux(session_id, conn_id, 0x02, data)
        except Exception as e:
            self.logger.debug(f"Target read error on conn {conn_id}: {e}")
        finally:
            self._send_server_kcp_mux(session_id, conn_id, 0x03)
            if (
                session_id in self.sessions
                and "tcp_connections" in self.sessions[session_id]
            ):
                await self._close_server_tcp_conn(
                    self.sessions[session_id]["tcp_connections"], conn_id
                )

    async def _close_server_tcp_conn(self, tcp_conns: dict, conn_id: int):
        """Safely close target TCP connection."""
        if conn_id in tcp_conns:
            _, writer = tcp_conns.pop(conn_id)
            if not writer.is_closing():
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            self.logger.debug(f"Server TCP conn {conn_id} cleanly closed.")

    async def _handle_data_kcp(
        self,
        data=None,
        labels=None,
        request_domain=None,
        addr=None,
        parsed_packet=None,
        session_id=None,
    ) -> Optional[bytes]:
        """Process incoming KCP packets and generate responses."""
        if session_id not in self.sessions:
            return None

        self.sessions[session_id]["last_packet_time"] = asyncio.get_event_loop().time()
        kcp_obj, downlink_queue, _, _ = self._get_or_create_kcp(session_id)

        # 1. Feed UDP payload to KCP Engine
        extracted_data = self.dns_parser.extract_vpn_data_from_labels(labels)

        if extracted_data:
            try:
                if hasattr(kcp_obj, "receive"):
                    kcp_obj.receive(extracted_data)
                elif hasattr(kcp_obj, "input"):
                    kcp_obj.input(extracted_data)
            except Exception as e:
                # Log additional debug information to help diagnose conv-id/data issues
                try:
                    hex_snippet = extracted_data[:16].hex()
                    data_len = len(extracted_data)
                except Exception:
                    hex_snippet = ""
                    data_len = 0

                kcp_conv = None
                try:
                    # Some KCP implementations expose a conv attribute
                    if hasattr(kcp_obj, "conv"):
                        kcp_conv = getattr(kcp_obj, "conv")
                except Exception:
                    kcp_conv = None

                self.logger.debug(
                    f"Server KCP Engine rejected bad packet: {e} | len={data_len} | hex={hex_snippet} | kcp_conv={kcp_conv}"
                )

        # 2. Force immediate KCP update to generate ACKs instantly
        try:
            kcp_obj.update()
        except Exception:
            kcp_obj.update(int(time.time() * 1000) & 0xFFFFFFFF)

        # 3. Pull ONE complete Datagram from KCP output
        try:
            response_payload = downlink_queue.get_nowait()
        except asyncio.QueueEmpty:
            response_payload = b""

        data_bytes = (
            self.dns_parser.codec_transform(response_payload, encrypt=True)
            if response_payload
            else b""
        )

        response_packet = await self.dns_parser.generate_vpn_response_packet(
            domain=request_domain,
            session_id=session_id,
            packet_type=Packet_Type.DATA_KCP,
            data=data_bytes,
            question_packet=data,
        )
        return response_packet

    async def start(self) -> None:
        """Initialize sockets, start background tasks, and wait for shutdown signal."""
        try:
            self.logger.info("MasterDnsVPN Server starting ...")
            self.loop = asyncio.get_running_loop()

            host = self.config.get("UDP_HOST", "0.0.0.0")
            port = int(self.config.get("UDP_PORT", 53))

            self._kcp_update_task = self.loop.create_task(self._kcp_update_loop())

            self.logger.info("Binding UDP socket ...")
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except Exception:
                pass

            self.udp_sock.bind((host, port))

            self.logger.info(f"UDP socket bound on {host}:{port}")

            self._dns_task = self.loop.create_task(self.handle_dns_requests())
            self._session_cleanup_task = self.loop.create_task(
                self._session_cleanup_loop()
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
        try:
            if getattr(self, "_dns_task", None):
                self._dns_task.cancel()
        except Exception:
            pass

        try:
            if getattr(self, "_session_cleanup_task", None):
                self._session_cleanup_task.cancel()
        except Exception:
            pass

        try:
            await asyncio.gather(
                *(
                    t
                    for t in (
                        getattr(self, "_dns_task", None),
                        getattr(self, "_session_cleanup_task", None),
                    )
                    if t
                ),
                return_exceptions=True,
            )
        except Exception:
            pass

        if self.loop:
            try:
                self.loop.call_soon_threadsafe(self.should_stop.set)
            except Exception:
                try:
                    if not self.should_stop.is_set():
                        self.should_stop.set()
                except Exception:
                    pass

            try:
                self.loop.call_soon_threadsafe(self._close_udp_socket)
            except Exception:
                pass

            try:
                self.loop.call_soon_threadsafe(self._cancel_background_tasks)
            except Exception:
                pass

            try:
                self.loop.call_soon_threadsafe(self.loop.stop)
            except Exception:
                pass
        else:
            if not self.should_stop.is_set():
                try:
                    self.should_stop.set()
                except Exception:
                    pass

        if self.udp_sock:
            try:
                self.udp_sock.close()
            except Exception:
                pass

        os.exit(0)
        self.logger.info("MasterDnsVPN Server stopped.")

    def _cancel_background_tasks(self) -> None:
        """Cancel background tasks from the event loop thread."""
        try:
            if getattr(self, "_dns_task", None):
                try:
                    self._dns_task.cancel()
                except Exception:
                    pass
            if getattr(self, "_session_cleanup_task", None):
                try:
                    self._session_cleanup_task.cancel()
                except Exception:
                    pass
            self.logger.debug("Background tasks cancellation requested.")
        except Exception as e:
            self.logger.error(f"Error cancelling background tasks: {e}")

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

    def _close_udp_socket(self) -> None:
        """Close the UDP socket from the event loop thread."""
        try:
            if self.udp_sock:
                try:
                    self.udp_sock.close()
                    self.logger.info("UDP socket closed.")
                finally:
                    self.udp_sock = None
        except Exception as e:
            self.logger.error(f"Error closing UDP socket: {e}")


def main():
    server = MasterDnsVPNServer()
    try:
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

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
