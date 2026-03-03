# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import time
import random
import functools
import sys
import os
import socket
import asyncio
from typing import Optional, Tuple
import signal
import ctypes
from ctypes import wintypes

from client_config import master_dns_vpn_config
from dns_utils.utils import (
    getLogger,
    generate_random_hex_text,
    async_recvfrom,
    async_sendto,
)
from dns_utils.DnsPacketParser import DnsPacketParser
from dns_utils.DNS_ENUMS import Packet_Type, DNS_Record_Type
from dns_utils.PingManager import PingManager
from dns_utils.DNSBalancer import DNSBalancer

# Ensure UTF-8 output for consistent logging
try:
    if sys.stdout.encoding is not None and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


class MasterDnsVPNClient:
    """MasterDnsVPN Client class to handle DNS requests over UDP."""

    def __init__(self) -> None:
        self.udp_sock: Optional[socket.socket] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.should_stop: asyncio.Event = asyncio.Event()
        self.session_restart_event = None
        self.config: dict = master_dns_vpn_config.__dict__
        self.logger = getLogger(log_level=self.config.get("LOG_LEVEL", "INFO"))
        self.resolvers: list = self.config.get("RESOLVER_DNS_SERVERS", [])
        self.domains: list = self.config.get("DOMAINS", [])
        self.timeout: float = self.config.get("DNS_QUERY_TIMEOUT", 10.0)
        self.max_upload_mtu: int = self.config.get("MAX_UPLOAD_MTU", 512)
        self.max_download_mtu: int = self.config.get("MAX_DOWNLOAD_MTU", 4096)
        self.min_upload_mtu: int = self.config.get("MIN_UPLOAD_MTU", 0)
        self.min_download_mtu: int = self.config.get("MIN_DOWNLOAD_MTU", 0)
        self.encryption_method: int = self.config.get("DATA_ENCRYPTION_METHOD", 1)
        self.skip_resolver_with_packet_loss: int = self.config.get(
            "SKIP_RESOLVER_WITH_PACKET_LOSS", 100
        )
        self.resolver_balancing_strategy: int = self.config.get(
            "RESOLVER_BALANCING_STRATEGY", 0
        )
        self.encryption_key: str = self.config.get("ENCRYPTION_KEY", None)

        if not self.encryption_key:
            self.logger.error("No encryption key provided in configuration.")
            sys.exit(1)

        self.dns_packet_parser = DnsPacketParser(
            logger=self.logger,
            encryption_method=self.encryption_method,
            encryption_key=self.encryption_key,
        )

        self.packets_queue: dict = {}
        self.connections_map: list = []
        self.session_id = 0
        self.synced_upload_mtu = 0
        self.synced_upload_mtu_chars = 0
        self.synced_download_mtu = 0
        self.buffer_size = 65507  # Max UDP payload size
        self._background_tasks = set()
        self.last_stat_update = 0
        self.cached_valid_connections = []
        self.packet_duplication = self.config.get("PACKET_DUPLICATION_COUNT", 1)
        self.balancer = DNSBalancer(
            resolvers=self.connections_map, strategy=self.resolver_balancing_strategy
        )
        self.ping_manager = PingManager(self.balancer, self._send_ping_packet)

        self.logger.debug("<magenta>[INIT]</magenta> MasterDnsVPNClient initialized.")

    # ---------------------------------------------------------
    # Connection Management
    # ---------------------------------------------------------
    async def create_connection_map(self) -> None:
        """Create a map of all domain-resolver combinations."""
        self.logger.debug("<magenta>[CONN]</magenta> Creating connection map...")
        self.connections_map: list = []
        self.resent_connection_selected = -1
        self.connections_map = [
            {"domain": domain, "resolver": resolver}
            for domain in self.domains
            for resolver in self.resolvers
        ]

        self.connections_map = [
            dict(t) for t in {tuple(d.items()) for d in self.connections_map}
        ]
        self.logger.debug(
            f"<magenta>[CONN]</magenta> Total potential connections: {len(self.connections_map)}"
        )

    # ---------------------------------------------------------
    # Network I/O & Packet Processing
    # ---------------------------------------------------------
    async def _send_and_receive_dns(
        self,
        query_data: bytes,
        resolver: str,
        port: int,
        timeout: float = 10,
        buffer_size: int = 0,
    ) -> Optional[bytes]:
        """Send a UDP packet and wait for the response."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        if buffer_size <= 0:
            buffer_size = self.buffer_size

        try:
            self.logger.debug(
                f"<blue>[DNS_IO]</blue> Sending query to {resolver}:{port} ({len(query_data)} bytes)"
            )
            await async_sendto(self.loop, sock, query_data, (resolver, port))
            response, _ = await asyncio.wait_for(
                async_recvfrom(self.loop, sock, buffer_size), timeout=timeout
            )
            self.logger.debug(
                f"<blue>[DNS_IO]</blue> Received response from {resolver}:{port} ({len(response)} bytes)"
            )
            return response
        except asyncio.TimeoutError:
            self.logger.debug(
                f"<blue>[DNS_IO]</blue> Timeout waiting for response from {resolver}"
            )
            return None
        except Exception as e:
            self.logger.debug(
                f"Network error communicating with {resolver}:{port} - {e}"
            )
            return None
        finally:
            try:
                sock.close()
            except Exception:
                pass

    async def _send_ping_packet(self, server, is_ping=True):
        if not is_ping or not server:
            return

        import time

        dynamic_data = f"P{int(time.time() % 60)}R{random.randint(100, 999)}".encode()

        try:
            query_packets = await self.dns_packet_parser.build_request_dns_query(
                domain=server["domain"],
                session_id=self.session_id,
                packet_type=Packet_Type.PING,
                data=dynamic_data,
                mtu_chars=self.synced_upload_mtu_chars,
                encode_data=True,
                qType=DNS_Record_Type.TXT,
                stream_id=0,
                sequence_num=0,
            )
            if query_packets:
                await async_sendto(
                    self.loop,
                    self.tunnel_sock,
                    query_packets[0],
                    (server["resolver"], 53),
                )
        except Exception as e:
            self.logger.debug(f"Failed to send PING: {e}")

    async def _process_received_packet(
        self, response_bytes: bytes
    ) -> Tuple[Optional[int], bytes]:
        """
        Parse raw DNS response, extract VPN header, and return packet type alongside assembled data.
        Acts as the core for switching request/response types.
        """
        if not response_bytes:
            return None, b""

        parsed = await self.dns_packet_parser.parse_dns_packet(response_bytes)
        if not parsed or not parsed.get("answers"):
            self.logger.debug(
                "<yellow>[PARSER]</yellow> DNS response contains no answers."
            )
            return None, b""

        chunks = {}
        detected_packet_type = None

        for answer in parsed.get("answers", []):
            if answer.get("type") != DNS_Record_Type.TXT:
                continue

            txt_str = self.dns_packet_parser.extract_txt_from_rData(answer["rData"])
            if not txt_str:
                continue

            parts = txt_str.split(".", 2)
            if len(parts) < 3:
                continue

            header_str, answer_id_str, chunk_payload = parts[0], parts[1], parts[2]
            header_bytes = self.dns_packet_parser.decode_and_decrypt_data(
                header_str, lowerCaseOnly=False
            )

            parsed_header = self.dns_packet_parser.parse_vpn_header_bytes(header_bytes)
            if parsed_header:
                packet_type = parsed_header["packet_type"]

                if detected_packet_type is None:
                    detected_packet_type = packet_type

                if packet_type == detected_packet_type:
                    try:
                        chunks[int(answer_id_str)] = chunk_payload
                    except ValueError:
                        pass

        if detected_packet_type is None:
            self.logger.debug(
                "<yellow>[PARSER]</yellow> No valid VPN header found in answers."
            )
            return None, b""

        assembled_data_str = ""
        for i in sorted(chunks.keys()):
            assembled_data_str += chunks[i]

        decoded_data = self.dns_packet_parser.decode_and_decrypt_data(
            assembled_data_str, lowerCaseOnly=False
        )
        self.logger.debug(
            f"<yellow>[PARSER]</yellow> Packet Type: {detected_packet_type}, Data Len: {len(decoded_data)}"
        )
        return parsed_header, decoded_data

    # ---------------------------------------------------------
    # MTU Testing Logic
    # ---------------------------------------------------------
    async def _binary_search_mtu(
        self, test_callable, min_mtu: int, max_mtu: int, min_threshold: int = 30
    ) -> int:
        """Generic binary search for finding the optimal MTU size."""
        try:
            if max_mtu <= 0:
                return 0

            self.logger.debug(
                f"<cyan>[MTU]</cyan> Starting binary search for MTU. Range: {min_mtu}-{max_mtu}"
            )
            for _ in range(2):
                if await test_callable(max_mtu):
                    self.logger.debug(f"<cyan>[MTU]</cyan> Max MTU {max_mtu} is valid.")
                    return max_mtu

            low = min_mtu
            high = max_mtu - 1
            optimal = 0

            while low <= high:
                mid = (low + high) // 2
                if mid < min_threshold:
                    break

                ok = False
                for _ in range(3):
                    try:
                        ok = await test_callable(mid)
                        if ok:
                            break
                    except Exception as e:
                        self.logger.debug(f"MTU test callable raised: {e}")
                        ok = False

                if ok:
                    optimal = mid
                    low = mid + 1
                else:
                    high = mid - 1

            self.logger.debug(f"<cyan>[MTU]</cyan> Binary search result: {optimal}")
            return optimal
        except Exception as e:
            self.logger.debug(f"Error in MTU binary search: {e}")
            return 0

    async def send_upload_mtu_test(
        self, domain: str, dns_server: str, dns_port: int, mtu_size: int
    ) -> bool:
        mtu_char_len, mtu_bytes = self.dns_packet_parser.calculate_upload_mtu(
            domain=domain, mtu=mtu_size
        )

        if mtu_size > mtu_bytes:
            return False

        if mtu_char_len < 29:
            return False

        random_hex = generate_random_hex_text(mtu_char_len).lower()
        dns_queries = await self.dns_packet_parser.build_request_dns_query(
            domain=domain,
            session_id=random.randint(0, 255),
            packet_type=Packet_Type.MTU_UP_REQ,
            data=random_hex,
            mtu_chars=mtu_char_len,
            encode_data=False,
            qType=DNS_Record_Type.TXT,
        )

        if not dns_queries:
            return False

        response = await self._send_and_receive_dns(
            dns_queries[0], dns_server, dns_port, 2
        )

        parsed_header, _ = await self._process_received_packet(response)
        packet_type = parsed_header["packet_type"] if parsed_header else None

        if packet_type == Packet_Type.MTU_UP_RES:
            return True
        elif packet_type == Packet_Type.ERROR_DROP:
            return False
        return False

    async def send_download_mtu_test(
        self, domain: str, dns_server: str, dns_port: int, mtu_size: int
    ) -> bool:
        data_bytes = mtu_size.to_bytes(4, byteorder="big")
        encrypted_data = self.dns_packet_parser.codec_transform(
            data_bytes, encrypt=True
        )

        mtu_char_len, _ = self.dns_packet_parser.calculate_upload_mtu(
            domain=domain, mtu=64
        )

        dns_queries = await self.dns_packet_parser.build_request_dns_query(
            domain=domain,
            session_id=random.randint(0, 255),
            packet_type=Packet_Type.MTU_DOWN_REQ,
            data=encrypted_data,
            mtu_chars=mtu_char_len,
            encode_data=True,
            qType=DNS_Record_Type.TXT,
        )

        if not dns_queries:
            return False

        response = await self._send_and_receive_dns(
            dns_queries[0], dns_server, dns_port, 2
        )
        parsed_header, returned_data = await self._process_received_packet(response)
        packet_type = parsed_header["packet_type"] if parsed_header else None

        if packet_type == Packet_Type.MTU_DOWN_RES:
            if returned_data and len(returned_data) == mtu_size:
                return True
            else:
                return False
        return False

    async def test_upload_mtu_size(
        self, domain: str, dns_server: str, dns_port: int, default_mtu: int
    ) -> tuple:
        try:
            self.logger.debug(f"<cyan>[MTU]</cyan> Testing upload MTU for {domain}")
            mtu_char_len, mtu_bytes = self.dns_packet_parser.calculate_upload_mtu(
                domain=domain, mtu=0
            )
            if default_mtu > 512 or default_mtu <= 0:
                default_mtu = 512
            if mtu_bytes > default_mtu:
                mtu_bytes = default_mtu

            test_fn = functools.partial(
                self.send_upload_mtu_test, domain, dns_server, dns_port
            )
            optimal_mtu = await self._binary_search_mtu(
                test_fn, 0, default_mtu, min_threshold=30
            )

            if optimal_mtu > 29:
                mtu_char_len, mtu_bytes = self.dns_packet_parser.calculate_upload_mtu(
                    domain=domain, mtu=optimal_mtu
                )
                return True, mtu_bytes, mtu_char_len
        except Exception as e:
            self.logger.debug(f"Error calculating upload MTU for {domain}: {e}")
        return False, 0, 0

    async def test_download_mtu_size(
        self, domain: str, dns_server: str, dns_port: int, default_mtu: int
    ) -> tuple:
        try:
            self.logger.debug(f"<cyan>[MTU]</cyan> Testing download MTU for {domain}")
            test_fn = functools.partial(
                self.send_download_mtu_test, domain, dns_server, dns_port
            )
            optimal_mtu = await self._binary_search_mtu(
                test_fn, 0, default_mtu, min_threshold=30
            )

            if optimal_mtu >= max(30, self.min_download_mtu):
                return True, optimal_mtu
        except Exception as e:
            self.logger.debug(f"Error calculating download MTU for {domain}: {e}")
        return False, 0

    async def test_mtu_sizes(self) -> bool:
        self.logger.info("=" * 80)
        self.logger.info("<y>Testing MTU sizes for all resolver-domain pairs...</y>")

        for connection in self.connections_map:
            if not connection or self.should_stop.is_set():
                continue

            domain = connection.get("domain")
            resolver = connection.get("resolver")
            dns_port = 53

            connection["is_valid"] = False
            connection["upload_mtu_bytes"] = 0
            connection["upload_mtu_chars"] = 0
            connection["download_mtu_bytes"] = 0
            connection["packet_loss"] = 100

            # Step 1: Upload MTU
            up_valid, up_mtu_bytes, up_mtu_char = await self.test_upload_mtu_size(
                domain, resolver, dns_port, self.max_upload_mtu
            )

            if not up_valid or (
                self.min_upload_mtu > 0 and up_mtu_bytes < self.min_upload_mtu
            ):
                self.logger.warning(
                    f"Connection invalid for {domain} via {resolver}: Upload MTU failed."
                )
                continue

            # Step 2: Download MTU
            down_valid, down_mtu_bytes = await self.test_download_mtu_size(
                domain, resolver, dns_port, self.max_download_mtu
            )

            if not down_valid or (
                self.min_download_mtu > 0 and down_mtu_bytes < self.min_download_mtu
            ):
                self.logger.warning(
                    f"Connection invalid for {domain} via {resolver}: Download MTU failed."
                )
                continue

            # Marking as Valid
            connection["is_valid"] = True
            connection["upload_mtu_bytes"] = up_mtu_bytes
            connection["upload_mtu_chars"] = up_mtu_char
            connection["download_mtu_bytes"] = down_mtu_bytes
            connection["packet_loss"] = 0

            self.logger.info(
                f"<green>Valid: <cyan>{domain}</cyan> via <cyan>{resolver}</cyan> | "
                f"UP: {up_mtu_bytes}B ({up_mtu_char}c) | DOWN: {down_mtu_bytes}B</green>"
            )

        valid_conns = [c for c in self.connections_map if c.get("is_valid")]
        if not valid_conns:
            self.logger.error(
                "<red>No valid connections found after MTU testing!</red>"
            )
            return False

        return True

    async def _sync_mtu_with_server(self, domain: str, resolver: str) -> bool:
        """Send the synced MTU values to the server for this session."""
        self.logger.info(f"Syncing MTU with server for session {self.session_id}...")

        # Pack MTUs into 8 bytes (4 bytes UP, 4 bytes DOWN)
        data_bytes = self.synced_upload_mtu.to_bytes(
            4, byteorder="big"
        ) + self.synced_download_mtu.to_bytes(4, byteorder="big")

        # Encrypt the payload before sending
        encrypted_data = self.dns_packet_parser.codec_transform(
            data_bytes, encrypt=True
        )

        mtu_char_len, _ = self.dns_packet_parser.calculate_upload_mtu(
            domain=domain, mtu=64
        )
        dns_queries = await self.dns_packet_parser.build_request_dns_query(
            domain=domain,
            session_id=self.session_id,
            packet_type=Packet_Type.SET_MTU_REQ,
            data=encrypted_data,
            mtu_chars=mtu_char_len,
            encode_data=True,
            qType=DNS_Record_Type.TXT,
        )

        if not dns_queries:
            return False

        max_retries = 10
        base_delay = 1.0

        for attempt in range(max_retries):
            if self.should_stop.is_set():
                break

            response = await self._send_and_receive_dns(
                dns_queries[0], resolver, 53, self.timeout
            )

            if response:
                parsed_header, returned_data = await self._process_received_packet(
                    response
                )
                packet_type = parsed_header["packet_type"] if parsed_header else None

                if packet_type == Packet_Type.SET_MTU_RES:
                    self.logger.success(
                        "<g>MTU values successfully synced with the server!</g>"
                    )
                    return True

            if attempt < max_retries - 1:
                delay = min(base_delay * (1.5**attempt), 8.0)
                self.logger.warning(
                    f"MTU sync failed. Retrying in {delay:.1f}s (Attempt {attempt + 1}/{max_retries})..."
                )
                await asyncio.sleep(delay)

        self.logger.error("Failed to sync MTU with the server after multiple attempts.")
        return False

    # ---------------------------------------------------------
    # Core Loop & Session Setup
    # ---------------------------------------------------------
    async def _init_session(self, domain: str, resolver: str) -> bool:
        """Initialize a new session with the server."""
        self.logger.info(f"Initializing session via {resolver} for {domain}...")

        mtu_char_len, _ = self.dns_packet_parser.calculate_upload_mtu(
            domain=domain, mtu=64
        )
        dns_queries = await self.dns_packet_parser.build_request_dns_query(
            domain=domain,
            session_id=0,  # 0 signals a request for a new session ID
            packet_type=Packet_Type.SESSION_INIT,
            data=b"INIT",
            mtu_chars=mtu_char_len,
            encode_data=True,
            qType=DNS_Record_Type.TXT,
        )

        if not dns_queries:
            return False

        max_retries = 10
        base_delay = 1.0

        for attempt in range(max_retries):
            if self.should_stop.is_set():
                break

            response = await self._send_and_receive_dns(
                dns_queries[0], resolver, 53, self.timeout
            )

            if response:
                parsed_header, returned_data = await self._process_received_packet(
                    response
                )
                packet_type = parsed_header["packet_type"] if parsed_header else None

                if packet_type == Packet_Type.SESSION_ACCEPT and returned_data:
                    try:
                        self.session_id = int(returned_data.decode("utf-8"))
                        self.logger.debug(
                            f"<green>[SESSION]</green> New session ID: {self.session_id}"
                        )
                        return True
                    except ValueError:
                        self.logger.error("Failed to parse Session ID from server.")

            if attempt < max_retries - 1:
                delay = min(base_delay * (1.5**attempt), 8.0)
                self.logger.warning(
                    f"Session init failed. Retrying in {delay:.1f}s (Attempt {attempt + 1}/{max_retries})..."
                )
                await asyncio.sleep(delay)

        self.logger.error("Failed to initialize session after multiple attempts.")
        return False

    async def run_client(self) -> None:
        """Run the MasterDnsVPN Client main logic."""
        self.logger.info("Setting up connections...")
        try:
            await self.create_connection_map()

            if not await self.test_mtu_sizes():
                self.logger.error("No valid servers found to connect.")
                return

            valid_conns = [c for c in self.connections_map if c.get("is_valid")]

            self.balancer.resolvers = valid_conns

            self.synced_upload_mtu = min(c["upload_mtu_bytes"] for c in valid_conns)
            self.synced_upload_mtu_chars = min(
                c["upload_mtu_chars"] for c in valid_conns
            )
            self.synced_download_mtu = min(c["download_mtu_bytes"] for c in valid_conns)

            self.logger.info(
                f"<green>Synced Global MTU -> UP: {self.synced_upload_mtu}B, DOWN: {self.synced_download_mtu}B</green>"
            )

            selected_conn = self.balancer.get_best_server()
            if not selected_conn:
                return

            if await self._init_session(
                selected_conn["domain"], selected_conn["resolver"]
            ):
                self.logger.success(
                    f"<g>Session Established! Session ID: {self.session_id}</g>"
                )

                if await self._sync_mtu_with_server(
                    selected_conn["domain"], selected_conn["resolver"]
                ):
                    await self._main_tunnel_loop()
                else:
                    self.logger.error("Stopping due to MTU sync failure.")
            else:
                self.logger.error("Session initialization failed.")

        except Exception as e:
            self.logger.error(f"Error setting up connections: {e}")
            return

    # ---------------------------------------------------------
    # TCP Multiplexing Logic & KCP Handlers
    # ---------------------------------------------------------
    async def _main_tunnel_loop(self):
        """Start local TCP server and main worker tasks."""
        self.logger.info("Entering VPN Tunnel Main Loop...")
        self.session_restart_event = asyncio.Event()
        self.outbound_queue = asyncio.PriorityQueue()
        self.active_streams = {}
        self.pending_streams = {}
        self.last_activity_time = self.loop.time()

        self.tunnel_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.tunnel_sock.setsockopt(
                socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024
            )
            self.tunnel_sock.setsockopt(
                socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024
            )
        except Exception as e:
            self.logger.debug(f"Failed to increase socket buffer: {e}")

        self.tunnel_sock.bind(("0.0.0.0", 0))

        if sys.platform == "win32":
            try:
                SIO_UDP_CONNRESET = -1744830452
                self.tunnel_sock.ioctl(SIO_UDP_CONNRESET, False)
            except Exception as e:
                self.logger.debug(f"Failed to set SIO_UDP_CONNRESET: {e}")
        self.tunnel_sock.setblocking(False)

        listen_ip = self.config.get("LISTEN_IP", "127.0.0.1")
        listen_port = int(self.config.get("LISTEN_PORT", 1080))

        server = None
        try:
            server = await asyncio.start_server(
                self._handle_local_tcp_connection,
                listen_ip,
                listen_port,
                reuse_address=True,
                reuse_port=True,
            )

            self.logger.success(
                f"<g>Ready! Local Proxy listening on {listen_ip}:{listen_port}</g>"
            )

            self.workers = []
            self.workers.append(self.loop.create_task(self._rx_worker()))

            num_workers = self.config.get("NUM_DNS_WORKERS", 4)
            self.logger.debug(
                f"<magenta>[LOOP]</magenta> Starting {num_workers} TX workers."
            )
            for _ in range(num_workers):
                self.workers.append(self.loop.create_task(self._tx_worker()))

            self.workers.append(self.loop.create_task(self._retransmit_worker()))
            self.workers.append(self.loop.create_task(self.ping_manager.ping_loop()))

            stop_task = asyncio.create_task(self.should_stop.wait())
            restart_task = asyncio.create_task(self.session_restart_event.wait())

            await asyncio.wait(
                [stop_task, restart_task], return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            self.logger.info("Cleaning up tunnel resources...")

            if server:
                try:
                    server.close()
                    await server.wait_closed()
                except Exception:
                    pass

            for w in getattr(self, "workers", []):
                w.cancel()

            for stream in list(getattr(self, "active_streams", {}).values()):
                try:
                    await stream.close()
                except Exception:
                    pass

            if hasattr(self, "tunnel_sock") and self.tunnel_sock:
                try:
                    self.tunnel_sock.close()
                except Exception:
                    pass

        stop_task.cancel()
        restart_task.cancel()

        self.logger.info("Cleaning up old connections before reconnecting...")

        await asyncio.gather(*self.workers, return_exceptions=True)

        for sid, (reader, writer) in self.pending_streams.items():
            try:
                writer.close()
            except Exception:
                pass

        self.active_streams.clear()
        self.pending_streams.clear()

    async def _rx_worker(self):
        """Continuously listen for incoming VPN packets on the tunnel socket."""
        self.logger.debug("<magenta>[RX]</magenta> RX Worker started.")
        while not self.should_stop.is_set():
            try:
                data, addr = await asyncio.wait_for(
                    async_recvfrom(self.loop, self.tunnel_sock, 65536), timeout=1.0
                )
                self.logger.debug(
                    f"<magenta>[RX]</magenta> Data from tunnel socket: {len(data)} bytes"
                )
                self.loop.create_task(self._process_and_route_incoming(data))

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.debug(f"RX Worker error: {e}")

    async def _process_and_route_incoming(self, data):
        """Helper to process incoming data asynchronously."""
        parsed_header, returned_data = await self._process_received_packet(data)
        if parsed_header:
            await self._handle_server_response(parsed_header, returned_data)

    async def _handle_local_tcp_connection(self, reader, writer):
        stream_id = 1
        while stream_id in self.active_streams or stream_id in self.pending_streams:
            stream_id += 1
            if stream_id > 65535:
                self.logger.error("No available Stream IDs! Too many connections.")
                writer.close()
                return

        self.logger.info(f"New local connection, assigning Stream ID: {stream_id}")

        # Priority 2 (Control)
        await self.outbound_queue.put(
            (2, self.loop.time(), Packet_Type.STREAM_SYN, stream_id, 0, b"")
        )
        self.pending_streams[stream_id] = (reader, writer, self.loop.time())

    async def _client_enqueue_tx(
        self, priority, stream_id, sn, data, is_ack=False, is_fin=False, is_resend=False
    ):
        ptype = Packet_Type.STREAM_DATA
        if is_ack:
            ptype = Packet_Type.STREAM_DATA_ACK
        elif is_fin:
            ptype = Packet_Type.STREAM_FIN
        elif is_resend:
            ptype = Packet_Type.STREAM_RESEND

        self.logger.debug(
            f"<blue>[QUEUE]</blue> Enqueueing {ptype} for SID: {stream_id} SN: {sn} Priority: {priority}"
        )
        await self.outbound_queue.put(
            (priority, self.loop.time(), ptype, stream_id, sn, data)
        )

    async def _tx_worker(self):
        self.logger.debug("<magenta>[TX]</magenta> TX Worker started.")
        while not self.should_stop.is_set():
            self.ping_manager.active_connections = len(self.active_streams) + len(
                self.pending_streams
            )

            try:
                priority, _, pkt_type, stream_id, sn, data = await asyncio.wait_for(
                    self.outbound_queue.get(), timeout=1.0
                )

                self.ping_manager.update_activity()
                self.last_activity_time = self.loop.time()

            except asyncio.TimeoutError:
                continue

            try:
                data_encrypted = (
                    self.dns_packet_parser.codec_transform(data, encrypt=True)
                    if data
                    else b""
                )

                target_conns = self.balancer.get_unique_servers(self.packet_duplication)
                if not target_conns:
                    continue

                for conn in target_conns:
                    query_packets = (
                        await self.dns_packet_parser.build_request_dns_query(
                            domain=conn["domain"],
                            session_id=self.session_id,
                            packet_type=pkt_type,
                            data=data_encrypted,
                            mtu_chars=self.synced_upload_mtu_chars,
                            encode_data=True,
                            qType=DNS_Record_Type.TXT,
                            stream_id=stream_id,
                            sequence_num=sn,
                        )
                    )

                    if not query_packets:
                        continue

                    for query_packet in query_packets:
                        await async_sendto(
                            self.loop,
                            self.tunnel_sock,
                            query_packet,
                            (conn["resolver"], 53),
                        )

                    conn["total_packets"] = conn.get("total_packets", 0) + 1
                    if pkt_type == Packet_Type.STREAM_RESEND:
                        conn["lost_packets"] = conn.get("lost_packets", 0) + 1

            except Exception as e:
                self.logger.debug(
                    f"TX Worker error during packet building/sending: {e}"
                )

    async def _handle_server_response(self, header, data):
        ptype = header["packet_type"]
        stream_id = header.get("stream_id", 0)
        sn = header.get("sequence_num", 0)
        self.logger.debug(
            f"<yellow>[RESP]</yellow> Server sent {ptype} for SID {stream_id} SN {sn}"
        )

        if ptype == Packet_Type.STREAM_SYN_ACK:
            if stream_id in self.pending_streams:
                reader, writer, ptime = self.pending_streams.pop(stream_id)
                from dns_utils.ARQ import ARQStream

                stream = ARQStream(
                    stream_id=stream_id,
                    session_id=self.session_id,
                    enqueue_tx_cb=self._client_enqueue_tx,
                    reader=reader,
                    writer=writer,
                    mtu=self.synced_upload_mtu,
                    logger=self.logger,
                )
                self.active_streams[stream_id] = stream
                self.logger.info(f"Stream {stream_id} Established with server.")

        elif ptype in (Packet_Type.STREAM_DATA, Packet_Type.STREAM_RESEND):
            if stream_id in self.active_streams:
                await self.active_streams[stream_id].receive_data(sn, data)
            else:
                self.logger.debug(
                    f"<yellow>[RESP]</yellow> Data for unknown SID {stream_id}, sending FIN."
                )
                await self._client_enqueue_tx(1, stream_id, 0, b"", is_fin=True)

        elif ptype == Packet_Type.STREAM_DATA_ACK:
            if stream_id in self.active_streams:
                await self.active_streams[stream_id].receive_ack(sn)

        elif ptype == Packet_Type.STREAM_FIN:
            if stream_id in self.active_streams:
                self.logger.info(f"<y>Stream {stream_id} Closed by server.</y>")
                stream = self.active_streams.pop(stream_id, None)
                if stream:
                    await stream.close()

        elif ptype == Packet_Type.ERROR_DROP:
            self.logger.error(
                "<red>Session dropped by server (Server Restarted or Invalid). Reconnecting...</red>"
            )

            if self.session_restart_event:
                self.session_restart_event.set()

    async def _retransmit_worker(self):
        self.logger.debug("<magenta>[RETRANS]</magenta> Retransmit Worker started.")
        SYN_RETRY_INTERVAL = 20.0
        syn_last_sent = {}

        while not self.should_stop.is_set():
            await asyncio.sleep(0.1)

            dead_streams = [sid for sid, s in self.active_streams.items() if s.closed]
            for sid in dead_streams:
                self.active_streams.pop(sid, None)

            dead_pending = []
            now = self.loop.time()

            for sid, stream_data in list(self.pending_streams.items()):
                reader, writer, syn_time = stream_data

                if reader.at_eof() or writer.is_closing():
                    dead_pending.append(sid)
                    continue

                if now - syn_time > 90.0:  # Timeout
                    dead_pending.append(sid)
                    continue

                if now - syn_last_sent.get(sid, 0) > SYN_RETRY_INTERVAL:
                    syn_last_sent[sid] = now
                    await self.outbound_queue.put(
                        (2, self.loop.time(), Packet_Type.STREAM_SYN, sid, 0, b"")
                    )

            for sid in dead_pending:
                self.logger.info(f"Pending Stream {sid} aborted.")
                data = self.pending_streams.pop(sid, None)
                if data:
                    data[1].close()
                await self._client_enqueue_tx(2, sid, 0, b"", is_fin=True)

            for stream in list(self.active_streams.values()):
                await stream.check_retransmits()

    # ---------------------------------------------------------
    # App Lifecycle
    # ---------------------------------------------------------
    async def start(self) -> None:
        try:
            self.loop = asyncio.get_running_loop()
            self.logger.info("=" * 80)
            self.logger.success("<g>Starting MasterDnsVPN Client...</g>")
            if not self.domains or not self.resolvers:
                self.logger.error("Domains or Resolvers are missing in config.")
                return

            while not self.should_stop.is_set():
                self.logger.info("=" * 80)
                self.logger.info("<green>Running MasterDnsVPN Client...</green>")
                self.packets_queue.clear()

                await self.run_client()

                if not self.should_stop.is_set():
                    self.logger.info(
                        "================================================================================"
                    )
                    self.logger.warning(
                        "<yellow>Restarting Client workflow in 2 seconds...</yellow>"
                    )
                    await self._sleep(2)

        except asyncio.CancelledError:
            self.logger.info("MasterDnsVPN Client is stopping...")
        except Exception as e:
            self.logger.error(f"Error in MasterDnsVPN Client: {e}")

    async def _sleep(self, seconds: float) -> None:
        """Async sleep helper."""
        try:
            await asyncio.wait_for(self.should_stop.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            pass

    def _signal_handler(self, signum, frame) -> None:
        """Handle termination signals to stop the client gracefully.

        Only log the received signal the first time to avoid repeated INFO
        messages when multiple console events are received.
        """
        if not self.should_stop.is_set():
            self.logger.info(
                f"Received signal {signum}. Stopping MasterDnsVPN Client..."
            )
            self.should_stop.set()
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.logger.info("MasterDnsVPN Client stopped. Goodbye!")
        else:
            self.logger.info(f"Received signal {signum} again. Already stopping...")
            os._exit(0)


def main():
    client = MasterDnsVPNClient()
    try:
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            loop.add_signal_handler(
                signal.SIGINT, lambda: client._signal_handler(signal.SIGINT, None)
            )
        except Exception:
            try:
                signal.signal(signal.SIGINT, client._signal_handler)
            except Exception:
                pass

        try:
            loop.add_signal_handler(
                signal.SIGTERM, lambda: client._signal_handler(signal.SIGTERM, None)
            )
        except Exception:
            try:
                signal.signal(signal.SIGTERM, client._signal_handler)
            except Exception:
                pass

        # On Windows, register a Console Ctrl Handler early so Ctrl+C is handled
        if sys.platform == "win32":
            try:
                HandlerRoutine = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)

                def _console_handler(dwCtrlType):
                    # CTRL_C_EVENT == 0, CTRL_BREAK_EVENT == 1, others ignored
                    try:
                        client._signal_handler(dwCtrlType, None)
                    except Exception:
                        pass
                    return True

                c_handler = HandlerRoutine(_console_handler)
                ctypes.windll.kernel32.SetConsoleCtrlHandler(c_handler, True)
            except Exception:
                pass

        try:
            loop.run_until_complete(client.start())
        except KeyboardInterrupt:
            try:
                client._signal_handler(signal.SIGINT, None)
            except Exception:
                pass
            print("\nClient stopped by user (Ctrl+C). Goodbye!")
            return
    except KeyboardInterrupt:
        print("\nClient stopped by user (Ctrl+C). Goodbye!")
    except Exception as e:
        print(f"{e}")

    try:
        os._exit(0)
    except Exception as e:
        print(f"Error while stopping the client: {e}")
        exit()


if __name__ == "__main__":
    main()
