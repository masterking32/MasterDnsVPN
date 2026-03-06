# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026


import asyncio
import ctypes
import functools
import os
import random
import signal
import socket
import sys
import time
from ctypes import wintypes
from typing import Optional, Tuple

from dns_utils.ARQ import ARQStream
from dns_utils.DNS_ENUMS import DNS_Record_Type, Packet_Type
from dns_utils.DNSBalancer import DNSBalancer
from dns_utils.DnsPacketParser import DnsPacketParser
from dns_utils.PingManager import PingManager
from dns_utils.utils import (
    async_recvfrom,
    async_sendto,
    generate_random_hex_text,
    getLogger,
)
from dns_utils.config_loader import load_config, get_config_path

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
        self.config: dict = load_config("client_config.toml")
        if not os.path.isfile(get_config_path("client_config.toml")):
            self.logger = getLogger(log_level=self.config.get("LOG_LEVEL", "DEBUG"))
            self.logger.error(
                "Config file '<cyan>client_config.toml</cyan>' not found."
            )
            self.logger.error(
                "Please place it in the same directory as the executable and restart."
            )
            input("Press Enter to exit...")
            sys.exit(1)

        self.logger = getLogger(log_level=self.config.get("LOG_LEVEL", "INFO"))
        self.resolvers: list = self.config.get("RESOLVER_DNS_SERVERS", [])
        self.domains: list = self.config.get("DOMAINS", [])
        self.timeout: float = self.config.get("DNS_QUERY_TIMEOUT", 5.0)
        self.max_upload_mtu: int = self.config.get("MAX_UPLOAD_MTU", 512)
        self.max_download_mtu: int = self.config.get("MAX_DOWNLOAD_MTU", 4096)
        self.min_upload_mtu: int = self.config.get("MIN_UPLOAD_MTU", 0)
        self.min_download_mtu: int = self.config.get("MIN_DOWNLOAD_MTU", 0)
        self.encryption_method: int = self.config.get("DATA_ENCRYPTION_METHOD", 1)

        self.resolver_balancing_strategy: int = self.config.get(
            "RESOLVER_BALANCING_STRATEGY", 0
        )
        self.encryption_key: str = self.config.get("ENCRYPTION_KEY", None)

        if not self.encryption_key:
            self.logger.error(
                "No encryption key provided. "
                "Please set <yellow>ENCRYPTION_KEY</yellow> in <yellow>client_config.toml</yellow>."
            )
            input("Press Enter to exit...")
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
        self.last_stream_id = 0
        self.packet_duplication = self.config.get("PACKET_DUPLICATION_COUNT", 1)
        self.balancer = DNSBalancer(
            resolvers=self.connections_map, strategy=self.resolver_balancing_strategy
        )
        self.ping_manager = PingManager(self._send_ping_packet)
        self._enqueue_seq = 0

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
            await async_sendto(self.loop, sock, query_data, (resolver, port))
            response, _ = await asyncio.wait_for(
                async_recvfrom(self.loop, sock, buffer_size), timeout=timeout
            )
            return response
        except asyncio.TimeoutError:
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

    async def _send_ping_packet(self, payload=None):
        """Unified function to queue PING/PULL packets with lowest priority (4) and max limit (3)."""
        if not hasattr(self, "session_queue") or self.session_queue is None:
            return

        # use queue_meta counts if available to avoid iterating the internal deque
        qmeta = self.queue_meta.get("session") if hasattr(self, "queue_meta") else None
        ping_count = 0
        try:
            if qmeta and isinstance(qmeta.get("counts"), dict):
                ping_count = qmeta["counts"].get(Packet_Type.PING, 0)
            else:
                ping_count = sum(
                    1
                    for item in self.session_queue._queue
                    if len(item) > 3 and item[3] == Packet_Type.PING
                )
        except Exception:
            ping_count = 0

        if ping_count >= 3:
            return

        if payload is None:
            payload = f"P{int(time.time() % 60)}R{random.randint(100, 999)}".encode()

        try:
            self._enqueue_seq = (getattr(self, "_enqueue_seq", 0) + 1) & 0x7FFFFFFF
            self.session_queue.put_nowait(
                (
                    4,
                    self._enqueue_seq,
                    self.loop.time(),
                    Packet_Type.PING,
                    0,
                    0,
                    payload,
                )
            )
            self.tx_event.set()
        except asyncio.QueueFull:
            pass

    async def _process_received_packet(
        self, response_bytes: bytes, addr=None
    ) -> Tuple[Optional[dict], bytes]:
        """
        Parse raw DNS response, extract VPN header, and return packet type alongside assembled data.
        Acts as the core for switching request/response types.
        """
        if not response_bytes:
            return None, b""

        parsed = self.dns_packet_parser.parse_dns_packet(response_bytes)
        if addr and parsed and parsed.get("questions"):
            try:
                qname = parsed["questions"][0].get("qName", "").lower()
                base_domain = next(
                    (d for d in self.domains if qname.endswith(d.lower())), None
                )
                if base_domain:
                    self.balancer.report_success(f"{addr[0]}:{base_domain}")
            except Exception as _:
                pass

        if not parsed or not parsed.get("answers"):
            self.logger.debug(
                "<yellow>[PARSER]</yellow> DNS response contains no answers."
            )
            return None, b""

        chunks = {}
        detected_packet_type = None
        final_parsed_header = None

        for answer in parsed.get("answers", []):
            if answer.get("type") != DNS_Record_Type.TXT:
                continue

            txt_str = self.dns_packet_parser.extract_txt_from_rData(answer["rData"])
            if not txt_str:
                continue

            parts = txt_str.split(".", 2)

            if len(parts) == 3:
                header_str, answer_id_str, chunk_payload = parts[0], parts[1], parts[2]
                header_bytes = self.dns_packet_parser.decode_and_decrypt_data(
                    header_str, lowerCaseOnly=False
                )

                parsed_header = self.dns_packet_parser.parse_vpn_header_bytes(
                    header_bytes
                )
                if parsed_header:
                    packet_type = parsed_header["packet_type"]

                    if detected_packet_type is None:
                        detected_packet_type = packet_type
                        final_parsed_header = parsed_header

                    if packet_type == detected_packet_type:
                        try:
                            chunks[int(answer_id_str)] = chunk_payload
                        except ValueError:
                            pass

            elif len(parts) == 2:
                answer_id_str, chunk_payload = parts[0], parts[1]
                try:
                    chunks[int(answer_id_str)] = chunk_payload
                except ValueError:
                    pass

        if detected_packet_type is None or final_parsed_header is None:
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
        return final_parsed_header, decoded_data

    # ---------------------------------------------------------
    # MTU Testing Logic
    # ---------------------------------------------------------
    async def _binary_search_mtu(
        self,
        test_callable,
        min_mtu: int,
        max_mtu: int,
        min_threshold: int = 30,
        allowed_min_mtu: int = 0,
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
                if mid < min_threshold or mid < allowed_min_mtu:
                    break

                ok = False

                for _ in range(2):
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
        dns_queries = self.dns_packet_parser.build_request_dns_query(
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
            dns_queries[0], dns_server, dns_port, 1
        )

        parsed_header, _ = await self._process_received_packet(response)
        packet_type = parsed_header["packet_type"] if parsed_header else None

        if packet_type == Packet_Type.MTU_UP_RES:
            self.logger.success(
                f"<green>Upload Test Success: <yellow>{mtu_size}</yellow> via <cyan>{dns_server}</cyan> for <cyan>{domain}</cyan></green>"
            )
            return True
        elif packet_type == Packet_Type.ERROR_DROP:
            self.logger.warning(
                f"<yellow>Upload Test Dropped (Server MTU Limit): <yellow>{mtu_size}</yellow> via <cyan>{dns_server}</cyan> for <cyan>{domain}</cyan></yellow>"
            )
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

        dns_queries = self.dns_packet_parser.build_request_dns_query(
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
            dns_queries[0], dns_server, dns_port, 1
        )
        parsed_header, returned_data = await self._process_received_packet(response)
        packet_type = parsed_header["packet_type"] if parsed_header else None

        if packet_type == Packet_Type.MTU_DOWN_RES:
            if returned_data and len(returned_data) == mtu_size:
                self.logger.success(
                    f"<green>Download Test Success: <yellow>{mtu_size}</yellow> via <cyan>{dns_server}</cyan> for <cyan>{domain}</cyan></green>"
                )
                return True
            else:
                self.logger.warning(
                    f"<yellow>Download Test Failed (Data Mismatch): <yellow>{mtu_size}</yellow> via <cyan>{dns_server}</cyan> for <cyan>{domain}</cyan></yellow>"
                )
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
            actual_max_allowed = min(default_mtu if default_mtu > 0 else 512, mtu_bytes)
            optimal_mtu = await self._binary_search_mtu(
                test_fn,
                0,
                actual_max_allowed,
                min_threshold=30,
                allowed_min_mtu=self.min_upload_mtu,
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
                test_fn,
                0,
                default_mtu,
                min_threshold=30,
                allowed_min_mtu=self.min_download_mtu,
            )

            if optimal_mtu >= max(30, self.min_download_mtu):
                return True, optimal_mtu
        except Exception as e:
            self.logger.debug(f"Error calculating download MTU for {domain}: {e}")
        return False, 0

    async def test_mtu_sizes(self) -> bool:
        self.logger.info("=" * 80)
        self.logger.info("<y>Testing MTU sizes for all resolver-domain pairs...</y>")

        server_id = 0
        total_conns = len(self.connections_map)
        for connection in self.connections_map:
            if not connection or self.should_stop.is_set():
                continue
            server_id += 1
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
                    f"<red>❌ Connection invalid for <yellow>{domain}</yellow> via <yellow>{resolver}</yellow>: Upload MTU failed. <yellow>({server_id}/{total_conns})</yellow></red>"
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
                    f"<red>❌ Connection invalid for <yellow>{domain}</yellow> via <yellow>{resolver}</yellow>: Download MTU failed. <yellow>({server_id}/{total_conns})</yellow></red>"
                )
                continue

            # Marking as Valid
            connection["is_valid"] = True
            connection["upload_mtu_bytes"] = up_mtu_bytes
            connection["upload_mtu_chars"] = up_mtu_char
            connection["download_mtu_bytes"] = down_mtu_bytes
            connection["packet_loss"] = 0

            self.logger.info(
                f"<cyan>✅ Valid: {domain} via <green>{resolver}</green> | "
                f"Upload MTU: <red>{up_mtu_bytes}</red> | Download MTU: <red>{down_mtu_bytes}</red> <yellow>({server_id}/{total_conns})</yellow></cyan>"
            )

        valid_conns = [c for c in self.connections_map if c.get("is_valid")]
        if not valid_conns:
            self.logger.error(
                "<red>No valid connections found after MTU testing!</red>"
            )
            return False

        return True

    async def _sync_mtu_with_server(self, max_attempts=10) -> bool:
        """Send the synced MTU values to the server for this session."""
        self.logger.info(f"Syncing MTU with server for session {self.session_id}...")

        if self.should_stop.is_set() or max_attempts <= 0:
            return False

        selected_conn = self.balancer.get_best_server()
        if not selected_conn:
            return False

        domain = selected_conn.get("domain")
        resolver = selected_conn.get("resolver")

        # Pack MTUs into 8 bytes (4 bytes UP, 4 bytes DOWN)
        # Generate a random sync token
        sync_token = (generate_random_hex_text(8) + str(int(time.time()))).encode()

        # Pack MTUs into 8 bytes (4 bytes UP, 4 bytes DOWN) + Sync Token
        data_bytes = (
            self.synced_upload_mtu.to_bytes(4, byteorder="big")
            + self.synced_download_mtu.to_bytes(4, byteorder="big")
            + sync_token
        )

        # Encrypt the payload before sending
        encrypted_data = self.dns_packet_parser.codec_transform(
            data_bytes, encrypt=True
        )

        dns_queries = self.dns_packet_parser.build_request_dns_query(
            domain=domain,
            session_id=self.session_id,
            packet_type=Packet_Type.SET_MTU_REQ,
            data=encrypted_data,
            mtu_chars=self.synced_upload_mtu_chars,
            encode_data=True,
            qType=DNS_Record_Type.TXT,
        )

        if not dns_queries:
            self.logger.error(
                f"Failed to sync MTU with server via {resolver} for {domain}, Retrying..."
            )
            await self._sleep(0.2)
            return False

        max_retries = 3
        # base_delay = 1.0

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
                    # Validate the returned token
                    if returned_data == sync_token:
                        self.logger.success(
                            "<g>MTU values successfully synced with the server!</g>"
                        )
                        return True
                    else:
                        self.logger.warning(
                            "MTU Sync token mismatch! Ignoring response."
                        )

            if attempt < max_retries - 1:
                # delay = min(base_delay * (1.5**attempt), 8.0)
                delay = 0.5
                self.logger.warning(
                    f"MTU sync failed via {resolver} for {domain}. Retrying in {delay:.1f}s (Attempt {attempt + 1}/{max_retries})..."
                )
                await asyncio.sleep(delay)

        self.logger.error(
            f"Failed to build MTU sync via {resolver} for {domain}, Retrying..."
        )

        await self._sleep(0.2)
        return await self._sync_mtu_with_server(max_attempts - 1)

    # ---------------------------------------------------------
    # Core Loop & Session Setup
    # ---------------------------------------------------------
    async def _init_session(self, max_attempts=10) -> bool:
        """Initialize a new session with the server."""
        self.logger.info("Initializing session ...")

        if self.should_stop.is_set() or max_attempts <= 0:
            return False

        selected_conn = self.balancer.get_best_server()
        if not selected_conn:
            return False

        domain = selected_conn.get("domain")
        resolver = selected_conn.get("resolver")
        init_token = (generate_random_hex_text(8) + str(int(time.time()))).encode()
        encrypted_token = self.dns_packet_parser.codec_transform(
            init_token, encrypt=True
        )

        dns_queries = self.dns_packet_parser.build_request_dns_query(
            domain=domain,
            session_id=0,
            packet_type=Packet_Type.SESSION_INIT,
            data=encrypted_token,
            mtu_chars=self.synced_upload_mtu_chars,
            encode_data=True,
            qType=DNS_Record_Type.TXT,
        )

        if not dns_queries:
            self.logger.error(
                f"Failed to build session init DNS query via {resolver} for {domain}, Retrying..."
            )
            await self._sleep(0.2)
            return False

        max_retries = 3
        # base_delay = 1.0

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

                if (
                    parsed_header
                    and parsed_header["packet_type"] == Packet_Type.SESSION_ACCEPT
                ):
                    try:
                        decoded_str = returned_data.decode("utf-8")
                        if ":" in decoded_str:
                            received_token, received_sid = decoded_str.split(":", 1)
                            if received_token == init_token.decode():
                                self.session_id = int(received_sid)
                                self.logger.success(
                                    f"<g>Validated Session ID: {self.session_id}</g>"
                                )
                                return True
                            else:
                                self.logger.warning(
                                    "Token mismatch! Ignoring old session response."
                                )
                    except Exception as e:
                        self.logger.error(f"Session parse error: {e}")

            if attempt < max_retries - 1:
                # delay = min(base_delay * (1.5**attempt), 8.0)
                delay = 0.5
                self.logger.warning(
                    f"Session init failed via {resolver} for {domain}. Retrying in {delay:.1f}s (Attempt {attempt + 1}/{max_retries})..."
                )
                await asyncio.sleep(delay)

        self.logger.error(
            f"Failed to build session init DNS query via {resolver} for {domain}, Retrying..."
        )

        await self._sleep(0.2)
        return await self._init_session(max_attempts - 1)

    async def run_client(self) -> None:
        """Run the MasterDnsVPN Client main logic."""
        self.logger.info("Setting up connections...")
        all_resolvers = 0
        try:
            self.session_restart_event = asyncio.Event()
            if not self.success_mtu_checks or len(self.connections_map) <= 0:
                await self.create_connection_map()
                all_resolvers = len(self.connections_map)

                if not await self.test_mtu_sizes():
                    self.logger.error("No valid servers found to connect.")
                    return

                valid_conns = [c for c in self.connections_map if c.get("is_valid")]

                if not valid_conns:
                    self.logger.error("No valid connections found after MTU testing!")
                    return

                if len(valid_conns) <= 0:
                    self.logger.error(
                        "No valid connections available after MTU testing!"
                    )
                    return

                self.balancer.set_balancers(valid_conns)

                self.synced_upload_mtu = min(c["upload_mtu_bytes"] for c in valid_conns)
                self.synced_upload_mtu_chars = min(
                    c["upload_mtu_chars"] for c in valid_conns
                )
                self.synced_download_mtu = min(
                    c["download_mtu_bytes"] for c in valid_conns
                )

                max_founded_upload_mtu = max(c["upload_mtu_bytes"] for c in valid_conns)
                max_founded_download_mtu = max(
                    c["download_mtu_bytes"] for c in valid_conns
                )

                self.logger.success("<green>MTU Testing Completed!</green>")
                self.logger.info("=" * 80)
                self.logger.success(
                    f"Total valid resolvers after MTU testing: <cyan>{len(self.balancer.valid_servers)}</cyan> of <cyan>{all_resolvers}</cyan>"
                )

                self.logger.info("=" * 80)
                self.logger.info(
                    f"<cyan>[MTU RESULTS]</cyan> Max Upload MTU found: <yellow>{max_founded_upload_mtu}</yellow> | Max Download MTU found: <yellow>{max_founded_download_mtu}</yellow>"
                )
                self.logger.info(
                    f"<cyan>[MTU RESULTS]</cyan> Selected Synced Upload MTU: <yellow>{self.synced_upload_mtu}</yellow> | Selected Synced Download MTU: <yellow>{self.synced_download_mtu}</yellow>"
                )

                self.logger.info(
                    "<cyan>[EXPLANATION]</cyan> Max MTU values represent the best performance potential across all valid resolvers, while synced MTU values ensure compatibility with all resolvers by using the lowest common denominator."
                )
                self.logger.info(
                    "<cyan>[EXPLANATION]</cyan> Synced MTU = minimum MTU across all valid resolvers (ensures compatibility with all)"
                )

                self.logger.warning(
                    "<yellow>[OPTION 1 - RECOMMENDED]</yellow> <cyan>For Maximum Performance:</cyan>"
                )
                self.logger.warning(
                    f"<yellow>  • Set <cyan>MIN_UPLOAD_MTU</cyan> and <cyan>MAX_UPLOAD_MTU</cyan> = <green>{max_founded_upload_mtu}</green></yellow>"
                )
                self.logger.warning(
                    f"<yellow>  • Set <cyan>MIN_DOWNLOAD_MTU</cyan> and <cyan>MAX_DOWNLOAD_MTU</cyan> = <green>{max_founded_download_mtu}</green></yellow>"
                )
                self.logger.warning(
                    "<yellow>  • Effect: Skips binary search, tests only with maximum MTU size directly</yellow>"
                )
                self.logger.warning(
                    "<yellow>  • Trade-off: May exclude slower resolvers, but better performance on compatible ones</yellow>"
                )
                self.logger.warning(
                    "<yellow>  • Best for: Users with many resolvers or prioritizing speed over compatibility</yellow>"
                )

                self.logger.warning(
                    "<yellow>[OPTION 2 - BALANCED]</yellow> <cyan>For Compatibility:</cyan>"
                )
                self.logger.warning(
                    f"<yellow>  • Set <cyan>MIN_UPLOAD_MTU</cyan> = <green>{self.synced_upload_mtu}</green> | <cyan>MAX_UPLOAD_MTU</cyan> = <green>{max_founded_upload_mtu}</green></yellow>"
                )
                self.logger.warning(
                    f"<yellow>  • Set <cyan>MIN_DOWNLOAD_MTU</cyan> = <green>{self.synced_download_mtu}</green> | <cyan>MAX_DOWNLOAD_MTU</cyan> = <green>{max_founded_download_mtu}</green></yellow>"
                )
                self.logger.warning(
                    "<yellow>  • Effect: Tests MTU sizes between synced and maximum values</yellow>"
                )
                self.logger.warning(
                    "<yellow>  • Trade-off: Keeps all valid resolvers but uses lower MTU (less performance than Option 1)</yellow>"
                )
                self.logger.warning(
                    "<yellow>  • Best for: Users wanting to keep all resolvers while improving test speed</yellow>"
                )

                self.logger.info("=" * 80)
                self.logger.info(
                    f"<green>Global MTU Configuration -> Upload: <cyan>{self.synced_upload_mtu}B</cyan>, Download: <cyan>{self.synced_download_mtu}B</cyan></green>"
                )
                self.success_mtu_checks = True

            selected_conn = self.balancer.get_best_server()
            if not selected_conn:
                return

            if not await self._init_session():
                self.logger.error("Failed to initialize session with the server.")
                return

            self.logger.success(
                f"<green>Session Established! Session ID: <cyan>{self.session_id}</cyan></green>"
            )

            if not await self._sync_mtu_with_server():
                self.logger.error("Failed to sync MTU with the server.")
                return

            await self._main_tunnel_loop()
        except Exception as e:
            self.logger.error(f"Error setting up connections: {e}")
            return

    # ---------------------------------------------------------
    # TCP Multiplexing Logic & Handlers
    # ---------------------------------------------------------
    async def _main_tunnel_loop(self):
        """Start local TCP server and main worker tasks."""
        self.logger.info("Entering VPN Tunnel Main Loop...")
        self.session_restart_event = asyncio.Event()
        self.session_queue = asyncio.PriorityQueue()
        # queue_meta maps queue_key -> {"types": set(), "acks": set(), "resends": set()}
        self.queue_meta = {}
        self.stream_queues = {}
        self.round_robin_index = 0
        self.tx_event = asyncio.Event()
        self.active_streams = {}
        self.pending_resends = set()
        self.canceled_streams = set()

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
            if sys.platform == "win32":
                server = await asyncio.start_server(
                    self._handle_local_tcp_connection,
                    listen_ip,
                    listen_port,
                    reuse_address=True,
                )
            else:
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

            for w in getattr(self, "workers", []):
                if not w.done():
                    w.cancel()

            if hasattr(self, "workers") and self.workers:
                await asyncio.gather(*self.workers, return_exceptions=True)

            if server:
                try:
                    server.close()
                    await asyncio.wait_for(server.wait_closed(), timeout=1.0)
                except Exception:
                    pass

            close_tasks = []
            for sid in list(self.active_streams.keys()):
                close_tasks.append(self.close_stream(sid, reason="Client App Closing"))

            if close_tasks:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*close_tasks, return_exceptions=True),
                        timeout=1.5,
                    )
                except Exception:
                    pass

            self.active_streams.clear()

            if hasattr(self, "tunnel_sock") and self.tunnel_sock:
                try:
                    self.tunnel_sock.close()
                except Exception:
                    pass

            if hasattr(self, "session_queue"):
                while not self.session_queue.empty():
                    try:
                        self.session_queue.get_nowait()
                    except Exception:
                        break
                # clear session queue meta
                try:
                    self.queue_meta.pop("session", None)
                except Exception:
                    pass
            if hasattr(self, "stream_queues"):
                for sq in self.stream_queues.values():
                    while not sq.empty():
                        try:
                            sq.get_nowait()
                        except Exception:
                            break
                self.stream_queues.clear()
                # clear stream-related queue meta
                try:
                    keys = [
                        k
                        for k in list(self.queue_meta.keys())
                        if k.startswith("stream:")
                    ]
                    for k in keys:
                        self.queue_meta.pop(k, None)
                except Exception:
                    pass

        if not stop_task.done():
            stop_task.cancel()
        if not restart_task.done():
            restart_task.cancel()

        self.logger.info("Cleaning up old connections before reconnecting...")
        self.active_streams.clear()

    async def _rx_worker(self):
        """Continuously listen for incoming VPN packets on the tunnel socket."""
        self.logger.debug("<magenta>[RX]</magenta> RX Worker started.")
        while not self.should_stop.is_set() and not self.session_restart_event.is_set():
            try:
                data, addr = await asyncio.wait_for(
                    async_recvfrom(self.loop, self.tunnel_sock, 65536), timeout=1.0
                )
                self.loop.create_task(self._process_and_route_incoming(data, addr))

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.debug(f"RX Worker error: {e}")

    async def _process_and_route_incoming(self, data, addr):
        """Helper to process incoming data asynchronously."""
        parsed_header, returned_data = await self._process_received_packet(data, addr)
        if parsed_header:
            await self._handle_server_response(parsed_header, returned_data)

    async def _close_writer_safely(self, writer):
        """Safely close the writer connection"""
        try:
            if writer and not writer.is_closing():
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
        except Exception:
            pass

    def _new_get_stream_id(self):
        start = (self.last_stream_id + 1) or 1
        stream_id = start
        wrapped = False

        while not self.should_stop.is_set() and not self.session_restart_event.is_set():
            if stream_id > 65535:
                if wrapped:
                    return False, 0
                stream_id = 1
                wrapped = True

            if stream_id not in self.active_streams:
                self.last_stream_id = stream_id
                if hasattr(self, "canceled_streams"):
                    self.canceled_streams.discard(stream_id)
                return True, stream_id

            stream_id += 1

        return False, 0

    async def _handle_local_tcp_connection(self, reader, writer):
        if self.should_stop.is_set() or (
            self.session_restart_event and self.session_restart_event.is_set()
        ):
            await self._close_writer_safely(writer)
            return

        stream_id_status, stream_id = self._new_get_stream_id()
        if not stream_id_status:
            self.logger.error("No available Stream IDs! Too many connections.")
            await self._close_writer_safely(writer)
            return

        self.logger.info(f"New local connection, assigning Stream ID: {stream_id}")

        now = self.loop.time()
        try:
            syn_data = (
                f"PONG:{int(time.time()) % 10000}:{random.randint(1000, 9999)}".encode()
            )
            target_queue = self.stream_queues.setdefault(
                stream_id, asyncio.PriorityQueue()
            )
            target_queue.put_nowait(
                (0, 0, now, Packet_Type.STREAM_SYN, stream_id, 0, syn_data)
            )
            self.tx_event.set()
        except asyncio.QueueFull:
            self.logger.debug("Queue is full, dropping new connection.")
            await self._close_writer_safely(writer)
            return

        self.active_streams[stream_id] = {
            "reader": reader,
            "writer": writer,
            "create_time": now,
            "last_activity_time": now,
            "status": "PENDING",
            "stream": None,
        }

    async def _clear_stream_from_queue(self, stream_id: int):
        """Marks a stream as canceled so the TX worker skips its packets instantly."""
        if hasattr(self, "canceled_streams"):
            self.canceled_streams.add(stream_id)
            self.logger.debug(
                f"Stream {stream_id} marked as canceled. TX worker will skip its pending packets."
            )

        # remove any queue_meta for this stream
        try:
            self.queue_meta.pop(f"stream:{stream_id}", None)
        except Exception:
            pass

        if hasattr(self, "pending_resends"):
            to_remove = [item for item in self.pending_resends if item[0] == stream_id]
            for item in to_remove:
                self.pending_resends.discard(item)

    async def _client_enqueue_tx(
        self, priority, stream_id, sn, data, is_ack=False, is_fin=False, is_resend=False
    ):
        if self.should_stop.is_set() or (
            self.session_restart_event and self.session_restart_event.is_set()
        ):
            return

        ptype = Packet_Type.STREAM_DATA
        effective_priority = priority

        if is_ack:
            ptype = Packet_Type.STREAM_DATA_ACK
            effective_priority = 0
        elif is_fin:
            ptype = Packet_Type.STREAM_FIN
            effective_priority = 0
        elif is_resend:
            ptype = Packet_Type.STREAM_RESEND
            effective_priority = 1

        if is_resend:
            resend_key = (stream_id, sn)
            if resend_key in self.pending_resends:
                return
            self.pending_resends.add(resend_key)

        if stream_id == 0:
            target_queue = self.session_queue
        else:
            target_queue = self.stream_queues.setdefault(
                stream_id, asyncio.PriorityQueue()
            )

        # maintain lightweight queue metadata to avoid scanning internal deque
        qkey = "session" if stream_id == 0 else f"stream:{stream_id}"
        qm = self.queue_meta.setdefault(
            qkey, {"types": set(), "acks": set(), "resends": set(), "counts": {}}
        )

        if is_resend:
            # already handled above by pending_resends
            pass

        if ptype in (
            Packet_Type.STREAM_FIN,
            Packet_Type.STREAM_SYN,
            Packet_Type.STREAM_SYN_ACK,
        ):
            if ptype in qm["types"]:
                return
        elif ptype == Packet_Type.STREAM_DATA_ACK:
            if (ptype, sn) in qm["acks"]:
                return

        try:
            self._enqueue_seq = (getattr(self, "_enqueue_seq", 0) + 1) & 0x7FFFFFFF
            target_queue.put_nowait(
                (
                    effective_priority,
                    self._enqueue_seq,
                    self.loop.time(),
                    ptype,
                    stream_id,
                    sn,
                    data,
                )
            )
            self.tx_event.set()
        except asyncio.QueueFull:
            pass
        # update meta after enqueue
        if ptype in (
            Packet_Type.STREAM_FIN,
            Packet_Type.STREAM_SYN,
            Packet_Type.STREAM_SYN_ACK,
        ):
            qm["types"].add(ptype)
        if ptype == Packet_Type.STREAM_DATA_ACK:
            qm["acks"].add((ptype, sn))
        if is_resend:
            qm["resends"].add((stream_id, sn))
        # increment counts
        try:
            qm["counts"][ptype] = qm["counts"].get(ptype, 0) + 1
        except Exception:
            pass

    async def _tx_worker(self):
        self.logger.debug("<magenta>[TX]</magenta> TX Worker started.")
        while not self.should_stop.is_set() and not self.session_restart_event.is_set():
            try:
                await asyncio.wait_for(self.tx_event.wait(), timeout=0.2)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"TX wait error: {e}")
                continue

            item = None

            canceled_streams = getattr(self, "canceled_streams", set())

            for sid in list(self.stream_queues.keys()):
                if self.stream_queues[sid].empty() and sid in canceled_streams:
                    del self.stream_queues[sid]
                    canceled_streams.discard(sid)

            to_remove_canceled = [
                sid for sid in canceled_streams if sid not in self.stream_queues
            ]
            for sid in to_remove_canceled:
                canceled_streams.discard(sid)

            active_streams = [
                sid for sid, q in self.stream_queues.items() if not q.empty()
            ]

            if active_streams:
                if self.round_robin_index >= len(active_streams):
                    self.round_robin_index = 0

                selected_sid = active_streams[self.round_robin_index]
                target_queue = self.stream_queues[selected_sid]
                self.round_robin_index = (self.round_robin_index + 1) % len(
                    active_streams
                )

                try:
                    item = target_queue.get_nowait()
                    # remove queue meta for this dequeued item
                    try:
                        qkey = f"stream:{selected_sid}"
                        qmeta = self.queue_meta.get(qkey)
                        if qmeta:
                            q_ptype = item[3]
                            q_sn = item[5]
                            if q_ptype in (
                                Packet_Type.STREAM_FIN,
                                Packet_Type.STREAM_SYN,
                                Packet_Type.STREAM_SYN_ACK,
                            ):
                                qmeta["types"].discard(q_ptype)
                            if q_ptype == Packet_Type.STREAM_DATA_ACK:
                                qmeta["acks"].discard((q_ptype, q_sn))
                            if q_ptype == Packet_Type.STREAM_RESEND:
                                qmeta["resends"].discard((item[4], q_sn))
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
                except Exception:
                    pass

            elif not self.session_queue.empty():
                try:
                    item = self.session_queue.get_nowait()
                    # update session queue meta
                    try:
                        qmeta = self.queue_meta.get("session")
                        if qmeta:
                            q_ptype = item[3]
                            q_sn = item[5]
                            if q_ptype in (
                                Packet_Type.STREAM_FIN,
                                Packet_Type.STREAM_SYN,
                                Packet_Type.STREAM_SYN_ACK,
                            ):
                                qmeta["types"].discard(q_ptype)
                            if q_ptype == Packet_Type.STREAM_DATA_ACK:
                                qmeta["acks"].discard((q_ptype, q_sn))
                            if q_ptype == Packet_Type.STREAM_RESEND:
                                qmeta["resends"].discard((item[4], q_sn))
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
                except Exception:
                    pass

            else:
                self.tx_event.clear()
                continue

            if not item:
                continue

            try:
                q_ptype, q_stream_id, q_sn = item[3], item[4], item[5]

                if q_ptype == Packet_Type.STREAM_RESEND:
                    getattr(self, "pending_resends", set()).discard((q_stream_id, q_sn))

                if q_stream_id in getattr(
                    self, "canceled_streams", set()
                ) and q_ptype not in (Packet_Type.STREAM_FIN, Packet_Type.STREAM_SYN):
                    continue

                if q_ptype in (Packet_Type.STREAM_DATA, Packet_Type.STREAM_RESEND):
                    stream_data = self.active_streams.get(q_stream_id)
                    if stream_data and "stream" in stream_data:
                        arq = stream_data["stream"]
                        if arq and q_sn not in arq.snd_buf:
                            continue

                await self._send_single_packet(item)
            except Exception as e:
                self.logger.error(f"TX Error: {e}")

    async def _send_single_packet(self, item):
        self.ping_manager.active_connections = len(self.active_streams)

        priority, rr_count, _, pkt_type, stream_id, sn, data = item

        self.ping_manager.update_activity()

        if stream_id in self.active_streams:
            now = self.loop.time()
            self.active_streams[stream_id]["last_activity_time"] = now

        try:
            data_encrypted = (
                self.dns_packet_parser.codec_transform(data, encrypt=True)
                if data
                else b""
            )

            target_conns = self.balancer.get_unique_servers(self.packet_duplication)

            for conn in target_conns:
                self.balancer.report_send(f"{conn['resolver']}:{conn['domain']}")
                query_packets = self.dns_packet_parser.build_request_dns_query(
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

                if not query_packets:
                    return

                for query_packet in query_packets:
                    try:
                        await async_sendto(
                            self.loop,
                            self.tunnel_sock,
                            query_packet,
                            (conn["resolver"], 53),
                        )
                    except Exception as e:
                        self.logger.debug(
                            f"Failed async_sendto to {conn['resolver']}: {e}"
                        )
                        try:
                            await asyncio.sleep(0.001)
                        except Exception:
                            pass
        except Exception as e:
            self.logger.debug(f"TX Worker error during packet building/sending: {e}")

    async def _handle_server_response(self, header, data):
        ptype = header["packet_type"]
        stream_id = header.get("stream_id", 0)
        sn = header.get("sequence_num", 0)
        self.logger.debug(
            f"<yellow>[RESP]</yellow> Server sent {ptype} for SID {stream_id} SN {sn}"
        )

        stream_id_exists = False
        if stream_id > 0 and stream_id in self.active_streams:
            stream_id_exists = True
            self.active_streams[stream_id]["last_activity_time"] = self.loop.time()

        if ptype == Packet_Type.STREAM_SYN_ACK and stream_id_exists:
            if (
                self.active_streams[stream_id].get("stream")
                or self.active_streams[stream_id].get("status") == "ACTIVE"
            ):
                return

            if self.active_streams[stream_id].get("stream_creating"):
                self.logger.debug(
                    f"Stream {stream_id} creation in progress; ignoring duplicate SYN_ACK."
                )
                return

            writer = self.active_streams[stream_id].get("writer")
            if not writer or writer.is_closing():
                self.logger.debug(
                    f"Stream {stream_id} local connection closed before SYN_ACK. Cleaning up."
                )
                self.active_streams.pop(stream_id, None)

            self.active_streams[stream_id]["stream_creating"] = True

            try:
                self.active_streams[stream_id]["status"] = "ACTIVE"
                reader = self.active_streams[stream_id]["reader"]
                writer = self.active_streams[stream_id]["writer"]

                crypto_overhead = 0
                if self.encryption_method == 2:
                    crypto_overhead = 16
                elif self.encryption_method in (3, 4, 5):
                    crypto_overhead = 28

                safe_uplink_mtu = max(
                    64, self.synced_upload_mtu - crypto_overhead - 8 - 16
                )

                stream = ARQStream(
                    stream_id=stream_id,
                    session_id=self.session_id,
                    enqueue_tx_cb=self._client_enqueue_tx,
                    reader=reader,
                    writer=writer,
                    mtu=safe_uplink_mtu,
                    logger=self.logger,
                    window_size=self.config.get("ARQ_WINDOW_SIZE", 600),
                )

                self.active_streams[stream_id]["stream"] = stream
                self.logger.info(f"Stream {stream_id} Established with server.")
            finally:
                self.active_streams[stream_id].pop("stream_creating", None)
        elif (
            ptype in (Packet_Type.STREAM_DATA, Packet_Type.STREAM_RESEND)
            and stream_id_exists
            and data
        ):
            stream_obj = self.active_streams[stream_id].get("stream")
            if stream_obj:
                await stream_obj.receive_data(sn, data)
            # else:
            #     self.logger.debug(f"Got data for SID {stream_id} but stream not ready.")

            pull_count = 2
            for _ in range(pull_count):
                await self._send_ping_packet()

        elif ptype == Packet_Type.STREAM_DATA_ACK and stream_id_exists:
            stream_obj = self.active_streams[stream_id].get("stream")
            if stream_obj:
                await stream_obj.receive_ack(sn)
            # else:
            #     self.logger.debug(f"Got ACK for SID {stream_id} but stream not ready.")

            pull_count = 2
            for _ in range(pull_count):
                await self._send_ping_packet()

        elif ptype == Packet_Type.STREAM_FIN and stream_id_exists:
            await self.close_stream(stream_id, reason="Server sent FIN")

        elif ptype == Packet_Type.ERROR_DROP:
            if not self.session_restart_event.is_set():
                self.logger.error(
                    "<red>Session dropped by server (Server Restarted or Invalid). Reconnecting...</red>"
                )
                self.session_restart_event.set()

    async def close_stream(self, stream_id: int, reason: str = "Unknown") -> None:
        """Safely and fully close a specific local stream."""
        if stream_id not in self.active_streams:
            return

        self.logger.info(f"<y>Closing Client Stream {stream_id}. Reason: {reason}</y>")
        stream_data = self.active_streams.pop(stream_id)

        await self._clear_stream_from_queue(stream_id)

        stream_obj = stream_data.get("stream")
        if stream_obj:
            await stream_obj.close(reason=reason)
        else:
            fin_data = (
                f"FIN:{int(time.time()) % 10000}:{random.randint(1000, 9999)}".encode()
            )
            await self._client_enqueue_tx(1, stream_id, 0, fin_data, is_fin=True)

        writer = stream_data.get("writer")
        await self._close_writer_safely(writer)

    async def _retransmit_worker(self):
        self.logger.debug("<magenta>[RETRANS]</magenta> Retransmit Worker started.")
        while not self.should_stop.is_set() and not self.session_restart_event.is_set():
            await asyncio.sleep(0.5)

            dead_streams = [
                sid
                for sid, s in self.active_streams.items()
                if "stream" in s
                and (
                    (
                        s["stream"] is not None
                        and getattr(s["stream"], "closed", False)
                        and s.get("status") == "ACTIVE"
                    )
                    or (
                        s.get("status") == "PENDING"
                        and self.loop.time() - s.get("create_time", 0) > 350.0
                    )
                )
            ]

            for sid in dead_streams:
                s = self.active_streams.get(sid, {})
                if (
                    s.get("status") == "PENDING"
                    and self.loop.time() - s.get("create_time", 0) > 350.0
                ):
                    reason = "Handshake timeout (No SYN_ACK from server)"
                else:
                    arq = s.get("stream")
                    reason = getattr(
                        arq, "close_reason", "Closed locally or Inactivity Timeout"
                    )

                await self.close_stream(sid, reason=reason)

            for s in list(self.active_streams.values()):
                arq = s.get("stream")
                if arq and hasattr(arq, "check_retransmits"):
                    try:
                        await arq.check_retransmits()
                    except Exception as _:
                        pass

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

            self.success_mtu_checks = False
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
