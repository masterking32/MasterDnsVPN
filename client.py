# MasterDnsVPN Client
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import asyncio
import ctypes
import heapq
import os
import signal
import socket
import struct
import sys
import time
from ctypes import wintypes
from typing import Optional, Tuple

from dns_utils import ARQ, PrependReader
from dns_utils.config_loader import get_config_path, load_config
from dns_utils.DNS_ENUMS import DNS_Record_Type, Packet_Type
from dns_utils import DNSBalancer
from dns_utils import DnsPacketParser
from dns_utils import PingManager
from dns_utils.utils import (
    async_recvfrom,
    async_sendto,
    generate_random_hex_text,
    getLogger,
)

# Ensure UTF-8 output for consistent logging
try:
    if sys.stdout.encoding is not None and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


class MasterDnsVPNClient:
    """MasterDnsVPN Client class to handle DNS requests over UDP."""

    def __init__(self) -> None:
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
        self.max_download_mtu: int = self.config.get("MAX_DOWNLOAD_MTU", 1200)
        self.min_upload_mtu: int = self.config.get("MIN_UPLOAD_MTU", 0)
        self.min_download_mtu: int = self.config.get("MIN_DOWNLOAD_MTU", 0)

        self.mtu_test_retries: int = self.config.get("MTU_TEST_RETRIES", 2)
        self.mtu_test_timeout: float = float(self.config.get("MTU_TEST_TIMEOUT", 1.0))

        self.encryption_method: int = self.config.get("DATA_ENCRYPTION_METHOD", 1)

        self.protocol_type: str = self.config.get("PROTOCOL_TYPE", "SOCKS5").upper()
        self.socks5_auth: bool = self.config.get("SOCKS5_AUTH", False)
        self.socks5_user: str = str(self.config.get("SOCKS5_USER", ""))
        self.socks5_pass: str = str(self.config.get("SOCKS5_PASS", ""))

        if self.protocol_type not in ("SOCKS5", "TCP"):
            self.logger.error(
                f"Invalid PROTOCOL_TYPE '{self.protocol_type}' in config. Must be 'SOCKS5' or 'TCP'."
            )
            input("Press Enter to exit...")
            sys.exit(1)

        self.crypto_overhead = 0
        if self.encryption_method == 2:
            self.crypto_overhead = 16
        elif self.encryption_method in (3, 4, 5):
            self.crypto_overhead = 28

        self.success_mtu_checks: bool = False
        self.max_packed_blocks: int = 1
        self.max_packets_per_batch: int = self.config.get("MAX_PACKETS_PER_BATCH", 3)

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

        self.connections_map: list = []
        self.session_id = 0
        self.synced_upload_mtu = 0
        self.synced_upload_mtu_chars = 0
        self.synced_download_mtu = 0
        self.buffer_size = 65507  # Max UDP payload size
        self.balancer = DNSBalancer(
            resolvers=self.connections_map, strategy=self.resolver_balancing_strategy
        )
        self.ping_manager = PingManager(self._send_ping_packet)
        self.packet_duplication_count = self.config.get("PACKET_DUPLICATION_COUNT", 1)
        self.rx_tasks = set()
        self.domains: list = self.config.get("DOMAINS", [])
        self.domains_lower: tuple = tuple(d.lower() for d in self.domains)
        self.main_queue = []
        self.tx_event = asyncio.Event()
        self.rx_semaphore = asyncio.Semaphore(200)

        self.logger.debug("<magenta>[INIT]</magenta> MasterDnsVPNClient initialized.")

    # ---------------------------------------------------------
    # Connection Management
    # ---------------------------------------------------------
    async def create_connection_map(self) -> None:
        """Create a map of all domain-resolver combinations."""
        unique_domains = set(self.domains)
        unique_resolvers = set(self.resolvers)
        unique_domains.discard("")
        unique_resolvers.discard("")
        unique_domains = list(set(d.lower() for d in unique_domains))
        unique_resolvers = list(unique_resolvers)

        self.connections_map = [
            {"domain": domain, "resolver": resolver}
            for domain in unique_domains
            for resolver in unique_resolvers
        ]

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
        buf_size = buffer_size or self.buffer_size

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)

        try:
            await async_sendto(self.loop, sock, query_data, (resolver, port))
            response, _ = await asyncio.wait_for(
                async_recvfrom(self.loop, sock, buf_size), timeout=timeout
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
            sock.close()

    def _send_ping_packet(self, payload=None):
        """Unified function to queue PING packets with lowest priority (4)."""
        if self.count_ping >= 100:
            return

        if self.session_restart_event and self.session_restart_event.is_set():
            return

        if payload is None:
            payload = b"PO:" + os.urandom(4)

        try:
            self.enqueue_seq = (self.enqueue_seq + 1) & 0x7FFFFFFF
            heapq.heappush(
                self.main_queue,
                (4, self.enqueue_seq, Packet_Type.PING, 0, 0, payload),
            )
            self.count_ping += 1
            self.tx_event.set()
        except Exception:
            pass

    async def _process_received_packet(
        self, response_bytes: bytes, addr=None
    ) -> Tuple[Optional[dict], bytes]:
        """Parse raw DNS response, extract VPN header, and return packet type."""
        if not response_bytes:
            return None, b""

        parsed = self.dns_packet_parser.parse_dns_packet(response_bytes)
        if addr and parsed and parsed.get("questions"):
            try:
                qname = parsed["questions"][0].get("qName", "").lower()
                if qname.endswith(self.domains_lower):
                    for d in self.domains_lower:
                        if qname.endswith(d):
                            self.balancer.report_success(f"{addr[0]}:{d}")
                            break
            except Exception:
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

        if len(chunks) == 1:
            assembled_data_str = next(iter(chunks.values()))
        else:
            assembled_data_str = "".join(chunks[i] for i in sorted(chunks.keys()))

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
        if max_mtu <= 0:
            return 0

        min_allowed = max(min_threshold, allowed_min_mtu)

        if max_mtu < min_allowed:
            self.logger.debug(
                f"<cyan>[MTU]</cyan> Max MTU {max_mtu} is lower than allowed minimum {min_allowed}. Skipping."
            )
            return 0

        self.logger.debug(
            f"<cyan>[MTU]</cyan> Starting binary search for MTU. Range: {min_allowed}-{max_mtu}"
        )

        for attempt in range(self.mtu_test_retries):
            if self.should_stop.is_set():
                return 0
            if await test_callable(max_mtu, is_retry=(attempt > 0)):
                self.logger.debug(f"<cyan>[MTU]</cyan> Max MTU {max_mtu} is valid.")
                return max_mtu

        low = max(min_mtu, min_allowed)
        high = max_mtu - 1
        optimal = 0

        while low <= high:
            if self.should_stop.is_set():
                return 0

            mid = (low + high) // 2
            ok = False

            for attempt in range(self.mtu_test_retries):
                if self.should_stop.is_set():
                    return 0
                try:
                    if await test_callable(mid, is_retry=(attempt > 0)):
                        ok = True
                        break
                except Exception as e:
                    self.logger.debug(f"MTU test callable raised: {e}")

            if ok:
                optimal = mid
                low = mid + 1
            else:
                high = mid - 1

        self.logger.debug(f"<cyan>[MTU]</cyan> Binary search result: {optimal}")
        return optimal

    async def send_upload_mtu_test(
        self,
        domain: str,
        dns_server: str,
        dns_port: int,
        mtu_size: int,
        is_retry: bool = False,
    ) -> bool:
        if not is_retry:
            self.logger.debug(
                f"<magenta>[MTU Probe]</magenta> Testing Upload MTU: <yellow>{mtu_size}</yellow> bytes via <cyan>{dns_server}</cyan>"
            )

        mtu_char_len, mtu_bytes = self.dns_packet_parser.calculate_upload_mtu(
            domain=domain, mtu=mtu_size
        )
        if mtu_size > mtu_bytes or mtu_char_len < 29:
            return False

        random_hex = generate_random_hex_text(mtu_char_len)
        dns_queries = self.dns_packet_parser.build_request_dns_query(
            domain=domain,
            session_id=os.urandom(1)[0],
            packet_type=Packet_Type.MTU_UP_REQ,
            data=random_hex,
            mtu_chars=mtu_char_len,
            encode_data=False,
            qType=DNS_Record_Type.TXT,
        )

        if not dns_queries:
            return False

        response = await self._send_and_receive_dns(
            dns_queries[0], dns_server, dns_port, self.mtu_test_timeout
        )

        if not response:
            if not is_retry:
                self.logger.info(
                    f"<yellow>⚠️ Upload test failed: Upload MTU <cyan>{mtu_size}</cyan> bytes via <cyan>{dns_server}</cyan> for <cyan>{domain}</cyan></yellow>"
                )
            return False

        parsed_header, _ = await self._process_received_packet(response)
        packet_type = parsed_header["packet_type"] if parsed_header else None

        if packet_type == Packet_Type.MTU_UP_RES:
            self.logger.success(
                f"<yellow>🟢 Upload test passed: Upload MTU <green>{mtu_size}</green> bytes via <cyan>{dns_server}</cyan> for <cyan>{domain}</cyan></yellow>"
            )
            return True
        elif packet_type == Packet_Type.ERROR_DROP:
            if not is_retry:
                self.logger.info(
                    f"<yellow>⚠️ Upload test failed (Server Dropped Packet): Upload MTU <cyan>{mtu_size}</cyan> bytes via <cyan>{dns_server}</cyan> for <cyan>{domain}</cyan></yellow>"
                )
            return False

        if not is_retry:
            self.logger.info(
                f"<yellow>⚠️ Upload test failed: Upload MTU <cyan>{mtu_size}</cyan> bytes via <cyan>{dns_server}</cyan> for <cyan>{domain}</cyan></yellow>"
            )
        return False

    async def send_download_mtu_test(
        self,
        domain: str,
        dns_server: str,
        dns_port: int,
        mtu_size: int,
        is_retry: bool = False,
    ) -> bool:
        if not is_retry:
            self.logger.debug(
                f"<magenta>[MTU Probe]</magenta> Testing Download MTU: <yellow>{mtu_size}</yellow> bytes via <cyan>{dns_server}</cyan>"
            )

        data_bytes = mtu_size.to_bytes(4, "big")
        encrypted_data = self.dns_packet_parser.codec_transform(
            data_bytes, encrypt=True
        )

        mtu_char_len, _ = self.dns_packet_parser.calculate_upload_mtu(
            domain=domain, mtu=64
        )

        dns_queries = self.dns_packet_parser.build_request_dns_query(
            domain=domain,
            session_id=os.urandom(1)[0],
            packet_type=Packet_Type.MTU_DOWN_REQ,
            data=encrypted_data,
            mtu_chars=mtu_char_len,
            encode_data=True,
            qType=DNS_Record_Type.TXT,
        )

        if not dns_queries:
            return False

        response = await self._send_and_receive_dns(
            dns_queries[0], dns_server, dns_port, self.mtu_test_timeout
        )

        if not response:
            if not is_retry:
                self.logger.info(
                    f"<yellow>⚠️ Download test failed: Download MTU <cyan>{mtu_size}</cyan> bytes via <cyan>{dns_server}</cyan> for <cyan>{domain}</cyan> (No Response)</yellow>"
                )
            return False

        parsed_header, returned_data = await self._process_received_packet(response)
        packet_type = parsed_header["packet_type"] if parsed_header else None

        if packet_type == Packet_Type.MTU_DOWN_RES:
            if returned_data and len(returned_data) == mtu_size:
                self.logger.success(
                    f"<yellow>🟢 Download test passed: Download MTU <green>{mtu_size}</green> bytes via <cyan>{dns_server}</cyan> for <cyan>{domain}</cyan></yellow>"
                )
                return True
            else:
                if not is_retry:
                    self.logger.info(
                        f"<yellow>⚠️ Download test failed: Download MTU <cyan>{mtu_size}</cyan> bytes via <cyan>{dns_server}</cyan> for <cyan>{domain}</cyan> (Data Size Mismatch)</yellow>"
                    )
                return False

        if not is_retry:
            self.logger.info(
                f"<yellow>⚠️ Download test failed: Download MTU <cyan>{mtu_size}</cyan> bytes via <cyan>{dns_server}</cyan> for <cyan>{domain}</cyan> (Unexpected Packet Type)</yellow>"
            )
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

            async def test_fn(m, is_retry=False):
                return await self.send_upload_mtu_test(
                    domain, dns_server, dns_port, m, is_retry
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

            async def test_fn(m, is_retry=False):
                return await self.send_download_mtu_test(
                    domain, dns_server, dns_port, m, is_retry
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

        try:
            self.logger.info("=" * 80)
            self.logger.info(
                "<cyan>🛡️ [Stealth Mode] Calculating optimal MTUs for Severe Filtering & High Loss...</cyan>"
            )

            raw_header = bytes([0, Packet_Type.STREAM_DATA, 0, 0, 0, 0, 0, 0, 0, 0])
            if self.encryption_method == 0:
                enc_header = raw_header
            else:
                enc_header = self.dns_packet_parser.codec_transform(
                    raw_header, encrypt=True
                )

            base36_header = self.dns_packet_parser.base_encode(
                enc_header, lowerCaseOnly=True
            )
            prefix_len = len(base36_header) + 3

            available_txt_chars = 191 - prefix_len

            max_enc_down_bytes = (available_txt_chars // 4) * 3
            optimal_down_mtu = max_enc_down_bytes - self.crypto_overhead

            unique_domains = set(self.domains)
            for d in unique_domains:
                _, max_up_bytes = self.dns_packet_parser.calculate_upload_mtu(
                    domain=d, mtu=0
                )
                optimal_up_mtu = max_up_bytes
                self.max_upload_mtu = min(self.max_upload_mtu, optimal_up_mtu)
                self.min_upload_mtu = min(self.min_upload_mtu, self.max_upload_mtu)

                self.logger.info(
                    f"   Domain: <yellow>{d}</yellow> -> "
                    f"MIN and MAX_UPLOAD_MTU = <green>{optimal_up_mtu}</green> | "
                    f"MIN and MAX_DOWNLOAD_MTU = <green>{optimal_down_mtu}</green> | "
                    f"MAX_PACKETS_PER_BATCH = <green>{self.max_packets_per_batch}</green>"
                )

            self.logger.info(
                "<red>   [Note]</red> The calculated optimal MTUs for stealth mode are quite low due to the heavy encryption overhead and DNS encoding. In real-world conditions with severe filtering, you may find that only very small MTUs succeed consistently. It's recommended to use these values as a baseline and adjust based on observed performance and reliability in your specific environment."
            )
            self.logger.info(
                "<red>   [Note]</red> But if you find that even these low MTUs are not reliable, you may need to further reduce them or increase packet duplication to improve chances of successful transmission."
            )
            self.logger.info(
                "<red>   [Note]</red> Always prioritize reliability over speed in highly restrictive environments, and consider using the stealth mode MTU values as a starting point for further tuning based on your testing results."
            )
            self.logger.info(
                "<red>   [Note]</red> The MTU testing process can be time-consuming, especially if you have many resolvers and domains. It's recommended to start with a smaller set of servers for initial testing to quickly identify any major issues before scaling up to test all combinations."
            )

            self.logger.info("=" * 80)
        except Exception as e:
            self.logger.debug(f"Failed to calculate stealth MTU: {e}")

        server_id = 0
        total_conns = len(self.connections_map)

        for connection in self.connections_map:
            if self.should_stop.is_set():
                break

            if not connection:
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

            valid_count = sum(1 for c in self.connections_map if c.get("is_valid"))
            errors_count = server_id - valid_count
            self.logger.info(
                f"<blue>Testing connection <yellow>{domain}</yellow> via <cyan>{resolver}</cyan> (<green>V: {valid_count}</green>, <red>E: {errors_count}</red>, <yellow>{server_id} / {total_conns}</yellow>)...</blue>"
            )
            # Step 1: Upload MTU
            up_valid, up_mtu_bytes, up_mtu_char = await self.test_upload_mtu_size(
                domain, resolver, dns_port, self.max_upload_mtu
            )

            valid_count = sum(1 for c in self.connections_map if c.get("is_valid"))
            errors_count = server_id - valid_count
            if not up_valid or (
                self.min_upload_mtu > 0 and up_mtu_bytes < self.min_upload_mtu
            ):
                self.logger.warning(
                    f"<red>❌ Upload test failed: Upload MTU <cyan>{up_mtu_bytes}</cyan> bytes via <cyan>{resolver}</cyan> for <cyan>{domain}</cyan> - (<green>V: {valid_count}</green>, <red>E: {errors_count}</red>, <yellow>{server_id} / {total_conns}</yellow>)</red>"
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
                    f"<red>❌ Download test failed: Download MTU <cyan>{down_mtu_bytes}</cyan> bytes via <cyan>{resolver}</cyan> for <cyan>{domain}</cyan> - (<green>V: {valid_count}</green>, <red>E: {errors_count}</red>, <yellow>{server_id} / {total_conns}</yellow>)</red>"
                )
                continue

            # Marking as Valid
            connection["is_valid"] = True
            connection["upload_mtu_bytes"] = up_mtu_bytes
            connection["upload_mtu_chars"] = up_mtu_char
            connection["download_mtu_bytes"] = down_mtu_bytes
            connection["packet_loss"] = 0

            valid_count = sum(1 for c in self.connections_map if c.get("is_valid"))
            errors_count = server_id - valid_count
            self.logger.success(
                f"<green>✅ Valid: {domain} via <green>{resolver}</green> | "
                f"Upload MTU: <cyan>{up_mtu_bytes}</cyan> | Download MTU: <cyan>{down_mtu_bytes}</cyan> - (<green>V: {valid_count}</green>, <red>E: {errors_count}</red>, <yellow>{server_id} / {total_conns}</yellow>)</green>"
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
        self.logger.info(
            f"<blue>Syncing MTU with server for session <cyan>{self.session_id}</cyan>...</blue>"
        )

        for overall_attempt in range(max_attempts):
            if self.should_stop.is_set():
                return False

            selected_conn = self.balancer.get_best_server()
            if not selected_conn:
                await asyncio.sleep(0.5)
                continue

            domain = selected_conn.get("domain")
            resolver = selected_conn.get("resolver")

            sync_token = os.urandom(8)

            data_bytes = (
                self.synced_upload_mtu.to_bytes(4, byteorder="big")
                + self.synced_download_mtu.to_bytes(4, byteorder="big")
                + sync_token
            )

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
                    f"<yellow>Failed to build MTU sync via <cyan>{resolver}</cyan> for <cyan>{domain}</cyan>, Retrying...</yellow>"
                )
                await asyncio.sleep(0.2)
                continue

            for inner_attempt in range(3):
                if self.should_stop.is_set():
                    return False

                response = await self._send_and_receive_dns(
                    dns_queries[0], resolver, 53, self.timeout
                )

                if response:
                    parsed_header, returned_data = await self._process_received_packet(
                        response
                    )
                    packet_type = (
                        parsed_header["packet_type"] if parsed_header else None
                    )

                    if packet_type == Packet_Type.SET_MTU_RES:
                        if returned_data == sync_token:
                            self.logger.success(
                                "<green>MTU values successfully synced with the server!</green>"
                            )
                            return True
                        else:
                            self.logger.warning(
                                "<red>MTU Sync token mismatch! Ignoring response.</red>"
                            )

                if inner_attempt < 2:
                    await asyncio.sleep(0.5)

            self.logger.warning(
                f"<yellow>MTU sync failed via <cyan>{resolver}</cyan> for <cyan>{domain}</cyan>. Retrying overall process...</yellow>"
            )
            await asyncio.sleep(0.2)

        return False

    # ---------------------------------------------------------
    # Core Loop & Session Setup
    # ---------------------------------------------------------
    async def _init_session(self, max_attempts=10) -> bool:
        """Initialize a new session with the server."""
        self.logger.info("<blue>Initializing session ...</blue>")

        for overall_attempt in range(max_attempts):
            if self.should_stop.is_set():
                return False

            selected_conn = self.balancer.get_best_server()
            if not selected_conn:
                await asyncio.sleep(0.5)
                continue

            domain = selected_conn.get("domain")
            resolver = selected_conn.get("resolver")

            init_token = os.urandom(8).hex().encode("ascii")

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
                await asyncio.sleep(0.2)
                continue

            for inner_attempt in range(3):
                if self.should_stop.is_set():
                    return False

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
                            decoded_str = returned_data.decode("utf-8", errors="ignore")
                            if ":" in decoded_str:
                                received_token, received_sid = decoded_str.split(":", 1)
                                if received_token == init_token.decode("ascii"):
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

                if inner_attempt < 2:
                    await asyncio.sleep(0.5)

            self.logger.warning(
                f"Session init failed via {resolver} for {domain}. Retrying overall process..."
            )
            await asyncio.sleep(0.2)

        return False

    async def run_client(self) -> None:
        """Run the MasterDnsVPN Client main logic."""
        self.logger.info("Setting up connections...")
        all_resolvers = 0
        self.count_ping = 0
        self.active_streams = {}
        self.enqueue_seq = 0
        self.last_stream_id = 0
        self.main_queue = []
        self.tx_event = asyncio.Event()
        self.round_robin_index = 0
        self.last_stream_id = 0

        self.count_ack = 0
        self.count_data = 0
        self.count_resend = 0
        self.count_ping = 0
        self.track_ack = set()
        self.track_resend = set()
        self.track_types = set()
        self.track_data = set()
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

                self.balancer.set_balancers(valid_conns)

                self.synced_upload_mtu = min(c["upload_mtu_bytes"] for c in valid_conns)
                self.synced_upload_mtu_chars = min(
                    c["upload_mtu_chars"] for c in valid_conns
                )
                self.synced_download_mtu = min(
                    c["download_mtu_bytes"] for c in valid_conns
                )

                self.safe_uplink_mtu = max(
                    64, self.synced_upload_mtu - self.crypto_overhead
                )

                remaining_mtu_space = (
                    self.safe_uplink_mtu - 4
                )  # 4 bytes for os.urandom(4) to avoid DNS caching

                self.max_packed_blocks = max(
                    1,
                    min(
                        remaining_mtu_space // 5,
                        self.config.get("MAX_PACKETS_PER_BATCH", 3),
                    ),
                )  # Each block is 5 bytes (1 byte type + 2 bytes stream ID + 2 bytes seq num)

                max_founded_upload_mtu = max(c["upload_mtu_bytes"] for c in valid_conns)
                max_founded_download_mtu = max(
                    c["download_mtu_bytes"] for c in valid_conns
                )

                self.logger.success("<green>MTU Testing Completed!</green>")
                self.logger.info("=" * 80)
                self.logger.info("<cyan>Valid Connections After MTU Testing:</cyan>")
                self.logger.info("=" * 80)
                self.logger.info(
                    f"{'Resolver':<20} {'Upload MTU':<15} {'Download MTU':<15} {'Domain':<30}"
                )
                self.logger.info("-" * 80)
                for conn in valid_conns:
                    resolver = conn.get("resolver", "N/A")
                    up_mtu = conn.get("upload_mtu_bytes", 0)
                    down_mtu = conn.get("download_mtu_bytes", 0)
                    domain = conn.get("domain", "N/A")
                    self.logger.info(
                        f"<cyan>{resolver:<20}</cyan> <green>{up_mtu:<15}</green> <green>{down_mtu:<15}</green> <blue>{domain:<30}</blue>"
                    )
                self.logger.info("=" * 80)
                self.logger.success(
                    f"<blue>Total valid resolvers after MTU testing: <cyan>{len(self.balancer.valid_servers)}</cyan> of <cyan>{all_resolvers}</cyan></blue>"
                )
                self.logger.info(
                    f"<blue>Note:</blue> Each packet will be sent <yellow>{self.packet_duplication_count}</yellow> times to improve reliability."
                )

                self.logger.info("=" * 80)
                self.logger.info(
                    f"<cyan>[MTU RESULTS]</cyan> Max Upload MTU found: <yellow>{max_founded_upload_mtu}</yellow> | Max Download MTU found: <yellow>{max_founded_download_mtu}</yellow>"
                )
                self.logger.info(
                    f"<cyan>[MTU RESULTS]</cyan> Selected Synced Upload MTU: <yellow>{self.synced_upload_mtu}</yellow> | Selected Synced Download MTU: <yellow>{self.synced_download_mtu}</yellow>"
                )
                self.logger.info("=" * 80)
                self.logger.info(
                    f"<green>Global MTU Configuration -> Upload: <cyan>{self.synced_upload_mtu}</cyan>, Download: <cyan>{self.synced_download_mtu}</cyan></green>"
                )
                self.success_mtu_checks = True

            selected_conn = self.balancer.get_best_server()
            if not selected_conn:
                self.logger.error("No active servers available from Balancer.")
                return
            max_attempts = self.config.get("MAX_CONNECTION_ATTEMPTS", 10)
            if not await self._init_session(max_attempts):
                self.logger.error("Failed to initialize session with the server.")
                return

            self.logger.success(
                f"<green>Session Established! Session ID: <cyan>{self.session_id}</cyan></green>"
            )

            if not await self._sync_mtu_with_server(max_attempts):
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
        self.logger.info("<blue>Entering VPN Tunnel Main Loop...</blue>")
        self.main_queue = []
        self.round_robin_index = 0
        self.tx_event = asyncio.Event()
        self.active_streams = {}
        self.enqueue_seq = 0
        self.last_stream_id = 0

        self.count_ack = 0
        self.count_data = 0
        self.count_resend = 0
        self.count_ping = 0
        self.track_ack = set()
        self.track_resend = set()
        self.track_types = set()
        self.track_data = set()

        self.tunnel_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            buffer_size = int(self.config.get("SOCKET_BUFFER_SIZE", 8388608))
            try:
                self.tunnel_sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_RCVBUF, buffer_size
                )
                self.tunnel_sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_SNDBUF, buffer_size
                )
            except OSError:
                new_size = 65535
                self.tunnel_sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_RCVBUF, new_size
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

            if self.protocol_type == "SOCKS5":
                if self.config.get("AUTH_USERNAME") and self.config.get(
                    "AUTH_PASSWORD"
                ):
                    self.logger.info(
                        f"<green>SOCKS5 Proxy started on {listen_port} with Authentication. Username: <cyan>{self.config.get('AUTH_USERNAME')}</cyan></green>"
                    )
                else:
                    self.logger.info(
                        f"<green>SOCKS5 Proxy started on {listen_port} without Authentication.</green>"
                    )
            else:
                self.logger.info(
                    f"<green>TCP Proxy started on {listen_port} (Protocol: {self.protocol_type})</green>"
                )

            self.workers = []

            num_rx_workers = self.config.get("NUM_RX_WORKERS", 2)
            for _ in range(num_rx_workers):
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
            self.logger.info("<yellow>Cleaning up tunnel resources...</yellow>")

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

            for task in list(self.rx_tasks):
                if not task.done():
                    task.cancel()

            if self.rx_tasks:
                await asyncio.gather(*self.rx_tasks, return_exceptions=True)

            self.rx_tasks.clear()
            self.active_streams.clear()

            if hasattr(self, "tunnel_sock") and self.tunnel_sock:
                try:
                    self.tunnel_sock.close()
                except Exception:
                    pass

            try:
                self.main_queue.clear()
                self.track_ack.clear()
                self.track_resend.clear()
                self.track_types.clear()
                self.track_data.clear()
            except Exception:
                pass

        if not stop_task.done():
            stop_task.cancel()
        if not restart_task.done():
            restart_task.cancel()

        self.logger.info(
            "<yellow>Cleaning up old connections before reconnecting...</yellow>"
        )
        self.active_streams.clear()

    async def _rx_worker(self):
        """Continuously listen for incoming VPN packets on the tunnel socket."""
        self.logger.debug("<magenta>[RX]</magenta> RX Worker started.")
        while not self.should_stop.is_set() and not self.session_restart_event.is_set():
            try:
                data, addr = await async_recvfrom(self.loop, self.tunnel_sock, 65536)
                await self.rx_semaphore.acquire()
                task = self.loop.create_task(
                    self._process_and_route_incoming(data, addr)
                )
                self.rx_tasks.add(task)
                task.add_done_callback(
                    lambda t: (self.rx_tasks.discard(t), self.rx_semaphore.release())
                )

            except asyncio.CancelledError:
                break
            except OSError as e:
                if getattr(e, "winerror", None) == 10054:
                    continue
                await asyncio.sleep(0.01)
            except Exception as _:
                await asyncio.sleep(0.01)

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

        while not self.should_stop.is_set() and not (
            self.session_restart_event and self.session_restart_event.is_set()
        ):
            if stream_id > 65535:
                if wrapped:
                    return False, 0
                stream_id = 1
                wrapped = True

            if stream_id not in self.active_streams:
                self.last_stream_id = stream_id
                return True, stream_id

            stream_id += 1

        return False, 0

    async def _handle_local_tcp_connection(self, reader, writer):
        if self.should_stop.is_set() or (
            self.session_restart_event and self.session_restart_event.is_set()
        ):
            await self._close_writer_safely(writer)
            return

        target_payload = b""
        is_socks5 = False

        # -------------------------------------------------------------------
        # SOCKS5 HANDSHAKE LOGIC
        # -------------------------------------------------------------------
        if self.protocol_type == "SOCKS5":
            try:
                # 1. Greeting
                try:
                    greeting = await asyncio.wait_for(
                        reader.readexactly(2), timeout=3.0
                    )
                except asyncio.TimeoutError:
                    await self._close_writer_safely(writer)
                    return

                if greeting[0] != 0x05:
                    await self._close_writer_safely(writer)
                    return
                num_methods = greeting[1]
                methods = await reader.readexactly(num_methods)
                client_IP = "Unknown"
                try:
                    client_IP = writer.get_extra_info("peername")[0]
                except Exception:
                    pass
                # Auth Negotiation
                if getattr(self, "socks5_auth", False):
                    if 0x02 not in methods:  # 0x02 is Username/Password
                        self.logger.warning(
                            f"<yellow>🔒 SOCKS5 Client does not support required Username/Password authentication method. Rejecting connection. IP: <cyan>{client_IP}</cyan></yellow>"
                        )
                        writer.write(b"\x05\xff")  # No acceptable methods
                        await writer.drain()
                        await self._close_writer_safely(writer)
                        return
                    writer.write(b"\x05\x02")
                    await writer.drain()

                    # Read Auth Request
                    auth_version = await reader.readexactly(1)
                    if auth_version[0] != 0x01:
                        await self._close_writer_safely(writer)
                        return

                    ulast = await reader.readexactly(1)
                    uname = await reader.readexactly(ulast[0])

                    plast = await reader.readexactly(1)
                    passwd = await reader.readexactly(plast[0])

                    if (
                        uname.decode() != self.socks5_user
                        or passwd.decode() != self.socks5_pass
                    ):
                        writer.write(b"\x01\x01")  # Auth failed
                        await writer.drain()
                        self.logger.warning(
                            f"<yellow>🔒 SOCKS5 Auth failed for user: <cyan>{uname.decode()}</cyan> from IP: <cyan>{client_IP}</cyan></yellow>"
                        )
                        await self._close_writer_safely(writer)
                        return

                    writer.write(b"\x01\x00")  # Auth success
                    await writer.drain()
                    self.logger.info(
                        f"<green>🔓 SOCKS5 Auth successful for user: <cyan>{uname.decode()}</cyan> from IP: <cyan>{client_IP}</cyan></green>"
                    )
                else:
                    if 0x00 not in methods:  # 0x00 is No Auth
                        writer.write(b"\x05\xff")
                        await writer.drain()
                        await self._close_writer_safely(writer)
                        return
                    writer.write(b"\x05\x00")
                    await writer.drain()

                is_socks5 = True
                # 2. Connection Request
                req_header = await reader.readexactly(4)
                # VER(1), CMD(1), RSV(1), ATYP(1)
                if req_header[0] != 0x05:
                    await self._close_writer_safely(writer)
                    return

                cmd = req_header[1]
                # We only support TCP CONNECT (0x01)
                if cmd != 0x01:
                    if cmd == 0x03:
                        self.logger.debug(
                            "<yellow>SOCKS5 UDP Associate requested. Rejecting gracefully (Not Supported).</yellow>"
                        )
                    writer.write(
                        b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00"
                    )  # Command not supported
                    await writer.drain()
                    await self._close_writer_safely(writer)
                    return

                atyp = req_header[3]
                target_addr_bytes = b""
                if atyp == 0x01:  # IPv4
                    target_addr_bytes = await reader.readexactly(4)
                elif atyp == 0x03:  # Domain
                    dlen = await reader.readexactly(1)
                    target_addr_bytes = dlen + await reader.readexactly(dlen[0])
                elif atyp == 0x04:  # IPv6
                    target_addr_bytes = await reader.readexactly(16)
                else:
                    await self._close_writer_safely(writer)
                    return

                target_port_bytes = await reader.readexactly(2)

                # Format:  [ATYP] [ADDR_BYTES] [PORT_BYTES]
                target_payload = bytes([atyp]) + target_addr_bytes + target_port_bytes

                # Send SOCKS5 Success Reply
                reply = b"\x05\x00\x00"  # VER, REP=0(success), RSV
                if atyp == 0x01:  # IPv4
                    reply += b"\x01" + target_addr_bytes + target_port_bytes
                elif atyp == 0x03:  # Domain
                    reply += b"\x03" + target_addr_bytes + target_port_bytes
                elif atyp == 0x04:  # IPv6
                    reply += b"\x04" + target_addr_bytes + target_port_bytes
                writer.write(reply)
                await writer.drain()

            except Exception as e:
                self.logger.debug(f"SOCKS5 Handshake error: {e}")
                await self._close_writer_safely(writer)
                return

        stream_id_status, stream_id = self._new_get_stream_id()
        if not stream_id_status:
            self.logger.error(
                "<red>No available Stream IDs! Too many connections.</red>"
            )
            await self._close_writer_safely(writer)
            return

        self.logger.info(
            f"<green>New local connection, assigning Stream ID: <cyan>{stream_id}</cyan></green>"
        )

        now_mono = time.monotonic()
        syn_data = b"SY:" + os.urandom(4)

        self.active_streams[stream_id] = {
            "reader": reader,
            "writer": writer,
            "create_time": now_mono,
            "last_activity_time": now_mono,
            "status": "PENDING",
            "stream": None,
            "stream_creating": False,
            "tx_queue": [],
            "initial_payload": target_payload,
            "count_ack": 0,
            "count_data": 0,
            "count_resend": 0,
            "count_fin": 0,
            "count_syn_ack": 0,
            "track_ack": set(),
            "track_resend": set(),
            "track_fin": set(),
            "track_syn_ack": set(),
            "track_data": set(),
        }

        if not is_socks5:
            self.enqueue_seq = (self.enqueue_seq + 1) & 0x7FFFFFFF

            heapq.heappush(
                self.active_streams[stream_id]["tx_queue"],
                (0, self.enqueue_seq, Packet_Type.STREAM_SYN, stream_id, 0, syn_data),
            )
            self.tx_event.set()
        else:
            await self._stream_syn_handler(stream_id, target_payload, reader, writer)

    async def _stream_syn_handler(
        self, stream_id: int, target_payload: bytes, reader, writer
    ):
        stream_data = self.active_streams[stream_id]
        stream_data["status"] = "ACTIVE"

        stream = ARQ(
            stream_id=stream_id,
            session_id=self.session_id,
            enqueue_tx_cb=self._client_enqueue_tx,
            reader=reader,
            writer=writer,
            mtu=self.safe_uplink_mtu,
            logger=self.logger,
            window_size=self.config.get("ARQ_WINDOW_SIZE", 600),
            rto=float(self.config.get("ARQ_INITIAL_RTO", 0.8)),
            max_rto=float(self.config.get("ARQ_MAX_RTO", 1.5)),
            is_socks=True,
            initial_data=target_payload,
        )
        stream_data["stream"] = stream
        self.logger.info(
            f"<green>SOCKS5 Stream <cyan>{stream_id}</cyan> Created and queued SOCKS5_SYN chunks.</green>"
        )
        self._send_ping_packet()

    async def _client_enqueue_tx(
        self,
        priority,
        stream_id,
        sn,
        data,
        is_ack=False,
        is_fin=False,
        is_resend=False,
        is_socks_syn=False,
    ):
        if self.should_stop.is_set() or (
            self.session_restart_event and self.session_restart_event.is_set()
        ):
            return

        ptype = Packet_Type.STREAM_DATA
        effective_priority = priority

        if is_socks_syn:
            ptype = Packet_Type.SOCKS5_SYN
            effective_priority = priority
        elif is_ack:
            ptype = Packet_Type.STREAM_DATA_ACK
            effective_priority = 0
        elif is_fin:
            ptype = Packet_Type.STREAM_FIN
            effective_priority = 4
        elif is_resend:
            ptype = Packet_Type.STREAM_RESEND
            effective_priority = 1

        self.enqueue_seq = (self.enqueue_seq + 1) & 0x7FFFFFFF
        queue_item = (effective_priority, self.enqueue_seq, ptype, stream_id, sn, data)

        if stream_id == 0:
            if is_resend:
                if sn in self.track_data:
                    return
                if sn in self.track_resend:
                    return
                self.track_resend.add(sn)
                self.count_resend += 1

            elif ptype in (
                Packet_Type.STREAM_FIN,
                Packet_Type.STREAM_SYN,
                Packet_Type.STREAM_SYN_ACK,
            ):
                if ptype in self.track_types:
                    return
                self.track_types.add(ptype)

            elif ptype == Packet_Type.STREAM_DATA_ACK:
                if sn in self.track_ack:
                    return
                self.track_ack.add(sn)
                self.count_ack += 1

            elif ptype == Packet_Type.STREAM_DATA:
                if sn in self.track_data:
                    return
                self.track_data.add(sn)
                self.count_data += 1

            heapq.heappush(self.main_queue, queue_item)
            self.tx_event.set()

        else:
            stream_data = self.active_streams.get(stream_id)
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

            elif ptype in (Packet_Type.STREAM_DATA, Packet_Type.SOCKS5_SYN):
                if sn in stream_data["track_data"]:
                    return
                stream_data["track_data"].add(sn)
                stream_data["count_data"] += 1

            heapq.heappush(stream_data["tx_queue"], queue_item)
            self.tx_event.set()

    async def _tx_worker(self):
        while not self.should_stop.is_set() and not self.session_restart_event.is_set():
            try:
                await self.tx_event.wait()
            except asyncio.CancelledError:
                break
            except Exception:
                continue

            item = None
            target_queue = None
            is_main = False
            selected_stream_data = None

            active_sids = []
            _append = active_sids.append
            for sid in list(self.active_streams.keys()):
                s = self.active_streams.get(sid)
                if s and s.get("tx_queue"):
                    _append(sid)

            if active_sids:
                num_active = len(active_sids)
                if self.round_robin_index >= num_active:
                    self.round_robin_index = 0

                selected_sid = active_sids[self.round_robin_index]
                selected_stream_data = self.active_streams[selected_sid]
                t_queue = selected_stream_data["tx_queue"]

                if self.main_queue and self.main_queue[0][0] < t_queue[0][0]:
                    target_queue = self.main_queue
                    is_main = True
                else:
                    target_queue = t_queue
                    self.round_robin_index = (self.round_robin_index + 1) % num_active
            elif self.main_queue:
                target_queue = self.main_queue
                is_main = True
            else:
                self.tx_event.clear()
                continue

            if target_queue:
                item = heapq.heappop(target_queue)
                q_ptype, q_stream_id, q_sn = item[2], item[3], item[4]

                if is_main:
                    if q_ptype == Packet_Type.STREAM_DATA:
                        self.track_data.discard(q_sn)
                        if self.count_data > 0:
                            self.count_data -= 1
                    elif q_ptype == Packet_Type.STREAM_DATA_ACK:
                        self.track_ack.discard(q_sn)
                        if self.count_ack > 0:
                            self.count_ack -= 1
                    elif q_ptype == Packet_Type.STREAM_RESEND:
                        self.track_resend.discard(q_sn)
                        if self.count_resend > 0:
                            self.count_resend -= 1
                    elif q_ptype in (
                        Packet_Type.STREAM_FIN,
                        Packet_Type.STREAM_SYN,
                        Packet_Type.STREAM_SYN_ACK,
                    ):
                        self.track_types.discard(q_ptype)
                    elif q_ptype == Packet_Type.PING:
                        if self.count_ping > 0:
                            self.count_ping -= 1
                else:
                    if q_ptype in (Packet_Type.STREAM_DATA, Packet_Type.SOCKS5_SYN):
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

            if (
                item
                and item[2] == Packet_Type.STREAM_DATA_ACK
                and getattr(self, "max_packed_blocks", 1) > 1
            ):
                _pack = struct.pack
                packed_buffer = bytearray(_pack(">BHH", item[2], item[3], item[4]))
                blocks = 1
                max_blocks = self.max_packed_blocks

                mq = getattr(self, "main_queue", [])
                while self.count_ack > 0 and mq and blocks < max_blocks:
                    if mq[0][2] == Packet_Type.STREAM_DATA_ACK:
                        popped = heapq.heappop(mq)
                        self.track_ack.discard(popped[4])
                        self.count_ack -= 1
                        packed_buffer.extend(
                            _pack(">BHH", popped[2], popped[3], popped[4])
                        )
                        blocks += 1
                    else:
                        break

                if blocks < max_blocks and active_sids:
                    start_idx = self.round_robin_index
                    num_active = len(active_sids)

                    for offset in range(num_active):
                        if blocks >= max_blocks:
                            break

                        sid = active_sids[(start_idx + offset) % num_active]
                        s_data = self.active_streams[sid]

                        if s_data["count_ack"] > 0:
                            t_q = s_data["tx_queue"]
                            while (
                                s_data["count_ack"] > 0 and t_q and blocks < max_blocks
                            ):
                                if t_q[0][2] == Packet_Type.STREAM_DATA_ACK:
                                    popped = heapq.heappop(t_q)
                                    s_data["track_ack"].discard(popped[4])
                                    s_data["count_ack"] -= 1
                                    packed_buffer.extend(
                                        _pack(">BHH", popped[2], popped[3], popped[4])
                                    )
                                    blocks += 1
                                else:
                                    break

                item = (
                    item[0],
                    item[1],
                    Packet_Type.PACKED_CONTROL_BLOCKS,
                    0,
                    0,
                    bytes(packed_buffer),
                )

            if not item:
                continue

            try:
                q_ptype, q_stream_id, q_sn = item[2], item[3], item[4]
                if q_ptype in (Packet_Type.STREAM_DATA, Packet_Type.STREAM_RESEND):
                    stream_data = self.active_streams.get(q_stream_id)
                    if stream_data and "stream" in stream_data:
                        arq = stream_data["stream"]
                        if arq and q_sn not in getattr(arq, "snd_buf", {}):
                            continue

                await self._send_single_packet(item)
            except Exception as _:
                pass

    async def _send_single_packet(self, item):
        self.ping_manager.active_connections = len(self.active_streams)
        _, _, pkt_type, stream_id, sn, data = item

        if pkt_type != Packet_Type.PING:
            self.ping_manager.update_activity()

        if stream_id in self.active_streams:
            now_mono = time.monotonic()
            self.active_streams[stream_id]["last_activity_time"] = now_mono

        try:
            data_encrypted = (
                self.dns_packet_parser.codec_transform(data, encrypt=True)
                if data
                else b""
            )

            target_conns = self.balancer.get_unique_servers(
                self.packet_duplication_count
            )

            for conn in target_conns:
                self.balancer.report_send(conn["_key"])
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
                    continue

                for query_packet in query_packets:
                    try:
                        await async_sendto(
                            self.loop,
                            self.tunnel_sock,
                            query_packet,
                            (conn["resolver"], 53),
                        )
                    except Exception as _:
                        pass
        except Exception as e:
            self.logger.debug(f"TX Worker error during packet building/sending: {e}")

    async def _handle_server_response(self, header, data):
        ptype = header["packet_type"]
        stream_id = header.get("stream_id", 0)
        sn = header.get("sequence_num", 0)

        stream_id_exists = False
        if stream_id > 0 and stream_id in self.active_streams:
            stream_id_exists = True
            self.active_streams[stream_id]["last_activity_time"] = time.monotonic()

        if ptype == Packet_Type.STREAM_SYN_ACK and stream_id_exists:
            stream_data = self.active_streams[stream_id]

            if stream_data.get("stream") or stream_data.get("status") == "ACTIVE":
                return

            if stream_data.get("stream_creating"):
                return

            writer = stream_data.get("writer")
            if not writer or writer.is_closing():
                self.active_streams.pop(stream_id, None)
                return

            stream_data["stream_creating"] = True

            try:
                stream_data["status"] = "ACTIVE"

                raw_reader = stream_data["reader"]
                initial_payload = stream_data.get("initial_payload", b"")
                wrapped_reader = PrependReader(raw_reader, initial_payload)

                stream = ARQ(
                    stream_id=stream_id,
                    session_id=self.session_id,
                    enqueue_tx_cb=self._client_enqueue_tx,
                    reader=wrapped_reader,
                    writer=writer,
                    mtu=self.safe_uplink_mtu,
                    logger=self.logger,
                    window_size=self.config.get("ARQ_WINDOW_SIZE", 600),
                    rto=float(self.config.get("ARQ_INITIAL_RTO", 0.8)),
                    max_rto=float(self.config.get("ARQ_MAX_RTO", 1.5)),
                )

                stream_data["stream"] = stream
                self.logger.info(
                    f"<blue>Stream <cyan>{stream_id}</cyan> Established with server.</blue>"
                )
            finally:
                stream_data.pop("stream_creating", None)
                self._send_ping_packet()
        elif ptype == Packet_Type.SOCKS5_SYN_ACK and stream_id_exists:
            stream_obj = self.active_streams[stream_id].get("stream")
            if (
                stream_obj
                and hasattr(stream_obj, "socks_connected")
                and not stream_obj.socks_connected.is_set()
            ):
                stream_obj.socks_connected.set()
                self.logger.info(
                    f"<green>Socks5 Stream <cyan>{stream_id}</cyan> connection established.</green>"
                )
            self._send_ping_packet()
        elif (
            ptype in (Packet_Type.STREAM_DATA, Packet_Type.STREAM_RESEND)
            and stream_id_exists
            and data
        ):
            stream_obj = self.active_streams[stream_id].get("stream")
            if stream_obj:
                await stream_obj.receive_data(sn, data)
            self._send_ping_packet()
        elif ptype == Packet_Type.STREAM_DATA_ACK and stream_id_exists:
            stream_obj = self.active_streams[stream_id].get("stream")
            if stream_obj:
                await stream_obj.receive_ack(sn)
            self._send_ping_packet()
        elif ptype == Packet_Type.STREAM_FIN and stream_id_exists:
            self._send_ping_packet()
            self.active_streams[stream_id]["fin_retries"] = 99
            await self.close_stream(stream_id, reason="Server sent FIN")
        elif ptype == Packet_Type.PACKED_CONTROL_BLOCKS and data:
            _unpack_from = struct.unpack_from
            for i in range(0, len(data), 5):
                if i + 5 > len(data):
                    break
                b_ptype, b_stream_id, b_sn = _unpack_from(">BHH", data, i)

                if (
                    b_ptype == Packet_Type.STREAM_DATA_ACK
                    and b_stream_id in self.active_streams
                ):
                    stream_obj = self.active_streams[b_stream_id].get("stream")
                    if stream_obj:
                        await stream_obj.receive_ack(b_sn)
                elif (
                    b_ptype == Packet_Type.SOCKS5_SYN_ACK
                    and b_stream_id in self.active_streams
                ):
                    stream_obj = self.active_streams[b_stream_id].get("stream")
                    if (
                        stream_obj
                        and hasattr(stream_obj, "socks_connected")
                        and not stream_obj.socks_connected.is_set()
                    ):
                        stream_obj.socks_connected.set()
                        self.logger.info(
                            f"<green>Socks5 Stream <cyan>{b_stream_id}</cyan> connection established.</green>"
                        )
            self._send_ping_packet()
        elif ptype == Packet_Type.ERROR_DROP:
            if not self.session_restart_event.is_set():
                self.logger.error(
                    "<red>Session dropped by server (Server Restarted or Invalid). Reconnecting...</red>"
                )
                self.session_restart_event.set()

    async def close_stream(self, stream_id: int, reason: str = "Unknown") -> None:
        """Safely and fully close a specific local stream and salvage pending FIN/ACKs."""

        stream_data = self.active_streams.get(stream_id)
        if not stream_data or stream_data.get("status") in ("CLOSING", "TIME_WAIT"):
            return

        stream_data["status"] = "CLOSING"

        self.logger.info(
            f"<yellow>Closing Client Stream <cyan>{stream_id}</cyan>. Reason: <yellow>{reason}</yellow></yellow>"
        )

        stream_obj = stream_data.get("stream")
        if stream_obj:
            try:
                await stream_obj.close(reason=reason)
            except Exception as e:
                self.logger.debug(
                    f"<red>Error closing ARQStream {stream_id}: {e}</red>"
                )
        else:
            fin_data = b"FIN:" + os.urandom(4)
            await self._client_enqueue_tx(1, stream_id, 0, fin_data, is_fin=True)

        pending_tx = stream_data.get("tx_queue", [])
        if pending_tx:
            for item in pending_tx:
                if item[2] in (Packet_Type.STREAM_FIN, Packet_Type.STREAM_DATA_ACK):
                    heapq.heappush(self.main_queue, item)
            self.tx_event.set()

        try:
            stream_data.get("tx_queue", []).clear()
            stream_data.get("track_data", set()).clear()
            stream_data.get("track_resend", set()).clear()
            stream_data.get("track_ack", set()).clear()
            stream_data["status"] = "TIME_WAIT"
            stream_data["close_time"] = time.monotonic()
        except Exception:
            pass

        writer = stream_data.get("writer")
        await self._close_writer_safely(writer)

    async def _retransmit_worker(self):
        while not self.should_stop.is_set() and not self.session_restart_event.is_set():
            try:
                await asyncio.sleep(0.5)
                now = time.monotonic()

                for sid, s in list(self.active_streams.items()):
                    status = s.get("status")
                    last_act = s.get("last_activity_time", now)
                    close_time = s.get("close_time", now)

                    if status == "PENDING" and (now - last_act) > 1.5:
                        s["last_activity_time"] = now
                        self.track_types.discard(Packet_Type.STREAM_SYN)
                        syn_data = b"SY:" + os.urandom(4)
                        await self._client_enqueue_tx(0, sid, 0, syn_data)

                    elif status == "TIME_WAIT":
                        if (now - close_time) > 15.0:
                            self.active_streams.pop(sid, None)
                        elif (now - last_act) > 5.0 and s.get("fin_retries", 0) < 2:
                            s["last_activity_time"] = now
                            s["fin_retries"] = s.get("fin_retries", 0) + 1
                            fin_data = b"FIN:" + os.urandom(4)
                            await self._client_enqueue_tx(
                                1, sid, 0, fin_data, is_fin=True
                            )

                dead_streams = []
                for sid, s in list(self.active_streams.items()):
                    stream_obj = s.get("stream")
                    status = s.get("status")
                    create_time = s.get("create_time", 0)

                    if (
                        stream_obj
                        and getattr(stream_obj, "closed", False)
                        and status == "ACTIVE"
                    ):
                        dead_streams.append(sid)
                    elif status == "PENDING" and (now - create_time) > 350.0:
                        dead_streams.append(sid)

                for sid in dead_streams:
                    try:
                        s = self.active_streams.get(sid, {})
                        if s.get("status") == "PENDING":
                            reason = "Handshake timeout (No SYN_ACK from server)"
                        else:
                            arq = s.get("stream")
                            reason = getattr(
                                arq,
                                "close_reason",
                                "Closed locally or Inactivity Timeout",
                            )
                        await self.close_stream(sid, reason=reason)
                    except Exception as e:
                        self.logger.debug(
                            f"Error closing stream {sid} in retransmit worker: {e}"
                        )

                for sid, s in list(self.active_streams.items()):
                    arq = s.get("stream")
                    if arq and hasattr(arq, "check_retransmits"):
                        try:
                            await arq.check_retransmits()
                        except Exception as _:
                            pass

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Unexpected error in retransmit worker: {e}")
                await asyncio.sleep(0.5)

    # ---------------------------------------------------------
    # App Lifecycle
    # ---------------------------------------------------------
    async def start(self) -> None:
        try:
            self.loop = asyncio.get_running_loop()
            self.logger.info("=" * 60)
            self.logger.success("<magenta>Starting MasterDnsVPN Client...</magenta>")
            if not self.domains or not self.resolvers:
                self.logger.error(
                    "<red>Domains or Resolvers are missing in config.</red>"
                )
                return

            self.success_mtu_checks = False
            while not self.should_stop.is_set():
                self.logger.info("=" * 60)

                await self.run_client()

                if not self.should_stop.is_set():
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

    def _signal_handler(self, signum, frame=None) -> None:
        """Handle termination signals to stop the client gracefully (Thread-Safe)."""

        def _trigger_stop():
            if getattr(self, "should_stop", None) and not self.should_stop.is_set():
                self.logger.info(
                    f"<red>Received signal <cyan>{signum}</cyan>. Stopping MasterDnsVPN Client...</red>"
                )
                self.should_stop.set()
                if (
                    getattr(self, "session_restart_event", None)
                    and not self.session_restart_event.is_set()
                ):
                    self.session_restart_event.set()
                self.logger.info("<magenta>Stopping MasterDnsVPN Client...</magenta>")
            else:
                self.logger.info(
                    f"<red>Received signal <cyan>{signum}</cyan> again. Forcing exit...</red>"
                )
                os._exit(0)

        try:
            if getattr(self, "loop", None) and self.loop.is_running():
                self.loop.call_soon_threadsafe(_trigger_stop)
            else:
                _trigger_stop()
        except Exception:
            os._exit(0)


def main():
    client = MasterDnsVPNClient()
    try:
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        elif sys.platform == "darwin":
            pass
        else:
            try:
                import uvloop

                asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
            except ImportError:
                pass

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
            loop.create_task(client.start())
            loop.run_forever()
        except KeyboardInterrupt:
            try:
                client._signal_handler(signal.SIGINT, None)
            except Exception:
                pass
            print("\nClient stopped by user (Ctrl+C). Goodbye!")
            return
    except Exception as e:
        print(f"{e}")

    try:
        os._exit(0)
    except Exception as e:
        print(f"Error while stopping the client: {e}")
        exit()


if __name__ == "__main__":
    main()
