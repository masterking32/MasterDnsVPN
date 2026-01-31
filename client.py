# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import random
import sys
import os
import socket
import asyncio
from typing import Optional


from client_config import master_dns_vpn_config

from dns_utils.utils import getLogger, generate_random_hex_text
from dns_utils.DnsPacketParser import DnsPacketParser
from dns_utils.UDPClient import UDPClient
from dns_utils.DNS_ENUMS import PACKET_TYPES, Q_CLASSES, RESOURCE_RECORDS

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
        self.config: dict = master_dns_vpn_config.__dict__
        self.logger = getLogger(log_level=self.config.get("LOG_LEVEL", "INFO"))
        self.resolvers: list = self.config.get("RESOLVER_DNS_SERVERS", [])
        self.domains: list = self.config.get("DOMAINS", [])
        self.timeout: float = self.config.get("DNS_QUERY_TIMEOUT", 10.0)
        self.max_upload_mtu: int = self.config.get("MAX_UPLOAD_MTU", 512)
        self.max_download_mtu: int = self.config.get("MAX_DOWNLOAD_MTU", 4096)
        self.min_upload_mtu: int = self.config.get("MIN_UPLOAD_MTU", 0)
        self.min_download_mtu: int = self.config.get("MIN_DOWNLOAD_MTU", 0)
        self.encryption_method: int = self.config.get(
            "DATA_ENCRYPTION_METHOD", 1)
        self.skip_resolver_with_packet_loss: int = self.config.get(
            "SKIP_RESOLVER_WITH_PACKET_LOSS", 100)
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

        # Build a map of all domain-resolver combinations
        self.connections_map: list = [
            {"domain": domain, "resolver": resolver}
            for domain in self.domains
            for resolver in self.resolvers
        ]

        self.connections_map = [
            dict(t) for t in {tuple(d.items())
                              for d in self.connections_map}
        ]

        self.resent_connection_selected: int = -1

    async def select_connection(self) -> Optional[dict]:
        """Select a connection based on the balancing strategy."""
        valid_connections = [
            conn for conn in self.connections_map if conn.get("is_valid", True)
        ]

        if not valid_connections:
            self.logger.error("No valid connections available.")
            return None

        for conn in valid_connections:
            total_packets = conn.get("total_packets", 0)
            lost_packets = conn.get("lost_packets", 0)
            if total_packets > 0:
                packet_loss = (lost_packets / total_packets) * 100
            else:
                packet_loss = 0
            conn['packet_loss'] = packet_loss

        valid_connections = [
            conn for conn in valid_connections
            if conn['packet_loss'] <= self.skip_resolver_with_packet_loss
        ]

        if not valid_connections:
            self.logger.error(
                "No valid connections available after applying packet loss filter.")
            return None

        if self.resolver_balancing_strategy == 2:
            self.resent_connection_selected = (
                self.resent_connection_selected + 1) % len(valid_connections)
            selected_connection = valid_connections[self.resent_connection_selected]
            self.logger.debug(
                f"Round Robin selected connection, domain: {selected_connection['domain']}, resolver: {selected_connection['resolver']}")
            return selected_connection

        elif self.resolver_balancing_strategy == 3:
            valid_connections.sort(key=lambda x: x['packet_loss'])
            min_loss = valid_connections[0]['packet_loss']
            same_loss_connections = [
                conn for conn in valid_connections if conn['packet_loss'] == min_loss]
            if len(same_loss_connections) > 1:
                selected_connection = random.choice(same_loss_connections)
                self.logger.debug(
                    f"Least Packet Loss (tie) randomly selected connection with packet loss: {selected_connection['packet_loss']:.2f}%, domain: {selected_connection['domain']}, resolver: {selected_connection['resolver']}")
            else:
                selected_connection = same_loss_connections[0]
                self.logger.debug(
                    f"Least Packet Loss selected connection with packet loss: {selected_connection['packet_loss']:.2f}%, domain: {selected_connection['domain']}, resolver: {selected_connection['resolver']}")
            return selected_connection

        else:
            selected_connection = random.choice(valid_connections)
            self.logger.debug(
                f"Randomly selected connection, domain: {selected_connection['domain']}, resolver: {selected_connection['resolver']}")
            return selected_connection

    async def get_main_connection_index(self, selected_connection: Optional[dict] = None) -> Optional[int]:
        """Find and return the main connection (connections_map) based on the selected connection."""
        if selected_connection is None:
            selected_connection = await self.select_connection()
            if selected_connection is None:
                return None

        for index, conn in enumerate(self.connections_map):
            if (conn.get("domain") == selected_connection.get("domain") and
                    conn.get("resolver") == selected_connection.get("resolver")):
                return index

        self.logger.error(
            "Selected connection not found in connections map.")
        return None

    async def dns_request(self, server_host: str, server_port: int, data: bytes, timeout: float = 0, buffer_size: int = 65507) -> tuple:
        """
        Send a DNS request to the specified server and port using UDPClient.
        Returns: (response_bytes, response_parsed, addr) or (None, None, None) on error.
        """
        self.logger.debug(
            f"Sending DNS request to {server_host}:{server_port}, data length: {len(data)} bytes")

        if timeout <= 0:
            timeout = self.timeout

        udp_client = UDPClient(
            logger=self.logger,
            server_host=server_host,
            server_port=server_port,
            timeout=timeout,
            buffer_size=buffer_size,
        )

        try:
            if not udp_client.connect():
                self.logger.debug("Failed to connect UDP client.")
                return None, None, None

            request_id = int.from_bytes(data[0:2], byteorder='big')

            if not udp_client.send_bytes(data):
                self.logger.debug("Failed to send DNS request.")
                return None, None, None

            response_bytes, addr = udp_client.receive_bytes()
            if response_bytes is None:
                self.logger.debug("No response received from DNS server.")
                return None, None, None

            response_id_answered = int.from_bytes(
                response_bytes[0:2], byteorder='big')
            if response_id_answered != request_id:
                self.logger.debug(
                    f"Response ID {response_id_answered} does not match request ID {request_id}. Discarding response.")
                return None, None, None

            response_parsed = await self.dns_packet_parser.parse_dns_packet(response_bytes)

            return response_bytes, response_parsed, addr
        finally:
            udp_client.close()

    async def parse_dns_response(self, response_parsed: dict) -> tuple:
        """Parse the DNS response and extract relevant information."""

        if "headers" not in response_parsed or response_parsed["headers"].get("AnCount", 0) == 0:
            self.logger.debug("No answers in DNS response header.")
            return False, False, False, False

        answers = response_parsed.get("answers", [])
        vpn_packet_header = None
        final_answers = []
        for answer in answers:
            if answer.get("type") != RESOURCE_RECORDS["TXT"]:
                continue

            if answer.get("class") != Q_CLASSES["IN"]:
                continue

            if answer.get("TTL", 0) != 0:
                continue

            txt_rData = answer.get("rData", b"")
            if len(txt_rData) == 0:
                continue

            txt_data = self.dns_packet_parser.extract_txt_from_rData(txt_rData)
            if len(txt_data) == 0:
                continue

            if "." not in txt_data:
                self.logger.debug(
                    f"TXT record without expected format: {txt_data}")
                continue

            if txt_data.count(".") >= 2:
                vpn_packet_header, chunk_id, data_part = txt_data.split(".", 2)
            else:
                chunk_id, data_part = txt_data.split(".", 1)

            final_answers.append({
                "chunk_id": int(chunk_id),
                "data": data_part,
            })

        if len(final_answers) == 0 or vpn_packet_header is None:
            self.logger.debug(
                f"Extracted VPN packet header: {vpn_packet_header}")
            return False, False, False, False

        final_answers.sort(key=lambda x: x["chunk_id"])
        extracted_header = self.dns_packet_parser.decode_and_decrypt_data(
            vpn_packet_header, lowerCaseOnly=False)

        if len(extracted_header) != 2:
            self.logger.error(
                f"Invalid VPN packet header length: {len(extracted_header)}")
            return False, False, False, False

        session_id = extracted_header[0]
        packet_type = extracted_header[1]

        if packet_type not in PACKET_TYPES.values():
            self.logger.debug(
                f"Received non-VPN or stray packet type: {packet_type}")
            return False, None, None, None

        is_VPN_packet = True
        merged_answers = "".join(
            [answer["data"] for answer in final_answers])

        decoded_answers = self.dns_packet_parser.base_decode(
            merged_answers, lowerCaseOnly=False)
        return is_VPN_packet, session_id, packet_type, decoded_answers

    async def perform_upload_mtu_test(self, domain: str, dns_server: str, dns_port: int, mtu: int) -> bool:
        """Perform a single upload MTU test."""
        try:
            mtu_char_len, mtu_bytes = self.dns_packet_parser.calculate_upload_mtu(
                domain=domain,
                mtu=mtu
            )

            if (mtu_char_len < 29):
                self.logger.error(
                    f"Calculated MTU character length too small: {mtu_char_len} characters for domain {domain}")
                return False

            self.logger.debug(
                f"Performing upload MTU test: {mtu_bytes} bytes ({mtu_char_len} characters) to {dns_server}:{dns_port} for domain {domain}")

            random_hex = generate_random_hex_text(mtu_char_len).lower()
            labels = self.dns_packet_parser.generate_labels(
                domain=domain,
                session_id=random.randint(0, 255),
                packet_type=PACKET_TYPES["SERVER_UPLOAD_TEST"],
                data=random_hex,
                mtu_chars=mtu_char_len,
                encode_data=False
            )

            if labels is not None and len(labels) > 0:
                label = labels[0]

                test_packet = await self.dns_packet_parser.simple_question_packet(
                    domain=label,
                    qType=RESOURCE_RECORDS["TXT"]
                )

                response_bytes, response_parsed, addr = await self.dns_request(
                    dns_server, dns_port, test_packet, timeout=5.0, buffer_size=mtu_bytes + 512)

                if response_bytes is not None and response_parsed is not None:
                    is_VPN_packet, session_id, packet_type, answers = await self.parse_dns_response(
                        response_parsed)

                    if is_VPN_packet and packet_type == PACKET_TYPES["SERVER_UPLOAD_TEST"]:
                        return True
            elif len(labels) == 0:
                self.logger.debug(
                    "Failed to generate labels for MTU test.")
                return False
            elif len(labels) > 1:
                self.logger.debug(
                    "Generated multiple labels for MTU test; expected only one.")

            self.logger.debug(
                f"Upload MTU test failed for {mtu_bytes} bytes to {dns_server}:{dns_port} for domain {domain}.")
            return False

        except Exception as e:
            self.logger.error(
                f"Error during upload MTU test to {dns_server}:{dns_port} for domain {domain}: {e}")

        return False

    async def test_upload_mtu(self, domain: str, dns_server: str, dns_port: int, default_mtu: int) -> tuple:
        """Test and determine the optimal upload MTU for DNS tunneling."""
        self.logger.info(
            f"[Upload MTU Test] Starting upload MTU test to {dns_server}:{dns_port} for domain '{domain}'...")

        try:
            mtu_char_len, mtu_bytes = self.dns_packet_parser.calculate_upload_mtu(
                domain=domain,
                mtu=0
            )

            if default_mtu > 512 or default_mtu <= 0:
                default_mtu = 512

            if default_mtu > mtu_bytes:
                default_mtu = mtu_bytes

            min_mtu = 0
            max_mtu_candidate = default_mtu
            optimal_mtu = 0

            self.logger.debug(
                f"[Upload MTU Test] Starting test with maximum MTU {max_mtu_candidate} bytes to {dns_server}:{dns_port} for domain '{domain}'")

            # Initial attempt with the maximum MTU
            if await self.perform_upload_mtu_test(domain, dns_server, dns_port, max_mtu_candidate):
                mtu_char_len, mtu_bytes = self.dns_packet_parser.calculate_upload_mtu(
                    domain=domain,
                    mtu=max_mtu_candidate
                )
                return True, mtu_bytes, mtu_char_len

            while min_mtu <= max_mtu_candidate:
                current_mtu = (min_mtu + max_mtu_candidate) // 2
                self.logger.debug(
                    f"[Upload MTU Test] Testing <y>{current_mtu}</y> bytes to {dns_server}:{dns_port} for domain '{domain}'")

                if current_mtu < 30:
                    self.logger.debug(
                        f"[Upload MTU Test] Current MTU {current_mtu} bytes is below minimum threshold. Ending test.")
                    break

                if await self.perform_upload_mtu_test(domain, dns_server, dns_port, current_mtu):
                    optimal_mtu = current_mtu
                    min_mtu = current_mtu + 1
                    self.logger.debug(
                        f"[Upload MTU Test] Success at {current_mtu} bytes. Trying higher...")
                else:
                    max_mtu_candidate = current_mtu - 1
                    self.logger.debug(
                        f"[Upload MTU Test] Failure at {current_mtu} bytes. Trying lower...")
            if optimal_mtu > 29:
                mtu_char_len, mtu_bytes = self.dns_packet_parser.calculate_upload_mtu(
                    domain=domain,
                    mtu=optimal_mtu
                )
                return True, mtu_bytes, mtu_char_len

            return False, 0, 0
        except Exception as exc:
            self.logger.error(
                f"[Upload MTU Test] Exception occurred while testing upload MTU to {dns_server}:{dns_port} for domain '{domain}': {exc}")
            return False, 0, 0

    async def perform_download_mtu_test(self, domain: str, dns_server: str, dns_port: int, mtu: int, max_upload_chars: int) -> bool:
        """Perform a single download MTU test."""
        try:
            # convert mtu to bytes
            mtu_bytes = mtu.to_bytes(2, byteorder='big')
            mtu_encrypt = self.dns_packet_parser.codec_transform(
                mtu_bytes, encrypt=True)
            mtu_encode = self.dns_packet_parser.base_encode(
                mtu_encrypt, lowerCaseOnly=True)
            mtu_len = len(mtu_encode) + 1  # +1 for the dot separator
            upload_mtu = max_upload_chars - mtu_len
            payload_data = generate_random_hex_text(upload_mtu).lower()
            labels = self.dns_packet_parser.generate_labels(
                domain=domain,
                session_id=random.randint(0, 255),
                packet_type=PACKET_TYPES["SERVER_DOWNLOAD_TEST"],
                data=payload_data,
                mtu_chars=upload_mtu,
                encode_data=False
            )

            if labels is not None and len(labels) > 0:
                label = mtu_encode + "." + labels[0]

                test_packet = await self.dns_packet_parser.simple_question_packet(
                    domain=label,
                    qType=RESOURCE_RECORDS["TXT"]
                )

                response_bytes, response_parsed, addr = await self.dns_request(
                    dns_server, dns_port, test_packet, timeout=5.0)

                if response_bytes is not None and response_parsed is not None:
                    is_VPN_packet, session_id, packet_type, answers = await self.parse_dns_response(
                        response_parsed)

                    if is_VPN_packet and packet_type == PACKET_TYPES["SERVER_DOWNLOAD_TEST"]:
                        if ":".encode() not in answers:
                            self.logger.debug(
                                "Download MTU test failed: Invalid response format.")
                            return False

                        received_mtu_encrypted, _ = answers.split(
                            b":", 1)
                        download_size = self.dns_packet_parser.codec_transform(
                            received_mtu_encrypted, encrypt=False)
                        if download_size == mtu_bytes:
                            self.logger.debug(
                                f"Download MTU test successful for {mtu} bytes to {dns_server}:{dns_port} for domain {domain}.")
                            return True
                elif len(labels) == 0:
                    self.logger.debug(
                        "Failed to generate labels for download MTU test.")
                    return False
                elif len(labels) > 1:
                    self.logger.debug(
                        "Generated multiple labels for download MTU test; expected only one.")
                    return False
            self.logger.debug(
                f"Download MTU test failed for {mtu} bytes to {dns_server}:{dns_port} for domain {domain}.")
            return False

        except Exception as e:
            self.logger.debug(
                f"Error during download MTU test to {dns_server}:{dns_port} for domain {domain}: {e}")
            return False

    async def test_download_mtu(self, domain: str, dns_server: str, dns_port: int, max_mtu: int, max_upload_chars: int) -> int:
        """
        Determine the optimal download MTU for DNS tunneling using binary search.
        Returns the highest MTU value that succeeds, or 0 if none succeed.
        """
        min_mtu = 0
        max_mtu_candidate = max_mtu
        optimal_mtu = 0
        self.logger.info(
            f"[Download MTU Test] Starting download MTU test to {dns_server}:{dns_port} for domain '{domain}' ...")
        try:
            # Initial attempt with the maximum MTU
            self.logger.debug(
                f"[Download MTU Test] Attempting initial test with {max_mtu_candidate} bytes to {dns_server}:{dns_port} for domain '{domain}'")
            if await self.perform_download_mtu_test(domain, dns_server, dns_port, max_mtu_candidate, max_upload_chars):
                self.logger.success(
                    f"[Download MTU Test] Maximum MTU <g>{max_mtu_candidate}</g> bytes is supported by {dns_server}:{dns_port} for domain '{domain}'")
                return max_mtu_candidate
            else:
                max_mtu_candidate -= 1

            # Binary search for the highest working MTU
            while min_mtu <= max_mtu_candidate:
                current_mtu = (min_mtu + max_mtu_candidate) // 2
                self.logger.debug(
                    f"[Download MTU Test] Testing <y>{current_mtu}</y> bytes to {dns_server}:{dns_port} for domain '{domain}'")

                if current_mtu < 30:
                    self.logger.debug(
                        f"[Download MTU Test] Current MTU {current_mtu} bytes is below minimum threshold. Ending test.")
                    break

                if await self.perform_download_mtu_test(domain, dns_server, dns_port, current_mtu, max_upload_chars):
                    optimal_mtu = current_mtu
                    min_mtu = current_mtu + 1
                    self.logger.debug(
                        f"[Download MTU Test] Success at {current_mtu} bytes. Trying higher...")
                else:
                    max_mtu_candidate = current_mtu - 1
                    self.logger.debug(
                        f"[Download MTU Test] Failure at {current_mtu} bytes. Trying lower...")

            if optimal_mtu > 29:
                return optimal_mtu

            return 0
        except Exception as exc:
            self.logger.error(
                f"[Download MTU Test] Exception occurred while testing download MTU to {dns_server}:{dns_port} for domain '{domain}': {exc}")
            return 0

    async def test_all_mtu(self) -> None:
        """Test MTU for all domain-resolver combinations."""
        for connection in self.connections_map:
            domain = connection.get("domain")
            resolver = connection.get("resolver")
            dns_server = resolver
            dns_port = 53
            upload_mtu = self.max_upload_mtu

            isValid, mtu_bytes, mtu_char_len = await self.test_upload_mtu(
                domain=domain,
                dns_server=dns_server,
                dns_port=dns_port,
                default_mtu=upload_mtu
            )

            if isValid and self.min_upload_mtu > 0 and mtu_bytes < self.min_upload_mtu:
                self.logger.error(
                    f"Upload MTU {mtu_bytes} bytes is below minimum threshold of {self.min_upload_mtu} bytes for {dns_server}:{dns_port} and domain <g>{domain}</g>")
                isValid = False
                connection["is_valid"] = False
                connection["upload_mtu_bytes"] = 0
                connection["upload_mtu_chars"] = 0
                connection['packet_loss'] = 100
                continue

            if isValid:
                self.logger.success(
                    f"Upload MTU test successful: <g>{mtu_bytes}</g> bytes to <g>{dns_server}:{dns_port}</g> for domain <g>{domain}</g>")
                connection["is_valid"] = True
                connection["upload_mtu_bytes"] = mtu_bytes
                connection["upload_mtu_chars"] = mtu_char_len
                connection['packet_loss'] = 0
            else:
                self.logger.error(
                    f"Upload MTU test failed for {dns_server}:{dns_port} and domain <g>{domain}</g>")
                connection["is_valid"] = False
                connection["upload_mtu_bytes"] = 0
                connection["upload_mtu_chars"] = 0
                connection['packet_loss'] = 100

            if not connection["is_valid"]:
                continue

        lowest_upload_mtu, lowest_upload_mtu_chars, all_invalid = None, None, True
        for connection in self.connections_map:
            if connection.get("is_valid", False):
                all_invalid = False
                mtu_bytes = connection.get("upload_mtu_bytes", 0)
                mtu_chars = connection.get("upload_mtu_chars", 0)
                if lowest_upload_mtu is None or mtu_bytes < lowest_upload_mtu:
                    lowest_upload_mtu = mtu_bytes
                    lowest_upload_mtu_chars = mtu_chars

        if all_invalid:
            self.logger.error(
                "All domain-resolver combinations failed MTU tests.")
            return

        self.logger.warning("=" * 80)
        self.logger.success(
            f"<cyan>Lowest upload MTU across all valid connections: <g>{lowest_upload_mtu}</g> bytes ({lowest_upload_mtu_chars} characters)</cyan>")
        self.logger.warning("=" * 80)

        self.logger.info(
            "Beginning download MTU tests for all valid domain-resolver combinations..."
        )

        for connection in self.connections_map:
            if not connection.get("is_valid", False):
                continue
            domain = connection.get("domain")
            resolver = connection.get("resolver")
            dns_server = resolver
            dns_port = 53
            connection['total_packets'] = 0

            download_mtu = await self.test_download_mtu(
                domain=domain,
                dns_server=dns_server,
                dns_port=dns_port,
                max_mtu=self.max_download_mtu,
                max_upload_chars=lowest_upload_mtu_chars
            )

            if self.min_download_mtu > 0 and download_mtu < self.min_download_mtu:
                self.logger.error(
                    f"Download MTU {download_mtu} bytes is below minimum threshold of {self.min_download_mtu} bytes for {dns_server}:{dns_port} and domain <g>{domain}</g>")
                connection["is_valid"] = False
                connection["download_mtu_bytes"] = 0
                continue

            if download_mtu > 0:
                self.logger.success(
                    f"Download MTU test successful: <g>{download_mtu}</g> bytes to <g>{dns_server}:{dns_port}</g> for domain <g>{domain}</g>")
                connection["download_mtu_bytes"] = download_mtu
            else:
                self.logger.error(
                    f"Download MTU test failed for {dns_server}:{dns_port} and domain <g>{domain}</g>")
                connection["is_valid"] = False
                connection["download_mtu_bytes"] = 0

        lowest_download_mtu, all_invalid = None, True
        for connection in self.connections_map:
            if connection.get("is_valid", False):
                all_invalid = False
                mtu_bytes = connection.get("download_mtu_bytes", 0)
                if lowest_download_mtu is None or mtu_bytes < lowest_download_mtu:
                    lowest_download_mtu = mtu_bytes
        if all_invalid:
            self.logger.error(
                "All domain-resolver combinations failed download MTU tests.")
            return

        self.logger.warning("=" * 80)
        self.logger.success(
            f"<cyan>Lowest download MTU across all valid connections: <g>{lowest_download_mtu}</g> bytes</cyan>")

        self.max_download_mtu = lowest_download_mtu
        self.max_upload_mtu = lowest_upload_mtu

        self.logger.warning("=" * 80)
        self.logger.warning(
            f"<green>MTU tests completed.</green> <cyan>For optimal performance, please remove any invalid or slow resolvers from your configuration, you can set the <yellow>MIN_UPLOAD_MTU</yellow> and <yellow>MIN_DOWNLOAD_MTU</yellow> values to filter out low MTU resolvers automatically.</cyan>")
        self.logger.warning(
            f"<green>You can set the <yellow>MAX_UPLOAD_MTU</yellow> to <blue>{self.max_upload_mtu}</blue> and <yellow>MAX_DOWNLOAD_MTU</yellow> to <blue>{self.max_download_mtu}</blue> in your configuration for best results.</green>"
        )
        self.logger.warning("=" * 80)

    async def send_new_session_request(self, connection: dict, retry_id: int = 0) -> bool:
        """Send a new session request to the server."""
        domain = connection.get("domain")
        resolver = connection.get("resolver")
        dns_server = resolver
        dns_port = 53

        if retry_id >= 3:
            self.logger.error(
                f"Exceeded maximum retries for new session request to {dns_server}:{dns_port} for domain '{domain}'.")
            return False

        self.logger.debug(
            f"Sending new session request to {dns_server}:{dns_port} for domain '{domain}'...")

        random_bytes = generate_random_hex_text(random.randint(2, 5)).lower()

        labels = self.dns_packet_parser.generate_labels(
            domain=domain,
            session_id=random.randint(0, 255),
            packet_type=PACKET_TYPES["NEW_SESSION"],
            data=random_bytes,
            mtu_chars=self.max_upload_mtu,
            encode_data=False
        )

        if labels is None or len(labels) == 0:
            self.logger.error("Failed to generate labels for new session.")
            return await self.send_new_session_request(connection, retry_id=retry_id + 1)

        label = labels[0]
        new_session_packet = await self.dns_packet_parser.simple_question_packet(
            domain=label,
            qType=RESOURCE_RECORDS["TXT"]
        )

        response_bytes, response_parsed, addr = await self.dns_request(
            dns_server, dns_port, new_session_packet, timeout=10.0)

        if response_bytes is None or response_parsed is None:
            self.logger.error(
                f"No response received for new session request to {dns_server}:{dns_port} for domain '{domain}', retrying...")
            return await self.send_new_session_request(connection, retry_id=retry_id + 1)

        is_VPN_packet, session_id, packet_type, answers = await self.parse_dns_response(
            response_parsed)

        if not is_VPN_packet:
            self.logger.error(
                f"Invalid VPN packet received for new session request to {dns_server}:{dns_port} for domain '{domain}', retrying...")
            return await self.send_new_session_request(connection, retry_id=retry_id + 1)

        if packet_type != PACKET_TYPES["NEW_SESSION"]:
            self.logger.error(
                f"Unexpected packet type received for new session request to {dns_server}:{dns_port} for domain '{domain}', retrying...")
            return await self.send_new_session_request(connection, retry_id=retry_id + 1)

        if session_id is None:
            self.logger.error(
                f"No session ID received for new session request to {dns_server}:{dns_port} for domain '{domain}', retrying...")
            return await self.send_new_session_request(connection, retry_id=retry_id + 1)

        decoded_response = self.dns_packet_parser.codec_transform(
            answers, encrypt=False)

        if decoded_response is None:
            self.logger.error(
                f"Failed to decode response for new session request to {dns_server}:{dns_port} for domain '{domain}', retrying...")
            return await self.send_new_session_request(connection, retry_id=retry_id + 1)

        session_id_int = 0
        try:
            if isinstance(decoded_response, bytes):
                try:
                    decoded_str = decoded_response.decode('ascii')
                    session_id_int = int(decoded_str)
                except Exception:
                    session_id_int = int.from_bytes(
                        decoded_response, byteorder='big')
            else:
                session_id_int = int(decoded_response)
        except Exception:
            session_id_int = decoded_response

        if session_id_int != session_id:
            self.logger.error(
                f"Session ID mismatch for new session request to {dns_server}:{dns_port} for domain '{domain}', retrying...")
            return await self.send_new_session_request(connection, retry_id=retry_id + 1)

        self.session_id = session_id_int
        self.logger.success(
            f"New session established with Session ID: <g>{self.session_id}</g>")
        return True

    async def new_session(self) -> None:
        """Create a new VPN session."""
        self.logger.info("Creating a new VPN session...")
        selected_connection = await self.select_connection()
        if selected_connection is None:
            self.logger.error(
                "Failed to select a valid connection, Looks like all connections are invalid.")
            return None
        success = await self.send_new_session_request(selected_connection)
        if not success:
            self.logger.error("Failed to send new session request.")
            return None
        self.logger.success("New VPN session created successfully.")
        return selected_connection

    async def start(self) -> None:
        """Start the MasterDnsVPN Client."""
        try:
            self.logger.info("=" * 80)
            self.logger.success("Starting MasterDnsVPN Client...")

            self.logger.debug(f"Checking configuration...")
            if not self.domains:
                self.logger.error("No domains configured for DNS tunneling.")
                return

            if not self.resolvers:
                self.logger.error("No DNS resolvers configured.")
                return

            if self.encryption_method is None or self.encryption_key is None:
                self.logger.error("Encryption method or key not configured.")
                return

            self.logger.debug(f"Configuration looks good.")
            self.logger.success("MasterDnsVPN Client started successfully.")
            self.logger.info("=" * 80)

            self.logger.info(
                "Beginning MTU tests for all domain-resolver combinations...")
            await self.test_all_mtu()

            new_session = await self.new_session()
            if new_session is None:
                self.logger.error("Failed to create a new VPN session.")
                return
        except asyncio.CancelledError:
            self.logger.info("MasterDnsVPN Client is stopping...")
        except Exception as e:
            self.logger.error(f"Error in MasterDnsVPN Client: {e}")


def main():
    client = MasterDnsVPNClient()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        loop.run_until_complete(client.start())
    except KeyboardInterrupt:
        print("\n\033[91m[!] Forced shutdown requested...\033[0m")
    finally:
        try:
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
        except:
            pass
        os._exit(0)


if __name__ == "__main__":
    main()
