# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import random
import sys
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
        self.encryption_method: int = self.config.get(
            "DATA_ENCRYPTION_METHOD", 1)
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
                self.logger.error("Failed to connect UDP client.")
                return None, None, None
            if not udp_client.send_bytes(data):
                self.logger.error("Failed to send DNS request.")
                return None, None, None
            response_bytes, addr = udp_client.receive_bytes()
            if response_bytes is None:
                self.logger.error("No response received from DNS server.")
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

            name = answer.get("name", "")
            txt_rData = answer.get("rData", b"")

            if "." in name:
                vpn_packet_header = name.split(".")[0]
                name = name[len(vpn_packet_header) + 1:]

            txt_data = self.dns_packet_parser.extract_txt_from_rData(txt_rData)
            final_answers.append({
                "name": name,
                "rData": txt_rData,
                "txt": txt_data
            })

        if len(final_answers) == 0 or vpn_packet_header is None:
            self.logger.debug(
                f"Extracted VPN packet header: {vpn_packet_header}")
            return False, False, False, False

        final_answers.sort(key=lambda x: x["name"])
        extracted_header = self.dns_packet_parser.decode_and_decrypt_data(
            vpn_packet_header, lowerCaseOnly=True)

        if len(extracted_header) != 2:
            self.logger.error(
                f"Invalid VPN packet header length: {len(extracted_header)}")
            return False, False, False, False

        session_id = extracted_header[0]
        packet_type = extracted_header[1]

        if packet_type not in PACKET_TYPES.values():
            self.logger.error(f"Unknown packet type: {packet_type}")
            return False, False, False, False

        is_VPN_packet = True
        merged_answers = "".join(
            [answer["txt"] for answer in final_answers])
        return is_VPN_packet, session_id, packet_type, merged_answers

    async def test_upload_mtu(self, domain: str, dns_server: str, dns_port: int, default_mtu: int) -> tuple:
        """Test and determine the optimal upload MTU for DNS tunneling."""
        try:
            while True:
                if (default_mtu <= 30 and default_mtu != 0) or default_mtu > 512:
                    self.logger.error(
                        f"Upload MTU test failed: Could not determine optimal MTU to {dns_server}:{dns_port} for domain {domain}")
                    return False, 0, 0

                mtu_char_len, mtu_bytes = self.dns_packet_parser.calculate_upload_mtu(
                    domain=domain,
                    mtu=default_mtu
                )

                default_mtu = mtu_bytes - 1

                self.logger.debug(
                    f"Testing upload MTU: {mtu_bytes} bytes ({mtu_char_len} characters) to {dns_server}:{dns_port} for domain {domain}")

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
                            self.logger.success(
                                f"Upload MTU test successful: <g>{mtu_bytes}</g> bytes to <g>{dns_server}:{dns_port}</g> for domain <g>{domain}</g>")
                            return True, mtu_bytes, mtu_char_len
                elif len(labels) == 0:
                    self.logger.error(
                        "Failed to generate labels for MTU test.")
                    return False, 0, 0
                elif len(labels) > 1:
                    self.logger.error(
                        "Generated multiple labels for MTU test; expected only one.")

                self.logger.warning(
                    f"Upload MTU test failed for {mtu_bytes} bytes to {dns_server}:{dns_port} for domain {domain}. Retrying with lower MTU...")

        except Exception as e:
            self.logger.error(
                f"Error during upload MTU test to {dns_server}:{dns_port} for domain {domain}: {e}")

        return False, 0, 0

    async def perform_download_mtu_test(self, domain: str, dns_server: str, dns_port: int, mtu: int, max_upload_chars: int) -> bool:
        """Perform a single download MTU test."""
        try:
            # convert mtu to bytes
            mtu_bytes = mtu.to_bytes(2, byteorder='big')
            mtu_encrypt = self.dns_packet_parser.data_encrypt(data=mtu_bytes)
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
                        answers_decode = self.dns_packet_parser.base_decode(
                            answers, False)

                        if ".".encode() not in answers_decode:
                            self.logger.error(
                                "Download MTU test failed: Invalid response format.")
                            return False
                        received_mtu_encrypted, _ = answers_decode.split(
                            b".", 1)
                        received_mtu_decrypted = self.dns_packet_parser.data_decrypt(
                            received_mtu_encrypted)

                        if received_mtu_decrypted == mtu_bytes:
                            self.logger.info(
                                f"Download MTU test successful for {mtu} bytes to {dns_server}:{dns_port} for domain {domain}.")
                            return True
                elif len(labels) == 0:
                    self.logger.error(
                        "Failed to generate labels for download MTU test.")
                    return False
                elif len(labels) > 1:
                    self.logger.error(
                        "Generated multiple labels for download MTU test; expected only one.")
                    return False
            self.logger.warning(
                f"Download MTU test failed for {mtu} bytes to {dns_server}:{dns_port} for domain {domain}.")
            return False

        except Exception as e:
            self.logger.error(
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
                self.logger.success(
                    f"[Download MTU Test] Optimal download MTU determined: <g>{optimal_mtu}</g> bytes to <g>{dns_server}:{dns_port}</g> for domain <g>{domain}</g>")
                return optimal_mtu

            self.logger.error(
                f"[Download MTU Test] Failed to determine a valid download MTU for {dns_server}:{dns_port} and domain '{domain}'")
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

            if isValid:
                connection["is_valid"] = True
                connection["upload_mtu_bytes"] = mtu_bytes
                connection["upload_mtu_chars"] = mtu_char_len
                connection['packet_loss'] = 0
            else:
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
        self.logger.success(
            f"Lowest upload MTU across all valid connections: <g>{lowest_upload_mtu}</g> bytes ({lowest_upload_mtu_chars} characters)")
        self.logger.warning(
            "<y>For optimal performance, please remove any invalid or slow resolvers from your configuration.</y>")

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

            download_mtu = await self.test_download_mtu(
                domain=domain,
                dns_server=dns_server,
                dns_port=dns_port,
                max_mtu=self.max_download_mtu,
                max_upload_chars=lowest_upload_mtu_chars
            )

            if download_mtu > 0:
                connection["download_mtu_bytes"] = download_mtu
            else:
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

        self.logger.success(
            f"Lowest download MTU across all valid connections: <g>{lowest_download_mtu}</g> bytes")

        self.max_download_mtu = lowest_download_mtu
        self.max_upload_mtu = lowest_upload_mtu

    async def start(self) -> None:
        """Start the MasterDnsVPN Client."""
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

        self.logger.info(
            "Beginning MTU tests for all domain-resolver combinations...")
        await self.test_all_mtu()


def main():
    """Main function to start the MasterDnsVPN Client."""
    client = MasterDnsVPNClient()

    try:
        asyncio.run(client.start())
    except KeyboardInterrupt:
        print("MasterDnsVPN Client stopped by user.")


if __name__ == "__main__":
    main()
