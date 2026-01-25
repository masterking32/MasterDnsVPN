# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import random
import sys
import socket
import asyncio
from typing import Optional

from dns_utils.utils import getLogger, generate_random_hex_text
from client_config import master_dns_vpn_config
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
        """Initialize the MasterDnsVPNClient with configuration and logger."""
        self.udp_sock: Optional[socket.socket] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.should_stop = asyncio.Event()

        self.config = master_dns_vpn_config.__dict__
        self.logger = getLogger(log_level=self.config.get("LOG_LEVEL", "INFO"))
        self.resolvers = self.config.get("RESOLVER_DNS_SERVERS", [])
        self.domains = self.config.get("DOMAINS", [])
        self.timeout = self.config.get("DNS_QUERY_TIMEOUT", 10.0)
        self.max_upload_mtu = self.config.get("MAX_UPLOAD_MTU", 512)
        self.max_download_mtu = self.config.get("MAX_DOWNLOAD_MTU", 4096)
        self.encryption_method = self.config.get(
            "DATA_ENCRYPTION_METHOD", 1)
        self.encryption_key = self.config.get("ENCRYPTION_KEY", None)
        if not self.encryption_key:
            self.logger.error("No encryption key provided in configuration.")
            sys.exit(1)

        self.dns_packet_parser = DnsPacketParser(
            logger=self.logger,
            encryption_method=self.encryption_method,
            encryption_key=self.encryption_key,
        )

        # Build a map of all domain-resolver combinations
        self.connections_map = [
            {"domain": domain, "resolver": resolver}
            for domain in self.domains
            for resolver in self.resolvers
        ]

    async def dns_request(self, server_host: str, server_port: int, data: bytes):
        """Send a DNS request to the specified server and port using asyncio DatagramProtocol."""
        self.logger.debug(
            f"Sending DNS request to {server_host}:{server_port}, data length: {len(data)} bytes")
        udp_client = UDPClient(
            logger=self.logger,
            server_host=server_host,
            server_port=server_port,
            timeout=self.timeout,
        )

        if not udp_client.connect():
            self.logger.error("Failed to connect UDP client.")
            return None, None, None

        if not udp_client.send_bytes(data):
            self.logger.error("Failed to send DNS request.")
            udp_client.close()
            return None, None, None

        response_bytes, addr = udp_client.receive_bytes()
        if response_bytes is None:
            self.logger.error("No response received from DNS server.")
            udp_client.close()
            return None, None, None

        response_parsed = await self.dns_packet_parser.parse_dns_packet(
            response_bytes)
        udp_client.close()
        return response_bytes, response_parsed, addr

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
            txt_data = answer.get("rData", b"")

            if "." in name:
                vpn_packet_header = name.split(".")[0]
                name = name[len(vpn_packet_header) + 1:]

            final_answers.append({
                "name": name,
                "rData": txt_data
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
        return is_VPN_packet, session_id, packet_type, final_answers

    async def test_upload_mtu(self, domain, dns_server: str, dns_port: int, default_mtu: int) -> tuple:
        """Test and determine the optimal upload MTU for DNS tunneling."""
        try:
            while True:
                if (default_mtu <= 30 and default_mtu != 0) or default_mtu > 512:
                    self.logger.error(
                        f"Upload MTU test failed: Could not determine optimal MTU to {dns_server}:{dns_port} for domain {domain}")
                    return False, 0

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
                    packet_type=PACKET_TYPES["SERVER_TEST"],
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
                        dns_server, dns_port, test_packet)

                    if response_bytes is not None and response_parsed is not None:
                        is_VPN_packet, session_id, packet_type, answers = await self.parse_dns_response(
                            response_parsed)

                        if is_VPN_packet and packet_type == PACKET_TYPES["SERVER_TEST"]:
                            self.logger.success(
                                f"Upload MTU test successful: <g>{mtu_bytes}</g> bytes to <g>{dns_server}:{dns_port}</g> for domain <g>{domain}</g>")
                            return True, mtu_bytes
                elif len(labels) == 0:
                    self.logger.error(
                        "Failed to generate labels for MTU test.")
                    return False, 0
                elif len(labels) > 1:
                    self.logger.error(
                        "Generated multiple labels for MTU test; expected only one.")

                self.logger.warning(
                    f"Upload MTU test failed for {mtu_bytes} bytes to {dns_server}:{dns_port} for domain {domain}. Retrying with lower MTU...")

        except Exception as e:
            self.logger.error(f"Error during upload MTU test: {e}")

    async def test_all_mtu(self) -> None:
        """Test MTU for all domain-resolver combinations."""
        for connection in self.connections_map:
            domain = connection.get("domain")
            resolver = connection.get("resolver")
            dns_server = resolver
            dns_port = 53
            upload_mtu = self.max_upload_mtu

            isValid, mtu_bytes = await self.test_upload_mtu(
                domain=domain,
                dns_server=dns_server,
                dns_port=dns_port,
                default_mtu=upload_mtu
            )

            if isValid:
                connection["is_valid"] = True
                connection["mtu_bytes"] = mtu_bytes
            else:
                connection["is_valid"] = False
                connection["mtu_bytes"] = 0

            if not connection["is_valid"]:
                continue

            # TODO Test download MTU here similarly

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
