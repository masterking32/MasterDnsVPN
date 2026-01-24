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
from dns_utils.DNS_ENUMS import PACKET_TYPES, RESOURCE_RECORDS

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

    async def dns_request(self, server_host: str, server_port: int, data: bytes, timeout: float = 5.0):
        """Send a DNS request to the specified server and port using asyncio DatagramProtocol."""
        self.logger.debug(
            f"Sending DNS request to {server_host}:{server_port}, data length: {len(data)} bytes")
        udp_client = UDPClient(
            logger=self.logger,
            server_host=server_host,
            server_port=server_port,
            timeout=timeout
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

    async def test_upload_mtu(self, domain, dns_server: str, dns_port: int, default_mtu: int) -> None:
        """Test and determine the optimal upload MTU for DNS tunneling."""
        try:
            mtu_char_len, mtu_bytes = self.dns_packet_parser.calculate_upload_mtu(
                domain=domain,
                mtu=default_mtu
            )

            while True:
                self.logger.debug(
                    f"Testing upload MTU: {mtu_bytes} bytes ({mtu_char_len} characters) to {dns_server}:{dns_port} for domain {domain}")

                random_hex = generate_random_hex_text(mtu_char_len).lower()
                labels = self.dns_packet_parser.data_to_labels(random_hex)

                header_packet = self.dns_packet_parser.create_vpn_header(
                    session_id=random.randint(0, 255),
                    packet_type=PACKET_TYPES["SERVER_TEST"],
                )

                labels += "." + header_packet + "." + domain
                test_packet = await self.dns_packet_parser.simple_question_packet(
                    domain=labels,
                    qType=RESOURCE_RECORDS["TXT"]
                )

                response_bytes, response_parsed, addr = await self.dns_request(
                    dns_server, dns_port, test_packet)
                self.logger.debug(
                    f"Upload MTU test response bytes: {response_bytes}")

                # validate response
                if True:
                    return
                mtu_char_len = mtu_char_len - 1
                return

        except Exception as e:
            self.logger.error(f"Error during upload MTU test: {e}")

    async def test_all_mtu(self) -> None:
        """Test MTU for all domain-resolver combinations."""
        for connection in self.connections_map:
            domain = connection.get("domain")
            resolver = connection.get("resolver")
            dns_server = resolver.get("address")
            dns_port = resolver.get("port", 53)
            mtu = resolver.get("WRITE_MTU", 0)

            await self.test_upload_mtu(
                domain=domain,
                dns_server=dns_server,
                dns_port=dns_port,
                default_mtu=mtu
            )

    async def start(self) -> None:
        """Start the MasterDnsVPN Client."""
        self.logger.info("Starting MasterDnsVPN Client...")

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
        self.logger.info("MasterDnsVPN Client started successfully.")

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
