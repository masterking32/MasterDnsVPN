# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import sys
import socket
import asyncio
import signal
from typing import Optional, Any

from dns_utils.utils import getLogger
from client_config import master_dns_vpn_config
from dns_utils.DnsPacketParser import DnsPacketParser
from dns_utils.UDPClient import UDPClient

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
        self.domains = self.config.get("DOMAIN")
        self.encryption_method = self.config.get(
            "DATA_ENCRYPTION_METHOD", None)
        self.encryption_key = self.config.get("ENCRYPTION_KEY", None)
        self.dns_packet_parser = DnsPacketParser(
            logger=self.logger,
            encryption_method=self.encryption_method,
            encryption_key=self.encryption_key,
        )

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

        test_packet = await self.dns_packet_parser.simple_question_packet(
            domain="google.com",
            qtype="A"
        )

        # server ip : 127.0.0.1:53

        self.logger.info("MasterDnsVPN Client started successfully.")
        response_bytes, response_parsed, addr = await self.dns_request('127.0.0.1', 53, test_packet)
        self.logger.debug(f"Test DNS question packet: {test_packet}")
        self.logger.debug(f"Response bytes: {response_bytes}")
        self.logger.debug(f"Response parsed: {response_parsed}")
        # @TODO: TEST connectivity to resolvers and domains
        # @TODO: Find MTU for each resolver


def main():
    """Main function to start the MasterDnsVPN Client."""
    client = MasterDnsVPNClient()

    try:
        asyncio.run(client.start())
    except KeyboardInterrupt:
        print("MasterDnsVPN Client stopped by user.")


if __name__ == "__main__":
    main()
