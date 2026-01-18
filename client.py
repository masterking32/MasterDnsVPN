# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import sys
import socket
import asyncio
import signal
from typing import Optional, Any

from dns_utils.utils import getLogger, load_json
from dns_utils.dns_packet_parser import dns_packet_parser

# Ensure UTF-8 output for consistent logging
try:
    if sys.stdout.encoding is not None and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


class MasterDnsVPNClient:
    """MasterDnsVPN Client class to handle DNS requests over UDP."""

    def __init__(self, log_level="INFO", dns_server=None, encrypt_key=None, vpn_packet_sign=None) -> None:
        """Initialize the MasterDnsVPNClient with configuration and logger."""
        self.logger = getLogger(log_level=log_level)
        self.udp_sock: Optional[socket.socket] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.should_stop = asyncio.Event()
        self.dns_server = dns_server
        self.encrypt_key = encrypt_key
        self.vpn_packet_sign = vpn_packet_sign
        self.dns_parser = dns_packet_parser(logger=self.logger)

    async def connect(self) -> None:
        """Start the MasterDnsVPN Client."""
        if self.udp_sock is not None:
            self.logger.error("Client is already running.")
            return

        if self.dns_server is None:
            self.logger.error("DNS server is not configured.")
            return

        if self.encrypt_key is None:
            self.logger.error("Encryption key is not configured.")
            return

        if self.vpn_packet_sign is None:
            self.logger.error("VPN packet signature is not configured.")
            return

        self.logger.info("Connecting to DNS server...")
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.setblocking(False)
        self.udp_sock.settimeout(10)

        # create a packet to solve google.com
        test_query, packet = await self.dns_parser.create_packet("A", "google.com", True)

        self.logger.debug(
            f"Sending test query to DNS server: {test_query}")
        try:
            await self.loop.sock_sendto(self.udp_sock, test_query, (self.dns_server, 53))
            self.logger.debug(
                f"Sent test query to DNS server: {test_query.hex()}")
            recv_result = await asyncio.wait_for(self.loop.sock_recvfrom(self.udp_sock, 512), timeout=10)
            response = recv_result[0]
            addr = recv_result[1]
            parsed_response = await self.dns_parser.parse_dns_packet(response)
            self.logger.debug(
                f"Received response from DNS server {addr}: {parsed_response}")
            self.logger.info("Successfully connected to DNS server.")
        except Exception as e:
            self.logger.error(f"Failed to connect to DNS server: {e}")
            self.udp_sock.close()
            self.udp_sock = None


# test
if __name__ == "__main__":
    config = load_json("client_config.json")
    client = MasterDnsVPNClient(
        log_level=config.get("log_level", "INFO"),
        dns_server="127.0.0.1",
        encrypt_key="test",
        vpn_packet_sign="test"
    )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    client.loop = loop

    try:
        loop.run_until_complete(client.connect())
    except KeyboardInterrupt:
        pass
    finally:
        if client.udp_sock:
            client.udp_sock.close()
