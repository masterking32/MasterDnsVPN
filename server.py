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


class MasterDnsVPNServer:
    """MasterDnsVPN Server class to handle DNS requests over UDP."""

    def __init__(self) -> None:
        """Initialize the MasterDnsVPNServer with configuration and logger."""
        self.config = load_json("server_config.json")
        self.logger = getLogger(log_level=self.config.get("log_level", "INFO"))
        self.udp_sock: Optional[socket.socket] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.should_stop = asyncio.Event()
        self.vpn_packet_sign = self.config.get("vpn_packet_sign", "0032")
        self.allowed_domains = self.config.get("domain", [])

        self.recv_data_cache = {}
        self.send_data_cache = {}
        self.dns_parser = dns_packet_parser(logger=self.logger)

    async def solve_dns(self, query: bytes) -> bytes:
        """
        Solve DNS query by forwarding it to configured DNS servers asynchronously.
        """
        for dns_server in self.config.get('dns_servers', []):
            try:
                if self.udp_sock is None or self.udp_sock.fileno() == -1:
                    self.logger.warning(
                        "UDP socket is closed. Exiting DNS solving.")
                    return b''

                self.logger.debug(f"Forwarding DNS query to {dns_server}")
                loop = asyncio.get_running_loop()
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.setblocking(False)
                    await loop.sock_sendto(sock, query, (dns_server, 53))
                    try:
                        response, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 512), timeout=10)
                    except asyncio.TimeoutError:
                        self.logger.error(
                            f"Timeout waiting for response from {dns_server}")
                        continue
                    self.logger.debug(
                        f"Received DNS response from {dns_server}")
                    return response
            except Exception as e:
                self.logger.error(
                    f"Failed to get response from {dns_server}: {e}")
        self.logger.error("All DNS servers failed to respond.")
        return b''

    async def is_vpn_packet(self, parsed_packet: dict) -> bool:
        """
        Check if the DNS packet is a VPN packet based on a specific signature.
        """

        if not parsed_packet.get('additionals'):
            return False

        for additional in parsed_packet['additionals']:
            rdata = additional.get('rdata', b'')
            if len(rdata) >= 2 and rdata[-2:].hex() == self.vpn_packet_sign:
                return True

        return False

    async def handle_vpn_packet(self, parsed_packet: dict, addr) -> None:
        """
        Handle VPN packet logic.
        """
        try:
            self.logger.info(f"Handling VPN packet from {addr}")
            if not parsed_packet.get('questions'):
                self.logger.error(
                    f"No questions found in VPN packet from {addr}")
                return

            packet_main_domain = ''
            packet_domain = parsed_packet['questions']['qname']

            for domain in self.allowed_domains:
                if packet_domain.endswith(domain):
                    packet_main_domain = domain
                    break

            if not packet_main_domain:
                self.logger.warning(
                    f"Domain {packet_domain} not allowed for VPN packets from {addr}")
                return

            input_data = packet_domain.replace('.' + packet_main_domain, '')
            self.logger.debug(
                f"Extracted VPN data from domain {packet_domain}: {input_data}")

        except Exception as e:
            self.logger.error(f"Error handling VPN packet from {addr}: {e}")

    async def handle_single_request(self, data, addr):
        """
        Handle a single DNS request in its own task.
        """
        if data is None or addr is None:
            self.logger.error("Invalid data or address in DNS request.")
            return

        self.logger.debug(f"Received DNS request from {addr}")
        parsed_packet = await self.dns_parser.parse_dns_packet(data)
        self.logger.debug(
            f"Parsed DNS packet from {addr}: {parsed_packet}")

        if await self.is_vpn_packet(parsed_packet):
            self.logger.debug(
                f"VPN packet detected from {addr}, processing accordingly.")
            await self.handle_vpn_packet(parsed_packet, addr)
            return

        # Normal DNS query processing
        response = await self.solve_dns(data)
        if not response:
            self.logger.error(
                f"No response generated for DNS request from {addr}")
            return

        try:
            self.udp_sock.sendto(response, addr)
            self.logger.debug(f"Sent DNS response to {addr}")
        except Exception as e:
            self.logger.error(
                f"Failed to send DNS response to {addr}: {e}")

    async def handle_dns_requests(self) -> None:
        """
        Asynchronously handle incoming DNS requests and spawn a new task for each.
        """
        assert self.udp_sock is not None, "UDP socket is not initialized."
        assert self.loop is not None, "Event loop is not initialized."
        self.udp_sock.setblocking(False)
        while not self.should_stop.is_set():
            try:
                data, addr = await self.loop.sock_recvfrom(self.udp_sock, 512)
            except OSError as e:
                self.logger.error(
                    f"Socket error: {e}. Exiting DNS request handler.")
                break
            except Exception as e:
                self.logger.exception(
                    f"Unexpected error receiving DNS request: {e}")
                continue
            # Spawn a new task for each request
            self.loop.create_task(self.handle_single_request(data, addr))

    def _signal_handler(self, signum: int, frame: Any = None) -> None:
        """
        Handle termination signals for graceful shutdown.
        """
        self.logger.info(
            f"Received signal {signum}, shutting down MasterDnsVPN Server ...")
        if self.loop and not self.loop.is_closed():
            self.loop.call_soon_threadsafe(self.should_stop.set)
        if self.udp_sock:
            try:
                self.udp_sock.close()
            except Exception as e:
                self.logger.error(f"Error closing UDP socket: {e}")

    def dns_loop(self) -> None:
        """
        Start the main DNS handling event loop.
        """
        self.logger.debug("Entering MasterDnsVPN DNS handling loop ...")
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        # Register signal handlers for graceful shutdown (only in main thread)
        import threading
        if threading.current_thread() is threading.main_thread():
            try:
                for sig in (signal.SIGINT, signal.SIGTERM):
                    self.loop.add_signal_handler(
                        sig, lambda sig=sig: self._signal_handler(sig))
            except NotImplementedError:
                # Fallback for platforms that do not support add_signal_handler (e.g., Windows)
                signal.signal(signal.SIGINT, self._signal_handler)
                signal.signal(signal.SIGTERM, self._signal_handler)

        try:
            self.loop.run_until_complete(self.handle_dns_requests())
        except Exception as e:
            self.logger.exception(f"Exception in DNS loop: {e}")
        finally:
            if self.udp_sock:
                try:
                    self.udp_sock.close()
                except Exception as e:
                    self.logger.error(f"Error closing UDP socket: {e}")
            self.loop.close()
            self.logger.info("Event loop closed. Server shutdown complete.")

    def start(self) -> None:
        """
        Start the MasterDnsVPN server: bind UDP socket and enter DNS loop.
        """
        self.logger.info("MasterDnsVPN Server starting ...")
        try:
            self.logger.debug("Binding UDP socket ...")
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_sock.bind((self.config.get("udp_host", "0.0.0.0"),
                                self.config.get("udp_port", 53)))
            self.logger.info(
                f"UDP socket bound on {self.config.get('udp_host', '0.0.0.0')}:{self.config.get('udp_port', 53)}")
            self.logger.info("MasterDnsVPN Server started successfully.")
            self.dns_loop()
        except Exception as e:
            self.logger.exception(f"Failed to start MasterDnsVPN Server: {e}")
            if self.udp_sock:
                try:
                    self.udp_sock.close()
                except Exception:
                    pass


def main() -> None:
    """
    Entry point for the MasterDnsVPN server.
    """
    server = MasterDnsVPNServer()
    server.start()


if __name__ == "__main__":
    main()
