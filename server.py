# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import sys
import socket
import asyncio
import signal
import random
from typing import Optional, Any

from server_config import master_dns_vpn_config

from dns_utils.utils import getLogger, get_encrypt_key
from dns_utils.DnsPacketParser import DnsPacketParser
from dns_utils.DNS_ENUMS import PACKET_TYPES, Q_CLASSES, RESOURCE_RECORDS

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
        self.udp_sock: Optional[socket.socket] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.should_stop = asyncio.Event()

        self.config = master_dns_vpn_config.__dict__
        self.logger = getLogger(log_level=self.config.get("LOG_LEVEL", "INFO"))
        self.vpn_packet_sign = self.config.get("VPN_PACKET_SIGN", "0032")
        self.allowed_domains = self.config.get("DOMAIN", [])

        self.recv_data_cache = {}
        self.send_data_cache = {}

        # Generate or load encryption key
        self.encrypt_key = get_encrypt_key(
            self.config.get("DATA_ENCRYPTION_METHOD", 1))
        self.logger.warning(
            f"Using encryption key: <green>{self.encrypt_key}</green>")

        self.dns_parser = DnsPacketParser(logger=self.logger,
                                          encryption_method=self.config.get(
                                              "DATA_ENCRYPTION_METHOD", 1),
                                          encryption_key=self.encrypt_key)

    async def solve_dns(self, query: bytes) -> bytes:
        """
        Solve DNS query by forwarding it to configured DNS servers asynchronously.
        """

        if not query:
            self.logger.error("Empty DNS query received.")
            return b''

        if not self.config.get("DNS_SERVERS"):
            self.logger.error("No DNS servers configured.")
            return b''

        dns_server = random.choice(self.config["DNS_SERVERS"])
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
                    response, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 65507), timeout=self.config.get("DNS_QUERY_TIMEOUT", 10.0))
                except asyncio.TimeoutError:
                    self.logger.error(
                        f"Timeout waiting for response from {dns_server}")
                    return b''
                self.logger.debug(
                    f"Received DNS response from {dns_server}")
                return response
        except Exception as e:
            self.logger.error(
                f"Failed to get response from {dns_server}: {e}")
        return b''

    async def handle_vpn_packet(self, data: bytes, parsed_packet: dict, addr) -> tuple[bool, Optional[bytes]]:
        """
        Handle VPN packet logic and return (is_vpn_packet, response_bytes).
        """
        try:
            self.logger.info(
                f"Handling VPN packet from {addr}")

            questions = parsed_packet.get('questions')
            if not questions:
                self.logger.error(
                    f"No questions found in VPN packet from {addr}")
                return False, None

            packet_domain = questions[0]['qName']
            packet_main_domain = next(
                (domain for domain in self.allowed_domains if packet_domain.endswith(domain)), '')

            if questions[0]['qType'] != RESOURCE_RECORDS["TXT"]:
                self.logger.warning(
                    f"Invalid DNS query type for VPN packet from {addr}: {questions[0]['qType']}")
                return False, None

            if not packet_main_domain:
                self.logger.warning(
                    f"Domain {packet_domain} not allowed for VPN packets from {addr}")
                return False, None

            if packet_domain.count('.') < 3:
                self.logger.warning(
                    f"Invalid domain format for VPN packet from {addr}: {packet_domain}")
                return False, None

            labels = packet_domain.replace(
                '.' + packet_main_domain, '')

            self.logger.debug(
                f"Extracted VPN data from domain {packet_main_domain}: {labels}")

            extracted_header = self.dns_parser.extract_vpn_header_from_labels(
                labels)
            if not extracted_header:
                self.logger.warning(
                    f"Failed to extract VPN header from labels for packet from {addr}")
                return False, None

            if len(extracted_header) != 2:
                self.logger.warning(
                    f"Invalid VPN header length from labels for packet from {addr}: {len(extracted_header)}")
                return False, None

            packet_type = extracted_header[1]
            if packet_type not in PACKET_TYPES.values():
                self.logger.warning(
                    f"Invalid VPN packet type from labels for packet from {addr}: {packet_type}")
                return False, None

            self.logger.debug(
                f"Extracted VPN header from labels: {extracted_header}")

            if packet_type == PACKET_TYPES["SERVER_UPLOAD_TEST"]:
                self.logger.info(
                    f"Received CLIENT_TEST packet from {addr}, sending SERVER_UPLOAD_TEST response.")
                txt_str = "1"
                vpn_header = self.dns_parser.create_vpn_header(
                    session_id=random.randint(0, 255),
                    packet_type=PACKET_TYPES["SERVER_UPLOAD_TEST"],
                    base36_encode=True
                ) + ".0"
                txt_bytes = bytes(
                    [len(txt_str)]) + txt_str.encode()
                response_packet = await self.dns_parser.simple_answer_packet(
                    answers=[{
                        "name": vpn_header,
                        "type": RESOURCE_RECORDS["TXT"],
                        "class": Q_CLASSES["IN"],
                        "TTL": 0,
                        "rData": txt_bytes
                    }],
                    question_packet=data
                )
                return True, response_packet
            return True, None
        except Exception as e:
            self.logger.error(
                f"Error handling VPN packet from {addr}: {e}")
            return False, None

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

        # Check for VPN packet
        vpn_packet, vpn_response = await self.handle_vpn_packet(data, parsed_packet, addr)
        if vpn_response:
            try:
                self.udp_sock.sendto(vpn_response, addr)
                self.logger.debug(f"Sent VPN DNS response to {addr}")
            except Exception as e:
                self.logger.error(
                    f"Failed to send VPN DNS response to {addr}: {e}")
            return

        if vpn_packet:
            return

        # Normal DNS query processing
        response = await self.solve_dns(data)
        if not response:
            self.logger.error(
                f"No response generated for DNS request from {addr}")
            response = await self.dns_parser.server_fail_response(data)
            if not response:
                self.logger.error(
                    f"Failed to generate Server Failure response for DNS request from {addr}")
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
            self.udp_sock.bind((self.config.get("UDP_HOST", "0.0.0.0"),
                                self.config.get("UDP_PORT", 53)))
            self.logger.info(
                f"UDP socket bound on {self.config.get('UDP_HOST', '0.0.0.0')}:{self.config.get('UDP_PORT', 53)}")
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
