# MasterDnsVPN Server - Professional Edition
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import sys
import socket
import asyncio
import signal
from typing import Optional, Any

from dns_utils.utils import getLogger, load_json

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

        self.recv_data_cache = {}
        self.send_data_cache = {}

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

        # last bytes of rdata in additional section
        for additional in parsed_packet['additionals']:
            rdata = additional.get('rdata', b'')
            if len(rdata) >= 2 and rdata[-2:].hex() == self.vpn_packet_sign:
                return True

        return False

    async def handle_single_request(self, data, addr):
        """
        Handle a single DNS request in its own task.
        """
        if data is None or addr is None:
            self.logger.error("Invalid data or address in DNS request.")
            return

        self.logger.debug(f"Received DNS request from {addr}")
        parsed_packet = await self.parse_dns_packet(data)
        self.logger.debug(
            f"Parsed DNS packet from {addr}: {parsed_packet}")

        if await self.is_vpn_packet(parsed_packet):
            self.logger.debug(
                f"VPN packet detected from {addr}, processing accordingly.")
            # TODO: Add VPN packet handling logic here
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

    async def parse_dns_headers(self, data: bytes) -> Any:
        """
        Parse incoming DNS packet data.
        """
        try:
            headers = {}
            headers['id'] = int.from_bytes(data[0:2], byteorder='big')
            flags = int.from_bytes(data[2:4], byteorder='big')
            headers['qr'] = (flags >> 15) & 0x1
            headers['opcode'] = (flags >> 11) & 0xF
            headers['aa'] = (flags >> 10) & 0x1
            headers['tc'] = (flags >> 9) & 0x1
            headers['rd'] = (flags >> 8) & 0x1
            headers['ra'] = (flags >> 7) & 0x1
            headers['z'] = (flags >> 4) & 0x7
            headers['rcode'] = flags & 0xF
            headers['qdcount'] = int.from_bytes(data[4:6], byteorder='big')
            headers['ancount'] = int.from_bytes(data[6:8], byteorder='big')
            headers['nscount'] = int.from_bytes(data[8:10], byteorder='big')
            headers['arcount'] = int.from_bytes(data[10:12], byteorder='big')
            return headers
        except Exception as e:
            self.logger.error(f"Failed to parse DNS headers: {e}")
            return {}

    async def parse_dns_question(self, headers: dict, data: bytes, offset: int) -> Any:
        """
        Parse the DNS question section from the packet data.
        """
        try:
            qname = []
            if headers['qdcount'] == 0:
                return None, offset

            while True:
                length = data[offset]
                if length == 0:
                    offset += 1
                    break
                offset += 1
                qname.append(data[offset:offset + length].decode('utf-8'))
                offset += length
            qtype = int.from_bytes(data[offset:offset + 2], byteorder='big')
            offset += 2
            qclass = int.from_bytes(data[offset:offset + 2], byteorder='big')
            offset += 2
            question = {
                'qname': '.'.join(qname),
                'qtype': qtype,
                'qclass': qclass
            }
            return question, offset
        except Exception as e:
            self.logger.error(f"Failed to parse DNS question: {e}")
            return None, offset

    async def parse_dns_answer(self, headers: dict, data: bytes, offset: int) -> Any:
        """
        Parse the DNS answer section from the packet data.
        """
        try:
            if headers['ancount'] == 0:
                return None, offset

            answers = []
            for _ in range(headers['ancount']):
                name = []
                while True:
                    length = data[offset]
                    if length == 0:
                        offset += 1
                        break
                    offset += 1
                    name.append(data[offset:offset + length].decode('utf-8'))
                    offset += length
                atype = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                aclass = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                ttl = int.from_bytes(data[offset:offset + 4], byteorder='big')
                offset += 4
                rdlength = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                rdata = data[offset:offset + rdlength]
                offset += rdlength
                answer = {
                    'name': '.'.join(name),
                    'type': atype,
                    'class': aclass,
                    'ttl': ttl,
                    'rdata': rdata
                }
                answers.append(answer)
            return answers, offset
        except Exception as e:
            self.logger.error(f"Failed to parse DNS answer: {e}")
            return None, offset

    async def parse_dns_authority(self, headers: dict, data: bytes, offset: int) -> Any:
        """
        Parse the DNS authority section from the packet data.
        """
        try:
            if headers['nscount'] == 0:
                return None, offset

            authorities = []
            for _ in range(headers['nscount']):
                name = []
                while True:
                    length = data[offset]
                    if length == 0:
                        offset += 1
                        break
                    offset += 1
                    name.append(data[offset:offset + length].decode('utf-8'))
                    offset += length
                atype = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                aclass = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                ttl = int.from_bytes(data[offset:offset + 4], byteorder='big')
                offset += 4
                rdlength = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                rdata = data[offset:offset + rdlength]
                offset += rdlength
                authority = {
                    'name': '.'.join(name),
                    'type': atype,
                    'class': aclass,
                    'ttl': ttl,
                    'rdata': rdata
                }
                authorities.append(authority)
            return authorities, offset
        except Exception as e:
            self.logger.error(f"Failed to parse DNS authority: {e}")
            return None, offset

    async def parse_dns_additional(self, headers: dict, data: bytes, offset: int) -> Any:
        """
        Parse the DNS additional section from the packet data.
        """
        try:
            if headers['arcount'] == 0:
                return None, offset

            additionals = []
            for _ in range(headers['arcount']):
                name = []
                while True:
                    length = data[offset]
                    if length == 0:
                        offset += 1
                        break
                    offset += 1
                    name.append(data[offset:offset + length].decode('utf-8'))
                    offset += length
                atype = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                aclass = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                ttl = int.from_bytes(data[offset:offset + 4], byteorder='big')
                offset += 4
                rdlength = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                rdata = data[offset:offset + rdlength]
                offset += rdlength
                additional = {
                    'name': '.'.join(name),
                    'type': atype,
                    'class': aclass,
                    'ttl': ttl,
                    'rdata': rdata
                }
                additionals.append(additional)
            return additionals, offset
        except Exception as e:
            self.logger.error(f"Failed to parse DNS additional: {e}")
            return None, offset

    async def parse_dns_packet(self, data: bytes) -> Any:
        """
        Parse the entire DNS packet from the data.
        """
        try:
            headers = await self.parse_dns_headers(data)
            offset = 12
            questions, offset = await self.parse_dns_question(headers, data, offset)
            answers, offset = await self.parse_dns_answer(headers, data, offset)
            authorities, offset = await self.parse_dns_authority(headers, data, offset)
            additionals, offset = await self.parse_dns_additional(headers, data, offset)
            dns_packet = {
                'headers': headers,
                'questions': questions,
                'answers': answers,
                'authorities': authorities,
                'additionals': additionals
            }
            return dns_packet
        except Exception as e:
            self.logger.error(f"Failed to parse DNS packet: {e}")
            return {}

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
