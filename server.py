# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026


import sys
import os
import socket
import asyncio
import signal
import threading
import random
import time
from typing import Optional, Any
import ctypes
from ctypes import wintypes

from server_config import master_dns_vpn_config

from dns_utils.utils import getLogger, get_encrypt_key
from dns_utils.DnsPacketParser import DnsPacketParser
from dns_utils.DNS_ENUMS import PACKET_TYPES, Q_CLASSES, RESOURCE_RECORDS
from dns_utils.UDPClient import UDPClient

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

        self.sessions = {}

        # Generate or load encryption key
        self.encrypt_key = get_encrypt_key(
            self.config.get("DATA_ENCRYPTION_METHOD", 1))
        self.logger.warning(
            f"Using encryption key: <green>{self.encrypt_key}</green>")

        self.dns_parser = DnsPacketParser(logger=self.logger,
                                          encryption_method=self.config.get(
                                              "DATA_ENCRYPTION_METHOD", 1),
                                          encryption_key=self.encrypt_key)
        # Background task references (used for fast shutdown)
        self._dns_task = None
        self._session_cleanup_task = None

    async def new_session(self) -> int:
        """
        Create a new session and return its session ID.
        """
        for session_id in range(1, 256):
            if session_id not in self.sessions:
                self.sessions[session_id] = {
                    "last_packet_time": asyncio.get_event_loop().time()
                }
                self.logger.info(f"Created new session with ID: {session_id}")
                return session_id

    async def is_session_valid(self, session_id: int) -> bool:
        """
        Check if a session ID is valid.
        """
        return session_id in self.sessions

    async def close_inactive_sessions(self, timeout: int = 300) -> None:
        """
        Close sessions that have been inactive for a specified timeout (seconds).
        """
        current_time = asyncio.get_event_loop().time()
        inactive_sessions = [
            session_id for session_id, session_info in self.sessions.items()
            if current_time - session_info["last_packet_time"] > timeout
        ]
        for session_id in inactive_sessions:
            del self.sessions[session_id]
            self.logger.info(f"Closed inactive session with ID: {session_id}")

    async def solve_dns(self, query: bytes) -> bytes:
        """
        Solve DNS query by forwarding it to configured DNS servers asynchronously.
        """
        # TODO: Add allow list domains!
        if not query:
            self.logger.error("Empty DNS query received.")
            return b''

        dns_servers = self.config.get("DNS_SERVERS") or []
        if not dns_servers:
            self.logger.error("No DNS servers configured.")
            return b''

        dns_server = random.choice(dns_servers)
        self.logger.debug(f"Forwarding DNS query to {dns_server}")

        try:
            # Use UDPClient async helper to simplify send/receive
            udp_client = UDPClient(logger=self.logger, server_host=dns_server,
                                   server_port=53, timeout=self.config.get("DNS_QUERY_TIMEOUT", 10.0))
            result = await udp_client.send_and_receive_async(query, retries=3)
            if not result:
                self.logger.debug(f"No response from {dns_server}")
                return b''
            response, _addr = result
            self.logger.debug(f"Received DNS response from {dns_server}")
            return response
        except Exception as e:
            self.logger.error(f"Failed to get response from {dns_server}: {e}")
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

            request_domain = questions[0]['qName']
            packet_domain = questions[0]['qName'].lower()
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
                data_bytes = self.dns_parser.codec_transform(
                    txt_str.encode(), encrypt=True)

                response_packet = await self.dns_parser.generate_vpn_response_packet(
                    domain=request_domain,
                    session_id=1,
                    packet_type=PACKET_TYPES["SERVER_UPLOAD_TEST"],
                    data=data_bytes,
                    question_packet=data
                )

                return True, response_packet
            elif packet_type == PACKET_TYPES["SERVER_DOWNLOAD_TEST"]:
                if '.' not in labels:
                    self.logger.warning(
                        f"Invalid SERVER_DOWNLOAD_TEST packet format from {addr}: {labels}")
                    return False, None

                first_part_of_data = labels.split('.')[0]
                if not first_part_of_data:
                    self.logger.warning(
                        f"Empty data in SERVER_DOWNLOAD_TEST packet from {addr}")
                    return False, None

                download_size_bytes = self.dns_parser.decode_and_decrypt_data(
                    first_part_of_data, lowerCaseOnly=True)
                if download_size_bytes is None:
                    self.logger.warning(
                        f"Failed to decode download size in SERVER_DOWNLOAD_TEST packet from {addr}")
                    return False, None

                download_size = int.from_bytes(
                    download_size_bytes, byteorder='big')

                if download_size < 29:
                    self.logger.warning(
                        f"Download size too small in SERVER_DOWNLOAD_TEST packet from {addr}: {download_size}")
                    return False, None

                data_bytes = self.dns_parser.codec_transform(
                    download_size_bytes, encrypt=True)
                data_bytes = data_bytes + ":".encode()
                data_bytes = data_bytes + random.randbytes(
                    download_size - len(data_bytes))

                if len(data_bytes) != download_size:
                    self.logger.error(
                        f"Prepared download data size mismatch for packet from {addr}: expected {download_size}, got {len(data_bytes)}")
                    return False, None

                response_packet = await self.dns_parser.generate_vpn_response_packet(
                    domain=request_domain,
                    session_id=255,
                    packet_type=PACKET_TYPES["SERVER_DOWNLOAD_TEST"],
                    data=data_bytes,
                    question_packet=data
                )

                return True, response_packet

            elif packet_type == PACKET_TYPES["NEW_SESSION"]:
                new_session_id = await self.new_session()
                if new_session_id is None:
                    self.logger.error(
                        f"Failed to create new session for NEW_SESSION packet from {addr}")
                    return False, None

                txt_str = str(new_session_id)
                data_bytes = self.dns_parser.codec_transform(
                    txt_str.encode(), encrypt=True)

                response_packet = await self.dns_parser.generate_vpn_response_packet(
                    domain=request_domain,
                    session_id=new_session_id,
                    packet_type=PACKET_TYPES["NEW_SESSION"],
                    data=data_bytes,
                    question_packet=data
                )

                return True, response_packet
            return True, None
        except Exception as e:
            self.logger.error(
                f"Error handling VPN packet from {addr}: {e}")
            return False, None

    async def send_udp_response(self, response: bytes, addr) -> bool:
        """Async send helper to write UDP response to addr using the server socket."""
        if not response or addr is None:
            return False
        try:
            if self.udp_sock is None:
                self.logger.error(
                    "UDP socket is not initialized for sending response.")
                return False
            # Ensure non-blocking socket and event loop available
            if self.loop is None:
                self.loop = asyncio.get_running_loop()
            await self.loop.sock_sendto(self.udp_sock, response, addr)
            self.logger.debug(f"Sent DNS response to {addr}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to send DNS response to {addr}: {e}")
            return False

    async def handle_single_request(self, data, addr):
        """
        Handle a single DNS request in its own task.
        """
        if data is None or addr is None:
            self.logger.error("Invalid data or address in DNS request.")
            return
        self.logger.debug(f"Received DNS request from {addr}")

        parsed_packet = await self.dns_parser.parse_dns_packet(data)
        self.logger.debug(f"Parsed DNS packet from {addr}: {parsed_packet}")

        # Check for VPN packet
        vpn_packet, vpn_response = await self.handle_vpn_packet(data, parsed_packet, addr)
        if vpn_response:
            await self.send_udp_response(vpn_response, addr)
            return

        # If it was a VPN packet but no response to send, nothing more to do
        if vpn_packet:
            return

        # Non-VPN request: try to forward (optional) or return server failure
        # Forwarding disabled by default for safety — use solve_dns if enabled
        # response = await self.solve_dns(data)
        response = None
        if not response:
            response = await self.dns_parser.server_fail_response(data)
            if not response:
                self.logger.error(
                    f"Failed to generate Server Failure response for DNS request from {addr}")
                return

        await self.send_udp_response(response, addr)

    async def handle_dns_requests(self) -> None:
        """
        Asynchronously handle incoming DNS requests and spawn a new task for each.
        """
        assert self.udp_sock is not None, "UDP socket is not initialized."
        assert self.loop is not None, "Event loop is not initialized."
        self.udp_sock.setblocking(False)
        # Use a short timeout on recv so shutdown can be handled quickly
        while not self.should_stop.is_set():
            try:
                try:
                    data, addr = await asyncio.wait_for(
                        self.loop.sock_recvfrom(self.udp_sock, 512), timeout=1.0)
                except asyncio.TimeoutError:
                    # Timeout: loop back to check should_stop
                    continue
            except OSError as e:
                self.logger.error(
                    f"Socket error: {e}. Exiting DNS request handler.")
                break
            except Exception as e:
                # Unexpected; log and continue listening
                self.logger.exception(
                    f"Unexpected error receiving DNS request: {e}")
                continue

            # Spawn a new task for each request
            try:
                self.loop.create_task(self.handle_single_request(data, addr))
            except Exception as e:
                self.logger.error(
                    f"Failed to create task for request from {addr}: {e}")

    async def _session_cleanup_loop(self) -> None:
        """Background task to periodically cleanup inactive sessions."""
        try:
            while not self.should_stop.is_set():
                try:
                    await asyncio.sleep(self.config.get("SESSION_CLEANUP_INTERVAL", 30))
                    await self.close_inactive_sessions(self.config.get("SESSION_TIMEOUT", 300))
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    self.logger.error(f"Error during session cleanup: {e}")
        finally:
            self.logger.debug("Session cleanup loop stopped.")

    def _cancel_background_tasks(self) -> None:
        """Cancel background tasks from the event loop thread."""
        try:
            if getattr(self, '_dns_task', None):
                try:
                    self._dns_task.cancel()
                except Exception:
                    pass
            if getattr(self, '_session_cleanup_task', None):
                try:
                    self._session_cleanup_task.cancel()
                except Exception:
                    pass
            self.logger.debug("Background tasks cancellation requested.")
        except Exception as e:
            self.logger.error(f"Error cancelling background tasks: {e}")

    async def start(self) -> None:
        """Initialize sockets, start background tasks, and wait for shutdown signal."""
        try:
            self.logger.info("MasterDnsVPN Server starting ...")

            # Set up event loop and UDP socket
            self.loop = asyncio.get_running_loop()

            host = self.config.get("UDP_HOST", "0.0.0.0")
            port = int(self.config.get("UDP_PORT", 53))

            self.logger.info("Binding UDP socket ...")
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                self.udp_sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except Exception:
                pass
            self.udp_sock.bind((host, port))

            self.logger.info(f"UDP socket bound on {host}:{port}")

            # create new tasks for dns handling and session cleanup
            self._dns_task = self.loop.create_task(self.handle_dns_requests())
            self._session_cleanup_task = self.loop.create_task(
                self._session_cleanup_loop())

            self.logger.info("MasterDnsVPN Server started successfully.")

            # wait until stop is signalled
            try:
                await self.should_stop.wait()
            except asyncio.CancelledError:
                pass
            finally:
                try:
                    if getattr(self, '_dns_task', None):
                        self._dns_task.cancel()
                except Exception:
                    pass
                try:
                    if getattr(self, '_session_cleanup_task', None):
                        self._session_cleanup_task.cancel()
                except Exception:
                    pass
                await asyncio.gather(
                    *(t for t in (getattr(self, '_dns_task', None),
                      getattr(self, '_session_cleanup_task', None)) if t),
                    return_exceptions=True)
                # ensure socket closed
                if self.udp_sock:
                    try:
                        self.udp_sock.close()
                    except Exception:
                        pass
                self.logger.info("MasterDnsVPN Server stopped.")

        except Exception as e:
            self.logger.exception(f"Failed to start MasterDnsVPN Server: {e}")
            if self.udp_sock:
                try:
                    self.udp_sock.close()
                except Exception:
                    pass

    def _signal_handler(self, signum: int, frame: Any = None) -> None:
        """
        Handle termination signals for graceful shutdown.
        """
        self.logger.info(
            f"Received signal {signum}, shutting down MasterDnsVPN Server ...")
        # Use call_soon_threadsafe to interact with the asyncio loop from a signal handler
        try:
            if self.loop:
                try:
                    # Wake the main task waiting on the event
                    self.loop.call_soon_threadsafe(self.should_stop.set)
                except Exception:
                    # Fallback if loop isn't running yet
                    try:
                        if not self.should_stop.is_set():
                            self.should_stop.set()
                    except Exception:
                        pass

                # Close UDP socket safely on the loop thread
                try:
                    self.loop.call_soon_threadsafe(self._close_udp_socket)
                except Exception:
                    # fallback to immediate close
                    if self.udp_sock:
                        try:
                            self.udp_sock.close()
                            self.logger.info("UDP socket closed.")
                        except Exception as e:
                            self.logger.error(f"Error closing UDP socket: {e}")

                # Cancel background tasks on the loop thread for faster shutdown
                try:
                    self.loop.call_soon_threadsafe(
                        self._cancel_background_tasks)
                except Exception:
                    pass

                # Stop the event loop from the loop thread
                try:
                    self.loop.call_soon_threadsafe(self.loop.stop)
                except Exception:
                    pass
            else:
                # No loop available: set event and close socket directly
                if not self.should_stop.is_set():
                    try:
                        self.should_stop.set()
                    except Exception:
                        pass
                if self.udp_sock:
                    try:
                        self.udp_sock.close()
                        self.logger.info("UDP socket closed.")
                    except Exception as e:
                        self.logger.error(f"Error closing UDP socket: {e}")
        except Exception as e:
            self.logger.error(f"Error in signal handler: {e}")

        self.logger.info("Shutdown signalled.")

    def _close_udp_socket(self) -> None:
        """Close the UDP socket from the event loop thread."""
        try:
            if self.udp_sock:
                try:
                    self.udp_sock.close()
                    self.logger.info("UDP socket closed.")
                finally:
                    self.udp_sock = None
        except Exception as e:
            self.logger.error(f"Error closing UDP socket: {e}")


def main():
    server = MasterDnsVPNServer()
    try:
        # Prefer manual loop management to reliably register loop-level signal handlers
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(
                asyncio.WindowsSelectorEventLoopPolicy())

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        # Try to register loop-level handlers (more reliable for asyncio shutdown)
        try:
            loop.add_signal_handler(
                signal.SIGINT, lambda: server._signal_handler(signal.SIGINT, None))
        except Exception:
            try:
                signal.signal(signal.SIGINT, server._signal_handler)
            except Exception:
                pass

        try:
            loop.add_signal_handler(
                signal.SIGTERM, lambda: server._signal_handler(signal.SIGTERM, None))
        except Exception:
            try:
                signal.signal(signal.SIGTERM, server._signal_handler)
            except Exception:
                pass

        try:
            loop.run_until_complete(server.start())
        except KeyboardInterrupt:
            # Fallback: ensure handler runs
            try:
                server._signal_handler(signal.SIGINT, None)
            except Exception:
                pass
            print("\n🛑 Server stopped by user (Ctrl+C). Goodbye!")
            return
        # On Windows, also register a ConsoleCtrlHandler to catch CTRL events
        if sys.platform == 'win32':
            try:
                # Define handler prototype
                HandlerRoutine = ctypes.WINFUNCTYPE(
                    wintypes.BOOL, wintypes.DWORD)

                def _console_handler(dwCtrlType):
                    # CTRL_C_EVENT == 0, CTRL_BREAK_EVENT == 1, others ignored
                    try:
                        server._signal_handler(dwCtrlType, None)
                    except Exception:
                        pass
                    return True

                c_handler = HandlerRoutine(_console_handler)
                ctypes.windll.kernel32.SetConsoleCtrlHandler(c_handler, True)
            except Exception:
                pass
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user (Ctrl+C). Goodbye!")
    except Exception as e:
        print(f"🛑 Error starting the server: {e}")

    try:
        os._exit(0)
    except Exception as e:
        print(f"🛑 Error while stopping the server: {e}")
        exit()


if __name__ == "__main__":
    main()
