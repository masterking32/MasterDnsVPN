# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import socket
import asyncio
from typing import Optional


class UDPClient:
    def __init__(
        self,
        logger,
        server_host: str = "127.0.0.1",
        server_port: int = 53,
        timeout: float = 10.0,
        buffer_size: int = 65507,
        recv_callback=None,
    ):
        """
        Initialize UDP client.
        Args:
            logger: Logger instance
            server_host: Server IP address or hostname
            server_port: Server port number (default 53 for DNS)
            timeout: Socket timeout in seconds
            buffer_size: Maximum bytes to receive
        """
        self.server_host: str = server_host
        self.server_port: int = server_port
        self.timeout: float = timeout
        self.buffer_size: int = buffer_size
        self.sock: Optional[socket.socket] = None
        self.logger = logger
        self.recv_callback = recv_callback

    async def send_and_receive_async(
        self, data: bytes, retries: int = 1
    ) -> Optional[tuple[bytes, tuple]]:
        """
        Async send and receive using asyncio loop.sock_sendto / sock_recvfrom.
        Returns (response_bytes, addr) or None on failure.
        """
        loop = asyncio.get_running_loop()

        if not isinstance(data, (bytes, bytearray)):
            self.logger.debug("Data must be bytes")
            return None

        if self.sock is None:
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.sock.setblocking(False)
            except Exception as e:
                self.logger.debug(f"Async socket creation failed: {e}")
                return None

        for attempt in range(retries):
            if attempt > 0:
                self.logger.debug(f"Retry attempt {attempt}/{retries - 1}")
            try:
                await loop.sock_sendto(
                    self.sock, data, (self.server_host, self.server_port)
                )
                try:
                    resp, addr = await asyncio.wait_for(
                        loop.sock_recvfrom(self.sock, self.buffer_size),
                        timeout=self.timeout,
                    )
                    self.logger.debug(f"Async received {len(resp)} bytes from {addr}")
                    return resp, addr
                except asyncio.TimeoutError:
                    self.logger.debug("Timeout: No response from server (async)")
            except Exception as e:
                self.logger.debug(f"Failed to send data async: {e}")

        self.logger.debug("All async retry attempts failed")
        return None

    async def close_async(self) -> None:
        """Async-friendly close for the socket."""
        if self.sock:
            try:
                self.sock.close()
                self.logger.debug("Async socket closed")
            except Exception as e:
                self.logger.debug(f"Error closing async socket: {e}")
            self.sock = None
