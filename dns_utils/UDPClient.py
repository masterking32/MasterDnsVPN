# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import socket
import time
from typing import Optional


class UDPClient:
    def __init__(self, logger, server_host: str = '127.0.0.1', server_port: int = 53, timeout: float = 10.0, buffer_size: int = 4096) -> None:
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

    def connect(self) -> bool:
        """Create and configure the UDP socket."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(self.timeout)
            self.logger.debug(
                f"UDP client initialized for {self.server_host}:{self.server_port}")
            self.logger.debug(f"Timeout set to {self.timeout} seconds")
            return True
        except Exception as e:
            self.logger.debug(f"Failed to create socket: {e}")
            return False

    def send_bytes(self, data: bytes) -> bool:
        """
        Send bytes to the server.
        Args:
            data: Data to send
        Returns:
            bool: True if successful, False otherwise
        """
        if not isinstance(data, bytes):
            self.logger.debug("Data must be bytes")
            return False
        try:
            sent = self.sock.sendto(data, (self.server_host, self.server_port))
            self.logger.debug(f"Sent {sent} bytes to server")
            return True
        except Exception as e:
            self.logger.debug(f"Failed to send data: {e}")
            return False

    def receive_bytes(self) -> tuple[Optional[bytes], Optional[tuple]]:
        """
        Receive bytes from the server.
        Returns:
            tuple: (data, address) or (None, None) on error or timeout
        """
        try:
            data, addr = self.sock.recvfrom(self.buffer_size)
            self.logger.debug(f"Received {len(data)} bytes from {addr}")
            return data, addr
        except socket.timeout:
            self.logger.debug("Timeout: No response from server")
            return None, None
        except Exception as e:
            self.logger.debug(f"Failed to receive data: {e}")
            return None, None

    def send_and_receive(self, data: bytes, retries: int = 3) -> Optional[bytes]:
        """
        Send data and wait for response with retry mechanism.
        Args:
            data: Data to send
            retries: Number of retry attempts
        Returns:
            bytes: Response data or None
        """
        for attempt in range(retries):
            if attempt > 0:
                self.logger.info(f"Retry attempt {attempt}/{retries-1}")
            if self.send_bytes(data):
                response, addr = self.receive_bytes()
                if response is not None:
                    return response
            if attempt < retries - 1:
                time.sleep(0.5)
        self.logger.debug("All retry attempts failed")
        return None

    def close(self) -> None:
        """Close the socket and cleanup."""
        if self.sock:
            try:
                self.sock.close()
                self.logger.debug("Socket closed")
            except Exception as e:
                self.logger.debug(f"Error closing socket: {e}")
            self.sock = None
        self.logger.debug("UDP client cleanup complete")
