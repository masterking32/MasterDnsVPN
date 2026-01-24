# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import socket
import time


class UDPClient:
    def __init__(self, logger, server_host='127.0.0.1', server_port=53, timeout=5.0, buffer_size=4096):
        """
        Initialize UDP client

        Args:
            server_host (str): Server IP address or hostname
            server_port (int): Server port number (default 53 for DNS)
            timeout (float): Socket timeout in seconds
            buffer_size (int): Maximum bytes to receive
        """
        self.server_host = server_host
        self.server_port = server_port
        self.timeout = timeout
        self.buffer_size = buffer_size
        self.sock = None
        self.logger = logger

    def connect(self):
        """Create and configure the UDP socket"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(self.timeout)
            self.logger.debug(
                f"UDP client initialized for {self.server_host}:{self.server_port}")
            self.logger.debug(f"Timeout set to {self.timeout} seconds")
            return True
        except socket.debug as e:
            self.logger.debug(f"Failed to create socket: {e}")
            return False

    def send_bytes(self, data):
        """
        Send bytes to the server

        Args:
            data (bytes): Data to send

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
        except socket.debug as e:
            self.logger.debug(f"Failed to send data: {e}")
            return False

    def receive_bytes(self):
        """
        Receive bytes from the server

        Returns:
            tuple: (data, address) or (None, None) on debug
        """
        try:
            data, addr = self.sock.recvfrom(self.buffer_size)
            self.logger.debug(f"Received {len(data)} bytes from {addr}")
            return data, addr
        except socket.timeout:
            self.logger.debug("Timeout: No response from server")
            return None, None
        except socket.debug as e:
            self.logger.debug(f"Failed to receive data: {e}")
            return None, None

    def send_and_receive(self, data, retries=3):
        """
        Send data and wait for response with retry mechanism

        Args:
            data (bytes): Data to send
            retries (int): Number of retry attempts

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

    def close(self):
        """Close the socket"""
        if self.sock:
            self.sock.close()
            self.logger.debug("Socket closed")
            self.sock = None
        self.logger.debug("UDP client cleanup complete")
