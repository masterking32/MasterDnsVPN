# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import random
import functools
import sys
import os
import socket
import asyncio
from typing import Optional
import signal
import ctypes
from ctypes import wintypes


from client_config import master_dns_vpn_config

from dns_utils.utils import getLogger, generate_random_hex_text
from dns_utils.DnsPacketParser import DnsPacketParser
from dns_utils.UDPClient import UDPClient
from dns_utils.DNS_ENUMS import PACKET_TYPES, Q_CLASSES, RESOURCE_RECORDS

# Ensure UTF-8 output for consistent logging
try:
    if sys.stdout.encoding is not None and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


class MasterDnsVPNClient:
    """MasterDnsVPN Client class to handle DNS requests over UDP."""

    def __init__(self) -> None:
        self.udp_sock: Optional[socket.socket] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.should_stop: asyncio.Event = asyncio.Event()
        self.config: dict = master_dns_vpn_config.__dict__
        self.logger = getLogger(log_level=self.config.get("LOG_LEVEL", "INFO"))
        self.resolvers: list = self.config.get("RESOLVER_DNS_SERVERS", [])
        self.domains: list = self.config.get("DOMAINS", [])
        self.timeout: float = self.config.get("DNS_QUERY_TIMEOUT", 10.0)
        self.max_upload_mtu: int = self.config.get("MAX_UPLOAD_MTU", 512)
        self.max_download_mtu: int = self.config.get("MAX_DOWNLOAD_MTU", 4096)
        self.min_upload_mtu: int = self.config.get("MIN_UPLOAD_MTU", 0)
        self.min_download_mtu: int = self.config.get("MIN_DOWNLOAD_MTU", 0)
        self.encryption_method: int = self.config.get("DATA_ENCRYPTION_METHOD", 1)
        self.skip_resolver_with_packet_loss: int = self.config.get(
            "SKIP_RESOLVER_WITH_PACKET_LOSS", 100
        )
        self.resolver_balancing_strategy: int = self.config.get(
            "RESOLVER_BALANCING_STRATEGY", 0
        )
        self.encryption_key: str = self.config.get("ENCRYPTION_KEY", None)
        if not self.encryption_key:
            self.logger.error("No encryption key provided in configuration.")
            sys.exit(1)
        self.dns_packet_parser = DnsPacketParser(
            logger=self.logger,
            encryption_method=self.encryption_method,
            encryption_key=self.encryption_key,
        )

        self.packets_queue: dict = {}

    async def create_connection_map(self) -> None:
        """Create a map of all domain-resolver combinations."""
        self.connections_map: list = []
        self.resent_connection_selected = -1
        self.connections_map = [
            {"domain": domain, "resolver": resolver}
            for domain in self.domains
            for resolver in self.resolvers
        ]

        self.connections_map = [
            dict(t) for t in {tuple(d.items()) for d in self.connections_map}
        ]

    async def select_connection(self) -> Optional[dict]:
        """Select a connection based on the balancing strategy."""
        valid_connections = [
            conn for conn in self.connections_map if conn.get("is_valid", True)
        ]

        if not valid_connections:
            self.logger.error("No valid connections available.")
            return None

        for conn in valid_connections:
            total_packets = conn.get("total_packets", 0)
            lost_packets = conn.get("lost_packets", 0)
            if total_packets > 0:
                packet_loss = (lost_packets / total_packets) * 100
            else:
                packet_loss = 0
            conn["packet_loss"] = packet_loss

        valid_connections = [
            conn
            for conn in valid_connections
            if conn["packet_loss"] <= self.skip_resolver_with_packet_loss
        ]

        if not valid_connections:
            self.logger.error(
                "No valid connections available after applying packet loss filter."
            )
            return None

        if self.resolver_balancing_strategy == 2:
            self.resent_connection_selected = (
                self.resent_connection_selected + 1
            ) % len(valid_connections)
            selected_connection = valid_connections[self.resent_connection_selected]
            self.logger.debug(
                f"Round Robin selected connection, domain: {selected_connection['domain']}, resolver: {selected_connection['resolver']}"
            )
            return selected_connection

        elif self.resolver_balancing_strategy == 3:
            valid_connections.sort(key=lambda x: x["packet_loss"])
            min_loss = valid_connections[0]["packet_loss"]
            same_loss_connections = [
                conn for conn in valid_connections if conn["packet_loss"] == min_loss
            ]
            if len(same_loss_connections) > 1:
                selected_connection = random.choice(same_loss_connections)
                self.logger.debug(
                    f"Least Packet Loss (tie) randomly selected connection with packet loss: {selected_connection['packet_loss']:.2f}%, domain: {selected_connection['domain']}, resolver: {selected_connection['resolver']}"
                )
            else:
                selected_connection = same_loss_connections[0]
                self.logger.debug(
                    f"Least Packet Loss selected connection with packet loss: {selected_connection['packet_loss']:.2f}%, domain: {selected_connection['domain']}, resolver: {selected_connection['resolver']}"
                )
            return selected_connection

        else:
            selected_connection = random.choice(valid_connections)
            self.logger.debug(
                f"Randomly selected connection, domain: {selected_connection['domain']}, resolver: {selected_connection['resolver']}"
            )
            return selected_connection

    async def get_main_connection_index(
        self, selected_connection: Optional[dict] = None
    ) -> Optional[int]:
        """Find and return the main connection (connections_map) based on the selected connection."""
        if selected_connection is None:
            selected_connection = await self.select_connection()
            if selected_connection is None:
                return None

        for index, conn in enumerate(self.connections_map):
            if conn.get("domain") == selected_connection.get("domain") and conn.get(
                "resolver"
            ) == selected_connection.get("resolver"):
                return index

        self.logger.error("Selected connection not found in connections map.")
        return None

    async def _binary_search_mtu(
        self, test_callable, min_mtu: int, max_mtu: int, min_threshold: int = 30
    ) -> int:
        """
        Generic binary search for MTU tests.
        `test_callable(size)` should be an async callable returning True on success.
        Returns the highest successful MTU or 0 if none.
        """
        # Quick check max
        try:
            if max_mtu <= 0:
                return 0

            if await test_callable(max_mtu):
                return max_mtu
            max_candidate = max_mtu - 1

            low = min_mtu
            high = max_candidate
            optimal = 0

            while low <= high:
                mid = (low + high) // 2
                if mid < min_threshold:
                    break
                try:
                    ok = await test_callable(mid)
                except Exception as e:
                    self.logger.debug(f"MTU test callable raised: {e}")
                    ok = False

                if ok:
                    optimal = mid
                    low = mid + 1
                else:
                    high = mid - 1

            return optimal
        except Exception as e:
            self.logger.debug(f"Error in MTU binary search: {e}")
            return 0

    async def send_upload_mtu_test(
        self, domain: str, dns_server: str, dns_port: int, mtu_size: int
    ) -> bool:

        mtu_char_len, mtu_bytes = self.dns_packet_parser.calculate_upload_mtu(
            domain=domain, mtu=mtu_size
        )

        self.logger.debug(
            f"Sending upload MTU test of size {mtu_bytes} to domain {domain} via resolver {dns_server}..."
        )

        if mtu_char_len < 29:
            self.logger.error(
                f"Calculated MTU character length too small: {mtu_char_len} characters for domain {domain}"
            )
            return False

        random_hex = generate_random_hex_text(mtu_char_len).lower()
        dns_queries = await self.dns_packet_parser.build_request_dns_query(
            domain=domain,
            session_id=random.randint(0, 255),
            packet_type=PACKET_TYPES["SERVER_UPLOAD_TEST"],
            data=random_hex,
            mtu_chars=mtu_char_len,
            encode_data=False,
            qType=RESOURCE_RECORDS["TXT"],
        )

        if dns_queries is None or len(dns_queries) != 1:
            self.logger.debug(
                f"Failed to build DNS query for upload MTU test to domain {domain} via resolver {dns_server}."
            )
            return False

        # TODO SEND TO UDP AND WAIT FOR RESPONSE
        return False

    async def test_upload_mtu_size(
        self, domain: str, dns_server: str, dns_port: int, default_mtu: int
    ) -> tuple:
        """Test and adjust upload MTU size based on network conditions."""
        self.logger.debug(
            f"Testing upload MTU size for domain {domain} via resolver {dns_server}..."
        )

        try:
            mtu_char_len, mtu_bytes = self.dns_packet_parser.calculate_upload_mtu(
                domain=domain, mtu=0
            )

            if default_mtu > 512 or default_mtu <= 0:
                default_mtu = 512

            if mtu_bytes > default_mtu:
                mtu_bytes = default_mtu

            min_mtu = 0
            max_mtu_candidate = default_mtu
            optimal_mtu = 0

            test_fn = functools.partial(
                self.send_upload_mtu_test, domain, dns_server, dns_port
            )
            optimal_mtu = await self._binary_search_mtu(
                test_fn, min_mtu, max_mtu_candidate, min_threshold=30
            )

            if optimal_mtu > 29:
                mtu_char_len, mtu_bytes = self.dns_packet_parser.calculate_upload_mtu(
                    domain=domain, mtu=optimal_mtu
                )
                return True, mtu_bytes, mtu_char_len

        except Exception as e:
            self.logger.debug(
                f"Error calculating initial upload MTU for domain {domain} via resolver {dns_server}: {e}"
            )

        return False, 0, 0

    async def test_download_mtu_size(self) -> None:
        """Test and adjust download MTU size based on network conditions."""
        # Placeholder for MTU testing logic
        pass

    async def test_mtu_sizes(self) -> Optional[bool]:
        """Test and adjust MTU sizes based on network conditions."""

        self.logger.info("=" * 80)
        self.logger.info(
            "<y>Testing upload MTU sizes for all resolver-domain pairs...</y>"
        )

        for connection in self.connections_map:
            if not connection or self.should_stop.is_set():
                continue

            domain = connection.get("domain")
            resolver = connection.get("resolver")
            dns_server = resolver
            dns_port = 53
            upload_mtu = self.max_upload_mtu

            # Set initial MTU values
            connection["is_valid"] = False
            connection["upload_mtu_bytes"] = 0
            connection["upload_mtu_chars"] = 0
            connection["download_mtu_bytes"] = 0
            connection["packet_loss"] = 100

            is_valid, mtu_bytes, mtu_char_len = await self.test_upload_mtu_size(
                domain=domain,
                dns_server=dns_server,
                dns_port=dns_port,
                default_mtu=upload_mtu,
            )

            if is_valid and (
                self.min_upload_mtu == 0 or mtu_bytes >= self.min_upload_mtu
            ):
                connection["is_valid"] = True
                connection["upload_mtu_bytes"] = mtu_bytes
                connection["upload_mtu_chars"] = mtu_char_len
                self.logger.info(
                    f"<green>Connection valid for domain <cyan>{domain}</cyan> via resolver <cyan>{resolver}</cyan> with upload MTU <cyan>{mtu_bytes}</cyan> bytes ({mtu_char_len} chars).</green>"
                )
            else:
                self.logger.info(
                    f"Connection invalid for domain {domain} via resolver <red>{resolver}</red>. <red>Upload MTU test failed or below minimum.</red>"
                )

        self.logger.info(
            "Testing download MTU sizes for all valid resolver-domain pairs..."
        )

    async def sleep(self, seconds: float) -> None:
        """Async sleep helper."""
        try:
            await asyncio.wait_for(self.should_stop.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            pass

    async def run_client(self) -> None:
        """Run the MasterDnsVPN Client main logic."""
        self.logger.info("Setting up connections...")
        try:
            await self.create_connection_map()
            await self.test_mtu_sizes()

            # new session
            # set mtu sizes
        except Exception as e:
            self.logger.error(f"Error setting up connections: {e}")
            return

    async def start(self) -> None:
        """Start the MasterDnsVPN Client."""
        try:
            self.loop = asyncio.get_running_loop()

            self.logger.info("=" * 80)
            self.logger.success("<g>Starting MasterDnsVPN Client...</g>")

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

            while not self.should_stop.is_set():
                self.logger.info("=" * 80)
                self.logger.info("<green>Running MasterDnsVPN Client...</green>")
                self.packets_queue.clear()
                await self.run_client()
                self.logger.info("=" * 80)
                self.logger.error("<yellow>Retrying in 10 second...</yellow>")
                await self.sleep(10)

        except asyncio.CancelledError:
            self.logger.info("MasterDnsVPN Client is stopping...")
        except Exception as e:
            self.logger.error(f"Error in MasterDnsVPN Client: {e}")

    def _signal_handler(self, signum, frame) -> None:
        """Handle termination signals to stop the client gracefully.

        Only log the received signal the first time to avoid repeated INFO
        messages when multiple console events are received.
        """
        if not self.should_stop.is_set():
            self.logger.info(
                f"Received signal {signum}. Stopping MasterDnsVPN Client..."
            )
            self.should_stop.set()
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.logger.info("MasterDnsVPN Client stopped. Goodbye!")
        else:
            self.logger.info(f"Received signal {signum} again. Already stopping...")
            os._exit(0)


def main():
    client = MasterDnsVPNClient()
    try:
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            loop.add_signal_handler(
                signal.SIGINT, lambda: client._signal_handler(signal.SIGINT, None)
            )
        except Exception:
            try:
                signal.signal(signal.SIGINT, client._signal_handler)
            except Exception:
                pass

        try:
            loop.add_signal_handler(
                signal.SIGTERM, lambda: client._signal_handler(signal.SIGTERM, None)
            )
        except Exception:
            try:
                signal.signal(signal.SIGTERM, client._signal_handler)
            except Exception:
                pass

        # On Windows, register a Console Ctrl Handler early so Ctrl+C is handled
        if sys.platform == "win32":
            try:
                HandlerRoutine = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)

                def _console_handler(dwCtrlType):
                    # CTRL_C_EVENT == 0, CTRL_BREAK_EVENT == 1, others ignored
                    try:
                        client._signal_handler(dwCtrlType, None)
                    except Exception:
                        pass
                    return True

                c_handler = HandlerRoutine(_console_handler)
                ctypes.windll.kernel32.SetConsoleCtrlHandler(c_handler, True)
            except Exception:
                pass

        try:
            loop.run_until_complete(client.start())
        except KeyboardInterrupt:
            try:
                client._signal_handler(signal.SIGINT, None)
            except Exception:
                pass
            print("\nClient stopped by user (Ctrl+C). Goodbye!")
            return
    except KeyboardInterrupt:
        print("\nClient stopped by user (Ctrl+C). Goodbye!")
    except Exception as e:
        print(f"{e}")

    try:
        os._exit(0)
    except Exception as e:
        print(f"Error while stopping the client: {e}")
        exit()


if __name__ == "__main__":
    main()
