# MasterDnsVPN Client
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import asyncio
import concurrent.futures
import ctypes
import functools
import heapq
import ipaddress
import os
import random
import signal
import socket
import sys
import time
from bisect import bisect_left, bisect_right, insort
from collections import defaultdict, deque
from typing import Optional

from dns_utils.ARQ import ARQ
from dns_utils.compression import (
    Compression_Type,
    compress_payload,
    get_compression_name,
    normalize_compression_type,
    try_decompress_payload,
)
from dns_utils.config_loader import get_config_path, load_config
from dns_utils.DNS_ENUMS import DNS_Record_Type, Packet_Type
from dns_utils.DNSBalancer import DNSBalancer
from dns_utils.DnsPacketParser import DnsPacketParser
from dns_utils.PacketQueueMixin import PacketQueueMixin
from dns_utils.PingManager import PingManager
from dns_utils.PrependReader import PrependReader
from dns_utils.utils import (
    async_recvfrom,
    async_sendto,
    generate_random_hex_text,
    getLogger,
)

# Ensure UTF-8 output for consistent logging
try:
    if sys.stdout.encoding is not None and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


class MasterDnsVPNClient(PacketQueueMixin):
    """MasterDnsVPN Client class to handle DNS requests over UDP."""

    def _prompt_before_exit(self) -> None:
        """Best-effort pause for interactive users; never fail in non-interactive runs."""
        try:
            if sys.stdin and sys.stdin.isatty():
                input("Press Enter to exit...")
        except Exception:
            pass

    def __init__(self) -> None:
        # ---------------------------------------------------------
        # Runtime and lifecycle primitives
        # ---------------------------------------------------------
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.should_stop: asyncio.Event = asyncio.Event()
        self.session_restart_event = None
        self.rx_tasks = set()
        self.cpu_executor: Optional[concurrent.futures.ThreadPoolExecutor] = None

        # ---------------------------------------------------------
        # Config and logger bootstrap
        # ---------------------------------------------------------
        self.config: dict = load_config("client_config.toml")
        if not os.path.isfile(get_config_path("client_config.toml")):
            self.logger = getLogger(log_level=self.config.get("LOG_LEVEL", "DEBUG"))
            self.logger.error(
                "Config file '<cyan>client_config.toml</cyan>' not found."
            )
            self.logger.error(
                "Please place it in the same directory as the executable and restart."
            )
            self._prompt_before_exit()
            sys.exit(1)

        self.logger = getLogger(log_level=self.config.get("LOG_LEVEL", "INFO"))
        auto_cpu_workers = max(2, min(16, (os.cpu_count() or 1)))
        raw_cpu_workers = int(self.config.get("CPU_WORKER_THREADS", 0))
        if raw_cpu_workers < 0:
            self.cpu_worker_threads = 0
        elif raw_cpu_workers == 0:
            self.cpu_worker_threads = auto_cpu_workers
        else:
            self.cpu_worker_threads = raw_cpu_workers

        # ---------------------------------------------------------
        # Protocol and authentication configuration
        # ---------------------------------------------------------
        self.protocol_type: str = self.config.get("PROTOCOL_TYPE", "SOCKS5").upper()
        self.socks5_auth: bool = self.config.get("SOCKS5_AUTH", False)
        self.socks5_user: str = str(self.config.get("SOCKS5_USER", ""))
        self.socks5_pass: str = str(self.config.get("SOCKS5_PASS", ""))
        self.socks_handshake_timeout: float = float(
            self.config.get("SOCKS_HANDSHAKE_TIMEOUT", 240.0)
        )

        if self.protocol_type not in ("SOCKS5", "TCP"):
            self.logger.error(
                f"Invalid PROTOCOL_TYPE '{self.protocol_type}' in config. Must be 'SOCKS5' or 'TCP'."
            )
            self._prompt_before_exit()
            sys.exit(1)

        # ---------------------------------------------------------
        # DNS transport and listener configuration
        # ---------------------------------------------------------
        self.resolvers: list = self._load_resolvers_from_file()
        self.allowed_resolver_sources = {
            str(r).strip().lower() for r in self.resolvers if str(r).strip()
        }
        self.domains: list = self.config.get("DOMAINS", [])
        self.domains_lower: tuple = tuple(
            sorted((d.lower() for d in self.domains), key=len, reverse=True)
        )
        self.timeout: float = self.config.get("DNS_QUERY_TIMEOUT", 5.0)
        self.listener_ip = self.config.get("LISTEN_IP", "127.0.0.1")
        self.listener_port = int(self.config.get("LISTEN_PORT", 1080))
        self.buffer_size = 65507  # Max UDP payload size

        # ---------------------------------------------------------
        # MTU, batching and queueing configuration
        # ---------------------------------------------------------
        self.max_upload_mtu: int = self.config.get("MAX_UPLOAD_MTU", 512)
        self.max_download_mtu: int = self.config.get("MAX_DOWNLOAD_MTU", 1200)
        self.min_upload_mtu: int = self.config.get("MIN_UPLOAD_MTU", 0)
        self.min_download_mtu: int = self.config.get("MIN_DOWNLOAD_MTU", 0)
        self.mtu_test_retries: int = self.config.get("MTU_TEST_RETRIES", 2)
        self.mtu_test_timeout: float = float(self.config.get("MTU_TEST_TIMEOUT", 1.0))
        self.auto_scale_profiles: bool = bool(
            self.config.get("AUTO_SCALE_PROFILES", True)
        )
        self.mtu_test_parallelism: int = max(
            1, int(self.config.get("MTU_TEST_PARALLELISM", 10))
        )
        self.save_mtu_servers_to_file: bool = bool(
            self.config.get("SAVE_MTU_SERVERS_TO_FILE", False)
        )
        self.mtu_servers_file_name: str = str(
            self.config.get(
                "MTU_SERVERS_FILE_NAME", "masterdnsvpn_success_test_{time}.log"
            )
        )
        self.mtu_servers_file_format: str = str(
            self.config.get(
                "MTU_SERVERS_FILE_FORMAT",
                "{IP} - UP: {UP_MTU} DOWN: {DOWN-MTU}",
            )
        )
        self.mtu_using_separator_text: str = str(
            self.config.get("MTU_USING_SECTION_SEPARATOR_TEXT", "")
        )
        self.mtu_removed_server_log_format: str = str(
            self.config.get("MTU_REMOVED_SERVER_LOG_FORMAT", "")
        )
        self.mtu_added_server_log_format: str = str(
            self.config.get("MTU_ADDED_SERVER_LOG_FORMAT", "")
        )
        self.auto_disable_timeout_servers: bool = bool(
            self.config.get("AUTO_DISABLE_TIMEOUT_SERVERS", True)
        )
        self.auto_disable_timeout_window_seconds: float = float(
            self.config.get("AUTO_DISABLE_TIMEOUT_WINDOW_SECONDS", 300.0)
        )
        self.auto_disable_min_observations: int = max(
            1,
            int(self.config.get("AUTO_DISABLE_TIMEOUT_MIN_OBSERVATIONS", 3)),
        )
        self.auto_disable_check_interval_seconds: float = max(
            0.5, float(self.config.get("AUTO_DISABLE_CHECK_INTERVAL_SECONDS", 1.0))
        )
        self.recheck_inactive_servers_enabled: bool = bool(
            self.config.get("RECHECK_INACTIVE_SERVERS_ENABLED", True)
        )
        self.recheck_inactive_interval_seconds: float = max(
            60.0, float(self.config.get("RECHECK_INACTIVE_INTERVAL_SECONDS", 1800.0))
        )
        self.recheck_server_interval_seconds: float = max(
            3.0, float(self.config.get("RECHECK_SERVER_INTERVAL_SECONDS", 3.0))
        )
        self.recheck_batch_size: int = max(
            1, int(self.config.get("RECHECK_BATCH_SIZE", 5))
        )
        self.max_packets_per_batch: int = int(
            self.config.get("MAX_PACKETS_PER_BATCH", 100)
        )
        self.packet_duplication_count = self.config.get("PACKET_DUPLICATION_COUNT", 1)
        self.upload_compression_type: int = normalize_compression_type(
            self.config.get("UPLOAD_COMPRESSION_TYPE", Compression_Type.OFF)
        )
        self.download_compression_type: int = normalize_compression_type(
            self.config.get("DOWNLOAD_COMPRESSION_TYPE", Compression_Type.OFF)
        )
        self.compression_min_size: int = 100

        # ---------------------------------------------------------
        # ARQ and flow-control configuration
        # ---------------------------------------------------------
        self.arq_window_size = self.config.get("ARQ_WINDOW_SIZE", 1000)
        self.arq_initial_rto = self.config.get("ARQ_INITIAL_RTO", 0.2)
        self.arq_max_rto = self.config.get("ARQ_MAX_RTO", 1.5)
        self.arq_control_initial_rto = float(
            self.config.get("ARQ_CONTROL_INITIAL_RTO", 0.8)
        )
        self.arq_control_max_rto = float(self.config.get("ARQ_CONTROL_MAX_RTO", 2.5))
        self.arq_control_max_retries = int(
            self.config.get("ARQ_CONTROL_MAX_RETRIES", 40)
        )
        self.rx_semaphore_limit = int(self.config.get("RX_SEMAPHORE_LIMIT", 1000))
        self.rx_semaphore = asyncio.Semaphore(max(1, self.rx_semaphore_limit))

        # ---------------------------------------------------------
        # Crypto and payload encoding configuration
        # ---------------------------------------------------------
        self.base_encode_responses: bool = self.config.get("BASE_ENCODE_DATA", False)
        self.encryption_method: int = self.config.get("DATA_ENCRYPTION_METHOD", 1)
        self.encryption_key: Optional[str] = self.config.get("ENCRYPTION_KEY", None)

        if not self.encryption_key:
            self.logger.error(
                "No encryption key provided. "
                "Please set <yellow>ENCRYPTION_KEY</yellow> in <yellow>client_config.toml</yellow>."
            )
            self._prompt_before_exit()
            sys.exit(1)

        self.crypto_overhead = 0
        if self.encryption_method == 2:
            self.crypto_overhead = 16
        elif self.encryption_method in (3, 4, 5):
            self.crypto_overhead = 28

        # ---------------------------------------------------------
        # Runtime state and counters
        # ---------------------------------------------------------
        self.success_mtu_checks: bool = False
        self.max_packed_blocks: int = 1
        self.connections_map: list = []
        self.session_id = 0
        self.session_cookie = 0
        self.synced_upload_mtu = 0
        self.synced_upload_mtu_chars = 0
        self.synced_download_mtu = 0

        self.main_queue = []
        self.priority_counts = {}
        self.tx_event = asyncio.Event()
        self.enqueue_seq = 0
        self.count_ping = 0

        self.server_rtt_tracker = {}
        self.server_health = defaultdict(
            lambda: {
                "pending": deque(),
                "events": deque(),
            }
        )
        self.runtime_disabled_servers = {}
        self.mtu_success_output_path: str = ""
        self.mtu_usage_separator_written: bool = False
        self.initial_mtu_scan_finished_at: float = 0.0
        self.next_inactive_recheck_at: float = 0.0
        self.background_mtu_recheck_mode: bool = False
        self.max_closed_stream_records = int(
            self.config.get("MAX_CLOSED_STREAM_RECORDS", 2000)
        )

        # ---------------------------------------------------------
        # Resolver balancing and protocol helpers
        # ---------------------------------------------------------
        self.resolver_balancing_strategy: int = self.config.get(
            "RESOLVER_BALANCING_STRATEGY", 0
        )
        self.balancer = DNSBalancer(
            resolvers=self.connections_map, strategy=self.resolver_balancing_strategy
        )

        self.dns_parser = DnsPacketParser(
            logger=self.logger,
            encryption_method=self.encryption_method,
            encryption_key=self.encryption_key,
        )
        self.ping_manager = PingManager(self._send_ping_packet)

        # ---------------------------------------------------------
        # Packet/control metadata tables
        # ---------------------------------------------------------
        self._block_packer = DnsPacketParser.PACKED_CONTROL_BLOCK_STRUCT
        self._valid_packet_types = {
            v
            for k, v in Packet_Type.__dict__.items()
            if not k.startswith("__") and isinstance(v, int)
        }
        self._control_request_ack_map = {
            Packet_Type.STREAM_KEEPALIVE: Packet_Type.STREAM_KEEPALIVE_ACK,
            Packet_Type.STREAM_WINDOW_UPDATE: Packet_Type.STREAM_WINDOW_UPDATE_ACK,
            Packet_Type.STREAM_PROBE: Packet_Type.STREAM_PROBE_ACK,
            Packet_Type.SOCKS5_CONNECT_FAIL: Packet_Type.SOCKS5_CONNECT_FAIL_ACK,
            Packet_Type.SOCKS5_RULESET_DENIED: Packet_Type.SOCKS5_RULESET_DENIED_ACK,
            Packet_Type.SOCKS5_NETWORK_UNREACHABLE: Packet_Type.SOCKS5_NETWORK_UNREACHABLE_ACK,
            Packet_Type.SOCKS5_HOST_UNREACHABLE: Packet_Type.SOCKS5_HOST_UNREACHABLE_ACK,
            Packet_Type.SOCKS5_CONNECTION_REFUSED: Packet_Type.SOCKS5_CONNECTION_REFUSED_ACK,
            Packet_Type.SOCKS5_TTL_EXPIRED: Packet_Type.SOCKS5_TTL_EXPIRED_ACK,
            Packet_Type.SOCKS5_COMMAND_UNSUPPORTED: Packet_Type.SOCKS5_COMMAND_UNSUPPORTED_ACK,
            Packet_Type.SOCKS5_ADDRESS_TYPE_UNSUPPORTED: Packet_Type.SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
            Packet_Type.SOCKS5_AUTH_FAILED: Packet_Type.SOCKS5_AUTH_FAILED_ACK,
            Packet_Type.SOCKS5_UPSTREAM_UNAVAILABLE: Packet_Type.SOCKS5_UPSTREAM_UNAVAILABLE_ACK,
        }
        self._control_ack_types = set(self._control_request_ack_map.values()) | {
            Packet_Type.STREAM_SYN_ACK,
            Packet_Type.SOCKS5_SYN_ACK,
            Packet_Type.STREAM_FIN_ACK,
            Packet_Type.STREAM_RST_ACK,
        }
        self._packable_control_types = set(self._control_ack_types)
        self._packable_control_types.update(self._control_request_ack_map.keys())
        self._packable_control_types.add(Packet_Type.STREAM_DATA_ACK)
        self._packable_control_types.update(
            {
                Packet_Type.STREAM_SYN,
                Packet_Type.STREAM_FIN,
                Packet_Type.STREAM_RST,
            }
        )
        self._packet_type_names = {
            v: k
            for k, v in Packet_Type.__dict__.items()
            if not k.startswith("__") and isinstance(v, int)
        }
        self._socks5_error_reply_map = {
            Packet_Type.SOCKS5_CONNECT_FAIL: 0x01,
            Packet_Type.SOCKS5_RULESET_DENIED: 0x02,
            Packet_Type.SOCKS5_NETWORK_UNREACHABLE: 0x03,
            Packet_Type.SOCKS5_HOST_UNREACHABLE: 0x04,
            Packet_Type.SOCKS5_CONNECTION_REFUSED: 0x05,
            Packet_Type.SOCKS5_TTL_EXPIRED: 0x06,
            Packet_Type.SOCKS5_COMMAND_UNSUPPORTED: 0x07,
            Packet_Type.SOCKS5_ADDRESS_TYPE_UNSUPPORTED: 0x08,
            Packet_Type.SOCKS5_AUTH_FAILED: 0x01,
            Packet_Type.SOCKS5_UPSTREAM_UNAVAILABLE: 0x01,
        }

        # ---------------------------------------------------------
        # Config version markers
        # ---------------------------------------------------------
        self.config_version = self.config.get("CONFIG_VERSION", 0.1)
        self.min_config_version = 3.0
        self.scale_profile_name = "manual"

        self.logger.debug("<magenta>[INIT]</magenta> MasterDnsVPNClient initialized.")

    def _load_resolvers_from_file(self) -> list:
        """Load resolver IP addresses from client_resolvers.txt."""
        resolver_file = get_config_path("client_resolvers.txt")
        if not os.path.isfile(resolver_file):
            self.logger.error(
                "Resolver file '<cyan>client_resolvers.txt</cyan>' not found."
            )
            self.logger.error("Please place it next to the executable and restart.")
            self._prompt_before_exit()
            sys.exit(1)

        resolvers = []
        seen = set()
        try:
            with open(resolver_file, "r", encoding="utf-8") as f:
                for raw_line in f:
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        normalized_ip = str(ipaddress.ip_address(line))
                    except ValueError:
                        continue
                    if normalized_ip in seen:
                        continue
                    seen.add(normalized_ip)
                    resolvers.append(normalized_ip)
        except Exception as exc:
            self.logger.error(
                f"Failed to read resolver file '<cyan>client_resolvers.txt</cyan>': {exc}"
            )
            self._prompt_before_exit()
            sys.exit(1)

        if not resolvers:
            self.logger.error(
                "No valid resolver IP found in '<cyan>client_resolvers.txt</cyan>'."
            )
            self.logger.error("Add at least one valid IPv4/IPv6 per line and restart.")
            self._prompt_before_exit()
            sys.exit(1)

        return resolvers

    def _apply_scale_profile(self, total_pairs: int) -> None:
        """Apply runtime tuning profile based on resolver-domain pair count."""
        if not self.auto_scale_profiles:
            self.scale_profile_name = "manual"
            return

        n = max(1, int(total_pairs))
        if n <= 50:
            profile = "small"
            mtu_parallel = 10
            batch_size = 4
            recheck_interval = 600.0
            per_server_gap = 2.5
        elif n <= 1000:
            profile = "medium"
            mtu_parallel = 12
            batch_size = 5
            recheck_interval = 900.0
            per_server_gap = 3.0
        else:
            profile = "large"
            mtu_parallel = 16
            batch_size = 8
            recheck_interval = 1200.0
            per_server_gap = 4.0

        self.scale_profile_name = profile
        self.mtu_test_parallelism = max(1, mtu_parallel)
        self.recheck_batch_size = max(1, batch_size)
        self.recheck_inactive_interval_seconds = max(60.0, float(recheck_interval))
        self.recheck_server_interval_seconds = max(1.0, float(per_server_gap))

        self.logger.info(
            f"<cyan>🔸 [Scale Profile: <green>{self.scale_profile_name}</green>]: "
            f"MTU_TEST_PARALLELISM: <green>{self.mtu_test_parallelism}</green> | "
            f"RECHECK_BATCH_SIZE: <green>{self.recheck_batch_size}</green> | "
            f"RECHECK_INACTIVE_INTERVAL_SECONDS: <green>{int(self.recheck_inactive_interval_seconds)}</green> | "
            f"RECHECK_SERVER_INTERVAL_SECONDS: <green>{self.recheck_server_interval_seconds:.1f}</green></cyan>"
        )

    # ---------------------------------------------------------
    # Connection Management
    # ---------------------------------------------------------
    async def create_connection_map(self) -> None:
        """Create a map of all domain-resolver combinations."""
        unique_domains = set(self.domains)
        unique_resolvers = set(self.resolvers)
        unique_domains.discard("")
        unique_resolvers.discard("")
        unique_domains = list(set(d.lower() for d in unique_domains))
        unique_resolvers = list(unique_resolvers)

        self.connections_map = []
        for domain in unique_domains:
            for resolver in unique_resolvers:
                conn = {"domain": domain, "resolver": resolver}
                conn["_key"] = self._get_connection_key(conn)
                self._init_recheck_meta(conn)
                self.connections_map.append(conn)

    def _get_connection_key(self, connection: dict) -> str:
        resolver = str(connection.get("resolver", "")).strip()
        domain = str(connection.get("domain", "")).strip().lower()
        key = f"{resolver}:{domain}"
        connection["_key"] = key
        return key

    def _init_recheck_meta(self, connection: dict) -> None:
        connection.setdefault("_recheck_fail_count", 0)
        connection.setdefault("_recheck_next_at", 0.0)
        connection.setdefault("_was_valid_once", False)

    def _schedule_recheck_after_failure(
        self, connection: dict, runtime_priority: bool
    ) -> None:
        self._init_recheck_meta(connection)
        fails = int(connection.get("_recheck_fail_count", 0)) + 1
        connection["_recheck_fail_count"] = fails

        if runtime_priority:
            base = max(10.0, self.recheck_server_interval_seconds * 2.0)
        else:
            base = max(30.0, self.recheck_inactive_interval_seconds * 0.25)

        delay = min(
            self.recheck_inactive_interval_seconds,
            base * (1.8 ** min(fails, 6)),
        )
        jitter = random.uniform(0.0, min(2.0, delay * 0.15))
        next_at = time.monotonic() + delay + jitter
        connection["_recheck_next_at"] = next_at

        key = self._get_connection_key(connection)
        if runtime_priority and key in self.runtime_disabled_servers:
            self.runtime_disabled_servers[key]["next_retry_at"] = next_at
            self.runtime_disabled_servers[key]["retry_count"] = fails

    def _format_mtu_log_line(
        self,
        template: str,
        connection: Optional[dict] = None,
        cause: str = "",
    ) -> str:
        if not template:
            return ""

        conn = connection or {}
        ip_value = str(conn.get("resolver", ""))
        domain_value = str(conn.get("domain", ""))
        up_mtu_value = str(conn.get("upload_mtu_bytes", 0))
        down_mtu_value = str(conn.get("download_mtu_bytes", 0))
        up_chars_value = str(conn.get("upload_mtu_chars", 0))
        now_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        line = str(template)
        replacements = {
            "{IP}": ip_value,
            "{ip}": ip_value,
            "{RESOLVER}": ip_value,
            "{resolver}": ip_value,
            "{DOMAIN}": domain_value,
            "{domain}": domain_value,
            "{UP_MTU}": up_mtu_value,
            "{up_mtu}": up_mtu_value,
            "{DOWN_MTU}": down_mtu_value,
            "{down_mtu}": down_mtu_value,
            "{DOWN-MTU}": down_mtu_value,
            "{down-mtu}": down_mtu_value,
            "{UP_MTU_CHARS}": up_chars_value,
            "{up_mtu_chars}": up_chars_value,
            "{CAUSE}": str(cause),
            "{cause}": str(cause),
            "{TIME}": now_text,
            "{time}": now_text,
        }
        for token, value in replacements.items():
            line = line.replace(token, value)
        return line

    def _append_mtu_log_line(
        self,
        template: str,
        connection: Optional[dict] = None,
        cause: str = "",
        output_path: str = "",
    ) -> None:
        target_path = output_path or self.mtu_success_output_path
        if not target_path:
            return

        line = self._format_mtu_log_line(
            template=template,
            connection=connection,
            cause=cause,
        ).strip()
        if not line:
            return

        try:
            with open(target_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
        except Exception as e:
            self.logger.warning(
                f"<yellow>[MTU]</yellow> Failed to append custom runtime line: {e}"
            )

    def _log_mtu_probe(self, message: str, level: str = "info", is_retry: bool = False):
        if is_retry or self.background_mtu_recheck_mode:
            return

        # MTU probe logs are intentionally noisy; keep them debug-only.
        # Final per-connection outcomes are logged in test_mtu_sizes().
        if level == "error":
            self.logger.error(message)
        else:
            self.logger.debug(message)

    def _append_mtu_usage_separator_once(self) -> None:
        if self.mtu_usage_separator_written:
            return
        if not self.mtu_using_separator_text or not self.mtu_success_output_path:
            return
        self._append_mtu_log_line(self.mtu_using_separator_text)
        self.mtu_usage_separator_written = True

    def _refresh_balancer_valid_servers(self) -> None:
        valid_conns = [c for c in self.connections_map if c.get("is_valid")]
        self.balancer.set_balancers(valid_conns)

    def _reset_server_runtime_state(self, server_key: str) -> None:
        self.server_health.pop(server_key, None)
        self.server_rtt_tracker.pop(server_key, None)
        self.balancer.reset_server_stats(server_key)

    def _track_server_send(self, server_key: str) -> None:
        now = time.monotonic()
        h = self.server_health[server_key]
        h["pending"].append(now)

    def _track_server_success(self, server_key: str) -> None:
        now = time.monotonic()
        h = self.server_health[server_key]
        if h["pending"]:
            h["pending"].popleft()
        h["events"].append((now, True))
        self._prune_server_health_window(server_key, now)

    def _prune_server_health_window(self, server_key: str, now: float) -> None:
        h = self.server_health.get(server_key)
        if not h:
            return
        window = max(1.0, self.auto_disable_timeout_window_seconds)
        events = h["events"]
        cutoff = now - window
        while events and events[0][0] < cutoff:
            events.popleft()

    def _collect_expired_pending_timeouts(self) -> None:
        now = time.monotonic()
        timeout_age = max(0.2, self.timeout)
        for server_key, h in list(self.server_health.items()):
            pending = h["pending"]
            events = h["events"]
            expire_before = now - timeout_age
            while pending and pending[0] <= expire_before:
                pending.popleft()
                events.append((now, False))
            self._prune_server_health_window(server_key, now)
            if not pending and not events:
                self.server_health.pop(server_key, None)

    def _should_disable_for_timeouts(self, server_key: str) -> bool:
        if not self.auto_disable_timeout_servers:
            return False
        if self.balancer.valid_servers_count <= 1:
            return False
        h = self.server_health.get(server_key)
        if not h:
            return False
        events = h["events"]
        if not events:
            return False
        if len(events) < max(1, self.auto_disable_min_observations):
            return False
        last_event_ts = events[len(events) - 1][0]
        first_event_ts = events[0][0]
        if (last_event_ts - first_event_ts) < max(
            1.0, self.auto_disable_timeout_window_seconds
        ):
            return False
        success_count = sum(1 for _, ok in events if ok)
        return success_count == 0

    def _disable_connection(self, connection: dict, cause: str) -> bool:
        if not connection:
            return False
        if not connection.get("is_valid"):
            return False
        if self.balancer.valid_servers_count <= 1:
            return False

        connection["is_valid"] = False
        self._init_recheck_meta(connection)
        connection["_was_valid_once"] = True
        connection["_recheck_next_at"] = time.monotonic() + max(
            5.0, self.recheck_server_interval_seconds * 2.0
        )
        connection["_recheck_fail_count"] = max(
            0, int(connection.get("_recheck_fail_count", 0))
        )
        key = self._get_connection_key(connection)
        self.runtime_disabled_servers[key] = {
            "disabled_at": time.monotonic(),
            "cause": str(cause),
            "next_retry_at": connection["_recheck_next_at"],
            "retry_count": int(connection.get("_recheck_fail_count", 0)),
        }
        self._reset_server_runtime_state(key)
        self._refresh_balancer_valid_servers()

        resolver = connection.get("resolver", "N/A")
        self.logger.warning(
            f"<yellow>DNS server <cyan>{resolver}</cyan> disabled due to: <red>{cause}</red></yellow>"
        )
        self._append_mtu_log_line(
            self.mtu_removed_server_log_format, connection=connection, cause=str(cause)
        )
        return True

    def _reactivate_connection(self, connection: dict) -> bool:
        if not connection:
            return False
        if connection.get("is_valid"):
            return False

        key = self._get_connection_key(connection)
        self.runtime_disabled_servers.pop(key, None)
        self._reset_server_runtime_state(key)
        self._init_recheck_meta(connection)
        connection["_recheck_fail_count"] = 0
        connection["_recheck_next_at"] = 0.0
        connection["_was_valid_once"] = True
        connection["is_valid"] = True
        self._refresh_balancer_valid_servers()

        resolver = connection.get("resolver", "N/A")
        self.logger.info(
            f"<green>DNS server <cyan>{resolver}</cyan> re-enabled and added back to active list.</green>"
        )
        self._append_mtu_log_line(
            self.mtu_added_server_log_format, connection=connection
        )
        return True

    # ---------------------------------------------------------
    # Network I/O & Packet Processing
    # ---------------------------------------------------------
    async def _send_and_receive_dns(
        self,
        query_data: bytes,
        resolver: str,
        port: int,
        timeout: float = 10,
        buffer_size: int = 0,
    ) -> Optional[bytes]:
        """Send a UDP packet and wait for the response."""
        buf_size = buffer_size or self.buffer_size

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)

        try:
            await async_sendto(self.loop, sock, query_data, (resolver, port))
            response, _ = await asyncio.wait_for(
                async_recvfrom(self.loop, sock, buf_size), timeout=timeout
            )
            return response
        except asyncio.TimeoutError:
            return None
        except Exception as e:
            self.logger.debug(
                f"Network error communicating with {resolver}:{port} - {e}"
            )
            return None
        finally:
            sock.close()

    def _send_ping_packet(self, payload=None):
        """Unified function to queue PING packets with lowest priority (4)."""
        if self.count_ping >= 100:
            return

        if self.session_restart_event and self.session_restart_event.is_set():
            return

        if payload is None:
            payload = b"PO:" + os.urandom(4)

        try:
            self.enqueue_seq = (self.enqueue_seq + 1) & 0x7FFFFFFF
            queue_item = (4, self.enqueue_seq, Packet_Type.PING, 0, 0, payload)
            was_empty = not self.main_queue
            self._push_queue_item(
                self.main_queue,
                self.__dict__,
                queue_item,
                self.tx_event,
            )
            self.count_ping += 1
            if was_empty:
                self._activate_response_queue(0)
        except Exception:
            pass

    def _activate_response_queue(self, stream_id: int) -> None:
        sid = int(stream_id)
        if sid in self.active_response_set:
            return
        self.active_response_set.add(sid)
        insort(self.active_response_ids, sid)

    def _deactivate_response_queue(self, stream_id: int) -> None:
        sid = int(stream_id)
        if sid not in self.active_response_set:
            return
        self.active_response_set.discard(sid)
        idx = bisect_left(self.active_response_ids, sid)
        if idx < len(self.active_response_ids) and self.active_response_ids[idx] == sid:
            self.active_response_ids.pop(idx)

    def _get_active_response_queue(self, stream_id: int):
        sid = int(stream_id)
        if sid == 0:
            if self.main_queue:
                return self.main_queue, self.__dict__
        else:
            stream_data = self.active_streams.get(sid)
            if stream_data:
                tx_queue = stream_data.get("tx_queue")
                if tx_queue:
                    return tx_queue, stream_data

        self._deactivate_response_queue(sid)
        return None, None

    def _match_allowed_domain_suffix(self, qname: str) -> Optional[str]:
        """Return the matched allowed domain suffix for qname, if any."""
        if not qname:
            return None

        name = qname.lower()
        for domain_suffix in self.domains_lower:
            if name.endswith(domain_suffix):
                return domain_suffix
        return None

    def _apply_session_compression_policy(self) -> None:
        """
        Decide effective per-session compression after MTU discovery.
        Compression is disabled for a direction when synced MTU is too small.
        """
        up = self.upload_compression_type
        down = self.download_compression_type

        if (
            self.synced_upload_mtu <= self.compression_min_size
            and self.upload_compression_type != Compression_Type.OFF
        ):
            up = Compression_Type.OFF
            self.logger.info(
                f"<cyan>[Compression]</cyan> Upload compression disabled due to small MTU: {self.synced_upload_mtu}"
            )

        if (
            self.synced_download_mtu <= self.compression_min_size
            and self.download_compression_type != Compression_Type.OFF
        ):
            down = Compression_Type.OFF
            self.logger.info(
                f"<cyan>[Compression]</cyan> Download compression disabled due to small MTU: {self.synced_download_mtu}"
            )

        self.upload_compression_type = up
        self.download_compression_type = down

        self.logger.info(
            f"<cyan>[Compression]</cyan> <green>Effective Compression - Upload: <yellow>{get_compression_name(up)}</yellow>, Download: <yellow>{get_compression_name(down)}</yellow></green>"
        )

    async def _process_received_packet(self, response_bytes, addr=None):
        """Parse DNS response, validate source/domain once, then extract VPN payload."""
        if not response_bytes:
            return None, b""

        parsed = await self._run_cpu_task(
            self.dns_parser.parse_dns_packet, response_bytes
        )
        if not parsed or not parsed.get("questions"):
            return None, b""

        try:
            qname = parsed["questions"][0].get("qName", "")
            matched_domain = self._match_allowed_domain_suffix(qname)
            if not matched_domain:
                return None, b""

            if addr:
                source_ip = str(addr[0]).strip().lower()
                if (
                    self.allowed_resolver_sources
                    and source_ip not in self.allowed_resolver_sources
                ):
                    return None, b""

                server_key = f"{source_ip}:{matched_domain}"
                self._track_server_success(server_key)
                sent_time = self.server_rtt_tracker.pop(server_key, 0.0)
                if sent_time > 0.0:
                    self.balancer.report_success(
                        server_key, rtt=(time.monotonic() - sent_time)
                    )
        except Exception:
            return None, b""

        parsed_header, returned_data = await self._run_cpu_task(
            self.dns_parser.extract_vpn_response,
            parsed,
            is_encoded=self.base_encode_responses,
        )
        if not parsed_header:
            return None, b""

        packet_cookie = int(parsed_header.get("session_cookie", 0) or 0)
        expected_cookie = self._expected_inbound_session_cookie(
            int(parsed_header.get("packet_type", -1))
        )
        if packet_cookie != expected_cookie:
            return None, b""

        return parsed_header, returned_data

    async def _run_cpu_task(self, func, *args, **kwargs):
        """Run CPU-heavy parser/codec work on a thread pool while preserving single state owner."""
        if not self.cpu_executor:
            return func(*args, **kwargs)
        loop = self.loop or asyncio.get_running_loop()
        if kwargs:
            return await loop.run_in_executor(
                self.cpu_executor, functools.partial(func, *args, **kwargs)
            )
        return await loop.run_in_executor(self.cpu_executor, func, *args)

    # ---------------------------------------------------------
    # MTU Testing Logic
    # ---------------------------------------------------------
    async def _binary_search_mtu(
        self,
        test_callable,
        min_mtu,
        max_mtu,
        min_threshold=30,
        allowed_min_mtu=0,
    ):
        if max_mtu <= 0:
            return 0

        min_allowed = max(min_threshold, allowed_min_mtu)

        if max_mtu < min_allowed:
            self.logger.debug(
                f"<cyan>[MTU]</cyan> Max MTU {max_mtu} is lower than allowed minimum {min_allowed}. Skipping."
            )
            return 0

        low = max(min_mtu, min_allowed)
        high = max_mtu

        if low > high:
            self.logger.debug(
                f"<cyan>[MTU]</cyan> Invalid MTU range: low={low}, high={high}. Skipping."
            )
            return 0

        self.logger.debug(
            f"<cyan>[MTU]</cyan> Starting binary search for MTU. Range: {low}-{high}"
        )

        tested_cache = {}

        async def check_mtu(value: int) -> bool:
            if value in tested_cache:
                return tested_cache[value]

            ok = False
            for attempt in range(self.mtu_test_retries):
                if self.should_stop.is_set():
                    tested_cache[value] = False
                    return False

                try:
                    if await test_callable(value, is_retry=(attempt > 0)):
                        ok = True
                        break
                except Exception as e:
                    self.logger.debug(f"MTU test callable raised for {value}: {e}")

            tested_cache[value] = ok
            return ok

        if await check_mtu(high):
            self.logger.debug(f"<cyan>[MTU]</cyan> Max MTU {high} is valid.")
            return high

        if low == high:
            self.logger.debug(
                f"<cyan>[MTU]</cyan> Only one MTU candidate ({low}) existed and it failed."
            )
            return 0

        if not await check_mtu(low):
            self.logger.debug(
                f"<cyan>[MTU]</cyan> Both boundary MTUs failed (min={low}, max={high}). Skipping middle checks."
            )
            return 0

        optimal = low
        left = low + 1
        right = high - 1

        while left <= right:
            if self.should_stop.is_set():
                return 0

            mid = (left + right) // 2
            ok = await check_mtu(mid)

            if ok:
                optimal = mid
                left = mid + 1
            else:
                right = mid - 1

        self.logger.debug(f"<cyan>[MTU]</cyan> Binary search result: {optimal}")
        return optimal

    async def send_upload_mtu_test(
        self,
        domain,
        dns_server,
        dns_port,
        mtu_size,
        is_retry=False,
    ):
        if not is_retry:
            self.logger.debug(
                f"<magenta>[MTU Probe]</magenta> Testing Upload MTU: <yellow>{mtu_size}</yellow> bytes via <cyan>{dns_server}</cyan>"
            )

        mtu_char_len, mtu_bytes = self.dns_parser.calculate_upload_mtu(
            domain=domain, mtu=mtu_size
        )
        if mtu_size > mtu_bytes or mtu_char_len < 29:
            return False

        flag_str = "1" if self.base_encode_responses else "0"
        random_hex = flag_str + generate_random_hex_text(mtu_char_len - 1)
        dns_queries = self.dns_parser.build_request_dns_query(
            domain=domain,
            session_id=os.urandom(1)[0],
            packet_type=Packet_Type.MTU_UP_REQ,
            data=random_hex,
            mtu_chars=mtu_char_len,
            encode_data=False,
            qType=DNS_Record_Type.TXT,
        )

        if not dns_queries:
            return False

        response = await self._send_and_receive_dns(
            dns_queries[0], dns_server, dns_port, self.mtu_test_timeout
        )

        if not response:
            self._log_mtu_probe(
                f"<yellow>⚠️ Upload test failed: Upload MTU <cyan>{mtu_size}</cyan> bytes via <cyan>{dns_server}</cyan> for <cyan>{domain}</cyan></yellow>",
                level="info",
                is_retry=is_retry,
            )
            return False

        parsed_header, _ = await self._process_received_packet(response)
        packet_type = parsed_header["packet_type"] if parsed_header else None

        if packet_type == Packet_Type.MTU_UP_RES:
            self._log_mtu_probe(
                f"<yellow>🟢 Upload test passed: Upload MTU <green>{mtu_size}</green> bytes via <cyan>{dns_server}</cyan> for <cyan>{domain}</cyan></yellow>",
                level="success",
                is_retry=is_retry,
            )
            return True
        elif packet_type == Packet_Type.ERROR_DROP:
            self._log_mtu_probe(
                f"<yellow>⚠️ Upload test failed (Server Dropped Packet): Upload MTU <cyan>{mtu_size}</cyan> bytes via <cyan>{dns_server}</cyan> for <cyan>{domain}</cyan></yellow>",
                level="info",
                is_retry=is_retry,
            )
            return False

        self._log_mtu_probe(
            f"<yellow>⚠️ Upload test failed: Upload MTU <cyan>{mtu_size}</cyan> bytes via <cyan>{dns_server}</cyan> for <cyan>{domain}</cyan></yellow>",
            level="info",
            is_retry=is_retry,
        )
        return False

    async def send_download_mtu_test(
        self,
        domain,
        dns_server,
        dns_port,
        mtu_size,
        up_mtu_bytes,
        is_retry=False,
    ):
        if not is_retry:
            self.logger.debug(
                f"<magenta>[MTU Probe]</magenta> Testing Download MTU: <yellow>{mtu_size}</yellow> bytes via <cyan>{dns_server}</cyan>"
            )

        worst_header = self.dns_parser.get_max_vpn_header_raw_size()
        test_header = self.dns_parser.get_vpn_header_raw_size(Packet_Type.MTU_DOWN_RES)
        header_reserve = max(0, worst_header - test_header)
        effective_download_size = mtu_size + header_reserve

        target_length = max(5, up_mtu_bytes)
        flag_byte = b"\x01" if self.base_encode_responses else b"\x00"
        data_bytes = flag_byte + effective_download_size.to_bytes(4, "big")

        if target_length > 5:
            data_bytes += os.urandom(target_length - 5)

        encrypted_data = self.dns_parser.codec_transform(data_bytes, encrypt=True)

        mtu_char_len, _ = self.dns_parser.calculate_upload_mtu(
            domain=domain, mtu=target_length
        )

        dns_queries = self.dns_parser.build_request_dns_query(
            domain=domain,
            session_id=os.urandom(1)[0],
            packet_type=Packet_Type.MTU_DOWN_REQ,
            data=encrypted_data,
            mtu_chars=mtu_char_len,
            encode_data=True,
            qType=DNS_Record_Type.TXT,
        )

        if not dns_queries:
            return False

        response = await self._send_and_receive_dns(
            dns_queries[0], dns_server, dns_port, self.mtu_test_timeout
        )

        if not response:
            self._log_mtu_probe(
                f"<yellow>⚠️ Download test failed: Download MTU <cyan>{mtu_size}</cyan> bytes via <cyan>{dns_server}</cyan> for <cyan>{domain}</cyan> (No Response)</yellow>",
                level="info",
                is_retry=is_retry,
            )
            return False

        parsed_header, returned_data = await self._process_received_packet(response)
        packet_type = parsed_header["packet_type"] if parsed_header else None

        if packet_type == Packet_Type.MTU_DOWN_RES:
            if returned_data and len(returned_data) == effective_download_size:
                self._log_mtu_probe(
                    f"<yellow>🟢 Download test passed: Download MTU <green>{mtu_size}</green> bytes via <cyan>{dns_server}</cyan> for <cyan>{domain}</cyan></yellow>",
                    level="success",
                    is_retry=is_retry,
                )
                return True
            else:
                self._log_mtu_probe(
                    f"<yellow>⚠️ Download test failed: Download MTU <cyan>{mtu_size}</cyan> bytes via <cyan>{dns_server}</cyan> for <cyan>{domain}</cyan> (Data Size Mismatch)</yellow>",
                    level="info",
                    is_retry=is_retry,
                )
                return False

        self._log_mtu_probe(
            f"<yellow>⚠️ Download test failed: Download MTU <cyan>{mtu_size}</cyan> bytes via <cyan>{dns_server}</cyan> for <cyan>{domain}</cyan> (Unexpected Packet Type)</yellow>",
            level="info",
            is_retry=is_retry,
        )
        return False

    async def test_upload_mtu_size(self, domain, dns_server, dns_port, default_mtu):
        try:
            self.logger.debug(f"<cyan>[MTU]</cyan> Testing upload MTU for {domain}")
            mtu_char_len, mtu_bytes = self.dns_parser.calculate_upload_mtu(
                domain=domain, mtu=0
            )
            if default_mtu > 512 or default_mtu <= 0:
                default_mtu = 512
            if mtu_bytes > default_mtu:
                mtu_bytes = default_mtu

            async def test_fn(m, is_retry=False):
                return await self.send_upload_mtu_test(
                    domain, dns_server, dns_port, m, is_retry
                )

            actual_max_allowed = min(default_mtu if default_mtu > 0 else 512, mtu_bytes)
            optimal_mtu = await self._binary_search_mtu(
                test_fn,
                0,
                actual_max_allowed,
                min_threshold=30,
                allowed_min_mtu=self.min_upload_mtu,
            )
            if optimal_mtu > 29:
                mtu_char_len, mtu_bytes = self.dns_parser.calculate_upload_mtu(
                    domain=domain, mtu=optimal_mtu
                )
                return True, mtu_bytes, mtu_char_len
        except Exception as e:
            self.logger.debug(f"Error calculating upload MTU for {domain}: {e}")
        return False, 0, 0

    async def test_download_mtu_size(
        self,
        domain,
        dns_server,
        dns_port,
        default_mtu,
        up_mtu_bytes,
    ):
        try:
            self.logger.debug(f"<cyan>[MTU]</cyan> Testing download MTU for {domain}")

            async def test_fn(m, is_retry=False):
                return await self.send_download_mtu_test(
                    domain, dns_server, dns_port, m, up_mtu_bytes, is_retry
                )

            optimal_mtu = await self._binary_search_mtu(
                test_fn,
                0,
                default_mtu,
                min_threshold=30,
                allowed_min_mtu=self.min_download_mtu,
            )

            if optimal_mtu >= max(30, self.min_download_mtu):
                return True, optimal_mtu
        except Exception as e:
            self.logger.debug(f"Error calculating download MTU for {domain}: {e}")
        return False, 0

    async def _config_recommendations(self):
        self.logger.info("<yellow>" + "=" * 80 + "</yellow>")
        self.logger.success(
            "<fg #ff456d>📢 Join our Telegram channel: <cyan>@MasterDNSVPN</cyan> for support and updates! 📢</fg #ff456d>"
        )
        self.logger.info("<yellow>" + "=" * 80 + "</yellow>")
        self.logger.info("<cyan>📊 Smart Config Recommendations & Diagnostics:</cyan>")
        self.logger.info(
            "<yellow>Review these suggestions to maximize your speed, stability, and MTU!</yellow>"
        )

        wait_time = 0
        has_warnings = False
        has_info = False

        unique_domains = set(self.domains)
        if len(unique_domains) > 1:
            min_domain_len = min(len(d) for d in unique_domains)
            best_domains = [d for d in unique_domains if len(d) <= min_domain_len]
            self.logger.warning(
                f"<cyan>🔸 [Domains]:</cyan> <yellow>You have multiple domains. Shorter domains give larger MTU.</yellow>"
                f"<yellow>Best to keep:</yellow> <green>{', '.join(best_domains)}</green>."
            )
            has_warnings = True

        all_resolvers = len(self.connections_map)

        if len(set(self.resolvers)) < 5:
            self.logger.warning(
                "<yellow>🔸 [Resolvers]: Using less than 5 resolvers. Add more for better reliability.</yellow>"
            )
            has_warnings = True
        self._apply_scale_profile(all_resolvers)

        if self.packet_duplication_count > 2:
            self.logger.warning(
                f"<yellow>🔸 [Bandwidth]: <cyan>PACKET_DUPLICATION_COUNT</cyan> is <red>{self.packet_duplication_count}</red>. Reduce to <green>1-2</green> to save bandwidth.</yellow>"
            )
            self.logger.info(
                "<cyan>      🔹 [Bandwidth Tip]:</cyan> Higher <cyan>PACKET_DUPLICATION_COUNT</cyan> can improve stability on bad networks but consumes more bandwidth and resolver capacity. Recommended: <green>1</green> for stable, <green>2</green> for unstable connections."
            )
            has_warnings = True

        if self.resolver_balancing_strategy != 2:
            self.logger.info(
                "<cyan>🔹 [Balancing]:</cyan> Consider using <cyan>RESOLVER_BALANCING_STRATEGY</cyan> = <green>2</green> (Round Robin) for even load distribution."
            )
            has_info = True

        if self.protocol_type == "SOCKS5" and self.listener_ip == "0.0.0.0":
            self.logger.info(
                "<cyan>🔹 [Security]:</cyan> SOCKS5 is bound to <blue>0.0.0.0</blue>. If local-only, bind to <green>127.0.0.1</green>"
            )

            has_info = True
            if not self.socks5_auth and self.listener_ip == "0.0.0.0":
                self.logger.warning(
                    "<yellow>🔸 [Security]: <cyan>SOCKS5_AUTH</cyan> is disabled on a public IP! Highly recommended to enable it.</yellow>"
                )
                has_warnings = True

            if (
                self.socks5_auth
                and (not self.socks5_user or not self.socks5_pass)
                and self.listener_ip == "0.0.0.0"
            ):
                self.logger.warning(
                    "<yellow>🔸 [Security]: <cyan>SOCKS5_AUTH</cyan> is enabled but username or password is not set. Please set <cyan>SOCKS5_USER</cyan> and <cyan>SOCKS5_PASS</cyan> in your config for better security.</yellow>"
                )
                has_warnings = True
            elif (
                self.socks5_auth
                and self.listener_ip == "0.0.0.0"
                and (
                    self.socks5_user == "master_dns_vpn"
                    or self.socks5_pass == "master_dns_vpn"
                )
            ):
                self.logger.warning(
                    "<yellow>🔸 [Security]: <cyan>SOCKS5_AUTH</cyan> is using the default username and/or password. Please change <cyan>SOCKS5_USER</cyan> and <cyan>SOCKS5_PASS</cyan> to custom values for better security.</yellow>"
                )
                has_warnings = True

            if (
                self.listener_port in (1080, 1081, 8080, 8000)
                and self.listener_ip == "0.0.0.0"
            ):
                self.logger.warning(
                    "<yellow>🔸 [Security]: Your SOCKS5 listener is using a common port (<red>"
                    + str(self.listener_port)
                    + "</red>). Consider changing <cyan>LISTEN_PORT</cyan> to a less common port like <green>{}</green> for better security through obscurity.</yellow>".format(
                        random.randint(10000, 65000)
                    )
                )
                has_warnings = True

        if self.arq_initial_rto > 0.5:
            self.logger.info(
                f"<cyan>🔹 [Latency]:</cyan> <cyan>ARQ_INITIAL_RTO</cyan> is <yellow>{self.arq_initial_rto}s</yellow>. Reduce to <green>0.2s-0.5</green>s for faster packet recovery."
            )
            has_info = True

        if self.arq_max_rto > 1.5:
            self.logger.info(
                f"<cyan>🔹 [Latency]:</cyan> <cyan>ARQ_MAX_RTO</cyan> is <yellow>{self.arq_max_rto}s</yellow>. Keep below <green>1.5</green>s for snappy connections."
            )
            has_info = True

        if self.arq_window_size < 500:
            self.logger.warning(
                f"<yellow>🔸 [Throughput]: <cyan>ARQ_WINDOW_SIZE</cyan> is <red>{self.arq_window_size}</red>. Increase to <green>500</green>+ for high speeds.</yellow>"
            )
            has_warnings = True

        if self.max_packets_per_batch < 10:
            self.logger.warning(
                f"<yellow>🔸 [Performance]: <cyan>MAX_PACKETS_PER_BATCH</cyan> is low (<red>{self.max_packets_per_batch}</red>). Consider increasing to <green>10</green>+ for better performance.</yellow>"
            )
            has_warnings = True

        if self.mtu_test_retries > 2:
            self.logger.info(
                f"<yellow>🔹 [MTU Testing]: <cyan>MTU_TEST_RETRIES</cyan> is set to <red>{self.mtu_test_retries}</red>. Consider reducing to <green>1-2</green> for faster MTU testing. Higher values can significantly increase startup time.</yellow>"
            )
            has_info = True

        if self.mtu_test_timeout > 2.0:
            self.logger.info(
                f"<yellow>🔹 [MTU Testing]: <cyan>MTU_TEST_TIMEOUT</cyan> is set to <red>{self.mtu_test_timeout}</red> seconds. Consider reducing to <green>0.5–2</green> seconds for faster MTU testing. A lower timeout can skip slower servers and reduce startup time, while higher values help find optimal MTU on unstable networks. Recommended: <green>0.5–1</green> second for stable networks, <green>2</green> seconds for unstable networks. Note that higher values can significantly increase startup time.</yellow>"
            )
            has_info = True

        try:
            max_len_domain = max(unique_domains, key=len) if unique_domains else ""
            _, optimal_up_mtu = self.dns_parser.calculate_upload_mtu(
                domain=max_len_domain, mtu=0
            )

            self.logger.info("<cyan>📦 --- MTU Limits & Calculations --- 📦</cyan>")
            self.logger.info(
                f"<green>   [Upload Limit]:</green> Based on your longest domain name, max theoretical Upload MTU is <green>{optimal_up_mtu}</green> bytes."
            )
            min_optimal_mtu = optimal_up_mtu - 5
            self.logger.info(
                f"      <fg #acff1c>• Best value for <cyan>MIN_UPLOAD_MTU</cyan> is <green>{min_optimal_mtu} - {optimal_up_mtu}</green> bytes.</fg #acff1c>"
            )
            self.logger.info(
                f"      <fg #acff1c>• Best value for <cyan>MAX_UPLOAD_MTU</cyan> is <green>{optimal_up_mtu}</green> bytes.</fg #acff1c>"
            )
            if self.min_upload_mtu < min_optimal_mtu:
                self.logger.warning(
                    f"<red>   [MTU Warning]:</red> Your <cyan>MIN_UPLOAD_MTU</cyan> <red>({self.min_upload_mtu})</red> is set very low. Consider increasing it to at least <green>{min_optimal_mtu}</green> bytes for better performance!"
                )
                self.logger.info(
                    "      • Setting <cyan>MIN_UPLOAD_MTU</cyan> lower than this range will support more resolvers but will decrease your speed."
                )
            if self.max_upload_mtu > optimal_up_mtu:
                self.logger.warning(
                    f"<red>      • [MTU Error]:</red> Your <cyan>MAX_UPLOAD_MTU</cyan> <red>({self.max_upload_mtu})</red> exceeds the theoretical limit based on your domain names <green>({optimal_up_mtu})</green>. Please reduce it!"
                )
            if self.min_upload_mtu > self.max_upload_mtu:
                self.logger.warning(
                    f"<red>      • [MTU Error]:</red> Your <cyan>MIN_UPLOAD_MTU</cyan> <red>({self.min_upload_mtu})</red> is greater than your <cyan>MAX_UPLOAD_MTU</cyan> <red>({self.max_upload_mtu})</red>. Please fix this!"
                )
            if self.min_upload_mtu > optimal_up_mtu:
                self.logger.warning(
                    f"<red>      • [MTU Warning]:</red> Your <cyan>MIN_UPLOAD_MTU</cyan> <red>({self.min_upload_mtu})</red> is set higher than the optimal range based on your domain names <green>({optimal_up_mtu})</green>. This may cause MTU testing to fail. Consider reducing it to at most <green>{optimal_up_mtu}</green> bytes!"
                )

            if optimal_up_mtu < 80:
                self.logger.warning(
                    f"<yellow>      • [Warning]: Your domain names are quite long, which significantly reduces your maximum Upload MTU to <red>{optimal_up_mtu}</red> bytes. Consider using shorter domain names for better performance.</yellow>"
                )

            # Max DNS Overhead = Header(12) + MaxQuestion(257) + AnswerHeader(12) + TXTOverhead(2) = 283
            dns_overhead = 283

            def calc_down_capacity(dns_limit):
                available = dns_limit - dns_overhead
                if available <= 0:
                    return 0
                if self.base_encode_responses:
                    raw_cap = int(
                        available * 0.75
                    )  # Base64 inflation (4 chars per 3 bytes)
                else:
                    raw_cap = available
                return max(
                    0,
                    raw_cap
                    - self.crypto_overhead
                    - self.dns_parser.get_max_vpn_header_raw_size(),
                )

            down_512 = calc_down_capacity(512)
            min_down_512 = max(0, down_512 - 10)
            down_1232 = calc_down_capacity(1232)
            min_down_1232 = max(0, down_1232 - 50)
            down_4096 = calc_down_capacity(4096)
            min_down_4096 = max(0, down_4096 - 100)

            mode_str = "Base64 (Encoded)" if self.base_encode_responses else "Raw Bytes"
            self.logger.info(
                f"<green>   [Download Limits]:</green> For a single Answer in <cyan>{mode_str}</cyan> mode:"
            )
            self.logger.info(
                f"      • <yellow>No EDNS0 (512 limit):</yellow> <cyan>MAX_DOWNLOAD_MTU</cyan> ~<green>{down_512}</green> and <cyan>MIN_DOWNLOAD_MTU</cyan> ~<green>{min_down_512}</green>"
            )
            self.logger.info(
                f"      • <yellow>Safe EDNS0 (1232 limit):</yellow> <cyan>MAX_DOWNLOAD_MTU</cyan> ~<green>{down_1232}</green> and <cyan>MIN_DOWNLOAD_MTU</cyan> ~<green>{min_down_1232}</green> bytes"
            )
            self.logger.info(
                f"      • <yellow>Max EDNS0 (4096 limit):</yellow> <cyan>MAX_DOWNLOAD_MTU</cyan> ~<green>{down_4096}</green> and <cyan>MIN_DOWNLOAD_MTU</cyan> ~<green>{min_down_4096}</green> bytes"
            )
            self.logger.info(
                f"      • Note: You can try <cyan>MIN_DOWNLOAD_MTU</cyan> = <green>{min_down_512}</green> and <cyan>MAX_DOWNLOAD_MTU</cyan> = <green>{down_4096}</green>, but if your network blocks EDNS0, you'll get better performance by setting <cyan>MAX_DOWNLOAD_MTU</cyan> to <green>{down_512}</green>."
            )

            if self.min_download_mtu < 100:
                self.logger.warning(
                    f"<red>      • [MTU Warning]:</red> Your <cyan>MIN_DOWNLOAD_MTU</cyan> ({self.min_download_mtu}) is set very low. Consider increasing it to at least <green>{min_down_512}</green> bytes for better performance!"
                )

            if self.max_download_mtu > down_4096:
                self.logger.warning(
                    f"<red>      • [MTU Error]:</red> Your <cyan>MAX_DOWNLOAD_MTU</cyan> ({self.max_download_mtu}) exceeds the absolute DNS limits ({down_4096}). Please reduce it!"
                )
                wait_time += 5
                has_warnings = True
            elif self.max_download_mtu > down_512:
                self.logger.info(
                    f"<cyan>      • [MTU Tip]:</cyan> If your network drops packets and MTU tests fail, it means EDNS0 is blocked. Lower <cyan>MAX_DOWNLOAD_MTU</cyan> to <green>{down_512}</green>."
                )

            self.max_upload_mtu = min(self.max_upload_mtu, optimal_up_mtu)
            self.min_upload_mtu = min(self.min_upload_mtu, self.max_upload_mtu)

        except Exception as e:
            self.logger.debug(f"Failed to calculate MTU bounds: {e}")

        self.logger.info("<yellow>" + "=" * 80 + "</yellow>")
        if self.base_encode_responses:
            self.logger.info(
                "<cyan>🔹 [Encoding Mode]:</cyan> <cyan>BASE_ENCODE_DATA</cyan> is <green>enabled</green>. "
                "<fg #acff1c>Pros:</fg #acff1c> Most resolvers support it. "
                "<fg #ff6b6b>Cons:</fg #ff6b6b> ~33% overhead reduces max Download MTU."
            )
        else:
            self.logger.info(
                "<cyan>🔹 [Encoding Mode]:</cyan> <cyan>BASE_ENCODE_DATA</cyan> is <red>disabled</red>. "
                "<fg #acff1c>Pros:</fg #acff1c> Larger Download MTU, higher performance. "
                "<fg #ff6b6b>Cons:</fg #ff6b6b> Some resolvers may reject raw binary data."
            )

        if self.config_version < self.min_config_version:
            self.logger.warning(
                f"<yellow>🔸 [Config Version]:</yellow> Your config version ({self.config_version}) is outdated. Please update to the latest version ({self.min_config_version}) for best performance and new features."
            )

        if has_warnings:
            wait_time += 5
        if has_info:
            wait_time += 3

        if wait_time > 0:
            try:
                self.logger.info("<yellow>" + "=" * 80 + "</yellow>")
                self.logger.success(
                    "<fg #ff456d>📢 Join our Telegram channel: <cyan>@MasterDNSVPN</cyan> for support and updates! 📢</fg #ff456d>"
                )
                self.logger.info("<yellow>" + "=" * 80 + "</yellow>")
                self.logger.info(
                    f"<fg #e8a251>Waiting <cyan>{wait_time}</cyan> seconds so you can read the warnings above...</fg #e8a251>"
                )
                self.logger.info(
                    "<fg #51e8bd>Press <green>ENTER</green> key to skip the wait and start immediately...</fg #51e8bd>"
                )
                self.logger.info(
                    "<fg #e85151>Or press <cyan>CTRL+C</cyan> to stop and fix your configuration!</fg #e85151>"
                )
                await asyncio.wait_for(
                    self.loop.run_in_executor(None, input), timeout=wait_time
                )
            except Exception:
                pass
        else:
            self.logger.success(
                "\n<green>✅ Your configuration looks great! No critical warnings found. 🚀</green>"
            )

    def _resolve_mtu_success_output_path(self) -> str:
        if not self.save_mtu_servers_to_file:
            return ""

        raw_name = (self.mtu_servers_file_name or "").strip()
        if not raw_name:
            self.logger.warning(
                "<yellow>MTU result saving is enabled, but MTU_SERVERS_FILE_NAME is empty.</yellow>"
            )
            return ""

        if "{time}" in raw_name:
            ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())
            base_name = raw_name.replace("{time}", "").strip()
            if not base_name:
                base_name = "masterdnsvpn_success_test"

            root, ext = os.path.splitext(base_name)
            if not root:
                root = base_name
            if not ext:
                ext = ".log"

            raw_name = f"{root}_{ts}{ext}"

        return os.path.abspath(raw_name)

    def _prepare_mtu_success_output_file(self) -> str:
        output_path = self._resolve_mtu_success_output_path()
        self.mtu_usage_separator_written = False
        if not output_path:
            self.mtu_success_output_path = ""
            return ""

        try:
            output_dir = os.path.dirname(output_path)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)

            # Rewrite file from scratch at test start.
            with open(output_path, "w", encoding="utf-8"):
                pass

            self.logger.info(
                f"<blue>[MTU]</blue> Success output file initialized: <cyan>{output_path}</cyan>"
            )
            self.mtu_success_output_path = output_path
            return output_path
        except Exception as e:
            self.logger.warning(
                f"<yellow>[MTU]</yellow> Failed to initialize output file <cyan>{output_path}</cyan>: {e}"
            )
            self.mtu_success_output_path = ""
            return ""

    def _append_mtu_success_line(self, output_path: str, connection: dict) -> None:
        if not output_path:
            return

        template = (
            self.mtu_servers_file_format or "{IP} - UP: {UP_MTU} DOWN: {DOWN-MTU}"
        )
        self._append_mtu_log_line(
            template=template,
            connection=connection,
            output_path=output_path,
        )

    async def test_mtu_sizes(self) -> bool:

        try:
            await asyncio.wait_for(self._config_recommendations(), timeout=10)
        except Exception as _:
            pass

        self.logger.info("=" * 80)
        self.logger.info(
            f"<y>Testing MTU sizes for all resolver-domain pairs (parallel={self.mtu_test_parallelism})...</y>"
        )

        total_conns = len(self.connections_map)
        mtu_output_path = self._prepare_mtu_success_output_file()
        for connection in self.connections_map:
            if not connection:
                continue
            self._init_recheck_meta(connection)
            connection["is_valid"] = False
            connection["upload_mtu_bytes"] = 0
            connection["upload_mtu_chars"] = 0
            connection["download_mtu_bytes"] = 0
            connection["packet_loss"] = 100
            connection["_recheck_fail_count"] = 0
            connection["_was_valid_once"] = False
            connection["_recheck_next_at"] = 0.0

        sem = asyncio.Semaphore(max(1, self.mtu_test_parallelism))
        counters = {
            "completed": 0,
            "valid": 0,
            "reject_upload": 0,
            "reject_download": 0,
        }
        counters_lock = asyncio.Lock()

        async def _test_one_connection(server_id: int, connection: dict) -> None:
            if not connection or self.should_stop.is_set():
                return

            async with sem:
                if self.should_stop.is_set():
                    return

                domain = connection.get("domain")
                resolver = connection.get("resolver")
                dns_port = 53

                self.logger.debug(
                    f"<blue>Testing connection <yellow>{domain}</yellow> via <cyan>{resolver}</cyan> (<yellow>{server_id} / {total_conns}</yellow>)...</blue>"
                )

                up_valid, up_mtu_bytes, up_mtu_char = await self.test_upload_mtu_size(
                    domain, resolver, dns_port, self.max_upload_mtu
                )

                if not up_valid or (
                    self.min_upload_mtu > 0 and up_mtu_bytes < self.min_upload_mtu
                ):
                    connection["_recheck_next_at"] = (
                        time.monotonic() + self.recheck_inactive_interval_seconds
                    )
                    async with counters_lock:
                        counters["completed"] += 1
                        counters["reject_upload"] += 1
                        completed = counters["completed"]
                        valid_now = counters["valid"]
                        rejected_now = (
                            counters["reject_upload"] + counters["reject_download"]
                        )
                    self.logger.warning(
                        f"<red>❌ Rejected ({completed}/{total_conns}): <cyan>{domain}</cyan> via <cyan>{resolver}</cyan> | reason=<yellow>UPLOAD_MTU</yellow> | value=<cyan>{up_mtu_bytes}</cyan> | totals: valid=<green>{valid_now}</green>, rejected=<red>{rejected_now}</red></red>"
                    )
                    return

                down_valid, down_mtu_bytes = await self.test_download_mtu_size(
                    domain, resolver, dns_port, self.max_download_mtu, up_mtu_bytes
                )

                if not down_valid or (
                    self.min_download_mtu > 0 and down_mtu_bytes < self.min_download_mtu
                ):
                    connection["_recheck_next_at"] = (
                        time.monotonic() + self.recheck_inactive_interval_seconds
                    )
                    async with counters_lock:
                        counters["completed"] += 1
                        counters["reject_download"] += 1
                        completed = counters["completed"]
                        valid_now = counters["valid"]
                        rejected_now = (
                            counters["reject_upload"] + counters["reject_download"]
                        )
                    self.logger.warning(
                        f"<red>❌ Rejected ({completed}/{total_conns}): <cyan>{domain}</cyan> via <cyan>{resolver}</cyan> | reason=<yellow>DOWNLOAD_MTU</yellow> | value=<cyan>{down_mtu_bytes}</cyan> | totals: valid=<green>{valid_now}</green>, rejected=<red>{rejected_now}</red></red>"
                    )
                    return

                connection["is_valid"] = True
                connection["upload_mtu_bytes"] = up_mtu_bytes
                connection["upload_mtu_chars"] = up_mtu_char
                connection["download_mtu_bytes"] = down_mtu_bytes
                connection["packet_loss"] = 0
                connection["_recheck_fail_count"] = 0
                connection["_recheck_next_at"] = 0.0
                connection["_was_valid_once"] = True

                async with counters_lock:
                    counters["completed"] += 1
                    counters["valid"] += 1
                    completed = counters["completed"]
                    valid_now = counters["valid"]
                    rejected_now = (
                        counters["reject_upload"] + counters["reject_download"]
                    )
                self.logger.info(
                    f"<green>✅ Accepted ({completed}/{total_conns}): <cyan>{domain}</cyan> via <cyan>{resolver}</cyan> | upload=<cyan>{up_mtu_bytes}</cyan> | download=<cyan>{down_mtu_bytes}</cyan> | totals: valid=<green>{valid_now}</green>, rejected=<red>{rejected_now}</red></green>"
                )

                self._append_mtu_success_line(mtu_output_path, connection)

        tasks = [
            asyncio.create_task(_test_one_connection(idx, conn))
            for idx, conn in enumerate(self.connections_map, start=1)
            if conn
        ]
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    self.logger.debug(f"MTU parallel test worker error: {r}")
                    counters["completed"] += 1

        valid_conns = [c for c in self.connections_map if c.get("is_valid")]
        if not valid_conns:
            self.logger.error(
                "<red>No valid connections found after MTU testing!</red>"
            )
            return False

        self.initial_mtu_scan_finished_at = time.monotonic()
        self.next_inactive_recheck_at = (
            self.initial_mtu_scan_finished_at + self.recheck_inactive_interval_seconds
        )
        self._append_mtu_usage_separator_once()

        return True

    async def _runtime_timeout_guard_worker(self) -> None:
        while not self.should_stop.is_set() and not self.session_restart_event.is_set():
            try:
                self._collect_expired_pending_timeouts()
                if (
                    self.auto_disable_timeout_servers
                    and self.balancer.valid_servers_count > 1
                ):
                    for conn in list(self.balancer.valid_servers):
                        key = self._get_connection_key(conn)
                        if self._should_disable_for_timeouts(key):
                            self._disable_connection(
                                conn,
                                cause=f"100% timeout for {int(self.auto_disable_timeout_window_seconds)}s window",
                            )
                await self._sleep(max(0.5, self.auto_disable_check_interval_seconds))
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.debug(f"Runtime timeout guard worker error: {e}")
                await self._sleep(1.0)

    async def _recheck_one_inactive_connection(self, connection: dict) -> bool:
        domain = connection.get("domain")
        resolver = connection.get("resolver")
        if not domain or not resolver:
            return False

        up_valid, up_mtu_bytes, up_mtu_char = await self.test_upload_mtu_size(
            domain, resolver, 53, self.max_upload_mtu
        )
        if (not up_valid) or (
            self.min_upload_mtu > 0 and up_mtu_bytes < self.min_upload_mtu
        ):
            return False

        down_valid, down_mtu_bytes = await self.test_download_mtu_size(
            domain, resolver, 53, self.max_download_mtu, up_mtu_bytes
        )
        if (not down_valid) or (
            self.min_download_mtu > 0 and down_mtu_bytes < self.min_download_mtu
        ):
            return False

        # Keep runtime MTU consistency; avoid adding servers that cannot handle
        # the currently negotiated session MTU.
        if (
            self.synced_upload_mtu > 0
            and self.synced_download_mtu > 0
            and (
                up_mtu_bytes < self.synced_upload_mtu
                or down_mtu_bytes < self.synced_download_mtu
            )
        ):
            return False

        connection["upload_mtu_bytes"] = up_mtu_bytes
        connection["upload_mtu_chars"] = up_mtu_char
        connection["download_mtu_bytes"] = down_mtu_bytes
        connection["packet_loss"] = 0
        return self._reactivate_connection(connection)

    async def _recheck_inactive_servers_worker(self) -> None:
        while not self.should_stop.is_set() and not self.session_restart_event.is_set():
            try:
                if not self.recheck_inactive_servers_enabled:
                    await self._sleep(2.0)
                    continue
                if not self.success_mtu_checks or not self.connections_map:
                    await self._sleep(2.0)
                    continue

                now = time.monotonic()
                inactive_conns = [
                    c for c in self.connections_map if not c.get("is_valid", False)
                ]
                if not inactive_conns:
                    self.next_inactive_recheck_at = (
                        now + self.recheck_inactive_interval_seconds
                    )

                    await self._sleep(min(2.0, self.recheck_server_interval_seconds))
                    continue

                for conn in inactive_conns:
                    self._init_recheck_meta(conn)

                runtime_priority = []
                normal_candidates = []
                for conn in inactive_conns:
                    key = self._get_connection_key(conn)
                    due_at = float(conn.get("_recheck_next_at", 0.0) or 0.0)
                    if now < due_at:
                        continue

                    if key in self.runtime_disabled_servers:
                        runtime_priority.append(conn)
                    else:
                        normal_candidates.append(conn)

                if not runtime_priority and not normal_candidates:
                    await self._sleep(min(5.0, self.recheck_server_interval_seconds))
                    continue

                runtime_priority.sort(
                    key=lambda c: (
                        float(
                            self.runtime_disabled_servers.get(
                                c.get("_key", ""), {}
                            ).get("next_retry_at", 0.0)
                        ),
                        int(c.get("_recheck_fail_count", 0)),
                    )
                )
                normal_candidates.sort(
                    key=lambda c: (
                        int(c.get("_recheck_fail_count", 0)),
                        float(c.get("_recheck_next_at", 0.0)),
                    )
                )

                selected = runtime_priority[: self.recheck_batch_size]
                remaining_slots = max(0, self.recheck_batch_size - len(selected))
                if remaining_slots > 0:
                    selected.extend(normal_candidates[:remaining_slots])

                self.background_mtu_recheck_mode = True
                try:
                    for idx, conn in enumerate(selected):
                        if (
                            self.should_stop.is_set()
                            or self.session_restart_event.is_set()
                        ):
                            break

                        ok = await self._recheck_one_inactive_connection(conn)
                        key = self._get_connection_key(conn)
                        if not ok:
                            self._schedule_recheck_after_failure(
                                conn,
                                runtime_priority=(key in self.runtime_disabled_servers),
                            )
                        else:
                            conn["_recheck_fail_count"] = 0
                            conn["_recheck_next_at"] = 0.0

                        if idx < len(selected) - 1:
                            await self._sleep(self.recheck_server_interval_seconds)
                finally:
                    self.background_mtu_recheck_mode = False
                    self.next_inactive_recheck_at = time.monotonic() + min(
                        5.0, max(1.0, self.recheck_server_interval_seconds)
                    )
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.background_mtu_recheck_mode = False
                self.logger.debug(f"Inactive server recheck worker error: {e}")
                await self._sleep(2.0)

    async def _sync_mtu_with_server(self, max_attempts=10) -> bool:
        """Send the synced MTU values to the server for this session."""
        self.logger.info(
            f"<blue>Syncing MTU with server for session <cyan>{self.session_id}</cyan>...</blue>"
        )

        for overall_attempt in range(max_attempts):
            if self.should_stop.is_set():
                return False

            selected_conn = self.balancer.get_best_server()
            if not selected_conn:
                await asyncio.sleep(0.5)
                continue

            domain = selected_conn.get("domain")
            resolver = selected_conn.get("resolver")

            sync_token = os.urandom(8)

            data_bytes = (
                self.synced_upload_mtu.to_bytes(4, byteorder="big")
                + self.synced_download_mtu.to_bytes(4, byteorder="big")
                + sync_token
            )

            encrypted_data = self.dns_parser.codec_transform(data_bytes, encrypt=True)

            dns_queries = self.dns_parser.build_request_dns_query(
                domain=domain,
                session_id=self.session_id,
                packet_type=Packet_Type.SET_MTU_REQ,
                data=encrypted_data,
                mtu_chars=self.synced_upload_mtu_chars,
                encode_data=True,
                qType=DNS_Record_Type.TXT,
                session_cookie=self.session_cookie,
            )

            if not dns_queries:
                self.logger.error(
                    f"<yellow>Failed to build MTU sync via <cyan>{resolver}</cyan> for <cyan>{domain}</cyan>, Retrying...</yellow>"
                )
                await asyncio.sleep(0.2)
                continue

            for inner_attempt in range(3):
                if self.should_stop.is_set():
                    return False

                response = await self._send_and_receive_dns(
                    dns_queries[0], resolver, 53, 2.0
                )

                if response:
                    parsed_header, returned_data = await self._process_received_packet(
                        response
                    )
                    packet_type = (
                        parsed_header["packet_type"] if parsed_header else None
                    )

                    if packet_type == Packet_Type.SET_MTU_RES:
                        if returned_data == sync_token:
                            self.logger.success(
                                "<green>MTU values successfully synced with the server!</green>"
                            )
                            return True
                        else:
                            self.logger.warning(
                                "<red>MTU Sync token mismatch! Ignoring response.</red>"
                            )

                if inner_attempt < 2:
                    await asyncio.sleep(0.5)

            self.logger.warning(
                f"<yellow>MTU sync failed via <cyan>{resolver}</cyan> for <cyan>{domain}</cyan>. Retrying overall process...</yellow>"
            )
            await asyncio.sleep(0.2)

        return False

    # ---------------------------------------------------------
    # Core Loop & Session Setup
    # ---------------------------------------------------------
    async def _init_session(self, max_attempts=10) -> bool:
        """Initialize a new session with the server."""
        self.logger.info("<blue>Initializing session ...</blue>")

        for overall_attempt in range(max_attempts):
            if self.should_stop.is_set():
                return False

            selected_conn = self.balancer.get_best_server()
            if not selected_conn:
                await asyncio.sleep(0.5)
                continue

            domain = selected_conn.get("domain")
            resolver = selected_conn.get("resolver")

            init_token = os.urandom(8).hex().encode("ascii")
            flag_byte = b"\x01" if self.base_encode_responses else b"\x00"
            compression_pref_byte = bytes(
                [
                    ((self.upload_compression_type & 0x0F) << 4)
                    | (self.download_compression_type & 0x0F)
                ]
            )
            payload = init_token + flag_byte + compression_pref_byte

            encrypted_token = self.dns_parser.codec_transform(payload, encrypt=True)

            dns_queries = self.dns_parser.build_request_dns_query(
                domain=domain,
                session_id=0,
                packet_type=Packet_Type.SESSION_INIT,
                data=encrypted_token,
                mtu_chars=self.synced_upload_mtu_chars,
                encode_data=True,
                qType=DNS_Record_Type.TXT,
            )

            if not dns_queries:
                self.logger.error(
                    f"Failed to build session init DNS query via {resolver} for {domain}, Retrying..."
                )
                await asyncio.sleep(0.2)
                continue

            for inner_attempt in range(3):
                if self.should_stop.is_set():
                    return False

                response = await self._send_and_receive_dns(
                    dns_queries[0], resolver, 53, self.timeout
                )

                if response:
                    parsed_header, returned_data = await self._process_received_packet(
                        response
                    )

                    if (
                        parsed_header
                        and parsed_header["packet_type"] == Packet_Type.SESSION_ACCEPT
                    ):
                        try:
                            if isinstance(returned_data, str):
                                returned_data = returned_data.encode(
                                    "ascii", errors="ignore"
                                )
                            elif not isinstance(returned_data, (bytes, bytearray)):
                                returned_data = bytes(returned_data or b"")

                            parts = bytes(returned_data).split(b":", 2)
                            if len(parts) < 2:
                                return False

                            received_token = parts[0].decode("ascii", errors="ignore")
                            raw_sid = bytes(parts[1] or b"")
                            compression_pref = 0
                            session_cookie = 0
                            if len(parts) >= 3:
                                raw_comp = bytes(parts[2] or b"")
                                if len(raw_comp) >= 1:
                                    compression_pref = raw_comp[0]
                                    if len(raw_comp) >= 2:
                                        session_cookie = raw_comp[1]
                                else:
                                    comp_txt = (
                                        raw_comp.decode("ascii", errors="ignore")
                                        .strip()
                                        .strip("\x00")
                                    )
                                    if comp_txt.isdigit():
                                        compression_pref = int(comp_txt)
                                    elif raw_comp:
                                        compression_pref = raw_comp[0]
                                        self.logger.warning(
                                            f"Unexpected compression payload format from server: {raw_comp!r}. Falling back to first byte value {compression_pref}."
                                        )

                            if received_token != init_token.decode("ascii"):
                                self.logger.warning(
                                    "Token mismatch! Ignoring old session response."
                                )
                                return False

                            new_upload_compression_type = normalize_compression_type(
                                (compression_pref >> 4) & 0x0F
                            )

                            if (
                                new_upload_compression_type
                                != self.upload_compression_type
                            ):
                                self.upload_compression_type = (
                                    new_upload_compression_type
                                )
                                self.logger.warning(
                                    f"<yellow>Server requested upload compression change. New Upload Compression: <cyan>{get_compression_name(self.upload_compression_type)}</cyan></yellow>"
                                )

                            new_download_compression_type = normalize_compression_type(
                                compression_pref & 0x0F
                            )
                            if (
                                new_download_compression_type
                                != self.download_compression_type
                            ):
                                self.download_compression_type = (
                                    new_download_compression_type
                                )
                                self.logger.warning(
                                    f"<yellow>Server requested download compression change. New Download Compression: <cyan>{get_compression_name(self.download_compression_type)}</cyan></yellow>"
                                )
                            sid_txt = (
                                raw_sid.decode("ascii", errors="ignore")
                                .strip()
                                .strip("\x00")
                            )
                            if sid_txt.isdigit():
                                self.session_id = int(sid_txt)
                            elif len(raw_sid) == 1:
                                # Backward-compatible fallback for binary SID payloads.
                                self.session_id = raw_sid[0]
                            else:
                                raise ValueError(
                                    f"Invalid session id payload: {raw_sid!r}"
                                )
                            self.session_cookie = int(session_cookie) & 0xFF
                            self.logger.success(
                                f"<green>Validated Session ID: <cyan>{self.session_id}</cyan>, Upload Compression: <cyan>{get_compression_name(self.upload_compression_type)}</cyan>, Download Compression: <cyan>{get_compression_name(self.download_compression_type)}</cyan></green>"
                            )
                            return True
                        except Exception as e:
                            self.logger.error(f"Session parse error: {e}")

                if inner_attempt < 2:
                    await asyncio.sleep(0.5)

            self.logger.warning(
                f"Session init failed via {resolver} for {domain}. Retrying overall process..."
            )
            await asyncio.sleep(0.2)

        return False

    async def run_client(self) -> None:
        """Run the MasterDnsVPN Client main logic."""
        self.logger.info("Setting up connections...")
        all_resolvers = 0
        self._reset_tunnel_runtime_state()
        self.session_id = 0
        try:
            self.session_restart_event = asyncio.Event()

            if not self.success_mtu_checks or len(self.connections_map) <= 0:
                await self.create_connection_map()
                all_resolvers = len(self.connections_map)

                if not await self.test_mtu_sizes():
                    self.logger.error("No valid servers found to connect.")
                    return

                valid_conns = [c for c in self.connections_map if c.get("is_valid")]

                if not valid_conns:
                    self.logger.error("No valid connections found after MTU testing!")
                    return

                self.balancer.set_balancers(valid_conns)

                self.synced_upload_mtu = min(c["upload_mtu_bytes"] for c in valid_conns)
                self.synced_upload_mtu_chars = min(
                    c["upload_mtu_chars"] for c in valid_conns
                )
                self.synced_download_mtu = min(
                    c["download_mtu_bytes"] for c in valid_conns
                )

                self.safe_uplink_mtu = max(
                    64, self.synced_upload_mtu - self.crypto_overhead
                )

                upload_pack_limit = self._compute_mtu_based_pack_limit(
                    self.synced_upload_mtu,
                    50.0,
                    self._block_packer.size,
                )
                self.max_packed_blocks = max(
                    1,
                    min(upload_pack_limit, self.max_packets_per_batch),
                )
                max_found_upload_mtu = max(c["upload_mtu_bytes"] for c in valid_conns)
                max_found_download_mtu = max(
                    c["download_mtu_bytes"] for c in valid_conns
                )

                self.logger.success("<green>MTU Testing Completed!</green>")
                self.logger.info("=" * 80)
                self.logger.info("<cyan>Valid Connections After MTU Testing:</cyan>")
                self.logger.info("=" * 80)
                self.logger.info(
                    f"{'Resolver':<20} {'Upload MTU':<15} {'Download MTU':<15} {'Domain':<30}"
                )
                self.logger.info("-" * 80)
                for conn in valid_conns:
                    resolver = conn.get("resolver", "N/A")
                    up_mtu = conn.get("upload_mtu_bytes", 0)
                    down_mtu = conn.get("download_mtu_bytes", 0)
                    domain = conn.get("domain", "N/A")
                    self.logger.info(
                        f"<cyan>{resolver:<20}</cyan> <green>{up_mtu:<15}</green> <green>{down_mtu:<15}</green> <blue>{domain:<30}</blue>"
                    )
                self.logger.info("=" * 80)
                self.logger.success(
                    f"<blue>Total valid resolvers after MTU testing: <cyan>{len(self.balancer.valid_servers)}</cyan> of <cyan>{all_resolvers}</cyan></blue>"
                )
                self.logger.info(
                    f"<blue>Note:</blue> Each packet will be sent <yellow>{self.packet_duplication_count}</yellow> times to improve reliability."
                )

                self.logger.info("=" * 80)
                self.logger.info(
                    f"<cyan>[MTU RESULTS]</cyan> Max Upload MTU found: <yellow>{max_found_upload_mtu}</yellow> | Max Download MTU found: <yellow>{max_found_download_mtu}</yellow>"
                )
                self.logger.info(
                    f"<cyan>[MTU RESULTS]</cyan> Selected Synced Upload MTU: <yellow>{self.synced_upload_mtu}</yellow> | Selected Synced Download MTU: <yellow>{self.synced_download_mtu}</yellow>"
                )
                self.logger.info("=" * 80)
                self.logger.info(
                    f"<green>Global MTU Configuration -> Upload: <cyan>{self.synced_upload_mtu}</cyan>, Download: <cyan>{self.synced_download_mtu}</cyan></green>"
                )
                self.success_mtu_checks = True

            selected_conn = self.balancer.get_best_server()
            if not selected_conn:
                self.logger.error("No active servers available from Balancer.")
                return
            max_attempts = self.config.get("MAX_CONNECTION_ATTEMPTS", 10)
            self._apply_session_compression_policy()
            if not await self._init_session(max_attempts):
                self.logger.error("Failed to initialize session with the server.")
                return

            self.logger.success(
                f"<green>Session Established! Session ID: <cyan>{self.session_id}</cyan></green>"
            )

            if not await self._sync_mtu_with_server(max_attempts):
                self.logger.error("Failed to sync MTU with the server.")
                return

            await self._main_tunnel_loop()

        except Exception as e:
            self.logger.error(f"Error setting up connections: {e}")
            return

    # ---------------------------------------------------------
    # TCP Multiplexing Logic & Handlers
    # ---------------------------------------------------------
    def _reset_tunnel_runtime_state(self, reset_session_cookie: bool = True) -> None:
        """
        Reset reconnect-sensitive runtime state.
        IMPORTANT: MTU discovery fields are intentionally preserved.
        """
        self.count_ping = 0
        self.enqueue_seq = 0
        self.round_robin_stream_id = -1
        self.last_stream_id = 0
        if reset_session_cookie:
            self.session_cookie = 0

        self.main_queue = []
        self.active_response_ids = []
        self.active_response_set = set()
        self.tx_event = asyncio.Event()

        self.active_streams = {}
        self.closed_streams = {}
        self.priority_counts = {}
        self.track_ack = set()
        self.track_resend = set()
        self.track_types = set()
        self.track_data = set()
        self.track_seq_packets = set()
        self.track_fragment_packets = set()
        self.rx_tasks = set()
        self.server_rtt_tracker.clear()
        self.server_health.clear()

        ping_mgr = getattr(self, "ping_manager", None)
        if ping_mgr:
            now = time.monotonic()
            ping_mgr.active_connections = 0
            ping_mgr.last_data_activity = now
            ping_mgr.last_ping_time = now

    def _clear_runtime_state_after_disconnect(self) -> None:
        """
        Best-effort cleanup after tunnel disconnect/restart.
        IMPORTANT: MTU discovery fields are intentionally preserved.
        """
        try:
            self.main_queue.clear()
            self.track_ack.clear()
            self.track_resend.clear()
            self.track_types.clear()
            self.track_data.clear()
            self.track_seq_packets.clear()
            self.track_fragment_packets.clear()
            self.priority_counts.clear()
            self.active_response_ids.clear()
            self.active_response_set.clear()
            self.active_streams.clear()
            self.closed_streams.clear()
            self.rx_tasks.clear()
            self.server_rtt_tracker.clear()
            self.server_health.clear()
        except Exception:
            pass

        self.tx_event = asyncio.Event()

        ping_mgr = getattr(self, "ping_manager", None)
        if ping_mgr:
            now = time.monotonic()
            ping_mgr.active_connections = 0
            ping_mgr.last_data_activity = now
            ping_mgr.last_ping_time = now

    async def _main_tunnel_loop(self):
        """Start local TCP server and main worker tasks."""
        self.logger.info("<blue>Entering VPN Tunnel Main Loop...</blue>")
        self._reset_tunnel_runtime_state(reset_session_cookie=False)
        self.tunnel_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            buffer_size = int(self.config.get("SOCKET_BUFFER_SIZE", 8388608))
            try:
                self.tunnel_sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_RCVBUF, buffer_size
                )
                self.tunnel_sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_SNDBUF, buffer_size
                )
            except OSError:
                new_size = 65535
                self.tunnel_sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_RCVBUF, new_size
                )
        except Exception as e:
            self.logger.debug(f"Failed to increase socket buffer: {e}")

        self.tunnel_sock.bind(("0.0.0.0", 0))

        if sys.platform == "win32":
            try:
                sio_udp_connreset = getattr(socket, "SIO_UDP_CONNRESET", 0x9800000C)
                if hasattr(self.tunnel_sock, "ioctl"):
                    self.tunnel_sock.ioctl(sio_udp_connreset, 0)
            except OSError as e:
                msg = str(e).lower()
                if "invalid ioctl command" in msg or "not supported" in msg:
                    self.logger.debug(
                        "SIO_UDP_CONNRESET is not supported in this runtime; continuing without it."
                    )
                else:
                    self.logger.debug(f"Failed to set SIO_UDP_CONNRESET: {e}")
            except Exception as e:
                self.logger.debug(f"Failed to set SIO_UDP_CONNRESET: {e}")

        self.tunnel_sock.setblocking(False)

        listen_ip = self.listener_ip
        listen_port = int(self.listener_port)

        server = None
        stop_task = None
        restart_task = None
        try:
            if sys.platform == "win32":
                server = await asyncio.start_server(
                    self._handle_local_tcp_connection,
                    listen_ip,
                    listen_port,
                    reuse_address=False,
                )
            else:
                server = await asyncio.start_server(
                    self._handle_local_tcp_connection,
                    listen_ip,
                    listen_port,
                    reuse_address=True,
                    reuse_port=True,
                )

            try:
                bound_addrs = []
                for sock in server.sockets or []:
                    try:
                        bound_addrs.append(str(sock.getsockname()))
                    except Exception:
                        pass
                if bound_addrs:
                    self.logger.info(
                        f"<cyan>Local listener sockets: {', '.join(bound_addrs)}</cyan>"
                    )
            except Exception:
                pass

            if self.protocol_type == "SOCKS5":
                if self.config.get("SOCKS5_USER") and self.config.get("SOCKS5_PASS"):
                    self.logger.info(
                        f"<green>SOCKS5 Proxy started on <cyan>{listen_port}</cyan> with Authentication. Username: <red>{self.config.get('SOCKS5_USER')}</red></green>"
                    )
                else:
                    self.logger.info(
                        f"<green>SOCKS5 Proxy started on <cyan>{listen_port}</cyan> without Authentication.</green>"
                    )
            else:
                self.logger.info(
                    f"<green>TCP Proxy started on <cyan>{listen_port}</cyan> (Protocol: <cyan>{self.protocol_type}</cyan>)</green>"
                )

            self.workers = []
            cpu_count = os.cpu_count() or 1

            num_rx_workers = self.config.get("NUM_RX_WORKERS", 2)
            for _ in range(num_rx_workers):
                self.workers.append(self.loop.create_task(self._rx_worker()))

            num_workers = self.config.get("NUM_DNS_WORKERS", 4)
            self.logger.info(
                f"<cyan>Runtime CPU cores detected: {cpu_count} | RX workers: {num_rx_workers} | TX workers: {num_workers}</cyan>"
            )
            self.logger.debug(
                f"<magenta>[LOOP]</magenta> Starting {num_workers} TX workers."
            )
            for _ in range(num_workers):
                self.workers.append(self.loop.create_task(self._tx_worker()))

            self.workers.append(self.loop.create_task(self._retransmit_worker()))
            self.workers.append(self.loop.create_task(self.ping_manager.ping_loop()))
            self.workers.append(
                self.loop.create_task(self._runtime_timeout_guard_worker())
            )
            self.workers.append(
                self.loop.create_task(self._recheck_inactive_servers_worker())
            )

            stop_task = asyncio.create_task(self.should_stop.wait())
            restart_task = asyncio.create_task(self.session_restart_event.wait())

            await asyncio.wait(
                [stop_task, restart_task], return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            self.logger.info("<yellow>Cleaning up tunnel resources...</yellow>")

            for w in getattr(self, "workers", []):
                if not w.done():
                    w.cancel()

            if hasattr(self, "workers") and self.workers:
                await asyncio.gather(*self.workers, return_exceptions=True)

            if server:
                try:
                    server.close()
                    await asyncio.wait_for(server.wait_closed(), timeout=1.0)
                except Exception:
                    pass

            close_tasks = []
            is_restart = bool(
                self.session_restart_event and self.session_restart_event.is_set()
            )
            close_reason = "Client Restarting" if is_restart else "Client App Closing"
            for sid in list(self.active_streams.keys()):
                close_tasks.append(
                    self.close_stream(
                        sid,
                        reason=close_reason,
                        abortive=is_restart,
                    )
                )

            if close_tasks:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*close_tasks, return_exceptions=True),
                        timeout=1.5,
                    )
                except Exception:
                    pass
            for task in list(self.rx_tasks):
                if not task.done():
                    task.cancel()

            if self.rx_tasks:
                await asyncio.gather(*self.rx_tasks, return_exceptions=True)

            self.rx_tasks.clear()
            self.active_streams.clear()

            if hasattr(self, "tunnel_sock") and self.tunnel_sock:
                try:
                    self.tunnel_sock.close()
                except Exception:
                    pass
                self.tunnel_sock = None

            self._clear_runtime_state_after_disconnect()

        if stop_task and not stop_task.done():
            stop_task.cancel()
        if restart_task and not restart_task.done():
            restart_task.cancel()
        if stop_task or restart_task:
            await asyncio.gather(
                *(t for t in (stop_task, restart_task) if t),
                return_exceptions=True,
            )

        self.logger.info(
            "<yellow>Cleaning up old connections before reconnecting...</yellow>"
        )
        self._clear_runtime_state_after_disconnect()

    async def _rx_worker(self):
        """Continuously listen for incoming VPN packets on the tunnel socket."""
        self.logger.debug("<magenta>[RX]</magenta> RX Worker started.")
        while not self.should_stop.is_set() and not self.session_restart_event.is_set():
            try:
                data, addr = await async_recvfrom(self.loop, self.tunnel_sock, 65536)
                await self.rx_semaphore.acquire()
                task = self.loop.create_task(
                    self._process_and_route_incoming(data, addr)
                )
                self.rx_tasks.add(task)
                task.add_done_callback(
                    lambda t: (self.rx_tasks.discard(t), self.rx_semaphore.release())
                )

            except asyncio.CancelledError:
                break
            except OSError as e:
                if getattr(e, "winerror", None) == 10054:
                    continue
                await asyncio.sleep(0.01)
            except Exception as _:
                await asyncio.sleep(0.01)

    async def _process_and_route_incoming(self, data, addr):
        """Helper to process incoming data asynchronously."""
        parsed_header, returned_data = await self._process_received_packet(data, addr)
        if parsed_header:
            await self._handle_server_response(parsed_header, returned_data)

    async def _close_writer_safely(self, writer):
        """Safely close the writer connection"""
        try:
            if writer and not writer.is_closing():
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
        except Exception:
            pass

    def _new_get_stream_id(self):
        start = (self.last_stream_id + 1) or 1
        stream_id = start
        wrapped = False

        while not self.should_stop.is_set() and not (
            self.session_restart_event and self.session_restart_event.is_set()
        ):
            if stream_id > 65535:
                if wrapped:
                    return False, 0
                stream_id = 1
                wrapped = True

            if stream_id not in self.active_streams:
                self.last_stream_id = stream_id
                return True, stream_id

            stream_id += 1

        return False, 0

    def _is_socks5_error_packet(self, packet_type: int) -> bool:
        return int(packet_type) in self._socks5_error_reply_map

    def _packet_type_to_socks5_rep(self, packet_type: int) -> int:
        return int(self._socks5_error_reply_map.get(int(packet_type), 0x01))

    def _build_socks5_fail_reply(self, packet_type: int) -> bytes:
        rep = self._packet_type_to_socks5_rep(packet_type)
        return bytes([0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])

    def _expected_inbound_session_cookie(self, packet_type: int) -> int:
        if int(packet_type) in (
            Packet_Type.SESSION_ACCEPT,
            Packet_Type.MTU_UP_RES,
            Packet_Type.MTU_DOWN_RES,
            Packet_Type.ERROR_DROP,
        ):
            return 0
        return int(self.session_cookie or 0)

    def _create_client_arq_stream(
        self,
        stream_id: int,
        reader,
        writer,
        is_socks: bool = False,
        initial_data: bytes = b"",
    ) -> ARQ:
        kwargs = {}
        if is_socks:
            kwargs["is_socks"] = True
            kwargs["initial_data"] = initial_data

        return ARQ(
            stream_id=stream_id,
            session_id=self.session_id,
            enqueue_tx_cb=self._client_enqueue_tx,
            enqueue_control_tx_cb=self._client_enqueue_control_tx,
            reader=reader,
            writer=writer,
            mtu=self.safe_uplink_mtu,
            logger=self.logger,
            window_size=int(self.arq_window_size),
            rto=float(self.arq_initial_rto),
            max_rto=float(self.arq_max_rto),
            enable_control_reliability=True,
            control_rto=self.arq_control_initial_rto,
            control_max_rto=self.arq_control_max_rto,
            control_max_retries=self.arq_control_max_retries,
            **kwargs,
        )

    async def _handle_local_tcp_connection(self, reader, writer):
        if self.should_stop.is_set() or (
            self.session_restart_event and self.session_restart_event.is_set()
        ):
            await self._close_writer_safely(writer)
            return

        target_payload = b""
        is_socks5 = False

        # -------------------------------------------------------------------
        # SOCKS5 HANDSHAKE LOGIC
        # -------------------------------------------------------------------
        if self.protocol_type == "SOCKS5":
            try:
                # 1. Greeting
                try:
                    greeting = await asyncio.wait_for(
                        reader.readexactly(2), timeout=3.0
                    )
                except asyncio.TimeoutError:
                    await self._close_writer_safely(writer)
                    return

                if greeting[0] != 0x05:
                    await self._close_writer_safely(writer)
                    return
                num_methods = greeting[1]
                methods = await reader.readexactly(num_methods)
                client_IP = "Unknown"
                try:
                    client_IP = writer.get_extra_info("peername")[0]
                except Exception:
                    pass
                # Auth Negotiation
                if getattr(self, "socks5_auth", False):
                    if 0x02 not in methods:  # 0x02 is Username/Password
                        self.logger.warning(
                            f"<yellow>🔒 SOCKS5 Client does not support required Username/Password authentication method. Rejecting connection. IP: <cyan>{client_IP}</cyan></yellow>"
                        )
                        writer.write(b"\x05\xff")  # No acceptable methods
                        await writer.drain()
                        await self._close_writer_safely(writer)
                        return
                    writer.write(b"\x05\x02")
                    await writer.drain()

                    # Read Auth Request
                    auth_version = await reader.readexactly(1)
                    if auth_version[0] != 0x01:
                        await self._close_writer_safely(writer)
                        return

                    ulast = await reader.readexactly(1)
                    uname = await reader.readexactly(ulast[0])

                    plast = await reader.readexactly(1)
                    passwd = await reader.readexactly(plast[0])

                    if (
                        uname.decode() != self.socks5_user
                        or passwd.decode() != self.socks5_pass
                    ):
                        writer.write(b"\x01\x01")  # Auth failed
                        await writer.drain()
                        self.logger.warning(
                            f"<yellow>🔒 SOCKS5 Auth failed for user: <cyan>{uname.decode()}</cyan> from IP: <cyan>{client_IP}</cyan></yellow>"
                        )
                        await self._close_writer_safely(writer)
                        return

                    writer.write(b"\x01\x00")  # Auth success
                    await writer.drain()
                    self.logger.debug(
                        f"<green>🔓 SOCKS5 Auth successful for user: <cyan>{uname.decode()}</cyan> from IP: <cyan>{client_IP}</cyan></green>"
                    )
                else:
                    if 0x00 not in methods:  # 0x00 is No Auth
                        writer.write(b"\x05\xff")
                        await writer.drain()
                        await self._close_writer_safely(writer)
                        return
                    writer.write(b"\x05\x00")
                    await writer.drain()

                is_socks5 = True
                # 2. Connection Request
                req_header = await reader.readexactly(4)
                # VER(1), CMD(1), RSV(1), ATYP(1)
                if req_header[0] != 0x05:
                    await self._close_writer_safely(writer)
                    return

                cmd = req_header[1]
                # We only support TCP CONNECT (0x01)
                if cmd != 0x01:
                    if cmd == 0x03:
                        self.logger.debug(
                            "<yellow>SOCKS5 UDP Associate requested. Rejecting gracefully (Not Supported).</yellow>"
                        )
                    writer.write(
                        b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00"
                    )  # Command not supported
                    await writer.drain()
                    await self._close_writer_safely(writer)
                    return

                atyp = req_header[3]
                target_addr_bytes = b""
                if atyp == 0x01:  # IPv4
                    target_addr_bytes = await reader.readexactly(4)
                elif atyp == 0x03:  # Domain
                    dlen = await reader.readexactly(1)
                    target_addr_bytes = dlen + await reader.readexactly(dlen[0])
                elif atyp == 0x04:  # IPv6
                    target_addr_bytes = await reader.readexactly(16)
                else:
                    await self._close_writer_safely(writer)
                    return

                target_port_bytes = await reader.readexactly(2)

                # Format:  [ATYP] [ADDR_BYTES] [PORT_BYTES]
                target_payload = bytes([atyp]) + target_addr_bytes + target_port_bytes

            except Exception as e:
                self.logger.debug(f"SOCKS5 Handshake error: {e}")
                await self._close_writer_safely(writer)
                return

        stream_id_status, stream_id = self._new_get_stream_id()
        if not stream_id_status:
            self.logger.error(
                "<red>No available Stream IDs! Too many connections.</red>"
            )
            await self._close_writer_safely(writer)
            return

        self.logger.info(
            f"<green>New local connection, assigning Stream ID: <cyan>{stream_id}</cyan></green>"
        )

        now_mono = time.monotonic()
        syn_data = b""

        self.active_streams[stream_id] = {
            "stream_id": stream_id,
            "reader": reader,
            "writer": writer,
            "create_time": now_mono,
            "last_activity_time": now_mono,
            "status": "PENDING",
            "stream": None,
            "stream_creating": False,
            "pending_inbound_data": {},
            "tx_queue": [],
            "initial_payload": target_payload,
            "priority_counts": {},
            "track_ack": set(),
            "track_resend": set(),
            "track_fin": set(),
            "track_syn_ack": set(),
            "track_data": set(),
            "track_types": set(),
            "track_seq_packets": set(),
            "track_fragment_packets": set(),
        }

        if not is_socks5:
            await self._enqueue_packet(
                0, stream_id, 0, Packet_Type.STREAM_SYN, syn_data
            )
        else:
            self.active_streams[stream_id]["handshake_event"] = asyncio.Event()

            await self._stream_syn_handler(stream_id, target_payload, reader, writer)

            try:
                await asyncio.wait_for(
                    self.active_streams[stream_id]["handshake_event"].wait(),
                    timeout=self.socks_handshake_timeout,
                )

                stream_data = self.active_streams.get(stream_id)
                if not stream_data:
                    raise ConnectionError("Stream closed before handshake completion.")

                socks_err_ptype = stream_data.get("socks_error_packet")
                if socks_err_ptype is not None:
                    packet_name = self._packet_type_names.get(
                        int(socks_err_ptype), str(socks_err_ptype)
                    )
                    raise ConnectionError(f"SOCKS handshake failed ({packet_name})")

                if stream_data.get("status") == "ACTIVE":
                    if writer and not writer.is_closing():
                        reply = b"\x05\x00\x00"  # VER, REP=0(success), RSV
                        if atyp == 0x01:
                            reply += b"\x01" + target_addr_bytes + target_port_bytes
                        elif atyp == 0x03:
                            reply += b"\x03" + target_addr_bytes + target_port_bytes
                        elif atyp == 0x04:
                            reply += b"\x04" + target_addr_bytes + target_port_bytes

                        try:
                            writer.write(reply)
                            await writer.drain()

                            stream_obj = stream_data.get("stream")
                            if (
                                stream_obj
                                and hasattr(stream_obj, "socks_connected")
                                and not stream_obj.socks_connected.is_set()
                            ):
                                stream_obj.socks_connected.set()

                        except Exception as e:
                            self.logger.debug(
                                f"Failed to write SOCKS5 reply to local client: {e}"
                            )
                    else:
                        await self.close_stream(
                            stream_id,
                            reason="Local app closed before SOCKS5 reply",
                            abortive=True,
                        )
                        return
                else:
                    raise ConnectionError("Stream closed before handshake completion.")

            except asyncio.TimeoutError:
                stream_data = self.active_streams.get(stream_id, {})
                socks_err_ptype = stream_data.get(
                    "socks_error_packet", Packet_Type.SOCKS5_UPSTREAM_UNAVAILABLE
                )
                self.logger.debug(
                    f"SOCKS handshake timed out for stream {stream_id} after {self.socks_handshake_timeout:.1f}s"
                )
                try:
                    fail_reply = self._build_socks5_fail_reply(socks_err_ptype)
                    writer.write(fail_reply)
                    await writer.drain()
                except Exception:
                    pass
                await self.close_stream(
                    stream_id,
                    reason="SOCKS handshake timeout",
                    abortive=True,
                )
                return

            except Exception as e:
                stream_data = self.active_streams.get(stream_id, {})
                socks_err_ptype = stream_data.get("socks_error_packet")
                self.logger.debug(f"SOCKS Target Rejected by Server: {e}")
                try:
                    fail_reply = self._build_socks5_fail_reply(
                        socks_err_ptype or Packet_Type.SOCKS5_CONNECT_FAIL
                    )
                    writer.write(fail_reply)
                    await writer.drain()
                except Exception:
                    pass
                await self.close_stream(
                    stream_id,
                    reason="SOCKS Target Rejected by Server",
                    abortive=True,
                )

    async def _stream_syn_handler(
        self, stream_id: int, target_payload: bytes, reader, writer
    ):
        stream_data = self.active_streams[stream_id]
        stream_data["status"] = "ACTIVE"

        stream = self._create_client_arq_stream(
            stream_id=stream_id,
            reader=reader,
            writer=writer,
            is_socks=True,
            initial_data=b"",
        )
        stream_data["stream"] = stream
        stream_data.pop("socks_error_packet", None)
        await stream.send_control_packet(
            packet_type=Packet_Type.SOCKS5_SYN,
            sequence_num=0,
            payload=target_payload,
            priority=0,
            track_for_ack=True,
            ack_type=Packet_Type.SOCKS5_SYN_ACK,
        )
        self.logger.debug(
            f"<green>SOCKS5 Stream <cyan>{stream_id}</cyan> Created and queued SOCKS5_SYN chunks.</green>"
        )
        self._send_ping_packet()

    # ---------------------------------------------------------
    # ARQ Enqueue Adapters
    # ---------------------------------------------------------
    async def _client_enqueue_tx(
        self,
        priority,
        stream_id,
        sn,
        data,
        **flags,
    ):
        if self.should_stop.is_set() or (
            self.session_restart_event and self.session_restart_event.is_set()
        ):
            return

        ptype = self._resolve_arq_packet_type(**flags)
        await self._enqueue_packet(priority, stream_id, sn, ptype, data)

    async def _client_enqueue_control_tx(
        self,
        priority,
        stream_id,
        sn,
        packet_type,
        payload,
        is_retransmit=False,
    ):
        _ = is_retransmit
        await self._enqueue_packet(
            priority, stream_id, sn, int(packet_type), payload or b""
        )

    async def _enqueue_packet(self, priority, stream_id, sn, packet_type, data):
        ptype = int(packet_type)
        effective_priority = self._effective_priority_for_packet(ptype, priority)

        self.enqueue_seq = (self.enqueue_seq + 1) & 0x7FFFFFFF
        queue_item = (
            effective_priority,
            self.enqueue_seq,
            ptype,
            stream_id,
            sn,
            data,
        )

        if stream_id == 0:
            if not self._track_main_packet_once(
                self.__dict__,
                stream_id,
                ptype,
                sn,
                payload=data,
            ):
                return
            was_empty = not self.main_queue
            self._push_queue_item(
                self.main_queue, self.__dict__, queue_item, self.tx_event
            )
            if was_empty:
                self._activate_response_queue(0)
            return

        stream_data = self.active_streams.get(stream_id)
        if not stream_data:
            if (
                ptype
                in (
                    Packet_Type.STREAM_RST,
                    Packet_Type.STREAM_RST_ACK,
                    Packet_Type.STREAM_FIN_ACK,
                )
                or ptype in self._control_request_ack_map.values()
            ):
                if not self._track_main_packet_once(
                    self.__dict__,
                    stream_id,
                    ptype,
                    sn,
                    payload=data,
                ):
                    return
                was_empty = not self.main_queue
                self._push_queue_item(
                    self.main_queue, self.__dict__, queue_item, self.tx_event
                )
                if was_empty:
                    self._activate_response_queue(0)
            return

        if not self._track_stream_packet_once(
            stream_data,
            ptype,
            sn,
            data_packet_types=(Packet_Type.STREAM_DATA,),
            payload=data,
        ):
            return
        was_empty = not stream_data["tx_queue"]
        self._push_queue_item(
            stream_data["tx_queue"], stream_data, queue_item, self.tx_event
        )
        if was_empty:
            self._activate_response_queue(stream_id)

    def _pack_selected_response_blocks(
        self,
        selected_stream_id: int,
        selected_queue,
        selected_owner: dict,
        first_item: tuple,
    ) -> bytes:
        if self.max_packed_blocks <= 1:
            return b""

        target_priority = int(first_item[0])
        _pack = self._block_packer.pack
        _pop_packable = self._pop_packable_control_block
        _owner_has_priority = self._owner_has_priority
        packed_buffer = bytearray(_pack(first_item[2], first_item[3], first_item[4]))
        blocks = 1

        while blocks < self.max_packed_blocks:
            popped = _pop_packable(selected_queue, selected_owner, target_priority)
            if popped is None:
                break
            packed_buffer.extend(_pack(popped[2], popped[3], popped[4]))
            blocks += 1
            if not selected_queue:
                self._deactivate_response_queue(selected_stream_id)
                break

        if blocks >= self.max_packed_blocks:
            return bytes(packed_buffer)

        active_ids = tuple(self.active_response_ids)
        if not active_ids:
            return bytes(packed_buffer)

        num_queues = len(active_ids)
        start_pos = bisect_right(active_ids, selected_stream_id)
        if start_pos >= num_queues:
            start_pos = 0

        for offset in range(num_queues):
            if blocks >= self.max_packed_blocks:
                break
            sid = active_ids[(start_pos + offset) % num_queues]
            if sid == selected_stream_id:
                continue
            q_ref, owner = self._get_active_response_queue(sid)
            if not q_ref or not owner:
                continue
            if not _owner_has_priority(owner, target_priority):
                continue

            while blocks < self.max_packed_blocks:
                popped = _pop_packable(q_ref, owner, target_priority)
                if popped is None:
                    break
                packed_buffer.extend(_pack(popped[2], popped[3], popped[4]))
                blocks += 1
                if not q_ref:
                    self._deactivate_response_queue(sid)
                    break

        return bytes(packed_buffer) if blocks > 1 else b""

    def _dequeue_response_packet(self):
        if not self.active_response_ids:
            return None

        last_stream_id = int(self.round_robin_stream_id)
        selected_pos = bisect_right(self.active_response_ids, last_stream_id)
        attempts = len(self.active_response_ids)
        target_queue = None
        pop_owner = None
        selected_stream_id = 0

        while attempts > 0 and self.active_response_ids:
            if selected_pos >= len(self.active_response_ids):
                selected_pos = 0
            candidate_stream_id = self.active_response_ids[selected_pos]
            target_queue, pop_owner = self._get_active_response_queue(
                candidate_stream_id
            )
            if target_queue and pop_owner:
                selected_stream_id = candidate_stream_id
                break
            attempts -= 1

        if not target_queue or not pop_owner:
            return None

        item = heapq.heappop(target_queue)
        self._on_queue_pop(pop_owner, item)
        if not target_queue:
            self._deactivate_response_queue(selected_stream_id)
        self.round_robin_stream_id = selected_stream_id

        if item[2] == Packet_Type.PING and self.count_ping > 0:
            self.count_ping -= 1

        if (
            item[2] in self._packable_control_types
            and not item[5]
            and self.max_packed_blocks > 1
        ):
            packed = self._pack_selected_response_blocks(
                selected_stream_id=selected_stream_id,
                selected_queue=target_queue,
                selected_owner=pop_owner,
                first_item=item,
            )
            if packed:
                return (
                    item[0],
                    item[1],
                    Packet_Type.PACKED_CONTROL_BLOCKS,
                    0,
                    0,
                    packed,
                )

        return item

    async def _tx_worker(self):
        while not self.should_stop.is_set() and not self.session_restart_event.is_set():
            try:
                await self.tx_event.wait()
            except asyncio.CancelledError:
                break
            except Exception:
                continue

            item = self._dequeue_response_packet()
            if not item:
                self.tx_event.clear()
                continue

            try:
                q_ptype, q_stream_id, q_sn = item[2], item[3], item[4]
                if q_ptype in (Packet_Type.STREAM_DATA, Packet_Type.STREAM_RESEND):
                    stream_data = self.active_streams.get(q_stream_id)
                    if stream_data and "stream" in stream_data:
                        arq = stream_data["stream"]
                        if arq and q_sn not in getattr(arq, "snd_buf", {}):
                            continue

                await self._send_single_packet(item)
            except Exception as _:
                pass

    async def _send_single_packet(self, item):
        self.ping_manager.active_connections = len(self.active_streams)
        _, _, pkt_type, stream_id, sn, data = item

        if pkt_type != Packet_Type.PING:
            self.ping_manager.update_activity()

        if stream_id in self.active_streams:
            now_mono = time.monotonic()
            self.active_streams[stream_id]["last_activity_time"] = now_mono
        try:
            actual_comp_type = 0
            if (
                data
                and self.upload_compression_type != Compression_Type.OFF
                and pkt_type in self.dns_parser._PT_COMP_EXT
            ):
                data, actual_comp_type = compress_payload(
                    data, self.upload_compression_type, self.compression_min_size
                )

            data_encrypted = (
                self.dns_parser.codec_transform(data, encrypt=True) if data else b""
            )

            target_conns = self.balancer.get_unique_servers(
                self.packet_duplication_count
            )

            for conn in target_conns:
                self.server_rtt_tracker[conn["_key"]] = time.monotonic()
                self.balancer.report_send(conn["_key"])
                self._track_server_send(conn["_key"])
                query_packets = self.dns_parser.build_request_dns_query(
                    domain=conn["domain"],
                    session_id=self.session_id,
                    packet_type=pkt_type,
                    data=data_encrypted,
                    mtu_chars=self.synced_upload_mtu_chars,
                    encode_data=True,
                    qType=DNS_Record_Type.TXT,
                    stream_id=stream_id,
                    sequence_num=sn,
                    compression_type=actual_comp_type,
                    session_cookie=self.session_cookie,
                )

                if not query_packets:
                    continue

                for query_packet in query_packets:
                    try:
                        await async_sendto(
                            self.loop,
                            self.tunnel_sock,
                            query_packet,
                            (conn["resolver"], 53),
                        )
                    except Exception as _:
                        pass
        except Exception as e:
            self.logger.debug(f"TX Worker error during packet building/sending: {e}")

    async def _handle_closed_stream_packet(
        self, ptype: int, stream_id: int, sn: int
    ) -> bool:
        if stream_id <= 0 or stream_id not in self.closed_streams:
            return False

        if ptype == Packet_Type.STREAM_FIN:
            await self._enqueue_packet(
                0, stream_id, sn, Packet_Type.STREAM_FIN_ACK, b""
            )
            return True
        if ptype == Packet_Type.STREAM_RST:
            await self._enqueue_packet(
                0, stream_id, sn, Packet_Type.STREAM_RST_ACK, b""
            )
            return True
        if ptype in (
            Packet_Type.STREAM_DATA,
            Packet_Type.STREAM_RESEND,
            Packet_Type.STREAM_DATA_ACK,
        ):
            await self._enqueue_packet(
                0,
                stream_id,
                0,
                Packet_Type.STREAM_RST,
                b"",
            )
            return True
        return False

    async def _handle_server_response(self, header, data):
        ptype = int(header["packet_type"])
        header_session_id = header.get("session_id", -1)

        if header_session_id != self.session_id and ptype != Packet_Type.SESSION_ACCEPT:
            return

        if data and ptype in self.dns_parser._PT_COMP_EXT:
            comp_type = int(
                header.get("compression_type", Compression_Type.OFF)
                or Compression_Type.OFF
            )
            if comp_type != Compression_Type.OFF:
                data, ok = try_decompress_payload(data, comp_type)
                if not ok:
                    # Invalid/mismatched compressed payload; drop packet to avoid parser churn.
                    return

        stream_id = header.get("stream_id", 0)
        sn = header.get("sequence_num", 0)

        if await self._handle_closed_stream_packet(ptype, stream_id, sn):
            return

        stream_data = self.active_streams.get(stream_id) if stream_id > 0 else None
        stream_id_exists = stream_data is not None
        if stream_id_exists:
            stream_data["last_activity_time"] = time.monotonic()

        if ptype == Packet_Type.PACKED_CONTROL_BLOCKS and data:
            _unpack_from = self._block_packer.unpack_from
            block_size = self._block_packer.size
            inline_batch = []
            for i in range(0, len(data), block_size):
                if i + block_size > len(data):
                    break
                b_ptype, b_stream_id, b_sn = _unpack_from(data, i)
                if (
                    b_ptype not in self._valid_packet_types
                    or b_ptype == Packet_Type.PACKED_CONTROL_BLOCKS
                ):
                    continue
                inline_batch.append(
                    self._handle_server_response(
                        {
                            "packet_type": b_ptype,
                            "session_id": self.session_id,
                            "stream_id": b_stream_id,
                            "sequence_num": b_sn,
                        },
                        b"",
                    )
                )
                if len(inline_batch) >= 8:
                    await asyncio.gather(*inline_batch, return_exceptions=True)
                    inline_batch.clear()

            if inline_batch:
                await asyncio.gather(
                    *inline_batch,
                    return_exceptions=True,
                )

            self._send_ping_packet()
            return
        if ptype == Packet_Type.STREAM_SYN_ACK and stream_id_exists:
            if stream_data.get("stream") or stream_data.get("status") == "ACTIVE":
                return
            if stream_data.get("stream_creating"):
                return

            writer = stream_data.get("writer")
            if not writer or writer.is_closing():
                self.active_streams.pop(stream_id, None)
                return

            stream_data["stream_creating"] = True
            try:
                stream_data["status"] = "ACTIVE"
                raw_reader = stream_data["reader"]
                initial_payload = stream_data.get("initial_payload", b"")
                wrapped_reader = PrependReader(raw_reader, initial_payload)

                stream = self._create_client_arq_stream(
                    stream_id=stream_id,
                    reader=wrapped_reader,
                    writer=writer,
                )
                stream_data["stream"] = stream
                stream_data.pop("socks_error_packet", None)
                pending_inbound = stream_data.pop("pending_inbound_data", {})
                if pending_inbound:
                    for pending_sn in sorted(pending_inbound):
                        pending_payload = pending_inbound.get(pending_sn, b"")
                        if pending_payload:
                            await stream.receive_data(pending_sn, pending_payload)
                self.logger.debug(
                    f"<blue>Stream <cyan>{stream_id}</cyan> Established with server.</blue>"
                )
            finally:
                stream_data.pop("stream_creating", None)
            self._send_ping_packet()
            return

        if ptype in self._control_request_ack_map:
            ack_ptype = self._control_request_ack_map[ptype]
            await self._enqueue_packet(0, stream_id, sn, ack_ptype, b"")
            if self._is_socks5_error_packet(ptype) and stream_id_exists:
                stream_data["socks_error_packet"] = ptype
                if "handshake_event" in stream_data:
                    stream_data["handshake_event"].set()
            self._send_ping_packet()
            return

        if ptype in self._control_ack_types and stream_id_exists:
            is_socks_fragment_ack = ptype == Packet_Type.SOCKS5_SYN_ACK and bool(data)
            arq = stream_data.get("stream")
            if arq and not is_socks_fragment_ack:
                await arq.receive_control_ack(ptype, sn)
            if (
                ptype == Packet_Type.SOCKS5_SYN_ACK
                and not is_socks_fragment_ack
                and "handshake_event" in stream_data
            ):
                stream_data["handshake_event"].set()
            self._send_ping_packet()
            return

        if (
            ptype in (Packet_Type.STREAM_DATA, Packet_Type.STREAM_RESEND)
            and stream_id_exists
            and data
        ):
            arq = stream_data.get("stream")
            status = stream_data.get("status")
            if arq and status in (
                "ACTIVE",
                "DRAINING",
                "CLOSING",
                "TIME_WAIT",
            ):
                await arq.receive_data(sn, data)
            elif not arq and status == "PENDING":
                stream_data.setdefault("pending_inbound_data", {}).setdefault(sn, data)
            else:
                await self._enqueue_packet(0, stream_id, 0, Packet_Type.STREAM_RST, b"")
            self._send_ping_packet()
            return

        if ptype == Packet_Type.STREAM_DATA_ACK and stream_id_exists:
            arq = stream_data.get("stream")
            if arq and stream_data.get("status") in (
                "ACTIVE",
                "DRAINING",
                "CLOSING",
                "TIME_WAIT",
            ):
                await arq.receive_ack(sn)
            self._send_ping_packet()
            return

        if ptype == Packet_Type.STREAM_FIN and stream_id_exists:
            arq = stream_data.get("stream")
            if not arq or getattr(arq, "closed", False):
                await self._enqueue_packet(
                    0, stream_id, sn, Packet_Type.STREAM_FIN_ACK, b""
                )
                return

            if (
                getattr(arq, "_remote_write_closed", False)
                and getattr(arq, "_fin_seq_received", None) == sn
            ):
                await self._enqueue_packet(
                    0, stream_id, sn, Packet_Type.STREAM_FIN_ACK, b""
                )
                return

            if getattr(arq, "_fin_sent", False) and getattr(arq, "_fin_acked", False):
                stream_data["fin_retries"] = 99

            arq.mark_fin_received(sn)
            await arq._try_finalize_remote_eof()
            self._send_ping_packet()
            return

        if ptype == Packet_Type.STREAM_FIN_ACK and stream_id_exists:
            arq = stream_data.get("stream")
            if arq:
                await arq.receive_control_ack(Packet_Type.STREAM_FIN_ACK, sn)
                if getattr(arq, "_fin_received", False):
                    await arq._try_finalize_remote_eof()
            self._send_ping_packet()
            return

        if ptype == Packet_Type.STREAM_RST and stream_id_exists:
            await self._enqueue_packet(
                0, stream_id, sn, Packet_Type.STREAM_RST_ACK, b""
            )
            arq = stream_data.get("stream")
            if arq:
                arq.mark_rst_received(sn)
            await self.close_stream(
                stream_id,
                reason="Remote stream reset",
                abortive=True,
                remote_reset=True,
            )
            self._send_ping_packet()
            return

        if ptype == Packet_Type.STREAM_RST_ACK and stream_id_exists:
            arq = stream_data.get("stream")
            if arq and getattr(arq, "_rst_seq_sent", None) == sn:
                await arq.receive_control_ack(Packet_Type.STREAM_RST_ACK, sn)
                stream_data["rst_retries"] = 99
            elif stream_data.get("rst_seq_sent") == sn:
                stream_data["rst_acked"] = True
                stream_data["rst_retries"] = 99
            self._send_ping_packet()
            return

        if ptype == Packet_Type.ERROR_DROP:
            if not self.session_restart_event.is_set():
                self.logger.error(
                    "<red>Session dropped by server (Server Restarted or Invalid). Reconnecting...</red>"
                )
                self.session_restart_event.set()

    async def close_stream(
        self,
        stream_id: int,
        reason: str = "Unknown",
        abortive: bool = False,
        remote_reset: bool = False,
    ) -> None:
        """Safely close a stream without sending FIN before snd_buf is drained."""

        stream_data = self.active_streams.get(stream_id)
        if not stream_data:
            return

        status = stream_data.get("status")
        if status in ("CLOSING", "TIME_WAIT"):
            return

        if (
            "handshake_event" in stream_data
            and not stream_data["handshake_event"].is_set()
        ):
            stream_data["handshake_event"].set()

        stream_obj = stream_data.get("stream") or stream_data.get("arq_obj")

        # Phase 1: start graceful drain, but do NOT finalize yet
        if not abortive and stream_obj and not getattr(stream_obj, "closed", False):
            if not getattr(stream_obj, "_fin_sent", False):
                stream_data["status"] = "DRAINING"
                self.logger.debug(
                    f"<yellow>Draining Client Stream <cyan>{stream_id}</cyan>. Reason: "
                    f"<yellow>{reason}</yellow></yellow>"
                )
                try:
                    await stream_obj._initiate_graceful_close(reason=reason)
                except Exception:
                    pass
                return

        # Phase 2: final cleanup
        stream_data["status"] = "CLOSING"
        self.closed_streams[stream_id] = time.monotonic()

        if len(self.closed_streams) > self.max_closed_stream_records:
            self.closed_streams.pop(next(iter(self.closed_streams)))

        self.logger.debug(
            f"<yellow>Closing Client Stream <cyan>{stream_id}</cyan>. Reason: "
            f"<yellow>{reason}</yellow></yellow>"
        )

        if stream_obj:
            try:
                if abortive:
                    if remote_reset or getattr(stream_obj, "_rst_received", False):
                        await stream_obj.close(reason=reason, send_fin=False)
                    else:
                        await stream_obj.abort(reason=reason)
                elif not getattr(stream_obj, "closed", False):
                    await stream_obj.close(
                        reason=reason,
                        send_fin=False
                        if getattr(stream_obj, "_rst_sent", False)
                        else True,
                    )
            except Exception:
                pass

        pending_tx = stream_data.get("tx_queue", [])
        if pending_tx:
            main_was_empty = not self.main_queue
            moved_any = False
            for item in pending_tx:
                ptype = int(item[2])
                if (
                    ptype in self._packable_control_types
                    and ptype != Packet_Type.SOCKS5_SYN
                ):
                    if self._track_main_packet_once(
                        self.__dict__,
                        int(item[3]),
                        ptype,
                        int(item[4]),
                        payload=item[5],
                    ):
                        self._push_queue_item(
                            self.main_queue, self.__dict__, item, self.tx_event
                        )
                        moved_any = True
                    self._dec_priority_counter(stream_data, item[0])

            if main_was_empty and moved_any:
                self._activate_response_queue(0)

        try:
            stream_data.get("tx_queue", []).clear()
            stream_data.get("track_data", set()).clear()
            stream_data.get("track_resend", set()).clear()
            stream_data.get("track_ack", set()).clear()
            stream_data.get("track_fin", set()).clear()
            stream_data.get("track_syn_ack", set()).clear()
            stream_data.get("track_types", set()).clear()
            stream_data.get("track_seq_packets", set()).clear()
            stream_data.get("track_fragment_packets", set()).clear()
            stream_data.get("priority_counts", {}).clear()
            stream_data.get("pending_inbound_data", {}).clear()
            stream_data["status"] = "TIME_WAIT"
            stream_data["close_time"] = time.monotonic()
            self._deactivate_response_queue(stream_id)
        except Exception:
            pass

        writer = stream_data.get("writer")
        await self._close_writer_safely(writer)

    async def _retransmit_worker(self):
        while not self.should_stop.is_set() and not self.session_restart_event.is_set():
            try:
                await asyncio.sleep(0.5)
                now = time.monotonic()

                for sid, s in list(self.active_streams.items()):
                    status = s.get("status")
                    last_act = s.get("last_activity_time", now)
                    close_time = s.get("close_time", now)

                    if status == "PENDING" and (now - last_act) > 1.5:
                        s["last_activity_time"] = now
                        syn_data = b""
                        await self._enqueue_packet(
                            0, sid, 0, Packet_Type.STREAM_SYN, syn_data
                        )

                    elif status == "TIME_WAIT":
                        stream_obj = s.get("stream")

                        if (now - close_time) > 45.0:
                            self.active_streams.pop(sid, None)

                        elif (
                            stream_obj
                            and not getattr(
                                stream_obj, "enable_control_reliability", False
                            )
                            and getattr(stream_obj, "_rst_sent", False)
                            and not getattr(stream_obj, "_rst_acked", False)
                            and (now - last_act) > 1.5
                            and s.get("rst_retries", 0) < 10
                        ):
                            s["last_activity_time"] = now
                            s["rst_retries"] = s.get("rst_retries", 0) + 1

                            rst_sn = getattr(stream_obj, "_rst_seq_sent", None)
                            if rst_sn is not None:
                                await self._client_enqueue_tx(
                                    0,
                                    sid,
                                    rst_sn,
                                    b"",
                                    is_rst=True,
                                )

                        elif (
                            not (
                                stream_obj
                                and getattr(
                                    stream_obj, "enable_control_reliability", False
                                )
                            )
                            and not (
                                stream_obj and getattr(stream_obj, "_rst_sent", False)
                            )
                            and not (
                                stream_obj
                                and getattr(stream_obj, "_rst_received", False)
                            )
                            and not (
                                stream_obj and getattr(stream_obj, "_fin_acked", False)
                            )
                            and (now - last_act) > 3.0
                            and s.get("fin_retries", 0) < 15
                        ):
                            s["last_activity_time"] = now
                            s["fin_retries"] = s.get("fin_retries", 0) + 1
                            fin_data = b""

                            fin_sn = 0
                            if (
                                stream_obj
                                and getattr(stream_obj, "_fin_seq_sent", None)
                                is not None
                            ):
                                fin_sn = stream_obj._fin_seq_sent

                            await self._client_enqueue_tx(
                                1, sid, fin_sn, fin_data, is_fin=True
                            )

                expired_closed = [
                    sid
                    for sid, closed_at in self.closed_streams.items()
                    if now - closed_at > 45.0
                ]
                for sid in expired_closed:
                    self.closed_streams.pop(sid, None)

                dead_streams = []
                for sid, s in list(self.active_streams.items()):
                    stream_obj = s.get("stream")
                    status = s.get("status")
                    create_time = s.get("create_time", 0)

                    if (
                        stream_obj
                        and getattr(stream_obj, "closed", False)
                        and status in ("ACTIVE", "DRAINING")
                    ):
                        dead_streams.append(sid)
                    elif status == "PENDING" and (now - create_time) > 350.0:
                        dead_streams.append(sid)

                for sid in dead_streams:
                    try:
                        s = self.active_streams.get(sid, {})
                        if s.get("status") == "PENDING":
                            reason = "Handshake timeout (No SYN_ACK from server)"
                        else:
                            arq = s.get("stream")
                            reason = getattr(
                                arq,
                                "close_reason",
                                "Closed locally or Inactivity Timeout",
                            )
                        await self.close_stream(sid, reason=reason)
                    except Exception as e:
                        self.logger.debug(
                            f"Error closing stream {sid} in retransmit worker: {e}"
                        )

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Unexpected error in retransmit worker: {e}")
                await asyncio.sleep(0.5)

    # ---------------------------------------------------------
    # App Lifecycle
    # ---------------------------------------------------------
    async def start(self) -> None:
        try:
            self.loop = asyncio.get_running_loop()
            if self.cpu_worker_threads > 0 and self.cpu_executor is None:
                self.cpu_executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=self.cpu_worker_threads,
                    thread_name_prefix="mdns-cpu",
                )
            self.logger.info("=" * 60)
            self.logger.success("<magenta>Starting MasterDnsVPN Client...</magenta>")
            self.logger.success(
                "<cyan>GitHub:</cyan> <blue>https://github.com/masterking32/MasterDnsVPN</blue>"
            )
            self.logger.success(
                "<fg #03fcc2>Telegram:</fg #03fcc2> <blue>@MasterDnsVPN</blue>"
            )
            self.logger.info(
                f"<cyan>CPU worker threads enabled: {self.cpu_worker_threads}</cyan>"
            )

            self.logger.info("=" * 60)
            if not self.domains or not self.resolvers:
                self.logger.error(
                    "<red>Domains or Resolvers are missing in config.</red>"
                )
                return

            self.success_mtu_checks = False
            while not self.should_stop.is_set():
                self.logger.info("=" * 60)

                await self.run_client()

                if not self.should_stop.is_set():
                    self.logger.warning(
                        "<yellow>Restarting Client workflow in 2 seconds...</yellow>"
                    )
                    await self._sleep(2)

        except asyncio.CancelledError:
            self.logger.info("MasterDnsVPN Client is stopping...")
        except Exception as e:
            self.logger.error(f"Error in MasterDnsVPN Client: {e}")
        finally:
            if self.cpu_executor:
                try:
                    self.cpu_executor.shutdown(wait=False, cancel_futures=True)
                except Exception:
                    pass
                self.cpu_executor = None

    async def _sleep(self, seconds: float) -> None:
        """Async sleep helper."""
        try:
            await asyncio.wait_for(self.should_stop.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            pass

    def _signal_handler(self, signum, frame=None):
        """Handle termination signals to stop the client gracefully (Thread-Safe)."""

        if getattr(self, "_force_quit_flag", False):
            if self.logger:
                self.logger.warning(
                    f"<red>Force quitting immediately due to repeated signal <cyan>{signum}</cyan>.</red>"
                )
            else:
                print("\n[!] Force quitting immediately...")
            os._exit(0)

        self._force_quit_flag = True
        if self.logger:
            self.logger.warning(
                "<red>Stopping operations... (Press CTRL+C again to force quit)</red>"
            )
        else:
            print("\n[!] Stopping operations... (Press CTRL+C again to force quit)")

        if hasattr(self, "should_stop"):
            self.should_stop._value = True

        def _trigger_stop():
            if getattr(self, "should_stop", None) and not self.should_stop.is_set():
                self.logger.info(
                    f"<red>Received signal <cyan>{signum}</cyan>. Stopping MasterDnsVPN Client...</red>"
                )
                self.should_stop.set()
                if (
                    getattr(self, "session_restart_event", None)
                    and not self.session_restart_event.is_set()
                ):
                    self.session_restart_event.set()
                self.logger.info("<magenta>Stopping MasterDnsVPN Client...</magenta>")
            else:
                os._exit(0)

        try:
            if getattr(self, "loop", None) and self.loop.is_running():
                self.loop.call_soon_threadsafe(_trigger_stop)
            else:
                _trigger_stop()
        except Exception:
            os._exit(0)


def main():
    client = MasterDnsVPNClient()
    try:
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        elif sys.platform == "darwin":
            pass
        else:
            try:
                import uvloop

                asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
            except ImportError:
                print(
                    "[MasterDnsVPN] uvloop is not available; using default asyncio loop."
                )

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        def custom_exception_handler(loop, context):
            msg = context.get("message", "")
            if (
                "socket.send() raised exception" in msg
                or "Connection reset by peer" in msg
            ):
                return

            loop.default_exception_handler(context)

        loop.set_exception_handler(custom_exception_handler)

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
                from ctypes import wintypes

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
    except Exception as e:
        print(f"{e}")

    try:
        os._exit(0)
    except Exception as e:
        print(f"Error while stopping the client: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
