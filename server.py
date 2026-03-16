# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026


import asyncio
import concurrent.futures
import ctypes
import functools
import heapq
import os
import random
import signal
import socket
import struct
import sys
import time
from bisect import bisect_left, bisect_right, insort
from collections import deque
from typing import Optional

from dns_utils.ARQ import ARQ
from dns_utils.compression import (
    Compression_Type,
    SUPPORTED_COMPRESSION_TYPES,
    compress_payload,
    get_compression_name,
    is_compression_type_available,
    normalize_compression_type,
    try_decompress_payload,
)
from dns_utils.config_loader import get_config_path, load_config
from dns_utils.DNS_ENUMS import DNS_Record_Type, Packet_Type
from dns_utils.DnsPacketParser import DnsPacketParser
from dns_utils.PacketQueueMixin import PacketQueueMixin
from dns_utils.utils import async_recvfrom, async_sendto, get_encrypt_key, getLogger


class Socks5ConnectError(Exception):
    """SOCKS5 connect error carrying REP code from upstream."""

    def __init__(self, rep_code: int, message: str) -> None:
        super().__init__(message)
        self.rep_code = int(rep_code)


# Ensure UTF-8 output for consistent logging
try:
    if sys.stdout.encoding is not None and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


class MasterDnsVPNServer(PacketQueueMixin):
    """MasterDnsVPN Server class to handle DNS requests over UDP."""

    def _prompt_before_exit(self) -> None:
        """Best-effort pause for interactive sessions; never fail in headless runs."""
        try:
            if sys.stdin and sys.stdin.isatty():
                input("Press Enter to exit...")
        except Exception:
            pass

    def __init__(self) -> None:
        """Initialize the MasterDnsVPNServer with configuration and logger."""
        # ---------------------------------------------------------
        # Runtime primitives
        # ---------------------------------------------------------
        self.udp_sock: Optional[socket.socket] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.should_stop = asyncio.Event()

        # ---------------------------------------------------------
        # Config and logger bootstrap
        # ---------------------------------------------------------
        self.config = load_config("server_config.toml")
        if not os.path.isfile(get_config_path("server_config.toml")):
            self.logger = getLogger(
                log_level=self.config.get("LOG_LEVEL", "DEBUG"), is_server=True
            )
            self.logger.error(
                "Config file '<cyan>server_config.toml</cyan>' not found."
            )
            self.logger.error(
                "Please place it in the same directory as the executable and restart."
            )
            self._prompt_before_exit()
            sys.exit(1)

        self.logger = getLogger(
            log_level=self.config.get("LOG_LEVEL", "INFO"), is_server=True
        )

        # ---------------------------------------------------------
        # Domain, protocol and SOCKS settings
        # ---------------------------------------------------------
        self.allowed_domains = self.config.get("DOMAIN", [])
        self.allowed_domains_lower = tuple(
            sorted((d.lower() for d in self.allowed_domains), key=len, reverse=True)
        )

        self.protocol_type: str = self.config.get("PROTOCOL_TYPE", "TCP").upper()
        self.use_external_socks5: bool = self.config.get("USE_EXTERNAL_SOCKS5", False)
        self.socks5_auth: bool = self.config.get("SOCKS5_AUTH", False)
        self.socks5_user: str = str(self.config.get("SOCKS5_USER", ""))
        self.socks5_pass: str = str(self.config.get("SOCKS5_PASS", ""))
        self.socks5_user_bytes: bytes = self.socks5_user.encode("utf-8")
        self.socks5_pass_bytes: bytes = self.socks5_pass.encode("utf-8")

        if self.protocol_type not in ("SOCKS5", "TCP"):
            self.logger.error(
                f"Invalid PROTOCOL_TYPE '{self.protocol_type}' in config. Must be 'SOCKS5' or 'TCP'."
            )
            self._prompt_before_exit()
            sys.exit(1)

        # ---------------------------------------------------------
        # Encryption and DNS parser settings
        # ---------------------------------------------------------
        self.encryption_method: int = self.config.get("DATA_ENCRYPTION_METHOD", 1)
        self.encrypt_key = get_encrypt_key(self.encryption_method)

        self.crypto_overhead = 0
        if self.encryption_method == 2:
            self.crypto_overhead = 16
        elif self.encryption_method in (3, 4, 5):
            self.crypto_overhead = 28

        self.dns_parser = DnsPacketParser(
            logger=self.logger,
            encryption_method=self.encryption_method,
            encryption_key=self.encrypt_key,
        )

        # ---------------------------------------------------------
        # Forward target and performance configuration
        # ---------------------------------------------------------
        self.forward_ip = self.config["FORWARD_IP"]
        self.forward_port = int(self.config["FORWARD_PORT"])

        self.max_packets_per_batch = int(self.config.get("MAX_PACKETS_PER_BATCH", 1000))
        self.arq_window_size = int(self.config.get("ARQ_WINDOW_SIZE", 300))
        self.arq_initial_rto = float(self.config.get("ARQ_INITIAL_RTO", 0.8))
        self.arq_max_rto = float(self.config.get("ARQ_MAX_RTO", 1.5))
        self.arq_control_initial_rto = float(
            self.config.get("ARQ_CONTROL_INITIAL_RTO", 0.8)
        )
        self.arq_control_max_rto = float(self.config.get("ARQ_CONTROL_MAX_RTO", 2.5))
        self.arq_control_max_retries = int(
            self.config.get("ARQ_CONTROL_MAX_RETRIES", 40)
        )
        self.session_timeout = int(self.config.get("SESSION_TIMEOUT", 300))
        self.session_cleanup_interval = int(
            self.config.get("SESSION_CLEANUP_INTERVAL", 30)
        )
        self.socks_handshake_timeout = float(
            self.config.get("SOCKS_HANDSHAKE_TIMEOUT", 120.0)
        )
        self.max_concurrent_requests = asyncio.Semaphore(
            int(self.config.get("MAX_CONCURRENT_REQUESTS", 1000))
        )

        self.supported_upload_compression_types = (
            self._load_supported_compression_types_config(
                "SUPPORTED_UPLOAD_COMPRESSION_TYPES"
            )
        )
        self.supported_download_compression_types = (
            self._load_supported_compression_types_config(
                "SUPPORTED_DOWNLOAD_COMPRESSION_TYPES"
            )
        )

        # ---------------------------------------------------------
        # Session pools and server runtime state
        # ---------------------------------------------------------
        self.sessions = {}
        self._max_sessions = max(1, min(255, int(self.config.get("MAX_SESSIONS", 255))))
        self.free_session_ids = deque(range(1, self._max_sessions + 1))
        self.recently_closed_sessions = {}

        self._dns_task = None
        self._session_cleanup_task = None
        self._background_tasks = set()
        self.cpu_executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
        auto_cpu_workers = max(2, min(16, (os.cpu_count() or 1)))
        raw_cpu_workers = int(self.config.get("CPU_WORKER_THREADS", 0))
        if raw_cpu_workers < 0:
            self.cpu_worker_threads = 0
        elif raw_cpu_workers == 0:
            self.cpu_worker_threads = auto_cpu_workers
        else:
            self.cpu_worker_threads = raw_cpu_workers

        # ---------------------------------------------------------
        # Packet metadata and dispatch maps
        # ---------------------------------------------------------
        self._valid_packet_types = {
            v
            for k, v in Packet_Type.__dict__.items()
            if not k.startswith("__") and isinstance(v, int)
        }
        self._packet_type_names = {
            v: k
            for k, v in Packet_Type.__dict__.items()
            if not k.startswith("__") and isinstance(v, int)
        }

        self._pre_session_packet_types = {
            Packet_Type.SESSION_INIT,
            Packet_Type.MTU_UP_REQ,
            Packet_Type.MTU_DOWN_REQ,
        }
        self._block_packer = DnsPacketParser.PACKED_CONTROL_BLOCK_STRUCT
        self._stream_packet_handlers = {
            Packet_Type.STREAM_DATA: self._handle_stream_data_packet,
            Packet_Type.STREAM_RESEND: self._handle_stream_data_packet,
            Packet_Type.STREAM_DATA_ACK: self._handle_stream_data_ack_packet,
            Packet_Type.STREAM_SYN: self._handle_stream_syn_packet,
            Packet_Type.STREAM_SYN_ACK: self._handle_control_ack_packet,
            Packet_Type.SOCKS5_SYN: self._handle_socks5_syn_packet,
            Packet_Type.SOCKS5_SYN_ACK: self._handle_control_ack_packet,
            Packet_Type.STREAM_FIN: self._handle_stream_fin_packet,
            Packet_Type.STREAM_RST: self._handle_stream_rst_packet,
            Packet_Type.STREAM_RST_ACK: self._handle_stream_rst_ack_packet,
            Packet_Type.STREAM_FIN_ACK: self._handle_stream_fin_ack_packet,
            Packet_Type.STREAM_KEEPALIVE: self._handle_control_request_packet,
            Packet_Type.STREAM_KEEPALIVE_ACK: self._handle_control_ack_packet,
            Packet_Type.STREAM_WINDOW_UPDATE: self._handle_control_request_packet,
            Packet_Type.STREAM_WINDOW_UPDATE_ACK: self._handle_control_ack_packet,
            Packet_Type.STREAM_PROBE: self._handle_control_request_packet,
            Packet_Type.STREAM_PROBE_ACK: self._handle_control_ack_packet,
            Packet_Type.SOCKS5_CONNECT_FAIL: self._handle_control_request_packet,
            Packet_Type.SOCKS5_CONNECT_FAIL_ACK: self._handle_control_ack_packet,
            Packet_Type.SOCKS5_RULESET_DENIED: self._handle_control_request_packet,
            Packet_Type.SOCKS5_RULESET_DENIED_ACK: self._handle_control_ack_packet,
            Packet_Type.SOCKS5_NETWORK_UNREACHABLE: self._handle_control_request_packet,
            Packet_Type.SOCKS5_NETWORK_UNREACHABLE_ACK: self._handle_control_ack_packet,
            Packet_Type.SOCKS5_HOST_UNREACHABLE: self._handle_control_request_packet,
            Packet_Type.SOCKS5_HOST_UNREACHABLE_ACK: self._handle_control_ack_packet,
            Packet_Type.SOCKS5_CONNECTION_REFUSED: self._handle_control_request_packet,
            Packet_Type.SOCKS5_CONNECTION_REFUSED_ACK: self._handle_control_ack_packet,
            Packet_Type.SOCKS5_TTL_EXPIRED: self._handle_control_request_packet,
            Packet_Type.SOCKS5_TTL_EXPIRED_ACK: self._handle_control_ack_packet,
            Packet_Type.SOCKS5_COMMAND_UNSUPPORTED: self._handle_control_request_packet,
            Packet_Type.SOCKS5_COMMAND_UNSUPPORTED_ACK: self._handle_control_ack_packet,
            Packet_Type.SOCKS5_ADDRESS_TYPE_UNSUPPORTED: self._handle_control_request_packet,
            Packet_Type.SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK: self._handle_control_ack_packet,
            Packet_Type.SOCKS5_AUTH_FAILED: self._handle_control_request_packet,
            Packet_Type.SOCKS5_AUTH_FAILED_ACK: self._handle_control_ack_packet,
            Packet_Type.SOCKS5_UPSTREAM_UNAVAILABLE: self._handle_control_request_packet,
            Packet_Type.SOCKS5_UPSTREAM_UNAVAILABLE_ACK: self._handle_control_ack_packet,
            Packet_Type.PACKED_CONTROL_BLOCKS: self._handle_packed_control_blocks_packet,
        }
        # Heavy packet handlers are deferred to background tasks so DNS responses
        # can be returned immediately from queue without waiting on local I/O.
        self._deferred_handler_packet_types = {
            Packet_Type.STREAM_SYN,
            Packet_Type.SOCKS5_SYN,
            Packet_Type.STREAM_DATA,
            Packet_Type.STREAM_RESEND,
            Packet_Type.PACKED_CONTROL_BLOCKS,
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
        self._socks5_rep_packet_map = {
            0x01: Packet_Type.SOCKS5_CONNECT_FAIL,
            0x02: Packet_Type.SOCKS5_RULESET_DENIED,
            0x03: Packet_Type.SOCKS5_NETWORK_UNREACHABLE,
            0x04: Packet_Type.SOCKS5_HOST_UNREACHABLE,
            0x05: Packet_Type.SOCKS5_CONNECTION_REFUSED,
            0x06: Packet_Type.SOCKS5_TTL_EXPIRED,
            0x07: Packet_Type.SOCKS5_COMMAND_UNSUPPORTED,
            0x08: Packet_Type.SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
        }

        # ---------------------------------------------------------
        # Config version markers and startup diagnostics
        # ---------------------------------------------------------
        self.config_version = self.config.get("CONFIG_VERSION", 0.1)
        self.min_config_version = 2.0

        self.logger.warning("=" * 60)
        self.logger.warning(
            "<yellow>MasterDnsVPN Server Starting with Configuration:</yellow>"
        )
        self.logger.warning("-" * 60)
        self.logger.warning(
            f"<red>Using encryption key: <green>{self.encrypt_key}</green></red>"
        )
        self.logger.warning(
            f"<red>Encryption method: <green>{self.encryption_method}</green></red>"
        )
        self.logger.warning(
            f"<yellow>Allowed domains: <cyan>{', '.join(self.allowed_domains)}</cyan></yellow>"
        )
        self.logger.warning("=" * 60)

        if self.config_version < self.min_config_version:
            self.logger.warning(
                f"Your config version ({self.config_version}) is outdated. "
                f"Please update your config file to the latest version ({self.min_config_version}) for best performance and new features."
            )

    def _parse_compression_value(self, value) -> Optional[int]:
        if isinstance(value, str):
            v = value.strip()
            if not v:
                return None
            if v.isdigit():
                return int(v)
            name_map = {
                "OFF": Compression_Type.OFF,
                "ZSTD": Compression_Type.ZSTD,
                "LZ4": Compression_Type.LZ4,
                "ZLIB": Compression_Type.ZLIB,
            }
            return name_map.get(v.upper())
        try:
            return int(value)
        except Exception:
            return None

    def _load_supported_compression_types_config(self, key: str) -> tuple[int, ...]:
        raw = self.config.get(key, list(SUPPORTED_COMPRESSION_TYPES))

        if isinstance(raw, str):
            items = [x.strip() for x in raw.split(",") if x.strip()]
        elif isinstance(raw, (list, tuple)):
            items = list(raw)
        else:
            items = [raw]

        allowed_set = set(SUPPORTED_COMPRESSION_TYPES)
        valid: list[int] = []
        for item in items:
            parsed = self._parse_compression_value(item)
            if parsed is None:
                self.logger.error(f"{key}: invalid compression value '{item}' removed.")
                continue

            if parsed < 0 or parsed > 3:
                self.logger.error(
                    f"{key}: compression value '{parsed}' is out of allowed range 0..3 and was removed."
                )
                continue

            if parsed not in allowed_set:
                self.logger.error(
                    f"{key}: compression value '{parsed}' is not in SUPPORTED_COMPRESSION_TYPES and was removed."
                )
                continue

            if parsed not in valid:
                valid.append(parsed)

        if Compression_Type.OFF not in valid:
            valid.insert(0, Compression_Type.OFF)
            self.logger.warning(f"{key}: OFF(0) was missing, added automatically.")

        return tuple(valid)

    def _resolve_session_compression_types(
        self,
        requested_upload_type: int,
        requested_download_type: int,
    ) -> tuple[int, int]:
        if requested_upload_type not in self.supported_upload_compression_types:
            self.logger.warning(
                f"<yellow>Client requested upload compression <cyan>'{get_compression_name(requested_upload_type)}'</cyan> "
                f"which is not allowed by server policy. Falling back to OFF.</yellow>"
            )
            requested_upload_type = Compression_Type.OFF

        if requested_download_type not in self.supported_download_compression_types:
            self.logger.warning(
                f"<yellow>Client requested download compression <cyan>'{get_compression_name(requested_download_type)}'</cyan> "
                f"which is not allowed by server policy. Falling back to OFF.</yellow>"
            )
            requested_download_type = Compression_Type.OFF

        return requested_upload_type, requested_download_type

    # ---------------------------------------------------------
    # Session Management
    # ---------------------------------------------------------
    async def new_session(
        self,
        base_flag: bool = False,
        client_token: bytes = b"",
        client_upload_compression_type: int = 0,
        client_download_compression_type: int = 0,
    ) -> Optional[int]:
        try:
            if not self.free_session_ids:
                self.logger.error(
                    f"<yellow>All {self._max_sessions} session slots are full!</yellow>"
                )
                return None

            session_id = self.free_session_ids.popleft()
            now = time.monotonic()

            self.sessions[session_id] = {
                "session_id": session_id,
                "session_cookie": random.randint(1, 255),
                "created_at": now,
                "last_packet_time": now,
                "init_token": client_token,
                "streams": {},
                "main_queue": [],
                "active_response_ids": [],
                "active_response_set": set(),
                "round_robin_stream_id": -1,
                "enqueue_seq": 0,
                "priority_counts": {},
                "track_ack": set(),
                "track_resend": set(),
                "track_types": set(),
                "track_data": set(),
                "upload_mtu": 512,
                "download_mtu": 512,
                "max_packed_blocks": 1,
                "base_encode_responses": base_flag,
                "client_upload_compression_type": client_upload_compression_type,
                "client_download_compression_type": client_download_compression_type,
            }

            server_response_type = "Bytes"
            if base_flag:
                server_response_type = "Base-Encoded String"

            self.logger.info(
                f"<green>Created new session with ID: <cyan>{session_id}</cyan>, Response Type: <cyan>{server_response_type}</cyan>, Compression: <cyan>Upload: <yellow>{get_compression_name(client_upload_compression_type)}</yellow>, Download: <yellow>{get_compression_name(client_download_compression_type)}</yellow></cyan></green>"
            )
            return session_id
        except Exception as e:
            self.logger.error(f"<red>Error creating new session: {e}</red>")
            return None

    async def _close_session(self, session_id: int) -> None:
        session = self.sessions.get(session_id)
        if not session:
            return

        self.logger.debug(
            f"<yellow>Closing Session <cyan>{session_id}</cyan> and all its streams...</yellow>"
        )

        base_flag = session.get("base_encode_responses", False)
        self.recently_closed_sessions[session_id] = {
            "time": time.monotonic(),
            "base_encode": base_flag,
            "session_cookie": int(session.get("session_cookie", 0) or 0),
        }

        stream_ids = list(session.get("streams", {}).keys())

        if stream_ids:
            close_tasks = [
                self.close_stream(session_id, sid, reason="Session Closing")
                for sid in stream_ids
            ]
            try:
                await asyncio.wait_for(
                    asyncio.gather(*close_tasks, return_exceptions=True), timeout=2.0
                )
            except Exception:
                pass

        try:
            session.get("main_queue", []).clear()
            session.get("track_ack", set()).clear()
            session.get("track_resend", set()).clear()
            session.get("track_types", set()).clear()
            session.get("track_data", set()).clear()
            session.get("track_seq_packets", set()).clear()
            session.get("track_fragment_packets", set()).clear()
            session.get("priority_counts", {}).clear()
            session.get("active_response_ids", []).clear()
            session.get("active_response_set", set()).clear()
            session.get("streams", {}).clear()
        except Exception:
            pass

        self.sessions.pop(session_id, None)

        try:
            if 1 <= session_id <= getattr(self, "_max_sessions", 255):
                self.free_session_ids.appendleft(session_id)
        except Exception:
            pass

        self.logger.info(
            f"<yellow>Closed session with ID: <cyan>{session_id}</cyan></yellow>"
        )

    def _touch_session(self, session_id: int) -> None:
        """Update a session's last activity timestamp."""
        try:
            session = self.sessions.get(session_id)
            if session:
                session["last_packet_time"] = time.monotonic()
        except Exception:
            pass

    def _expected_session_cookie(self, packet_type: int, session_id: int) -> int | None:
        ptype = int(packet_type)
        if ptype in self._pre_session_packet_types:
            return 0

        session = self.sessions.get(session_id)
        if session is not None:
            return int(session.get("session_cookie", 0) or 0)

        closed_info = self.recently_closed_sessions.get(session_id)
        if closed_info is not None:
            return int(closed_info.get("session_cookie", 0) or 0)

        return None

    def _activate_response_queue(self, session: dict, stream_id: int) -> None:
        sid = int(stream_id)
        active_set = session.setdefault("active_response_set", set())
        if sid in active_set:
            return
        active_set.add(sid)
        insort(session.setdefault("active_response_ids", []), sid)

    def _deactivate_response_queue(self, session: dict, stream_id: int) -> None:
        sid = int(stream_id)
        active_set = session.get("active_response_set")
        if not active_set or sid not in active_set:
            return
        active_set.discard(sid)
        active_ids = session.get("active_response_ids")
        if not active_ids:
            return
        idx = bisect_left(active_ids, sid)
        if idx < len(active_ids) and active_ids[idx] == sid:
            active_ids.pop(idx)

    def _extract_packet_payload(
        self, labels: str, extracted_header: Optional[dict]
    ) -> bytes:
        """Extract packet payload and apply optional decompression based on header flag."""
        try:
            if not labels or "." not in labels:
                return b""

            payload = self.dns_parser.extract_vpn_data_from_labels(labels)
            if not payload:
                return b""

            if not extracted_header:
                return payload

            ptype = extracted_header.get("packet_type", -1)
            if ptype not in self.dns_parser._PT_COMP_EXT:
                return payload

            comp_type = (
                extracted_header.get("compression_type", Compression_Type.OFF)
                or Compression_Type.OFF
            )
            if comp_type == Compression_Type.OFF:
                return payload

            if not is_compression_type_available(comp_type):
                return b""

            decompressed, ok = try_decompress_payload(payload, comp_type)
            if not ok:
                return b""

            return decompressed
        except Exception as e:
            self.logger.debug(f"Error extracting packet payload: {e}")
            return b""

    def _spawn_background_task(self, coro):
        """Create a tracked background task so shutdown can cancel and release it."""
        if not self.loop:
            return None

        task = self.loop.create_task(coro)
        self._background_tasks.add(task)

        def _on_done(t):
            self._background_tasks.discard(t)
            try:
                t.exception()
            except asyncio.CancelledError:
                pass
            except Exception:
                pass

        task.add_done_callback(_on_done)
        return task

    async def _handle_session_init(
        self,
        data=None,
        labels=None,
        request_domain=None,
        addr=None,
        parsed_packet=None,
        session_id=None,
        extracted_header=None,
    ) -> Optional[bytes]:
        """Handle NEW_SESSION VPN packet."""
        try:
            client_payload = self._extract_packet_payload(labels, extracted_header)
            if not client_payload or len(client_payload) < 17:
                return None

            client_upload_compression_type = 0
            client_download_compression_type = 0
            payload_len = len(client_payload)
            if payload_len < 17:
                self.logger.debug(
                    f"<yellow>Session init packet from {addr} has insufficient payload length ({payload_len} bytes). Expected at least 17 bytes for token and flags. Ignoring.</yellow>"
                )
                return None

            flag = client_payload[payload_len - 2]
            compression_pref = client_payload[payload_len - 1]
            client_token = client_payload[: payload_len - 2]

            (
                client_upload_compression_type,
                client_download_compression_type,
            ) = self._resolve_session_compression_types(
                normalize_compression_type((compression_pref >> 4) & 0x0F),
                normalize_compression_type(compression_pref & 0x0F),
            )

            base_encode = flag == 1
            now = time.monotonic()

            existing_session_id = None
            for sid, sess in self.sessions.items():
                if (
                    now - sess.get("created_at", 0) <= 10.0
                    and sess.get("init_token") == client_token
                ):
                    existing_session_id = sid
                    break

            if existing_session_id is not None:
                new_session_id = existing_session_id
                self.logger.debug(
                    f"<yellow>Retransmit detected from {addr}. Reusing Session {new_session_id}</yellow>"
                )
            else:
                new_session_id = await self.new_session(
                    base_encode,
                    client_token,
                    client_upload_compression_type,
                    client_download_compression_type,
                )
                if new_session_id is None:
                    self.logger.debug(
                        f"<red>Failed to create new session from {addr}</red>"
                    )
                    return None

            compression_pref_byte = bytes(
                [
                    ((client_upload_compression_type & 0x0F) << 4)
                    | (client_download_compression_type & 0x0F)
                ]
            )
            response_bytes = (
                client_token
                + b":"
                + str(new_session_id).encode("ascii", errors="ignore")
                + b":"
                + compression_pref_byte
                + bytes(
                    [int(self.sessions[new_session_id].get("session_cookie", 0) or 0)]
                )
            )

            return self.dns_parser.generate_vpn_response_packet(
                domain=request_domain,
                session_id=new_session_id,
                packet_type=Packet_Type.SESSION_ACCEPT,
                data=response_bytes,
                question_packet=data,
                encode_data=base_encode,
                session_cookie=0,
            )
        except Exception as e:
            self.logger.error(
                f"<red>Error handling session init from {addr}: {e}</red>"
            )
            return None

    async def _session_cleanup_loop(self) -> None:
        """Background task to periodically cleanup inactive sessions (Crash-Proof)."""
        cleanup_interval = float(self.session_cleanup_interval)
        timeout_limit = self.session_timeout

        while not self.should_stop.is_set():
            try:
                await asyncio.sleep(cleanup_interval)
                now = time.monotonic()

                expired_sessions = [
                    sid
                    for sid, sess in self.sessions.items()
                    if now - sess.get("last_packet_time", 0) > timeout_limit
                ]

                for sid in expired_sessions:
                    try:
                        await self._close_session(sid)
                        self.logger.debug(
                            f"<yellow>Closed inactive session ID: <cyan>{sid}</cyan></yellow>"
                        )
                    except Exception as e:
                        self.logger.debug(
                            f"<red>Error closing session <cyan>{sid}</cyan>: {e}</red>"
                        )

                expired_closed = [
                    sid
                    for sid, data in self.recently_closed_sessions.items()
                    if now - data["time"] > 600
                ]
                for sid in expired_closed:
                    self.recently_closed_sessions.pop(sid, None)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Unexpected error in session cleanup loop: {e}")
                await asyncio.sleep(1)

    # ---------------------------------------------------------
    # Network I/O & Packet Processing
    # ---------------------------------------------------------
    async def send_udp_response(self, response: bytes, addr) -> bool:
        """Async send helper to write UDP response to addr using the server socket."""
        if not response or addr is None:
            return False

        sock = self.udp_sock
        if sock is None:
            self.logger.error(
                "<red>UDP socket is not initialized for sending response.</red>"
            )
            return False

        loop = self.loop or asyncio.get_running_loop()

        try:
            await async_sendto(loop, sock, response, addr)
            return True
        except (BlockingIOError, OSError) as e:
            try:
                self.logger.debug(
                    f"<red>Failed to send DNS response to {addr}: {e}</red>"
                )
            except Exception:
                pass
            return False
        except asyncio.CancelledError:
            raise
        except Exception:
            return False

    async def _handle_closed_stream_packet(
        self, session_id, stream_id, packet_type, sn
    ):
        """Handle packets for recently closed streams."""
        session = self.sessions.get(session_id)
        if (
            not session
            or stream_id <= 0
            or stream_id not in session.get("closed_streams", {})
        ):
            return False

        if packet_type == Packet_Type.STREAM_FIN:
            await self._enqueue_packet(
                session_id,
                0,
                stream_id,
                sn,
                Packet_Type.STREAM_FIN_ACK,
                b"",
            )
            return True
        if packet_type == Packet_Type.STREAM_RST:
            await self._enqueue_packet(
                session_id,
                0,
                stream_id,
                sn,
                Packet_Type.STREAM_RST_ACK,
                b"",
            )
            return True
        if packet_type == Packet_Type.SOCKS5_SYN:
            await self._enqueue_packet(
                session_id,
                0,
                stream_id,
                0,
                Packet_Type.SOCKS5_CONNECT_FAIL,
                b"",
            )
            return True
        if packet_type in (
            Packet_Type.STREAM_DATA,
            Packet_Type.STREAM_RESEND,
            Packet_Type.STREAM_DATA_ACK,
        ):
            await self._enqueue_packet(
                session_id,
                0,
                stream_id,
                0,
                Packet_Type.STREAM_RST,
                b"",
            )
            return True
        return False

    async def _handle_stream_data_packet(
        self, session_id, stream_id, sn, labels, extracted_header, now_mono
    ):
        """Handle STREAM_DATA and STREAM_RESEND packets."""
        session = self.sessions.get(session_id)
        if not session:
            return

        stream_data = session.get("streams", {}).get(stream_id)
        if not stream_data:
            return

        # Data-plane traffic must continue to drain while the stream is moving
        # through graceful close states, otherwise late DATA/ACK packets get
        # dropped and the close path degenerates into resets/timeouts.
        if stream_data.get("status") not in (
            "CONNECTED",
            "DRAINING",
            "CLOSING",
            "TIME_WAIT",
        ):
            await self._enqueue_packet(
                session_id,
                0,
                stream_id,
                0,
                Packet_Type.STREAM_RST,
                b"",
            )
            return

        stream_data["last_activity"] = now_mono
        arq = stream_data.get("arq_obj")
        if not arq:
            await self._enqueue_packet(
                session_id,
                0,
                stream_id,
                0,
                Packet_Type.STREAM_RST,
                b"",
            )
            return

        diff = (sn - arq.rcv_nxt) & 65535
        if diff >= 32768:
            await self._enqueue_packet(
                session_id, 1, stream_id, sn, Packet_Type.STREAM_DATA_ACK, b""
            )
            return

        extracted_data = self._extract_packet_payload(labels, extracted_header)
        if extracted_data:
            await arq.receive_data(sn, extracted_data)

    async def _handle_stream_data_ack_packet(
        self, session_id, stream_id, sn, labels, extracted_header, now_mono
    ):
        """Handle STREAM_DATA_ACK packets."""
        session = self.sessions.get(session_id)
        if not session:
            return

        stream_data = session.get("streams", {}).get(stream_id)
        if not stream_data:
            return

        if stream_data.get("status") not in (
            "CONNECTED",
            "DRAINING",
            "CLOSING",
            "TIME_WAIT",
        ):
            return

        stream_data["last_activity"] = now_mono
        arq = stream_data.get("arq_obj")
        if arq:
            await arq.receive_ack(sn)

    async def _handle_stream_syn_packet(
        self, session_id, stream_id, sn, labels, extracted_header, now_mono
    ):
        """Handle STREAM_SYN packets without blocking current response."""
        await self._handle_stream_syn(session_id, stream_id, sn)

    def _map_socks5_exception_to_packet(self, exc: Exception) -> int:
        """Best-effort exception to SOCKS5 result packet mapping."""
        if isinstance(exc, Socks5ConnectError):
            return self._socks5_rep_packet_map.get(
                int(exc.rep_code), Packet_Type.SOCKS5_CONNECT_FAIL
            )

        if isinstance(exc, asyncio.TimeoutError):
            return Packet_Type.SOCKS5_UPSTREAM_UNAVAILABLE

        if isinstance(exc, socket.gaierror):
            return Packet_Type.SOCKS5_HOST_UNREACHABLE

        if isinstance(exc, OSError):
            err_no = getattr(exc, "errno", None)
            if err_no in (111, 10061, 61):
                return Packet_Type.SOCKS5_CONNECTION_REFUSED
            if err_no in (113, 10065, 65):
                return Packet_Type.SOCKS5_HOST_UNREACHABLE
            if err_no in (101, 10051, 51):
                return Packet_Type.SOCKS5_NETWORK_UNREACHABLE
            if err_no in (110, 10060, 60):
                return Packet_Type.SOCKS5_TTL_EXPIRED
            return Packet_Type.SOCKS5_UPSTREAM_UNAVAILABLE

        msg = str(exc).lower()
        if "authentication failed" in msg:
            return Packet_Type.SOCKS5_AUTH_FAILED
        if "unsupported authentication method" in msg:
            return Packet_Type.SOCKS5_AUTH_FAILED
        if "address type" in msg:
            return Packet_Type.SOCKS5_ADDRESS_TYPE_UNSUPPORTED
        if "timed out" in msg:
            return Packet_Type.SOCKS5_UPSTREAM_UNAVAILABLE
        if "unreachable" in msg:
            return Packet_Type.SOCKS5_HOST_UNREACHABLE

        return Packet_Type.SOCKS5_CONNECT_FAIL

    def _cache_response(
        self,
        stream_data: dict | None,
        response_key,
        *,
        packet_type: int,
        payload: bytes = b"",
        priority: int = 0,
        sequence_num: int = 0,
    ) -> None:
        """Store one cached SYN-family response in the per-stream response cache."""
        if not stream_data:
            return

        stream_data.setdefault("syn_responses", {})[response_key] = {
            "packet_type": int(packet_type),
            "payload": payload or b"",
            "priority": int(priority),
            "sequence_num": int(sequence_num) & 0xFFFF,
            "updated_at": time.monotonic(),
            "last_replay": 0.0,
        }

    async def _enqueue_cached_response(
        self,
        session_id: int,
        stream_id: int,
        stream_data: dict | None,
        response_key,
        *,
        sequence_num: int | None = None,
    ) -> bool:
        """Replay a cached response instead of re-running stream/SOCKS setup work."""
        if not stream_data:
            return False

        cached = stream_data.get("syn_responses", {}).get(response_key)
        if not cached:
            return False

        cached["last_replay"] = time.monotonic()
        replay_sn = (
            int(sequence_num) & 0xFFFF
            if sequence_num is not None
            else int(cached.get("sequence_num", 0)) & 0xFFFF
        )
        await self._enqueue_packet(
            session_id,
            int(cached.get("priority", 0)),
            stream_id,
            replay_sn,
            int(cached["packet_type"]),
            cached.get("payload", b""),
        )
        return True

    async def _queue_and_cache_response(
        self,
        session_id: int,
        stream_id: int,
        stream_data: dict | None,
        response_key,
        *,
        packet_type: int,
        payload: bytes = b"",
        priority: int = 0,
        sequence_num: int = 0,
    ) -> None:
        """Cache the response metadata first, then enqueue it through normal dedupe."""
        self._cache_response(
            stream_data,
            response_key,
            packet_type=packet_type,
            payload=payload,
            priority=priority,
            sequence_num=sequence_num,
        )
        await self._enqueue_packet(
            session_id,
            priority,
            stream_id,
            sequence_num,
            int(packet_type),
            payload or b"",
        )

    async def _send_socks5_error_packet(
        self,
        session_id: int,
        stream_id: int,
        packet_type: int,
        stream_data: dict | None = None,
        fragment_id: int | None = None,
    ) -> None:
        """Queue SOCKS5 error packet for client."""
        payload = b""
        packet_name = self._packet_type_names.get(int(packet_type), str(packet_type))
        self.logger.debug(
            f"<yellow>Queueing SOCKS5 error <cyan>{packet_name}</cyan> for session "
            f"<cyan>{session_id}</cyan> stream <cyan>{stream_id}</cyan></yellow>"
        )
        await self._queue_and_cache_response(
            session_id,
            stream_id,
            stream_data,
            "socks",
            packet_type=int(packet_type),
            payload=payload,
            priority=0,
            sequence_num=0,
        )
        if stream_data is not None and fragment_id is not None:
            self._cache_response(
                stream_data,
                ("socks_frag", int(fragment_id) & 0xFF),
                packet_type=int(packet_type),
                payload=payload,
                priority=0,
                sequence_num=0,
            )

    async def _handle_socks5_syn_packet(
        self, session_id, stream_id, sn, labels, extracted_header, now_mono
    ):
        """Handle SOCKS5 SYN/target setup packets."""
        session = self.sessions.get(session_id)
        if not session:
            return

        frag_id = int(extracted_header.get("fragment_id", 0)) if extracted_header else 0
        expected_chunk_count = (
            int(extracted_header.get("total_fragments", 1)) if extracted_header else 1
        )

        streams = session.setdefault("streams", {})
        stream_data = streams.get(stream_id)
        if stream_data:
            if await self._enqueue_cached_response(
                session_id,
                stream_id,
                stream_data,
                ("socks_frag", int(frag_id) & 0xFF),
            ):
                return

            if await self._enqueue_cached_response(
                session_id,
                stream_id,
                stream_data,
                "socks",
            ):
                return

            if stream_data.get("status") != "PENDING":
                return

        elif stream_id in session.get("closed_streams", {}):
            # Recently closed streams must never restart SOCKS setup from a late SYN.
            return
        else:
            now = time.monotonic()
            stream_data = {
                "stream_id": stream_id,
                "created_at": now,
                "last_activity": now,
                "status": "PENDING",
                "arq_obj": None,
                "tx_queue": [],
                "priority_counts": {},
                "track_ack": set(),
                "track_fin": set(),
                "track_syn_ack": set(),
                "track_data": set(),
                "track_resend": set(),
                "track_types": set(),
                "socks_chunks": {},
                "syn_responses": {},
                "socks_expected_frags": None,
            }
            streams[stream_id] = stream_data

        stream_data["last_activity"] = now_mono

        if expected_chunk_count < 1 or expected_chunk_count > 20:
            await self._send_socks5_error_packet(
                session_id,
                stream_id,
                Packet_Type.SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
                stream_data=stream_data,
                fragment_id=frag_id,
            )
            await self.close_stream(
                session_id,
                stream_id,
                reason="Invalid SOCKS5 fragment count",
                abortive=True,
            )
            return

        if frag_id < 0 or frag_id >= expected_chunk_count:
            await self._send_socks5_error_packet(
                session_id,
                stream_id,
                Packet_Type.SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
                stream_data=stream_data,
                fragment_id=frag_id,
            )
            await self.close_stream(
                session_id,
                stream_id,
                reason="Invalid SOCKS5 fragment index",
                abortive=True,
            )
            return

        stored_expected = stream_data.get("socks_expected_frags")
        if stored_expected is None:
            stream_data["socks_expected_frags"] = expected_chunk_count
        elif int(stored_expected) != expected_chunk_count:
            return

        socks_chunks = stream_data.get("socks_chunks", {})
        extracted_data = self._extract_packet_payload(labels, extracted_header)
        if not extracted_data or len(extracted_data) < 1:
            return

        existing_fragment = socks_chunks.get(frag_id)
        if existing_fragment is not None:
            if existing_fragment != extracted_data:
                return
            await self._enqueue_cached_response(
                session_id,
                stream_id,
                stream_data,
                ("socks_frag", int(frag_id) & 0xFF),
            )
            return

        socks_chunks[frag_id] = extracted_data

        if len(socks_chunks) > expected_chunk_count:
            # Too many fragments received, possible attack or client bug. Stop processing.
            await self._send_socks5_error_packet(
                session_id,
                stream_id,
                Packet_Type.SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
                stream_data=stream_data,
                fragment_id=frag_id,
            )
            await self.close_stream(
                session_id,
                stream_id,
                reason="Too many SOCKS5 fragments received",
                abortive=True,
            )
            return

        if len(socks_chunks) < expected_chunk_count:
            if expected_chunk_count > 1:
                fragment_payload = bytes(
                    (
                        ord("S"),
                        ord("F"),
                        ord("R"),
                        int(frag_id) & 0xFF,
                        int(expected_chunk_count) & 0xFF,
                        len(socks_chunks) & 0xFF,
                    )
                )
                self._cache_response(
                    stream_data,
                    ("socks_frag", int(frag_id) & 0xFF),
                    packet_type=Packet_Type.SOCKS5_SYN_ACK,
                    payload=fragment_payload,
                    priority=0,
                    sequence_num=0,
                )
                await self._enqueue_packet(
                    session_id,
                    0,
                    stream_id,
                    0,
                    Packet_Type.SOCKS5_SYN_ACK,
                    fragment_payload,
                )
            return

        stream_data["status"] = "SOCKS_HANDSHAKE"

        # join chunks and start
        if any(i not in socks_chunks for i in range(expected_chunk_count)):
            return

        assembled = b"".join(socks_chunks[i] for i in range(expected_chunk_count))
        if len(assembled) < 1:
            return

        atyp = assembled[0]
        expected_len = -1
        if atyp == 0x01:
            expected_len = 1 + 4 + 2
        elif atyp == 0x03 and len(assembled) >= 2:
            expected_len = 1 + 1 + assembled[1] + 2
        elif atyp == 0x04:
            expected_len = 1 + 16 + 2

        if expected_len == -1:
            await self._send_socks5_error_packet(
                session_id,
                stream_id,
                Packet_Type.SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
                stream_data=stream_data,
                fragment_id=frag_id,
            )
            await self.close_stream(
                session_id,
                stream_id,
                reason="SOCKS5 address type unsupported",
                abortive=True,
            )
            return
        if len(assembled) < expected_len:
            await self._send_socks5_error_packet(
                session_id,
                stream_id,
                Packet_Type.SOCKS5_CONNECT_FAIL,
                stream_data=stream_data,
                fragment_id=frag_id,
            )
            await self.close_stream(
                session_id,
                stream_id,
                reason="Truncated SOCKS5 target payload",
                abortive=True,
            )
            return
        if len(assembled) > expected_len:
            assembled = assembled[:expected_len]

        stream_data["status"] = "SOCKS_CONNECTING"
        stream_data["socks_expected_frags"] = None
        stream_data.get("socks_chunks", {}).clear()
        await self._process_socks5_target(
            session_id,
            stream_id,
            assembled,
            response_fragment_id=frag_id if expected_chunk_count > 1 else None,
        )

    async def _handle_stream_fin_packet(
        self, session_id, stream_id, sn, labels, extracted_header, now_mono
    ):
        """Handle STREAM_FIN packets."""
        session = self.sessions.get(session_id)
        if not session:
            return

        stream_data = session.get("streams", {}).get(stream_id)
        if not stream_data:
            await self.close_stream(session_id, stream_id, reason="Client sent FIN")
            return

        arq = stream_data.get("arq_obj")
        if not arq:
            await self._enqueue_packet(
                session_id,
                0,
                stream_id,
                sn,
                Packet_Type.STREAM_FIN_ACK,
                b"",
            )
            return

        # If FIN was already processed and its ACK may have been lost, re-ACK duplicate
        # FIN packets while the stream is still alive and not yet moved to closed_streams.
        if (
            getattr(arq, "_remote_write_closed", False)
            and getattr(arq, "_fin_seq_received", None) == sn
        ):
            await self._enqueue_packet(
                session_id,
                0,
                stream_id,
                sn,
                Packet_Type.STREAM_FIN_ACK,
                b"",
            )
            return

        if getattr(arq, "_fin_sent", False) and getattr(arq, "_fin_acked", False):
            stream_data["fin_retries"] = 99

        arq.mark_fin_received(sn)
        await arq._try_finalize_remote_eof()

    async def _handle_stream_rst_packet(
        self, session_id, stream_id, sn, labels, extracted_header, now_mono
    ):
        """Handle STREAM_RST packets."""
        await self._enqueue_packet(
            session_id,
            0,
            stream_id,
            sn,
            Packet_Type.STREAM_RST_ACK,
            b"",
        )

        session = self.sessions.get(session_id)
        stream_data = session.get("streams", {}).get(stream_id) if session else None
        if stream_data:
            arq = stream_data.get("arq_obj")
            if arq:
                arq.mark_rst_received(sn)

        await self.close_stream(
            session_id,
            stream_id,
            reason="Connection Reset By Client (RST)",
            abortive=True,
            remote_reset=True,
        )

    async def _handle_stream_rst_ack_packet(
        self, session_id, stream_id, sn, labels, extracted_header, now_mono
    ):
        """Handle STREAM_RST_ACK packets."""
        session = self.sessions.get(session_id)
        if not session:
            return

        stream_data = session.get("streams", {}).get(stream_id)
        if not stream_data:
            return

        arq = stream_data.get("arq_obj")
        if arq and getattr(arq, "_rst_seq_sent", None) == sn:
            await arq.receive_control_ack(Packet_Type.STREAM_RST_ACK, sn)
            stream_data["rst_retries"] = 99
        elif stream_data.get("rst_seq_sent") == sn:
            stream_data["rst_acked"] = True
            stream_data["rst_retries"] = 99

    async def _handle_stream_fin_ack_packet(
        self, session_id, stream_id, sn, labels, extracted_header, now_mono
    ):
        """Handle STREAM_FIN_ACK packets."""
        session = self.sessions.get(session_id)
        if not session:
            return

        stream_data = session.get("streams", {}).get(stream_id)
        if not stream_data:
            return

        arq = stream_data.get("arq_obj")
        if arq and getattr(arq, "_fin_seq_sent", None) == sn:
            await arq.receive_control_ack(Packet_Type.STREAM_FIN_ACK, sn)
            if arq._fin_received:
                await arq._try_finalize_remote_eof()
            elif not getattr(arq, "snd_buf", True) and getattr(
                arq, "_remote_write_closed", False
            ):
                await self.close_stream(
                    session_id, stream_id, reason="FIN acknowledged"
                )

    async def _handle_control_request_packet(
        self, session_id, stream_id, sn, labels, extracted_header, now_mono
    ):
        """Handle control request packets by replying with their ACK type."""

        ptype = extracted_header.get("packet_type") if extracted_header else None
        ack_ptype = self._control_request_ack_map.get(ptype)
        if ack_ptype is None:
            return

        await self._enqueue_packet(session_id, 0, stream_id, sn, ack_ptype, b"")

        session = self.sessions.get(session_id)
        if not session:
            return

        stream_data = session.get("streams", {}).get(stream_id)
        if stream_data:
            stream_data["last_activity"] = now_mono

    async def _handle_control_ack_packet(
        self, session_id, stream_id, sn, labels, extracted_header, now_mono
    ):
        """Handle control ACK packets and notify stream ARQ tracker."""
        ptype = extracted_header.get("packet_type") if extracted_header else None
        if ptype is None:
            return

        session = self.sessions.get(session_id)
        if not session:
            return

        stream_data = session.get("streams", {}).get(stream_id)
        if not stream_data:
            return

        arq = stream_data.get("arq_obj")
        if not arq:
            return

        stream_data["last_activity"] = now_mono
        await arq.receive_control_ack(ptype, sn)

    async def _handle_packed_control_blocks_packet(
        self, session_id, stream_id, sn, labels, extracted_header, now_mono
    ):
        """Handle PACKED_CONTROL_BLOCKS packets."""

        session = self.sessions.get(session_id)
        if not session:
            return

        extracted_data = self._extract_packet_payload(labels, extracted_header)
        if not extracted_data:
            return

        _unpack_from = self._block_packer.unpack_from
        block_size = self._block_packer.size
        handlers = self._stream_packet_handlers
        deferred_types = self._deferred_handler_packet_types
        spawn_task = self._spawn_background_task
        loop = self.loop
        inline_batch = []
        for i in range(0, len(extracted_data), block_size):
            if i + block_size > len(extracted_data):
                break
            b_ptype, b_stream_id, b_sn = _unpack_from(extracted_data, i)
            if (
                b_ptype not in self._valid_packet_types
                or b_ptype == Packet_Type.PACKED_CONTROL_BLOCKS
            ):
                continue

            handler = handlers.get(b_ptype)
            if not handler:
                continue

            block_coro = handler(
                session_id,
                b_stream_id,
                b_sn,
                "",
                {"packet_type": b_ptype},
                now_mono,
            )
            if b_ptype in deferred_types and loop:
                spawn_task(block_coro)
                continue

            inline_batch.append(block_coro)
            if len(inline_batch) >= 8:
                await asyncio.gather(*inline_batch, return_exceptions=True)
                inline_batch.clear()

        if inline_batch:
            await asyncio.gather(*inline_batch, return_exceptions=True)

    async def _dispatch_stream_packet(
        self, packet_type, session_id, stream_id, sn, labels, extracted_header, now_mono
    ):
        """Dispatch stream/control packet to dedicated handler method."""
        handler = self._stream_packet_handlers.get(packet_type)
        if not handler:
            return

        await handler(session_id, stream_id, sn, labels, extracted_header, now_mono)

    async def _dispatch_stream_packet_nonblocking(
        self, packet_type, session_id, stream_id, sn, labels, extracted_header, now_mono
    ):
        """Dispatch handlers with deferred execution for heavy packet types."""
        dispatch_coro = self._dispatch_stream_packet(
            packet_type=packet_type,
            session_id=session_id,
            stream_id=stream_id,
            sn=sn,
            labels=labels,
            extracted_header=extracted_header,
            now_mono=now_mono,
        )

        if packet_type in self._deferred_handler_packet_types and self.loop:
            self._spawn_background_task(dispatch_coro)
            return

        await dispatch_coro

    async def _handle_pre_session_packet(
        self,
        packet_type: int,
        session_id: int,
        data: bytes,
        labels: str,
        request_domain: str,
        extracted_header: Optional[dict] = None,
    ) -> Optional[bytes]:
        if packet_type == Packet_Type.SESSION_INIT:
            return await self._handle_session_init(
                request_domain=request_domain,
                data=data,
                labels=labels,
                extracted_header=extracted_header,
            )
        if packet_type == Packet_Type.MTU_UP_REQ:
            return await self._handle_mtu_up(
                request_domain=request_domain,
                session_id=session_id,
                data=data,
                labels=labels,
            )
        if packet_type == Packet_Type.MTU_DOWN_REQ:
            return await self._handle_mtu_down(
                request_domain=request_domain,
                session_id=session_id,
                labels=labels,
                data=data,
                extracted_header=extracted_header,
            )
        return None

    async def _process_session_packet(
        self,
        packet_type: int,
        session_id: int,
        stream_id: int,
        sn: int,
        labels: str,
        extracted_header: Optional[dict],
        now_mono: float,
    ) -> None:
        """Process a session packet without blocking response generation."""
        handled_closed_stream = await self._handle_closed_stream_packet(
            session_id, stream_id, packet_type, sn
        )

        if handled_closed_stream:
            return

        await self._dispatch_stream_packet_nonblocking(
            packet_type=packet_type,
            session_id=session_id,
            stream_id=stream_id,
            sn=sn,
            labels=labels,
            extracted_header=extracted_header,
            now_mono=now_mono,
        )

    def _get_active_response_queue(
        self, session: dict, streams: dict, stream_id: int
    ) -> tuple[Optional[list], Optional[dict]]:
        """
        Resolve one active response queue by stream_id.
        stream_id 0 is the session main queue.
        If the cached active id became stale, drop it immediately.
        """
        sid = int(stream_id)
        if sid == 0:
            main_queue = session.get("main_queue")
            if main_queue:
                return main_queue, session
        else:
            stream_data = streams.get(sid)
            if stream_data:
                tx_queue = stream_data.get("tx_queue")
                if tx_queue:
                    return tx_queue, stream_data

        self._deactivate_response_queue(session, sid)
        return None, None

    def _pack_selected_response_blocks(
        self,
        session: dict,
        streams: dict,
        selected_stream_id: int,
        selected_queue,
        selected_owner: dict,
        first_item: tuple,
        max_blocks: int,
    ) -> bytes:
        """
        Pack same-priority payload-less control blocks starting from the selected
        queue, then do one circular pass over the remaining active queues.
        """
        if max_blocks <= 1:
            return b""

        target_priority = int(first_item[0])
        _pack = self._block_packer.pack
        _pop_packable = self._pop_packable_control_block
        _owner_has_priority = self._owner_has_priority
        packed_buffer = bytearray(_pack(first_item[2], first_item[3], first_item[4]))
        blocks = 1

        while blocks < max_blocks:
            popped = _pop_packable(
                selected_queue,
                selected_owner,
                target_priority,
            )
            if popped is None:
                break
            packed_buffer.extend(_pack(popped[2], popped[3], popped[4]))
            blocks += 1
            if not selected_queue:
                self._deactivate_response_queue(session, selected_stream_id)
                break

        if blocks >= max_blocks:
            return bytes(packed_buffer)

        active_ids = tuple(session.get("active_response_ids", ()))
        if not active_ids:
            return bytes(packed_buffer)

        num_queues = len(active_ids)
        start_pos = bisect_right(active_ids, selected_stream_id)
        if start_pos >= num_queues:
            start_pos = 0

        for offset in range(num_queues):
            if blocks >= max_blocks:
                break
            sid = active_ids[(start_pos + offset) % num_queues]
            if sid == selected_stream_id:
                continue
            q_ref, owner = self._get_active_response_queue(session, streams, sid)
            if not q_ref or not owner:
                continue
            if not _owner_has_priority(owner, target_priority):
                continue

            while blocks < max_blocks:
                popped = _pop_packable(
                    q_ref,
                    owner,
                    target_priority,
                )
                if popped is None:
                    break
                packed_buffer.extend(_pack(popped[2], popped[3], popped[4]))
                blocks += 1
                if not q_ref:
                    self._deactivate_response_queue(session, sid)
                    break

        return bytes(packed_buffer) if blocks > 1 else b""

    def _dequeue_response_packet(self, session: dict, streams: dict):
        """
        Round-robin dequeue across all active response queues.
        The session main queue participates as virtual stream 0.
        """
        res_data = None
        res_stream_id = 0
        res_sn = 0
        res_ptype = Packet_Type.PONG

        active_ids = session.get("active_response_ids", [])
        if not active_ids:
            return res_ptype, res_stream_id, res_sn, res_data

        last_stream_id = int(session.get("round_robin_stream_id", -1))
        selected_pos = bisect_right(active_ids, last_stream_id)
        attempts = len(active_ids)
        target_queue = None
        pop_owner = None
        selected_stream_id = 0

        while attempts > 0 and active_ids:
            if selected_pos >= len(active_ids):
                selected_pos = 0
            candidate_stream_id = active_ids[selected_pos]
            target_queue, pop_owner = self._get_active_response_queue(
                session, streams, candidate_stream_id
            )
            if target_queue and pop_owner:
                selected_stream_id = candidate_stream_id
                break
            attempts -= 1

        if not target_queue or not pop_owner:
            return res_ptype, res_stream_id, res_sn, res_data

        item = heapq.heappop(target_queue)
        self._on_queue_pop(pop_owner, item)
        if not target_queue:
            self._deactivate_response_queue(session, selected_stream_id)
        session["round_robin_stream_id"] = selected_stream_id

        res_ptype, res_stream_id, res_sn, res_data = (
            item[2],
            item[3],
            item[4],
            item[5],
        )

        if (
            res_ptype in self._packable_control_types
            and not res_data
            and session["max_packed_blocks"] > 1
        ):
            packed = self._pack_selected_response_blocks(
                session=session,
                streams=streams,
                selected_stream_id=selected_stream_id,
                selected_queue=target_queue,
                selected_owner=pop_owner,
                first_item=item,
                max_blocks=session["max_packed_blocks"],
            )
            if packed:
                res_ptype = Packet_Type.PACKED_CONTROL_BLOCKS
                res_stream_id = 0
                res_sn = 0
                res_data = packed

        return res_ptype, res_stream_id, res_sn, res_data

    def _build_invalid_session_error_response(
        self,
        session_id: int,
        request_domain: str,
        question_packet: bytes,
        closed_info: Optional[dict],
    ) -> bytes:
        try:
            is_base = (
                closed_info["base_encode"]
                if closed_info
                else random.choice([True, False])
            )
            invalid_response_data = b"INV" + os.urandom(5)
            return self.dns_parser.generate_vpn_response_packet(
                domain=request_domain,
                session_id=session_id,
                packet_type=Packet_Type.ERROR_DROP,
                data=invalid_response_data,
                question_packet=question_packet,
                encode_data=is_base,
                session_cookie=0,
            )
        except Exception as e:
            self.logger.debug(
                f"<red>Error building invalid session response: {e}</red>"
            )
            return b""

    async def handle_vpn_packet(
        self,
        packet_type: int,
        session_id: int,
        data: bytes = b"",
        labels: str = "",
        parsed_packet: Optional[dict] = None,
        addr=None,
        request_domain: str = "",
        extracted_header: Optional[dict] = None,
    ) -> Optional[bytes]:
        # First handle packets that don't require an active session (e.g. session init, MTU negotiation).
        if packet_type in self._pre_session_packet_types:
            pre_session_response = await self._handle_pre_session_packet(
                packet_type=packet_type,
                session_id=session_id,
                data=data,
                labels=labels,
                request_domain=request_domain,
                extracted_header=extracted_header,
            )

            if pre_session_response:
                return pre_session_response
            else:
                return None

        session = self.sessions.get(session_id)
        if not session:
            self.logger.debug(
                f"<yellow>Packet received for expired/invalid session <cyan>{session_id}</cyan> from <cyan>{addr}</cyan>. Dropping.</yellow>"
            )

            closed_info = self.recently_closed_sessions.get(session_id)
            return self._build_invalid_session_error_response(
                session_id=session_id,
                request_domain=request_domain,
                question_packet=data,
                closed_info=closed_info,
            )

        if packet_type == Packet_Type.SET_MTU_REQ:
            return await self._handle_set_mtu(
                request_domain=request_domain,
                session_id=session_id,
                labels=labels,
                data=data,
                extracted_header=extracted_header,
                addr=addr,
            )

        now_mono = time.monotonic()
        self._touch_session(session_id)

        stream_id = extracted_header.get("stream_id", 0) if extracted_header else 0
        sn = extracted_header.get("sequence_num", 0) if extracted_header else 0

        streams = session.get("streams")
        if streams is None:
            session["streams"] = {}
            streams = session["streams"]

        await self._process_session_packet(
            packet_type=packet_type,
            session_id=session_id,
            stream_id=stream_id,
            sn=sn,
            labels=labels,
            extracted_header=extracted_header,
            now_mono=now_mono,
        )

        res_ptype, res_stream_id, res_sn, res_data = self._dequeue_response_packet(
            session, streams
        )

        if res_ptype == Packet_Type.PONG:
            res_data = b"PO:" + os.urandom(4)

        response_compression_type = Compression_Type.OFF
        if res_data and res_ptype in self.dns_parser._PT_COMP_EXT:
            preferred_download_comp = session.get(
                "client_download_compression_type", Compression_Type.OFF
            )
            res_data, response_compression_type = compress_payload(
                res_data, preferred_download_comp, 100
            )

        base_encode = session.get("base_encode_responses", False)

        return self.dns_parser.generate_vpn_response_packet(
            domain=request_domain,
            session_id=session_id,
            packet_type=res_ptype,
            data=res_data,
            question_packet=data,
            stream_id=res_stream_id,
            sequence_num=res_sn,
            encode_data=base_encode,
            compression_type=response_compression_type,
            session_cookie=int(session.get("session_cookie", 0) or 0),
        )

    async def _process_socks5_target(
        self,
        session_id,
        stream_id,
        target_payload,
        response_fragment_id: int | None = None,
    ):
        session = self.sessions.get(session_id)
        if not session:
            return
        stream_data = session.get("streams", {}).get(stream_id)
        if not stream_data:
            return

        use_external_socks5 = self.use_external_socks5
        forward_ip = self.forward_ip
        forward_port = self.forward_port
        socks5_auth = self.socks5_auth
        logger = self.logger

        try:
            if not target_payload or len(target_payload) < 3:
                raise Socks5ConnectError(0x01, "Invalid SOCKS5 target payload")

            atyp = target_payload[0]
            offset = 1
            if atyp == 0x01:
                if len(target_payload) < offset + 4 + 2:
                    raise Socks5ConnectError(0x01, "Truncated IPv4 target payload")
                target_ip = socket.inet_ntoa(target_payload[offset : offset + 4])
                offset += 4
            elif atyp == 0x03:
                if len(target_payload) < offset + 1:
                    raise Socks5ConnectError(0x01, "Missing domain length in payload")
                dlen = target_payload[offset]
                offset += 1
                if dlen == 0 or len(target_payload) < offset + dlen + 2:
                    raise Socks5ConnectError(0x01, "Truncated domain target payload")
                target_ip = target_payload[offset : offset + dlen].decode(
                    "utf-8", errors="ignore"
                )
                offset += dlen
            elif atyp == 0x04:
                if len(target_payload) < offset + 16 + 2:
                    raise Socks5ConnectError(0x01, "Truncated IPv6 target payload")
                target_ip = socket.inet_ntop(
                    socket.AF_INET6, target_payload[offset : offset + 16]
                )
                offset += 16
            else:
                raise Socks5ConnectError(
                    0x08, f"Unsupported SOCKS5 target address type: {atyp}"
                )

            if len(target_payload) < offset + 2:
                raise Socks5ConnectError(0x01, "Missing target port in payload")
            target_port = struct.unpack(">H", target_payload[offset : offset + 2])[0]

            async def _connect_and_handshake():
                if use_external_socks5:
                    logger.debug(
                        f"<green>Forwarding to External SOCKS5 <blue>{forward_ip}:{forward_port}</blue> for target <cyan>{target_ip}:{target_port}</cyan> (Stream {stream_id})</green>"
                    )
                    c_reader, c_writer = await asyncio.open_connection(
                        forward_ip, forward_port
                    )

                    if socks5_auth:
                        c_writer.write(b"\x05\x01\x02")
                    else:
                        c_writer.write(b"\x05\x01\x00")
                    await c_writer.drain()

                    greeting_res = await c_reader.readexactly(2)
                    if greeting_res[0] != 0x05:
                        raise ValueError("Upstream proxy is not a valid SOCKS5 server")

                    if socks5_auth and greeting_res[1] == 0x02:
                        u_bytes = self.socks5_user_bytes
                        p_bytes = self.socks5_pass_bytes
                        auth_req = (
                            b"\x01"
                            + bytes([len(u_bytes)])
                            + u_bytes
                            + bytes([len(p_bytes)])
                            + p_bytes
                        )
                        c_writer.write(auth_req)
                        await c_writer.drain()

                        auth_res = await c_reader.readexactly(2)
                        if auth_res[1] != 0x00:
                            raise ValueError("External SOCKS5 Authentication failed!")
                    elif greeting_res[1] != 0x00:
                        raise ValueError(
                            "External SOCKS5 requires unsupported authentication method"
                        )

                    conn_req = b"\x05\x01\x00" + target_payload
                    c_writer.write(conn_req)
                    await c_writer.drain()

                    resp_header = await c_reader.readexactly(4)
                    if resp_header[0] != 0x05 or resp_header[1] != 0x00:
                        raise Socks5ConnectError(
                            resp_header[1],
                            f"External SOCKS5 failed to connect to target. Code: {resp_header[1]}",
                        )

                    bnd_atyp = resp_header[3]
                    if bnd_atyp == 0x01:
                        await c_reader.readexactly(6)
                    elif bnd_atyp == 0x03:
                        dlen = await c_reader.readexactly(1)
                        await c_reader.readexactly(dlen[0] + 2)
                    elif bnd_atyp == 0x04:
                        await c_reader.readexactly(18)

                    return c_reader, c_writer
                else:
                    logger.debug(
                        f"<green>SOCKS5 Fast-Connecting directly to <blue>{target_ip}:{target_port}</blue> for stream <cyan>{stream_id}</cyan></green>"
                    )
                    return await asyncio.open_connection(target_ip, target_port)

            try:
                reader, writer = await asyncio.wait_for(
                    _connect_and_handshake(), timeout=45.0
                )
            except asyncio.TimeoutError as timeout_exc:
                raise timeout_exc

            if stream_data.get("status") in ("CLOSING", "TIME_WAIT"):
                writer.close()
                await writer.wait_closed()
                self.logger.debug(
                    f"<yellow>Stream {stream_id} was closed by client during connection phase. Aborting to prevent zombies.</yellow>"
                )
                return

            arq = ARQ(
                stream_id=stream_id,
                session_id=session_id,
                enqueue_tx_cb=lambda p, sid, sn, d, **kw: self._arq_enqueue_tx(
                    session_id, p, sid, sn, d, **kw
                ),
                enqueue_control_tx_cb=lambda p, sid, sn, pt, d, **kw: (
                    self._arq_enqueue_control_tx(session_id, p, sid, sn, pt, d, **kw)
                ),
                reader=reader,
                writer=writer,
                mtu=session.get("download_mtu", 50),
                logger=logger,
                window_size=self.arq_window_size,
                rto=self.arq_initial_rto,
                max_rto=self.arq_max_rto,
                enable_control_reliability=True,
                control_rto=self.arq_control_initial_rto,
                control_max_rto=self.arq_control_max_rto,
                control_max_retries=self.arq_control_max_retries,
            )

            # SOCKS5_SYN is handled on control-plane now, so ARQ data-plane
            # sequence must start from 0 for first STREAM_DATA packet.
            arq.rcv_nxt = 0

            stream_data["arq_obj"] = arq
            stream_data["status"] = "CONNECTED"

            await self._queue_and_cache_response(
                session_id,
                stream_id,
                stream_data,
                "socks",
                packet_type=Packet_Type.SOCKS5_SYN_ACK,
                payload=b"",
                priority=2,
                sequence_num=0,
            )
            if response_fragment_id is not None:
                self._cache_response(
                    stream_data,
                    ("socks_frag", int(response_fragment_id) & 0xFF),
                    packet_type=Packet_Type.SOCKS5_SYN_ACK,
                    payload=stream_data["syn_responses"]["socks"].get("payload", b""),
                    priority=2,
                    sequence_num=0,
                )

        except Exception as e:
            err_packet = self._map_socks5_exception_to_packet(e)
            await self._send_socks5_error_packet(
                session_id,
                stream_id,
                err_packet,
                stream_data=stream_data,
                fragment_id=response_fragment_id,
            )

            self.logger.debug(
                f"<red>SOCKS5 target connection failed for stream {stream_id}: {e}</red>"
            )
            await self.close_stream(
                session_id,
                stream_id,
                reason=f"SOCKS target unreachable: {e}",
                abortive=True,
            )

    async def _send_parser_response(self, builder, data, addr=None):
        if addr is None:
            self.logger.debug("<red>Cannot send parser response: addr is None.</red>")
            return

        response = await self._run_cpu_task(builder, data)
        if response:
            await self.send_udp_response(response, addr)

    async def handle_single_request(self, data, addr):
        """Handle a single DNS request efficiently."""
        try:
            if not data or not addr:
                return

            parsed_packet = await self._run_cpu_task(
                self.dns_parser.parse_dns_packet, data
            )

            if not parsed_packet or not parsed_packet.get("questions"):
                self.logger.debug(
                    f"Received invalid DNS request from {addr}. Ignoring."
                )
                await self._send_parser_response(
                    self.dns_parser.format_error_response, data, addr
                )
                return

            q0 = parsed_packet["questions"][0]
            request_domain = q0.get("qName")
            if not request_domain:
                self.logger.debug(
                    f"Received DNS request with empty qName from {addr}. Ignoring."
                )
                await self._send_parser_response(
                    self.dns_parser.format_error_response, data, addr
                )
                return

            packet_domain = request_domain.lower()

            packet_main_domain = next(
                (d for d in self.allowed_domains_lower if packet_domain.endswith(d)),
                "",
            )

            if not packet_main_domain:
                self.logger.debug(
                    f"Received DNS request for unauthorized domain '{request_domain}' from {addr}. Ignoring."
                )
                await self._send_parser_response(
                    self.dns_parser.refused_response, data, addr
                )
                return

            if q0.get("qType") != DNS_Record_Type.TXT:
                await self._send_parser_response(
                    self.dns_parser.empty_noerror_response, data, addr
                )
                return

            labels = (
                packet_domain[: -len("." + packet_main_domain)]
                if packet_main_domain
                else ""
            )

            if not labels:
                await self._send_parser_response(
                    self.dns_parser.empty_noerror_response, data, addr
                )
                return

            if len(labels) < 3:
                self.logger.debug(
                    f"Received DNS request with insufficient labels '{labels}' from {addr}. Ignoring."
                )
                await self._send_parser_response(
                    self.dns_parser.empty_noerror_response, data, addr
                )
                return

            try:
                extracted_header = await self._run_cpu_task(
                    self.dns_parser.extract_vpn_header_from_labels, labels
                )
            except Exception as e:
                self.logger.debug(
                    f"Error extracting VPN header from labels '{labels}': {e}"
                )
                extracted_header = None

            if not extracted_header:
                self.logger.debug(
                    f"Failed to extract VPN header from labels '{labels}' in request from {addr}. Ignoring."
                )
                await self._send_parser_response(
                    self.dns_parser.empty_noerror_response, data, addr
                )
                return

            packet_type = int(extracted_header.get("packet_type", -1))
            session_id = int(extracted_header.get("session_id", -1))
            packet_cookie = int(extracted_header.get("session_cookie", 0) or 0)
            expected_cookie = self._expected_session_cookie(packet_type, session_id)
            if expected_cookie is None or packet_cookie != expected_cookie:
                self.logger.debug(
                    f"Invalid session cookie for packet type '{packet_type}' session '{session_id}' from {addr}. Dropping."
                )
                return

            if packet_type in self._valid_packet_types:
                try:
                    vpn_response = await self.handle_vpn_packet(
                        packet_type=packet_type,
                        session_id=session_id,
                        data=data,
                        labels=labels,
                        parsed_packet=parsed_packet,
                        addr=addr,
                        request_domain=request_domain,
                        extracted_header=extracted_header,
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    self.logger.debug(
                        f"Error handling VPN packet for session_id '{session_id}' from {addr}: {e}"
                    )
                    vpn_response = None

            if vpn_response:
                await self.send_udp_response(vpn_response, addr)
                return

            await self._send_parser_response(
                self.dns_parser.empty_noerror_response, data, addr
            )
        except Exception as error:
            self.logger.debug(
                f"Unexpected error in handle_single_request from {addr}: {error}"
            )
            return

    async def _run_cpu_task(self, func, *args, **kwargs):
        """Run CPU-heavy pure parser/codec work off-loop without touching session state."""
        if not self.cpu_executor:
            return func(*args, **kwargs)
        loop = self.loop or asyncio.get_running_loop()
        if kwargs:
            return await loop.run_in_executor(
                self.cpu_executor, functools.partial(func, *args, **kwargs)
            )
        return await loop.run_in_executor(self.cpu_executor, func, *args)

    async def handle_dns_requests(self) -> None:
        """Asynchronously handle incoming DNS requests and spawn a new task for each."""
        assert self.udp_sock is not None, "UDP socket is not initialized."
        assert self.loop is not None, "Event loop is not initialized."
        self.udp_sock.setblocking(False)

        loop = self.loop
        sock = self.udp_sock
        bg_tasks = self._background_tasks
        handle_req = self.handle_single_request
        semaphore = self.max_concurrent_requests

        while not self.should_stop.is_set():
            try:
                data, addr = await async_recvfrom(loop, sock, 65536)
                if len(data) < 12:
                    continue

                await semaphore.acquire()

                task = loop.create_task(handle_req(data, addr))
                bg_tasks.add(task)

                task.add_done_callback(
                    lambda t: (bg_tasks.discard(t), semaphore.release())
                )

            except asyncio.CancelledError:
                break
            except OSError as e:
                if getattr(e, "winerror", None) == 10054:
                    continue
                self.logger.debug(f"Socket error: {e}")
                await asyncio.sleep(0.1)
            except Exception as e:
                self.logger.debug(f"Unexpected error receiving DNS request: {e}")
                await asyncio.sleep(0.1)

    # ---------------------------------------------------------
    # MTU Testing Logic
    # ---------------------------------------------------------
    async def _handle_set_mtu(
        self,
        data=None,
        labels=None,
        request_domain=None,
        addr=None,
        parsed_packet=None,
        session_id=None,
        extracted_header=None,
    ) -> Optional[bytes]:
        """Handle SET_MTU_REQ VPN packet and save it to the session."""
        try:
            session = self.sessions.get(session_id)
            if not session:
                self.logger.debug(
                    f"SET_MTU_REQ received for invalid session_id: {session_id} from {addr}"
                )
                return None

            extracted_data = self._extract_packet_payload(labels, extracted_header)

            if not extracted_data or len(extracted_data) < 8:
                self.logger.debug(f"Invalid or missing SET_MTU_REQ data from {addr}")
                return None

            upload_mtu = int.from_bytes(extracted_data[:4], "big")
            download_mtu = int.from_bytes(extracted_data[4:8], "big")
            sync_token = extracted_data[8:] if len(extracted_data) > 8 else b"OK"

            safe_upload_mtu = min(upload_mtu, 4096)
            safe_download_mtu = min(download_mtu, 4096)

            safe_downlink_mtu = safe_download_mtu - self.crypto_overhead
            session["upload_mtu"] = safe_upload_mtu - self.crypto_overhead
            session["download_mtu"] = safe_downlink_mtu

            download_pack_limit = self._compute_mtu_based_pack_limit(
                safe_download_mtu,
                80.0,
                self._block_packer.size,
            )
            session["max_packed_blocks"] = max(
                1,
                min(download_pack_limit, self.max_packets_per_batch),
            )
            self._touch_session(session_id)

            self.logger.info(
                f"<green>Session <cyan>{session_id}</cyan> MTU synced - Upload: <cyan>{safe_upload_mtu}</cyan>, Download: <cyan>{safe_download_mtu}</cyan></green>"
            )

            base_encode = session.get("base_encode_responses", False)
            return self.dns_parser.generate_vpn_response_packet(
                domain=request_domain,
                session_id=session_id,
                packet_type=Packet_Type.SET_MTU_RES,
                data=sync_token,
                question_packet=data,
                encode_data=base_encode,
                session_cookie=int(session.get("session_cookie", 0) or 0),
            )
        except Exception as e:
            self.logger.debug(f"Error handling SET_MTU_REQ from {addr}: {e}")
            return None

    async def _handle_mtu_down(
        self,
        data=None,
        labels=None,
        request_domain=None,
        addr=None,
        parsed_packet=None,
        session_id=None,
        extracted_header=None,
    ) -> Optional[bytes]:
        """Handle MTU_DOWN_REQ (download MTU test) VPN packet."""
        try:
            download_size_bytes = self._extract_packet_payload(labels, extracted_header)

            if not download_size_bytes or len(download_size_bytes) < 5:
                self.logger.warning(
                    f"Failed to decode download size in SERVER_DOWNLOAD_TEST packet from {addr}"
                )
                return None

            flag = download_size_bytes[0]
            base_encode = flag == 1
            download_size = int.from_bytes(download_size_bytes[1:5], "big")

            if download_size < 29:
                self.logger.warning(
                    f"Download size too small in packet from {addr}: {download_size}"
                )
                return None

            if download_size > len(download_size_bytes) - 1:
                padding_len = download_size - (len(download_size_bytes) - 1)
                raw_plaintext = download_size_bytes[1:] + os.urandom(padding_len)
            else:
                raw_plaintext = download_size_bytes[1 : 1 + download_size]

            return self.dns_parser.generate_vpn_response_packet(
                domain=request_domain,
                session_id=session_id if session_id is not None else 255,
                packet_type=Packet_Type.MTU_DOWN_RES,
                data=raw_plaintext,
                question_packet=data,
                encode_data=base_encode,
                session_cookie=0,
            )
        except Exception as e:
            self.logger.debug(f"Error handling MTU_DOWN_REQ from {addr}: {e}")
            return None

    async def _handle_mtu_up(
        self,
        data=None,
        labels=None,
        request_domain=None,
        addr=None,
        parsed_packet=None,
        session_id=None,
        extracted_header=None,
    ) -> Optional[bytes]:
        """Handle SERVER_UPLOAD_TEST VPN packet."""
        try:
            raw_label = labels.split(".")[0] if "." in labels else labels
            base_encode = raw_label.startswith("1")

            return self.dns_parser.generate_vpn_response_packet(
                domain=request_domain,
                session_id=session_id if session_id is not None else 255,
                packet_type=Packet_Type.MTU_UP_RES,
                data=b"1",
                question_packet=data,
                encode_data=base_encode,
                session_cookie=0,
            )
        except Exception as e:
            self.logger.debug(f"Error handling MTU_UP_REQ from {addr}: {e}")
            return None

    # ---------------------------------------------------------
    # TCP Forwarding Logic & Server Retransmits
    # ---------------------------------------------------------
    async def close_stream(
        self,
        session_id: int,
        stream_id: int,
        reason: str = "Unknown",
        abortive: bool = False,
        remote_reset: bool = False,
    ) -> None:
        """Safely close a specific stream without sending FIN before snd_buf is drained."""
        session = self.sessions.get(session_id)
        if not session:
            return

        session_streams = session.get("streams", {})
        stream_data = session_streams.get(stream_id)
        if not stream_data:
            return

        status = stream_data.get("status")
        if status in ("CLOSING", "TIME_WAIT"):
            return

        arq_obj = stream_data.get("arq_obj")

        # Phase 1: graceful drain first
        if not abortive and arq_obj and not getattr(arq_obj, "closed", False):
            if not getattr(arq_obj, "_fin_sent", False):
                stream_data["status"] = "DRAINING"
                self.logger.debug(
                    f"<yellow>Draining Stream <cyan>{stream_id}</cyan> in Session "
                    f"<cyan>{session_id}</cyan>. Reason: <yellow>{reason}</yellow></yellow>"
                )
                try:
                    await arq_obj._initiate_graceful_close(reason=reason)
                except Exception as e:
                    self.logger.debug(f"Error draining ARQStream {stream_id}: {e}")
                return

        # Phase 2: final cleanup
        stream_data["status"] = "CLOSING"
        session.setdefault("closed_streams", {})[stream_id] = time.monotonic()

        if len(session["closed_streams"]) > 1000:
            session["closed_streams"].pop(next(iter(session["closed_streams"])))

        self.logger.debug(
            f"<yellow>Closing Stream <cyan>{stream_id}</cyan> in Session "
            f"<cyan>{session_id}</cyan>. Reason: <yellow>{reason}</yellow></yellow>"
        )

        if arq_obj:
            try:
                if abortive:
                    if remote_reset or getattr(arq_obj, "_rst_received", False):
                        await arq_obj.close(reason=reason, send_fin=False)
                    else:
                        await arq_obj.abort(reason=reason)
                elif not getattr(arq_obj, "closed", False):
                    await arq_obj.close(reason=reason, send_fin=True)
            except Exception as e:
                self.logger.debug(f"Error closing ARQStream {stream_id}: {e}")
        else:
            if abortive and not remote_reset:
                rst_sn = stream_data.get("rst_seq_sent", 0)
                stream_data["rst_sent"] = True
                stream_data["rst_acked"] = False
                stream_data["rst_seq_sent"] = rst_sn

                await self._enqueue_packet(
                    session_id, 0, stream_id, rst_sn, Packet_Type.STREAM_RST, b""
                )
            elif not abortive:
                await self._enqueue_packet(
                    session_id, 1, stream_id, 0, Packet_Type.STREAM_FIN, b""
                )

        pending_tx = stream_data.get("tx_queue", [])
        if pending_tx:
            main_q = session.setdefault("main_queue", [])
            main_was_empty = not main_q
            moved_any = False
            for item in pending_tx:
                ptype = int(item[2])
                if (
                    ptype in self._packable_control_types
                    and ptype != Packet_Type.SOCKS5_SYN
                ):
                    if self._track_main_packet_once(
                        session,
                        int(item[3]),
                        ptype,
                        int(item[4]),
                        payload=item[5],
                    ):
                        self._push_queue_item(main_q, session, item)
                        moved_any = True
                    self._dec_priority_counter(stream_data, item[0])

            if main_was_empty and moved_any:
                self._activate_response_queue(session, 0)

        try:
            stream_data["tx_queue"].clear()
            stream_data["track_ack"].clear()
            stream_data["track_fin"].clear()
            stream_data["track_syn_ack"].clear()
            stream_data["track_resend"].clear()
            stream_data["track_data"].clear()
            stream_data.get("track_types", set()).clear()
            stream_data.get("track_seq_packets", set()).clear()
            stream_data.get("track_fragment_packets", set()).clear()
            stream_data.get("socks_chunks", {}).clear()
            stream_data.get("syn_responses", {}).clear()
            stream_data["socks_expected_frags"] = None
            stream_data["priority_counts"].clear()
            stream_data["status"] = "TIME_WAIT"
            stream_data["close_time"] = time.monotonic()
            self._deactivate_response_queue(session, stream_id)
        except Exception:
            pass

    # ---------------------------------------------------------
    # ARQ Enqueue Adapters
    # ---------------------------------------------------------
    async def _arq_enqueue_tx(self, session_id, priority, stream_id, sn, data, **flags):
        """Data-plane enqueue adapter for ARQ (legacy flag API -> Packet_Type)."""
        ptype = self._resolve_arq_packet_type(**flags)
        await self._enqueue_packet(session_id, priority, stream_id, sn, ptype, data)

    async def _arq_enqueue_control_tx(
        self,
        session_id,
        priority,
        stream_id,
        sn,
        packet_type,
        payload,
        is_retransmit=False,
    ):
        """Control-plane enqueue adapter for ARQ control packets."""
        _ = is_retransmit
        await self._enqueue_packet(
            session_id,
            priority,
            stream_id,
            sn,
            int(packet_type),
            payload or b"",
        )

    async def _enqueue_packet(
        self, session_id, priority, stream_id, sn, packet_type, data
    ):
        """Enqueue one outgoing VPN packet into session/stream queues."""
        # All outbound packets pass through this function so dedupe and queue
        # bookkeeping stay consistent no matter which subsystem produced them.
        session = self.sessions.get(session_id)
        if not session:
            return

        ptype = int(packet_type)
        # Normalize caller priority once so control packets get their forced priority.
        eff_priority = self._effective_priority_for_packet(ptype, priority)

        # enqueue_seq provides deterministic heap ordering between same-priority items.
        session["enqueue_seq"] = (session.get("enqueue_seq", 0) + 1) & 0x7FFFFFFF
        queue_item = (eff_priority, session["enqueue_seq"], ptype, stream_id, sn, data)

        if stream_id == 0:
            # stream_id 0 is the session/main queue. Dedupe here must be session-aware.
            if not self._track_main_packet_once(
                session, stream_id, ptype, sn, payload=data
            ):
                return
            was_empty = not session["main_queue"]
            self._push_queue_item(session["main_queue"], session, queue_item)
            if was_empty:
                self._activate_response_queue(session, 0)
            return

        stream_data = session.get("streams", {}).get(stream_id)
        if not stream_data:
            # Once a stream disappears, only terminal cleanup packets are allowed to
            # fall back to main_queue so the peer can still converge its state.
            if ptype in (
                Packet_Type.STREAM_RST,
                Packet_Type.STREAM_RST_ACK,
                Packet_Type.STREAM_FIN_ACK,
                Packet_Type.SOCKS5_CONNECT_FAIL,
                Packet_Type.SOCKS5_RULESET_DENIED,
                Packet_Type.SOCKS5_NETWORK_UNREACHABLE,
                Packet_Type.SOCKS5_HOST_UNREACHABLE,
                Packet_Type.SOCKS5_CONNECTION_REFUSED,
                Packet_Type.SOCKS5_TTL_EXPIRED,
                Packet_Type.SOCKS5_COMMAND_UNSUPPORTED,
                Packet_Type.SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
                Packet_Type.SOCKS5_AUTH_FAILED,
                Packet_Type.SOCKS5_UPSTREAM_UNAVAILABLE,
            ):
                if not self._track_main_packet_once(
                    session, stream_id, ptype, sn, payload=data
                ):
                    return
                was_empty = not session["main_queue"]
                self._push_queue_item(session["main_queue"], session, queue_item)
                if was_empty:
                    self._activate_response_queue(session, 0)
            return

        # Normal per-stream traffic uses stream-local dedupe so duplicate control/data
        # packets do not accumulate while the original copy is still queued.
        if not self._track_stream_packet_once(
            stream_data,
            ptype,
            sn,
            data_packet_types=(Packet_Type.STREAM_DATA,),
            payload=data,
        ):
            return
        was_empty = not stream_data["tx_queue"]
        self._push_queue_item(stream_data["tx_queue"], stream_data, queue_item)
        if was_empty:
            self._activate_response_queue(session, stream_id)

    async def _handle_stream_syn(self, session_id, stream_id, syn_sn=0):
        session = self.sessions.get(session_id)
        if not session:
            return

        syn_sn = int(syn_sn) & 0xFFFF

        if stream_id in session.get("closed_streams", {}):
            await self._enqueue_packet(
                session_id,
                1,
                stream_id,
                0,
                Packet_Type.STREAM_RST,
                b"",
            )
            return

        session_streams = session["streams"]

        if stream_id in session_streams:
            existing = session_streams.get(stream_id)
            if not existing:
                return

            await self._enqueue_cached_response(
                session_id,
                stream_id,
                existing,
                "stream",
                sequence_num=syn_sn,
            )
            return

        now = time.monotonic()
        stream_data = {
            "stream_id": stream_id,
            "created_at": now,
            "last_activity": now,
            "status": "CONNECTING",
            "arq_obj": None,
            "tx_queue": [],
            "priority_counts": {},
            "track_ack": set(),
            "track_fin": set(),
            "track_syn_ack": set(),
            "track_data": set(),
            "track_resend": set(),
            "track_types": set(),
            "socks_chunks": {},
        }

        session_streams[stream_id] = stream_data

        try:
            reader, writer = await asyncio.open_connection(
                self.forward_ip, self.forward_port
            )

            stream = ARQ(
                stream_id=stream_id,
                session_id=session_id,
                enqueue_tx_cb=lambda p, sid, sn, d, **kw: self._arq_enqueue_tx(
                    session_id, p, sid, sn, d, **kw
                ),
                enqueue_control_tx_cb=lambda p, sid, sn, pt, d, **kw: (
                    self._arq_enqueue_control_tx(session_id, p, sid, sn, pt, d, **kw)
                ),
                reader=reader,
                writer=writer,
                mtu=session.get("download_mtu", 50),
                logger=self.logger,
                window_size=self.arq_window_size,
                rto=self.arq_initial_rto,
                max_rto=self.arq_max_rto,
                enable_control_reliability=True,
                control_rto=self.arq_control_initial_rto,
                control_max_rto=self.arq_control_max_rto,
                control_max_retries=self.arq_control_max_retries,
            )

            stream_data["arq_obj"] = stream
            stream_data["status"] = "CONNECTED"

            await self._queue_and_cache_response(
                session_id,
                stream_id,
                stream_data,
                "stream",
                packet_type=Packet_Type.STREAM_SYN_ACK,
                payload=b"",
                priority=2,
                sequence_num=syn_sn,
            )
            self.logger.debug(
                f"<green>Stream <cyan>{stream_id}</cyan> connected to Forward Target: <blue>{self.forward_ip}:{self.forward_port}</blue> for Session <cyan>{session_id}</cyan></green>"
            )
        except Exception as e:
            self.logger.error(
                f"<red>Failed to connect to forward target for stream <cyan>{stream_id}</cyan> for Session <cyan>{session_id}</cyan>: {e}</red>"
            )
            await self.close_stream(
                session_id,
                stream_id,
                reason=f"Connection Error: {e}, Session {session_id}, Stream {stream_id}",
                abortive=True,
            )

    async def _server_retransmit_loop(self):
        """Background task to handle ARQ retransmissions for all active streams (Crash-Proof)."""
        while not self.should_stop.is_set():
            try:
                sessions = self.sessions
                sleep_interval = 0.5 if sessions else 1.5
                await asyncio.sleep(sleep_interval)
                now = time.monotonic()
                for session_id, session in list(sessions.items()):
                    streams = session.get("streams", {})
                    if not streams:
                        continue

                    for sid in list(streams.keys()):
                        stream_data = streams.get(sid)
                        if not stream_data:
                            continue
                        status = stream_data.get("status")
                        last_act = stream_data.get("last_activity", now)
                        close_time = stream_data.get("close_time", now)

                        if status in (
                            "CONNECTING",
                            "SOCKS_HANDSHAKE",
                            "SOCKS_CONNECTING",
                        ):
                            if (now - last_act) > self.socks_handshake_timeout:
                                await self.close_stream(
                                    session_id,
                                    sid,
                                    reason="Handshake/connect timeout",
                                    abortive=True,
                                )
                            continue

                        if status == "TIME_WAIT":
                            arq_obj = stream_data.get("arq_obj")
                            control_reliable = bool(
                                arq_obj
                                and getattr(
                                    arq_obj, "enable_control_reliability", False
                                )
                            )

                            rst_sent = (
                                getattr(arq_obj, "_rst_sent", False)
                                if arq_obj
                                else stream_data.get("rst_sent", False)
                            )
                            rst_acked = (
                                getattr(arq_obj, "_rst_acked", False)
                                if arq_obj
                                else stream_data.get("rst_acked", False)
                            )
                            rst_received = (
                                getattr(arq_obj, "_rst_received", False)
                                if arq_obj
                                else False
                            )

                            if (now - close_time) > 45.0:
                                streams.pop(sid, None)

                            elif (
                                not control_reliable
                                and rst_sent
                                and not rst_acked
                                and (now - last_act) > 1.5
                                and stream_data.get("rst_retries", 0) < 10
                            ):
                                stream_data["last_activity"] = now
                                stream_data["rst_retries"] = (
                                    stream_data.get("rst_retries", 0) + 1
                                )

                                rst_sn = (
                                    getattr(arq_obj, "_rst_seq_sent", None)
                                    if arq_obj
                                    else stream_data.get("rst_seq_sent", 0)
                                )

                                if rst_sn is not None:
                                    await self._enqueue_packet(
                                        session_id,
                                        0,
                                        sid,
                                        rst_sn,
                                        Packet_Type.STREAM_RST,
                                        b"",
                                    )

                            elif (
                                not control_reliable
                                and not rst_sent
                                and not rst_received
                                and not (
                                    arq_obj and getattr(arq_obj, "_fin_acked", False)
                                )
                                and (now - last_act) > 3.0
                                and stream_data.get("fin_retries", 0) < 15
                            ):
                                stream_data["last_activity"] = now
                                stream_data["fin_retries"] = (
                                    stream_data.get("fin_retries", 0) + 1
                                )

                                fin_sn = 0
                                if (
                                    arq_obj
                                    and getattr(arq_obj, "_fin_seq_sent", None)
                                    is not None
                                ):
                                    fin_sn = arq_obj._fin_seq_sent

                                await self._enqueue_packet(
                                    session_id,
                                    1,
                                    sid,
                                    fin_sn,
                                    Packet_Type.STREAM_FIN,
                                    b"",
                                )

                    closed_ids = [
                        sid
                        for sid, sdata in streams.items()
                        if sdata.get("arq_obj")
                        and getattr(sdata["arq_obj"], "closed", False)
                        and sdata.get("status") not in ("TIME_WAIT", "CLOSING")
                    ]

                    for sid in closed_ids:
                        try:
                            stream_data = streams.get(sid, {})
                            arq_obj = stream_data.get("arq_obj")
                            real_reason = getattr(
                                arq_obj, "close_reason", "Unknown ARQ Error"
                            )
                            abortive = False
                            if arq_obj:
                                abortive = bool(
                                    getattr(arq_obj, "_rst_sent", False)
                                    or getattr(arq_obj, "_rst_received", False)
                                )

                            await self.close_stream(
                                session_id,
                                sid,
                                reason=f"Marked Closed by ARQStream ({real_reason})",
                                abortive=abortive,
                            )
                        except Exception as e:
                            self.logger.debug(
                                f"Error closing stream {sid} during retransmit check: {e}"
                            )
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.debug(f"Unexpected error in retransmit loop: {e}")
                await asyncio.sleep(0.5)

    # ---------------------------------------------------------
    # App Lifecycle
    # ---------------------------------------------------------
    async def start(self) -> None:
        """Initialize sockets, start background tasks, and wait for shutdown signal."""
        try:
            self.logger.info("<magenta>MasterDnsVPN Server starting ...</magenta>")
            self.loop = asyncio.get_running_loop()

            host = self.config.get("UDP_HOST", "0.0.0.0")
            port = int(self.config.get("UDP_PORT", 53))

            self.logger.debug("Binding UDP socket ...")
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            buffer_size = int(self.config.get("SOCKET_BUFFER_SIZE", 8388608))
            try:
                self.udp_sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_RCVBUF, buffer_size
                )
                self.udp_sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_SNDBUF, buffer_size
                )
            except OSError:
                new_size = 65535
                self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, new_size)

            try:
                self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except Exception:
                pass

            self.udp_sock.bind((host, port))

            self.logger.info(
                f"<green>UDP socket bound on <blue>{host}:{port}</blue></green>"
            )
            self.logger.info(
                f"<green>Runtime CPU cores detected: <cyan>{os.cpu_count() or 1}</cyan> | MAX_CONCURRENT_REQUESTS: <cyan>{int(self.config.get('MAX_CONCURRENT_REQUESTS', 1000))}</cyan></green>"
            )
            if self.cpu_worker_threads > 0:
                self.cpu_executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=self.cpu_worker_threads,
                    thread_name_prefix="mdns-cpu",
                )
                self.logger.info(
                    f"<green>CPU worker threads enabled: <cyan>{self.cpu_worker_threads}</cyan></green>"
                )
            else:
                self.logger.info("<yellow>CPU worker threads disabled.</yellow>")

            if sys.platform == "win32":
                try:
                    sio_udp_connreset = getattr(socket, "SIO_UDP_CONNRESET", 0x9800000C)
                    if hasattr(self.udp_sock, "ioctl"):
                        self.udp_sock.ioctl(sio_udp_connreset, 0)
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

            self._dns_task = self.loop.create_task(self.handle_dns_requests())
            self._session_cleanup_task = self.loop.create_task(
                self._session_cleanup_loop()
            )

            self._retransmit_task = self.loop.create_task(
                self._server_retransmit_loop()
            )
            self.logger.info("<green>MasterDnsVPN Server started successfully.</green>")
            try:
                await self.should_stop.wait()
            except asyncio.CancelledError:
                pass

            await self.stop()
        except Exception as e:
            self.logger.exception(
                f"<red>Failed to start MasterDnsVPN Server: {e}</red>"
            )
            await self.stop()

    async def stop(self) -> None:
        """Signal the server to stop."""
        self.should_stop.set()

        bg_snapshot = list(self._background_tasks)
        for task in bg_snapshot:
            if not task.done():
                task.cancel()
        if bg_snapshot:
            try:
                await asyncio.gather(*bg_snapshot, return_exceptions=True)
            except Exception:
                pass
        self._background_tasks.clear()

        for task_name in ["_retransmit_task", "_dns_task", "_session_cleanup_task"]:
            task = getattr(self, task_name, None)
            if task and not task.done():
                task.cancel()

        session_ids = list(self.sessions.keys())
        close_tasks = [self._close_session(sid) for sid in session_ids]
        if close_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*close_tasks, return_exceptions=True), timeout=3.0
                )
            except Exception:
                pass

        if self.udp_sock:
            try:
                self.udp_sock.close()
            except Exception:
                pass
        if self.cpu_executor:
            try:
                self.cpu_executor.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass
            self.cpu_executor = None

        self.logger.info("<magenta>MasterDnsVPN Server stopped.</magenta>")
        os._exit(0)

    def _signal_handler(self, signum, frame=None):
        """
        Handle termination signals for graceful shutdown.
        """
        self.logger.info(
            f"<red>Received signal {signum}, shutting down MasterDnsVPN Server ...</red>"
        )

        try:
            if self.loop:
                asyncio.run_coroutine_threadsafe(self.stop(), self.loop)
            else:
                asyncio.run(self.stop())
        except Exception:
            os._exit(0)
            pass

        self.logger.info("<yellow>Shutdown signalled.</yellow>")


def main():
    server = MasterDnsVPNServer()
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
                signal.SIGINT, lambda: server._signal_handler(signal.SIGINT, None)
            )
        except Exception:
            try:
                signal.signal(signal.SIGINT, server._signal_handler)
            except Exception:
                pass

        try:
            loop.add_signal_handler(
                signal.SIGTERM, lambda: server._signal_handler(signal.SIGTERM, None)
            )
        except Exception:
            try:
                signal.signal(signal.SIGTERM, server._signal_handler)
            except Exception:
                pass

        if sys.platform == "win32":
            try:
                from ctypes import wintypes

                HandlerRoutine = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)

                def _console_handler(dwCtrlType):
                    try:
                        server._signal_handler(dwCtrlType, None)
                    except Exception:
                        pass
                    return True

                c_handler = HandlerRoutine(_console_handler)
                ctypes.windll.kernel32.SetConsoleCtrlHandler(c_handler, True)
            except Exception:
                pass

        try:
            loop.run_until_complete(server.start())
        except KeyboardInterrupt:
            try:
                server._signal_handler(signal.SIGINT, None)
            except Exception:
                pass
            print("\nServer stopped by user (Ctrl+C). Goodbye!")
            return
    except KeyboardInterrupt:
        print("\nServer stopped by user (Ctrl+C). Goodbye!")
    except Exception as e:
        print(f"{e}")

    try:
        os._exit(0)
    except Exception as e:
        print(f"Error while stopping the server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
