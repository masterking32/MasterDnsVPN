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

        self._pre_session_packet_types = {
            Packet_Type.SESSION_INIT,
            Packet_Type.MTU_UP_REQ,
            Packet_Type.MTU_DOWN_REQ,
            Packet_Type.SET_MTU_REQ,
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
                "created_at": now,
                "last_packet_time": now,
                "init_token": client_token,
                "streams": {},
                "main_queue": [],
                "round_robin_index": 0,
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
            session.get("priority_counts", {}).clear()
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
            )

            return self.dns_parser.generate_vpn_response_packet(
                domain=request_domain,
                session_id=new_session_id,
                packet_type=Packet_Type.SESSION_ACCEPT,
                data=response_bytes,
                question_packet=data,
                encode_data=base_encode,
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
                b"FA" + os.urandom(4),
            )
            return True
        if packet_type == Packet_Type.STREAM_RST:
            await self._enqueue_packet(
                session_id,
                0,
                stream_id,
                sn,
                Packet_Type.STREAM_RST_ACK,
                b"RA" + os.urandom(4),
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
                b"RS" + os.urandom(4),
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
        if not (stream_data and stream_data.get("status") == "CONNECTED"):
            return

        stream_data["last_activity"] = now_mono
        arq = stream_data.get("arq_obj")
        if not arq:
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
        if not (stream_data and stream_data.get("status") == "CONNECTED"):
            return

        stream_data["last_activity"] = now_mono
        arq = stream_data.get("arq_obj")
        if arq:
            await arq.receive_ack(sn)

    async def _handle_stream_syn_packet(
        self, session_id, stream_id, sn, labels, extracted_header, now_mono
    ):
        """Handle STREAM_SYN packets without blocking current response."""
        if self.loop:
            self._spawn_background_task(
                self._handle_stream_syn(session_id, stream_id, sn)
            )

    def _map_socks5_rep_to_packet(self, rep_code: int) -> int:
        """Map SOCKS5 REP code to Packet_Type."""
        return self._socks5_rep_packet_map.get(
            int(rep_code), Packet_Type.SOCKS5_CONNECT_FAIL
        )

    def _map_socks5_exception_to_packet(self, exc: Exception) -> int:
        """Best-effort exception to SOCKS5 result packet mapping."""
        if isinstance(exc, Socks5ConnectError):
            return self._map_socks5_rep_to_packet(exc.rep_code)

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

    async def _send_socks5_error_packet(
        self, session_id: int, stream_id: int, packet_type: int
    ) -> None:
        """Queue SOCKS5 error packet for client."""
        await self._enqueue_packet(
            session_id,
            0,
            stream_id,
            0,
            int(packet_type),
            b"",
        )

    async def _handle_socks5_syn_packet(
        self, session_id, stream_id, sn, labels, extracted_header, now_mono
    ):
        """Handle SOCKS5 SYN/target setup packets."""
        session = self.sessions.get(session_id)
        if not session:
            return

        if stream_id in session.get("closed_streams", {}):
            await self._enqueue_packet(
                session_id, 1, stream_id, 0, Packet_Type.STREAM_FIN, b""
            )
            return

        streams = session.setdefault("streams", {})
        stream_data = streams.get(stream_id)
        if not stream_data:
            now = time.monotonic()
            stream_data = {
                "stream_id": stream_id,
                "created_at": now,
                "last_activity": now,
                "status": "SOCKS_HANDSHAKE",
                "arq_obj": None,
                "tx_queue": [],
                "priority_counts": {},
                "track_ack": set(),
                "track_fin": set(),
                "track_syn_ack": set(),
                "track_data": set(),
                "track_resend": set(),
                "socks_chunks": {},
            }
            streams[stream_id] = stream_data

        stream_data["last_activity"] = now_mono

        if stream_data["status"] == "CONNECTED":
            now_ack = time.monotonic()
            last_syn_ack = stream_data.get("last_socks_syn_ack", 0.0)
            if now_ack - last_syn_ack >= 0.5:
                stream_data["last_socks_syn_ack"] = now_ack
                await self._enqueue_packet(
                    session_id, 2, stream_id, 0, Packet_Type.SOCKS5_SYN_ACK, b""
                )
            return

        if stream_data["status"] == "SOCKS_CONNECTING":
            return

        if stream_data["status"] not in ("SOCKS_HANDSHAKE", "PENDING"):
            return

        stream_data.setdefault("socks_chunks", {})
        if stream_data.get("status") == "PENDING":
            stream_data["status"] = "SOCKS_HANDSHAKE"

        frag_id = int(extracted_header.get("fragment_id", 0)) if extracted_header else 0
        expected_chunk_count = (
            int(extracted_header.get("total_fragments", 1)) if extracted_header else 1
        )
        if expected_chunk_count <= 0:
            expected_chunk_count = 1
        expected_chunk_count = min(expected_chunk_count, 64)

        if stream_data.get("socks_expected_frags") not in (None, expected_chunk_count):
            # New SOCKS5_SYN series with different fragmentation profile.
            stream_data["socks_chunks"].clear()
        stream_data["socks_expected_frags"] = expected_chunk_count

        extracted_data = self._extract_packet_payload(labels, extracted_header)
        if extracted_data and 0 <= frag_id < expected_chunk_count:
            stream_data["socks_chunks"][frag_id] = extracted_data

        chunks = stream_data["socks_chunks"]
        if 0 not in chunks:
            return

        if len(chunks) != expected_chunk_count:
            return

        if any(i not in chunks for i in range(expected_chunk_count)):
            return

        assembled = b"".join(chunks[i] for i in range(expected_chunk_count))
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
                session_id, stream_id, Packet_Type.SOCKS5_ADDRESS_TYPE_UNSUPPORTED
            )
            await self.close_stream(
                session_id, stream_id, reason="SOCKS5 address type unsupported"
            )
            return
        if len(assembled) < expected_len:
            return
        if len(assembled) > expected_len:
            assembled = assembled[:expected_len]

        stream_data["status"] = "SOCKS_CONNECTING"
        stream_data.get("socks_chunks", {}).clear()
        if self.loop:
            self._spawn_background_task(
                self._process_socks5_target(session_id, stream_id, assembled)
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
            session_id, 0, stream_id, sn, Packet_Type.STREAM_RST_ACK, b""
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
        block_tasks = []
        block_size = self._block_packer.size
        for i in range(0, len(extracted_data), block_size):
            if i + block_size > len(extracted_data):
                break
            b_ptype, b_stream_id, b_sn = _unpack_from(extracted_data, i)
            if b_ptype not in self._valid_packet_types:
                continue

            block_tasks.append(
                self._dispatch_stream_packet(
                    packet_type=b_ptype,
                    session_id=session_id,
                    stream_id=b_stream_id,
                    sn=b_sn,
                    labels="",
                    extracted_header={"packet_type": b_ptype},
                    now_mono=now_mono,
                )
            )

        for idx in range(0, len(block_tasks), 8):
            await asyncio.gather(
                *block_tasks[idx : idx + 8],
                return_exceptions=True,
            )

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
        if packet_type == Packet_Type.SET_MTU_REQ:
            return await self._handle_set_mtu(
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

    def _iter_active_response_queues(self, session: dict, streams: dict) -> list[tuple]:
        """
        Return active response queues as round-robin participants.
        stream_id 0 represents the session main queue.
        """
        queue_entries = []

        main_queue = session.get("main_queue")
        if main_queue:
            queue_entries.append((0, main_queue, session))

        for sid, stream_data in streams.items():
            if int(sid) <= 0:
                continue
            if stream_data and stream_data.get("tx_queue"):
                queue_entries.append((sid, stream_data["tx_queue"], stream_data))

        return queue_entries

    def _pack_selected_response_blocks(
        self,
        selected_idx: int,
        queue_entries: list[tuple],
        first_item: tuple,
        max_blocks: int,
    ) -> bytes:
        """
        Pack same-priority control blocks starting from the selected queue, then
        do a single pass over the remaining queues to fill the available slots.
        """
        if max_blocks <= 1:
            return b""

        target_priority = int(first_item[0])
        target_ptype = int(first_item[2])
        _pack = self._block_packer.pack
        packed_buffer = bytearray(_pack(target_ptype, first_item[3], first_item[4]))
        blocks = 1

        _, selected_queue, selected_owner = queue_entries[selected_idx]

        while blocks < max_blocks and self._owner_has_priority(
            selected_owner, target_priority
        ):
            popped = self._pop_packable_control_block(
                selected_queue,
                selected_owner,
                target_priority,
                packet_type=target_ptype,
            )
            if popped is None:
                break
            packed_buffer.extend(_pack(popped[2], popped[3], popped[4]))
            blocks += 1

        if blocks >= max_blocks:
            return bytes(packed_buffer)

        num_queues = len(queue_entries)
        for offset in range(1, num_queues):
            if blocks >= max_blocks:
                break
            _, q_ref, owner = queue_entries[(selected_idx + offset) % num_queues]
            if not self._owner_has_priority(owner, target_priority):
                continue

            while blocks < max_blocks:
                popped = self._pop_packable_control_block(
                    q_ref,
                    owner,
                    target_priority,
                    packet_type=target_ptype,
                )
                if popped is None:
                    break
                packed_buffer.extend(_pack(popped[2], popped[3], popped[4]))
                blocks += 1

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

        queue_entries = self._iter_active_response_queues(session, streams)
        if not queue_entries:
            return res_ptype, res_stream_id, res_sn, res_data

        rr_index = int(session.get("round_robin_index", 0))
        num_queues = len(queue_entries)
        if rr_index >= num_queues:
            rr_index = 0
        elif rr_index < 0:
            rr_index = 0

        selected_idx = rr_index % num_queues
        _, target_queue, pop_owner = queue_entries[selected_idx]

        item = heapq.heappop(target_queue)
        self._on_queue_pop(pop_owner, item)
        session["round_robin_index"] = (selected_idx + 1) % num_queues

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
                selected_idx=selected_idx,
                queue_entries=queue_entries,
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
        )

    async def _process_socks5_target(self, session_id, stream_id, target_payload):
        session = self.sessions.get(session_id)
        if not session:
            return
        stream_data = session.get("streams", {}).get(stream_id)
        if not stream_data:
            return

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
                if getattr(self, "use_external_socks5", False):
                    self.logger.debug(
                        f"<green>Forwarding to External SOCKS5 <blue>{self.forward_ip}:{self.forward_port}</blue> for target <cyan>{target_ip}:{target_port}</cyan> (Stream {stream_id})</green>"
                    )
                    c_reader, c_writer = await asyncio.open_connection(
                        self.forward_ip, self.forward_port
                    )

                    if self.socks5_auth:
                        c_writer.write(b"\x05\x01\x02")
                    else:
                        c_writer.write(b"\x05\x01\x00")
                    await c_writer.drain()

                    greeting_res = await c_reader.readexactly(2)
                    if greeting_res[0] != 0x05:
                        raise ValueError("Upstream proxy is not a valid SOCKS5 server")

                    if self.socks5_auth and greeting_res[1] == 0x02:
                        u_bytes = self.socks5_user.encode("utf-8")
                        p_bytes = self.socks5_pass.encode("utf-8")
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
                    self.logger.debug(
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
                logger=self.logger,
                window_size=self.arq_window_size,
                rto=float(self.config.get("ARQ_INITIAL_RTO", 0.8)),
                max_rto=float(self.config.get("ARQ_MAX_RTO", 1.5)),
                enable_control_reliability=True,
                control_rto=float(self.config.get("ARQ_CONTROL_INITIAL_RTO", 0.8)),
                control_max_rto=float(self.config.get("ARQ_CONTROL_MAX_RTO", 2.5)),
                control_max_retries=int(self.config.get("ARQ_CONTROL_MAX_RETRIES", 40)),
            )

            # SOCKS5_SYN is handled on control-plane now, so ARQ data-plane
            # sequence must start from 0 for first STREAM_DATA packet.
            arq.rcv_nxt = 0

            stream_data["arq_obj"] = arq
            stream_data["status"] = "CONNECTED"

            stream_data["last_socks_syn_ack"] = time.monotonic()
            await self._enqueue_packet(
                session_id, 2, stream_id, 0, Packet_Type.SOCKS5_SYN_ACK, b""
            )

        except Exception as e:
            err_packet = self._map_socks5_exception_to_packet(e)
            await self._send_socks5_error_packet(session_id, stream_id, err_packet)
            self.logger.debug(
                f"<red>SOCKS5 target connection failed for stream {stream_id}: {e}</red>"
            )
            await self.close_stream(
                session_id, stream_id, reason=f"SOCKS target unreachable: {e}"
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

            packet_type = extracted_header.get("packet_type")
            session_id = extracted_header.get("session_id")

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

                rst_data = b"RST:" + os.urandom(4)
                await self._enqueue_packet(
                    session_id, 0, stream_id, rst_sn, Packet_Type.STREAM_RST, rst_data
                )
            elif not abortive:
                fin_data = b"FIN:" + os.urandom(4)
                await self._enqueue_packet(
                    session_id, 1, stream_id, 0, Packet_Type.STREAM_FIN, fin_data
                )

        pending_tx = stream_data.get("tx_queue", [])
        if pending_tx:
            main_q = session.setdefault("main_queue", [])
            for item in pending_tx:
                ptype = int(item[2])
                if (
                    ptype in self._packable_control_types
                    and ptype != Packet_Type.SOCKS5_SYN
                ):
                    heapq.heappush(main_q, item)
                    self._inc_priority_counter(session, item[0])
                    self._dec_priority_counter(stream_data, item[0])

        try:
            stream_data["tx_queue"].clear()
            stream_data["track_ack"].clear()
            stream_data["track_fin"].clear()
            stream_data["track_syn_ack"].clear()
            stream_data["track_resend"].clear()
            stream_data["track_data"].clear()
            stream_data["priority_counts"].clear()
            stream_data["status"] = "TIME_WAIT"
            stream_data["close_time"] = time.monotonic()
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
        session = self.sessions.get(session_id)
        if not session:
            return

        ptype = int(packet_type)
        eff_priority = self._effective_priority_for_packet(ptype, priority)

        session["enqueue_seq"] = (session.get("enqueue_seq", 0) + 1) & 0x7FFFFFFF
        queue_item = (eff_priority, session["enqueue_seq"], ptype, stream_id, sn, data)

        if stream_id == 0:
            if not self._track_main_packet_once(session, ptype, sn):
                return
            self._push_queue_item(session["main_queue"], session, queue_item)
            return

        stream_data = session.get("streams", {}).get(stream_id)
        if not stream_data:
            if ptype in (
                Packet_Type.STREAM_RST,
                Packet_Type.STREAM_RST_ACK,
                Packet_Type.STREAM_FIN_ACK,
            ):
                self._push_queue_item(session["main_queue"], session, queue_item)
            return

        if not self._track_stream_packet_once(
            stream_data, ptype, sn, data_packet_types=(Packet_Type.STREAM_DATA,)
        ):
            return
        self._push_queue_item(stream_data["tx_queue"], stream_data, queue_item)

    async def _handle_stream_syn(self, session_id, stream_id, syn_sn=0):
        session = self.sessions.get(session_id)
        if not session:
            return

        syn_sn = int(syn_sn) & 0xFFFF

        if stream_id in session.get("closed_streams", {}):
            await self._enqueue_packet(
                session_id, 1, stream_id, 0, Packet_Type.STREAM_FIN, b""
            )
            return

        session_streams = session["streams"]

        if stream_id in session_streams:
            existing = session_streams.get(stream_id, {})
            if existing.get("status") == "CONNECTED" and existing.get("arq_obj"):
                await self._enqueue_packet(
                    session_id, 2, stream_id, syn_sn, Packet_Type.STREAM_SYN_ACK, b""
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
            "socks_chunks": {},
            "last_socks_syn_ack": 0.0,
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
                rto=float(self.config.get("ARQ_INITIAL_RTO", 0.8)),
                max_rto=float(self.config.get("ARQ_MAX_RTO", 1.5)),
                enable_control_reliability=True,
                control_rto=float(self.config.get("ARQ_CONTROL_INITIAL_RTO", 0.8)),
                control_max_rto=float(self.config.get("ARQ_CONTROL_MAX_RTO", 2.5)),
                control_max_retries=int(self.config.get("ARQ_CONTROL_MAX_RETRIES", 40)),
            )

            stream_data["arq_obj"] = stream
            stream_data["status"] = "CONNECTED"

            syn_data = b"SYA:" + os.urandom(4)
            await self._enqueue_packet(
                session_id, 2, stream_id, syn_sn, Packet_Type.STREAM_SYN_ACK, syn_data
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
                                    rst_data = b"RST:" + os.urandom(4)
                                    await self._enqueue_packet(
                                        session_id,
                                        0,
                                        sid,
                                        rst_sn,
                                        Packet_Type.STREAM_RST,
                                        rst_data,
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
                                fin_data = b"FIN:" + os.urandom(4)

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
                                    fin_data,
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
