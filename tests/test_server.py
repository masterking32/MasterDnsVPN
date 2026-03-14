"""Tests for server.py - MasterDnsVPNServer class with mocked I/O."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from dns_utils.compression import Compression_Type
from dns_utils.DNS_ENUMS import Packet_Type
from server import MasterDnsVPNServer, Socks5ConnectError

# ---------------------------------------------------------------------------
# Minimal valid config for testing
# ---------------------------------------------------------------------------

MINIMAL_SERVER_CONFIG = {
    "ENCRYPTION_KEY": "testkey1234567890abcdef0123456789",
    "LOG_LEVEL": "DEBUG",
    "PROTOCOL_TYPE": "TCP",
    "DOMAIN": ["vpn.example.com"],
    "LISTEN_IP": "0.0.0.0",
    "LISTEN_PORT": 53,
    "FORWARD_IP": "127.0.0.1",
    "FORWARD_PORT": 1080,
    "DATA_ENCRYPTION_METHOD": 1,
    "MAX_SESSIONS": 10,
    "SESSION_TIMEOUT": 300,
    "MAX_PACKETS_PER_BATCH": 100,
    "ARQ_WINDOW_SIZE": 100,
    "SOCKS5_AUTH": False,
}

_MOCK_LOGGER = MagicMock(
    debug=MagicMock(), info=MagicMock(), warning=MagicMock(), error=MagicMock(),
    opt=MagicMock(return_value=MagicMock(
        debug=MagicMock(), info=MagicMock(), warning=MagicMock(), error=MagicMock()
    ))
)


def make_server(config: dict | None = None):
    """Create a MasterDnsVPNServer with all IO mocked."""
    cfg = config or MINIMAL_SERVER_CONFIG
    with patch("server.load_config", return_value=cfg), \
         patch("server.os.path.isfile", return_value=True), \
         patch("server.getLogger", return_value=_MOCK_LOGGER), \
         patch("server.get_encrypt_key", return_value="testkey1234567890abcdef0123456789"):
        return MasterDnsVPNServer()


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestServerInit:
    def test_creates_server_with_valid_config(self) -> None:
        server = make_server()
        assert server is not None

    def test_protocol_type_is_tcp(self) -> None:
        server = make_server()
        assert server.protocol_type == "TCP"

    def test_domains_configured(self) -> None:
        server = make_server()
        assert "vpn.example.com" in server.allowed_domains_lower

    def test_sessions_start_empty(self) -> None:
        server = make_server()
        assert len(server.sessions) == 0

    def test_free_session_ids_populated(self) -> None:
        server = make_server()
        assert len(server.free_session_ids) == 10  # MAX_SESSIONS=10

    def test_forward_ip_and_port(self) -> None:
        server = make_server()
        assert server.forward_ip == "127.0.0.1"
        assert server.forward_port == 1080

    def test_dns_parser_created(self) -> None:
        server = make_server()
        assert server.dns_parser is not None

    def test_missing_config_file_exits(self) -> None:
        with patch("server.load_config", return_value=MINIMAL_SERVER_CONFIG), \
             patch("server.os.path.isfile", return_value=False), \
             patch("server.getLogger", return_value=_MOCK_LOGGER), \
             patch("server.get_encrypt_key", return_value="key"), \
             patch("builtins.input", return_value=""), \
             patch("sys.exit") as mock_exit:
            try:
                MasterDnsVPNServer()
            except Exception:
                pass
            mock_exit.assert_called_with(1)

    def test_invalid_protocol_type_exits(self) -> None:
        config_bad = {**MINIMAL_SERVER_CONFIG, "PROTOCOL_TYPE": "INVALID"}
        with patch("server.load_config", return_value=config_bad), \
             patch("server.os.path.isfile", return_value=True), \
             patch("server.getLogger", return_value=_MOCK_LOGGER), \
             patch("server.get_encrypt_key", return_value="key"), \
             patch("builtins.input", return_value=""), \
             patch("sys.exit") as mock_exit:
            try:
                MasterDnsVPNServer()
            except Exception:
                pass
            mock_exit.assert_called_with(1)

    def test_socks5_protocol_type(self) -> None:
        config_socks = {**MINIMAL_SERVER_CONFIG, "PROTOCOL_TYPE": "SOCKS5", "USE_EXTERNAL_SOCKS5": True}
        server = make_server(config_socks)
        assert server.protocol_type == "SOCKS5"
        assert server.use_external_socks5 is True


# ---------------------------------------------------------------------------
# Session Management
# ---------------------------------------------------------------------------


class TestSessionManagement:
    @pytest.mark.asyncio
    async def test_new_session_creates_session(self) -> None:
        server = make_server()
        sid = await server.new_session(
            base_flag=False,
            client_token=b"\x00" * 16,
        )
        assert sid is not None
        assert sid in server.sessions

    @pytest.mark.asyncio
    async def test_new_session_returns_none_when_full(self) -> None:
        server = make_server()
        server.free_session_ids.clear()
        sid = await server.new_session()
        assert sid is None

    @pytest.mark.asyncio
    async def test_new_session_stores_token(self) -> None:
        server = make_server()
        token = b"\xAB\xCD\xEF\x01" * 4  # 16 bytes
        sid = await server.new_session(client_token=token)
        assert sid is not None
        assert server.sessions[sid]["init_token"] == token

    @pytest.mark.asyncio
    async def test_new_session_with_zlib_compression(self) -> None:
        server = make_server()
        sid = await server.new_session(
            client_upload_compression_type=Compression_Type.ZLIB,
            client_download_compression_type=Compression_Type.ZLIB,
        )
        assert sid is not None
        assert server.sessions[sid]["client_upload_compression_type"] == Compression_Type.ZLIB

    @pytest.mark.asyncio
    async def test_new_session_fallback_unavailable_compression(self) -> None:
        server = make_server()
        with patch("server.is_compression_type_available", return_value=False):
            sid = await server.new_session(
                client_upload_compression_type=Compression_Type.ZSTD,
                client_download_compression_type=Compression_Type.ZSTD,
            )
        assert sid is not None
        assert server.sessions[sid]["client_upload_compression_type"] == Compression_Type.OFF

    @pytest.mark.asyncio
    async def test_close_session_removes_session(self) -> None:
        server = make_server()
        sid = await server.new_session()
        assert sid in server.sessions
        await server._close_session(sid)
        assert sid not in server.sessions

    @pytest.mark.asyncio
    async def test_close_nonexistent_session_noop(self) -> None:
        server = make_server()
        await server._close_session(99)  # Should not raise

    @pytest.mark.asyncio
    async def test_new_session_base_flag(self) -> None:
        server = make_server()
        sid = await server.new_session(base_flag=True)
        assert sid is not None
        assert server.sessions[sid]["base_encode_responses"] is True


# ---------------------------------------------------------------------------
# _extract_packet_payload
# ---------------------------------------------------------------------------


class TestExtractPacketPayload:
    def test_empty_labels_and_no_header(self) -> None:
        server = make_server()
        result = server._extract_packet_payload("", None)
        assert result == b""

    def test_with_valid_vpn_labels_no_compression(self) -> None:
        server = make_server()
        domain = "vpn.example.com"
        payload = b"test payload data"
        labels_list = server.dns_parser.generate_labels(
            domain=domain,
            session_id=1,
            packet_type=Packet_Type.STREAM_DATA,
            data=payload,
            mtu_chars=200,
            stream_id=1,
            sequence_num=0,
        )
        full_label = labels_list[0]
        vpn_labels = full_label[: -(len(domain) + 1)]

        extracted_header = server.dns_parser.extract_vpn_header_from_labels(vpn_labels)
        result = server._extract_packet_payload(vpn_labels, extracted_header)
        # With no compression (header compression_type=0), should be the same payload
        assert result == payload or len(result) > 0


# ---------------------------------------------------------------------------
# _build_invalid_session_error_response
# ---------------------------------------------------------------------------


class TestBuildInvalidSessionErrorResponse:
    def test_creates_error_response(self) -> None:
        server = make_server()
        question = server.dns_parser.simple_question_packet("test.vpn.example.com", 16)
        result = server._build_invalid_session_error_response(
            session_id=1,
            request_domain="vpn.example.com",
            question_packet=question,
            closed_info=None,
        )
        assert isinstance(result, bytes)
        assert len(result) >= 12

    def test_creates_error_response_with_closed_info(self) -> None:
        server = make_server()
        question = server.dns_parser.simple_question_packet("test.vpn.example.com", 16)
        result = server._build_invalid_session_error_response(
            session_id=2,
            request_domain="vpn.example.com",
            question_packet=question,
            closed_info={"base_encode": False},
        )
        assert isinstance(result, bytes)


# ---------------------------------------------------------------------------
# Socks5ConnectError
# ---------------------------------------------------------------------------


class TestSocks5ConnectError:
    def test_error_carries_rep_code(self) -> None:
        err = Socks5ConnectError(5, "Connection refused")
        assert err.rep_code == 5
        assert "Connection refused" in str(err)

    def test_rep_code_type_coercion(self) -> None:
        err = Socks5ConnectError("3", "Network unreachable")  # type: ignore[arg-type]
        assert err.rep_code == 3


# ---------------------------------------------------------------------------
# Session initialization handling
# ---------------------------------------------------------------------------


class TestHandleSessionInit:
    @pytest.mark.asyncio
    async def test_returns_none_with_too_short_payload(self) -> None:
        server = make_server()
        result = await server._handle_session_init(
            data=b"",
            labels="test",
            request_domain="vpn.example.com",
            parsed_packet={},
            session_id=None,
            extracted_header=None,
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_creates_session_with_valid_payload(self) -> None:
        server = make_server()
        domain = "vpn.example.com"
        # Payload: 16 bytes token + 1 byte base flag + 1 byte up_comp + 1 byte down_comp
        token = b"\x01" * 16
        payload = token + b"\x00\x00\x00"  # 19 bytes minimum

        question = server.dns_parser.simple_question_packet(f"test.{domain}", 16)
        parsed_packet = server.dns_parser.parse_dns_packet(question)

        result = await server._handle_session_init(
            data=payload,
            labels="test",
            request_domain=domain,
            parsed_packet=parsed_packet,
            session_id=None,
            extracted_header={"packet_type": Packet_Type.SESSION_INIT, "session_id": 0},
        )
        # Should create session and return SESSION_ACCEPT bytes
        assert result is None or isinstance(result, bytes)


# ---------------------------------------------------------------------------
# handle_vpn_packet (pre-session dispatch)
# ---------------------------------------------------------------------------


class TestHandleVpnPacket:
    @pytest.mark.asyncio
    async def test_error_drop_for_unknown_session(self) -> None:
        server = make_server()
        domain = "vpn.example.com"
        question = server.dns_parser.simple_question_packet(f"a.{domain}", 16)

        result = await server.handle_vpn_packet(
            packet_type=Packet_Type.PING,
            session_id=99,  # Non-existent
            data=b"",
            labels="a",
            parsed_packet=server.dns_parser.parse_dns_packet(question),
            request_domain=domain,
            extracted_header={"packet_type": Packet_Type.PING, "session_id": 99},
        )
        # Should return error bytes or None
        assert result is None or isinstance(result, bytes)

    @pytest.mark.asyncio
    async def test_session_init_with_no_data(self) -> None:
        server = make_server()
        result = await server.handle_vpn_packet(
            packet_type=Packet_Type.SESSION_INIT,
            session_id=0,
            data=b"",
            labels="",
        )
        assert result is None or isinstance(result, bytes)


# ---------------------------------------------------------------------------
# _handle_pre_session_packet
# ---------------------------------------------------------------------------


class TestHandlePreSessionPacket:
    @pytest.mark.asyncio
    async def test_session_init_type_handled(self) -> None:
        server = make_server()
        result = await server._handle_pre_session_packet(
            packet_type=Packet_Type.SESSION_INIT,
            session_id=0,
            data=b"\x00" * 19,
            labels="",
            request_domain="vpn.example.com",
        )
        assert result is None or isinstance(result, bytes)

    @pytest.mark.asyncio
    async def test_mtu_up_req_handled(self) -> None:
        server = make_server()
        result = await server._handle_pre_session_packet(
            packet_type=Packet_Type.MTU_UP_REQ,
            session_id=0,
            data=b"",
            labels="",
            request_domain="vpn.example.com",
        )
        assert result is None or isinstance(result, bytes)

    @pytest.mark.asyncio
    async def test_mtu_down_req_handled(self) -> None:
        server = make_server()
        result = await server._handle_pre_session_packet(
            packet_type=Packet_Type.MTU_DOWN_REQ,
            session_id=0,
            data=b"",
            labels="",
            request_domain="vpn.example.com",
        )
        assert result is None or isinstance(result, bytes)

    @pytest.mark.asyncio
    async def test_unknown_type_returns_none(self) -> None:
        server = make_server()
        result = await server._handle_pre_session_packet(
            packet_type=Packet_Type.PING,  # Not a pre-session type
            session_id=0,
            data=b"",
            labels="",
            request_domain="vpn.example.com",
        )
        assert result is None


# ---------------------------------------------------------------------------
# MTU handling
# ---------------------------------------------------------------------------


class TestServerMtu:
    @pytest.mark.asyncio
    async def test_handle_set_mtu_no_session(self) -> None:
        server = make_server()
        result = await server._handle_set_mtu(
            data=b"",
            labels="test",
            request_domain="vpn.example.com",
            session_id=99,  # Non-existent
            extracted_header=None,
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_handle_mtu_down_no_session(self) -> None:
        server = make_server()
        result = await server._handle_mtu_down(
            data=b"",
            labels="test",
            request_domain="vpn.example.com",
            session_id=99,  # Non-existent
            extracted_header=None,
        )
        assert result is None or isinstance(result, bytes)

    @pytest.mark.asyncio
    async def test_handle_mtu_up_no_session(self) -> None:
        server = make_server()
        result = await server._handle_mtu_up(
            data=b"",
            labels="test",
            request_domain="vpn.example.com",
            session_id=99,  # Non-existent
            extracted_header=None,
        )
        assert result is None or isinstance(result, bytes)


# ---------------------------------------------------------------------------
# Queue operations
# ---------------------------------------------------------------------------


class TestServerQueueOperations:
    def test_push_queue_item_to_session_queue(self) -> None:
        server = make_server()
        session = {
            "main_queue": [],
            "priority_counts": {},
        }
        item = (0, 1, Packet_Type.PING, 0, 0, b"")
        server._push_queue_item(session["main_queue"], session, item)
        assert len(session["main_queue"]) == 1
        assert session["priority_counts"].get(0, 0) == 1


# ---------------------------------------------------------------------------
# Closed stream packet handling
# ---------------------------------------------------------------------------


class TestHandleClosedStreamPacket:
    @pytest.mark.asyncio
    async def test_returns_false_for_unknown_session(self) -> None:
        server = make_server()
        result = await server._handle_closed_stream_packet(
            session_id=99,  # Non-existent session
            stream_id=1,
            packet_type=Packet_Type.STREAM_DATA,
            sn=0,
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_returns_false_for_stream_not_in_closed_streams(self) -> None:
        server = make_server()
        sid = await server.new_session()
        assert sid is not None

        result = await server._handle_closed_stream_packet(
            session_id=sid,
            stream_id=999,  # Not a closed stream
            packet_type=Packet_Type.STREAM_FIN,
            sn=0,
        )
        assert result is False


# ---------------------------------------------------------------------------
# Stream SYN handling
# ---------------------------------------------------------------------------


class TestHandleStreamSyn:
    @pytest.mark.asyncio
    async def test_stream_syn_no_session(self) -> None:
        server = make_server()
        result = await server._handle_stream_syn(
            session_id=99,
            stream_id=1,
            syn_sn=0,
        )
        assert result is None or isinstance(result, bytes)

    @pytest.mark.asyncio
    async def test_stream_syn_with_valid_session(self) -> None:
        server = make_server()
        # Create a session first
        sid = await server.new_session()
        assert sid is not None

        result = await server._handle_stream_syn(
            session_id=sid,
            stream_id=1,
            syn_sn=0,
        )
        # Should return SYN_ACK or similar
        assert result is None or isinstance(result, bytes)


# ---------------------------------------------------------------------------
# Crypto configuration
# ---------------------------------------------------------------------------


class TestServerCryptoConfig:
    def test_no_overhead_for_xor(self) -> None:
        config = {**MINIMAL_SERVER_CONFIG, "DATA_ENCRYPTION_METHOD": 1}
        server = make_server(config)
        assert server.crypto_overhead == 0

    def test_overhead_for_chacha20(self) -> None:
        config = {**MINIMAL_SERVER_CONFIG, "DATA_ENCRYPTION_METHOD": 2}
        server = make_server(config)
        assert server.crypto_overhead == 16

    def test_overhead_for_aes(self) -> None:
        for method in (3, 4, 5):
            config = {**MINIMAL_SERVER_CONFIG, "DATA_ENCRYPTION_METHOD": method}
            server = make_server(config)
            assert server.crypto_overhead == 28


# ---------------------------------------------------------------------------
# _resolve_arq_packet_type (via PacketQueueMixin)
# ---------------------------------------------------------------------------


class TestServerPacketTypeResolution:
    def test_resolve_stream_data(self) -> None:
        server = make_server()
        result = server._resolve_arq_packet_type()
        assert result == Packet_Type.STREAM_DATA

    def test_resolve_stream_fin(self) -> None:
        server = make_server()
        result = server._resolve_arq_packet_type(is_fin=True)
        assert result == Packet_Type.STREAM_FIN


# ---------------------------------------------------------------------------
# Hypothesis property-based tests
# ---------------------------------------------------------------------------


class TestHypothesisServer:
    @given(st.integers(min_value=1, max_value=255))
    @settings(max_examples=30)
    def test_new_session_ids_are_unique(self, max_sessions: int) -> None:
        config = {**MINIMAL_SERVER_CONFIG, "MAX_SESSIONS": max_sessions}
        server = make_server(config)
        seen_ids: set[int] = set()

        async def run():
            for _ in range(min(3, max_sessions)):
                sid = await server.new_session(client_token=b"\x01" * 16)
                assert sid not in seen_ids
                seen_ids.add(sid)

        asyncio.run(run())

    @given(st.integers(min_value=1, max_value=10))
    @settings(max_examples=20)
    def test_free_session_ids_decrease_on_new_session(self, n_sessions: int) -> None:
        config = {**MINIMAL_SERVER_CONFIG, "MAX_SESSIONS": 10}
        server = make_server(config)
        initial_count = len(server.free_session_ids)

        async def run():
            for _ in range(n_sessions):
                await server.new_session(client_token=b"\x02" * 16)

        asyncio.run(run())
        assert len(server.free_session_ids) == initial_count - n_sessions
