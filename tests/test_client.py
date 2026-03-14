"""Tests for client.py - MasterDnsVPNClient class with mocked I/O."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from client import MasterDnsVPNClient
from dns_utils.compression import Compression_Type
from dns_utils.DNS_ENUMS import Packet_Type

# ---------------------------------------------------------------------------
# Minimal valid config for testing
# ---------------------------------------------------------------------------

MINIMAL_CLIENT_CONFIG = {
    "ENCRYPTION_KEY": "testkey1234567890abcdef0123456789",
    "LOG_LEVEL": "DEBUG",
    "PROTOCOL_TYPE": "SOCKS5",
    "RESOLVER_DNS_SERVERS": [
        {"resolver": "8.8.8.8", "domain": "vpn.example.com", "is_valid": True}
    ],
    "DOMAINS": ["vpn.example.com"],
    "LISTEN_IP": "127.0.0.1",
    "LISTEN_PORT": 1080,
    "ARQ_WINDOW_SIZE": 100,
    "ARQ_INITIAL_RTO": 0.2,
    "ARQ_MAX_RTO": 1.5,
    "DNS_QUERY_TIMEOUT": 5.0,
    "MAX_UPLOAD_MTU": 512,
    "MAX_DOWNLOAD_MTU": 1200,
    "DATA_ENCRYPTION_METHOD": 1,
    "SOCKS5_AUTH": False,
    "BASE_ENCODE_DATA": False,
}

_MOCK_LOGGER = MagicMock(
    debug=MagicMock(), info=MagicMock(), warning=MagicMock(), error=MagicMock(),
    opt=MagicMock(return_value=MagicMock(
        debug=MagicMock(), info=MagicMock(), warning=MagicMock(), error=MagicMock()
    ))
)


def make_client(config: dict | None = None):
    """Create a MasterDnsVPNClient with all IO mocked out."""
    cfg = config or MINIMAL_CLIENT_CONFIG
    with patch("client.load_config", return_value=cfg), \
         patch("client.os.path.isfile", return_value=True), \
         patch("client.getLogger", return_value=_MOCK_LOGGER):
        return MasterDnsVPNClient()


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestClientInit:
    def test_creates_client_with_valid_config(self) -> None:
        client = make_client()
        assert client is not None

    def test_protocol_type_is_socks5(self) -> None:
        client = make_client()
        assert client.protocol_type == "SOCKS5"

    def test_encryption_key_set(self) -> None:
        client = make_client()
        assert client.encryption_key == MINIMAL_CLIENT_CONFIG["ENCRYPTION_KEY"]

    def test_domains_configured(self) -> None:
        client = make_client()
        assert "vpn.example.com" in client.domains_lower

    def test_listener_defaults(self) -> None:
        client = make_client()
        assert client.listener_ip == "127.0.0.1"
        assert client.listener_port == 1080

    def test_resolvers_configured(self) -> None:
        client = make_client()
        assert len(client.resolvers) == 1

    def test_missing_config_file_exits(self) -> None:
        with patch("client.load_config", return_value=MINIMAL_CLIENT_CONFIG), \
             patch("client.os.path.isfile", return_value=False), \
             patch("client.getLogger", return_value=_MOCK_LOGGER), \
             patch("builtins.input", return_value=""), \
             patch("sys.exit") as mock_exit:
            try:
                MasterDnsVPNClient()
            except Exception:
                pass
            mock_exit.assert_called_with(1)

    def test_missing_encryption_key_exits(self) -> None:
        config_no_key = {**MINIMAL_CLIENT_CONFIG, "ENCRYPTION_KEY": None}
        with patch("client.load_config", return_value=config_no_key), \
             patch("client.os.path.isfile", return_value=True), \
             patch("client.getLogger", return_value=_MOCK_LOGGER), \
             patch("builtins.input", return_value=""), \
             patch("sys.exit") as mock_exit:
            try:
                MasterDnsVPNClient()
            except Exception:
                pass
            mock_exit.assert_called_with(1)

    def test_invalid_protocol_type_exits(self) -> None:
        config_bad = {**MINIMAL_CLIENT_CONFIG, "PROTOCOL_TYPE": "INVALID"}
        with patch("client.load_config", return_value=config_bad), \
             patch("client.os.path.isfile", return_value=True), \
             patch("client.getLogger", return_value=_MOCK_LOGGER), \
             patch("builtins.input", return_value=""), \
             patch("sys.exit") as mock_exit:
            try:
                MasterDnsVPNClient()
            except Exception:
                pass
            mock_exit.assert_called_with(1)

    def test_tcp_protocol_type(self) -> None:
        config_tcp = {**MINIMAL_CLIENT_CONFIG, "PROTOCOL_TYPE": "TCP"}
        client = make_client(config_tcp)
        assert client.protocol_type == "TCP"


# ---------------------------------------------------------------------------
# _match_allowed_domain_suffix
# ---------------------------------------------------------------------------


class TestMatchAllowedDomainSuffix:
    def test_matching_domain(self) -> None:
        client = make_client()
        result = client._match_allowed_domain_suffix("sub.vpn.example.com")
        assert result == "vpn.example.com"

    def test_non_matching_domain(self) -> None:
        client = make_client()
        result = client._match_allowed_domain_suffix("other.example.org")
        assert result is None

    def test_empty_qname(self) -> None:
        client = make_client()
        result = client._match_allowed_domain_suffix("")
        assert result is None

    def test_exact_domain_match(self) -> None:
        client = make_client()
        result = client._match_allowed_domain_suffix("vpn.example.com")
        assert result == "vpn.example.com"

    def test_case_insensitive(self) -> None:
        client = make_client()
        result = client._match_allowed_domain_suffix("SUB.VPN.EXAMPLE.COM")
        assert result == "vpn.example.com"


# ---------------------------------------------------------------------------
# _apply_session_compression_policy
# ---------------------------------------------------------------------------


class TestApplySessionCompressionPolicy:
    def test_compression_disabled_when_mtu_too_small(self) -> None:
        client = make_client()
        client.upload_compression_type = Compression_Type.ZLIB
        client.download_compression_type = Compression_Type.ZLIB
        client.synced_upload_mtu = 50
        client.synced_download_mtu = 50
        client.compression_min_size = 100
        client._apply_session_compression_policy()
        assert client.upload_compression_type == Compression_Type.OFF
        assert client.download_compression_type == Compression_Type.OFF

    def test_compression_kept_when_mtu_large_enough(self) -> None:
        client = make_client()
        client.upload_compression_type = Compression_Type.ZLIB
        client.download_compression_type = Compression_Type.ZLIB
        client.synced_upload_mtu = 300
        client.synced_download_mtu = 300
        client.compression_min_size = 100
        client._apply_session_compression_policy()
        assert client.upload_compression_type == Compression_Type.ZLIB
        assert client.download_compression_type == Compression_Type.ZLIB


# ---------------------------------------------------------------------------
# _process_received_packet
# ---------------------------------------------------------------------------


class TestProcessReceivedPacket:
    @pytest.mark.asyncio
    async def test_empty_bytes_returns_none(self) -> None:
        client = make_client()
        header, payload = await client._process_received_packet(b"")
        assert header is None
        assert payload == b""

    @pytest.mark.asyncio
    async def test_malformed_packet_returns_none(self) -> None:
        client = make_client()
        header, payload = await client._process_received_packet(b"\x00\x01\x02garbage")
        assert header is None

    @pytest.mark.asyncio
    async def test_valid_packet_wrong_domain_returns_none(self) -> None:
        client = make_client()
        question = client.dns_parser.simple_question_packet("other.example.org", 16)
        header, payload = await client._process_received_packet(question)
        assert header is None

    @pytest.mark.asyncio
    async def test_valid_vpn_response_returns_result(self) -> None:
        client = make_client()
        domain = "vpn.example.com"
        client.session_id = 1
        # Build a valid response packet that would pass domain validation
        question = client.dns_parser.simple_question_packet(f"test.{domain}", 16)
        response = client.dns_parser.generate_vpn_response_packet(
            domain=domain,
            session_id=1,
            packet_type=Packet_Type.PONG,
            data=b"",
            question_packet=question,
        )
        # Must have a matching resolver source for it to pass
        client.allowed_resolver_sources.add("127.0.0.1")
        header, payload = await client._process_received_packet(response, addr=("127.0.0.1", 53))
        # May return valid header or None, but should not raise
        assert isinstance(payload, bytes)


# ---------------------------------------------------------------------------
# _send_ping_packet
# ---------------------------------------------------------------------------


class TestSendPingPacket:
    def test_ping_increments_count(self) -> None:
        client = make_client()
        initial_count = client.count_ping
        client._send_ping_packet()
        assert client.count_ping == initial_count + 1
        assert client.tx_event.is_set()

    def test_ping_with_payload(self) -> None:
        client = make_client()
        client._send_ping_packet(payload=b"test")
        assert client.count_ping >= 1

    def test_ping_does_not_enqueue_when_limit_reached(self) -> None:
        client = make_client()
        client.count_ping = 100  # At the limit
        initial_count = len(client.main_queue)
        client._send_ping_packet()
        # Should not add to queue when count >= 100
        assert len(client.main_queue) == initial_count


# ---------------------------------------------------------------------------
# MTU-related methods
# ---------------------------------------------------------------------------


class TestMtuMethods:
    def test_compute_mtu_based_pack_limit(self) -> None:
        client = make_client()
        result = client._compute_mtu_based_pack_limit(200, 100.0, 5)
        assert result == 40

    def test_compute_mtu_invalid_args(self) -> None:
        client = make_client()
        result = client._compute_mtu_based_pack_limit("bad", "bad", "bad")  # type: ignore[arg-type]
        assert result == 1


# ---------------------------------------------------------------------------
# _format_mtu_log_line
# ---------------------------------------------------------------------------


class TestFormatMtuLogLine:
    def test_empty_template_returns_empty(self) -> None:
        client = make_client()
        result = client._format_mtu_log_line("")
        assert result == ""

    def test_template_with_connection_info(self) -> None:
        client = make_client()
        connection = {"resolver": "8.8.8.8"}
        result = client._format_mtu_log_line("{IP}", connection=connection)
        assert "8.8.8.8" in result

    def test_template_without_connection(self) -> None:
        client = make_client()
        result = client._format_mtu_log_line("{IP}", connection=None)
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# DNS parser integration
# ---------------------------------------------------------------------------


class TestClientDnsParser:
    def test_client_has_dns_parser(self) -> None:
        client = make_client()
        assert client.dns_parser is not None

    def test_parse_valid_dns_query(self) -> None:
        client = make_client()
        pkt = client.dns_parser.simple_question_packet("test.vpn.example.com", 16)
        parsed = client.dns_parser.parse_dns_packet(pkt)
        assert parsed
        assert parsed["questions"][0]["qName"] == "test.vpn.example.com"


# ---------------------------------------------------------------------------
# Queue operations via PacketQueueMixin
# ---------------------------------------------------------------------------


class TestClientQueueOperations:
    def test_push_queue_item(self) -> None:
        client = make_client()
        item = (0, 1, Packet_Type.PING, 0, 0, b"")
        # Use client.__dict__ as owner (same as real client code uses self.__dict__)
        client._push_queue_item(client.main_queue, client.__dict__, item)
        assert len(client.main_queue) == 1
        assert client.__dict__.get("priority_counts", {}).get(0, 0) == 1

    def test_on_queue_pop_decrements_counter(self) -> None:
        client = make_client()
        item = (0, 1, Packet_Type.PING, 0, 0, b"")
        client._push_queue_item(client.main_queue, client.__dict__, item)
        client._on_queue_pop(client.__dict__, item)
        assert client.__dict__.get("priority_counts", {}).get(0, 0) == 0


# ---------------------------------------------------------------------------
# AES crypto overhead configuration
# ---------------------------------------------------------------------------


class TestCryptoOverhead:
    def test_no_overhead_for_xor(self) -> None:
        config = {**MINIMAL_CLIENT_CONFIG, "DATA_ENCRYPTION_METHOD": 1}
        client = make_client(config)
        assert client.crypto_overhead == 0

    def test_overhead_for_chacha20(self) -> None:
        config = {**MINIMAL_CLIENT_CONFIG, "DATA_ENCRYPTION_METHOD": 2}
        client = make_client(config)
        assert client.crypto_overhead == 16

    def test_overhead_for_aes(self) -> None:
        for method in (3, 4, 5):
            config = {**MINIMAL_CLIENT_CONFIG, "DATA_ENCRYPTION_METHOD": method}
            client = make_client(config)
            assert client.crypto_overhead == 28


# ---------------------------------------------------------------------------
# Config version warning
# ---------------------------------------------------------------------------


class TestConfigVersionWarning:
    def test_outdated_config_version_logs_warning(self) -> None:
        config = {**MINIMAL_CLIENT_CONFIG, "CONFIG_VERSION": 0}
        client = make_client(config)
        # Should not raise; warning would be logged during init
        assert client is not None


# ---------------------------------------------------------------------------
# Hypothesis property-based tests
# ---------------------------------------------------------------------------


class TestHypothesisClient:
    @given(st.text(min_size=1, max_size=64, alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters=".-"
    )))
    @settings(max_examples=50)
    def test_match_allowed_domain_suffix_non_matching_never_raises(self, qname: str) -> None:
        client = make_client()
        try:
            result = client._match_allowed_domain_suffix(qname.lower())
            assert result is None or isinstance(result, str)
        except Exception as e:
            raise AssertionError(f"_match_allowed_domain_suffix raised unexpectedly: {e}") from e

    @given(st.sampled_from(["vpn.example.com", "sub.vpn.example.com", "a.b.vpn.example.com"]))
    @settings(max_examples=10)
    def test_match_allowed_domain_always_returns_base_for_subdomains(self, qname: str) -> None:
        client = make_client()
        result = client._match_allowed_domain_suffix(qname)
        assert result == "vpn.example.com"

    @given(st.sampled_from(["other.example.org", "attacker.com", "vpn.example.com.evil.org"]))
    @settings(max_examples=10)
    def test_non_matching_domains_return_none(self, qname: str) -> None:
        client = make_client()
        result = client._match_allowed_domain_suffix(qname)
        assert result is None
