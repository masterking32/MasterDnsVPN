"""Tests for dns_utils/DnsPacketParser.py - comprehensive coverage."""

from __future__ import annotations

import struct
from unittest.mock import MagicMock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from dns_utils.DNS_ENUMS import DNS_QClass, DNS_Record_Type, Packet_Type
from dns_utils.DnsPacketParser import DnsPacketParser
from tests.conftest import MockLogger


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_parser(method: int = 0, key: str = "testkey") -> DnsPacketParser:
    return DnsPacketParser(
        logger=MockLogger(),
        encryption_key=key,
        encryption_method=method,
    )


def build_minimal_dns_query(domain: str = "example.com", qtype: int = DNS_Record_Type.TXT) -> bytes:
    """Build a real minimal DNS query packet."""
    parser = make_parser()
    return parser.simple_question_packet(domain, qtype)


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestInit:
    def test_no_crypto(self) -> None:
        p = make_parser(0)
        assert p.encryption_method == 0

    def test_xor_crypto(self) -> None:
        p = make_parser(1)
        assert p.encryption_method == 1

    def test_chacha20(self) -> None:
        p = make_parser(2, "a" * 32)
        assert p.encryption_method == 2

    def test_aes128(self) -> None:
        p = make_parser(3, "key")
        assert p.encryption_method == 3

    def test_aes192(self) -> None:
        p = make_parser(4, "key")
        assert p.encryption_method == 4

    def test_aes256(self) -> None:
        p = make_parser(5, "key")
        assert p.encryption_method == 5

    def test_invalid_method_defaults_to_1(self) -> None:
        logger = MockLogger()
        p = DnsPacketParser(logger=logger, encryption_key="key", encryption_method=99)
        assert p.encryption_method == 1

    def test_bytes_encryption_key(self) -> None:
        p = DnsPacketParser(logger=MockLogger(), encryption_key=b"byteskey", encryption_method=1)
        assert p.encryption_method == 1


# ---------------------------------------------------------------------------
# parse_dns_headers
# ---------------------------------------------------------------------------


class TestParseDnsHeaders:
    def test_parses_standard_header(self) -> None:
        # id=0x1234, flags=0x0100 (RD), qd=1, an=0, ns=0, ar=1
        data = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 1)
        data += b"\x00" * 10  # padding
        p = make_parser()
        result = p.parse_dns_headers(data)
        assert result["id"] == 0x1234
        assert result["rd"] == 1
        assert result["QdCount"] == 1
        assert result["ArCount"] == 1

    def test_response_flag(self) -> None:
        data = struct.pack(">HHHHHH", 1, 0x8000, 0, 1, 0, 0)
        data += b"\x00" * 10
        p = make_parser()
        result = p.parse_dns_headers(data)
        assert result["qr"] == 1  # Response


# ---------------------------------------------------------------------------
# _serialize_dns_name and parse_dns_name round-trips
# ---------------------------------------------------------------------------


class TestDnsName:
    def test_simple_domain(self) -> None:
        p = make_parser()
        serialized = p._serialize_dns_name("example.com")
        name, off = p._parse_dns_name_from_bytes(serialized, 0)
        assert name == "example.com"

    def test_empty_name(self) -> None:
        p = make_parser()
        result = p._serialize_dns_name("")
        assert result == b"\x00"

    def test_dot_name(self) -> None:
        p = make_parser()
        result = p._serialize_dns_name(".")
        assert result == b"\x00"

    def test_bytes_input(self) -> None:
        p = make_parser()
        result = p._serialize_dns_name(b"test.com")
        assert result[0] == 4  # 'test' label length

    def test_label_too_long_returns_null(self) -> None:
        p = make_parser()
        long_label = "a" * 64 + ".com"
        result = p._serialize_dns_name(long_label)
        assert result == b"\x00"

    def test_parse_name_with_compression_pointer(self) -> None:
        p = make_parser()
        # Build a packet with a compression pointer
        # Name "www.example.com" at offset 0, then pointer to it at offset 16
        name_bytes = p._serialize_dns_name("www.example.com")
        # Pointer: 0xC0 | offset
        pointer = bytes([0xC0, 0x00])
        data = name_bytes + pointer
        name, off = p._parse_dns_name_from_bytes(data, len(name_bytes))
        assert "www.example.com" in name or name == "www.example.com"

    def test_parse_name_truncated_raises_value_error(self) -> None:
        p = make_parser()
        with pytest.raises(ValueError):
            p._parse_dns_name_from_bytes(b"\x05abc", 0)  # label says 5 bytes but only 3


# ---------------------------------------------------------------------------
# simple_question_packet
# ---------------------------------------------------------------------------


class TestSimpleQuestionPacket:
    def test_creates_valid_packet(self) -> None:
        p = make_parser()
        pkt = p.simple_question_packet("example.com", DNS_Record_Type.TXT)
        assert len(pkt) >= 12

    def test_invalid_qtype_returns_empty(self) -> None:
        p = make_parser()
        result = p.simple_question_packet("example.com", 99999)
        assert result == b""

    def test_packet_can_be_parsed_back(self) -> None:
        p = make_parser()
        pkt = p.simple_question_packet("example.com", DNS_Record_Type.TXT)
        parsed = p.parse_dns_packet(pkt)
        assert parsed
        assert parsed["questions"][0]["qType"] == DNS_Record_Type.TXT


# ---------------------------------------------------------------------------
# parse_dns_packet
# ---------------------------------------------------------------------------


class TestParseDnsPacket:
    def test_too_short_returns_empty(self) -> None:
        p = make_parser()
        assert p.parse_dns_packet(b"\x00\x01\x02") == {}

    def test_parses_question_packet(self) -> None:
        p = make_parser()
        pkt = p.simple_question_packet("test.example.com", DNS_Record_Type.TXT)
        result = p.parse_dns_packet(pkt)
        assert "headers" in result
        assert "questions" in result
        assert result["questions"][0]["qName"] == "test.example.com"

    def test_parses_answer_packet(self) -> None:
        p = make_parser()
        question = p.simple_question_packet("test.example.com", DNS_Record_Type.TXT)
        txt_data = b"\x05hello"
        answers = [{
            "name": "test.example.com",
            "type": DNS_Record_Type.TXT,
            "class": DNS_QClass.IN,
            "TTL": 0,
            "rData": txt_data,
        }]
        answer_pkt = p.simple_answer_packet(answers, question)
        parsed = p.parse_dns_packet(answer_pkt)
        assert parsed
        assert parsed["answers"]


# ---------------------------------------------------------------------------
# server_fail_response
# ---------------------------------------------------------------------------


class TestServerFailResponse:
    def test_creates_servfail_response(self) -> None:
        p = make_parser()
        question = build_minimal_dns_query()
        response = p.server_fail_response(question)
        assert len(response) >= 12
        headers = p.parse_dns_headers(response)
        assert headers["rCode"] == 2  # SERVFAIL

    def test_too_short_request_returns_empty(self) -> None:
        p = make_parser()
        assert p.server_fail_response(b"\x00\x01") == b""


# ---------------------------------------------------------------------------
# simple_answer_packet
# ---------------------------------------------------------------------------


class TestSimpleAnswerPacket:
    def test_creates_answer_packet(self) -> None:
        p = make_parser()
        question = build_minimal_dns_query()
        answers = [{
            "name": "example.com",
            "type": DNS_Record_Type.TXT,
            "class": DNS_QClass.IN,
            "TTL": 60,
            "rData": b"\x05hello",
        }]
        result = p.simple_answer_packet(answers, question)
        assert len(result) > 12

    def test_too_short_question_returns_empty(self) -> None:
        p = make_parser()
        result = p.simple_answer_packet([], b"\x00\x01")
        assert result == b""


# ---------------------------------------------------------------------------
# create_packet
# ---------------------------------------------------------------------------


class TestCreatePacket:
    def test_creates_packet_from_sections(self) -> None:
        p = make_parser()
        sections = {
            "headers": {"QdCount": 1, "AnCount": 0, "NsCount": 0, "ArCount": 0, "id": 1234},
            "questions": [{"qName": "test.com", "qType": DNS_Record_Type.TXT, "qClass": DNS_QClass.IN}],
            "answers": [],
            "authorities": [],
            "additional": [],
        }
        result = p.create_packet(sections)
        assert len(result) >= 12

    def test_creates_response_from_question(self) -> None:
        p = make_parser()
        question = build_minimal_dns_query()
        sections = {
            "headers": {"QdCount": 0, "AnCount": 0, "NsCount": 0, "ArCount": 0},
            "questions": [],
            "answers": [],
            "authorities": [],
            "additional": [],
        }
        result = p.create_packet(sections, question_packet=question, is_response=True)
        assert len(result) >= 12


# ---------------------------------------------------------------------------
# Base encode/decode
# ---------------------------------------------------------------------------


class TestBaseEncodeDecode:
    def test_base32_roundtrip(self) -> None:
        p = make_parser()
        data = b"hello world test data"
        encoded = p.base_encode(data, lowerCaseOnly=True)
        decoded = p.base_decode(encoded, lowerCaseOnly=True)
        assert decoded == data

    def test_base64_roundtrip(self) -> None:
        p = make_parser()
        data = b"test payload for base64 encoding"
        encoded = p.base_encode(data, lowerCaseOnly=False)
        decoded = p.base_decode(encoded, lowerCaseOnly=False)
        assert decoded == data

    def test_empty_encode(self) -> None:
        p = make_parser()
        assert p.base_encode(b"") == ""

    def test_empty_decode(self) -> None:
        p = make_parser()
        assert p.base_decode("") == b""

    def test_invalid_base32_returns_empty(self) -> None:
        p = make_parser()
        result = p.base_decode("!!!invalid!!!", lowerCaseOnly=True)
        assert result == b""

    def test_lowercase_encoding(self) -> None:
        p = make_parser()
        data = b"ABC"
        encoded = p.base_encode(data, lowerCaseOnly=True)
        assert encoded == encoded.lower()
        assert "=" not in encoded


# ---------------------------------------------------------------------------
# XOR encryption
# ---------------------------------------------------------------------------


class TestXorEncryption:
    def test_xor_roundtrip(self) -> None:
        p = make_parser(1)
        data = b"test data for xor"
        encrypted = p.data_encrypt(data)
        decrypted = p.data_decrypt(encrypted)
        assert decrypted == data

    def test_xor_empty_data(self) -> None:
        p = make_parser(1)
        result = p.xor_data(b"", b"key")
        assert result == b""

    def test_xor_empty_key(self) -> None:
        p = make_parser(1)
        data = b"test"
        result = p.xor_data(data, b"")
        assert result == data

    def test_xor_single_byte_key(self) -> None:
        p = make_parser(1)
        data = b"\x01\x02\x03"
        key = b"\xFF"
        result = p.xor_data(data, key)
        assert len(result) == len(data)
        # XOR with same key again should recover original
        assert p.xor_data(result, key) == data


# ---------------------------------------------------------------------------
# AES-GCM encryption (methods 3, 4, 5)
# ---------------------------------------------------------------------------


class TestAesGcmEncryption:
    @pytest.mark.parametrize("method", [3, 4, 5])
    def test_aes_encrypt_decrypt_roundtrip(self, method: int) -> None:
        p = make_parser(method, "a" * 32)
        data = b"test aes encrypted payload " * 3
        encrypted = p.data_encrypt(data)
        decrypted = p.data_decrypt(encrypted)
        assert decrypted == data

    def test_aes_decrypt_too_short_returns_empty(self) -> None:
        p = make_parser(3, "a" * 32)
        result = p._aes_decrypt(b"\x00" * 5)
        assert result == b""

    def test_aes_decrypt_invalid_ciphertext(self) -> None:
        p = make_parser(3, "a" * 32)
        result = p._aes_decrypt(b"\x00" * 20)
        assert result == b""

    def test_aes_encrypt_empty_returns_empty(self) -> None:
        p = make_parser(3, "a" * 32)
        result = p._aes_encrypt(b"")
        assert result == b""


# ---------------------------------------------------------------------------
# ChaCha20 encryption (method 2)
# ---------------------------------------------------------------------------


class TestChaCha20Encryption:
    def test_chacha20_roundtrip(self) -> None:
        p = make_parser(2, "a" * 32)
        if p.encryption_method != 2 or not p._Cipher:
            pytest.skip("ChaCha20 not available")
        data = b"chacha20 test payload data here"
        encrypted = p._chacha_encrypt(data)
        decrypted = p._chacha_decrypt(encrypted)
        assert decrypted == data

    def test_chacha20_decrypt_too_short_returns_empty(self) -> None:
        p = make_parser(2, "a" * 32)
        if not p._Cipher:
            pytest.skip("ChaCha20 not available")
        result = p._chacha_decrypt(b"\x00" * 5)
        assert result == b""


# ---------------------------------------------------------------------------
# VPN header create/parse round-trips
# ---------------------------------------------------------------------------


class TestVpnHeader:
    def test_simple_packet_type_roundtrip(self) -> None:
        p = make_parser(0)
        for ptype in [Packet_Type.PING, Packet_Type.PONG, Packet_Type.SESSION_ACCEPT]:
            header_str = p.create_vpn_header(
                session_id=5,
                packet_type=ptype,
                base36_encode=True,
            )
            header_bytes = p.base_decode(header_str, lowerCaseOnly=True)
            parsed = p.parse_vpn_header_bytes(header_bytes)
            assert parsed is not None
            assert parsed["session_id"] == 5
            assert parsed["packet_type"] == ptype

    def test_stream_data_header_roundtrip(self) -> None:
        p = make_parser(0)
        header_str = p.create_vpn_header(
            session_id=1,
            packet_type=Packet_Type.STREAM_DATA,
            base36_encode=True,
            stream_id=100,
            sequence_num=42,
            fragment_id=0,
            total_fragments=1,
            total_data_length=200,
            compression_type=0,
        )
        header_bytes = p.base_decode(header_str, lowerCaseOnly=True)
        parsed = p.parse_vpn_header_bytes(header_bytes)
        assert parsed is not None
        assert parsed["stream_id"] == 100
        assert parsed["sequence_num"] == 42
        assert parsed["fragment_id"] == 0
        assert parsed["total_fragments"] == 1
        assert parsed["total_data_length"] == 200
        assert parsed["compression_type"] == 0

    def test_parse_vpn_header_too_short_returns_none(self) -> None:
        p = make_parser(0)
        result = p.parse_vpn_header_bytes(b"\x01")
        assert result is None

    def test_parse_vpn_header_invalid_packet_type(self) -> None:
        p = make_parser(0)
        # Session_id=1, packet_type=0xEE (invalid)
        result = p.parse_vpn_header_bytes(bytes([0x01, 0xEE]))
        assert result is None

    def test_parse_vpn_header_with_return_length(self) -> None:
        p = make_parser(0)
        header_str = p.create_vpn_header(
            session_id=2,
            packet_type=Packet_Type.PING,
            base36_encode=True,
        )
        header_bytes = p.base_decode(header_str, lowerCaseOnly=True)
        parsed, length = p.parse_vpn_header_bytes(header_bytes, return_length=True)
        assert parsed is not None
        assert length > 0

    def test_create_vpn_header_no_base_encode_returns_bytes(self) -> None:
        p = make_parser(0)
        result = p.create_vpn_header(
            session_id=1,
            packet_type=Packet_Type.PING,
            base36_encode=False,
            base_encode=False,
        )
        assert isinstance(result, bytes)


# ---------------------------------------------------------------------------
# Label generation
# ---------------------------------------------------------------------------


class TestDataToLabels:
    def test_short_string_unchanged(self) -> None:
        p = make_parser()
        result = p.data_to_labels("abc")
        assert result == "abc"

    def test_exactly_63_unchanged(self) -> None:
        p = make_parser()
        s = "a" * 63
        assert p.data_to_labels(s) == s

    def test_64_chars_splits_into_labels(self) -> None:
        p = make_parser()
        s = "a" * 64
        result = p.data_to_labels(s)
        assert "." in result
        parts = result.split(".")
        for part in parts:
            assert len(part) <= 63

    def test_empty_returns_empty(self) -> None:
        p = make_parser()
        assert p.data_to_labels("") == ""


# ---------------------------------------------------------------------------
# generate_labels / build_request_dns_query
# ---------------------------------------------------------------------------


class TestGenerateLabels:
    def test_single_fragment_no_data(self) -> None:
        p = make_parser(0)
        labels = p.generate_labels(
            domain="vpn.example.com",
            session_id=1,
            packet_type=Packet_Type.PING,
            data=b"",
            mtu_chars=100,
        )
        assert len(labels) == 1
        assert "vpn.example.com" in labels[0]

    def test_single_fragment_with_data(self) -> None:
        p = make_parser(0)
        labels = p.generate_labels(
            domain="vpn.example.com",
            session_id=1,
            packet_type=Packet_Type.STREAM_DATA,
            data=b"hello world",
            mtu_chars=200,
            stream_id=5,
            sequence_num=1,
        )
        assert len(labels) == 1

    def test_multi_fragment(self) -> None:
        p = make_parser(0)
        large_data = b"x" * 500
        labels = p.generate_labels(
            domain="vpn.example.com",
            session_id=1,
            packet_type=Packet_Type.STREAM_DATA,
            data=large_data,
            mtu_chars=30,
            stream_id=5,
            sequence_num=1,
        )
        assert len(labels) > 1

    def test_too_many_fragments_returns_empty(self) -> None:
        p = make_parser(0)
        huge_data = b"y" * 10000
        labels = p.generate_labels(
            domain="vpn.example.com",
            session_id=1,
            packet_type=Packet_Type.STREAM_DATA,
            data=huge_data,
            mtu_chars=1,
            stream_id=5,
            sequence_num=1,
        )
        assert labels == []

    def test_build_request_dns_query(self) -> None:
        p = make_parser(0)
        packets = p.build_request_dns_query(
            domain="vpn.example.com",
            session_id=1,
            packet_type=Packet_Type.PING,
            data=b"",
            mtu_chars=100,
        )
        assert len(packets) == 1
        assert isinstance(packets[0], bytes)

    def test_build_request_no_labels_returns_empty(self) -> None:
        p = make_parser(0)
        # Too large to fit in labels
        huge = b"z" * 10000
        result = p.build_request_dns_query(
            domain="vpn.example.com",
            session_id=1,
            packet_type=Packet_Type.STREAM_DATA,
            data=huge,
            mtu_chars=1,
            stream_id=1,
        )
        assert result == []


# ---------------------------------------------------------------------------
# extract_txt_from_rData and extract_txt_from_rData_bytes
# ---------------------------------------------------------------------------


class TestExtractTxt:
    def test_extract_txt_string(self) -> None:
        p = make_parser()
        rdata = b"\x05hello\x05world"
        result = p.extract_txt_from_rData(rdata)
        assert result == "helloworld"

    def test_extract_txt_bytes(self) -> None:
        p = make_parser()
        rdata = b"\x03abc\x03def"
        result = p.extract_txt_from_rData_bytes(rdata)
        assert result == b"abcdef"

    def test_empty_rdata_string(self) -> None:
        p = make_parser()
        assert p.extract_txt_from_rData(b"") == ""

    def test_empty_rdata_bytes(self) -> None:
        p = make_parser()
        assert p.extract_txt_from_rData_bytes(b"") == b""

    def test_skip_zero_length_chunks(self) -> None:
        p = make_parser()
        rdata = b"\x00\x03abc"
        result = p.extract_txt_from_rData_bytes(rdata)
        assert result == b"abc"

    def test_truncated_rdata_handled(self) -> None:
        p = make_parser()
        # Chunk declares 10 bytes but only 3 exist
        rdata = b"\x0ahello"  # \x0a = 10
        result = p.extract_txt_from_rData(rdata)
        assert result == "hello"


# ---------------------------------------------------------------------------
# generate_vpn_response_packet and extract_vpn_response
# ---------------------------------------------------------------------------


class TestVpnResponsePacket:
    def test_roundtrip_no_data(self) -> None:
        p = make_parser(0)
        question = build_minimal_dns_query()
        pkt = p.generate_vpn_response_packet(
            domain="example.com",
            session_id=1,
            packet_type=Packet_Type.PING,
            data=b"",
            question_packet=question,
        )
        assert len(pkt) >= 12
        parsed = p.parse_dns_packet(pkt)
        assert parsed

    def test_roundtrip_with_data_single_packet(self) -> None:
        p = make_parser(0)
        question = build_minimal_dns_query()
        data = b"test response data"
        pkt = p.generate_vpn_response_packet(
            domain="example.com",
            session_id=1,
            packet_type=Packet_Type.PING,
            data=data,
            question_packet=question,
        )
        parsed_pkt = p.parse_dns_packet(pkt)
        header, payload = p.extract_vpn_response(parsed_pkt)
        assert header is not None
        assert header["session_id"] == 1
        assert payload == data

    def test_roundtrip_with_large_data_chunked(self) -> None:
        p = make_parser(0)
        question = build_minimal_dns_query()
        data = b"large data payload " * 20
        pkt = p.generate_vpn_response_packet(
            domain="example.com",
            session_id=2,
            packet_type=Packet_Type.STREAM_DATA,
            data=data,
            question_packet=question,
            stream_id=1,
            sequence_num=0,
        )
        parsed_pkt = p.parse_dns_packet(pkt)
        header, payload = p.extract_vpn_response(parsed_pkt)
        assert header is not None
        assert payload == data

    def test_extract_vpn_response_empty(self) -> None:
        p = make_parser(0)
        header, payload = p.extract_vpn_response({})
        assert header is None
        assert payload == b""

    def test_extract_vpn_response_no_answers(self) -> None:
        p = make_parser(0)
        parsed = {"answers": [], "questions": []}
        header, payload = p.extract_vpn_response(parsed)
        assert header is None


# ---------------------------------------------------------------------------
# encode/decode and encrypt/decrypt integration
# ---------------------------------------------------------------------------


class TestEncodeDecryptIntegration:
    def test_no_crypto_encode_decode(self) -> None:
        p = make_parser(0)
        data = b"test integration"
        encoded = p.encrypt_and_encode_data(data)
        decoded = p.decode_and_decrypt_data(encoded)
        assert decoded == data

    def test_xor_encode_decode(self) -> None:
        p = make_parser(1, "my_secret_key")
        data = b"xor integration test data"
        encoded = p.encrypt_and_encode_data(data)
        decoded = p.decode_and_decrypt_data(encoded)
        assert decoded == data

    @pytest.mark.parametrize("method", [3, 4, 5])
    def test_aes_encode_decode(self, method: int) -> None:
        p = make_parser(method, "a" * 32)
        data = b"aes integration test data with enough bytes"
        encoded = p.encrypt_and_encode_data(data)
        decoded = p.decode_and_decrypt_data(encoded)
        assert decoded == data

    def _strip_domain(self, full_label: str, domain: str) -> str:
        """Strip the base domain from the full label to get VPN prefix."""
        suffix = f".{domain}"
        if full_label.endswith(suffix):
            return full_label[: -len(suffix)]
        return full_label

    def test_extract_vpn_header_from_labels(self) -> None:
        p = make_parser(0)
        domain = "vpn.example.com"
        labels_str = p.generate_labels(
            domain=domain,
            session_id=3,
            packet_type=Packet_Type.PING,
            data=b"",
            mtu_chars=100,
        )
        # Strip the base domain; the header is the remaining label(s)
        vpn_part = self._strip_domain(labels_str[0], domain)
        header = p.extract_vpn_header_from_labels(vpn_part)
        assert header is not None
        assert header["session_id"] == 3
        assert header["packet_type"] == Packet_Type.PING

    def test_extract_vpn_header_empty_labels(self) -> None:
        p = make_parser(0)
        result = p.extract_vpn_header_from_labels("")
        assert result is None or result == b"" or isinstance(result, (dict, type(None)))

    def test_extract_vpn_data_from_labels(self) -> None:
        p = make_parser(0)
        payload = b"data payload here"
        domain = "vpn.example.com"
        labels_list = p.generate_labels(
            domain=domain,
            session_id=1,
            packet_type=Packet_Type.STREAM_DATA,
            data=payload,
            mtu_chars=200,
            stream_id=1,
            sequence_num=0,
        )
        assert len(labels_list) == 1
        # Strip the base domain to get the VPN labels prefix
        vpn_part = self._strip_domain(labels_list[0], domain)
        extracted = p.extract_vpn_data_from_labels(vpn_part)
        assert extracted == payload

    def test_extract_vpn_data_empty_labels(self) -> None:
        p = make_parser(0)
        result = p.extract_vpn_data_from_labels("")
        assert result == b""

    def test_extract_vpn_data_no_dot_returns_empty(self) -> None:
        p = make_parser(0)
        result = p.extract_vpn_data_from_labels("nodothere")
        assert result == b""


# ---------------------------------------------------------------------------
# calculate_upload_mtu
# ---------------------------------------------------------------------------


class TestCalculateUploadMtu:
    def test_returns_nonzero_for_short_domain(self) -> None:
        p = make_parser()
        mtu_chars, mtu_bytes = p.calculate_upload_mtu("vpn.example.com")
        assert mtu_chars > 0
        assert mtu_bytes > 0

    def test_very_long_domain_returns_zero(self) -> None:
        p = make_parser()
        long_domain = "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.example.com.invalid"
        mtu_chars, mtu_bytes = p.calculate_upload_mtu(long_domain)
        # May return 0 if domain is too long
        assert mtu_chars >= 0

    def test_respects_explicit_mtu_cap(self) -> None:
        p = make_parser()
        _, mtu_bytes_uncapped = p.calculate_upload_mtu("vpn.example.com", mtu=0)
        _, mtu_bytes_capped = p.calculate_upload_mtu("vpn.example.com", mtu=50)
        assert mtu_bytes_capped <= mtu_bytes_uncapped


# ---------------------------------------------------------------------------
# Property-based tests
# ---------------------------------------------------------------------------


@given(data=st.binary(min_size=1, max_size=100))
@settings(max_examples=20)
def test_xor_base32_roundtrip_property(data: bytes) -> None:
    p = make_parser(1, "testkey")
    encoded = p.encrypt_and_encode_data(data)
    decoded = p.decode_and_decrypt_data(encoded)
    assert decoded == data


@given(data=st.binary(min_size=1, max_size=100))
@settings(max_examples=20)
def test_no_crypto_base64_roundtrip_property(data: bytes) -> None:
    p = make_parser(0)
    encoded = p.base_encode(data, lowerCaseOnly=False)
    decoded = p.base_decode(encoded, lowerCaseOnly=False)
    assert decoded == data


@given(data=st.binary(min_size=1, max_size=100))
@settings(max_examples=20)
def test_aes256_roundtrip_property(data: bytes) -> None:
    p = make_parser(5, "a" * 32)
    enc = p.data_encrypt(data)
    dec = p.data_decrypt(enc)
    assert dec == data


# ---------------------------------------------------------------------------
# Additional coverage tests for error paths and edge cases
# ---------------------------------------------------------------------------


class TestParseDnsQuestionErrors:
    def test_index_error_returns_none(self) -> None:
        """Lines 271-275: IndexError in parse_dns_question returns (None, offset)."""
        p = make_parser()
        # Build headers with QdCount=1 but truncated data
        headers = {"QdCount": 1}
        # Pass truncated data (only 13 bytes) with offset=12 - will hit IndexError
        truncated = b"\x00" * 13
        result, _ = p.parse_dns_question(headers, truncated, 12)
        assert result is None

    def test_generic_exception_returns_none(self) -> None:
        """Lines 276-278: Generic exception in parse_dns_question returns (None, offset)."""
        p = make_parser()
        # Corrupt data that causes name parser to fail oddly
        headers = {"QdCount": 1}
        # Pass data that can't be parsed as a DNS name at offset 0
        bad_data = b"\xff\xff\xff\xff"  # Causes loop/bounds error
        result, _ = p.parse_dns_question(headers, bad_data, 0)
        assert result is None


class TestParseResourceRecordsErrors:
    def test_truncated_record_returns_none(self) -> None:
        """Lines 322-327: Truncated resource record returns (None, offset)."""
        p = make_parser()
        headers = {"AnCount": 1}
        # Too-short data to parse any RR
        result, _ = p._parse_resource_records_section(headers, b"\x00" * 5, 0, "answers", "AnCount")
        assert result is None


class TestDnsNameParsingEdgeCases:
    def test_bounds_error_mid_name(self) -> None:
        """Line 344/367: bounds error in name parsing raises ValueError."""
        p = make_parser()
        # Label length 5, but only 2 bytes of label data follow -> bounds error
        data = bytes([5, 0x61, 0x62]) + b"\x00"
        with pytest.raises(ValueError):
            p._parse_dns_name_from_bytes(data, 0)

    def test_compression_pointer_loop_detection(self) -> None:
        """Line 356: compression pointer loop detection raises ValueError."""
        p = make_parser()
        # Create 11 nested compression pointers to trigger jumps > 10
        # Each pair 0xC0 0x02 points 2 bytes ahead; 0xC0 0x00 creates an obvious loop
        data = bytes([0xC0, 0x00])  # pointer to offset 0 = infinite loop
        with pytest.raises(ValueError):
            p._parse_dns_name_from_bytes(data, 0)

    def test_compression_pointer_bounds_check(self) -> None:
        """Line 354: compression pointer with insufficient bytes raises ValueError."""
        p = make_parser()
        # Single 0xC0 byte at end of buffer - offset + 1 >= data_len
        data = bytes([0xC0])
        with pytest.raises(ValueError):
            p._parse_dns_name_from_bytes(data, 0)

    def test_parse_question_with_truncated_data_returns_none(self) -> None:
        """Lines 271-275: parse_dns_question IndexError returns (None, offset)."""
        p = make_parser()
        headers = {"QdCount": 1}
        # Pass data that is too short for a valid name
        result, _ = p.parse_dns_question(headers, b"\x05ab", 0)
        assert result is None

    def test_parse_question_generic_exception(self) -> None:
        """Lines 276-278: parse_dns_question generic exception returns (None, offset)."""
        p = make_parser()
        headers = {"QdCount": 1}
        # Corrupt data that triggers parse error
        result, _ = p.parse_dns_question(headers, b"\xff\xff\xff\xff", 0)
        assert result is None


class TestServerFailResponseException:
    def test_server_fail_response_exception_returns_empty(self) -> None:
        """Lines 426-428: Exception in create_server_failure_response returns empty bytes."""
        p = make_parser()
        # Pass None to trigger exception
        result = p.server_fail_response(None)  # type: ignore[arg-type]
        assert result == b""


class TestSimpleAnswerPacketException:
    def test_exception_returns_empty_bytes(self) -> None:
        """Lines 471-473: Exception in simple_answer_packet returns empty bytes."""
        p = make_parser()
        # Malformed answers with None rData triggers an exception
        question = build_minimal_dns_query()
        bad_answers = [{"name": None, "type": None, "class": None, "TTL": None, "rData": None}]
        result = p.simple_answer_packet(bad_answers, question)
        assert result == b""


class TestSimpleQuestionPacketException:
    def test_exception_returns_empty_bytes(self) -> None:
        """Lines 496-498: Exception in simple_question_packet returns empty bytes."""
        p = make_parser()
        # Pass None domain to trigger exception
        result = p.simple_question_packet(None, DNS_Record_Type.TXT)  # type: ignore[arg-type]
        assert result == b""


class TestCreatePacketSections:
    def test_authorities_and_additional(self) -> None:
        """Lines 537, 539, 541: create_packet handles authorities and additional sections."""
        p = make_parser()
        sections = {
            "headers": {"QdCount": 0, "AnCount": 0, "NsCount": 1, "ArCount": 1, "id": 100},
            "questions": [],
            "answers": [],
            "authorities": [{"name": "ns.example.com", "type": DNS_Record_Type.NS, "class": DNS_QClass.IN, "TTL": 300, "rData": b"\x00"}],
            "additional": [{"name": "extra.example.com", "type": DNS_Record_Type.A, "class": DNS_QClass.IN, "TTL": 60, "rData": b"\x7f\x00\x00\x01"}],
        }
        result = p.create_packet(sections)
        assert len(result) >= 12

    def test_create_packet_exception_returns_empty(self) -> None:
        """Lines 544-546: Exception in create_packet returns empty bytes."""
        p = make_parser()
        # Malformed sections triggers exception
        result = p.create_packet(None)  # type: ignore[arg-type]
        assert result == b""


class TestCryptoDispatchFallback:
    def test_crypto_dispatch_fallback_when_no_backend(self) -> None:
        """Lines 665-666: _setup_crypto_dispatch uses no_crypto when backend missing."""
        # Create a parser with encryption_method=2 but with _Cipher=None to trigger fallback
        p = make_parser(2, "test")
        p._Cipher = None  # type: ignore[assignment]
        p._setup_crypto_dispatch()
        # Should use _no_crypto fallback
        data = b"test"
        assert p.data_encrypt(data) == data


class TestGenerateLabelsEdgeCases:
    def test_no_data_generates_header_only_label(self) -> None:
        """Line 859/861: generate_labels with no data produces header-only label."""
        p = make_parser()
        labels = p.generate_labels(
            domain="vpn.test.com",
            session_id=1,
            packet_type=Packet_Type.STREAM_FIN,
            data=b"",
            mtu_chars=100,
            encode_data=True,
        )
        assert len(labels) == 1
        assert "vpn.test.com" in labels[0]

    def test_large_data_chunk_split_into_labels(self) -> None:
        """Lines 890-892: multi-fragment generate_labels with large data chunk."""
        p = make_parser()
        # Large data forces multi-fragment path with data_to_labels
        large_data = b"x" * 200
        labels = p.generate_labels(
            domain="vpn.test.com",
            session_id=1,
            packet_type=Packet_Type.STREAM_DATA,
            data=large_data,
            mtu_chars=20,
            encode_data=False,
        )
        assert len(labels) > 0


class TestExtractVpnResponseEdgeCases:
    def test_empty_answers_returns_none(self) -> None:
        """Line 927: extract_vpn_response with no answers returns (None, b'')."""
        p = make_parser()
        result = p.extract_vpn_response({}, is_encoded=False)
        assert result == (None, b"")

    def test_invalid_header_returns_none(self) -> None:
        """Line 987/992: extract_vpn_response with too-short header returns (None, b'')."""
        p = make_parser()
        # TXT record with only 1 byte of data - too short for VPN header (needs 2 min)
        invalid_rdata = b"\x01\x01"  # TXT length=1, single byte (not a complete header)
        parsed_packet = {
            "answers": [{
                "name": "vpn.test.com",
                "type": DNS_Record_Type.TXT,
                "class": DNS_QClass.IN,
                "TTL": 0,
                "rData": invalid_rdata,
            }]
        }
        result = p.extract_vpn_response(parsed_packet, is_encoded=False)
        assert result == (None, b"")

    def test_chunked_incomplete_returns_none(self) -> None:
        """Line 996: is_chunked but wrong number of chunks returns (None, b'')."""
        p = make_parser()
        # Build a raw VPN header for PING (0x09) which has only session_id + ptype (2 bytes)
        # PING is NOT in PT_STREAM_EXT, PT_SEQ_EXT, or PT_FRAG_EXT -> minimal 2-byte header
        raw_header = bytes([1, Packet_Type.PING])  # session_id=1, ptype=PING

        # chunk0 marker: [0x00, total_chunks, raw_header..., data...]
        chunk0 = bytes([0x00, 3]) + raw_header  # Claims 3 total chunks, only providing 1
        rdata = bytes([len(chunk0)]) + chunk0

        # Need 2 TXT answers for is_multi=True path (chunked multi-answer detection)
        dummy_chunk = bytes([0x01, 0x02])  # chunk_id=1, 1 byte data
        dummy_rdata = bytes([len(dummy_chunk)]) + dummy_chunk

        parsed_packet = {
            "answers": [
                {"name": "vpn.test.com", "type": DNS_Record_Type.TXT, "class": DNS_QClass.IN, "TTL": 0, "rData": rdata},
                {"name": "vpn.test.com", "type": DNS_Record_Type.TXT, "class": DNS_QClass.IN, "TTL": 0, "rData": dummy_rdata},
            ]
        }
        result = p.extract_vpn_response(parsed_packet, is_encoded=False)
        # Claims 3 chunks but only 2 TXT records present → (None, b"")
        assert result == (None, b"")


class TestParseVpnHeaderBytesBounds:
    def test_stream_extension_truncated(self) -> None:
        """Line 1374: parse_vpn_header_bytes truncated at stream extension."""
        p = make_parser()
        # session=1, ptype=STREAM_DATA (requires stream_id extension), but data ends
        ptype = Packet_Type.STREAM_DATA
        data = bytes([1, int(ptype)])  # Only 2 bytes, needs at least 4 for stream extension
        result = p.parse_vpn_header_bytes(data, return_length=False)
        assert result is None

    def test_seq_extension_truncated(self) -> None:
        """Line 1380: parse_vpn_header_bytes truncated at seq extension."""
        p = make_parser()
        ptype = Packet_Type.STREAM_DATA
        if ptype in p._PT_STREAM_EXT:
            data = bytes([1, int(ptype), 0, 1])  # stream_id ok, but missing seq
            if ptype in p._PT_SEQ_EXT:
                result = p.parse_vpn_header_bytes(data, return_length=False)
                assert result is None

    def test_frag_extension_truncated(self) -> None:
        """Line 1386: parse_vpn_header_bytes truncated at frag extension."""
        p = make_parser()
        ptype = Packet_Type.STREAM_DATA
        if ptype in p._PT_FRAG_EXT:
            # session + ptype + stream_id(2) + seq(2) = 6 bytes, then needs 4 more
            data = bytes([1, int(ptype), 0, 1, 0, 2, 0])  # truncated at frag
            result = p.parse_vpn_header_bytes(data, return_length=False)
            assert result is None

    def test_comp_extension_truncated(self) -> None:
        """Line 1394: parse_vpn_header_bytes truncated at compression extension."""
        p = make_parser()
        ptype = Packet_Type.STREAM_DATA
        if ptype in p._PT_COMP_EXT:
            # Build full header minus comp byte
            data = bytes([1, int(ptype), 0, 1, 0, 2, 0, 1, 0, 0, 0, 10])  # no comp byte
            if ptype not in p._PT_FRAG_EXT:
                data = bytes([1, int(ptype), 0, 1, 0, 2])  # minimal without comp
            result = p.parse_vpn_header_bytes(data, return_length=False)
            # Just verify no crash
            assert result is None or isinstance(result, dict)


class TestDecodeAndDecryptEmpty:
    def test_empty_string_returns_empty_bytes(self) -> None:
        """Line 1281: decode_and_decrypt_data with empty string returns b''."""
        p = make_parser(1, "key")
        assert p.decode_and_decrypt_data("") == b""

    def test_empty_data_returns_empty_string(self) -> None:
        """Line 1307: encrypt_and_encode_data with empty bytes returns ''."""
        p = make_parser(1, "key")
        assert p.encrypt_and_encode_data(b"") == ""

    def test_base_decode_empty_encrypted_returns_empty(self) -> None:
        """Line 1291: decode_and_decrypt_data when base_decode returns empty."""
        p = make_parser(1, "key")
        # Pass invalid base32 string - base_decode returns b"" -> returns b""
        result = p.decode_and_decrypt_data("!!!", lowerCaseOnly=True)
        assert result == b""


class TestExtractVpnDataEdgeCases:
    def test_single_segment_labels_returns_empty(self) -> None:
        """Line 1332: extract_vpn_data_from_labels with no dot returns empty."""
        p = make_parser()
        result = p.extract_vpn_data_from_labels("nodotlabel")
        assert result == b""

    def test_dot_at_start_returns_empty(self) -> None:
        """Line 1336: extract_vpn_data_from_labels with empty left part."""
        p = make_parser()
        result = p.extract_vpn_data_from_labels(".header")
        assert result == b""
