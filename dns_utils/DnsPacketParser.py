# MasterDnsVPN
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026
import base64
import hashlib
import math
import os
import random
import struct
from typing import Any, Optional

from .DNS_ENUMS import DNS_QClass, DNS_Record_Type, Packet_Type, DNS_rCode


class DnsPacketParser:
    """
    DNS Packet Parser and Builder for VPN over DNS tunneling.
    Handles DNS packet parsing, construction, and custom VPN header encoding.
    """

    # Header extension rules:
    # - _PT_STREAM_EXT: packet carries stream_id
    # - _PT_SEQ_EXT: packet carries sequence_num (ARQ/control unification)
    # - _PT_FRAG_EXT: packet carries fragment_id

    _PT_STREAM_EXT = frozenset(
        {
            # Stream lifecycle and data
            Packet_Type.STREAM_SYN,
            Packet_Type.STREAM_SYN_ACK,
            Packet_Type.STREAM_DATA,
            Packet_Type.STREAM_DATA_ACK,
            Packet_Type.STREAM_RESEND,
            # Stream closure/reset
            Packet_Type.STREAM_FIN,
            Packet_Type.STREAM_FIN_ACK,
            Packet_Type.STREAM_RST,
            Packet_Type.STREAM_RST_ACK,
            # TCP-like stream control
            Packet_Type.STREAM_KEEPALIVE,
            Packet_Type.STREAM_KEEPALIVE_ACK,
            Packet_Type.STREAM_WINDOW_UPDATE,
            Packet_Type.STREAM_WINDOW_UPDATE_ACK,
            Packet_Type.STREAM_PROBE,
            Packet_Type.STREAM_PROBE_ACK,
            # MTU test packets that are stream-bound in parser format
            Packet_Type.MTU_UP_REQ,
            Packet_Type.MTU_DOWN_RES,
            # SOCKS handshake
            Packet_Type.SOCKS5_SYN,
            Packet_Type.SOCKS5_SYN_ACK,
            # SOCKS result/error packets
            Packet_Type.SOCKS5_CONNECT_FAIL,
            Packet_Type.SOCKS5_CONNECT_FAIL_ACK,
            Packet_Type.SOCKS5_RULESET_DENIED,
            Packet_Type.SOCKS5_RULESET_DENIED_ACK,
            Packet_Type.SOCKS5_NETWORK_UNREACHABLE,
            Packet_Type.SOCKS5_NETWORK_UNREACHABLE_ACK,
            Packet_Type.SOCKS5_HOST_UNREACHABLE,
            Packet_Type.SOCKS5_HOST_UNREACHABLE_ACK,
            Packet_Type.SOCKS5_CONNECTION_REFUSED,
            Packet_Type.SOCKS5_CONNECTION_REFUSED_ACK,
            Packet_Type.SOCKS5_TTL_EXPIRED,
            Packet_Type.SOCKS5_TTL_EXPIRED_ACK,
            Packet_Type.SOCKS5_COMMAND_UNSUPPORTED,
            Packet_Type.SOCKS5_COMMAND_UNSUPPORTED_ACK,
            Packet_Type.SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
            Packet_Type.SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
            Packet_Type.SOCKS5_AUTH_FAILED,
            Packet_Type.SOCKS5_AUTH_FAILED_ACK,
            Packet_Type.SOCKS5_UPSTREAM_UNAVAILABLE,
            Packet_Type.SOCKS5_UPSTREAM_UNAVAILABLE_ACK,
        }
    )

    _PT_SEQ_EXT = frozenset(
        {
            # Stream lifecycle and data
            Packet_Type.STREAM_SYN,
            Packet_Type.STREAM_SYN_ACK,
            Packet_Type.STREAM_DATA,
            Packet_Type.STREAM_DATA_ACK,
            Packet_Type.STREAM_RESEND,
            # Stream closure/reset
            Packet_Type.STREAM_FIN,
            Packet_Type.STREAM_FIN_ACK,
            Packet_Type.STREAM_RST,
            Packet_Type.STREAM_RST_ACK,
            # TCP-like stream control
            Packet_Type.STREAM_KEEPALIVE,
            Packet_Type.STREAM_KEEPALIVE_ACK,
            Packet_Type.STREAM_WINDOW_UPDATE,
            Packet_Type.STREAM_WINDOW_UPDATE_ACK,
            Packet_Type.STREAM_PROBE,
            Packet_Type.STREAM_PROBE_ACK,
            # MTU test packets that currently use seq in parser
            Packet_Type.MTU_UP_REQ,
            Packet_Type.MTU_DOWN_RES,
            # SOCKS handshake/data
            Packet_Type.SOCKS5_SYN,
            Packet_Type.SOCKS5_SYN_ACK,
            # SOCKS result/error packets
            Packet_Type.SOCKS5_CONNECT_FAIL,
            Packet_Type.SOCKS5_CONNECT_FAIL_ACK,
            Packet_Type.SOCKS5_RULESET_DENIED,
            Packet_Type.SOCKS5_RULESET_DENIED_ACK,
            Packet_Type.SOCKS5_NETWORK_UNREACHABLE,
            Packet_Type.SOCKS5_NETWORK_UNREACHABLE_ACK,
            Packet_Type.SOCKS5_HOST_UNREACHABLE,
            Packet_Type.SOCKS5_HOST_UNREACHABLE_ACK,
            Packet_Type.SOCKS5_CONNECTION_REFUSED,
            Packet_Type.SOCKS5_CONNECTION_REFUSED_ACK,
            Packet_Type.SOCKS5_TTL_EXPIRED,
            Packet_Type.SOCKS5_TTL_EXPIRED_ACK,
            Packet_Type.SOCKS5_COMMAND_UNSUPPORTED,
            Packet_Type.SOCKS5_COMMAND_UNSUPPORTED_ACK,
            Packet_Type.SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
            Packet_Type.SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
            Packet_Type.SOCKS5_AUTH_FAILED,
            Packet_Type.SOCKS5_AUTH_FAILED_ACK,
            Packet_Type.SOCKS5_UPSTREAM_UNAVAILABLE,
            Packet_Type.SOCKS5_UPSTREAM_UNAVAILABLE_ACK,
        }
    )

    _PT_FRAG_EXT = frozenset(
        {
            # Data-bearing / chunked payloads only
            Packet_Type.STREAM_DATA,
            Packet_Type.STREAM_RESEND,
            Packet_Type.MTU_UP_REQ,
            Packet_Type.MTU_DOWN_RES,
            Packet_Type.SOCKS5_SYN,
        }
    )

    # Every VPN header now reserves two integrity bytes:
    # - 1 byte session cookie
    # - 1 byte lightweight header check byte
    _VPN_HEADER_INTEGRITY_LEN = 2
    _PT_COMP_EXT = frozenset(
        {
            # Compress only data-heavy payloads to avoid CPU overhead on control/handshake packets.
            Packet_Type.STREAM_DATA,
            Packet_Type.STREAM_RESEND,
            Packet_Type.PACKED_CONTROL_BLOCKS,
        }
    )
    _VALID_PACKET_TYPES = frozenset(
        v for k, v in Packet_Type.__dict__.items() if not k.startswith("__")
    )

    _RR_PACKER = struct.Struct(">HHIH")
    _Q_PACKER = struct.Struct(">HH")
    _HEADER_PACKER = struct.Struct(">HHHHHH")

    # Packed control block format: packet_type(1) + stream_id(2) + sequence_num(2) = 5 bytes
    PACKED_CONTROL_BLOCK_STRUCT = struct.Struct(">BHH")
    PACKED_CONTROL_BLOCK_SIZE = PACKED_CONTROL_BLOCK_STRUCT.size

    _VALID_QTYPES = frozenset(
        v for k, v in DNS_Record_Type.__dict__.items() if not k.startswith("__")
    )

    LOG2_36 = 5

    def __init__(
        self,
        logger: Optional[Any] = None,
        encryption_key: str = "",
        encryption_method: int = 1,
    ):
        self.logger = logger
        self.encryption_key = (
            encryption_key.encode("utf-8", errors="ignore")
            if isinstance(encryption_key, str)
            else encryption_key
        )
        self.encryption_method = encryption_method
        if self.encryption_method not in (0, 1, 2, 3, 4, 5):
            self.logger.error(
                f"Invalid encryption_method value: {self.encryption_method}. Defaulting to 1 (XOR encryption)."
            )
            self.encryption_method = 1

        self.key = self._derive_key(encryption_key)
        self._aesgcm = None
        self._chacha_algo = None

        self._urandom = os.urandom
        self._Cipher = None
        self._default_backend = None

        if self.encryption_method in (3, 4, 5):
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                self._aesgcm = AESGCM(self.key)
            except ImportError:
                if self.logger:
                    self.logger.error("AES-GCM missing.")

        elif self.encryption_method == 2:
            try:
                from cryptography.hazmat.backends import default_backend
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

                self._Cipher = Cipher
                self._default_backend = default_backend
                self._chacha_algo = algorithms.ChaCha20
            except ImportError:
                pass

        self._setup_crypto_dispatch()
        self._alphabet_cache = {}
        self._int_bytes_cache = {
            i: (str(i) + ".").encode("ascii", errors="ignore") for i in range(512)
        }
        self._max_vpn_header_raw_size = max(
            self.get_vpn_header_raw_size(v)
            for k, v in Packet_Type.__dict__.items()
            if not k.startswith("__") and isinstance(v, int)
        )

    def get_vpn_header_raw_size(self, packet_type: int) -> int:
        """
        Return the raw VPN header byte length for a packet type, including the
        fixed session-cookie and header-check bytes.
        """
        size = 2
        if packet_type in self._PT_STREAM_EXT:
            size += 2
        if packet_type in self._PT_SEQ_EXT:
            size += 2
        if packet_type in self._PT_FRAG_EXT:
            size += 4
        if packet_type in self._PT_COMP_EXT:
            size += 1
        return size + self._VPN_HEADER_INTEGRITY_LEN

    def get_max_vpn_header_raw_size(self) -> int:
        """Return the largest raw VPN header size across all packet types."""
        return self._max_vpn_header_raw_size

    def _compute_header_check_byte(self, header_bytes: bytes) -> int:
        """
        Compute a lightweight 1-byte integrity check for the full raw header
        (including session cookie, excluding the check byte itself).
        """
        acc = (len(header_bytes) * 17 + 0x5D) & 0xFF
        for idx, value in enumerate(header_bytes):
            acc = (acc + value + idx) & 0xFF
            acc ^= (value << (idx & 0x03)) & 0xFF
        return acc & 0xFF

    """
    Default DNS Packet Parsers
    Methods to parse and create standard DNS packets.
    """

    def parse_dns_headers(self, data: bytes) -> dict:
        """
        Parse DNS packet headers from raw bytes.
        Returns a dictionary of header fields.
        """
        pkt_id, flags, qd, an, ns, ar = self._HEADER_PACKER.unpack_from(data, 0)

        return {
            "id": pkt_id,
            "qr": (flags >> 15) & 0x1,
            "OpCode": (flags >> 11) & 0xF,
            "aa": (flags >> 10) & 0x1,
            "tc": (flags >> 9) & 0x1,
            "rd": (flags >> 8) & 0x1,
            "ra": (flags >> 7) & 0x1,
            "z": (flags >> 4) & 0x7,
            "rCode": flags & 0xF,
            "QdCount": qd,
            "AnCount": an,
            "NsCount": ns,
            "ArCount": ar,
        }

    def parse_dns_question(self, headers: dict, data: bytes, offset: int) -> tuple:
        """
        Parse the DNS question section from the packet data.
        Returns a tuple (question_dict, new_offset).
        """
        try:
            qd_count = headers.get("QdCount", 0)
            if not qd_count:
                return None, offset

            questions = []

            _append = questions.append
            _parse_name = self._parse_dns_name_from_bytes

            for _ in range(qd_count):
                name, offset = _parse_name(data, offset)

                qType = (data[offset] << 8) | data[offset + 1]
                qClass = (data[offset + 2] << 8) | data[offset + 3]

                _append({"qName": name, "qType": qType, "qClass": qClass})

                offset += 4

            return questions, offset

        except IndexError:
            self.logger.debug(
                "Failed to parse DNS question: packet truncated (IndexError)"
            )
            return None, offset
        except Exception as e:
            self.logger.debug(f"Failed to parse DNS question: {e}")
            return None, offset

    def _parse_resource_records_section(
        self,
        headers: dict,
        data: bytes,
        offset: int,
        count_key: str,
        section_name: str = "",
    ) -> tuple:
        """
        Ultra-fast generic parser using struct unpacking from the class-level packer.
        """
        count = headers.get(count_key, 0)
        if count == 0:
            return None, offset

        records = []
        _append = records.append
        _parse_name = self._parse_dns_name_from_bytes
        _unpack_from = self._RR_PACKER.unpack_from

        try:
            for _ in range(count):
                name, offset = _parse_name(data, offset)

                r_type, r_class, ttl, rd_length = _unpack_from(data, offset)
                offset += 10

                end_rd = offset + rd_length
                r_data = data[offset:end_rd]

                _append(
                    {
                        "name": name,
                        "type": r_type,
                        "class": r_class,
                        "TTL": ttl,
                        "rData": r_data,
                    }
                )
                offset = end_rd

            return records, offset
        except (IndexError, struct.error):
            self.logger.debug(f"Failed to parse DNS {section_name}: Truncated packet.")
            return None, offset
        except Exception as e:
            self.logger.error(f"Failed to parse DNS {section_name}: {e}")
            return None, offset

    def _parse_dns_name_from_bytes(self, data: bytes, offset: int) -> tuple[str, int]:
        """
        Parse a DNS name from bytes, handling compression pointers.
        Returns (name, new_offset).
        """
        labels = []
        append = labels.append
        data_len = len(data)
        jumped = False
        jumps = 0
        orig_off = offset

        try:
            while True:
                if offset >= data_len:
                    raise ValueError("Bounds")

                length = data[offset]

                if length == 0:
                    offset += 1
                    break

                if length & 0xC0 == 0xC0:
                    if offset + 1 >= data_len:
                        raise ValueError("Bounds")
                    if jumps > 10:
                        raise ValueError("Loop")
                    if not jumped:
                        orig_off = offset + 2
                        jumped = True
                    offset = ((length & 0x3F) << 8) | data[offset + 1]
                    jumps += 1
                    continue

                offset += 1
                end = offset + length
                if end > data_len:
                    raise ValueError("Bounds")
                append(data[offset:end])
                offset = end

            return b".".join(labels).decode("utf-8", errors="ignore"), (
                orig_off if jumped else offset
            )

        except IndexError:
            raise ValueError("Bounds")

    def parse_dns_packet(self, data: bytes) -> dict:
        """
        Parse the entire DNS packet from the data.
        Returns a dictionary with all sections.
        """
        if len(data) < 12:
            return {}
        # Localize hot-path callables to reduce attribute lookups
        _parse_headers = self.parse_dns_headers
        _parse_question = self.parse_dns_question
        _parse_rr = self._parse_resource_records_section

        headers = _parse_headers(data)
        offset = 12

        questions, offset = _parse_question(headers, data, offset)
        if questions is None:
            return {}

        answers, offset = _parse_rr(headers, data, offset, "AnCount", "answer")
        authorities, offset = _parse_rr(headers, data, offset, "NsCount", "authority")
        additional, offset = _parse_rr(headers, data, offset, "ArCount", "additional")

        return {
            "headers": headers,
            "questions": questions,
            "answers": answers,
            "authorities": authorities,
            "additional": additional,
        }

    def server_fail_response(self, request_data: bytes) -> bytes:
        """
        Create a DNS Server Failure (RCODE=2) response packet based on the request data.
        """
        try:
            if len(request_data) < 12:
                return b""

            pkt_id = (request_data[0] << 8) | request_data[1]
            flags = (
                (request_data[2] << 8) | request_data[3] | 0x8000
            ) & 0xFFF0 | 0x0002
            qdcount = (request_data[4] << 8) | request_data[5]

            header = self._HEADER_PACKER.pack(pkt_id, flags, qdcount, 0, 0, 0)

            return header + request_data[12:]
        except Exception as e:
            self.logger.error(f"Failed to create Server Failure response: {e}")
            return b""

    def _basic_response_with_rcode(self, request_data: bytes, rcode: int) -> bytes:
        """
        Build a DNS response carrying the original question with no answers and the given RCODE.
        Mirrors EDNS0 presence when available.
        """
        try:
            if len(request_data) < 12:
                return b""

            pkt_id = (request_data[0] << 8) | request_data[1]
            flags = ((request_data[2] << 8) | request_data[3]) | 0x8000
            flags = (flags & 0xFFF0) | (rcode & 0xF)
            qd_count = (request_data[4] << 8) | request_data[5]
            ar_count = (request_data[10] << 8) | request_data[11]

            offset = 12
            for _ in range(qd_count):
                _, offset = self._parse_dns_name_from_bytes(request_data, offset)
                offset += 4  # Skip Type and Class

            res_ar_count = 0
            edns0_bytes = b""
            if ar_count > 0:
                edns0_bytes = b"\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00"
                res_ar_count = 1

            header = self._HEADER_PACKER.pack(
                pkt_id, flags, qd_count, 0, 0, res_ar_count
            )

            parts = [header, request_data[12:offset]]
            if edns0_bytes:
                parts.append(edns0_bytes)

            return b"".join(parts)
        except Exception as _:
            return b""

    def empty_noerror_response(self, request_data: bytes) -> bytes:
        """
        Create an empty DNS success response (NOERROR/NODATA) based on the request.
        Preserves the original question and mirrors EDNS0 presence when available.
        """
        return self._basic_response_with_rcode(request_data, DNS_rCode.NO_ERROR)

    def format_error_response(self, request_data: bytes) -> bytes:
        """
        Create a DNS Format Error response (RCODE=1).
        """
        return self._basic_response_with_rcode(request_data, DNS_rCode.FORMAT_ERROR)

    def refused_response(self, request_data: bytes) -> bytes:
        """
        Create a DNS Refused response (RCODE=5).
        """
        return self._basic_response_with_rcode(request_data, DNS_rCode.REFUSED)

    def simple_answer_packet(self, answers: list, question_packet: bytes) -> bytes:
        """
        Create a simple DNS answer packet for the given answers based on the question packet.
        answers: list of answer dicts with keys: name, type, class, TTL, rData
        """
        try:
            if len(question_packet) < 12:
                return b""

            pkt_id = (question_packet[0] << 8) | question_packet[1]
            flags = ((question_packet[2] << 8) | question_packet[3]) | 0x8000
            qd_count = (question_packet[4] << 8) | question_packet[5]

            ar_count = (question_packet[10] << 8) | question_packet[11]

            offset = 12
            for _ in range(qd_count):
                _, offset = self._parse_dns_name_from_bytes(question_packet, offset)
                offset += 4  # Skip Type and Class

            res_ar_count = 0
            edns0_bytes = b""
            if ar_count > 0:
                edns0_bytes = b"\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00"
                res_ar_count = 1

            new_header = self._HEADER_PACKER.pack(
                pkt_id, flags, qd_count, len(answers), 0, res_ar_count
            )

            parts = [new_header, question_packet[12:offset]]
            _append = parts.append
            for ans in answers:
                _append(
                    self._serialize_resource_record(ans, compress_pointer=b"\xc0\x0c")
                )

            if res_ar_count > 0:
                _append(edns0_bytes)

            return b"".join(parts)
        except Exception as e:
            self.logger.error(f"Failed to create answer packet: {e}")
            return b""

    def simple_question_packet(self, domain: str, qType: int) -> bytes:
        """
        Create a simple DNS question packet for the given domain and type with EDNS0 support.
        """
        if qType not in self._VALID_QTYPES:
            self.logger.debug(f"Invalid qType value: {qType}.")
            return b""

        try:
            pkt_id = random.getrandbits(16)

            header = self._HEADER_PACKER.pack(pkt_id, 0x0100, 1, 0, 0, 1)

            q_tail = self._Q_PACKER.pack(qType, DNS_QClass.IN)

            edns0_opt_record = b"\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00"

            return b"".join(
                (header, self._serialize_dns_name(domain), q_tail, edns0_opt_record)
            )

        except Exception as e:
            self.logger.error(f"Failed to create simple question packet: {e}")
            return b""

    def create_packet(
        self, sections: dict, question_packet: bytes = b"", is_response: bool = False
    ) -> bytes:
        """
        Create a DNS packet from the given sections for question or answer.
        sections: {
            'headers': dict,
            'questions': list,
            'answers': list,
            'authorities': list,
            'additional': list
        }
        question_packet: original packet with question section for ID and flags (optional)
        """
        try:
            h = sections.get("headers", {})
            qd, an, ns, ar = (
                int(h.get("QdCount", 0)),
                int(h.get("AnCount", 0)),
                int(h.get("NsCount", 0)),
                int(h.get("ArCount", 0)),
            )

            if question_packet and len(question_packet) >= 12:
                pkt_id = (question_packet[0] << 8) | question_packet[1]
                flags = (question_packet[2] << 8) | question_packet[3]
                if is_response:
                    flags |= 0x8000
            else:
                pkt_id, flags = int(h.get("id", 0)), 0x0100

            parts = [self._HEADER_PACKER.pack(pkt_id, flags, qd, an, ns, ar)]
            _append = parts.append

            for q in sections.get("questions", []):
                _append(self._serialize_dns_question(q))
            for a in sections.get("answers", []):
                _append(self._serialize_resource_record(a))
            for au in sections.get("authorities", []):
                _append(self._serialize_resource_record(au))
            for ad in sections.get("additional", []):
                _append(self._serialize_resource_record(ad))

            return b"".join(parts)
        except Exception as e:
            self.logger.debug(f"Failed to create DNS packet: {e}")
            return b""

    def _serialize_dns_question(self, question: dict) -> bytes:
        """
        Serialize a DNS question section to bytes.
        """
        packed_q = self._Q_PACKER.pack(int(question["qType"]), int(question["qClass"]))

        return b"".join((self._serialize_dns_name(question["qName"]), packed_q))

    def _serialize_resource_record(
        self, record: dict, compress_pointer: Optional[bytes] = None
    ) -> bytes:
        """
        Serialize a DNS resource record to bytes, with optional pointer compression.
        """
        rdata = record["rData"]

        packed_header = self._RR_PACKER.pack(
            int(record["type"]), int(record["class"]), int(record["TTL"]), len(rdata)
        )

        name_bytes = (
            compress_pointer
            if compress_pointer
            else self._serialize_dns_name(record["name"])
        )
        return b"".join((name_bytes, packed_header, rdata))

    def _serialize_dns_name(self, name) -> bytes:
        """
        Serialize a DNS name to bytes, handling label lengths and edge cases.
        """
        b_name = (
            name if isinstance(name, bytes) else name.encode("utf-8", errors="ignore")
        )

        if not b_name or b_name == b".":
            return b"\x00"

        parts = b_name.split(b".")
        res = bytearray()
        _append = res.append
        _extend = res.extend

        for p in parts:
            label_len = len(p)
            if label_len:
                if label_len > 63:
                    self.logger.error("Label too long")
                    return b"\x00"
                _append(label_len)
                _extend(p)

        _append(0)
        return bytes(res)

    """
    VPN over DNS Utilities
    Methods for data encoding, encryption, and custom VPN header creation.
    """

    def base_encode(
        self,
        data_bytes,
        lowerCaseOnly: bool = True,
        alphabet=None,
    ) -> str:
        if not data_bytes:
            return ""

        if lowerCaseOnly:
            encoded = base64.b32encode(data_bytes).decode("ascii", errors="ignore")
            return encoded.replace("=", "").lower()
        else:
            return base64.b64encode(data_bytes).decode("ascii", errors="ignore")

    def base_decode(
        self,
        encoded_str,
        lowerCaseOnly: bool = True,
        alphabet=None,
    ) -> bytes:
        try:
            if not encoded_str:
                return b""

            if isinstance(encoded_str, bytes):
                encoded_str = encoded_str.decode("ascii", errors="ignore")

            if lowerCaseOnly:
                pad_len = (8 - (len(encoded_str) % 8)) % 8
                padded_str = encoded_str.upper() + ("=" * pad_len)
                try:
                    return base64.b32decode(padded_str)
                except Exception:
                    return b""
            else:
                pad_len = (4 - (len(encoded_str) % 4)) % 4
                padded_str = encoded_str + ("=" * pad_len)
                try:
                    return base64.b64decode(padded_str)
                except Exception:
                    return b""
        except Exception:
            return b""

    def _setup_crypto_dispatch(self):
        """Pre-bind crypto functions to avoid if/else overhead in hot-paths."""
        if self.encryption_method == 0:
            self.data_encrypt = self._no_crypto
            self.data_decrypt = self._no_crypto
        elif self.encryption_method == 1:
            self.data_encrypt = self._xor_crypto
            self.data_decrypt = self._xor_crypto
        elif self.encryption_method == 2 and self._Cipher and self._chacha_algo:
            self.data_encrypt = self._chacha_encrypt
            self.data_decrypt = self._chacha_decrypt
        elif self.encryption_method in (3, 4, 5) and self._aesgcm:
            self.data_encrypt = self._aes_encrypt
            self.data_decrypt = self._aes_decrypt
        else:
            self.data_encrypt = self._no_crypto
            self.data_decrypt = self._no_crypto

        self.codec_transform = self._codec_transform_dynamic

    def _no_crypto(
        self, data: bytes, key: Optional[bytes] = None, method: Optional[int] = None
    ) -> bytes:
        return data

    def _xor_crypto(
        self, data: bytes, key: Optional[bytes] = None, method: Optional[int] = None
    ) -> bytes:
        return self.xor_data(data, key or self.key)

    def _aes_encrypt(
        self, data: bytes, key: Optional[bytes] = None, method: Optional[int] = None
    ) -> bytes:
        if not data:
            return data
        nonce = self._urandom(12)
        try:
            return nonce + self._aesgcm.encrypt(nonce, data, None)
        except Exception as e:
            if self.logger:
                self.logger.error(f"AES Encrypt failed: {e}")
            return b""

    def _aes_decrypt(
        self, data: bytes, key: Optional[bytes] = None, method: Optional[int] = None
    ) -> bytes:
        if len(data) <= 12:
            return b""
        nonce, ciphertext = data[:12], data[12:]
        try:
            return self._aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            return b""

    def _chacha_encrypt(
        self, data: bytes, key: Optional[bytes] = None, method: Optional[int] = None
    ) -> bytes:
        if not data:
            return data
        nonce = self._urandom(16)
        cipher = self._Cipher(
            self._chacha_algo(key or self.key, nonce),
            mode=None,
            backend=self._default_backend(),
        )
        return nonce + cipher.encryptor().update(data)

    def _chacha_decrypt(
        self, data: bytes, key: Optional[bytes] = None, method: Optional[int] = None
    ) -> bytes:
        if len(data) <= 16:
            return b""
        nonce, ciphertext = data[:16], data[16:]
        cipher = self._Cipher(
            self._chacha_algo(key or self.key, nonce),
            mode=None,
            backend=self._default_backend(),
        )
        return cipher.decryptor().update(ciphertext)

    def _codec_transform_dynamic(self, data: bytes, encrypt: bool = True) -> bytes:
        """Dynamically dispatched codec transform, ZERO branching overhead."""
        if self.encryption_method == 0:
            return data
        return self.data_encrypt(data) if encrypt else self.data_decrypt(data)

    def _derive_key(self, raw_key) -> bytes:
        """Derives a fixed-length key based on the encryption method."""
        b_key = raw_key.encode() if isinstance(raw_key, str) else raw_key
        lengths = {2: 32, 3: 16, 4: 24, 5: 32}
        target = lengths.get(self.encryption_method, 32)

        if self.encryption_method in (2, 5):
            return hashlib.sha256(b_key).digest()
        elif self.encryption_method == 3:
            return hashlib.md5(b_key).digest()
        return b_key.ljust(target, b"\0")[:target]

    def xor_data(self, data: bytes, key: bytes) -> bytes:
        """
        XOR data with key while minimizing temporary allocations.
        """
        if not key or not data:
            return data

        d_len = len(data)
        k_len = len(key)

        if k_len == 1:
            k = key * d_len
        else:
            q, r = divmod(d_len, k_len)
            k = key * q + key[:r]

        int_data = int.from_bytes(data, byteorder="little")
        int_key = int.from_bytes(k, byteorder="little")

        return (int_data ^ int_key).to_bytes(d_len, byteorder="little")

    def build_request_dns_query(
        self,
        domain: str,
        session_id: int,
        packet_type: int,
        data: bytes,
        mtu_chars: int,
        encode_data: bool = True,
        qType: int = DNS_Record_Type.TXT,
        stream_id: int = 0,
        sequence_num: int = 0,
        fragment_id: int = 0,
        total_fragments: int = 0,
        total_data_length: int = 0,
        compression_type: int = 0,
        session_cookie: int = 0,
    ) -> list[bytes]:
        gen = self.generate_labels
        sq = self.simple_question_packet

        labels = gen(
            domain,
            session_id,
            packet_type,
            data,
            mtu_chars,
            encode_data,
            stream_id,
            sequence_num,
            fragment_id,
            total_fragments,
            total_data_length,
            compression_type,
            session_cookie,
        )

        if not labels:
            return []

        return [sq(label, qType) for label in labels]

    def generate_labels(
        self,
        domain: str,
        session_id: int,
        packet_type: int,
        data: bytes,
        mtu_chars: int,
        encode_data: bool = True,
        stream_id: int = 0,
        sequence_num: int = 0,
        fragment_id: int = 0,
        total_fragments: int = 0,
        total_data_length: int = 0,
        compression_type: int = 0,
        session_cookie: int = 0,
    ) -> list:
        if encode_data and data:
            data_str = self.base_encode(data, lowerCaseOnly=True)
        else:
            data_str = (
                data.decode("utf-8", errors="ignore")
                if isinstance(data, bytes)
                else (data or "")
            )

        data_len = len(data_str)
        calculated_total_fragments = (
            1 if data_len == 0 else (data_len + mtu_chars - 1) // mtu_chars
        )

        if calculated_total_fragments > 255:
            self.logger.error("Data too large, exceeds maximum 255 fragments.")
            return []

        # Localize hot-path functions
        data_to_labels = self.data_to_labels
        create_vpn_header = self.create_vpn_header
        raw_data_len = len(data) if data else 0

        data_labels: list = []
        append = data_labels.append

        # Single fragment fast-path
        if data_len <= mtu_chars:
            header = create_vpn_header(
                session_id=session_id,
                packet_type=packet_type,
                base36_encode=True,
                stream_id=stream_id,
                sequence_num=sequence_num,
                fragment_id=0,
                total_fragments=calculated_total_fragments,
                total_data_length=raw_data_len,
                compression_type=compression_type,
                session_cookie=session_cookie,
            )

            if data_len:
                if data_len <= 63:
                    append(f"{data_str}.{header}.{domain}")
                else:
                    append(f"{data_to_labels(data_str)}.{header}.{domain}")
            else:
                append(f"{header}.{domain}")

            return data_labels

        # Multi-fragment path
        for frag_id in range(calculated_total_fragments):
            start = frag_id * mtu_chars
            end = start + mtu_chars

            chunk_str = ""
            if start < data_len:
                chunk_str = data_str[start:] if end >= data_len else data_str[start:end]

            header = create_vpn_header(
                session_id=session_id,
                packet_type=packet_type,
                base36_encode=True,
                stream_id=stream_id,
                sequence_num=sequence_num,
                fragment_id=frag_id,
                total_fragments=calculated_total_fragments,
                total_data_length=raw_data_len,
                compression_type=compression_type,
                session_cookie=session_cookie,
            )

            if chunk_str:
                if len(chunk_str) <= 63:
                    append(f"{chunk_str}.{header}.{domain}")
                else:
                    append(f"{data_to_labels(chunk_str)}.{header}.{domain}")
            else:
                append(f"{header}.{domain}")

        return data_labels

    def extract_txt_from_rData_bytes(self, rData: bytes) -> bytes:
        """
        Extract and concatenate all TXT chunks from the rData field as raw bytes.
        """
        if not rData:
            return b""

        extracted = []
        offset = 0
        total_len = len(rData)
        _append = extracted.append

        while offset < total_len:
            length = rData[offset]
            offset += 1
            if length == 0:
                continue

            _append(rData[offset : offset + length])
            offset += length

        return b"".join(extracted)

    def extract_vpn_response(
        self, parsed_packet: dict, is_encoded: bool = False
    ) -> tuple[Optional[dict], bytes]:
        """
        Extracts header and assembles chunked data from the DNS answers section.
        Returns (parsed_header_dict, decrypted_data_bytes).
        """
        if not parsed_packet or not parsed_packet.get("answers"):
            return None, b""

        chunks = {}
        header_dict = None
        total_expected = 1
        is_chunked = False

        answers = parsed_packet.get("answers", [])
        txt_answers = [a for a in answers if a.get("type") == DNS_Record_Type.TXT]
        is_multi = len(txt_answers) > 1

        for answer in txt_answers:
            raw_txt = self.extract_txt_from_rData_bytes(answer["rData"])
            if not raw_txt:
                continue

            if is_encoded:
                try:
                    decoded_txt = self.base_decode(
                        raw_txt.decode("ascii", errors="strict"), lowerCaseOnly=False
                    )

                    if not decoded_txt:
                        continue

                    raw_txt = decoded_txt
                except Exception:
                    continue

            if is_multi:
                if raw_txt[0] == 0x00:
                    # Chunk 0: [0x00] [TotalChunks] [RawHeader] [Data...]
                    is_chunked = True
                    if len(raw_txt) < 4:
                        continue
                    total_expected = raw_txt[1]

                    # Offset=2 skips the [0x00] and [TotalChunks] bytes
                    parsed_hdr, hlen = self.parse_vpn_header_bytes(
                        raw_txt, offset=2, return_length=True
                    )
                    if not parsed_hdr:
                        continue
                    header_dict = parsed_hdr
                    chunks[0] = raw_txt[2 + hlen :]
                else:
                    # Chunk N: [ChunkID] [Data...]
                    is_chunked = True
                    chunk_id = raw_txt[0]
                    chunks[chunk_id] = raw_txt[1:]
            else:
                # Single Packet: [RawHeader] [Data...]
                is_chunked = False
                total_expected = 1

                # Offset=0 because header starts immediately
                parsed_hdr, hlen = self.parse_vpn_header_bytes(
                    raw_txt, offset=0, return_length=True
                )
                if not parsed_hdr:
                    continue
                header_dict = parsed_hdr
                chunks[0] = raw_txt[hlen:]

        if not header_dict:
            return None, b""

        if is_chunked:
            if len(chunks) != total_expected:
                return None, b""
            # Ensure all pieces are present
            for i in range(total_expected):
                if i not in chunks:
                    return None, b""

        assembled_data_bytes = b"".join(chunks[i] for i in range(total_expected))

        return header_dict, assembled_data_bytes

    def generate_vpn_response_packet(
        self,
        domain: str,
        session_id: int,
        packet_type: int,
        data: bytes,
        question_packet: bytes = b"",
        stream_id: int = 0,
        sequence_num: int = 0,
        fragment_id: int = 0,
        total_fragments: int = 0,
        total_data_length: int = 0,
        encode_data: bool = False,
        compression_type: int = 0,
        session_cookie: int = 0,
    ) -> bytes:
        header_b = self.create_vpn_header(
            session_id,
            packet_type,
            False,
            stream_id,
            sequence_num,
            fragment_id,
            total_fragments,
            total_data_length,
            compression_type=compression_type,
            session_cookie=session_cookie,
            encrypt_data=False,
            base_encode=False,
        )

        _len = len
        _bytes = bytes
        _base_encode = self.base_encode

        txt_type = DNS_Record_Type.TXT
        in_class = DNS_QClass.IN
        simple_ans = self.simple_answer_packet
        answers = []
        _append = answers.append

        max_payload = 189 if encode_data else 255

        # Condition 1: No Data
        if not data:
            payload = (
                _base_encode(header_b, lowerCaseOnly=False).encode(
                    "ascii", errors="ignore"
                )
                if encode_data
                else header_b
            )
            _append(
                {
                    "name": domain,
                    "type": txt_type,
                    "class": in_class,
                    "TTL": 0,
                    "rData": _bytes([_len(payload)]) + payload,
                }
            )
            return simple_ans(answers, question_packet)

        # Condition 2: Fits in single packet
        single_payload = header_b + data
        if _len(single_payload) <= max_payload:
            payload = (
                _base_encode(single_payload, lowerCaseOnly=False).encode(
                    "ascii", errors="ignore"
                )
                if encode_data
                else single_payload
            )
            _append(
                {
                    "name": domain,
                    "type": txt_type,
                    "class": in_class,
                    "TTL": 0,
                    "rData": _bytes([_len(payload)]) + payload,
                }
            )
            return simple_ans(answers, question_packet)

        # Condition 3: Chunked Data
        chunk0_prefix = _bytes([0x00, 0])
        max_chunk0_data = max_payload - _len(chunk0_prefix) - _len(header_b)

        chunk0_payload = data[:max_chunk0_data]
        remaining_data_len = _len(data) - max_chunk0_data
        max_chunk_n_data = max_payload - 1

        total_chunks = (
            1 + (remaining_data_len + max_chunk_n_data - 1) // max_chunk_n_data
        )

        if total_chunks > 255:
            self.logger.error("Data too large, exceeds maximum 255 fragments.")
            return simple_ans(answers, question_packet)

        # Append Chunk 0
        raw_chunk0 = _bytes([0x00, total_chunks]) + header_b + chunk0_payload
        full_chunk0 = (
            _base_encode(raw_chunk0, lowerCaseOnly=False).encode(
                "ascii", errors="ignore"
            )
            if encode_data
            else raw_chunk0
        )
        _append(
            {
                "name": domain,
                "type": txt_type,
                "class": in_class,
                "TTL": 0,
                "rData": _bytes([_len(full_chunk0)]) + full_chunk0,
            }
        )

        cur = max_chunk0_data
        chunk_id = 1
        data_len = _len(data)

        # Append subsequent Chunks
        while cur < data_len:
            raw_chunk = _bytes([chunk_id]) + data[cur : cur + max_chunk_n_data]
            chunk = (
                _base_encode(raw_chunk, lowerCaseOnly=False).encode(
                    "ascii", errors="ignore"
                )
                if encode_data
                else raw_chunk
            )
            _append(
                {
                    "name": domain,
                    "type": txt_type,
                    "class": in_class,
                    "TTL": 0,
                    "rData": _bytes([_len(chunk)]) + chunk,
                }
            )
            cur += max_chunk_n_data
            chunk_id += 1

        return simple_ans(answers, question_packet)

    def extract_txt_from_rData(self, rData: bytes) -> str:
        """
        Extract and concatenate all TXT strings from the rData field.
        Optimized to join bytes at C-level before decoding.
        """
        if not rData:
            return ""

        extracted = []
        offset = 0
        total_len = len(rData)
        _append = extracted.append

        while offset < total_len:
            length = rData[offset]
            offset += 1
            if length == 0:
                continue

            if offset + length > total_len:
                _append(rData[offset:])
                break

            _append(rData[offset : offset + length])
            offset += length

        return b"".join(extracted).decode("utf-8", errors="ignore")

    def calculate_upload_mtu(self, domain: str, mtu: int = 0) -> tuple[int, int]:
        """
        Calculate the maximum upload MTU based on the domain length and DNS constraints.
        Returns (max_chars, max_bytes).
        """
        MAX_DNS_TOTAL = 253
        MAX_LABEL_LEN = 63

        # Localize frequently used attrs to reduce attribute lookups
        log2_36 = self.LOG2_36
        _ceil = math.ceil
        _len = len

        # MTU discovery must assume the largest possible VPN header so later
        # real traffic never exceeds the tested boundary.
        hb_len = self.get_max_vpn_header_raw_size()

        # include marker byte added before base-encoding
        bits = (hb_len + 1) * 8
        header_overhead_chars = int(_ceil(bits / log2_36)) + 1
        domain_overhead_chars = _len(domain) + 1
        total_overhead = header_overhead_chars + domain_overhead_chars + 1
        available_chars_space = MAX_DNS_TOTAL - total_overhead

        if available_chars_space <= 0:
            self.logger.error(f"Domain {domain} is too long, no space for data.")
            return 0, 0

        max_payload_chars = (available_chars_space * MAX_LABEL_LEN) // (
            MAX_LABEL_LEN + 1
        )
        if max_payload_chars <= 0:
            return 0, 0

        bits_capacity = max_payload_chars * self.LOG2_36
        safe_bytes_capacity = int(bits_capacity / 8)

        if mtu > 0 and mtu < safe_bytes_capacity:
            final_mtu_bytes = mtu
            final_mtu_chars = int(math.ceil((mtu * 8) / self.LOG2_36))
        else:
            final_mtu_bytes = safe_bytes_capacity
            final_mtu_chars = max_payload_chars

        return final_mtu_chars, final_mtu_bytes

    def data_to_labels(self, encoded_str: str) -> str:
        """
        Convert encoded string into DNS labels (max 63 chars each).
        """
        if not encoded_str:
            return ""

        n = len(encoded_str)
        if n <= 63:
            return encoded_str

        # Very fast C-optimized inline chunking
        return ".".join(encoded_str[i : i + 63] for i in range(0, n, 63))

    def extract_vpn_header_from_labels(self, labels):
        """
        Extract and decode the VPN header from DNS labels.

        Args:
            labels (str): The DNS labels containing the encoded header.
        Returns:
            dict | None: Parsed VPN header dictionary, or None on invalid input.
        """
        if isinstance(labels, bytes):
            labels = labels.decode("ascii", errors="ignore")

        if not labels or not isinstance(labels, str):
            return None

        # Avoid creating a list via split(); take the last label with rfind() and slice.
        last_dot = labels.rfind(".")
        header_encoded = labels if last_dot == -1 else labels[last_dot + 1 :]

        # Local aliases reduce attribute lookups on the hot path.
        _decode = self.decode_and_decrypt_data
        _parse = self.parse_vpn_header_bytes

        header_decrypted = _decode(header_encoded, lowerCaseOnly=True)
        if not header_decrypted:
            return None

        return _parse(header_decrypted)

    def decode_and_decrypt_data(self, encoded_str, lowerCaseOnly=True) -> bytes:
        """
        Decode and decrypt the VPN data from an encoded string.

        Args:
            encoded_str (str): The base-encoded string containing the data.
        Returns:
            bytes: Decoded and decrypted VPN data bytes.
        """
        # Fast-path + minimal overhead: avoid try/except and reduce attribute lookups.
        if not encoded_str:
            return b""

        if isinstance(encoded_str, bytes):
            encoded_str = encoded_str.decode("ascii", errors="ignore")

        base_dec = self.base_decode

        # If encryption is disabled, skip codec_transform entirely.
        if self.encryption_method == 0:
            return base_dec(encoded_str, lowerCaseOnly=lowerCaseOnly)

        data_encrypted = base_dec(encoded_str, lowerCaseOnly=lowerCaseOnly)
        if not data_encrypted:
            return b""

        codec = self.codec_transform
        return codec(data_encrypted, encrypt=False)

    def encrypt_and_encode_data(self, data: bytes, lowerCaseOnly=True) -> str:
        """
        Encrypt and encode the VPN data to a string.

        Args:
            data (bytes): The raw VPN data bytes.
        Returns:
            str: Encoded VPN data string.
        """

        if not data:
            return ""

        base_enc = self.base_encode

        if self.encryption_method == 0:
            return base_enc(data, lowerCaseOnly=lowerCaseOnly)

        codec = self.codec_transform
        encrypted = codec(data, encrypt=True)
        return base_enc(encrypted, lowerCaseOnly=lowerCaseOnly)

    def extract_vpn_data_from_labels(self, labels) -> bytes:
        """
        Extract and decode the VPN data from DNS labels.

        Args:
            labels (str): The DNS labels containing the encoded data.
        Returns:
            bytes: Decoded VPN data bytes.
        """
        if isinstance(labels, bytes):
            labels = labels.decode("ascii", errors="ignore")

        if not labels or not isinstance(labels, str):
            return b""

        last_dot = labels.rfind(".")
        if last_dot <= 0:
            return b""

        left = labels[:last_dot]
        if not left:
            return b""

        data_encoded = left.replace(".", "")
        try:
            decoded_data = self.decode_and_decrypt_data(
                data_encoded, lowerCaseOnly=True
            )

            if not decoded_data:
                return b""

            return decoded_data
        except Exception as e:
            self.logger.error(
                f"<red>Failed to extract VPN data: {e}, labels: {labels}</red>"
            )
            return b""

    def parse_vpn_header_bytes(
        self, header_bytes: bytes, offset: int = 0, return_length: bool = False
    ):
        """
        Parses dynamic header bytes into a dictionary.
        If return_length is True, returns (header_data_dict, header_byte_length).
        """
        hb = header_bytes
        ln = len(hb)
        if ln < offset + 2:
            return (None, 0) if return_length else None

        session_id = hb[offset]
        ptype = hb[offset + 1]

        if ptype not in self._VALID_PACKET_TYPES:
            return (None, 0) if return_length else None

        header_data = {"session_id": session_id, "packet_type": ptype}

        off = offset + 2
        PT_STREAM = self._PT_STREAM_EXT
        PT_SEQ = self._PT_SEQ_EXT
        PT_FRAG = self._PT_FRAG_EXT
        PT_COMP = self._PT_COMP_EXT

        if ptype in PT_STREAM:
            if ln < off + 2:
                return (None, 0) if return_length else None
            header_data["stream_id"] = (hb[off] << 8) | hb[off + 1]
            off += 2

        if ptype in PT_SEQ:
            if ln < off + 2:
                return (None, 0) if return_length else None
            header_data["sequence_num"] = (hb[off] << 8) | hb[off + 1]
            off += 2

        if ptype in PT_FRAG:
            if ln < off + 4:
                return (None, 0) if return_length else None
            header_data["fragment_id"] = hb[off]
            header_data["total_fragments"] = hb[off + 1]
            header_data["total_data_length"] = (hb[off + 2] << 8) | hb[off + 3]
            off += 4

        if ptype in PT_COMP:
            if ln < off + 1:
                return (None, 0) if return_length else None
            header_data["compression_type"] = hb[off]
            off += 1

        if ln < off + self._VPN_HEADER_INTEGRITY_LEN:
            return (None, 0) if return_length else None

        session_cookie = hb[off]
        check_byte = hb[off + 1]
        expected_check = self._compute_header_check_byte(hb[offset : off + 1])
        if check_byte != expected_check:
            return (None, 0) if return_length else None

        header_data["session_cookie"] = session_cookie
        off += self._VPN_HEADER_INTEGRITY_LEN

        if return_length:
            return header_data, off - offset
        return header_data

    #
    # Custom VPN Packet Header Structure (for data fragmentation over DNS)
    #
    # Overview:
    #   - Designed for minimal overhead and no redundant fields.
    #   - Easily extensible for future packet types.
    #   - All multi-byte fields are big-endian.
    #
    # Byte Layout:
    #   [0]  1 byte  (uint8)  : Session ID
    #   [1]  1 byte  (uint8)  : Packet Type
    #
    # Extended headers for packet types in _PT_STREAM_EXT:
    #   [2]  2 bytes (uint16) : Stream ID
    #
    # Extended headers for packet types in _PT_SEQ_EXT:
    #   [3]  2 bytes (uint16) : Sequence Number
    #
    # Extended headers for packet types in _PT_FRAG_EXT:
    #   [4]  1 byte  (uint8)  : Fragment ID
    # Extended header for first fragment only (commonly when sequence=0 and frag=0):
    #   [5]  1 byte  (uint8)  : Total Fragments (for first packet of a stream)
    #   [6]  2 bytes (uint16) : Total Data Length (for first packet of a stream)
    #
    # Extended header for packet types in _PT_COMP_EXT:
    #   [+1] 1 byte  (uint8)  : Compression Type (0=OFF, non-zero=algorithm id)
    def create_vpn_header(
        self,
        session_id: int,
        packet_type: int,
        base36_encode: bool = True,
        stream_id: int = 0,
        sequence_num: int = 0,
        fragment_id: int = 0,
        total_fragments: int = 0,
        total_data_length: int = 0,
        compression_type: int = 0,
        session_cookie: int = 0,
        encrypt_data: bool = True,
        base_encode: bool = True,
    ):
        """
        Construct custom VPN header for a DNS packet.

        Args:
            session_id (int): VPN session identifier (0-255).
            packet_type (int): Type of VPN packet (0-255).
            base36_encode (bool): Whether to base36 encode the header,
            stream_id (int): Stream ID for packets in _PT_STREAM_EXT (0-65535).
            sequence_num (int): Sequence number for packets in _PT_SEQ_EXT (0-65535).
            fragment_id (int): Fragment ID for packets in _PT_FRAG_EXT (0-255).
            total_fragments (int): Total fragments for packets in _PT_FRAG_EXT (0-255).
            total_data_length (int): Total payload length for packets in _PT_FRAG_EXT (0-65535).
            compression_type (int): Compression type byte for packet types in _PT_COMP_EXT.
            encrypt_data (bool): Whether to encrypt the header.
            base_encode (bool): Whether to base36 encode the header.
        Returns:
            str | bytes: Encoded VPN header (or raw bytes when base_encode=False).

        Raises:
            ValueError: If arguments are out of valid range.
        """
        h_list = [session_id, packet_type]

        if packet_type in self._PT_STREAM_EXT:
            h_list.extend([stream_id >> 8, stream_id & 0xFF])

        if packet_type in self._PT_SEQ_EXT:
            h_list.extend([sequence_num >> 8, sequence_num & 0xFF])

        if packet_type in self._PT_FRAG_EXT:
            h_list.append(fragment_id)
            h_list.extend(
                [
                    total_fragments & 0xFF,
                    (total_data_length >> 8) & 0xFF,
                    total_data_length & 0xFF,
                ]
            )

        if packet_type in self._PT_COMP_EXT:
            h_list.append(compression_type & 0xFF)

        raw_header = bytes(h_list + [session_cookie & 0xFF])
        raw_header += bytes([self._compute_header_check_byte(raw_header)])

        if not encrypt_data or self.encryption_method == 0:
            encrypted_header = raw_header
        else:
            encrypted_header = self.codec_transform(raw_header, encrypt=True)

        if not base_encode:
            return encrypted_header

        return self.base_encode(encrypted_header, lowerCaseOnly=base36_encode)
