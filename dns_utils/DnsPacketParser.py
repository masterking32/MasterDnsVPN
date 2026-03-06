# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026
import os
import hashlib
import math
import random
from typing import Any, Optional
import struct
from dns_utils.DNS_ENUMS import DNS_QClass, DNS_Record_Type, Packet_Type


class DnsPacketParser:
    """
    DNS Packet Parser and Builder for VPN over DNS tunneling.
    Handles DNS packet parsing, construction, and custom VPN header encoding.
    """

    _PT_STREAM_EXT = frozenset(
        {
            Packet_Type.STREAM_SYN,
            Packet_Type.STREAM_SYN_ACK,
            Packet_Type.STREAM_FIN,
            Packet_Type.STREAM_DATA,
            Packet_Type.STREAM_DATA_ACK,
            Packet_Type.STREAM_RESEND,
            Packet_Type.MTU_UP_REQ,
            Packet_Type.MTU_DOWN_RES,
        }
    )
    _PT_SEQ_EXT = frozenset(
        {
            Packet_Type.STREAM_DATA_ACK,
            Packet_Type.STREAM_DATA,
            Packet_Type.STREAM_RESEND,
            Packet_Type.MTU_UP_REQ,
            Packet_Type.MTU_DOWN_RES,
        }
    )
    _PT_FRAG_EXT = frozenset(
        {
            Packet_Type.STREAM_DATA,
            Packet_Type.STREAM_RESEND,
            Packet_Type.MTU_UP_REQ,
            Packet_Type.MTU_DOWN_RES,
        }
    )

    _RR_PACKER = struct.Struct(">HHIH")
    _Q_PACKER = struct.Struct(">HH")
    _HEADER_PACKER = struct.Struct(">HHHHHH")

    _VALID_QTYPES = frozenset(
        v for k, v in DNS_Record_Type.__dict__.items() if not k.startswith("__")
    )

    LOG2_36 = math.log2(36)

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
                from cryptography.hazmat.primitives.ciphers import Cipher
                from cryptography.hazmat.backends import default_backend

                self._Cipher = Cipher
                self._default_backend = default_backend
            except ImportError:
                pass

        self._setup_crypto_dispatch()
        self.base9x_alphabet = r"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+,-/;<=>?@[]^_`{|}~"
        self._alphabet_cache = {}
        self._int_bytes_cache = {
            i: (str(i) + ".").encode("ascii", errors="ignore") for i in range(512)
        }

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

            offset = 12
            for _ in range(qd_count):
                _, offset = self._parse_dns_name_from_bytes(question_packet, offset)
                offset += 4  # Skip Type and Class

            new_header = self._HEADER_PACKER.pack(
                pkt_id, flags, qd_count, len(answers), 0, 0
            )

            parts = [new_header, question_packet[12:offset]]
            _append = parts.append
            for ans in answers:
                _append(self._serialize_resource_record(ans))

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

    def _serialize_resource_record(self, record: dict) -> bytes:
        """
        Serialize a DNS resource record to bytes.
        """
        rdata = record["rData"]

        packed_header = self._RR_PACKER.pack(
            int(record["type"]), int(record["class"]), int(record["TTL"]), len(rdata)
        )

        return b"".join(
            (self._serialize_dns_name(record["name"]), packed_header, rdata)
        )

    def _serialize_dns_name(self, name: str | bytes) -> bytes:
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
            l = len(p)
            if l:
                if l > 63:
                    self.logger.error("Label too long")
                    return b"\x00"
                _append(l)
                _extend(p)

        _append(0)
        return bytes(res)

    """
    VPN over DNS Utilities
    Methods for data encoding, encryption, and custom VPN header creation.
    """

    def base_encode(
        self,
        data_bytes: bytes,
        lowerCaseOnly: bool = True,
        alphabet: str | None = None,
    ) -> str:
        if not data_bytes:
            return ""

        alph = (
            alphabet
            if alphabet is not None
            else (
                "0123456789abcdefghijklmnopqrstuvwxyz"
                if lowerCaseOnly
                else self.base9x_alphabet
            )
        )
        base = len(alph)

        num = int.from_bytes(b"\x01" + data_bytes, byteorder="big")

        res = []
        _append = res.append

        while num:
            num, rem = divmod(num, base)
            _append(alph[rem])

        return "".join(reversed(res))

    def base_decode(
        self,
        encoded_str: str,
        lowerCaseOnly: bool = True,
        alphabet: str | None = None,
    ) -> bytes:
        if not encoded_str:
            return b""

        alph = (
            alphabet
            if alphabet is not None
            else (
                "0123456789abcdefghijklmnopqrstuvwxyz"
                if lowerCaseOnly
                else self.base9x_alphabet
            )
        )
        base = len(alph)

        char_map = self._alphabet_cache.get(alph)
        if char_map is None:
            char_map = {c: i for i, c in enumerate(alph)}
            self._alphabet_cache[alph] = char_map

        # Fast-path: native int(s, base) for common lowercase alphabets up to base36
        if base <= 36 and alph == "0123456789abcdefghijklmnopqrstuvwxyz"[:base]:
            valid_chars = "".join(c for c in encoded_str if c in char_map)
            if not valid_chars:
                return b""
            try:
                num = int(valid_chars, base)
            except ValueError:
                return b""
        else:
            num = 0
            _get = char_map.get
            for ch in encoded_str:
                v = _get(ch)
                if v is not None:
                    num = num * base + v

        if num == 0:
            return b""

        full_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder="big")

        return full_bytes[1:] if full_bytes[0] == 1 else full_bytes

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

    def _no_crypto(self, data: bytes, key: bytes = None, method: int = None) -> bytes:
        return data

    def _xor_crypto(self, data: bytes, key: bytes = None, method: int = None) -> bytes:
        return self.xor_data(data, key or self.key)

    def _aes_encrypt(self, data: bytes, key: bytes = None, method: int = None) -> bytes:
        if not data:
            return data
        nonce = self._urandom(12)
        try:
            return nonce + self._aesgcm.encrypt(nonce, data, None)
        except Exception as e:
            if self.logger:
                self.logger.error(f"AES Encrypt failed: {e}")
            return b""

    def _aes_decrypt(self, data: bytes, key: bytes = None, method: int = None) -> bytes:
        if len(data) <= 12:
            return b""
        nonce, ciphertext = data[:12], data[12:]
        try:
            return self._aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            return b""

    def _chacha_encrypt(
        self, data: bytes, key: bytes = None, method: int = None
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
        self, data: bytes, key: bytes = None, method: int = None
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

    def _derive_key(self, raw_key: str) -> bytes:
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
        )

        if not labels:
            return b""

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
            )

            if chunk_str:
                if len(chunk_str) <= 63:
                    append(f"{chunk_str}.{header}.{domain}")
                else:
                    append(f"{data_to_labels(chunk_str)}.{header}.{domain}")
            else:
                append(f"{header}.{domain}")

        return data_labels

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
    ) -> bytes:
        MAX_ALLOWED_CHARS_PER_TXT = 191

        header = self.create_vpn_header(
            session_id,
            packet_type,
            base36_encode=False,
            stream_id=stream_id,
            sequence_num=sequence_num,
            fragment_id=fragment_id,
            total_fragments=total_fragments,
            total_data_length=total_data_length,
        )
        # Localize and fast-path: encode the full data once (all chars are ASCII from base_encode)
        base_enc = self.base_encode
        simple_ans = self.simple_answer_packet
        txt_type = DNS_Record_Type.TXT
        in_class = DNS_QClass.IN

        data_str = base_enc(data, lowerCaseOnly=False)
        answers = []
        append = answers.append

        if not data_str:
            # small response that contains only header + marker
            full_chunk_str = header + ".0."
            encoded = full_chunk_str.encode("ascii", errors="ignore")
            append(
                {
                    "name": domain,
                    "type": txt_type,
                    "class": in_class,
                    "TTL": 0,
                    "rData": bytes((len(encoded),)) + encoded,
                }
            )
            return simple_ans(answers, question_packet)

        # Encode once to bytes to avoid repeated str->bytes conversions in loop
        data_bytes = data_str.encode("ascii", errors="ignore")
        data_len = len(data_bytes)

        header_prefix_bytes = (header + ".").encode("ascii", errors="ignore")
        _int_cache = self._int_bytes_cache

        answer_id = 0
        cur = 0

        while cur < data_len:
            id_bytes = _int_cache.get(answer_id)
            if id_bytes is None:
                id_bytes = (str(answer_id) + ".").encode("ascii", errors="ignore")
                if answer_id < 512:
                    _int_cache[answer_id] = id_bytes

            if answer_id == 0:
                prefix_bytes = header_prefix_bytes + id_bytes
            else:
                prefix_bytes = id_bytes

            available_space = MAX_ALLOWED_CHARS_PER_TXT - len(prefix_bytes)

            next_idx = cur + available_space
            chunk_payload = data_bytes[cur:next_idx]
            full_chunk = prefix_bytes + chunk_payload

            append(
                {
                    "name": domain,
                    "type": txt_type,
                    "class": in_class,
                    "TTL": 0,
                    "rData": bytes((len(full_chunk),)) + full_chunk,
                }
            )

            cur = next_idx
            answer_id += 1

        return simple_ans(answers, question_packet)

    def extract_txt_from_rData(self, rData: bytes) -> str:
        """
        Extract the TXT string from the rData field of a DNS TXT record.
        """
        if not rData:
            return ""

        length = rData[0]
        if length == 0:
            return ""

        return rData[1 : 1 + length].decode("utf-8", errors="ignore")

    def calculate_upload_mtu(self, domain: str, mtu: int = 0) -> int:
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

        # Determine header raw byte length for STREAM_DATA test-case
        hb_len = 2
        if Packet_Type.STREAM_DATA in self._PT_STREAM_EXT:
            hb_len += 2
        if Packet_Type.STREAM_DATA in self._PT_SEQ_EXT:
            hb_len += 2
        if Packet_Type.STREAM_DATA in self._PT_FRAG_EXT:
            # frag byte + the special-case extra 3 bytes when seq==0 and frag==0
            hb_len += 1 + 3

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
            final_mtu_chars = int((mtu * 8) / self.LOG2_36)
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

    def extract_vpn_header_from_labels(self, labels: str) -> bytes:
        """
        Extract and decode the VPN header from DNS labels.

        Args:
            labels (str): The DNS labels containing the encoded header.
        Returns:
            bytes: Decoded VPN header bytes.
        """
        if not labels or not isinstance(labels, str):
            return b""

        # Avoid creating a list via split(); take the last label with rfind() and slice.
        last_dot = labels.rfind(".")
        header_encoded = labels if last_dot == -1 else labels[last_dot + 1 :]

        # Local aliases reduce attribute lookups on the hot path.
        _decode = self.decode_and_decrypt_data
        _parse = self.parse_vpn_header_bytes

        header_decrypted = _decode(header_encoded, lowerCaseOnly=True)
        return _parse(header_decrypted)

    def decode_and_decrypt_data(self, encoded_str: str, lowerCaseOnly=True) -> bytes:
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

    def extract_vpn_data_from_labels(self, labels: str) -> bytes:
        """
        Extract and decode the VPN data from DNS labels.

        Args:
            labels (str): The DNS labels containing the encoded data.
        Returns:
            bytes: Decoded VPN data bytes.
        """
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
            return self.decode_and_decrypt_data(data_encoded, lowerCaseOnly=True)
        except Exception as e:
            self.logger.error(f"Failed to extract VPN data: {e}")
            return b""

    def parse_vpn_header_bytes(self, header_bytes: bytes) -> dict:
        """
        Reverse of create_vpn_header. Parses dynamic header bytes into a dictionary.
        """
        if not header_bytes or len(header_bytes) < 2:
            return None

        hb = header_bytes
        ln = len(hb)
        ptype = hb[1]

        header_data = {"session_id": hb[0], "packet_type": ptype}

        off = 2
        PT_STREAM = self._PT_STREAM_EXT
        PT_SEQ = self._PT_SEQ_EXT
        PT_FRAG = self._PT_FRAG_EXT

        # STREAM: need 2 bytes
        if ptype in PT_STREAM:
            if ln < off + 2:
                return None
            header_data["stream_id"] = (hb[off] << 8) | hb[off + 1]
            off += 2

        # SEQ: need 2 bytes
        if ptype in PT_SEQ:
            if ln < off + 2:
                return None
            header_data["sequence_num"] = (hb[off] << 8) | hb[off + 1]
            off += 2

        # FRAG: need 1 byte, and possibly extra 3 bytes when seq==0 and frag==0
        if ptype in PT_FRAG:
            if ln < off + 1:
                return None
            frag = hb[off]
            header_data["fragment_id"] = frag
            off += 1

            if header_data.get("sequence_num") == 0 and frag == 0:
                if ln < off + 3:
                    return None
                header_data["total_fragments"] = hb[off]
                header_data["total_data_length"] = (hb[off + 1] << 8) | hb[off + 2]

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
    # Extended Headers for STREAM_SYN, STREAM_SYN_ACK, STREAM_FIN, STREAM_DATA, STREAM_DATA_ACK, STREAM_RESEND, MTU_UP_REQ, MTU_DOWN_RES
    #   [2]  2 bytes (uint16) : Stream ID (for STREAM_DATA packets)
    #
    # Extended Headers for STREAM_DATA_ACK, STREAM_DATA, STREAM_RESEND, MTU_UP_REQ, MTU_DOWN_RES
    #   [3]  2 bytes (uint16) : Sequence Number (for STREAM_DATA packets)
    #
    # Extended Headers for STREAM_DATA, STREAM_RESEND, MTU_UP_REQ, MTU_DOWN_RES
    #   [4]  1 byte  (uint8)  : Fragment ID (for STREAM_DATA packets)
    # Extended Header for STREAM_DATA or MTU_UP_REQ or MTU_DOWN_RES, If sequence number = 0 and fragment ID = 0
    #   [5]  1 byte  (uint8)  : Total Fragments (for first packet of a stream)
    #   [6]  2 bytes (uint16) : Total Data Length (for first packet of a stream)
    #
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
    ) -> str:
        """
        Construct custom VPN header for a DNS packet.

        Args:
            session_id (int): VPN session identifier (0-255).
            packet_type (int): Type of VPN packet (0-255).
            base36_encode (bool): Whether to base36 encode the header,
            stream_id (int): Stream ID for STREAM_DATA packets (0-65535).
            sequence_num (int): Sequence number for STREAM_DATA packets (0-65535).
            fragment_id (int): Fragment ID for STREAM_DATA packets (0-255).
            total_fragments (int): Total fragments for the stream (0-255).
        Returns:
            str: Encoded VPN header.

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
            if sequence_num == 0 and fragment_id == 0:
                h_list.extend(
                    [total_fragments, total_data_length >> 8, total_data_length & 0xFF]
                )

        raw_header = bytes(h_list)

        if self.encryption_method == 0:
            encrypted_header = raw_header
        else:
            encrypted_header = self.codec_transform(raw_header, encrypt=True)

        return self.base_encode(encrypted_header, lowerCaseOnly=base36_encode)
