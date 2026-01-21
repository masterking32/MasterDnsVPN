
# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

from typing import Any


class DnsPacketParser:
    """
    DNS Packet Parser and Builder for VPN over DNS tunneling.
    Handles DNS packet parsing, construction, and custom VPN header encoding.
    """

    def __init__(self, logger: Any = None, encryption_key: bytes = b"", encryption_method: int = 1):
        self.logger = logger
        self.encryption_key = encryption_key
        self.encryption_method = encryption_method

        if self.encryption_method not in (0, 1, 2, 3, 4, 5):
            if self.logger:
                self.logger.error(
                    f"Invalid encryption_method value: {self.encryption_method}. Defaulting to 1 (XOR encryption)."
                )
            self.encryption_method = 1

        # Adjust key length for encryption methods
        if self.encryption_method == 2:
            self.encryption_key = self.fix_key_length(self.encryption_key, 32)
        elif self.encryption_method == 3:
            self.encryption_key = self.fix_key_length(self.encryption_key, 16)
        elif self.encryption_method == 4:
            self.encryption_key = self.fix_key_length(self.encryption_key, 24)
        elif self.encryption_method == 5:
            self.encryption_key = self.fix_key_length(self.encryption_key, 32)

    def fix_key_length(self, key: bytes, desired_length: int) -> bytes:
        """
        Adjust the key to the desired length by truncating or padding with zeros.
        """
        if len(key) > desired_length:
            return key[:desired_length]
        elif len(key) * 2 == desired_length:
            return key + key
        elif len(key) < desired_length:
            return key.ljust(desired_length, b'\0')
        return key

    """
    Default DNS Packet Parsers
    Methods to parse and create standard DNS packets.
    """

    async def parse_dns_headers(self, data: bytes) -> dict:
        """
        Parse DNS packet headers from raw bytes.
        Returns a dictionary of header fields.
        """
        try:
            headers = {
                'id': int.from_bytes(data[0:2], byteorder='big'),
                'qr': (int.from_bytes(data[2:4], byteorder='big') >> 15) & 0x1,
                'opcode': (int.from_bytes(data[2:4], byteorder='big') >> 11) & 0xF,
                'aa': (int.from_bytes(data[2:4], byteorder='big') >> 10) & 0x1,
                'tc': (int.from_bytes(data[2:4], byteorder='big') >> 9) & 0x1,
                'rd': (int.from_bytes(data[2:4], byteorder='big') >> 8) & 0x1,
                'ra': (int.from_bytes(data[2:4], byteorder='big') >> 7) & 0x1,
                'z': (int.from_bytes(data[2:4], byteorder='big') >> 4) & 0x7,
                'rcode': int.from_bytes(data[2:4], byteorder='big') & 0xF,
                'qdcount': int.from_bytes(data[4:6], byteorder='big'),
                'ancount': int.from_bytes(data[6:8], byteorder='big'),
                'nscount': int.from_bytes(data[8:10], byteorder='big'),
                'arcount': int.from_bytes(data[10:12], byteorder='big'),
            }
            return headers
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to parse DNS headers: {e}")
            return {}

    async def parse_dns_question(self, headers: dict, data: bytes, offset: int) -> tuple:
        """
        Parse the DNS question section from the packet data.
        Returns a tuple (question_dict, new_offset).
        """
        try:
            if headers.get('qdcount', 0) == 0:
                return None, offset

            questions = []
            for _ in range(headers['qdcount']):
                name, offset = self._parse_name(data, offset)
                qtype = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                qclass = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                question = {
                    'qname': name,
                    'qtype': qtype,
                    'qclass': qclass
                }
                questions.append(question)

            return questions, offset
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to parse DNS question: {e}")
            return None, offset

    def _parse_name(self, data: bytes, offset: int) -> tuple:
        """
        Parse a domain name from DNS packet data, handling compression pointers.
        Returns (name, new_offset).
        """
        labels = []
        jumped = False
        original_offset = offset
        while True:
            length = data[offset]
            # Check for pointer (compression)
            if (length & 0xC0) == 0xC0:
                if not jumped:
                    original_offset = offset + 2
                pointer = ((length & 0x3F) << 8) | data[offset + 1]
                offset = pointer
                jumped = True
                continue
            if length == 0:
                offset += 1
                break
            offset += 1
            labels.append(data[offset:offset + length].decode('utf-8'))
            offset += length
        if not jumped:
            return '.'.join(labels), offset
        else:
            return '.'.join(labels), original_offset

    async def parse_dns_answer(self, headers: dict, data: bytes, offset: int) -> tuple:
        """
        Parse the DNS answer section from the packet data.
        Returns a tuple (answers_list, new_offset).
        """
        try:
            if headers.get('ancount', 0) == 0:
                return None, offset

            answers = []
            for _ in range(headers['ancount']):
                name, offset = self._parse_name(data, offset)
                atype = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                aclass = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                ttl = int.from_bytes(data[offset:offset + 4], byteorder='big')
                offset += 4
                rdlength = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                rdata = data[offset:offset + rdlength]
                offset += rdlength
                answer = {
                    'name': name,
                    'type': atype,
                    'class': aclass,
                    'ttl': ttl,
                    'rdata': rdata
                }
                answers.append(answer)

            return answers, offset
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to parse DNS answer: {e}")
            return None, offset

    async def parse_dns_authority(self, headers: dict, data: bytes, offset: int) -> tuple:
        """
        Parse the DNS authority section from the packet data.
        Returns a tuple (authorities_list, new_offset).
        """
        try:
            if headers.get('nscount', 0) == 0:
                return None, offset

            authorities = []
            for _ in range(headers['nscount']):
                name = []
                while True:
                    length = data[offset]
                    if length == 0:
                        offset += 1
                        break
                    offset += 1
                    name.append(data[offset:offset + length].decode('utf-8'))
                    offset += length
                atype = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                aclass = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                ttl = int.from_bytes(data[offset:offset + 4], byteorder='big')
                offset += 4
                rdlength = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                rdata = data[offset:offset + rdlength]
                offset += rdlength
                authority = {
                    'name': '.'.join(name),
                    'type': atype,
                    'class': aclass,
                    'ttl': ttl,
                    'rdata': rdata
                }
                authorities.append(authority)
            return authorities, offset
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to parse DNS authority: {e}")
            return None, offset

    async def parse_dns_additional(self, headers: dict, data: bytes, offset: int) -> tuple:
        """
        Parse the DNS additional section from the packet data.
        Returns a tuple (additionals_list, new_offset).
        """
        try:
            if headers.get('arcount', 0) == 0:
                return None, offset

            additionals = []
            for _ in range(headers['arcount']):
                name = []
                while True:
                    length = data[offset]
                    if length == 0:
                        offset += 1
                        break
                    offset += 1
                    name.append(data[offset:offset + length].decode('utf-8'))
                    offset += length
                atype = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                aclass = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                ttl = int.from_bytes(data[offset:offset + 4], byteorder='big')
                offset += 4
                rdlength = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                rdata = data[offset:offset + rdlength]
                offset += rdlength
                additional = {
                    'name': '.'.join(name),
                    'type': atype,
                    'class': aclass,
                    'ttl': ttl,
                    'rdata': rdata
                }
                additionals.append(additional)
            return additionals, offset
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to parse DNS additional: {e}")
            return None, offset

    async def parse_dns_packet(self, data: bytes) -> dict:
        """
        Parse the entire DNS packet from the data.
        Returns a dictionary with all sections.
        """
        try:
            headers = await self.parse_dns_headers(data)
            offset = 12
            questions, offset = await self.parse_dns_question(headers, data, offset)
            answers, offset = await self.parse_dns_answer(headers, data, offset)
            authorities, offset = await self.parse_dns_authority(headers, data, offset)
            additionals, offset = await self.parse_dns_additional(headers, data, offset)
            dns_packet = {
                'headers': headers,
                'questions': questions,
                'answers': answers,
                'authorities': authorities,
                'additionals': additionals
            }
            return dns_packet
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to parse DNS packet: {e}")
            return {}

    async def server_fail_response(self, request_data: bytes) -> bytes:
        """
        Create a DNS Server Failure (RCODE=2) response packet based on the request data.
        """
        try:
            if len(request_data) < 12:
                raise ValueError("Invalid DNS request data.")

            response = bytearray(request_data)
            # Set QR to 1 (response), Opcode remains the same, AA=0, TC=0, RD remains the same
            # Set RA=0, Z=0, RCODE=2 (Server Failure)
            flags = int.from_bytes(response[2:4], byteorder='big')
            flags |= 0x8000  # Set QR to 1
            flags &= 0xFFF0  # Clear RCODE
            flags |= 0x0002  # Set RCODE to 2
            response[2:4] = flags.to_bytes(2, byteorder='big')

            # Set ANCOUNT, NSCOUNT, ARCOUNT to 0
            response[6:8] = (0).to_bytes(2, byteorder='big')  # ANCOUNT
            response[8:10] = (0).to_bytes(2, byteorder='big')  # NSCOUNT
            response[10:12] = (0).to_bytes(2, byteorder='big')  # ARCOUNT

            return bytes(response)
        except Exception as e:
            if self.logger:
                self.logger.error(
                    f"Failed to create Server Failure response: {e}")
            return b''

    async def create_packet(self, dns_type: str = "A", domain: str = "google.com", is_request: bool = True) -> tuple:
        """
        Create a DNS packet for the given domain and type.
        Returns (packet_bytes, packet_bytearray).
        """
        try:
            if is_request:
                # Create DNS query packet
                packet = bytearray()
                packet += (0x1234).to_bytes(2, byteorder='big')  # ID
                packet += (0x0100).to_bytes(2, byteorder='big')  # Flags
                packet += (1).to_bytes(2, byteorder='big')       # QDCOUNT
                packet += (0).to_bytes(2, byteorder='big')       # ANCOUNT
                packet += (0).to_bytes(2, byteorder='big')       # NSCOUNT
                packet += (0).to_bytes(2, byteorder='big')       # ARCOUNT

                # Question Section
                for part in domain.split('.'):
                    packet += bytes([len(part)])
                    packet += part.encode('utf-8')
                packet += bytes([0])  # End of QNAME

                qtype_map = {
                    "A": 1,
                    "AAAA": 28,
                    "CNAME": 5,
                    "MX": 15,
                    "TXT": 16,
                    "NS": 2,
                    "SOA": 6
                }
                qtype = qtype_map.get(dns_type.upper(), 1)

                packet += qtype.to_bytes(2, byteorder='big')  # QTYPE
                packet += (1).to_bytes(2, byteorder='big')    # QCLASS
                return bytes(packet), packet
            else:
                # Create DNS response packet with TTL=0 (no cache)
                packet = bytearray()
                packet += (0x1234).to_bytes(2, byteorder='big')  # ID
                # Flags (standard response)
                packet += (0x8180).to_bytes(2, byteorder='big')
                packet += (1).to_bytes(2, byteorder='big')       # QDCOUNT
                packet += (1).to_bytes(2, byteorder='big')       # ANCOUNT
                packet += (0).to_bytes(2, byteorder='big')       # NSCOUNT
                packet += (0).to_bytes(2, byteorder='big')       # ARCOUNT

                # Question Section
                for part in domain.split('.'):
                    packet += bytes([len(part)])
                    packet += part.encode('utf-8')
                packet += bytes([0])  # End of QNAME

                qtype_map = {
                    "A": 1,
                    "AAAA": 28,
                    "CNAME": 5,
                    "MX": 15,
                    "TXT": 16,
                    "NS": 2,
                    "SOA": 6
                }
                qtype = qtype_map.get(dns_type.upper(), 1)

                packet += qtype.to_bytes(2, byteorder='big')  # QTYPE
                packet += (1).to_bytes(2, byteorder='big')    # QCLASS

                # Answer Section
                # Name: pointer to offset 12 (0xC00C)
                packet += (0xC00C).to_bytes(2, byteorder='big')
                packet += qtype.to_bytes(2, byteorder='big')  # TYPE
                packet += (1).to_bytes(2, byteorder='big')    # CLASS
                # TTL = 0 (no cache)
                packet += (0).to_bytes(4, byteorder='big')
                if qtype == 1:  # A
                    packet += (4).to_bytes(2, byteorder='big')  # RDLENGTH
                    packet += bytes([127, 0, 0, 1])  # RDATA: 127.0.0.1
                elif qtype == 28:  # AAAA
                    packet += (16).to_bytes(2, byteorder='big')  # RDLENGTH
                    packet += bytes([0]*15 + [1])  # ::1
                else:
                    packet += (0).to_bytes(2, byteorder='big')  # RDLENGTH
                return bytes(packet), packet
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to create DNS packet: {e}")
            return b'', b''

    """
    VPN over DNS Utilities
    Methods for data encoding, encryption, and custom VPN header creation.
    """

    def base_encode(self, data_bytes: bytes, lowerCaseOnly: bool = True) -> str:
        """
        Encode bytes to base lowercase (0-9, a-z) or mixed case.
        """
        alphabet = '0123456789abcdefghijklmnopqrstuvwxyz'  # base36
        if lowerCaseOnly is False:
            # base94
            alphabet = r'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&\()*+,-/:;<=>?@[\\]^_`{|}~ '

        num = int.from_bytes(data_bytes, byteorder='big')
        if num == 0:
            return alphabet[0]

        encoded = ''
        base = len(alphabet)
        while num > 0:
            num, rem = divmod(num, base)
            encoded = alphabet[rem] + encoded
        return encoded

    def xor_data(self, data: bytes, key: bytes) -> bytes:
        """
        XOR the data with the given key.
        """
        try:
            key_length = len(key)
            if key_length == 0:
                raise ValueError("Key length must be greater than 0 for XOR.")
            xored = bytearray()
            for i in range(len(data)):
                xored.append(data[i] ^ key[i % key_length])
            return bytes(xored)
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to XOR data: {e}")
            return b''

    def data_encrypt(self, data: bytes, key: bytes, method: int) -> bytes:
        """
        Encrypt data based on the selected method.
        Supported methods:
            0: None, 1: XOR, 2: ChaCha20, 3: AES-128-CTR, 4: AES-192-CTR, 5: AES-256-CTR
        """
        try:
            if method == 0:
                return data
            elif method == 1:
                return self.xor_data(data, key)
            elif method == 2:
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
                from cryptography.hazmat.backends import default_backend
                import os
                nonce = os.urandom(16)
                algorithm = algorithms.ChaCha20(key, nonce)
                cipher = Cipher(algorithm, mode=None,
                                backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_data = encryptor.update(data)
                return nonce + encrypted_data
            elif method in (3, 4, 5):
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                from cryptography.hazmat.backends import default_backend
                import os
                nonce = os.urandom(16)
                algorithm = algorithms.AES(key)
                cipher = Cipher(algorithm, modes.CTR(
                    nonce), backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_data = encryptor.update(data) + encryptor.finalize()
                return nonce + encrypted_data
            else:
                if self.logger:
                    self.logger.error(f"Unknown encryption method: {method}")
                return data
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to encrypt data: {e}")
            return b''

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
    #   [...]  Variable Length   : Optional payload (e.g., additional headers)
    #

    # Packet Types
    PACKET_TYPE_SERVER_TEST = 0x00
    PACKET_TYPE_SET_READ_MTU = 0x01
    PACKET_TYPE_SET_WRITE_MTU = 0x02
    PACKET_TYPE_NEW_SESSION = 0x03
    PACKET_TYPE_QUIC_PACKET = 0x04

    def create_chunk_header(
        self,
        session_id: int,
        packet_type: int,
        header_payload: bytes = b""
    ) -> bytes:
        """
        Construct custom VPN header for a DNS packet.

        Args:
            session_id (int): VPN session identifier (0-255).
            packet_type (int): Type of VPN packet (0-255).
            header_payload (bytes, optional): Additional header payload. Defaults to b"".
        Returns:
            bytes: Encoded VPN header.

        Raises:
            ValueError: If arguments are out of valid range.
        """
        # Input validation
        if not (0 <= session_id <= 0xFF):
            raise ValueError("session_id must be in 0-255.")
        if not (0 <= packet_type <= 0xFF):
            raise ValueError("packet_type must be in 0-255.")

        # Compose header
        header = bytearray()
        header.append(session_id)
        header.append(packet_type)

        if header_payload:
            header += header_payload
        return bytes(header)
