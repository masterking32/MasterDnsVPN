# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

from typing import Any
import random
import math
from dns_utils.DNS_ENUMS import PACKET_TYPES, RESOURCE_RECORDS, R_CODES, Q_CLASSES
from typing import Any, Optional


class DnsPacketParser:
    """
    DNS Packet Parser and Builder for VPN over DNS tunneling.
    Handles DNS packet parsing, construction, and custom VPN header encoding.
    """

    def __init__(self, logger: Optional[Any] = None, encryption_key: str = "", encryption_method: int = 1):
        self.logger = logger
        self.encryption_key = encryption_key.encode(
            'utf-8') if isinstance(encryption_key, str) else encryption_key
        self.encryption_method = encryption_method
        if self.encryption_method not in (0, 1, 2, 3, 4, 5):
            if self.logger:
                self.logger.error(
                    f"Invalid encryption_method value: {self.encryption_method}. Defaulting to 1 (XOR encryption).")
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
                'OpCode': (int.from_bytes(data[2:4], byteorder='big') >> 11) & 0xF,
                'aa': (int.from_bytes(data[2:4], byteorder='big') >> 10) & 0x1,
                'tc': (int.from_bytes(data[2:4], byteorder='big') >> 9) & 0x1,
                'rd': (int.from_bytes(data[2:4], byteorder='big') >> 8) & 0x1,
                'ra': (int.from_bytes(data[2:4], byteorder='big') >> 7) & 0x1,
                'z': (int.from_bytes(data[2:4], byteorder='big') >> 4) & 0x7,
                'rCode': int.from_bytes(data[2:4], byteorder='big') & 0xF,
                'QdCount': int.from_bytes(data[4:6], byteorder='big'),
                'AnCount': int.from_bytes(data[6:8], byteorder='big'),
                'NsCount': int.from_bytes(data[8:10], byteorder='big'),
                'ArCount': int.from_bytes(data[10:12], byteorder='big'),
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
            if headers.get('QdCount', 0) == 0:
                return None, offset

            questions = []
            for _ in range(headers['QdCount']):
                name, offset = self._parse_name(data, offset)
                qType = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                qClass = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                question = {
                    'qname': name,
                    'qType': qType,
                    'qClass': qClass
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
            if headers.get('AnCount', 0) == 0:
                return None, offset

            answers = []
            for _ in range(headers['AnCount']):
                name, offset = self._parse_name(data, offset)
                aType = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                aClass = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                TTL = int.from_bytes(data[offset:offset + 4], byteorder='big')
                offset += 4
                RdLength = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                rData = data[offset:offset + RdLength]
                offset += RdLength
                answer = {
                    'name': name,
                    'type': aType,
                    'class': aClass,
                    'TTL': TTL,
                    'rData': rData
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
            if headers.get('NsCount', 0) == 0:
                return None, offset

            authorities = []
            for _ in range(headers['NsCount']):
                name = []
                while True:
                    length = data[offset]
                    if length == 0:
                        offset += 1
                        break
                    offset += 1
                    name.append(data[offset:offset + length].decode('utf-8'))
                    offset += length
                aType = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                aClass = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                TTL = int.from_bytes(data[offset:offset + 4], byteorder='big')
                offset += 4
                RdLength = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                rData = data[offset:offset + RdLength]
                offset += RdLength
                authority = {
                    'name': '.'.join(name),
                    'type': aType,
                    'class': aClass,
                    'TTL': TTL,
                    'rData': rData
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
        Returns a tuple (additional_list, new_offset).
        """
        try:
            if headers.get('ArCount', 0) == 0:
                return None, offset

            additional = []
            for _ in range(headers['ArCount']):
                name = []
                while True:
                    length = data[offset]
                    if length == 0:
                        offset += 1
                        break
                    offset += 1
                    name.append(data[offset:offset + length].decode('utf-8'))
                    offset += length
                aType = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                aClass = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                TTL = int.from_bytes(data[offset:offset + 4], byteorder='big')
                offset += 4
                RdLength = int.from_bytes(
                    data[offset:offset + 2], byteorder='big')
                offset += 2
                rData = data[offset:offset + RdLength]
                offset += RdLength
                additional = {
                    'name': '.'.join(name),
                    'type': aType,
                    'class': aClass,
                    'TTL': TTL,
                    'rData': rData
                }
                additional.append(additional)
            return additional, offset
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
            additional, offset = await self.parse_dns_additional(headers, data, offset)
            dns_packet = {
                'headers': headers,
                'questions': questions,
                'answers': answers,
                'authorities': authorities,
                'additional': additional
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

            # Set AnCount, NsCount, ArCount to 0
            response[6:8] = (0).to_bytes(2, byteorder='big')  # AnCount
            response[8:10] = (0).to_bytes(2, byteorder='big')  # NsCount
            response[10:12] = (0).to_bytes(2, byteorder='big')  # ArCount

            return bytes(response)
        except Exception as e:
            if self.logger:
                self.logger.error(
                    f"Failed to create Server Failure response: {e}")
            return b''

    async def simple_answer_packet(self, answers: list, question_packet: bytes) -> bytes:
        """
        Create a simple DNS answer packet for the given answers based on the question packet.
        answers: list of answer dicts with keys: name, type, class, TTL, rData
        """
        try:
            # Parse question section from the question_packet
            headers = await self.parse_dns_headers(question_packet)
            offset = 12
            questions, offset = await self.parse_dns_question(headers, question_packet, offset)

            # Build sections
            section = {
                'headers': {
                    'id': headers['id'],
                    'QdCount': headers['QdCount'],
                    'AnCount': len(answers),
                    'NsCount': 0,
                    'ArCount': 0
                },
                'questions': questions,
                'answers': answers,
                'authorities': [],
                'additional': []
            }

            packet = await self.create_packet(section, question_packet)
            return packet
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to create answer packet: {e}")
            return b''

    async def simple_question_packet(self, domain: str, qType: int) -> bytes:
        """
        Create a simple DNS question packet for the given domain and type.
        """
        try:

            if qType is None or qType not in RESOURCE_RECORDS.values():
                self.logger.error(f"Invalid qType value: {qType}.")
                return b''

            random_id = random.randint(0, 65535)
            section = {
                'headers': {
                    'id': random_id,
                    'QdCount': 1,  # Question count
                    'AnCount': 0,
                    'NsCount': 0,
                    'ArCount': 0
                },
                'questions': [{
                    'qname': domain,
                    'qType': qType,
                    'qClass': Q_CLASSES["IN"]  # Internet
                }],
                'answers': [],
                'authorities': [],
                'additional': []
            }

            packet = await self.create_packet(section)
            return packet
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to create question packet: {e}")
            return b''

    async def create_packet(self, sections: dict, question_packet: bytes = b'') -> bytes:
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
            packet = bytearray()

            # Headers
            if question_packet and len(question_packet) >= 12:
                packet += question_packet[0:2]  # ID
                flags = int.from_bytes(
                    question_packet[2:4], byteorder='big')
                packet += flags.to_bytes(2, byteorder='big')  # Flags
            else:
                # Ensure all header fields are integers
                id_val = int(sections['headers']['id'])
                QdCount_val = int(sections['headers']['QdCount'])
                AnCount_val = int(sections['headers']['AnCount'])
                NsCount_val = int(sections['headers']['NsCount'])
                ArCount_val = int(sections['headers']['ArCount'])
                packet += id_val.to_bytes(2, byteorder='big')
                # Set flags for a standard query: QR=0, RD=1 (0x0100)
                flags = 0x0100
                packet += flags.to_bytes(2, byteorder='big')

            # Always ensure these are integers
            if question_packet and len(question_packet) >= 12:
                # Use counts from question_packet if present
                packet += int(sections['headers']['QdCount']
                              ).to_bytes(2, byteorder='big')
                packet += int(sections['headers']['AnCount']
                              ).to_bytes(2, byteorder='big')
                packet += int(sections['headers']['NsCount']
                              ).to_bytes(2, byteorder='big')
                packet += int(sections['headers']['ArCount']
                              ).to_bytes(2, byteorder='big')
            else:
                packet += QdCount_val.to_bytes(2, byteorder='big')
                packet += AnCount_val.to_bytes(2, byteorder='big')
                packet += NsCount_val.to_bytes(2, byteorder='big')
                packet += ArCount_val.to_bytes(2, byteorder='big')

            # Questions

            for question in sections.get('questions', []):
                for label in question['qname'].split('.'):
                    label_bytes = label.encode(
                        'utf-8') if not isinstance(label, bytes) else label
                    packet.append(len(label_bytes))
                    packet += label_bytes
                packet.append(0)  # End of name
                packet += int(question['qType']).to_bytes(2, byteorder='big')
                packet += int(question['qClass']).to_bytes(2, byteorder='big')

            # Answers
            for answer in sections.get('answers', []):
                for label in answer['name'].split('.'):
                    label_bytes = label.encode(
                        'utf-8') if not isinstance(label, bytes) else label
                    packet.append(len(label_bytes))
                    packet += label_bytes
                packet.append(0)  # End of name
                packet += int(answer['type']).to_bytes(2, byteorder='big')
                packet += int(answer['class']).to_bytes(2, byteorder='big')
                packet += int(answer['TTL']).to_bytes(4, byteorder='big')
                packet += len(answer['rData']).to_bytes(2, byteorder='big')
                packet += answer['rData']

            # Authorities
            for authority in sections.get('authorities', []):
                for label in authority['name'].split('.'):
                    label_bytes = label.encode(
                        'utf-8') if not isinstance(label, bytes) else label
                    packet.append(len(label_bytes))
                    packet += label_bytes
                packet.append(0)  # End of name
                packet += int(authority['type']).to_bytes(2, byteorder='big')
                packet += int(authority['class']).to_bytes(2, byteorder='big')
                packet += int(authority['TTL']).to_bytes(4, byteorder='big')
                packet += len(authority['rData']).to_bytes(2, byteorder='big')
                packet += authority['rData']

            # Additionals
            for additional in sections.get('additional', []):
                for label in additional['name'].split('.'):
                    label_bytes = label.encode(
                        'utf-8') if not isinstance(label, bytes) else label
                    packet.append(len(label_bytes))
                    packet += label_bytes
                packet.append(0)  # End of name
                packet += int(additional['type']).to_bytes(2, byteorder='big')
                packet += int(additional['class']).to_bytes(2, byteorder='big')
                packet += int(additional['TTL']).to_bytes(4, byteorder='big')
                packet += len(additional['rData']).to_bytes(2, byteorder='big')
                packet += additional['rData']

            return bytes(packet)
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to create DNS packet: {e}")
            return b''

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

    def base_decode(self, encoded_str: str, lowerCaseOnly: bool = True) -> bytes:
        """
        Decode base lowercase (0-9, a-z) or mixed case string to bytes.
        """
        alphabet = '0123456789abcdefghijklmnopqrstuvwxyz'  # base36
        if lowerCaseOnly is False:
            # base94
            alphabet = r'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&\()*+,-/:;<=>?@[\\]^_`{|}~ '

        base = len(alphabet)
        num = 0
        for char in encoded_str:
            num = num * base + alphabet.index(char)

        byte_length = (num.bit_length() + 7) // 8
        return num.to_bytes(byte_length, byteorder='big')

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

    def data_encrypt(self, data: bytes, key: bytes = None, method: int = None) -> bytes:
        """
        Encrypt data based on the selected method.
        Supported methods:
            0: None, 1: XOR, 2: ChaCha20, 3: AES-128-CTR, 4: AES-192-CTR, 5: AES-256-CTR
        """
        try:
            if key is None:
                key = self.encryption_key
            if method is None:
                method = self.encryption_method

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

    def data_decrypt(self, data: bytes, key: bytes = None, method: int = None) -> bytes:
        """
        Decrypt data based on the selected method.
        Supported methods:
            0: None, 1: XOR, 2: ChaCha20, 3: AES-128-CTR, 4: AES-192-CTR, 5: AES-256-CTR
        """
        try:
            if key is None:
                key = self.encryption_key
            if method is None:
                method = self.encryption_method

            if method == 0:
                return data
            elif method == 1:
                return self.xor_data(data, key)
            elif method == 2:
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
                from cryptography.hazmat.backends import default_backend
                nonce = data[:16]
                encrypted_data = data[16:]
                algorithm = algorithms.ChaCha20(key, nonce)
                cipher = Cipher(algorithm, mode=None,
                                backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(encrypted_data)
                return decrypted_data
            elif method in (3, 4, 5):
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                from cryptography.hazmat.backends import default_backend
                nonce = data[:16]
                encrypted_data = data[16:]
                algorithm = algorithms.AES(key)
                cipher = Cipher(algorithm, modes.CTR(
                    nonce), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(
                    encrypted_data) + decryptor.finalize()
                return decrypted_data
            else:
                if self.logger:
                    self.logger.error(f"Unknown decryption method: {method}")
                return data
        except Exception as e:
            if self.logger:
                self.logger.error(
                    f"Failed to decrypt data <red>Maybe encryption key/method is wrong?</red>: {e}")
            return b''

    def generate_labels(self, domain: str, session_id: int, packet_type: int, data: bytes, mtu_chars: int, encode_data: bool = True) -> str:
        """
        Generate DNS labels with encoded VPN header and data.
        Args:
            domain (str): The domain name used for DNS tunneling.
            session_id (int): The session ID for the VPN header.
            packet_type (int): The packet type for the VPN header.
            data (bytes): The raw data to be encoded and sent.
            mtu_chars (int): Maximum characters per DNS query label.
            encode_data (bool): Whether to base-encode the data.

        Returns:
            list[str]: List of DNS labels with encoded data and VPN header.
        """

        # 1. Create VPN Header
        header = self.create_vpn_header(session_id, packet_type)

        # 2. Encode Data
        if encode_data:
            data = self.base_encode(data, lowerCaseOnly=True)

        # 3. Create Labels
        data_labels = []
        for i in range(0, len(data), mtu_chars):
            chunk = data[i:i + mtu_chars]
            chunk_label = self.data_to_labels(chunk)
            chunk_label += '.' + header + '.' + domain
            data_labels.append(chunk_label)

        return data_labels

    def calculate_upload_mtu(self, domain: str, mtu: int = 0) -> int:
        """
        Calculate the maximum upload MTU based on the domain length and DNS constraints.
        Args:
            domain (str): The domain name used for DNS tunneling.
            mtu (int): The desired MTU size. If 0, defaults to 512 bytes.
        Returns:
            int: Maximum upload MTU in bytes.
        """
        # 1. Hard Limits of DNS Protocol
        MAX_DNS_TOTAL = 253  # Max length of full domain name
        MAX_LABEL_LEN = 63   # Max length between dots

        # 2. Prepare Header Overhead
        # Create a dummy header to measure its exact encoded size
        # We assume worst-case scenario (encryption adds size + max base36 expansion)
        test_header = self.create_vpn_header(session_id=255, packet_type=255)

        # Header Overhead = Encoded Header + 1 dot separator
        header_overhead_chars = len(test_header) + 1

        # 3. Domain Overhead
        # Domain Overhead = length of domain + 1 dot separator (before domain)
        domain_overhead_chars = len(domain) + 1

        # 4. Calculate Remaining Space for Payload Characters
        # We subtract 1 extra byte for safety/null terminator
        total_overhead = header_overhead_chars + domain_overhead_chars + 1
        available_chars_space = MAX_DNS_TOTAL - total_overhead

        if available_chars_space <= 0:
            if self.logger:
                self.logger.error(
                    f"Domain {domain} is too long, no space for data.")
            return 0, 0

        # 5. Calculate Max Usable Characters (accounting for forced dots)
        # We need to find 'N' such that: N + dots_needed(N) <= available_chars_space
        max_payload_chars = 0
        for chars in range(available_chars_space, 0, -1):
            # Calculate how many dots are needed for this many characters
            # (One dot every 63 chars)
            needed_dots = (chars - 1) // MAX_LABEL_LEN
            total_len_needed = chars + needed_dots

            if total_len_needed <= available_chars_space:
                max_payload_chars = chars
                break

        # 6. Convert Max Characters to Max Bytes (Base36 Logic)
        # log2(36) ≈ 5.1699 bits per character
        bits_capacity = max_payload_chars * math.log2(36)
        safe_bytes_capacity = int(bits_capacity / 8)

        # 7. Respect User's Requested MTU (if provided and smaller)
        if mtu > 0 and mtu < safe_bytes_capacity:
            final_mtu_bytes = mtu
            # Recalculate chars for the report (approximation)
            final_mtu_chars = int((mtu * 8) / math.log2(36))
        else:
            final_mtu_bytes = safe_bytes_capacity
            final_mtu_chars = max_payload_chars

        return final_mtu_chars, final_mtu_bytes

    def data_to_labels(self, encoded_str: str) -> str:
        """
        Convert encoded string into DNS labels (max 63 chars each).

        Args:
            encoded_str (str): The base-encoded string to convert.

        Returns:
            str: The encoded string split into DNS labels separated by dots.
        """
        MAX_LABEL_LEN = 63
        labels = []
        for i in range(0, len(encoded_str), MAX_LABEL_LEN):
            labels.append(encoded_str[i:i + MAX_LABEL_LEN])
        return '.'.join(labels)

    def extract_vpn_header_from_labels(self, labels: str) -> bytes:
        """
        Extract and decode the VPN header from DNS labels.

        Args:
            labels (str): The DNS labels containing the encoded header.
        Returns:
            bytes: Decoded VPN header bytes.
        """

        try:
            label_parts = labels.split('.')
            # last part is the header
            header_encoded = label_parts[-1]
            header_decrypted = self.decode_and_decrypt_data(
                header_encoded, lowerCaseOnly=True)
            return header_decrypted
        except Exception as e:
            if self.logger:
                self.logger.error(
                    f"Failed to extract VPN header <red>Maybe encryption key/method is wrong?</red>: {e}")
            return b''

    def decode_and_decrypt_data(self, encoded_str: str, lowerCaseOnly=True) -> bytes:
        """
        Decode and decrypt the VPN data from an encoded string.

        Args:
            encoded_str (str): The base-encoded string containing the data.
        Returns:
            bytes: Decoded and decrypted VPN data bytes.
        """
        try:
            data_encrypted = self.base_decode(
                encoded_str, lowerCaseOnly=lowerCaseOnly)
            data_decrypted = self.data_decrypt(
                data_encrypted)
            return data_decrypted
        except Exception as e:
            if self.logger:
                self.logger.error(
                    f"Failed to decode and decrypt VPN data <red>Maybe encryption key/method is wrong?</red>: {e}")
            return b''

    def extract_vpn_data_from_labels(self, labels: str) -> bytes:
        """
        Extract and decode the VPN data from DNS labels.

        Args:
            labels (str): The DNS labels containing the encoded data.
        Returns:
            bytes: Decoded VPN data bytes.
        """

        try:
            label_parts = labels.split('.')
            # all parts except last are data
            data_encoded = ''.join(label_parts[:-1])
            data_decrypted = self.decode_and_decrypt_data(
                data_encoded, lowerCaseOnly=True)
            return data_decrypted
        except Exception as e:
            if self.logger:
                self.logger.error(
                    f"Failed to extract VPN data <red>Maybe encryption key/method is wrong?</red>: {e}")
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
    #
    def create_vpn_header(
        self,
        session_id: int,
        packet_type: int,
        base36_encode: bool = True
    ) -> bytes:
        """
        Construct custom VPN header for a DNS packet.

        Args:
            session_id (int): VPN session identifier (0-255).
            packet_type (int): Type of VPN packet (0-255).
            base36_encode (bool): Whether to base36 encode the header
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

        encrypted_header = self.data_encrypt(
            bytes(header)
        )

        if base36_encode:
            return self.base_encode(encrypted_header, lowerCaseOnly=True)
        else:
            return self.base_encode(encrypted_header, lowerCaseOnly=False)
