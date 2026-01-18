# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026


from typing import Any


class dns_packet_parser:
    def __init__(self, logger: Any = None) -> None:
        self.logger = logger

    async def parse_dns_headers(self, data: bytes) -> Any:
        """
        Parse incoming DNS packet data.
        """
        try:
            headers = {}
            headers['id'] = int.from_bytes(data[0:2], byteorder='big')
            flags = int.from_bytes(data[2:4], byteorder='big')
            headers['qr'] = (flags >> 15) & 0x1
            headers['opcode'] = (flags >> 11) & 0xF
            headers['aa'] = (flags >> 10) & 0x1
            headers['tc'] = (flags >> 9) & 0x1
            headers['rd'] = (flags >> 8) & 0x1
            headers['ra'] = (flags >> 7) & 0x1
            headers['z'] = (flags >> 4) & 0x7
            headers['rcode'] = flags & 0xF
            headers['qdcount'] = int.from_bytes(data[4:6], byteorder='big')
            headers['ancount'] = int.from_bytes(data[6:8], byteorder='big')
            headers['nscount'] = int.from_bytes(data[8:10], byteorder='big')
            headers['arcount'] = int.from_bytes(data[10:12], byteorder='big')
            return headers
        except Exception as e:
            self.logger.error(f"Failed to parse DNS headers: {e}")
            return {}

    async def parse_dns_question(self, headers: dict, data: bytes, offset: int) -> Any:
        """
        Parse the DNS question section from the packet data.
        """
        try:
            qname = []
            if headers['qdcount'] == 0:
                return None, offset

            while True:
                length = data[offset]
                if length == 0:
                    offset += 1
                    break
                offset += 1
                qname.append(data[offset:offset + length].decode('utf-8'))
                offset += length
            qtype = int.from_bytes(data[offset:offset + 2], byteorder='big')
            offset += 2
            qclass = int.from_bytes(data[offset:offset + 2], byteorder='big')
            offset += 2
            question = {
                'qname': '.'.join(qname),
                'qtype': qtype,
                'qclass': qclass
            }
            return question, offset
        except Exception as e:
            self.logger.error(f"Failed to parse DNS question: {e}")
            return None, offset

    def _parse_name(self, data: bytes, offset: int):
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

    async def parse_dns_answer(self, headers: dict, data: bytes, offset: int) -> Any:
        """
        Parse the DNS answer section from the packet data.
        """
        try:
            if headers['ancount'] == 0:
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
            self.logger.error(f"Failed to parse DNS answer: {e}")
            return None, offset

    async def parse_dns_authority(self, headers: dict, data: bytes, offset: int) -> Any:
        """
        Parse the DNS authority section from the packet data.
        """
        try:
            if headers['nscount'] == 0:
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
            self.logger.error(f"Failed to parse DNS authority: {e}")
            return None, offset

    async def parse_dns_additional(self, headers: dict, data: bytes, offset: int) -> Any:
        """
        Parse the DNS additional section from the packet data.
        """
        try:
            if headers['arcount'] == 0:
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
            self.logger.error(f"Failed to parse DNS additional: {e}")
            return None, offset

    async def parse_dns_packet(self, data: bytes) -> Any:
        """
        Parse the entire DNS packet from the data.
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
            self.logger.error(f"Failed to parse DNS packet: {e}")
            return {}

    async def create_packet(self, dns_type: str = "A", domain: str = "google.com", is_request: bool = True) -> Any:
        """
        Create a DNS packet for the given domain and type.
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

                qtype = 1  # Default to A record
                if dns_type == "AAAA":
                    qtype = 28
                elif dns_type == "CNAME":
                    qtype = 5
                elif dns_type == "MX":
                    qtype = 15
                elif dns_type == "TXT":
                    qtype = 16
                elif dns_type == "NS":
                    qtype = 2
                elif dns_type == "SOA":
                    qtype = 6

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
                qtype = 1  # Default to A record
                if dns_type == "AAAA":
                    qtype = 28
                elif dns_type == "CNAME":
                    qtype = 5
                elif dns_type == "MX":
                    qtype = 15
                elif dns_type == "TXT":
                    qtype = 16
                elif dns_type == "NS":
                    qtype = 2
                elif dns_type == "SOA":
                    qtype = 6
                packet += qtype.to_bytes(2, byteorder='big')  # QTYPE
                packet += (1).to_bytes(2, byteorder='big')    # QCLASS

                # Answer Section
                # Name: pointer to offset 12 (0xC00C)
                packet += (0xC00C).to_bytes(2, byteorder='big')
                packet += qtype.to_bytes(2, byteorder='big')  # TYPE
                packet += (1).to_bytes(2, byteorder='big')    # CLASS
                # TTL = 0 (no cache)
                packet += (0).to_bytes(4, byteorder='big')
                if dns_type == "A":
                    packet += (4).to_bytes(2, byteorder='big')  # RDLENGTH
                    packet += bytes([127, 0, 0, 1])  # RDATA: 127.0.0.1
                elif dns_type == "AAAA":
                    packet += (16).to_bytes(2, byteorder='big')  # RDLENGTH
                    packet += bytes([0]*15 + [1])  # ::1
                else:
                    packet += (0).to_bytes(2, byteorder='big')  # RDLENGTH
                return bytes(packet), packet
        except Exception as e:
            self.logger.error(f"Failed to create DNS packet: {e}")
            return b'', b''
