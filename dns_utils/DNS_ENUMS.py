# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

# References:
# https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf
# https://en.wikipedia.org/wiki/List_of_DNS_record_types
# https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml

# Packet Types
PACKET_TYPES = {
    "SERVER_UPLOAD_TEST": 0x00,
    "SERVER_DOWNLOAD_TEST": 0x01,
    "NEW_SESSION": 0x02,
    "SET_DOWNLOAD_MTU": 0x03,
    "SET_UPLOAD_MTU": 0x04,
    "SESSION_CLOSE": 0x05,
    "DATA_PACKET": 0x06,
    "PING": 0x07,

    "RESERVE_1": 0x08,
    "RESERVE_2": 0x09,
    "RESERVE_3": 0x0A,
    "RESERVE_4": 0x0B,
    "RESERVE_5": 0x0C,

    "QUIC_INIT": 0x0D,
    "QUIC_PACKET": 0x0E,
    "KCP_PACKET": 0x0F,
}

# DNS Resource Record Types (qType)
RESOURCE_RECORDS = {
    "A": 1,  # IPv4 address
    "NS": 2,  # Authoritative name server
    "MD": 3,  # Mail destination (obsolete)
    "MF": 4,  # Mail forwarder (obsolete)
    "CNAME": 5,  # Canonical name for an alias
    "SOA": 6,  # Start of a zone of authority
    "MB": 7,  # Mailbox domain name
    "MG": 8,  # Mail group member
    "MR": 9,  # Mail rename name
    "NULL": 10,  # Null record
    "WKS": 11,  # Well known services
    "PTR": 12,  # Domain name pointer
    "HINFO": 13,  # Host information
    "MINFO": 14,  # Mailbox information
    "MX": 15,  # Mail exchange
    "TXT": 16,  # Text strings
    "PR": 17,  # Responsible person
    "AFSDB": 18,  # AFS database
    "X25": 19,  # X.25 calling address
    "ISDN": 20,  # ISDN calling address
    "RT": 21,  # Router
    "NSAP": 22,  # NSAP address
    "NSAP-PTR": 23,  # Reverse NSAP address (deprecated)
    "SIG": 24,  # Security signature
    "KEY": 25,  # Security key
    "PX": 26,  # X.400 mail mapping
    "GPOS": 27,  # Geographical position (withdrawn)
    "AAAA": 28,  # IPv6 address
    "LOC": 29,  # Location information
    "NXT": 30,  # Next valid name in zone (deprecated)
    "EID": 31,  # Endpoint identifier
    "NIMLOC": 32,  # Nimrod locator
    "SRV": 33,  # Service locator
    "ATMA": 34,  # ATM address
    "NAPTR": 35,  # Naming authority pointer
    "KX": 36,  # Key exchange
    "CERT": 37,  # Certificate
    "A6": 38,  # IPv6 address (experimental)
    "DNAME": 39,  # Delegation name
    "SINK": 40,  # Kitchen sink (experimental)
    "OPT": 41,  # Option
    "APL": 42,  # Address prefix list
    "DS": 43,  # Delegation signer
    "SSHFP": 44,  # SSH public key fingerprint
    "IPSECKEY": 45,  # IPsec key
    "RPSIG": 46,  # DNSSEC signature
    "NSEC": 47,  # Next secure record
    "DNSKEY": 48,  # DNS key record
    "DHCID": 49,  # DHCP identifier
    "NSEC3": 50,  # Next secure record version 3
    "NSEC3PARAM": 51,  # NSEC3 parameters
    "TLSA": 52,  # TLSA certificate association
    "SMIMEA": 53,  # S/MIME certificate association
    # 54: Unassigned
    "HIP": 55,  # Host identity protocol
    "NINFO": 56,  # NINFO
    "RKEY": 57,  # RKEY
    "TALINK": 58,  # Trust anchor link
    "CDS": 59,  # Child DS
    "CDNSKEY": 60,  # Child DNSKEY
    "OPENPGPKEY": 61,  # OpenPGP key
    "CSYNC": 62,  # Child-to-parent synchronization
    "ZONEMD": 63,  # Zone message digest
    "SVCB": 64,  # Service binding
    "HTTPS": 65,  # HTTPS service
    "DSYNC": 66,  # DNSSEC synchronization
    "HHIT": 67,  # Host identity tag
    "BRID": 68,  # BRID
    # 69-98: Unassigned
    "SPF": 99,  # Sender policy framework
    "UINFO": 100,  # UINFO
    "UID": 101,  # UID
    "GID": 102,  # GID
    "UNSPEC": 103,  # UNSPEC
    "NID": 104,  # NID
    "L32": 105,  # L32
    "L64": 106,  # L64
    "LP": 107,  # LP
    "EUI48": 108,  # EUI-48 address
    "EUI64": 109,  # EUI-64 address
    # 110-127: Unassigned
    "NXNAME": 128,  # Non-existent domain (experimental)
    # 129-248: Unassigned
    "TKEY": 249,  # Transaction key
    "TSIG": 250,  # Transaction signature
    "IXFR": 251,  # Incremental zone transfer
    "AXFR": 252,  # Authoritative zone transfer
    "MAILB": 253,  # Mailbox-related RRs (MB, MG or MR)
    "MAILA": 254,  # Mail agent RRs (obsolete)
    "ANY": 255,  # Any type (*)
    "URI": 256,  # Uniform resource identifier
    "CAA": 257,  # Certification authority authorization
    "AVC": 258,  # Application visibility and control
    "DOA": 259,  # Digital object architecture
    "AMTRELAY": 260,  # AMT relay
    "RESINFO": 261,  # Resolution information
    "WALLET": 262,  # Digital wallet
    "CLA": 263,  # BP Convergence Layer Adapter
    "IPN": 264,  # IPN node address
    # 265-32767: Unassigned
    "TA": 32768,  # DNSSEC trust authority
    "DLV": 32769,  # DNSSEC lookaside validation
    # 32770-65279: Unassigned
    # 65280-65534: Private use
    # 65535: Reserved
}

# rCode Values
R_CODES = {
    "NO_ERROR": 0,  # No error condition
    # Format error - The name server was unable to interpret the query.
    "FORMAT_ERROR": 1,
    # Server failure - The name server was unable to process this query due to a problem with the name server.
    "SERVER_FAILURE": 2,
    # Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.
    "NAME_ERROR": 3,
    # Not Implemented - The name server does not support the requested kind of query.
    "NOT_IMPLEMENTED": 4,
    # Refused - The name server refuses to perform the specified operation for policy reasons.
    "REFUSED": 5,
    "YXDOMAIN": 6,  # YXDOMAIN - Name Exists when it should not
    "YXRRSET": 7,  # YXRRSET - RR Set Exists when it should not
    "NXRRSET": 8,  # NXRRSET - RR Set that should exist does not
    # Not Authorized - The name server is not authoritative for the zone or not authorized to answer the query.
    "NOT_AUTHORIZED": 9,
    # Not Zone - The name specified in the query is not within the zone specified in the zone section.
    "NOT_ZONE": 10,
}

# qClass Values
Q_CLASSES = {
    "IN": 1,  # Internet
    "CS": 2,  # CSNET (obsolete)
    "CH": 3,  # CHAOS
    "HS": 4,  # Hesiod
    "ANY": 255,  # Any class
}
