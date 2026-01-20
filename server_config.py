
# MasterDnsVPN Server Configuration File
# --------------------------------------
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026
#
# This file contains all configurable parameters for the MasterDnsVPN server.
# Adjust these settings to fit your deployment environment and security requirements.
#
# Note: Changes to this file require a server restart to take effect.

class master_dns_vpn_config:
    # Logging level for server output.
    # Options:
    #   DEBUG    - Detailed information, useful for debugging.
    #   INFO     - General operational messages.
    #   WARNING  - Indications of possible issues.
    #   ERROR    - Errors that prevent some operations.
    #   CRITICAL - Severe errors causing shutdown.
    LOG_LEVEL = "DEBUG"

    # UDP server listening address.
    # Set to "0.0.0.0" to listen on all network interfaces, or specify a particular IP.
    UDP_HOST = "127.0.0.1"

    # UDP server listening port.
    # Standard DNS port is 53. Change if running as non-root or for testing.
    UDP_PORT = 53

    # List of upstream DNS servers to which queries will be forwarded.
    # These should be reliable and fast DNS resolvers.
    # You can add or remove IP addresses as needed.
    DNS_SERVERS = [
        "192.168.1.1",  # Example: Local network DNS
        "8.8.8.8",      # Google Public DNS
        "1.1.1.1"       # Cloudflare DNS
    ]

    # SOCKS5 proxy configuration for outgoing connections.
    # If you want to tunnel outgoing traffic through a proxy, set the details here.
    # Leave as-is if not using a proxy, or update with your proxy credentials.
    SOCKS5_PROXY = {
        "host": "127.0.0.1",   # Proxy server address
        "port": 1080,           # Proxy server port
        "username": "user",    # Username for proxy authentication
        "password": "pass"     # Password for proxy authentication
    }

    # List of authorized user hashes.
    # Only users whose hash appears here will be allowed to connect.
    # Each hash must be a 32-character hexadecimal string (MD5 or similar).
    USERS = [
        "83d3192c9fb9e73cb3305baaaaaaaaaaa"  # Example user hash
    ]

    # Domains used for DNS tunneling.
    # These domains must be controlled by you and configured to point to this server.
    # Add multiple domains for redundancy or load balancing.
    DOMAIN = [
        "t.example.com",  # Main tunnel domain
        "b.example.com"   # Backup or secondary domain
    ]

    # VPN packet signature in hexadecimal (2-4 characters).
    # Used to identify and validate VPN packets in DNS queries.
    # Change this value to add a layer of obfuscation.
    VPN_PACKET_SIGN = "0032"

    # Global encryption method for VPN headers.
    # 0 - No encryption (not recommended)
    # 1 - XOR encryption (default, fast, basic security)
    # 2 - ChaCha20 encryption (stronger, slower, larger packets)
    # 3 - AES-128-CTR encryption (strong, slower, larger packets)
    # 4 - AES-192-CTR encryption (strong, slower, larger packets)
    # 5 - AES-256-CTR encryption (strongest, slowest, largest packets)
    # Choose based on your security and performance needs.
    GLOBAL_ENCRYPT = 1

    # Global encryption key in hexadecimal format.
    # The required length depends on the encryption method:
    #   XOR:         32 hex chars (16 bytes)
    #   ChaCha20:    64 hex chars (32 bytes)
    #   AES-128-CTR: 32 hex chars (16 bytes)
    #   AES-192-CTR: 48 hex chars (24 bytes)
    #   AES-256-CTR: 64 hex chars (32 bytes)
    #
    # WARNING: Changing it will disconnect all clients until they update their configs.
    # You can share this key securely with your users.
    GLOBAL_KEY = "32323232323232323232323232323232"
