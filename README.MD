# 🚀 MasterDnsVPN

## [نسخه فارسی](https://github.com/masterking32/MasterDnsVPN/blob/main/README_FA.MD) | [English Version](https://github.com/masterking32/MasterDnsVPN/blob/main/README.MD) | [Spanish Version](https://github.com/masterking32/MasterDnsVPN/blob/main/README_ES.MD)


MasterDnsVPN is a high-performance DNS tunneling tool designed to encapsulate VPN traffic within DNS queries. This project is specifically engineered to bypass strict network censorship and firewalls where traditional VPN protocols are blocked.

It features a custom **ARQ (Automatic Repeat Request)** implementation, ensuring TCP-like reliability and packet ordering over the inherently unreliable UDP-based DNS protocol.

---

⭐ If you find this project useful or interesting, please support it by giving a star to the repository! ⭐

---

## ✨ Key Features
- 🛡️ **Censorship Circumvention:** Leverages the DNS protocol to tunnel traffic through restricted environments.
- 🔐 **Robust Security:** Supports multiple encryption methods including XOR, ChaCha20, AES-128-CTR, AES-192-CTR, and AES-256-CTR.
- ⚙️ **Smart MTU Management:** Automatically probes and synchronizes the optimal Maximum Transmission Unit (MTU) for both upload and download.
- 🔄 **Custom ARQ Protocol:** Solves packet loss and out-of-order delivery issues with dynamic retransmission and flow control.
- ⚡ **Resolver Load Balancing:** Supports multiple DNS resolvers with adaptive balancing strategies (Random, Round-robin, Best-loss).
- 🌐 **TCP Multiplexing:** Allows multiple local TCP connections to be multiplexed over a single DNS session.
- 📡 **Multi-Path Packet Duplication:** Each packet can be sent simultaneously through multiple resolver+domain paths for maximum reliability under extreme network conditions.

---

## 🛠️ Network Prerequisites (DNS Configuration)

To make the tunnel functional, you must own a domain and configure the following records in your DNS management panel (e.g., Cloudflare):

1. **A Record:** Create an **A** record pointing to your server's public IP.
   - Example: `s.example.com` -> `1.2.3.4`
2. **NS Record:** Create an **NS** record for your tunnel subdomain pointing to the A record created above.
   - Example: `v.example.com` -> `s.example.com`

> 💡 **Pro Tip:** The shorter your domain and subdomain names are (e.g., `v.ex.com`), the more space remains for actual data payloads in each DNS packet, significantly increasing throughput.

---

## 📦 Requirements

- 🐍 Python 3.7 or higher
- 🔐 `cryptography` (Required for AES/ChaCha20 encryption methods)
- 📝 `loguru` (For enhanced logging)

---

## 🚀 Installation & Usage

### Option A: Download Pre-built Executable (Recommended)

You can download the latest pre-built binary for your platform — no Python installation required.

**Client Downloads:**

| Platform | Download |
|----------|----------|
| 🪟 Windows (AMD64) | [MasterDnsVPN_Client_Windows_AMD64.zip](https://github.com/masterking32/MasterDnsVPN/releases/latest/download/MasterDnsVPN_Client_Windows_AMD64.zip) |
| 🐧 Linux (AMD64) | [MasterDnsVPN_Client_Linux_AMD64.zip](https://github.com/masterking32/MasterDnsVPN/releases/latest/download/MasterDnsVPN_Client_Linux_AMD64.zip) |
| 🐧 Linux (ARM64) | [MasterDnsVPN_Client_Linux_ARM64.zip](https://github.com/masterking32/MasterDnsVPN/releases/latest/download/MasterDnsVPN_Client_Linux_ARM64.zip) |
| 🍎 macOS (ARM64) | [MasterDnsVPN_Client_MacOS_ARM64.zip](https://github.com/masterking32/MasterDnsVPN/releases/latest/download/MasterDnsVPN_Client_MacOS_ARM64.zip) |

**Server Downloads:**

| Platform | Download |
|----------|----------|
| 🪟 Windows (AMD64) | [MasterDnsVPN_Server_Windows_AMD64.zip](https://github.com/masterking32/MasterDnsVPN/releases/latest/download/MasterDnsVPN_Server_Windows_AMD64.zip) |
| 🐧 Linux (AMD64) | [MasterDnsVPN_Server_Linux_AMD64.zip](https://github.com/masterking32/MasterDnsVPN/releases/latest/download/MasterDnsVPN_Server_Linux_AMD64.zip) |
| 🐧 Linux (ARM64) | [MasterDnsVPN_Server_Linux_ARM64.zip](https://github.com/masterking32/MasterDnsVPN/releases/latest/download/MasterDnsVPN_Server_Linux_ARM64.zip) |
| 🍎 macOS (ARM64) | [MasterDnsVPN_Server_MacOS_ARM64.zip](https://github.com/masterking32/MasterDnsVPN/releases/latest/download/MasterDnsVPN_Server_MacOS_ARM64.zip) |

Each client ZIP contains the executable and a `client_config.toml` template file. Each server ZIP contains the executable and a `server_config.toml` template file.

**Steps:**

1. Extract the ZIP archive.
2. Open `client_config.toml` in any text editor and set your values:
   - `ENCRYPTION_KEY` — copy from your server log on first run.
   - `DOMAINS` — your tunnel subdomain (e.g. `v.example.com`).
   - `RESOLVER_DNS_SERVERS` — public DNS resolvers (e.g. `8.8.8.8`).
3. Place `client_config.toml` in the **same folder** as the executable and run it.

---

### Option B: Run from Source

#### 1. Install Dependencies

Clone the repository and install the required Python libraries:
```bash
git clone https://github.com/masterking32/MasterDnsVPN.git
cd MasterDnsVPN
pip install -r requirements.txt
```

#### 2. Server Configuration

Copy the sample configuration:

```bash
cp server_config.toml.simple server_config.toml
```

Edit `server_config.toml` to include your domain and target forwarding IP/Port.
- Install a proxy server (e.g., SOCKS5, VLESS, VMESS, SSH, MTProto, OpenVPN TCP and etc) on the server machine to forward traffic to the internet.
- Configure `FORWARD_IP` and `FORWARD_PORT` in `server_config.toml` to point to your proxy server.
- Configure `DOMAIN` to match the subdomain you set up in your DNS records (e.g., `v.example.com`).

#### 3. Run the Server

```bash
python server.py
```

On the first run, the server will generate an encryption key. **Save this key**; you will need it to configure the client.

#### 4. Configure the Client

Copy the sample client configuration:

```bash
cp client_config.toml.simple client_config.toml
```

Edit `client_config.toml`:

 - `DOMAINS`: Your tunnel subdomain (e.g., `v.example.com`).

 - `ENCRYPTION_KEY`: The key displayed in the server log.

 - `RESOLVER_DNS_SERVERS`: List of public DNS resolvers (e.g., `8.8.8.8`, `1.1.1.1`).

#### 5. Run the Client

```bash
python client.py
```

The client starts a local SOCKS5 proxy on `127.0.0.1:1080` (configurable via `LISTEN_IP` / `LISTEN_PORT`). Point your browser or application to this proxy to route traffic through the tunnel.

---

## 🚨 Emergency Tip: Severe Network Disruption

> **When the network is almost completely down and only DNS queries are getting through (extremely high packet loss and disruption):**

1. **Collect as many DNS resolver IP addresses as possible.** Add them all to `RESOLVER_DNS_SERVERS` in `client_config.toml`. You can use public resolvers from Google (`8.8.8.8`, `8.8.4.4`), Cloudflare (`1.1.1.1`, `1.0.0.1`), Quad9 (`9.9.9.9`), OpenDNS (`208.67.222.222`, `208.67.220.220`), and others.

2. **Increase `PACKET_DUPLICATION_COUNT`** in `client_config.toml`. This parameter controls how many different resolver+domain paths each packet is sent through **simultaneously**.

   - With 6 resolvers and 2 domains, you have **12 potential paths**.
   - Setting `PACKET_DUPLICATION_COUNT = 6` means every packet is sent across 6 different paths at once.
   - Even if 5 out of 6 paths fail, the packet still arrives via the surviving path.

   > ⚠️ **Trade-off:** Higher duplication increases bandwidth usage and CPU load proportionally. A value of `3`–`6` is a good balance during disruptions. The ARQ layer on the server automatically deduplicates received copies so your application only sees each packet once.

3. **Add multiple tunnel domains** (`DOMAINS` list) to further multiply the number of available paths.

---

## ⚙️ Configuration Reference

### 🖥️ Server — `server_config.toml`

> 🔑 The encryption key is **auto-generated** on first run and saved to `encrypt_key.txt` next to the server executable. It is also printed in the server log. Copy it to the client's `ENCRYPTION_KEY` field. Delete `encrypt_key.txt` and restart to rotate the key.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `LOG_LEVEL` | `"INFO"` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `UDP_HOST` | `"0.0.0.0"` | IP address the DNS/UDP server binds to. `"0.0.0.0"` = all interfaces. |
| `UDP_PORT` | `53` | UDP port for the DNS server. Port `53` (standard DNS) requires root/admin privileges. |
| `DOMAIN` | `["t.example.com"]` | Tunnel domain(s) this server accepts. Must match the client's `DOMAINS` list. |
| `DATA_ENCRYPTION_METHOD` | `1` | Encryption algorithm. **Must match the client.** `0`=None, `1`=XOR, `2`=ChaCha20, `3`=AES-128-CTR, `4`=AES-192-CTR, `5`=AES-256-CTR |
| `SESSION_TIMEOUT` | `300` | Inactivity time (seconds) before a client session expires. |
| `SESSION_CLEANUP_INTERVAL` | `60` | Interval (seconds) at which expired sessions are removed. |
| `FORWARD_IP` | `"127.0.0.1"` | IP of the local proxy/service that decrypted traffic is forwarded to. |
| `FORWARD_PORT` | `8080` | Port of the local proxy/service (e.g. `1080` for SOCKS5, `443` for VLESS). |
| `ARQ_WINDOW_SIZE` | `600` | ARQ window size (number of unacknowledged packets allowed in flight). Larger window sizes can improve performance on high-latency connections but may increase memory usage. |

### 💻 Client — `client_config.toml`

| Parameter | Default | Description |
|-----------|---------|-------------|
| `LOG_LEVEL` | `"INFO"` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `RESOLVER_DNS_SERVERS` | `["8.8.8.8"]` | Public DNS resolvers that tunnel queries are forwarded through. Add multiple for redundancy and load balancing. |
| `MIN_UPLOAD_MTU` | `40` | Minimum upload MTU (bytes) a resolver must achieve to be used. Set to `0` to disable. |
| `MIN_DOWNLOAD_MTU` | `40` | Minimum download MTU (bytes) a resolver must achieve to be used. Set to `0` to disable. |
| `MAX_UPLOAD_MTU` | `160` | Upper bound (bytes) for upload MTU auto-probing. |
| `MAX_DOWNLOAD_MTU` | `200` | Upper bound (bytes) for download MTU auto-probing. |
| `RESOLVER_BALANCING_STRATEGY` | `1` | Load-balancing strategy across resolvers: `1`=Random, `2`=Round-Robin, `3`=Least-Loss |
| `DOMAINS` | `["t.example.com"]` | Tunnel domain(s) pointing to your server via NS records. Add multiple for multi-path redundancy. |
| `DATA_ENCRYPTION_METHOD` | `1` | Encryption algorithm. **Must match the server.** `0`=None, `1`=XOR, `2`=ChaCha20, `3`=AES-128-CTR, `4`=AES-192-CTR, `5`=AES-256-CTR |
| `ENCRYPTION_KEY` | `""` | Key from the server's `encrypt_key.txt` or first-run log. Must match the server. |
| `DNS_QUERY_TIMEOUT` | `5` | Seconds to wait for a DNS response before considering a query failed. |
| `LISTEN_IP` | `"127.0.0.1"` | Local IP the SOCKS5 proxy listens on. |
| `LISTEN_PORT` | `1080` | Local port for the SOCKS5 proxy. Point your application to this address. |
| `NUM_DNS_WORKERS` | `4` | Number of concurrent async DNS worker tasks. Increase for higher traffic. |
| `PACKET_DUPLICATION_COUNT` | `3` | How many resolver+domain paths each packet is sent through simultaneously. Higher = more reliable but more bandwidth. |
| `ARQ_WINDOW_SIZE` | `600` | ARQ window size (number of unacknowledged packets allowed in flight). Larger window sizes can improve performance on high-latency connections but may increase memory usage. |

---

## 🛠️ How It Works

### System Architecture

```mermaid
graph TD
    subgraph Client_Machine ["🖥️ Client Machine"]
        App["📱 Local App\n(Browser / any TCP app)"]
        Client["🐍 MasterDnsVPN Client\n(SOCKS5 listener on :1080)"]
    end

    subgraph Public_DNS ["🌐 Public DNS Resolvers"]
        R1["📡 8.8.8.8 (Google)"]
        R2["📡 1.1.1.1 (Cloudflare)"]
        R3["📡 9.9.9.9 (Quad9)"]
        RN["📡 ...more resolvers"]
    end

    subgraph Server_Machine ["🖥️ VPN Server Machine"]
        Server["🐍 MasterDnsVPN Server\n(UDP :53 — authoritative NS)"]
        Proxy["🔀 Local Proxy\n(VLESS / SOCKS5 / SSH)"]
    end

    Internet["🌍 Internet"]

    App -->|"TCP stream"| Client
    Client -->|"Encrypted DNS TXT queries\n(path 1: domain A)"| R1
    Client -->|"Encrypted DNS TXT queries\n(path 2: domain A)"| R2
    Client -->|"Encrypted DNS TXT queries\n(path 3: domain B)"| R3
    Client -->|"...duplicate packets\nacross N paths"| RN

    R1 -->|"NS lookup → routes to\nauthoritative server"| Server
    R2 --> Server
    R3 --> Server
    RN --> Server

    Server -->|"Decrypted TCP data"| Proxy
    Proxy -->|"Response"| Server
    Server -->|"Encrypted DNS responses"| R1
    R1 -->|"DNS response"| Client
```

### Packet Flow (Sequence Diagram)

```mermaid
sequenceDiagram
    participant App as 📱 Local App
    participant Client as 🐍 Client (ARQ)
    participant DNS1 as 📡 Resolver 8.8.8.8
    participant DNS2 as 📡 Resolver 1.1.1.1
    participant Server as 🖥️ Server (ARQ)
    participant Proxy as 🔀 Proxy

    App->>Client: TCP data (continuous stream)

    Note over Client: 1. Split data into MTU-sized chunks
    Note over Client: 2. Assign sequence number (ARQ)
    Note over Client: 3. Encrypt + encode into DNS TXT label
    Note over Client: 4. Duplicate to N resolver+domain paths

    par Simultaneous multi-path send (PACKET_DUPLICATION_COUNT = 2)
        Client->>DNS1: DNS TXT query — seq#5 — domain A
        Client->>DNS2: DNS TXT query — seq#5 — domain B
    end

    DNS1->>Server: Forward (authoritative NS for domain A)
    DNS2->>Server: Forward (authoritative NS for domain B)

    Note over Server: ARQ deduplicates copies of seq#5
    Note over Server: Reorder out-of-sequence packets
    Note over Server: Decrypt and reassemble stream

    Server->>Proxy: Forward reassembled TCP data
    Proxy-->>Server: Response data

    Note over Server: Split response, encrypt, enqueue

    Server-->>DNS1: DNS TXT response — seq#5 ack + data
    DNS1-->>Client: DNS response

    Note over Client: ARQ reorders + delivers in-order to App

    Client-->>App: TCP data (in-order)
```

### Key Concepts

| Concept | Description |
|---|---|
| **Session** | One client connection; up to 255 concurrent sessions per server |
| **Stream** | A single TCP connection multiplexed over a session |
| **MTU Probing** | Binary search at startup to find the maximum DNS payload size for your path |
| **ARQ** | Sequence numbers + retransmission ensure no data loss over UDP/DNS |
| **PACKET_DUPLICATION_COUNT** | Each packet is sent through this many resolver+domain paths simultaneously |
| **Resolver Balancing** | Strategies: Random (1), Round-Robin (2), Least-Loss (3) |

---

## 📝 Technical Notes

- ⚡ **MTU Optimization:** Upon connection, the client performs a binary search to find the maximum possible MTU for your specific path. This ensures maximum speed without packet fragmentation.

- 🔄 **Adaptive Polling:** The client uses smart backoff and idle-check mechanisms to reduce DNS overhead when no traffic is being transmitted.

- 🔒 **Encryption:** For AES/ChaCha20 methods the `cryptography` library is required. For low-resource devices, XOR (Method 1) is recommended.

- 🔁 **Multiple Concurrent Servers:** You can run multiple independent MasterDnsVPN server instances, each with a different tunnel domain, and list all domains in the client's `DOMAINS` array. The client will treat each domain+resolver combination as a separate path, automatically distributing and duplicating traffic across all of them.

---

## 🤝 Contributing
Contributions are welcome! Please fork the repository and create a pull request with your changes.

---

## 📄 License
This project is licensed under the MIT License. See the LICENSE file for details.

---

## 👨‍💻 Developer
Developed by [MasterkinG32](https://github.com/masterking32)
