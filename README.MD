# 🚀 MasterDnsVPN

## [نسخه فارسی](https://github.com/masterking32/MasterDnsVPN/blob/main/README_FA.MD) | [English Version](https://github.com/masterking32/MasterDnsVPN/blob/main/README.MD) | [Spanish Version](https://github.com/masterking32/MasterDnsVPN/blob/main/README_ES.MD)


MasterDnsVPN is a high-performance DNS tunneling tool designed to encapsulate VPN traffic within DNS queries. This project is specifically engineered to bypass strict network censorship and firewalls where traditional VPN protocols are blocked.

It features a custom **ARQ (Automatic Repeat Request)** implementation, ensuring TCP-like reliability and packet ordering over the inherently unreliable UDP-based DNS protocol.

---

⭐ If you find this project useful or interesting, please support it by giving a star to the repository! ⭐

---

## ✨ Key Features
- 🛡️ **Censorship Circumvention:** Leverages the DNS protocol to tunnel traffic through restricted environments.
- 🔐 **Robust Security:** Supports multiple encryption methods including XOR, AES-128-GCM, AES-192-GCM, and AES-256-GCM.
- ⚙️ **Smart MTU Management:** Automatically probes and synchronizes the optimal Maximum Transmission Unit (MTU) for both upload and download.
- 🔄 **Custom ARQ Protocol:** Solves packet loss and out-of-order delivery issues with dynamic retransmission and flow control.
- ⚡ **Resolver Load Balancing:** Supports multiple DNS resolvers with adaptive balancing strategies (Random, Round-robin, Best-loss).
- 🌐 **TCP Multiplexing:** Allows multiple local TCP connections to be multiplexed over a single DNS session.

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
- 🔐 cryptography (Required for AES encryption methods)
- 📝 loguru (For enhanced logging)

---

## 🚀 Installation & Usage

### 1. Install Dependencies

Clone the repository and install the required Python libraries:
```bash
git clone https://github.com/masterking32/MasterDnsVPN.git
cd MasterDnsVPN
pip install -r requirements.txt
```

### 2. Server Configuration

Copy the sample configuration:

```bash
cp server_config.py.simple server_config.py
```

Edit `server_config.py` to include your domain and target forwarding IP/Port.
- Install a proxy server (e.g., SOCKS5, VLESS, VMESS, SSH, MTProto, OpenVPN TCP and etc) on the server machine to forward traffic to the internet.
- Configure `FORWARD_IP` and `FORWARD_PORT` in `server_config.py` to point to your proxy server.
- Configure `DOMAIN` to match the subdomain you set up in your DNS records (e.g., `v.example.com`).
- After the first run, note the optimal MTU values for download and upload, then set `MAX_UPLOAD_MTU` and `MAX_DOWNLOAD_MTU` in `server_config.py` accordingly. This will significantly speed up subsequent runs.

### 3. Run the Server

```bash
python server.py
```

On the first run, the server will generate an encryption key. Save this key; you will need it to configure the client.

### 4. Configure the Client

Copy the sample client configuration:

```bash
cp client_config.py.simple client_config.py
```

Configure client_config.py:

 - DOMAINS: Your tunnel subdomain (e.g., v.example.com).

 - ENCRYPTION_KEY: The key provided by your server.

 - RESOLVER_DNS_SERVERS: List of public DNS resolvers (e.g., 8.8.8.8, 1.1.1.1).

### 5. Run the Client

```bash
python client.py
```

---

# 📝 Technical Notes

- ⚡ MTU Optimization: Upon connection, the client performs a binary search to find the maximum possible MTU for your specific path. This ensures maximum speed without packet fragmentation.

- 🔄 Adaptive Polling: The client uses smart backoff and idle-check mechanisms to reduce DNS overhead when no traffic is being transmitted.

- 🔒 Encryption: If using AES methods, the cryptography library is required. For low-resource devices, XOR (Method 1) is recommended.

---

## 🛠️ How It Works

```
┌────────────┐      DNS Queries     ┌────────────┐      ┌────────────┐
│  Client    │  <---------------->  │   Server   │ <--> │   Proxy    │
│ (Python)   │    (Encapsulated)    │  (Python)  │      │   Server   │
└────────────┘                      └────────────┘      └────────────┘
```

1. 🗝️ Client encodes and encrypts VPN data into DNS queries.
2. 🔓 Server decodes, decrypts, and forwards the traffic to your local Proxy Server (VLESS/SOCKS5).
3. 🔁 Replies are sent back via DNS responses.


## 🤝 Contributing
Contributions are welcome! Please fork the repository and create a pull request with your changes.

---

## 📄 License
This project is licensed under the MIT License. See the LICENSE file for details.

---

## 👨‍💻 Developer
Developed by [MasterkinG32](https://github.com/masterking32)
