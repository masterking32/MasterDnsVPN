# MasterDnsVPN Core

A high-performance DNS tunneling system carrying TCP and SOCKS traffic over recursive DNS queries and responses under restrictive network conditions.

## Language

### Core Components

**Client**:
The local program running on the user device. It intercepts local TCP or SOCKS traffic, packages it into DNS queries, and orchestrates transmission across resolvers.
_Avoid_: Agent, Consumer, Local host

**Server**:
The remote program running on an internet-connected host. It acts as the authoritative DNS server for the tunnel domain, decodes incoming DNS queries from clients, and forwards the traffic to the destination.
_Avoid_: Upstream server, Relay, Gateway

### Network & Routing

**Resolver**:
An external recursive DNS server (such as an ISP recursor or public DNS) used as an intermediary to relay queries between the Client and the Server.
_Avoid_: Nameserver, Upstream DNS, Server (when referring to resolvers)

**Resolver Endpoint**:
The concrete transport address (`IP:Port`) of a Resolver.
_Avoid_: Target, Server address

**Tunnel Domain**:
The domain name (e.g. `v.example.com`) delegated to the Server that the Client uses to build its DNS queries.
_Avoid_: Hostname, Zone

**Tunnel Path** (or **Path**):
A distinct transmission path carrying DNS tunnel queries, defined by one Resolver Endpoint and one Tunnel Domain.
_Avoid_: Pairing, Route, Connection, Channel, Tuple

**Resolver Pool**:
The client-side collection of candidate Tunnel Paths, tracked across five authoritative lifecycle states:
- **Untested**: Initial state before completed qualification.
- **Checking**: Leased for initial qualification or background rechecking.
- **Active**: Qualified and admitted to carry live traffic.
- **Standby**: Qualified, compatible with current Session requirements, and eligible for promotion.
- **Rejected**: Qualification failed or became incompatible; eligible for retry.
_Avoid_: Server pool, Balancer pool, Route pool

**Active Path**:
A Tunnel Path admitted to carry live traffic in the Resolver Pool.
_Avoid_: Active Resolver, Active server, Active pairing, Active route

**Standby Path**:
A qualified, non-active Tunnel Path compatible with current Session requirements and eligible for promotion into active duty if an active path degrades or capacity opens. Distinguished from Untested, Checking, or Rejected candidates.
_Avoid_: Standby Resolver, Standby server, Standby pairing, Standby route

**Resolver Balancer**:
The client component that selects which active Tunnel Path transmits each outgoing query. By default, it routes using the common composite evaluation score (RTT, loss, measured burst throughput) shared across diagnostics and pool rankings, while preserving explicit user strategies (e.g. Round Robin, Lowest Latency, Least Loss, Loss Then Latency).
_Avoid_: MLQ, Scheduler, Retrier

**Destination**:
The final internet host and port (e.g. `example.com:443`) that the user application connects to through the tunnel.
_Avoid_: Target, Upstream host, Final endpoint

**Egress DNS**:
The external recursive DNS servers queried directly by the Server when satisfying client DNS resolution requests (`DNS_QUERY_REQ`).
_Avoid_: DNS upstream servers, Server resolvers

### Multiplexing & Data Units

**Tunnel**:
The end-to-end transport carrying encapsulated traffic over DNS query-response exchanges.
_Avoid_: Proxy, VPN, Pipe

**Session**:
The long-lived authenticated association established between a Client and a Server.
_Avoid_: Connection, Socket, Channel

**Stream**:
An individual user connection (such as a single TCP connection or SOCKS request) carried within a Session.
_Avoid_: Flow, Tunnel, Sub-session

**Packet**:
The protocol data unit carrying a header (stream ID, sequence number, flags) and payload before DNS encoding.
_Avoid_: Frame, Message, Datagram

**Fragment**:
A slice of a Packet sized to fit within DNS label and record length limits.
_Avoid_: Chunk, Segment, Packet part

### Reliability & Scheduling

**ARQ (Automatic Repeat reQuest)**:
The selective-repeat protocol that guarantees reliable, ordered packet delivery over unreliable DNS transports.
_Avoid_: Retrier, TCP retransmit, Handshake

**Packet Priority Queue (MLQ)**:
The internal multi-level queue that prioritizes urgent packets (such as control signals, ACKs, and retransmissions) over standard stream data before transmission.
_Avoid_: Balancer, Resolver queue

**In-flight**:
A query or packet transmitted onto the network that has not yet received an acknowledgment or matching DNS response.
_Avoid_: Pending, Unresolved, Open

**Duplication**:
The mechanism of sending copies of the same fragment across different paths to survive extreme packet loss.
_Avoid_: Multipath, Cloning, Redundancy
