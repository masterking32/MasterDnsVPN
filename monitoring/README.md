# MasterDnsVPN Grafana Monitoring

Prometheus + Grafana monitoring for a MasterDnsVPN server running on Linux.

## Overview

```
MasterDnsVPN Server (UDP :53)
        │
        ▼
iptables byte counters ──┐
journalctl session logs ─┤
systemctl service state ─┤
                         ▼
              masterdns_exporter.py (:9101)
                         │
                         ▼
                    Prometheus (:9090)
                         │
                         ▼
                   Grafana Dashboard (:3000)
```

The exporter runs as a systemd service on the same host as MasterDnsVPN. It polls three data sources every 15 seconds and exposes Prometheus metrics at `/metrics`.

## Installation

### Automatic (via main installer)

When running `server_linux_install.sh`, you will be prompted:

```
>>> Do you want to install Grafana monitoring dashboard? (y/N):
```

Answering **y** installs everything automatically.

### Automatic (standalone)

If MasterDnsVPN is already installed, run the monitoring installer directly:

```bash
sudo bash /path/to/masterdnsvpn/monitoring/install.sh
```

The script auto-detects `INSTALL_DIR`, package manager, and firewall. It will:

1. Install Python 3 and Docker if missing
2. Add iptables OUTPUT rule for traffic accounting
3. Deploy and start the exporter as a systemd service
4. Launch Prometheus + Grafana via Docker Compose
5. Open firewall ports 3000 and 9090

### Manual Setup

If you prefer to set things up manually, follow the steps below.

#### Prerequisites

- MasterDnsVPN server running as `masterdnsvpn.service`
- Python 3 installed on the host
- Docker and Docker Compose
- `iptables` installed

#### Step 1: iptables Accounting Rules

The exporter reads iptables byte counters. The INPUT rule for `dpt:53` is created by the main installer. You need to add the OUTPUT rule:

```bash
sudo iptables -I OUTPUT -p udp --sport 53 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4
```

Verify:

```bash
sudo iptables -L INPUT -v -n --line-numbers | grep "udp dpt:53"
sudo iptables -L OUTPUT -v -n --line-numbers | grep "udp spt:53"
```

#### Step 2: Deploy the Exporter

Create the systemd service:

```bash
sudo tee /etc/systemd/system/masterdns-exporter.service > /dev/null << 'EOF'
[Unit]
Description=MasterDnsVPN Prometheus Exporter
After=network.target masterdnsvpn.service
Wants=masterdnsvpn.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /path/to/monitoring/exporters/masterdns_exporter.py
Restart=always
RestartSec=5
Environment=PORT=9101
Environment=SERVICE_NAME=masterdnsvpn
Environment=POLL_INTERVAL=15

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable masterdns-exporter
sudo systemctl start masterdns-exporter
```

**Environment variables:**

| Variable        | Default        | Description                            |
| --------------- | -------------- | -------------------------------------- |
| `PORT`          | `9101`         | HTTP port for `/metrics` endpoint      |
| `SERVICE_NAME`  | `masterdnsvpn` | systemd unit name to monitor           |
| `POLL_INTERVAL` | `15`           | Seconds between data collection cycles |

Verify:

```bash
curl -s http://127.0.0.1:9101/metrics
```

#### Step 3: Start Prometheus and Grafana

```bash
cd /path/to/monitoring
docker compose up -d
```

Verify Prometheus target:

```bash
curl -s http://localhost:9090/api/v1/targets | python3 -c "
import json,sys
for t in json.load(sys.stdin)['data']['activeTargets']:
    if t['labels']['job'] == 'masterdns':
        print(f\"Health: {t['health']}\")
"
```

Open Grafana at `http://<server-ip>:3000` (default credentials: `admin` / `admin`).

The MasterDnsVPN dashboard is auto-provisioned and ready to use.

## Metrics Reference

| Metric                             | Type    | Description                                 |
| ---------------------------------- | ------- | ------------------------------------------- |
| `masterdns_server_up`              | gauge   | 1 if systemd service is active, 0 otherwise |
| `masterdns_server_uptime_seconds`  | gauge   | Server uptime in seconds                    |
| `masterdns_sessions_alive`         | gauge   | Currently alive tunnel sessions             |
| `masterdns_sessions_created_total` | counter | Total sessions created since boot           |
| `masterdns_rx_bytes_total`         | counter | Total bytes received (UDP dpt:53)           |
| `masterdns_tx_bytes_total`         | counter | Total bytes transmitted (UDP spt:53)        |
| `masterdns_exporter_up`            | gauge   | 1 if exporter is running                    |

## Dashboard Panels

| Panel                    | Type       | Query                                                                         |
| ------------------------ | ---------- | ----------------------------------------------------------------------------- |
| Server Status            | stat       | `masterdns_server_up` with value mappings (0=DOWN, 1=UP)                      |
| Active Sessions          | stat       | `masterdns_sessions_alive`                                                    |
| Traffic (Selected Range) | stat       | `increase(rx[$__range]) + increase(tx[$__range])`                             |
| Traffic (Today)          | stat       | Same as above with `timeFrom: now/d`                                          |
| Throughput               | timeseries | `rate(masterdns_rx_bytes_total[2m])` and `rate(masterdns_tx_bytes_total[2m])` |
| Sessions Over Time       | timeseries | `masterdns_sessions_alive` (step-after)                                       |

## Uninstall

```bash
# Stop and remove containers
docker compose -f /path/to/monitoring/docker-compose.yml down -v

# Stop and remove exporter
sudo systemctl stop masterdns-exporter
sudo systemctl disable masterdns-exporter
sudo rm /etc/systemd/system/masterdns-exporter.service
sudo systemctl daemon-reload

# Remove iptables OUTPUT rule (optional)
sudo iptables -D OUTPUT -p udp --sport 53 -j ACCEPT
```

Deleting the `monitoring/` directory has zero impact on MasterDnsVPN itself.

## Troubleshooting

```bash
# Check exporter service
sudo systemctl status masterdns-exporter

# View exporter logs
sudo journalctl -u masterdns-exporter -f

# Check iptables counters are incrementing
sudo iptables -L INPUT -v -n -x | grep "dpt:53"
sudo iptables -L OUTPUT -v -n -x | grep "spt:53"

# Verify Prometheus can reach the exporter
curl -s http://127.0.0.1:9101/metrics | head -5

# Check container status
docker compose -f /path/to/monitoring/docker-compose.yml ps

# Test a Prometheus query
curl -s 'http://localhost:9090/api/v1/query?query=masterdns_server_up'
```

### Common Issues

| Problem                  | Cause                                           | Fix                                                                        |
| ------------------------ | ----------------------------------------------- | -------------------------------------------------------------------------- |
| `rx_bytes = 0`           | iptables rule for `dpt:53` not first match      | Move the UDP 53 rule above any other matching rules                        |
| Prometheus target `down` | Firewall blocking port 9101 from Docker network | Add `extra_hosts` to Docker Compose or allow port in firewall              |
| Sessions always 0        | Wrong `SERVICE_NAME` env var                    | Set it to match your systemd unit (e.g. `masterdnsvpn`)                    |
| Uptime always 0          | `systemctl show` timestamp format mismatch      | Check `systemctl show masterdnsvpn --property=ActiveEnterTimestamp` output |
| Grafana shows "No data"  | Prometheus not scraping                         | Check Prometheus targets page at `http://<ip>:9090/targets`                |
