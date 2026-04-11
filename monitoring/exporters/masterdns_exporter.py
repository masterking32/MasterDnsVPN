#!/usr/bin/env python3
"""MasterDnsVPN Prometheus Exporter

Collects metrics from systemctl, iptables, and journalctl and exposes them
on an HTTP /metrics endpoint in Prometheus exposition format.

No external dependencies -- stdlib only.
"""

import os
import re
import subprocess
import threading
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = int(os.environ.get("PORT", "9101"))
SERVICE_NAME = os.environ.get("SERVICE_NAME", "masterdnsvpn")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "15"))

_metrics_lock = threading.Lock()
_metrics: dict[str, float] = {
    "masterdns_server_up": 0,
    "masterdns_server_uptime_seconds": 0,
    "masterdns_sessions_alive": 0,
    "masterdns_sessions_created_total": 0,
    "masterdns_rx_bytes_total": 0,
    "masterdns_tx_bytes_total": 0,
    "masterdns_exporter_up": 1,
}

METRIC_META = {
    "masterdns_server_up": ("gauge", "MasterDnsVPN server systemd service is active"),
    "masterdns_server_uptime_seconds": ("gauge", "MasterDnsVPN server uptime in seconds"),
    "masterdns_sessions_alive": ("gauge", "Currently alive tunnel sessions"),
    "masterdns_sessions_created_total": ("counter", "Total sessions created since boot"),
    "masterdns_rx_bytes_total": ("counter", "Bytes received on UDP port 53 (client to server)"),
    "masterdns_tx_bytes_total": ("counter", "Bytes transmitted on UDP port 53 (server to client)"),
    "masterdns_exporter_up": ("gauge", "Exporter is running"),
}

RENDER_ORDER = [
    "masterdns_server_up",
    "masterdns_server_uptime_seconds",
    "masterdns_sessions_alive",
    "masterdns_sessions_created_total",
    "masterdns_rx_bytes_total",
    "masterdns_tx_bytes_total",
    "masterdns_exporter_up",
]


def _run(cmd: list[str], timeout: int = 10) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


def collect_service_state() -> tuple[float, float]:
    """Return (up, uptime_seconds) for the monitored systemd service."""
    out = _run(["systemctl", "is-active", SERVICE_NAME])
    if out.strip() != "active":
        return 0.0, 0.0

    ts_out = _run([
        "systemctl", "show", SERVICE_NAME, "--property=ActiveEnterTimestamp",
    ])
    match = re.search(r"ActiveEnterTimestamp=(.+)", ts_out)
    if not match:
        return 1.0, 0.0

    raw = match.group(1).strip()
    if not raw:
        return 1.0, 0.0

    try:
        dt = datetime.strptime(raw, "%a %Y-%m-%d %H:%M:%S %Z")
        dt = dt.replace(tzinfo=timezone.utc)
        uptime = max(0.0, (datetime.now(timezone.utc) - dt).total_seconds())
    except ValueError:
        uptime = 0.0

    return 1.0, uptime


def _parse_iptables_bytes(chain: str, pattern: str) -> float:
    """Parse exact byte count from iptables -L <chain> -v -n -x."""
    out = _run(["iptables", "-L", chain, "-v", "-n", "-x"])
    for line in out.splitlines():
        if pattern in line:
            parts = line.split()
            if len(parts) >= 2:
                try:
                    return float(parts[1])
                except ValueError:
                    pass
    return 0.0


def collect_traffic() -> tuple[float, float]:
    rx = _parse_iptables_bytes("INPUT", "dpt:53")
    tx = _parse_iptables_bytes("OUTPUT", "spt:53")
    return rx, tx


def collect_sessions() -> tuple[float, float]:
    """Parse journalctl for session created/closed/expired events.

    Returns (alive, total_created).
    """
    out = _run([
        "journalctl", "-u", SERVICE_NAME,
        "--no-pager", "-o", "short",
        "--boot",
    ], timeout=15)

    created = 0
    closed = 0
    for line in out.splitlines():
        if "Session Created" in line:
            created += 1
        elif "Session Closed By Client" in line:
            closed += 1
        elif "Expired Sessions Cleaned" in line:
            match = re.search(r"Count:\s*(\d+)", line)
            if match:
                closed += int(match.group(1))

    alive = max(0, created - closed)
    return float(alive), float(created)


def poll_loop() -> None:
    while True:
        try:
            up, uptime = collect_service_state()
            rx, tx = collect_traffic()
            alive, total = collect_sessions()

            with _metrics_lock:
                _metrics["masterdns_server_up"] = up
                _metrics["masterdns_server_uptime_seconds"] = uptime
                _metrics["masterdns_rx_bytes_total"] = rx
                _metrics["masterdns_tx_bytes_total"] = tx
                _metrics["masterdns_sessions_alive"] = alive
                _metrics["masterdns_sessions_created_total"] = total
                _metrics["masterdns_exporter_up"] = 1
        except Exception as exc:
            print(f"[exporter] collection error: {exc}")

        time.sleep(POLL_INTERVAL)


def render_metrics() -> str:
    with _metrics_lock:
        snapshot = dict(_metrics)

    lines: list[str] = []
    for name in RENDER_ORDER:
        mtype, mhelp = METRIC_META[name]
        value = snapshot.get(name, 0)
        lines.append(f"# HELP {name} {mhelp}")
        lines.append(f"# TYPE {name} {mtype}")
        if value == int(value):
            lines.append(f"{name} {int(value)}")
        else:
            lines.append(f"{name} {value}")
    lines.append("")
    return "\n".join(lines)


class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            body = render_metrics().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


def main() -> None:
    print(f"[exporter] starting on :{PORT}, service={SERVICE_NAME}, poll={POLL_INTERVAL}s")

    collector = threading.Thread(target=poll_loop, daemon=True)
    collector.start()

    server = HTTPServer(("0.0.0.0", PORT), MetricsHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
