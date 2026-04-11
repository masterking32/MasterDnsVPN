#!/usr/bin/env bash
# ============================================================================
# MasterDnsVPN Monitoring Installer (self-contained)
#
# Can be run in two ways:
#   1. Sourced by server_linux_install.sh  (inherits INSTALL_DIR, PM, etc.)
#   2. Standalone:  sudo bash monitoring/install.sh
#
# Flags:
#   --yes   Skip the interactive prompt and install monitoring
# ============================================================================

_MON_AUTO_YES="${_MON_AUTO_YES:-0}"
for _mon_arg in "$@"; do
  case "$_mon_arg" in
    --yes|-y) _MON_AUTO_YES=1 ;;
  esac
done

# ------------------------------------------------------------------
# Logging helpers -- define only if not already provided by the caller
# ------------------------------------------------------------------
if ! declare -f log_header >/dev/null 2>&1; then
  _RED='\033[1;31m'; _GREEN='\033[1;32m'; _YELLOW='\033[1;33m'
  _BLUE='\033[1;34m'; _CYAN='\033[1;36m'; _BOLD='\033[1m'; _NC='\033[0m'
  log_header()  { echo -e "\n${_CYAN}${_BOLD}>>> $1${_NC}"; }
  log_info()    { echo -e "${_BLUE}[INFO]${_NC} $1"; }
  log_success() { echo -e "${_GREEN}[DONE]${_NC} $1"; }
  log_warn()    { echo -e "${_YELLOW}[WARN]${_NC} $1"; }
  log_error()   { echo -e "${_RED}[ERROR]${_NC} $1"; return 1; }
fi

# ------------------------------------------------------------------
# Auto-detect variables when running standalone
# ------------------------------------------------------------------
if [[ -z "${INSTALL_DIR:-}" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  INSTALL_DIR="$(dirname "$SCRIPT_DIR")"
fi

if [[ -z "${PM:-}" ]]; then
  if command -v apt-get >/dev/null 2>&1; then PM="apt";
  elif command -v dnf >/dev/null 2>&1;     then PM="dnf";
  elif command -v yum >/dev/null 2>&1;     then PM="yum";
  else PM=""; fi
fi

if [[ -z "${ACTIVE_FIREWALL:-}" ]]; then
  ACTIVE_FIREWALL="none"
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qw active; then
    ACTIVE_FIREWALL="ufw"
  elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    ACTIVE_FIREWALL="firewalld"
  elif command -v iptables >/dev/null 2>&1; then
    ACTIVE_FIREWALL="iptables"
  elif command -v nft >/dev/null 2>&1; then
    ACTIVE_FIREWALL="nftables"
  fi
fi

MON_DIR="$INSTALL_DIR/monitoring"

# ------------------------------------------------------------------
# Prompt
# ------------------------------------------------------------------
if [[ "${_MON_AUTO_YES:-0}" == "1" ]]; then
  log_info "Setting up Prometheus exporter, Prometheus, and Grafana dashboard..."
  INSTALL_MONITORING="y"
else
  log_header "Grafana Monitoring (Optional)"
  INSTALL_MONITORING=""
  if (echo < /dev/tty) 2>/dev/null; then
    read -r -p ">>> Do you want to install Grafana monitoring dashboard? (y/N): " INSTALL_MONITORING </dev/tty || INSTALL_MONITORING=""
  fi
fi

case "${INSTALL_MONITORING:-}" in
  [yY]|[yY][eE][sS]) ;;
  *)
    log_info "Skipping monitoring installation."
    return 0 2>/dev/null || exit 0
    ;;
esac

# ------------------------------------------------------------------
# 1. Python 3
# ------------------------------------------------------------------
log_header "Installing Monitoring Dependencies"
if ! command -v python3 >/dev/null 2>&1; then
  log_info "Installing Python 3..."
  case "$PM" in
    apt) apt-get update -y >/dev/null 2>&1 && apt-get install -y python3 >/dev/null 2>&1 ;;
    dnf) dnf -y install python3 >/dev/null 2>&1 ;;
    yum) yum -y install python3 >/dev/null 2>&1 ;;
    *)   log_warn "No package manager found. Install Python 3 manually." ;;
  esac
fi
if command -v python3 >/dev/null 2>&1; then
  log_success "Python 3 is available: $(python3 --version 2>&1)"
else
  log_warn "Python 3 could not be installed. Exporter will not work."
fi

# ------------------------------------------------------------------
# 2. Docker & Docker Compose
# ------------------------------------------------------------------
install_docker() {
  log_info "Installing Docker..."
  case "$PM" in
    apt)
      apt-get update -y >/dev/null 2>&1
      apt-get install -y docker.io docker-compose-plugin >/dev/null 2>&1 \
        || apt-get install -y docker.io docker-compose >/dev/null 2>&1 \
        || true
      ;;
    dnf)
      dnf -y install docker docker-compose-plugin >/dev/null 2>&1 || true
      ;;
    yum)
      yum -y install docker docker-compose-plugin >/dev/null 2>&1 || true
      ;;
  esac

  if ! command -v docker >/dev/null 2>&1; then
    log_info "Package manager install failed, trying get.docker.com..."
    curl -fsSL https://get.docker.com | sh >/dev/null 2>&1 || true
  fi

  if command -v docker >/dev/null 2>&1; then
    systemctl enable docker >/dev/null 2>&1 || true
    systemctl start docker >/dev/null 2>&1 || true
  fi
}

if ! command -v docker >/dev/null 2>&1; then
  install_docker
fi

if command -v docker >/dev/null 2>&1; then
  log_success "Docker is available: $(docker --version 2>&1)"
else
  log_warn "Docker could not be installed. Prometheus/Grafana containers will not start."
fi

docker_compose_cmd=""
if docker compose version >/dev/null 2>&1; then
  docker_compose_cmd="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  docker_compose_cmd="docker-compose"
fi

if [[ -z "$docker_compose_cmd" ]]; then
  log_warn "Docker Compose not found. Trying to install standalone plugin..."
  mkdir -p /usr/local/lib/docker/cli-plugins 2>/dev/null || true
  COMPOSE_ARCH="$(uname -m)"
  case "$COMPOSE_ARCH" in
    x86_64|amd64) COMPOSE_ARCH="x86_64" ;;
    aarch64|arm64) COMPOSE_ARCH="aarch64" ;;
  esac
  curl -fsSL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-${COMPOSE_ARCH}" \
    -o /usr/local/lib/docker/cli-plugins/docker-compose 2>/dev/null || true
  chmod +x /usr/local/lib/docker/cli-plugins/docker-compose 2>/dev/null || true
  if docker compose version >/dev/null 2>&1; then
    docker_compose_cmd="docker compose"
    log_success "Docker Compose plugin installed."
  else
    log_warn "Docker Compose could not be installed."
  fi
fi

# ------------------------------------------------------------------
# 3. iptables OUTPUT rule for traffic accounting
# ------------------------------------------------------------------
log_header "Configuring Traffic Accounting"
if command -v iptables >/dev/null 2>&1; then
  iptables -C OUTPUT -p udp --sport 53 -j ACCEPT 2>/dev/null \
    || iptables -I OUTPUT -p udp --sport 53 -j ACCEPT 2>/dev/null || true

  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 || true
  elif command -v iptables-save >/dev/null 2>&1 && [[ -d /etc/iptables ]]; then
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
  fi
  log_success "iptables OUTPUT rule for UDP sport 53 is in place."
else
  log_warn "iptables not found. Traffic byte counters will read zero."
fi

# ------------------------------------------------------------------
# 4. Deploy exporter
# ------------------------------------------------------------------
log_header "Deploying Prometheus Exporter"
mkdir -p "$INSTALL_DIR/monitoring/exporters" 2>/dev/null || true

if [[ -f "$MON_DIR/exporters/masterdns_exporter.py" ]]; then
  log_success "Exporter script already at $MON_DIR/exporters/masterdns_exporter.py"
else
  log_warn "Exporter script not found at $MON_DIR/exporters/masterdns_exporter.py"
  log_warn "Ensure the monitoring/ directory from the repo is present in $INSTALL_DIR."
fi

# ------------------------------------------------------------------
# 5. systemd unit for exporter
# ------------------------------------------------------------------
log_header "Creating Exporter Service"
cat > /etc/systemd/system/masterdns-exporter.service <<EOF
[Unit]
Description=MasterDnsVPN Prometheus Exporter
After=network.target masterdnsvpn.service
Wants=masterdnsvpn.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 $MON_DIR/exporters/masterdns_exporter.py
Restart=always
RestartSec=5
Environment=PORT=9101
Environment=SERVICE_NAME=masterdnsvpn
Environment=POLL_INTERVAL=15

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable masterdns-exporter >/dev/null 2>&1
systemctl restart masterdns-exporter

sleep 2
if systemctl is-active --quiet masterdns-exporter; then
  log_success "Exporter service is running on port 9101."
else
  log_warn "Exporter service failed to start. Check: journalctl -u masterdns-exporter -f"
fi

# ------------------------------------------------------------------
# 6. Verify exporter endpoint
# ------------------------------------------------------------------
EXPORTER_CHECK="$(curl -s --max-time 5 http://127.0.0.1:9101/metrics 2>/dev/null | head -1 || true)"
if [[ -n "$EXPORTER_CHECK" ]]; then
  log_success "Exporter /metrics endpoint is reachable."
else
  log_warn "Could not reach http://127.0.0.1:9101/metrics -- exporter may need a moment to start."
fi

# ------------------------------------------------------------------
# 7. Start Prometheus + Grafana containers
# ------------------------------------------------------------------
log_header "Starting Prometheus & Grafana"
if [[ -n "$docker_compose_cmd" && -f "$MON_DIR/docker-compose.yml" ]]; then
  $docker_compose_cmd -f "$MON_DIR/docker-compose.yml" up -d 2>&1 | tail -5 || true
  log_success "Monitoring containers started."
else
  log_warn "Skipping container launch (Docker Compose or docker-compose.yml not available)."
fi

# ------------------------------------------------------------------
# 8. Open firewall ports (3000 Grafana, 9090 Prometheus)
# ------------------------------------------------------------------
log_header "Opening Monitoring Firewall Ports"
case "$ACTIVE_FIREWALL" in
  ufw)
    ufw allow 3000/tcp >/dev/null 2>&1 || true
    ufw allow 9090/tcp >/dev/null 2>&1 || true
    log_success "Ports 3000, 9090 opened via UFW."
    ;;
  firewalld)
    firewall-cmd --permanent --add-port=3000/tcp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=9090/tcp >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    log_success "Ports 3000, 9090 opened via firewalld."
    ;;
  iptables)
    iptables -C INPUT -p tcp --dport 3000 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 3000 -j ACCEPT 2>/dev/null || true
    iptables -C INPUT -p tcp --dport 9090 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 9090 -j ACCEPT 2>/dev/null || true
    if command -v netfilter-persistent >/dev/null 2>&1; then
      netfilter-persistent save >/dev/null 2>&1 || true
    elif command -v iptables-save >/dev/null 2>&1 && [[ -d /etc/iptables ]]; then
      iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
    log_success "Ports 3000, 9090 opened via iptables."
    ;;
  nftables)
    if nft list table inet filter >/dev/null 2>&1; then
      nft add rule inet filter input tcp dport 3000 accept >/dev/null 2>&1 || true
      nft add rule inet filter input tcp dport 9090 accept >/dev/null 2>&1 || true
      log_success "Ports 3000, 9090 opened via nftables."
    else
      log_warn "nftables inet filter table not found. Open ports 3000/9090 manually if needed."
    fi
    ;;
  *)
    log_warn "No firewall detected. Ensure ports 3000 and 9090 are accessible."
    ;;
esac

# ------------------------------------------------------------------
# 9. Print access info
# ------------------------------------------------------------------
log_success "Grafana monitoring is ready."
_MON_INSTALLED=1
_MON_SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[[ -z "$_MON_SERVER_IP" ]] && _MON_SERVER_IP="<your-server-ip>" || true
