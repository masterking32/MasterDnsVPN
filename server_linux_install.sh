#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
CYAN='\033[1;36m'
BOLD='\033[1m'
NC='\033[0m'

log_header() { echo -e "\n${CYAN}${BOLD}>>> $1${NC}"; }
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[DONE]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || log_error "Missing command: $1"; }
backup_file_once() {
  local f="$1"
  [[ -f "$f" && ! -f "${f}.bak" ]] && cp -a "$f" "${f}.bak"
}
extract_config_version() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  grep '^CONFIG_VERSION' "$f" | awk -F'=' '{print $2}' | tr -d ' "' | head -n1
}
version_lt() {
  [[ "$1" == "$2" ]] && return 1
  [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$1" ]]
}
detect_legacy_linux() {
  local id="${ID:-}"
  local version_major="${VERSION_ID%%.*}"

  case "$id" in
    ubuntu)
      [[ "${version_major:-0}" -le 20 ]]
      ;;
    debian)
      [[ "${version_major:-0}" -le 11 ]]
      ;;
    almalinux|rocky|rhel|centos)
      [[ "${version_major:-0}" -le 8 ]]
      ;;
    *)
      return 1
      ;;
  esac
}
select_release_artifact() {
  local arch="$1"
  local legacy=0
  if detect_legacy_linux; then
    legacy=1
    log_info "Legacy system detected (broader Linux compatibility mode)."
  fi

  case "$arch" in
    aarch64|arm64)
      if [[ $legacy -eq 1 ]]; then
        URL="https://github.com/masterking32/MasterDnsVPN/releases/latest/download/MasterDnsVPN_Server_Linux-Legacy_ARM64.zip"
        PREFIX="MasterDnsVPN_Server_Linux-Legacy_ARM64"
      else
        URL="https://github.com/masterking32/MasterDnsVPN/releases/latest/download/MasterDnsVPN_Server_Linux_ARM64.zip"
        PREFIX="MasterDnsVPN_Server_Linux_ARM64"
      fi
      ;;
    armv7l|armv7|armhf)
      URL="https://github.com/masterking32/MasterDnsVPN/releases/latest/download/MasterDnsVPN_Server_Linux_ARMV7.zip"
      PREFIX="MasterDnsVPN_Server_Linux_ARMV7"
      ;;
    x86_64|amd64)
      if [[ $legacy -eq 1 ]]; then
        URL="https://github.com/masterking32/MasterDnsVPN/releases/latest/download/MasterDnsVPN_Server_Linux-Legacy_AMD64.zip"
        PREFIX="MasterDnsVPN_Server_Linux-Legacy_AMD64"
      else
        URL="https://github.com/masterking32/MasterDnsVPN/releases/latest/download/MasterDnsVPN_Server_Linux_AMD64.zip"
        PREFIX="MasterDnsVPN_Server_Linux_AMD64"
      fi
      ;;
    i386|i486|i586|i686|x86)
      URL="https://github.com/masterking32/MasterDnsVPN/releases/latest/download/MasterDnsVPN_Server_Linux_X86.zip"
      PREFIX="MasterDnsVPN_Server_Linux_X86"
      ;;
    *)
      log_error "Unsupported architecture: $arch"
      ;;
  esac
}

if [[ "${EUID}" -ne 0 ]]; then
  log_error "Run this script as root (sudo)."
fi

INSTALL_DIR="$(pwd -P)"
[[ -n "${PWD:-}" ]] && INSTALL_DIR="$PWD"
if [[ "$INSTALL_DIR" == /dev/fd* || "$INSTALL_DIR" == /proc/*/fd* ]]; then
  INSTALL_DIR="$(pwd -P)"
fi
log_info "Installation directory: $INSTALL_DIR"
cd "$INSTALL_DIR" || log_error "Cannot access install directory: $INSTALL_DIR"
if [[ -f "server_config.toml" && -f "server_config.toml.backup" ]]; then
  log_error "Both server_config.toml and server_config.toml.backup exist. Remove one and retry."
fi

if [[ -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
else
  log_error "OS detection failed (/etc/os-release missing)."
fi

echo -e "${MAGENTA}${BOLD}"
echo "  __  __           _             _____  _   _  _____ "
echo " |  \/  |         | |           |  __ \| \ | |/ ____|"
echo " | \  / | __ _ ___| |_ ___ _ __ | |  | |  \| | (___  "
echo " | |\/| |/ _\` / __| __/ _ \ '__|| |  | | . \ |\___ \ "
echo " | |  | | (_| \__ \ ||  __/ |   | |__| | |\  |____) |"
echo " |_|  |_|\__,_|___/\__\___|_|   |_____/|_| \_|_____/ "
echo -e "           MasterDnsVPN Server Auto-Installer${NC}"
echo -e "${CYAN}------------------------------------------------------${NC}"

TMP_LOG="init_logs.tmp"
DOWNLOAD_DIR=""
cleanup() {
  rm -f "$TMP_LOG" 2>/dev/null || true
  if [[ -n "${DOWNLOAD_DIR:-}" && -d "${DOWNLOAD_DIR:-}" ]]; then
    rm -rf "$DOWNLOAD_DIR" 2>/dev/null || true
  fi
}
trap cleanup EXIT

PM=""
if command -v apt-get >/dev/null 2>&1; then PM="apt";
elif command -v dnf >/dev/null 2>&1; then PM="dnf";
elif command -v yum >/dev/null 2>&1; then PM="yum";
else log_error "No supported package manager found (apt/dnf/yum)."; fi

log_header "Preparing Environment"
log_info "Installing dependencies..."
if [[ "$PM" == "apt" ]]; then
  apt-get update -y >/dev/null 2>&1
  apt-get install -y lsof net-tools wget unzip curl ca-certificates iproute2 procps irqbalance >/dev/null 2>&1
elif [[ "$PM" == "dnf" ]]; then
  dnf -y install lsof net-tools wget unzip curl ca-certificates iproute procps-ng irqbalance >/dev/null 2>&1
else
  yum -y install lsof net-tools wget unzip curl ca-certificates iproute procps-ng irqbalance >/dev/null 2>&1
fi
require_cmd ss
require_cmd unzip
require_cmd systemctl
require_cmd sysctl
log_success "System tools are ready."

if systemctl list-unit-files --type=service --all 2>/dev/null | awk '{print $1}' | grep -qx 'irqbalance.service'; then
  log_info "Enabling irqbalance for better multi-core packet distribution..."
  systemctl enable --now irqbalance >/dev/null 2>&1 || log_warn "Could not enable/start irqbalance."
fi

check_port53() {
  ss -H -lun "sport = :53" 2>/dev/null | grep -q ':53' && return 0
  ss -H -ltn "sport = :53" 2>/dev/null | grep -q ':53' && return 0
  return 1
}

show_port53_usage() {
  log_warn "Current listeners on port 53:"
  ss -lupn "sport = :53" 2>/dev/null || true
  ss -ltpn "sport = :53" 2>/dev/null || true
  lsof -nP -iUDP:53 -iTCP:53 2>/dev/null || true
}

get_port53_pids() {
  local pids_udp pids_tcp pids
  pids_udp="$(ss -H -lupn "sport = :53" 2>/dev/null | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | sort -u)"
  pids_tcp="$(ss -H -ltpn "sport = :53" 2>/dev/null | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | sort -u)"
  pids="$(printf '%s\n%s\n' "$pids_udp" "$pids_tcp" | sed '/^$/d' | sort -u)"
  if [[ -n "$pids" ]]; then
    echo "$pids"
    return 0
  fi
  lsof -ti :53 2>/dev/null || true
}

stop_service_if_present() {
  local unit="$1"
  if systemctl list-unit-files --type=service --all 2>/dev/null | awk '{print $1}' | grep -qx "$unit"; then
    if systemctl is-active --quiet "$unit"; then
      log_info "Stopping conflicting service: $unit"
      systemctl stop "$unit" || true
    fi
    systemctl disable "$unit" >/dev/null 2>&1 || true
  fi
}

stop_socket_if_present() {
  local unit="$1"
  if systemctl list-unit-files --type=socket --all 2>/dev/null | awk '{print $1}' | grep -qx "$unit"; then
    if systemctl is-active --quiet "$unit"; then
      log_info "Stopping conflicting socket: $unit"
      systemctl stop "$unit" || true
    fi
    systemctl disable "$unit" >/dev/null 2>&1 || true
  fi
}

terminate_port53_pid() {
  local pid="$1"
  [[ -n "$pid" ]] || return 0
  if ! kill -0 "$pid" 2>/dev/null; then
    return 0
  fi

  local cmdline
  cmdline="$(ps -p "$pid" -o cmd= 2>/dev/null || true)"
  log_warn "Trying to terminate PID on port 53: $pid (${cmdline:-unknown})"

  kill "$pid" 2>/dev/null || true
  for _ in 1 2 3; do
    sleep 1
    if ! kill -0 "$pid" 2>/dev/null; then
      return 0
    fi
  done

  kill -9 "$pid" 2>/dev/null || true
  sleep 1
  if kill -0 "$pid" 2>/dev/null; then
    log_warn "PID $pid is still alive after SIGKILL."
    return 1
  fi
  return 0
}

force_release_port53() {
  local stubborn=0
  local pid

  while IFS= read -r pid; do
    [[ -z "$pid" ]] && continue
    terminate_port53_pid "$pid" || stubborn=1
  done <<< "$(get_port53_pids)"

  if command -v fuser >/dev/null 2>&1 && check_port53; then
    log_warn "Trying fuser fallback for port 53..."
    fuser -k 53/udp 2>/dev/null || true
    fuser -k 53/tcp 2>/dev/null || true
    sleep 1
  fi

  return "$stubborn"
}

remove_iptables_port53_redirects() {
  local tool="$1"
  command -v "$tool" >/dev/null 2>&1 || return 0

  local rule delete_rule
  while IFS= read -r rule; do
    [[ -z "$rule" ]] && continue
    delete_rule="${rule/-A /-D }"
    log_warn "Removing ${tool} NAT redirect rule for port 53: $rule"
    # shellcheck disable=SC2086
    $tool -t nat $delete_rule >/dev/null 2>&1 || true
  done < <("$tool" -t nat -S 2>/dev/null | grep -E '(^-A )' | grep -E -- '(-p (tcp|udp)|-p (udp|tcp)).*--dport 53([^0-9]|$)' | grep -E 'REDIRECT|DNAT' || true)
}

remove_nft_port53_redirects() {
  command -v nft >/dev/null 2>&1 || return 0

  local rule
  while IFS= read -r rule; do
    [[ -z "$rule" ]] && continue
    log_warn "Removing nftables redirect rule for port 53: $rule"
    nft delete rule $rule >/dev/null 2>&1 || true
  done < <(nft -a list ruleset 2>/dev/null | awk '
    / dport 53 / && ($0 ~ /redirect/ || $0 ~ /dnat/) {
      for (i = 1; i <= NF; i++) {
        if ($i == "table") table = $(i+1)
        if ($i == "chain") chain = $(i+1)
        if ($i == "handle") handle = $(i+1)
      }
      if (table != "" && chain != "" && handle != "") {
        print "ip " table " " chain " handle " handle
      }
      table = ""; chain = ""; handle = ""
    }
  ' || true)
}

remove_port53_forward_rules() {
  log_info "Checking for port 53 redirect/forward rules..."
  remove_iptables_port53_redirects iptables
  remove_iptables_port53_redirects ip6tables
  remove_nft_port53_redirects
}

stop_existing_masterdnsvpn_service() {
  local unit_present=0
  if systemctl list-unit-files --all 2>/dev/null | grep -q '^masterdnsvpn\.service'; then
    unit_present=1
    log_info "Stopping existing MasterDnsVPN service..."
    systemctl stop masterdnsvpn 2>/dev/null || true

    for _ in 1 2 3 4 5; do
      if ! systemctl is-active --quiet masterdnsvpn; then
        break
      fi
      sleep 1
    done

    local main_pid
    main_pid="$(systemctl show masterdnsvpn --property MainPID --value 2>/dev/null || true)"
    if [[ -n "${main_pid:-}" && "$main_pid" != "0" ]] && kill -0 "$main_pid" 2>/dev/null; then
      log_warn "masterdnsvpn service is still active. Trying to terminate MainPID: $main_pid"
      terminate_port53_pid "$main_pid" || true
    fi

    systemctl stop masterdnsvpn 2>/dev/null || true
    systemctl reset-failed masterdnsvpn 2>/dev/null || true
  fi

  local pid cmdline killed=0
  while IFS= read -r pid; do
    [[ -z "$pid" ]] && continue
    cmdline="$(ps -p "$pid" -o cmd= 2>/dev/null || true)"
    if echo "$cmdline" | grep -qiE 'masterdnsvpn|masterdnsvpn_server'; then
      if [[ $killed -eq 0 && $unit_present -eq 0 ]]; then
        log_info "Stopping existing MasterDnsVPN process that was started outside systemd..."
      fi
      terminate_port53_pid "$pid" || true
      killed=1
    fi
  done <<< "$(get_port53_pids)"
}

log_header "Stopping Existing MasterDnsVPN"
stop_existing_masterdnsvpn_service

log_header "Managing Network Ports (Port 53)"
remove_port53_forward_rules

if check_port53; then
  log_warn "Port 53 is occupied. Trying auto-cleanup..."
  show_port53_usage

  if systemctl is-active --quiet systemd-resolved; then
    log_info "Configuring systemd-resolved DNSStubListener=no ..."
    backup_file_once /etc/systemd/resolved.conf
    if grep -q '^#\?DNSStubListener=' /etc/systemd/resolved.conf; then
      sed -i 's/^#\?DNSStubListener=.*/DNSStubListener=no/' /etc/systemd/resolved.conf || true
    else
      echo 'DNSStubListener=no' >> /etc/systemd/resolved.conf
    fi
    if ! grep -q '^DNS=' /etc/systemd/resolved.conf; then
      echo 'DNS=8.8.8.8' >> /etc/systemd/resolved.conf
    fi
    systemctl restart systemd-resolved || true
  fi

  stop_socket_if_present systemd-resolved.socket
  stop_socket_if_present dnsmasq.socket

  for srv in \
    bind9 bind9.service named named.service named-pkcs11 named-pkcs11.service \
    dnsmasq dnsmasq.service unbound unbound.service pdns pdns.service \
    knot-resolver kresd kresd@1.service dnscrypt-proxy dnscrypt-proxy.service \
    smartdns smartdns.service coredns coredns.service pihole-FTL pihole-FTL.service; do
    stop_service_if_present "$srv"
  done

  if check_port53; then
    log_warn "Port 53 is still busy after stopping known services. Trying direct process termination..."
    force_release_port53 || true
  fi

  if check_port53 && systemctl is-active --quiet systemd-resolved; then
    log_warn "Port 53 is still in use. Stopping systemd-resolved completely..."
    systemctl stop systemd-resolved || true
    systemctl disable systemd-resolved >/dev/null 2>&1 || true
    stop_socket_if_present systemd-resolved.socket
  fi

  if check_port53; then
    log_warn "Port 53 still occupied. Trying one more forced cleanup pass..."
    force_release_port53 || true
  fi

  if check_port53; then
    OCC_INFO="$(ss -H -lupn 'sport = :53' 2>/dev/null | head -n1 | awk '{print $NF}' || true)"
    [[ -z "${OCC_INFO:-}" ]] && OCC_INFO="$(ss -H -ltn 'sport = :53' 2>/dev/null | head -n1 | awk '{print $NF}' || true)"
    show_port53_usage
    log_error "Port 53 is still occupied: ${OCC_INFO:-unknown}. Stop it manually and retry."
  fi
fi
log_success "Port 53 is available."

log_header "Configuring Firewall (Port 53 UDP/TCP)"
ACTIVE_FIREWALL="none"
if command -v ufw >/dev/null 2>&1 && ufw status | grep -qw active; then
  ACTIVE_FIREWALL="ufw"
  ufw allow 53/udp >/dev/null 2>&1 || true
  ufw allow 53/tcp >/dev/null 2>&1 || true
  log_success "Port 53 (UDP/TCP) opened via UFW."
elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
  ACTIVE_FIREWALL="firewalld"
  firewall-cmd --permanent --add-port=53/udp >/dev/null 2>&1 || true
  firewall-cmd --permanent --add-port=53/tcp >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
  log_success "Port 53 (UDP/TCP) opened via firewalld."
elif command -v iptables >/dev/null 2>&1; then
  ACTIVE_FIREWALL="iptables"
  iptables -C INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport 53 -j ACCEPT
  iptables -C INPUT -p tcp --dport 53 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 53 -j ACCEPT
  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -C INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p udp --dport 53 -j ACCEPT
    ip6tables -C INPUT -p tcp --dport 53 -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p tcp --dport 53 -j ACCEPT
  fi
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 || true
  elif command -v iptables-save >/dev/null 2>&1 && [[ -d /etc/iptables ]]; then
    iptables-save > /etc/iptables/rules.v4
    command -v ip6tables-save >/dev/null 2>&1 && ip6tables-save > /etc/iptables/rules.v6
  fi
  log_success "Port 53 (UDP/TCP) rule is ready via iptables."
elif command -v nft >/dev/null 2>&1; then
  ACTIVE_FIREWALL="nftables"
  if nft list table inet filter >/dev/null 2>&1; then
    nft add rule inet filter input udp dport 53 accept >/dev/null 2>&1 || true
    nft add rule inet filter input tcp dport 53 accept >/dev/null 2>&1 || true
    log_success "Port 53 (UDP/TCP) rule is ready via nftables."
  else
    log_warn "nftables is present but no 'inet filter' table was found. Open port 53 manually if needed."
  fi
else
  log_warn "No supported firewall tool detected. Skipping firewall setup."
fi
log_info "Detected firewall handling: ${ACTIVE_FIREWALL}"

log_header "Tuning Kernel & Limits"
cat > /etc/sysctl.d/99-masterdnsvpn.conf <<'EOF'
# MasterDnsVPN high-load tuning
fs.file-max = 2097152
fs.nr_open = 2097152
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 16384
net.core.optmem_max = 25165824
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.ipv4.udp_mem = 65536 131072 262144
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_udp_timeout = 15
net.netfilter.nf_conntrack_udp_timeout_stream = 60
net.ipv4.ip_local_port_range = 10240 65535
EOF
sysctl --system >/dev/null 2>&1 || log_warn "Could not fully apply sysctl settings."

cat > /etc/security/limits.d/99-masterdnsvpn.conf <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
log_success "Kernel and file descriptor limits configured."

log_header "Fetching Latest Release"
ARCH="$(uname -m)"
select_release_artifact "$ARCH"

if [[ -f "server_config.toml" ]]; then
  mv -f server_config.toml server_config.toml.backup
  log_info "Existing config backed up."
fi

log_info "Downloading server binaries..."
if ! DOWNLOAD_DIR="$(mktemp -d /tmp/masterdnsvpn_download.XXXXXX 2>/dev/null)"; then
  DOWNLOAD_DIR="$(mktemp -d "$INSTALL_DIR/masterdnsvpn_download.XXXXXX" 2>/dev/null || true)"
fi
[[ -n "${DOWNLOAD_DIR:-}" && -d "${DOWNLOAD_DIR:-}" ]] || log_error "Failed to create temporary download directory. Check free space and /tmp permissions."
ZIP_PATH="${DOWNLOAD_DIR}/server.zip"

if ! curl -fL --retry 3 --retry-delay 2 --connect-timeout 15 -o "$ZIP_PATH" "$URL"; then
  log_warn "curl download failed, trying wget..."
  wget -qO "$ZIP_PATH" "$URL" || {
    log_warn "Disk usage snapshot:"
    df -h "$INSTALL_DIR" /tmp 2>/dev/null || true
    log_error "Download failed."
  }
fi

[[ -s "$ZIP_PATH" ]] || log_error "Downloaded archive is missing or empty: $ZIP_PATH"
unzip -q -o "$ZIP_PATH" -d "$INSTALL_DIR" || log_error "Failed to extract archive."
log_success "Files extracted."

EXECUTABLE="$(ls -t ${PREFIX}_v* 2>/dev/null | head -n1 || true)"
[[ -z "$EXECUTABLE" ]] && log_error "Binary not found in package."
chmod +x "$EXECUTABLE"
shopt -s nullglob
for old_bin in ${PREFIX}_v*; do
  [[ "$old_bin" == "$EXECUTABLE" ]] && continue
  rm -f -- "$old_bin"
done
shopt -u nullglob

log_header "Configuration"
[[ -f "server_config.toml" ]] || log_error "server_config.toml not found after extraction."
CURRENT_VERSION="$(extract_config_version server_config.toml)"
if [[ -z "${CURRENT_VERSION:-}" ]]; then
  log_error "Downloaded server_config.toml is invalid (CONFIG_VERSION missing)."
fi
if [[ -f "server_config.toml.backup" ]]; then
  BACKUP_VERSION="$(extract_config_version server_config.toml.backup)"
  if [[ -z "${BACKUP_VERSION:-}" ]]; then
    log_error "Backup config is too old (CONFIG_VERSION missing). Merge manually."
  fi

  if [[ "$BACKUP_VERSION" == "$CURRENT_VERSION" ]]; then
    mv -f server_config.toml.backup server_config.toml
    log_info "Config restored from backup."
  elif version_lt "$BACKUP_VERSION" "$CURRENT_VERSION"; then
    OLD_CFG_NAME="server_config_$(date +%Y%m%d_%H%M%S).toml"
    mv -f server_config.toml.backup "$OLD_CFG_NAME"
    log_warn "Old config version detected (backup=$BACKUP_VERSION < new=$CURRENT_VERSION)."
    log_warn "Previous config renamed to: $OLD_CFG_NAME"
    log_info "Using fresh config template; please set DOMAIN and other required fields."
  else
    log_error "Backup config version is newer than package config (backup=$BACKUP_VERSION, new=$CURRENT_VERSION). Merge manually."
  fi
fi

if [[ -f "server_config.toml" ]] && grep -q '"v.domain.com"' server_config.toml; then
  echo -e "${YELLOW}${BOLD}Attention:${NC} Set your NS domain."
  read -r -p ">>> Enter your Domain (e.g. vpn.example.com): " USER_DOMAIN </dev/tty || true
  if [[ -n "${USER_DOMAIN:-}" ]]; then
    sed -i -E "s|^DOMAIN[[:space:]]*=.*$|DOMAIN = [\"${USER_DOMAIN}\"]|" server_config.toml
  fi
fi

log_header "Security Initialization"
log_info "Starting server once to generate encryption key..."
if ! ./"$EXECUTABLE" -genkey -nowait > "$TMP_LOG" 2>&1; then
  log_warn "Initialization log tail:"
  tail -n 20 "$TMP_LOG" || true
  log_error "Could not verify key generation."
fi

echo -e "${GREEN}${BOLD}------------------------------------------------------"
echo -e "  YOUR ENCRYPTION KEY: ${NC}${CYAN}$(cat encrypt_key.txt 2>/dev/null)${NC}"
echo -e "${GREEN}${BOLD}------------------------------------------------------${NC}"

log_header "Installing System Service"
SVC="/etc/systemd/system/masterdnsvpn.service"
cat > "$SVC" <<EOF
[Unit]
Description=MasterDnsVPN Server
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/$EXECUTABLE
Restart=always
RestartSec=3
User=root

LimitNOFILE=1048576
LimitNPROC=65535
TasksMax=infinity
TimeoutStopSec=15
KillMode=control-group

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable masterdnsvpn >/dev/null 2>&1
systemctl restart masterdnsvpn

if ! systemctl is-active --quiet masterdnsvpn; then
  journalctl -u masterdnsvpn -n 50 --no-pager || true
  log_error "Service failed to start. See logs above."
fi

log_success "MasterDnsVPN service is running."

echo -e "\n${CYAN}======================================================${NC}"
echo -e " ${GREEN}${BOLD}       INSTALLATION COMPLETED SUCCESSFULLY!${NC}"
echo -e "${CYAN}======================================================${NC}"
echo -e "${BOLD}Commands:${NC}"
echo -e "  ${YELLOW}>${NC} Start:   systemctl start masterdnsvpn"
echo -e "  ${YELLOW}>${NC} Stop:    systemctl stop masterdnsvpn"
echo -e "  ${YELLOW}>${NC} Restart: systemctl restart masterdnsvpn"
echo -e "  ${YELLOW}>${NC} Logs:    journalctl -u masterdnsvpn -f"
echo -e "\n${BOLD}Files:${NC}"
echo -e "  ${YELLOW}>${NC} ${INSTALL_DIR}/server_config.toml"
echo -e "  ${YELLOW}>${NC} ${INSTALL_DIR}/encrypt_key.txt"
echo -e "${YELLOW}Final Note:${NC} If config changes, run: systemctl restart masterdnsvpn"

rm -f *.spec >/dev/null 2>&1 || true
