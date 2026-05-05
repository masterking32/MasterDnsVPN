#!/usr/bin/env bash

# Uninstall MasterDnsVPN
# Run this from the same directory where MasterDnsVPN was installed

set -euo pipefail

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info() { echo -e "[INFO] $1"; }
log_success() { echo -e "${GREEN}[DONE]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

INSTALL_DIR="$(pwd -P)"
echo -e "Uninstalling MasterDnsVPN from: $INSTALL_DIR"

# 1. Stop and disable the systemd service
if systemctl list-unit-files --all 2>/dev/null | grep -q '^masterdnsvpn\.service'; then
    log_info "Stopping and disabling masterdnsvpn service..."
    systemctl stop masterdnsvpn 2>/dev/null || true
    systemctl disable masterdnsvpn >/dev/null 2>&1 || true
    systemctl reset-failed masterdnsvpn 2>/dev/null || true
fi

# 2. Remove the systemd unit file
if [[ -f /etc/systemd/system/masterdnsvpn.service ]]; then
    rm -f /etc/systemd/system/masterdnsvpn.service
    systemctl daemon-reload 2>/dev/null || true
    log_success "Removed systemd service file."
fi

# 3. Kill any running MasterDnsVPN processes
if pgrep -fi 'masterdnsvpn' >/dev/null 2>&1; then
    log_info "Terminating running MasterDnsVPN processes..."
    pkill -fi 'masterdnsvpn' 2>/dev/null || true
    sleep 1
    pkill -9 -fi 'masterdnsvpn' 2>/dev/null || true
fi

# 4. Remove kernel tuning config
if [[ -f /etc/sysctl.d/99-masterdnsvpn.conf ]]; then
    rm -f /etc/sysctl.d/99-masterdnsvpn.conf
    sysctl --system >/dev/null 2>&1 || true
    log_success "Removed kernel tuning config."
fi

# 5. Remove file descriptor limits
if [[ -f /etc/security/limits.d/99-masterdnsvpn.conf ]]; then
    rm -f /etc/security/limits.d/99-masterdnsvpn.conf
    log_success "Removed file descriptor limits."
fi

# 6. Restore systemd-resolved backup if exists
if [[ -f /etc/systemd/resolved.conf.bak ]]; then
    log_info "Restoring original /etc/systemd/resolved.conf..."
    mv -f /etc/systemd/resolved.conf.bak /etc/systemd/resolved.conf
    systemctl restart systemd-resolved 2>/dev/null || true
fi

# 7. Clean install directory
log_info "Cleaning install directory..."

shopt -s nullglob
REMOVED=0
for f in \
    "$INSTALL_DIR"/MasterDnsVPN_Server_Linux*_v* \
    "$INSTALL_DIR"/server_config.toml \
    "$INSTALL_DIR"/server_config.toml.backup \
    "$INSTALL_DIR"/server_config.toml.bak \
    "$INSTALL_DIR"/server_config_*.toml \
    "$INSTALL_DIR"/encrypt_key.txt \
    "$INSTALL_DIR"/init_logs.tmp \
    "$INSTALL_DIR"/*.spec; do
    if [[ -e "$f" ]]; then
        rm -f -- "$f"
        log_info "Removed: $f"
        REMOVED=1
    fi
done
shopt -u nullglob

if [[ $REMOVED -eq 0 ]]; then
    log_warn "No MasterDnsVPN files found in $INSTALL_DIR."
fi

echo -e "\n${GREEN}${BOLD}   MASTERDNSVPN UNINSTALL COMPLETED${NC}"
echo -e "${YELLOW}Note:${NC} Firewall rules for port 53 were left in place."
echo -e "      Remove them manually if no longer needed."