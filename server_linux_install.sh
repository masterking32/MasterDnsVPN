#!/bin/bash

# --- Colors & Styles ---
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
CYAN='\033[1;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# --- Helper Functions ---
log_header() { echo -e "\n${CYAN}${BOLD}>>> $1${NC}"; }
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[DONE]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Root check
if [ "$EUID" -ne 0 ]; then
  log_error "Please run this script as root (sudo)."
fi

# Set working directory
INSTALL_DIR="$(pwd)"
cd "$INSTALL_DIR"

# --- Welcome Banner ---
clear
echo -e "${MAGENTA}${BOLD}"
echo "  __  __           _             _____  _   _  _____ "
echo " |  \/  |         | |           |  __ \| \ | |/ ____|"
echo " | \  / | __ _ ___| |_ ___ _ __ | |  | |  \| | (___  "
echo " | |\/| |/ _\` / __| __/ _ \ '__|| |  | | . \ |\___ \ "
echo " | |  | | (_| \__ \ ||  __/ |   | |__| | |\  |____) |"
echo " |_|  |_|\__,_|___/\__\___|_|   |_____/|_| \_|_____/ "
echo -e "           MasterDnsVPN Server Auto-Installer${NC}"
echo -e "${CYAN}------------------------------------------------------${NC}"

# 1. Environment Prep
log_header "Preparing Environment"
log_info "Updating system and installing dependencies..."
apt-get update -y > /dev/null 2>&1
apt-get install -y lsof net-tools wget unzip curl > /dev/null 2>&1
log_success "System tools are ready."

# 2. Port 53 Management
log_header "Managing Network Ports (Port 53)"

# Stop existing service first
if systemctl list-unit-files | grep -q masterdnsvpn.service; then
    log_info "Stopping existing MasterDnsVPN service..."
    systemctl stop masterdnsvpn 2>/dev/null || true
fi

check_port53() { lsof -i :53 -t > /dev/null 2>&1; }

if check_port53; then
    log_warn "Port 53 is occupied. Cleaning up..."
    
    if systemctl is-active --quiet systemd-resolved; then
        log_info "Configuring systemd-resolved..."
        sed -i 's/#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf
        sed -i 's/DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf
        # Ensure server has a fallback DNS to keep internet access
        if ! grep -q "DNS=8.8.8.8" /etc/systemd/resolved.conf; then
            echo "DNS=8.8.8.8" >> /etc/systemd/resolved.conf
        fi
        systemctl restart systemd-resolved
    fi

    for srv in bind9 named dnsmasq; do
        if systemctl is-active --quiet $srv; then
            log_info "Disabling conflicting service: $srv"
            systemctl stop $srv && systemctl disable $srv > /dev/null 2>&1
        fi
    done

    if check_port53; then
        OCC_INFO=$(lsof -i :53 -n -P | grep -E "LISTEN|UDP" | awk 'NR==1 {print $1 " (PID: " $2 ")"}')
        log_error "Port 53 is still held by: ${BOLD}${RED}${OCC_INFO:-Unknown}${NC}\n       Kill it manually and restart."
    fi
fi
log_success "Port 53 is available."

# 3. Detection & Download
log_header "Fetching Latest Release"
ARCH=$(uname -m)
[ -f /etc/os-release ] && . /etc/os-release || log_error "OS detection failed."

if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    URL="https://github.com/masterking32/MasterDnsVPN/releases/latest/download/MasterDnsVPN_Server_Linux_ARM64.zip"
    PREFIX="MasterDnsVPN_Server_Linux_ARM64"
elif [ "$ARCH" = "x86_64" ]; then
    LEGACY=0
    [[ "$ID" == "ubuntu" && ${VERSION_ID%%.*} -le 20 ]] && LEGACY=1
    [[ "$ID" == "debian" && ${VERSION_ID%%.*} -le 11 ]] && LEGACY=1

    if [ $LEGACY -eq 1 ]; then
        log_info "Legacy system detected (GLIBC compatibility mode)."
        URL="https://github.com/masterking32/MasterDnsVPN/releases/latest/download/MasterDnsVPN_Server_Linux-Legacy_AMD64.zip"
        PREFIX="MasterDnsVPN_Server_Linux-Legacy_AMD64"
    else
        URL="https://github.com/masterking32/MasterDnsVPN/releases/latest/download/MasterDnsVPN_Server_Linux_AMD64.zip"
        PREFIX="MasterDnsVPN_Server_Linux_AMD64"
    fi
else
    log_error "Unsupported architecture: $ARCH"
fi

[ -f "server_config.toml" ] && mv server_config.toml server_config.toml.backup && log_info "Existing config backed up."

log_info "Downloading server binaries..."
wget -qO "server.zip" "$URL" || log_error "Download failed."
unzip -q -o "server.zip" && rm -f "server.zip"
log_success "Files extracted."

EXECUTABLE=$(ls -t ${PREFIX}_v* 2>/dev/null | head -n 1)
[ -z "$EXECUTABLE" ] && log_error "Binary not found in the package."
chmod +x "$EXECUTABLE"

# 4. Configuration
log_header "Configuration"
[ -f "server_config.toml.backup" ] && mv server_config.toml.backup server_config.toml && log_info "Config restored from backup."

if [ -f "server_config.toml" ] && grep -q 'DOMAIN = \["v.domain.com"\]' server_config.toml; then
    echo -e "${YELLOW}${BOLD}Attention:${NC} You need to set your NS Record Domain."
    read -p ">>> Enter your Domain (e.g. vpn.example.com): " USER_DOMAIN
    [ -n "$USER_DOMAIN" ] && sed -i "s/DOMAIN = \\[\"v.domain.com\"\\]/DOMAIN = \\[\"$USER_DOMAIN\"\\]/" server_config.toml
fi

# 5. Initialization & Key
log_header "Security Initialization"
log_info "Starting server to generate encryption key..."
./"$EXECUTABLE" > init_logs.tmp 2>&1 &
APP_PID=$!
READY=false
for i in {1..7}; do # Increased to 7s for slower CPUs
    if grep -q "Using encryption key" init_logs.tmp 2>/dev/null; then READY=true; break; fi
    sleep 1
done
kill $APP_PID 2>/dev/null || true
wait $APP_PID 2>/dev/null || true

if [ "$READY" = false ]; then
    log_warn "Initialization log dump:"
    tail -n 5 init_logs.tmp
    rm -f init_logs.tmp
    log_error "Could not verify key generation. Check if Port 53 is truly free."
fi
rm -f init_logs.tmp

echo -e "${GREEN}${BOLD}------------------------------------------------------"
echo -e "  YOUR ENCRYPTION KEY: ${NC}${CYAN}$(cat encrypt_key.txt 2>/dev/null)${NC}"
echo -e "${GREEN}${BOLD}------------------------------------------------------${NC}"

# 6. Service Installation
log_header "Installing System Service"
SVC="/etc/systemd/system/masterdnsvpn.service"
cat <<EOF > "$SVC"
[Unit]
Description=MasterDnsVPN Server
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/$EXECUTABLE
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable masterdnsvpn
systemctl start masterdnsvpn
log_success "MasterDnsVPN service is now running."

# 7. Final Instructions
echo -e "\n${CYAN}======================================================${NC}"
echo -e " ${GREEN}${BOLD}       INSTALLATION COMPLETED SUCCESSFULLY!${NC}"
echo -e "${CYAN}======================================================${NC}"
echo -e "${BOLD}Commands to manage your server:${NC}"
echo -e "  ${YELLOW}▶${NC} ${BOLD}Start:${NC}   systemctl start masterdnsvpn"
echo -e "  ${YELLOW}▶${NC} ${BOLD}Stop:${NC}    systemctl stop masterdnsvpn"
echo -e "  ${YELLOW}▶${NC} ${BOLD}Restart:${NC} systemctl restart masterdnsvpn"
echo -e "  ${YELLOW}▶${NC} ${BOLD}Logs:${NC}    journalctl -u masterdnsvpn -f"
echo -e "\n${BOLD}Files Location:${NC}"
echo -e "  ${YELLOW}📂${NC} ${INSTALL_DIR}/server_config.toml"
echo -e "  ${YELLOW}📂${NC} ${INSTALL_DIR}/encrypt_key.txt"
echo -e "${CYAN}------------------------------------------------------${NC}"
echo -e "${YELLOW}Final Note:${NC} If you change the config, run 'systemctl restart masterdnsvpn'"
echo -e "${CYAN}======================================================${NC}\n"

# Cleanup artifacts
rm -f *.spec > /dev/null 2>&1