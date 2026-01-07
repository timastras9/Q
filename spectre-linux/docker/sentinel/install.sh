#!/bin/bash
# Spectre - Installation Script
# ======================================
# Installs Spectre on Linux (Alpine, Rocky, Debian/Ubuntu)
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/spectre-sec/spectre/main/install.sh | sudo bash
#   or
#   sudo ./install.sh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║           Spectre - Installation                         ║"
echo "║     Autonomous Security Daemon for Linux                  ║"
echo "║     Autonomous Self-Healing Security                      ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root${NC}"
   exit 1
fi

# Detect OS and package manager
detect_os() {
    if [[ -f /etc/alpine-release ]]; then
        OS="alpine"
        PKG_MGR="apk"
    elif [[ -f /etc/redhat-release ]]; then
        OS="rhel"
        PKG_MGR="dnf"
    elif [[ -f /etc/debian_version ]]; then
        OS="debian"
        PKG_MGR="apt"
    else
        OS="unknown"
        PKG_MGR="unknown"
    fi
    echo -e "${GREEN}Detected OS: ${OS} (package manager: ${PKG_MGR})${NC}"
}

detect_os

echo -e "${GREEN}[1/6]${NC} Creating directory structure..."
mkdir -p /opt/spectre/{config,data,scripts}
mkdir -p /var/log/spectre

echo -e "${GREEN}[2/6]${NC} Installing system dependencies..."
case $PKG_MGR in
    apk)
        apk update
        apk add --no-cache \
            python3 py3-pip nmap curl jq iptables \
            procps util-linux bash openssl ca-certificates \
            findutils grep coreutils file lsof
        ;;
    dnf)
        dnf install -y python3 python3-pip nmap curl jq firewalld \
            policycoreutils-python-utils yum-utils procps-ng \
            2>/dev/null || yum install -y python3 python3-pip nmap curl jq firewalld
        ;;
    apt)
        apt-get update
        apt-get install -y python3 python3-pip nmap curl jq \
            procps coreutils findutils lsof
        ;;
    *)
        echo -e "${YELLOW}Warning: Unknown package manager, skipping system deps${NC}"
        ;;
esac

# Try to install Lynis and security tools
echo -e "${GREEN}[3/6]${NC} Installing security audit tools..."
case $PKG_MGR in
    apk)
        apk add --no-cache lynis rkhunter chkrootkit 2>/dev/null || \
            echo -e "${YELLOW}Some security tools not available - continuing${NC}"
        # Initialize rkhunter
        rkhunter --propupd 2>/dev/null || true
        ;;
    dnf)
        if ! rpm -q lynis &>/dev/null; then
            curl -s https://packages.cisofy.com/keys/cisofy-software-rpms-public.key | \
                gpg --dearmor -o /etc/pki/rpm-gpg/RPM-GPG-KEY-cisofy 2>/dev/null || true

            cat > /etc/yum.repos.d/lynis.repo << 'EOF'
[lynis]
name=Lynis Repository
baseurl=https://packages.cisofy.com/community/lynis/rpm/
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-cisofy
EOF
            dnf install -y lynis rkhunter 2>/dev/null || \
                echo -e "${YELLOW}Lynis installation optional - continuing${NC}"
        fi
        ;;
    apt)
        apt-get install -y lynis rkhunter chkrootkit 2>/dev/null || \
            echo -e "${YELLOW}Some security tools not available - continuing${NC}"
        ;;
esac

echo -e "${GREEN}[4/6]${NC} Installing Python dependencies..."
case $PKG_MGR in
    apk)
        pip3 install --no-cache-dir --break-system-packages requests anthropic psutil watchdog python-dotenv
        ;;
    *)
        pip3 install --quiet requests anthropic psutil watchdog python-dotenv
        ;;
esac

echo -e "${GREEN}[5/6]${NC} Installing Spectre daemon..."
# Copy daemon script (assuming it's in the same directory)
if [[ -f "$(dirname "$0")/daemon.py" ]]; then
    cp "$(dirname "$0")/daemon.py" /opt/spectre/daemon.py
elif [[ -f "/tmp/spectre/daemon.py" ]]; then
    cp /tmp/spectre/daemon.py /opt/spectre/daemon.py
else
    echo -e "${YELLOW}Warning: daemon.py not found, downloading from GitHub...${NC}"
    # In production, this would download from a release
    echo "Please copy daemon.py to /opt/spectre/daemon.py manually"
fi

chmod +x /opt/spectre/daemon.py

echo -e "${GREEN}[6/6]${NC} Installing systemd service..."
cat > /etc/systemd/system/spectre.service << 'EOF'
[Unit]
Description=Spectre - Autonomous Security Daemon
After=network.target network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=notify
ExecStart=/usr/bin/python3 /opt/spectre/daemon.py
User=root
Group=root
Restart=always
RestartSec=30
TimeoutStartSec=120
TimeoutStopSec=30
WatchdogSec=300
Environment=PYTHONUNBUFFERED=1
WorkingDirectory=/opt/spectre
StandardOutput=journal
StandardError=journal
SyslogIdentifier=spectre

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

# Check for Anthropic API key
if [[ -z "${ANTHROPIC_API_KEY}" ]]; then
    echo ""
    echo -e "${YELLOW}Optional: Set ANTHROPIC_API_KEY for AI-powered vulnerability analysis${NC}"
    echo "Add to /etc/environment:"
    echo "  ANTHROPIC_API_KEY=your-api-key-here"
fi

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           Installation Complete!                          ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "To start Spectre:"
echo -e "  ${BLUE}systemctl enable --now spectre${NC}"
echo ""
echo "To view logs:"
echo -e "  ${BLUE}journalctl -u spectre -f${NC}"
echo ""
echo "To run a manual scan:"
echo -e "  ${BLUE}/opt/spectre/daemon.py${NC}"
echo ""
echo "Scan reports are saved to: /opt/spectre/data/"
echo "Logs are saved to: /var/log/spectre/"
echo ""
echo -e "${GREEN}Philosophy: Secure by default, self-healing, minimal attack surface${NC}"
