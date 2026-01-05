#!/bin/bash
#
# Sentinel macOS Installer
# ========================
# Installs Sentinel security daemon on macOS
#

set -e

echo "
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝

        Sentinel for macOS - Installer
"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/usr/local/bin"
LAUNCH_AGENTS="$HOME/Library/LaunchAgents"
SENTINEL_DIR="$HOME/.sentinel"

echo "[*] Creating directories..."
mkdir -p "$SENTINEL_DIR"/{logs,evidence,reports}
mkdir -p "$LAUNCH_AGENTS"

echo "[*] Installing Sentinel..."
sudo cp "$SCRIPT_DIR/sentinel_macos.py" "$INSTALL_DIR/"
sudo chmod +x "$INSTALL_DIR/sentinel_macos.py"

echo "[*] Installing dashboard..."
sudo cp "$SCRIPT_DIR/dashboard.py" "$INSTALL_DIR/sentinel_dashboard.py" 2>/dev/null || true

echo "[*] Installing LaunchAgent..."
# Update plist with correct username
sed "s|/Users/tim|$HOME|g" "$SCRIPT_DIR/com.sentinel.agent.plist" > "$LAUNCH_AGENTS/com.sentinel.agent.plist"

echo "[*] Installing Python dependencies..."
pip3 install --quiet rich 2>/dev/null || true

echo ""
echo "Installation complete!"
echo ""
echo "Commands:"
echo "  sentinel_macos.py start     - Start Sentinel (foreground)"
echo "  sentinel_macos.py attackers - List known attackers"
echo "  sentinel_macos.py report --ip <IP> - Generate FBI IC3 report"
echo ""
echo "To start Sentinel as a background service:"
echo "  launchctl load ~/Library/LaunchAgents/com.sentinel.agent.plist"
echo ""
echo "To stop the background service:"
echo "  launchctl unload ~/Library/LaunchAgents/com.sentinel.agent.plist"
echo ""
echo "Logs:     $SENTINEL_DIR/logs/"
echo "Evidence: $SENTINEL_DIR/evidence/"
echo "Reports:  $SENTINEL_DIR/reports/"
echo ""
echo "Stay safe! 🛡️"
