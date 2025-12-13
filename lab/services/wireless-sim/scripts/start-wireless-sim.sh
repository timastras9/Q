#!/bin/bash
# Wireless Simulation Startup Script
# Simulates wireless networks for pentest training

echo "[*] Starting Wireless Network Simulation"

# Start RADIUS server for WPA-Enterprise simulation
echo "[+] Starting FreeRADIUS..."
/usr/sbin/freeradius -X &

# Create virtual network interface for simulation
echo "[+] Setting up virtual network..."
ip link add wlan-sim type dummy 2>/dev/null || true
ip addr add 192.168.100.1/24 dev wlan-sim 2>/dev/null || true
ip link set wlan-sim up 2>/dev/null || true

# Start dnsmasq for DHCP/DNS
echo "[+] Starting DNS/DHCP..."
dnsmasq -C /etc/dnsmasq.conf &

# Start web server for captive portal
echo "[+] Starting captive portal..."
python3 /opt/scripts/captive-portal.py &

# Generate sample handshake captures for practice
echo "[+] Generating sample captures..."
/opt/scripts/generate-captures.sh

# Keep container running
echo "[*] Wireless simulation running..."
echo "[*] Available targets:"
echo "    - WPA2-PSK: CorpWiFi-Guest (password: company123)"
echo "    - WPA2-Enterprise: CorpWiFi-Secure (RADIUS)"
echo "    - Sample handshakes in /captures/"
echo "    - Sample hashes in /hashes/"

tail -f /dev/null
