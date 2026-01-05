#!/usr/bin/env python3
"""
Sentinel for macOS
==================

Native macOS security daemon with:
- Real-time intrusion detection
- Attacker reconnaissance and profiling
- Evidence collection for law enforcement
- FBI IC3 report generation

Author: PentestAI
License: MIT
"""

import os
import sys
import json
import time
import socket
import subprocess
import threading
import hashlib
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from queue import Queue
import ssl
import re

# =============================================================================
# Configuration
# =============================================================================

SENTINEL_VERSION = "1.0.0-macos"
SENTINEL_DIR = Path.home() / ".sentinel"
LOG_DIR = SENTINEL_DIR / "logs"
EVIDENCE_DIR = SENTINEL_DIR / "evidence"
REPORTS_DIR = SENTINEL_DIR / "reports"
ATTACKERS_DB = SENTINEL_DIR / "attackers.json"

# Detection thresholds - ZERO TOLERANCE MODE
PORT_SCAN_THRESHOLD = 3  # ports in window - reduced for zero tolerance
PORT_SCAN_WINDOW = 60  # seconds
CONNECTION_FLOOD_THRESHOLD = 30  # connections per minute - reduced
BRUTE_FORCE_THRESHOLD = 3  # failed auths in window - reduced
BRUTE_FORCE_WINDOW = 300  # 5 minutes

# Aggressive defense mode
ZERO_TOLERANCE_MODE = True  # Block on first offense

# Whitelisted ports - connections to these ports won't trigger alerts
# (for legitimate P2P services like IPFS)
WHITELIST_PORTS = {
    4001,   # IPFS swarm
    4002,   # IPFS swarm (alt)
    5001,   # IPFS API (localhost only but included)
    8080,   # IPFS gateway (localhost only but included)
}

# =============================================================================
# Whitelist - Trusted Services (won't trigger alerts)
# =============================================================================

WHITELIST_DOMAINS = {
    # AI/Claude/Anthropic
    "api.anthropic.com",
    "anthropic.com",
    "claude.ai",
    "anthropic.ai",

    # Google
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "google-analytics.com",
    "googleusercontent.com",
    "googlevideo.com",
    "youtube.com",
    "ytimg.com",

    # Apple
    "apple.com",
    "icloud.com",
    "apple-cloudkit.com",
    "mzstatic.com",
    "cdn-apple.com",

    # Microsoft
    "microsoft.com",
    "azure.com",
    "office.com",
    "live.com",
    "msftconnecttest.com",

    # Amazon/AWS
    "amazon.com",
    "amazonaws.com",
    "cloudfront.net",

    # GitHub
    "github.com",
    "githubusercontent.com",
    "githubassets.com",

    # Cloudflare
    "cloudflare.com",
    "cloudflare-dns.com",

    # Common CDNs
    "akamai.net",
    "akamaiedge.net",
    "fastly.net",

    # DNS
    "1.1.1.1",
    "8.8.8.8",
    "8.8.4.4",
}

# IP ranges to whitelist (CIDR notation parsed manually)
WHITELIST_IP_PREFIXES = [
    # Apple
    "17.",
    # Google IPv4
    "172.217.", "142.250.", "172.253.", "216.58.", "74.125.", "173.194.",
    "64.233.",  # Google
    "34.149.", "34.107.", "34.36.",  # Google Cloud
    "35.190.", "35.191.", "35.192.", "35.193.", "35.194.", "35.195.", "35.186.",
    # GitHub
    "140.82.", "192.30.", "185.199.",
    # Microsoft
    "13.107.", "52.96.", "40.126.", "20.190.", "20.50.", "20.54.", "20.60.",
    # Cloudflare IPv4
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
    "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
    "162.159.", "172.64.", "172.65.", "172.66.", "172.67.",
    # Amazon/AWS
    "52.94.", "54.239.", "18.64.", "18.65.", "18.66.", "18.97.",
    "54.167.", "54.166.",  # AWS EC2
    # Anthropic/Claude
    "160.79.",
    # Fastly CDN
    "151.101.",
]

# IPv6 prefixes to whitelist
WHITELIST_IPV6_PREFIXES = [
    # Anthropic/Claude
    "2607:6bc0:",
    # Google
    "2607:f8b0:",  # Google
    "2a00:1450:",  # Google EU
    "2600:1901:",  # Google Cloud
    "2001:4860:",  # Google
    # Cloudflare
    "2606:4700:",
    "2803:f800:",
    # Microsoft
    "2603:1063:",
    "2603:1036:",
    # Fastly CDN
    "2a04:4e42:",
    "2603:1037:",
    "2603:1046:",
    "2620:1ec:",
    # Apple
    "2620:149:",
    # Amazon
    "2600:1f",
    # Akamai
    "2600:1400",
    "2600:1401",
    # Fastly
    "2606:50c0:",
]

WHITELIST_FILE = SENTINEL_DIR / "whitelist.json"
BLOCKED_IPS_FILE = SENTINEL_DIR / "blocked_ips.json"

# Ensure directories exist
for d in [SENTINEL_DIR, LOG_DIR, EVIDENCE_DIR, REPORTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)


# =============================================================================
# Logging
# =============================================================================

class SentinelLogger:
    def __init__(self):
        self.log_file = LOG_DIR / f"sentinel_{datetime.now().strftime('%Y%m%d')}.log"

    def _log(self, level: str, message: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"{timestamp} [{level}] {message}"
        print(line)
        with open(self.log_file, "a") as f:
            f.write(line + "\n")

    def info(self, msg): self._log("INFO", msg)
    def warning(self, msg): self._log("WARNING", msg)
    def error(self, msg): self._log("ERROR", msg)
    def critical(self, msg): self._log("CRITICAL", msg)
    def alert(self, msg): self._log("ALERT", f"🚨 {msg}")

log = SentinelLogger()


# =============================================================================
# Whitelist Manager
# =============================================================================

class WhitelistManager:
    """Manage trusted IPs and domains to prevent false positives"""

    def __init__(self):
        self.custom_whitelist: Set[str] = set()
        self.resolved_ips: Dict[str, str] = {}  # IP -> domain cache
        self._load_custom_whitelist()

    def _load_custom_whitelist(self):
        """Load user-defined whitelist"""
        if WHITELIST_FILE.exists():
            try:
                with open(WHITELIST_FILE) as f:
                    data = json.load(f)
                    self.custom_whitelist = set(data.get("ips", []))
                    self.custom_whitelist.update(data.get("domains", []))
            except:
                pass

    def save_whitelist(self):
        """Save custom whitelist"""
        with open(WHITELIST_FILE, "w") as f:
            json.dump({
                "ips": list(self.custom_whitelist),
                "domains": []
            }, f, indent=2)

    def add_to_whitelist(self, ip_or_domain: str):
        """Add IP or domain to whitelist"""
        self.custom_whitelist.add(ip_or_domain)
        self.save_whitelist()
        log.info(f"Added to whitelist: {ip_or_domain}")

    def remove_from_whitelist(self, ip_or_domain: str):
        """Remove from whitelist"""
        self.custom_whitelist.discard(ip_or_domain)
        self.save_whitelist()
        log.info(f"Removed from whitelist: {ip_or_domain}")

    def is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted"""
        # Check custom whitelist
        if ip in self.custom_whitelist:
            return True

        # Check IPv4 prefixes
        for prefix in WHITELIST_IP_PREFIXES:
            if ip.startswith(prefix):
                return True

        # Check IPv6 prefixes
        for prefix in WHITELIST_IPV6_PREFIXES:
            if ip.lower().startswith(prefix.lower()):
                return True

        # Check if IP resolves to whitelisted domain
        hostname = self._get_hostname(ip)
        if hostname:
            for domain in WHITELIST_DOMAINS:
                if hostname.endswith(domain):
                    return True
            for domain in self.custom_whitelist:
                if hostname.endswith(domain):
                    return True

        return False

    def _get_hostname(self, ip: str) -> Optional[str]:
        """Reverse DNS with caching"""
        if ip in self.resolved_ips:
            return self.resolved_ips[ip]

        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self.resolved_ips[ip] = hostname
            return hostname
        except:
            self.resolved_ips[ip] = None
            return None

    def get_whitelisted_reason(self, ip: str) -> Optional[str]:
        """Get reason why IP is whitelisted"""
        if ip in self.custom_whitelist:
            return "Custom whitelist"

        for prefix in WHITELIST_IP_PREFIXES:
            if ip.startswith(prefix):
                return f"Trusted IP range ({prefix}*)"

        hostname = self._get_hostname(ip)
        if hostname:
            for domain in WHITELIST_DOMAINS:
                if hostname.endswith(domain):
                    return f"Trusted domain ({domain})"

        return None


# =============================================================================
# Firewall Blocker (macOS pf)
# =============================================================================

class FirewallBlocker:
    """Block attackers using macOS packet filter (pf)"""

    def __init__(self):
        self.blocked_ips: Set[str] = set()
        self.block_table = "sentinel_blocked"
        self._load_blocked()

    def _load_blocked(self):
        """Load previously blocked IPs"""
        if BLOCKED_IPS_FILE.exists():
            try:
                with open(BLOCKED_IPS_FILE) as f:
                    self.blocked_ips = set(json.load(f))
            except:
                pass

    def _save_blocked(self):
        """Save blocked IPs"""
        with open(BLOCKED_IPS_FILE, "w") as f:
            json.dump(list(self.blocked_ips), f, indent=2)

    def block_ip(self, ip: str, reason: str = "") -> bool:
        """Block an IP address using pf"""
        if ip in self.blocked_ips:
            return True

        try:
            # Add to pf table (requires sudo)
            result = subprocess.run(
                ["sudo", "pfctl", "-t", self.block_table, "-T", "add", ip],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                self.blocked_ips.add(ip)
                self._save_blocked()
                log.alert(f"BLOCKED attacker: {ip} - {reason}")
                return True
            else:
                log.warning(f"Failed to block {ip}: {result.stderr}")
                # Still track it even if pf fails
                self.blocked_ips.add(ip)
                self._save_blocked()
                return False

        except Exception as e:
            log.error(f"Firewall block failed for {ip}: {e}")
            self.blocked_ips.add(ip)
            self._save_blocked()
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address"""
        try:
            subprocess.run(
                ["sudo", "pfctl", "-t", self.block_table, "-T", "delete", ip],
                capture_output=True,
                timeout=10
            )
            self.blocked_ips.discard(ip)
            self._save_blocked()
            log.info(f"Unblocked: {ip}")
            return True
        except Exception as e:
            log.error(f"Failed to unblock {ip}: {e}")
            return False

    def is_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        return ip in self.blocked_ips

    def list_blocked(self) -> List[str]:
        """List all blocked IPs"""
        return list(self.blocked_ips)

    def setup_pf_rules(self):
        """Setup pf rules for Sentinel (run once with sudo)"""
        pf_rules = f"""
# Sentinel Security Blocker Rules
# Add to /etc/pf.conf or load separately

table <{self.block_table}> persist

# Block all traffic from blocked IPs
block drop in quick from <{self.block_table}> to any
block drop out quick from any to <{self.block_table}>
"""
        rules_file = SENTINEL_DIR / "pf_sentinel.conf"
        with open(rules_file, "w") as f:
            f.write(pf_rules)

        log.info(f"PF rules written to: {rules_file}")
        log.info("To enable blocking, run:")
        log.info(f"  sudo pfctl -f {rules_file}")
        log.info("  sudo pfctl -e")
        return str(rules_file)


# =============================================================================
# Attacker Profile and Recon
# =============================================================================

@dataclass
class AttackerProfile:
    """Complete profile of an attacker for evidence collection"""
    ip: str
    first_seen: str
    last_seen: str
    attack_count: int = 0
    attack_types: List[str] = field(default_factory=list)

    # Reconnaissance data
    hostname: Optional[str] = None
    geolocation: Dict[str, Any] = field(default_factory=dict)
    whois_data: Dict[str, Any] = field(default_factory=dict)
    abuse_contacts: List[str] = field(default_factory=list)
    isp: Optional[str] = None
    organization: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None

    # Reputation
    threat_score: int = 0
    is_known_bad: bool = False
    reputation_sources: List[Dict] = field(default_factory=list)

    # Evidence
    evidence_files: List[str] = field(default_factory=list)
    attack_logs: List[Dict] = field(default_factory=list)


class AttackerRecon:
    """Gather intelligence on attackers"""

    def __init__(self):
        self.cache: Dict[str, AttackerProfile] = {}
        self._load_cache()

    def _load_cache(self):
        """Load cached attacker data"""
        if ATTACKERS_DB.exists():
            try:
                with open(ATTACKERS_DB) as f:
                    data = json.load(f)
                    for ip, profile_data in data.items():
                        self.cache[ip] = AttackerProfile(**profile_data)
            except Exception as e:
                log.error(f"Failed to load attacker cache: {e}")

    def _save_cache(self):
        """Save attacker data to disk"""
        try:
            data = {ip: asdict(profile) for ip, profile in self.cache.items()}
            with open(ATTACKERS_DB, "w") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            log.error(f"Failed to save attacker cache: {e}")

    def profile_attacker(self, ip: str, attack_type: str) -> AttackerProfile:
        """Build or update attacker profile with full recon"""
        now = datetime.now().isoformat()

        if ip in self.cache:
            profile = self.cache[ip]
            profile.last_seen = now
            profile.attack_count += 1
            if attack_type not in profile.attack_types:
                profile.attack_types.append(attack_type)
        else:
            profile = AttackerProfile(
                ip=ip,
                first_seen=now,
                last_seen=now,
                attack_count=1,
                attack_types=[attack_type]
            )
            self.cache[ip] = profile

            # Run full recon on new attacker
            log.info(f"Running reconnaissance on attacker: {ip}")
            self._run_recon(profile)

        self._save_cache()
        return profile

    def _run_recon(self, profile: AttackerProfile):
        """Run all reconnaissance on an attacker"""
        ip = profile.ip

        # Skip private IPs
        if self._is_private_ip(ip):
            log.info(f"Skipping recon for private IP: {ip}")
            return

        # Reverse DNS
        profile.hostname = self._reverse_dns(ip)

        # Geolocation
        geo = self._geolocate(ip)
        if geo:
            profile.geolocation = geo
            profile.country = geo.get("country")
            profile.city = geo.get("city")
            profile.isp = geo.get("isp")
            profile.organization = geo.get("org")

        # WHOIS
        whois = self._whois_lookup(ip)
        if whois:
            profile.whois_data = whois
            profile.abuse_contacts = whois.get("abuse_contacts", [])

        # Check reputation
        self._check_reputation(profile)

        log.info(f"Recon complete for {ip}: {profile.country}, {profile.isp}, threat_score={profile.threat_score}")

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local"""
        try:
            parts = [int(p) for p in ip.split(".")]
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 127:
                return True
        except:
            pass
        return False

    def _reverse_dns(self, ip: str) -> Optional[str]:
        """Reverse DNS lookup"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None

    def _geolocate(self, ip: str) -> Optional[Dict]:
        """Get IP geolocation using free API"""
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
            req = urllib.request.Request(url, headers={"User-Agent": "Sentinel-Security/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                if data.get("status") == "success":
                    return data
        except Exception as e:
            log.error(f"Geolocation failed for {ip}: {e}")
        return None

    def _whois_lookup(self, ip: str) -> Optional[Dict]:
        """WHOIS lookup for IP"""
        try:
            result = subprocess.run(
                ["whois", ip],
                capture_output=True,
                text=True,
                timeout=30
            )

            whois_data = {"raw": result.stdout}

            # Extract key fields
            patterns = {
                "org_name": r"OrgName:\s*(.+)",
                "org_id": r"OrgId:\s*(.+)",
                "net_range": r"NetRange:\s*(.+)",
                "net_name": r"NetName:\s*(.+)",
                "abuse_email": r"OrgAbuseEmail:\s*(.+)",
                "tech_email": r"OrgTechEmail:\s*(.+)",
                "country": r"Country:\s*(.+)",
            }

            abuse_contacts = []
            for key, pattern in patterns.items():
                match = re.search(pattern, result.stdout, re.IGNORECASE)
                if match:
                    whois_data[key] = match.group(1).strip()
                    if "email" in key.lower():
                        abuse_contacts.append(match.group(1).strip())

            whois_data["abuse_contacts"] = abuse_contacts
            return whois_data

        except Exception as e:
            log.error(f"WHOIS failed for {ip}: {e}")
        return None

    def _check_reputation(self, profile: AttackerProfile):
        """Check IP reputation against threat intelligence"""
        ip = profile.ip
        threat_score = 0

        # Check AbuseIPDB (free tier)
        try:
            # Note: Requires API key for full access
            # For now, just increment threat score based on attack count
            threat_score += min(profile.attack_count * 10, 50)
        except:
            pass

        # Check if from known bad countries/ASNs
        high_risk_countries = ["RU", "CN", "KP", "IR"]
        if profile.country in high_risk_countries:
            threat_score += 20

        profile.threat_score = min(threat_score, 100)
        profile.is_known_bad = threat_score >= 50

    def get_profile(self, ip: str) -> Optional[AttackerProfile]:
        """Get cached attacker profile"""
        return self.cache.get(ip)

    def get_all_attackers(self) -> List[AttackerProfile]:
        """Get all known attackers"""
        return list(self.cache.values())


# =============================================================================
# Evidence Collection
# =============================================================================

class EvidenceCollector:
    """Collect and preserve evidence for law enforcement"""

    def __init__(self):
        self.evidence_log = EVIDENCE_DIR / "evidence_chain.json"
        self.evidence_chain = []
        self._load_chain()

    def _load_chain(self):
        if self.evidence_log.exists():
            try:
                with open(self.evidence_log) as f:
                    self.evidence_chain = json.load(f)
            except:
                pass

    def _save_chain(self):
        with open(self.evidence_log, "w") as f:
            json.dump(self.evidence_chain, f, indent=2, default=str)

    def collect_evidence(self, attacker_ip: str, attack_type: str,
                         details: Dict, profile: AttackerProfile) -> str:
        """Collect and hash evidence for chain of custody"""
        timestamp = datetime.now()
        evidence_id = hashlib.sha256(
            f"{attacker_ip}{timestamp.isoformat()}{attack_type}".encode()
        ).hexdigest()[:16]

        evidence = {
            "evidence_id": evidence_id,
            "timestamp": timestamp.isoformat(),
            "attacker_ip": attacker_ip,
            "attack_type": attack_type,
            "details": details,
            "attacker_profile": asdict(profile),
            "system_info": {
                "hostname": socket.gethostname(),
                "platform": "macOS",
                "sentinel_version": SENTINEL_VERSION
            }
        }

        # Save evidence file
        evidence_file = EVIDENCE_DIR / f"evidence_{evidence_id}.json"
        with open(evidence_file, "w") as f:
            json.dump(evidence, f, indent=2, default=str)

        # Hash for integrity
        with open(evidence_file, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        # Add to chain
        chain_entry = {
            "evidence_id": evidence_id,
            "file": str(evidence_file),
            "hash": file_hash,
            "timestamp": timestamp.isoformat(),
            "attacker_ip": attacker_ip,
            "attack_type": attack_type
        }
        self.evidence_chain.append(chain_entry)
        self._save_chain()

        log.info(f"Evidence collected: {evidence_id} for {attacker_ip}")
        return evidence_id


# =============================================================================
# FBI IC3 Report Generator
# =============================================================================

class IC3ReportGenerator:
    """Generate FBI Internet Crime Complaint Center (IC3) reports"""

    def generate_report(self, attacker: AttackerProfile,
                        evidence_ids: List[str]) -> str:
        """Generate a formatted IC3 complaint report"""
        timestamp = datetime.now()
        report_id = f"IC3_{timestamp.strftime('%Y%m%d_%H%M%S')}_{attacker.ip.replace('.', '_')}"

        report = f"""
================================================================================
                    FBI INTERNET CRIME COMPLAINT (IC3)
                         INCIDENT REPORT
================================================================================

REPORT ID: {report_id}
GENERATED: {timestamp.strftime('%Y-%m-%d %H:%M:%S %Z')}
GENERATED BY: Sentinel Security System v{SENTINEL_VERSION}

================================================================================
                         COMPLAINANT INFORMATION
================================================================================

System Owner: [TO BE FILLED BY USER]
Contact Email: [TO BE FILLED BY USER]
Contact Phone: [TO BE FILLED BY USER]
Physical Address: [TO BE FILLED BY USER]

================================================================================
                         INCIDENT SUMMARY
================================================================================

INCIDENT TYPE: Computer Intrusion / Unauthorized Access Attempt
FIRST DETECTED: {attacker.first_seen}
LAST DETECTED: {attacker.last_seen}
TOTAL ATTACK COUNT: {attacker.attack_count}
ATTACK TYPES: {', '.join(attacker.attack_types)}

================================================================================
                         SUSPECT INFORMATION
================================================================================

IP ADDRESS: {attacker.ip}
HOSTNAME: {attacker.hostname or 'Unknown'}
COUNTRY: {attacker.country or 'Unknown'}
CITY: {attacker.city or 'Unknown'}
ISP: {attacker.isp or 'Unknown'}
ORGANIZATION: {attacker.organization or 'Unknown'}
THREAT SCORE: {attacker.threat_score}/100

ABUSE CONTACTS:
{chr(10).join(['  - ' + c for c in attacker.abuse_contacts]) or '  None identified'}

================================================================================
                         GEOLOCATION DATA
================================================================================

{json.dumps(attacker.geolocation, indent=2) if attacker.geolocation else 'No geolocation data available'}

================================================================================
                         WHOIS INFORMATION
================================================================================

{self._format_whois(attacker.whois_data)}

================================================================================
                         EVIDENCE CHAIN
================================================================================

Evidence IDs:
{chr(10).join(['  - ' + eid for eid in evidence_ids])}

Evidence files are stored in: {EVIDENCE_DIR}
Each file is SHA-256 hashed for integrity verification.

================================================================================
                         ATTACK TIMELINE
================================================================================

{self._format_attack_logs(attacker.attack_logs)}

================================================================================
                         RECOMMENDED ACTIONS
================================================================================

1. File this report at: https://www.ic3.gov/
2. Contact your ISP's abuse department
3. If significant damage occurred, contact local FBI field office
4. Preserve all evidence files for potential prosecution
5. Consider contacting the attacker's ISP abuse contacts listed above

================================================================================
                         LEGAL NOTICES
================================================================================

This report was generated automatically by Sentinel Security System.
All information is provided for law enforcement purposes.
Evidence integrity can be verified using the SHA-256 hashes in the evidence chain.

Relevant US Laws:
- 18 U.S.C. 1030 - Computer Fraud and Abuse Act
- 18 U.S.C. 2511 - Wiretapping and Electronic Surveillance
- 18 U.S.C. 1028 - Identity Theft

================================================================================
                              END OF REPORT
================================================================================
"""

        # Save report
        report_file = REPORTS_DIR / f"{report_id}.txt"
        with open(report_file, "w") as f:
            f.write(report)

        log.alert(f"FBI IC3 Report generated: {report_file}")
        return str(report_file)

    def _format_whois(self, whois_data: Dict) -> str:
        if not whois_data:
            return "No WHOIS data available"

        # Don't include raw WHOIS in report (too long)
        filtered = {k: v for k, v in whois_data.items() if k != "raw"}
        return json.dumps(filtered, indent=2)

    def _format_attack_logs(self, logs: List[Dict]) -> str:
        if not logs:
            return "No detailed attack logs available"

        lines = []
        for log_entry in logs[-20:]:  # Last 20 entries
            lines.append(f"  {log_entry.get('timestamp', 'Unknown')} - {log_entry.get('type', 'Unknown')}")
        return "\n".join(lines)


# =============================================================================
# macOS Network Monitor
# =============================================================================

class MacOSNetworkMonitor:
    """Monitor network connections on macOS"""

    def __init__(self, alert_callback):
        self.alert_callback = alert_callback
        self.connection_history: Dict[str, List[Tuple[datetime, int]]] = defaultdict(list)
        self.port_access: Dict[str, Set[int]] = defaultdict(set)
        self.running = False

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        log.info("macOS Network Monitor started")

    def stop(self):
        self.running = False

    def _monitor_loop(self):
        while self.running:
            try:
                connections = self._get_connections()
                self._analyze_connections(connections)
                self._cleanup_old_data()
                time.sleep(1)
            except Exception as e:
                log.error(f"Network monitor error: {e}")
                time.sleep(5)

    def _get_connections(self) -> List[Dict]:
        """Get current network connections using lsof"""
        connections = []
        try:
            result = subprocess.run(
                ["lsof", "-i", "-n", "-P"],
                capture_output=True,
                text=True,
                timeout=10
            )

            for line in result.stdout.split("\n")[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 9:
                    name = parts[8] if len(parts) > 8 else ""
                    if "->" in name:
                        local, remote = name.split("->")
                        remote_ip, remote_port = self._parse_address(remote)
                        local_ip, local_port = self._parse_address(local)

                        if remote_ip and not self._is_local(remote_ip):
                            connections.append({
                                "remote_ip": remote_ip,
                                "remote_port": remote_port,
                                "local_port": local_port,
                                "process": parts[0],
                                "pid": parts[1]
                            })
        except Exception as e:
            log.error(f"Failed to get connections: {e}")

        return connections

    def _parse_address(self, addr: str) -> Tuple[str, int]:
        """Parse address like '192.168.1.1:443' or '[::1]:443'"""
        try:
            if addr.startswith("["):
                # IPv6
                ip, port = addr.rsplit(":", 1)
                ip = ip.strip("[]")
            else:
                ip, port = addr.rsplit(":", 1)
            return ip, int(port) if port.isdigit() else 0
        except:
            return "", 0

    def _is_local(self, ip: str) -> bool:
        """Check if IP is local/private"""
        if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
            return True
        if ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31:
            return True
        if ip in ("::1", "0.0.0.0", "*"):
            return True
        return False

    def _analyze_connections(self, connections: List[Dict]):
        """Analyze connections for threats"""
        now = datetime.now()

        for conn in connections:
            ip = conn["remote_ip"]
            port = conn["local_port"]

            # Skip whitelisted ports (e.g., IPFS P2P)
            if port in WHITELIST_PORTS:
                continue

            self.connection_history[ip].append((now, port))
            self.port_access[ip].add(port)

        # Check for port scans
        for ip, ports in self.port_access.items():
            recent = [t for t, _ in self.connection_history[ip]
                     if (now - t).seconds < PORT_SCAN_WINDOW]
            if len(set(p for _, p in self.connection_history[ip]
                      if (now - _).seconds < PORT_SCAN_WINDOW)) >= PORT_SCAN_THRESHOLD:
                self.alert_callback("port_scan", ip, {
                    "ports_scanned": len(ports),
                    "ports": list(ports)[:20]
                })

        # Check for connection floods
        for ip, history in self.connection_history.items():
            recent = [t for t, _ in history if (now - t).seconds < 60]
            if len(recent) >= CONNECTION_FLOOD_THRESHOLD:
                self.alert_callback("connection_flood", ip, {
                    "connections_per_minute": len(recent)
                })

    def _cleanup_old_data(self):
        """Clean up old tracking data"""
        now = datetime.now()
        cutoff = timedelta(minutes=5)

        for ip in list(self.connection_history.keys()):
            self.connection_history[ip] = [
                (t, p) for t, p in self.connection_history[ip]
                if now - t < cutoff
            ]
            if not self.connection_history[ip]:
                del self.connection_history[ip]
                if ip in self.port_access:
                    del self.port_access[ip]


# =============================================================================
# SSL MITM Detection
# =============================================================================

# Critical domains to monitor for certificate changes (potential MITM)
CRITICAL_DOMAINS = {
    "api.anthropic.com": None,  # Will store expected cert fingerprint
    "claude.ai": None,
    "github.com": None,
    "api.github.com": None,
    "google.com": None,
    "icloud.com": None,
}

class SSLMITMDetector:
    """Detect SSL/TLS Man-in-the-Middle attacks"""

    def __init__(self, alert_callback):
        self.alert_callback = alert_callback
        self.cert_cache: Dict[str, Dict] = {}  # domain -> cert info
        self.running = False
        self.check_interval = 300  # Check every 5 minutes

    def start(self):
        self.running = True
        # Initial certificate baseline
        self._build_cert_baseline()
        # Start monitoring thread
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        log.info("SSL MITM Detector started")

    def stop(self):
        self.running = False

    def _build_cert_baseline(self):
        """Build baseline of expected certificates for critical domains"""
        log.info("Building SSL certificate baseline...")
        for domain in CRITICAL_DOMAINS.keys():
            try:
                cert_info = self._get_cert_info(domain)
                if cert_info:
                    self.cert_cache[domain] = cert_info
                    log.info(f"Baseline cert for {domain}: {cert_info['fingerprint'][:16]}...")
            except Exception as e:
                log.warning(f"Could not get baseline cert for {domain}: {e}")

    def _get_cert_info(self, domain: str, port: int = 443) -> Optional[Dict]:
        """Get certificate information for a domain"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()

                    # Calculate fingerprint
                    fingerprint = hashlib.sha256(cert).hexdigest()

                    # Extract key info
                    issuer = dict(x[0] for x in cert_dict.get('issuer', []))
                    subject = dict(x[0] for x in cert_dict.get('subject', []))

                    return {
                        'fingerprint': fingerprint,
                        'issuer': issuer.get('organizationName', 'Unknown'),
                        'subject': subject.get('commonName', domain),
                        'not_after': cert_dict.get('notAfter', ''),
                        'serial': cert_dict.get('serialNumber', ''),
                        'checked_at': datetime.now().isoformat()
                    }
        except ssl.SSLCertVerificationError as e:
            # Certificate verification failed - potential MITM!
            self._alert_mitm(domain, "ssl_cert_invalid", {
                "error": str(e),
                "reason": "Certificate verification failed - possible MITM attack"
            })
            return None
        except socket.timeout:
            # Timeout is not a MITM indicator
            log.debug(f"Timeout checking cert for {domain}")
            return None
        except ConnectionRefusedError:
            log.debug(f"Connection refused for {domain}")
            return None
        except Exception as e:
            # Don't alert on generic errors - only on SSL verification failures
            log.debug(f"Could not check cert for {domain}: {e}")
            return None

    def _monitor_loop(self):
        """Continuously monitor certificates for changes"""
        while self.running:
            try:
                self._check_certificates()
                time.sleep(self.check_interval)
            except Exception as e:
                log.error(f"SSL monitor error: {e}")
                time.sleep(60)

    def _check_certificates(self):
        """Check all critical domain certificates for changes"""
        for domain in CRITICAL_DOMAINS.keys():
            if not self.running:
                break

            try:
                current_cert = self._get_cert_info(domain)
                if not current_cert:
                    continue

                cached_cert = self.cert_cache.get(domain)

                if cached_cert:
                    # Check for certificate change
                    if current_cert['fingerprint'] != cached_cert['fingerprint']:
                        # Certificate changed! Could be legitimate rotation or MITM
                        self._alert_mitm(domain, "ssl_cert_changed", {
                            "old_fingerprint": cached_cert['fingerprint'],
                            "new_fingerprint": current_cert['fingerprint'],
                            "old_issuer": cached_cert['issuer'],
                            "new_issuer": current_cert['issuer'],
                            "reason": "Certificate fingerprint changed - verify legitimacy"
                        })

                    # Check for suspicious issuer change
                    if current_cert['issuer'] != cached_cert['issuer']:
                        self._alert_mitm(domain, "ssl_issuer_changed", {
                            "old_issuer": cached_cert['issuer'],
                            "new_issuer": current_cert['issuer'],
                            "reason": "Certificate issuer changed - possible MITM proxy"
                        })

                # Update cache
                self.cert_cache[domain] = current_cert

            except Exception as e:
                log.debug(f"Error checking {domain}: {e}")

    def _alert_mitm(self, domain: str, attack_type: str, details: Dict):
        """Generate MITM alert"""
        log.warning(f"🔐 POTENTIAL MITM DETECTED on {domain}: {attack_type}")

        # Try to get the IP we're connecting to
        try:
            ip = socket.gethostbyname(domain)
        except:
            ip = "unknown"

        self.alert_callback(attack_type, ip, {
            "domain": domain,
            **details
        })

    def check_connection(self, domain: str, ip: str, port: int = 443) -> bool:
        """
        Check if a specific connection might be MITM'd
        Returns True if suspicious, False if OK
        """
        try:
            context = ssl.create_default_context()
            with socket.create_connection((ip, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    # Connection succeeded with valid cert
                    return False
        except ssl.SSLCertVerificationError:
            self._alert_mitm(domain, "ssl_mitm_detected", {
                "ip": ip,
                "port": port,
                "reason": "SSL certificate verification failed for this IP"
            })
            return True
        except Exception:
            return False


# =============================================================================
# Fast Flux Detection
# =============================================================================

class FastFluxDetector:
    """
    Detect Fast Flux DNS attacks.

    Fast flux is a technique used by botnets where domain IPs change rapidly
    to hide malicious infrastructure. This detector monitors DNS resolutions
    and identifies suspicious patterns.
    """

    def __init__(self, alert_callback):
        self.alert_callback = alert_callback
        self.dns_history: Dict[str, List[Tuple[datetime, Set[str]]]] = defaultdict(list)
        self.running = False
        self.check_interval = 60  # Check every minute

        # Thresholds for fast flux detection
        self.ip_change_threshold = 3  # IPs changed 3+ times in window
        self.time_window = 300  # 5 minute window
        self.multi_a_threshold = 5  # 5+ A records is suspicious

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        log.info("Fast Flux Detector started")

    def stop(self):
        self.running = False

    def _monitor_loop(self):
        """Monitor DNS for fast flux patterns"""
        while self.running:
            try:
                self._check_active_connections()
                self._analyze_dns_patterns()
                time.sleep(self.check_interval)
            except Exception as e:
                log.error(f"Fast flux monitor error: {e}")
                time.sleep(30)

    def _check_active_connections(self):
        """Check DNS for domains in active connections"""
        try:
            # Get unique remote hosts from netstat
            result = subprocess.run(
                ["netstat", "-an"],
                capture_output=True, text=True, timeout=10
            )

            # Extract unique IPs and try reverse DNS
            seen_ips = set()
            for line in result.stdout.split('\n'):
                if 'ESTABLISHED' in line or 'SYN_SENT' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        remote = parts[4]
                        # Extract IP (handle IPv4 and IPv6)
                        if '.' in remote:
                            ip = remote.rsplit('.', 1)[0] if remote.count('.') > 3 else remote.rsplit(':', 1)[0]
                            if ip and not ip.startswith(('127.', '192.168.', '10.', '172.')):
                                seen_ips.add(ip)

            # Check suspicious IPs for fast flux
            for ip in list(seen_ips)[:20]:  # Limit to 20 to avoid overload
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    if hostname and not self._is_trusted_domain(hostname):
                        self._record_dns(hostname, ip)
                except:
                    pass

        except Exception as e:
            log.debug(f"Error checking connections: {e}")

    def _is_trusted_domain(self, domain: str) -> bool:
        """Check if domain is a trusted service"""
        trusted_suffixes = [
            'google.com', 'googleapis.com', 'github.com', 'microsoft.com',
            'apple.com', 'cloudflare.com', 'amazon.com', 'amazonaws.com',
            'anthropic.com', 'claude.ai', 'akamai.net', 'fastly.net'
        ]
        return any(domain.endswith(suffix) for suffix in trusted_suffixes)

    def _record_dns(self, domain: str, ip: str):
        """Record DNS resolution for analysis"""
        now = datetime.now()

        # Get all IPs for this domain
        try:
            ips = set()
            for info in socket.getaddrinfo(domain, 443):
                ip_addr = info[4][0]
                ips.add(ip_addr)

            self.dns_history[domain].append((now, ips))

            # Keep only recent history
            cutoff = now - timedelta(seconds=self.time_window * 2)
            self.dns_history[domain] = [
                (t, i) for t, i in self.dns_history[domain]
                if t > cutoff
            ]

            # Check for fast flux indicators
            if len(ips) >= self.multi_a_threshold:
                self._alert_fast_flux(domain, "multi_a_record", {
                    "ip_count": len(ips),
                    "ips": list(ips)[:10],
                    "reason": f"Domain has {len(ips)} A records - possible fast flux"
                })

        except Exception as e:
            log.debug(f"DNS lookup failed for {domain}: {e}")

    def _analyze_dns_patterns(self):
        """Analyze DNS history for fast flux patterns"""
        now = datetime.now()

        for domain, history in list(self.dns_history.items()):
            if len(history) < 2:
                continue

            # Get IPs in the time window
            recent = [(t, ips) for t, ips in history
                     if (now - t).seconds < self.time_window]

            if len(recent) < 2:
                continue

            # Count unique IP sets (changes)
            unique_ip_sets = []
            for _, ips in recent:
                if not unique_ip_sets or ips != unique_ip_sets[-1]:
                    unique_ip_sets.append(ips)

            # Detect rapid IP changes
            if len(unique_ip_sets) >= self.ip_change_threshold:
                all_ips = set()
                for ips in unique_ip_sets:
                    all_ips.update(ips)

                self._alert_fast_flux(domain, "rapid_ip_change", {
                    "changes": len(unique_ip_sets),
                    "window_seconds": self.time_window,
                    "unique_ips": len(all_ips),
                    "ips": list(all_ips)[:10],
                    "reason": f"Domain changed IPs {len(unique_ip_sets)} times in {self.time_window}s - FAST FLUX"
                })

    def _alert_fast_flux(self, domain: str, attack_type: str, details: Dict):
        """Generate fast flux alert"""
        log.warning(f"⚡ FAST FLUX DETECTED: {domain} - {attack_type}")

        # Try to get current IP
        try:
            ip = socket.gethostbyname(domain)
        except:
            ip = details.get('ips', ['unknown'])[0] if details.get('ips') else 'unknown'

        self.alert_callback(f"fast_flux_{attack_type}", ip, {
            "domain": domain,
            **details
        })

    def check_domain(self, domain: str) -> Dict:
        """
        Manually check a domain for fast flux indicators.
        Returns analysis results.
        """
        results = {
            "domain": domain,
            "is_fast_flux": False,
            "indicators": [],
            "ips": [],
            "ttl": None
        }

        try:
            # Get all IPs
            ips = set()
            for info in socket.getaddrinfo(domain, 443):
                ips.add(info[4][0])

            results["ips"] = list(ips)

            # Check for multiple A records
            if len(ips) >= self.multi_a_threshold:
                results["indicators"].append(f"High A record count: {len(ips)}")
                results["is_fast_flux"] = True

            # Try to get TTL via DNS query
            try:
                import dns.resolver
                answers = dns.resolver.resolve(domain, 'A')
                ttl = answers.rrset.ttl
                results["ttl"] = ttl

                if ttl < 300:  # Less than 5 minutes
                    results["indicators"].append(f"Low TTL: {ttl}s")
                    results["is_fast_flux"] = True
            except ImportError:
                pass  # dnspython not installed
            except:
                pass

        except Exception as e:
            results["error"] = str(e)

        return results


# =============================================================================
# macOS Auth Monitor
# =============================================================================

class MacOSAuthMonitor:
    """Monitor authentication attempts on macOS"""

    def __init__(self, alert_callback):
        self.alert_callback = alert_callback
        self.failed_attempts: Dict[str, List[datetime]] = defaultdict(list)
        self.running = False

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        log.info("macOS Auth Monitor started")

    def stop(self):
        self.running = False

    def _monitor_loop(self):
        """Monitor system log for auth failures"""
        try:
            # Use log stream to watch for auth events
            process = subprocess.Popen(
                ["log", "stream", "--predicate",
                 'process == "sshd" OR process == "sudo" OR process == "login"',
                 "--style", "syslog"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            while self.running:
                line = process.stdout.readline()
                if line:
                    self._parse_auth_line(line)

        except Exception as e:
            log.error(f"Auth monitor error: {e}")

    def _parse_auth_line(self, line: str):
        """Parse auth log line for failures"""
        line_lower = line.lower()

        if "failed" in line_lower or "invalid" in line_lower or "denied" in line_lower:
            # Try to extract IP
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if ip_match:
                ip = ip_match.group(1)
                now = datetime.now()

                self.failed_attempts[ip].append(now)

                # Check threshold
                recent = [t for t in self.failed_attempts[ip]
                         if (now - t).seconds < BRUTE_FORCE_WINDOW]

                if len(recent) >= BRUTE_FORCE_THRESHOLD:
                    self.alert_callback("brute_force", ip, {
                        "failed_attempts": len(recent),
                        "window_seconds": BRUTE_FORCE_WINDOW,
                        "log_line": line[:200]
                    })


# =============================================================================
# Main Sentinel Daemon
# =============================================================================

class SentinelMacOS:
    """Main Sentinel daemon for macOS"""

    def __init__(self, auto_block: bool = False):
        self.running = False
        self.auto_block = auto_block

        # Core components
        self.recon = AttackerRecon()
        self.evidence = EvidenceCollector()
        self.ic3 = IC3ReportGenerator()
        self.whitelist = WhitelistManager()
        self.firewall = FirewallBlocker()

        # Monitors
        self.network_monitor = MacOSNetworkMonitor(self._handle_alert)
        self.auth_monitor = MacOSAuthMonitor(self._handle_alert)
        self.ssl_monitor = SSLMITMDetector(self._handle_alert)
        self.flux_monitor = FastFluxDetector(self._handle_alert)

        self.alerted_ips: Dict[str, datetime] = {}
        self.alert_cooldown = 60  # seconds

    def _handle_alert(self, alert_type: str, ip: str, details: Dict):
        """Handle security alert with recon and evidence collection"""
        # Check if whitelisted (trusted service)
        if self.whitelist.is_whitelisted(ip):
            reason = self.whitelist.get_whitelisted_reason(ip)
            log.info(f"Ignoring whitelisted IP {ip}: {reason}")
            return

        # Check if already blocked
        if self.firewall.is_blocked(ip):
            return

        # Check cooldown
        now = datetime.now()
        if ip in self.alerted_ips:
            if (now - self.alerted_ips[ip]).seconds < self.alert_cooldown:
                return

        self.alerted_ips[ip] = now

        # Log alert
        log.alert(f"{alert_type.upper()} detected from {ip}")

        # Run recon on attacker
        profile = self.recon.profile_attacker(ip, alert_type)

        # Add to attack logs
        profile.attack_logs.append({
            "timestamp": now.isoformat(),
            "type": alert_type,
            "details": details
        })

        # Collect evidence
        evidence_id = self.evidence.collect_evidence(ip, alert_type, details, profile)
        profile.evidence_files.append(evidence_id)

        # Print attacker info
        self._print_attacker_info(profile)

        # Critical attack types - ALWAYS block immediately
        critical_attacks = {
            'ssl_mitm_detected', 'ssl_cert_invalid',
            'brute_force', 'ssh_brute_force',
            'fast_flux_rapid_ip_change',
            'port_scan',  # ZERO TOLERANCE
            'connection_flood'  # ZERO TOLERANCE
        }

        # Auth failures should block if user is actively logged in
        if alert_type in {'auth_failure', 'ssh_failed_login', 'failed_password'}:
            if self._is_user_active():
                log.alert(f"🚫 AUTH FAILURE while user active - Auto-blocking {ip}")
                self.firewall.block_ip(ip, f"Auth failure while user active: {alert_type}")
                return

        # ZERO TOLERANCE MODE - Block ALL attacks immediately
        if ZERO_TOLERANCE_MODE and alert_type in critical_attacks:
            log.alert(f"🚫 ZERO TOLERANCE ({alert_type}) - Auto-blocking {ip}")
            self.firewall.block_ip(ip, f"Zero tolerance: {alert_type}")
            # Also auto-report to abuse contacts
            if profile.abuse_contacts:
                log.info(f"📧 Report to: {profile.abuse_contacts[0]}")
        elif alert_type in critical_attacks:
            log.alert(f"🚫 CRITICAL ATTACK ({alert_type}) - Auto-blocking {ip}")
            self.firewall.block_ip(ip, f"Critical attack: {alert_type}")

        # Auto-block high-threat attackers
        elif self.auto_block:
            if profile.threat_score >= 70 or profile.attack_count >= 3:
                self.firewall.block_ip(ip, f"Threat score: {profile.threat_score}, attacks: {profile.attack_count}")

        # Generate IC3 report for high-threat attackers
        if profile.threat_score >= 50 or profile.attack_count >= 5:
            report_path = self.ic3.generate_report(profile, profile.evidence_files)
            log.alert(f"High-threat attacker! FBI IC3 report: {report_path}")

    def _print_attacker_info(self, profile: AttackerProfile):
        """Print attacker information"""
        print("\n" + "=" * 60)
        print("🔍 ATTACKER INTELLIGENCE")
        print("=" * 60)
        print(f"IP Address:    {profile.ip}")
        print(f"Hostname:      {profile.hostname or 'Unknown'}")
        print(f"Location:      {profile.city or '?'}, {profile.country or '?'}")
        print(f"ISP:           {profile.isp or 'Unknown'}")
        print(f"Organization:  {profile.organization or 'Unknown'}")
        print(f"Attack Count:  {profile.attack_count}")
        print(f"Attack Types:  {', '.join(profile.attack_types)}")
        print(f"Threat Score:  {profile.threat_score}/100")
        if profile.abuse_contacts:
            print(f"Abuse Contact: {profile.abuse_contacts[0]}")
        print("=" * 60 + "\n")

    def _is_user_active(self) -> bool:
        """Check if a user is actively logged in to the system"""
        try:
            # Check for active console/GUI sessions
            result = subprocess.run(
                ["who"],
                capture_output=True, text=True, timeout=5
            )
            # If there's output from 'who', a user is logged in
            if result.stdout.strip():
                return True

            # Also check if screen is unlocked (macOS specific)
            result = subprocess.run(
                ["ioreg", "-r", "-c", "AppleBacklightDisplay"],
                capture_output=True, text=True, timeout=5
            )
            # If display is on, user is likely active
            if "IOMFBBrightness" in result.stdout:
                return True

            return False
        except Exception:
            # If we can't determine, assume user is active (safer)
            return True

    def start(self):
        """Start Sentinel daemon"""
        self.running = True

        print("""
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝

        Sentinel for macOS v{version}

        Monitoring:
        - Network connections
        - Authentication attempts
        - Port scans & connection floods

        Evidence: {evidence_dir}
        Reports:  {reports_dir}
        Logs:     {log_dir}

        Press Ctrl+C to stop
""".format(
            version=SENTINEL_VERSION,
            evidence_dir=EVIDENCE_DIR,
            reports_dir=REPORTS_DIR,
            log_dir=LOG_DIR
        ))

        log.info("Sentinel for macOS starting...")

        # Start monitors
        self.network_monitor.start()
        self.auth_monitor.start()
        self.ssl_monitor.start()
        self.flux_monitor.start()

        log.info("All monitors active - watching for threats")

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        """Stop Sentinel daemon"""
        log.info("Stopping Sentinel...")
        self.running = False
        self.network_monitor.stop()
        self.auth_monitor.stop()
        self.ssl_monitor.stop()
        self.flux_monitor.stop()
        print("\nSentinel stopped. Stay safe! 🛡️")

    def generate_report(self, ip: str) -> Optional[str]:
        """Generate FBI IC3 report for specific attacker"""
        profile = self.recon.get_profile(ip)
        if profile:
            return self.ic3.generate_report(profile, profile.evidence_files)
        else:
            log.error(f"No profile found for {ip}")
            return None

    def list_attackers(self):
        """List all known attackers"""
        attackers = self.recon.get_all_attackers()
        if not attackers:
            print("No attackers recorded yet.")
            return

        print("\n" + "=" * 80)
        print("KNOWN ATTACKERS")
        print("=" * 80)
        print(f"{'IP':<18} {'Country':<8} {'Attacks':<8} {'Threat':<8} {'Last Seen':<20}")
        print("-" * 80)

        for a in sorted(attackers, key=lambda x: x.threat_score, reverse=True):
            print(f"{a.ip:<18} {(a.country or '?'):<8} {a.attack_count:<8} {a.threat_score:<8} {a.last_seen[:19]}")

        print("=" * 80 + "\n")


# =============================================================================
# CLI
# =============================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Sentinel Security for macOS")
    parser.add_argument("command", nargs="?", default="start",
                       choices=["start", "attackers", "report", "test"],
                       help="Command to run")
    parser.add_argument("--ip", help="IP address for report generation")

    args = parser.parse_args()

    sentinel = SentinelMacOS()

    if args.command == "start":
        sentinel.start()
    elif args.command == "attackers":
        sentinel.list_attackers()
    elif args.command == "report":
        if args.ip:
            report = sentinel.generate_report(args.ip)
            if report:
                print(f"Report generated: {report}")
        else:
            print("Please specify --ip for report generation")
    elif args.command == "test":
        # Simulate an attack for testing
        log.info("Simulating attack for testing...")
        sentinel._handle_alert("port_scan", "203.0.113.50", {
            "ports_scanned": 15,
            "ports": [22, 80, 443, 8080, 3306]
        })


if __name__ == "__main__":
    main()
