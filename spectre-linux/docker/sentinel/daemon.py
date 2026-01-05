#!/usr/bin/env python3
"""
Spectre - Autonomous Security Daemon
======================================

An autonomous, self-healing security daemon for Linux servers.
Runs on Rocky Linux 9 / AlmaLinux 9 / RHEL 9.

Core Philosophy:
- Secure by default
- Minimal attack surface
- Self-defending and self-healing
- Complete audit trail
- Never store plaintext credentials
- REACTIVE to threats in real-time

Scanning Modes:
- Continuous: Real-time file/process/network monitoring
- Quick: Every 5 minutes - fast checks
- Standard: Every hour - package and port scanning
- Deep: Every 4 hours - full Lynis audit

Author: PentestAI Integration
License: MIT
"""

import os
import sys
import json
import time
import socket
import hashlib
import logging
import subprocess
import threading
import signal
import re
import struct
import fcntl
import select
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple, Set, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict
from queue import Queue, Empty
import urllib.request
import urllib.error
import ssl

# =============================================================================
# Spectre-Style Constants (Linux naming conventions)
# =============================================================================

kSpectreVersion = "2.0.0"
kSpectrePrefix = "[Spectre]"
kConfigPath = Path("/opt/spectre/config")
kSpectreDataPath = Path("/opt/spectre/data")
kSpectreLogPath = Path("/var/log/spectre")
kSpectreBaselinePath = Path("/opt/spectre/baseline")

# Threat Intelligence URLs
kCISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
kEPSS_API_URL = "https://api.first.org/data/v1/epss"
kNVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Thresholds
kEPSS_CRITICAL_THRESHOLD = 0.8
kEPSS_HIGH_THRESHOLD = 0.4
kCVSS_CRITICAL_THRESHOLD = 9.0
kCVSS_HIGH_THRESHOLD = 7.0

# Scan intervals (seconds)
kQuickScanInterval = 300       # 5 minutes
kStandardScanInterval = 3600   # 1 hour
kDeepScanInterval = 14400      # 4 hours
kWatchdogTimeoutSeconds = 300

# inotify constants (from linux/inotify.h)
IN_ACCESS = 0x00000001
IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_CLOSE_NOWRITE = 0x00000010
IN_OPEN = 0x00000020
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_ALL_EVENTS = 0x00000FFF

# Critical paths to monitor
kCriticalPaths = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/root/.ssh",
    "/etc/pam.d",
    "/etc/security",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/tmp",
    "/var/tmp",
]

# Suspicious process patterns
kSuspiciousProcessPatterns = [
    r"nc\s+-[el]",           # netcat listeners
    r"ncat\s+",              # ncat
    r"/dev/tcp/",            # bash reverse shells
    r"base64.*decode",       # base64 decoding in cmd
    r"python.*-c.*socket",   # python reverse shells
    r"perl.*socket",         # perl reverse shells
    r"ruby.*socket",         # ruby reverse shells
    r"wget.*\|.*sh",         # download and execute
    r"curl.*\|.*sh",         # download and execute
    r"chmod\s+[0-7]*777",    # world writable
    r"chmod\s+\+s",          # setuid
]

# =============================================================================
# Spectre Context Structures
# =============================================================================

class Severity(Enum):
    """Severity levels following Spectre security model"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ActionType(Enum):
    """Types of autonomous actions"""
    PATCH_APPLIED = "patch_applied"
    SERVICE_DISABLED = "service_disabled"
    FIREWALL_RULE = "firewall_rule"
    SELINUX_POLICY = "selinux_policy"
    CONFIG_HARDENED = "config_hardened"
    PROCESS_KILLED = "process_killed"
    FILE_QUARANTINED = "file_quarantined"
    USER_LOCKED = "user_locked"
    ALERT_SENT = "alert_sent"
    NO_ACTION = "no_action"
    MANUAL_REQUIRED = "manual_required"

class ScanType(Enum):
    """Types of scans"""
    CONTINUOUS = "continuous"
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"

@dataclass
class Vulnerability:
    """Represents a discovered vulnerability"""
    cve_id: str
    description: str
    severity: Severity
    cvss_score: float
    epss_score: float
    is_kev: bool
    affected_package: str
    affected_version: str
    fixed_version: Optional[str]
    discovered_at: str
    evidence_hash: str
    scan_type: ScanType = ScanType.STANDARD

@dataclass
class Threat:
    """Represents a real-time detected threat"""
    threat_id: str
    threat_type: str  # file_change, suspicious_process, network_anomaly, auth_failure
    severity: Severity
    description: str
    source: str
    detected_at: str
    evidence: Dict[str, Any]
    auto_response: Optional[str] = None

@dataclass
class Mitigation:
    """Represents an applied mitigation"""
    vuln_id: str
    action_type: ActionType
    action_details: str
    applied_at: str
    success: bool
    verification_result: str
    rollback_command: Optional[str]

@dataclass
class ScanContext:
    """Context for a security scan session"""
    scan_id: str
    scan_type: ScanType
    started_at: str
    completed_at: Optional[str] = None
    hostname: str = ""
    ip_address: str = ""
    os_version: str = ""
    kernel_version: str = ""
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    threats: List[Threat] = field(default_factory=list)
    mitigations: List[Mitigation] = field(default_factory=list)
    autorecon_failure_count: int = 0
    kSpectreStatus: str = "initializing"

# =============================================================================
# Logging Configuration
# =============================================================================

class Logger:
    """Spectre-style logging with syslog integration"""

    def __init__(self):
        self.logger = logging.getLogger("Spectre")
        self.logger.setLevel(logging.DEBUG)

        # Prevent duplicate handlers
        if self.logger.handlers:
            return

        # Syslog handler (only if /dev/log exists)
        if os.path.exists('/dev/log'):
            try:
                from logging.handlers import SysLogHandler
                syslog_handler = SysLogHandler(address='/dev/log')
                syslog_handler.setLevel(logging.INFO)
                syslog_format = logging.Formatter(f'{kSpectrePrefix} %(levelname)s: %(message)s')
                syslog_handler.setFormatter(syslog_format)
                self.logger.addHandler(syslog_handler)
            except Exception:
                pass

        # File handler
        kSpectreLogPath.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(kSpectreLogPath / "spectre.log")
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter(
            '%(asctime)s ' + kSpectrePrefix + ' %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_format)
        self.logger.addHandler(file_handler)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(file_format)
        self.logger.addHandler(console_handler)

        # Alert log (critical events only)
        alert_handler = logging.FileHandler(kSpectreLogPath / "alerts.log")
        alert_handler.setLevel(logging.WARNING)
        alert_handler.setFormatter(file_format)
        self.logger.addHandler(alert_handler)

    def _hash_sensitive(self, data: str) -> str:
        """Hash sensitive data before logging"""
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def audit(self, action: str, details: Dict[str, Any], reasoning: str):
        """Log an auditable action with full reasoning"""
        safe_details = {}
        sensitive_keys = ['password', 'credential', 'secret', 'key', 'token']
        for k, v in details.items():
            if any(s in k.lower() for s in sensitive_keys):
                safe_details[k] = f"[HASHED:{self._hash_sensitive(str(v))}]"
            else:
                safe_details[k] = v

        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "details": safe_details,
            "reasoning": reasoning
        }
        self.logger.info(f"AUDIT: {json.dumps(audit_entry)}")

    def alert(self, msg: str, threat: Optional[Threat] = None):
        """Log a security alert"""
        alert_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "message": msg,
            "threat": asdict(threat) if threat else None
        }
        self.logger.warning(f"ALERT: {json.dumps(alert_data)}")

    def info(self, msg: str):
        self.logger.info(msg)

    def warning(self, msg: str):
        self.logger.warning(msg)

    def error(self, msg: str):
        self.logger.error(msg)

    def debug(self, msg: str):
        self.logger.debug(msg)

    def critical(self, msg: str):
        self.logger.critical(msg)

# Global logger
spectre_log = Logger()

# =============================================================================
# Configuration Manager
# =============================================================================

class Config:
    """Configuration management"""

    DEFAULT_CONFIG = {
        "version": "2.0.0",
        "spectre": {
            "quick_scan_interval_minutes": 5,
            "standard_scan_interval_hours": 1,
            "deep_scan_interval_hours": 4,
            "watchdog_timeout_seconds": 300,
            "max_concurrent_scans": 1
        },
        "continuous_monitoring": {
            "enabled": True,
            "file_monitoring": True,
            "process_monitoring": True,
            "network_monitoring": True,
            "auth_monitoring": True
        },
        "thresholds": {
            "epss_critical": 0.8,
            "epss_high": 0.4,
            "cvss_critical": 9.0,
            "cvss_high": 7.0,
            "auth_failures_threshold": 5,
            "auth_failures_window_minutes": 10
        },
        "auto_remediation": {
            "enabled": True,
            "patch_critical": True,
            "patch_high": True,
            "patch_medium": False,
            "disable_services": True,
            "firewall_rules": True,
            "selinux_policies": True,
            "kill_suspicious_processes": True,
            "quarantine_files": True,
            "lock_users": True
        },
        "expected_ports": [22, 80, 443],
        "excluded_packages": ["kernel", "glibc", "systemd"],
        "excluded_processes": ["sshd", "systemd", "spectre"],
        "threat_intel": {
            "cisa_kev_enabled": True,
            "epss_enabled": True,
            "nvd_enabled": True,
            "refresh_interval_hours": 1
        },
        "alerting": {
            "enabled": True,
            "webhook_url": "",
            "email": "",
            "slack_webhook": "",
            "alert_on_critical": True,
            "alert_on_high": True,
            "alert_on_medium": False
        },
        "logging": {
            "level": "INFO",
            "syslog_enabled": True,
            "file_enabled": True,
            "audit_trail": True
        }
    }

    def __init__(self):
        self.config_path = kConfigPath / "spectre.json"
        self.config = self._load_config()

    def _load_config(self) -> Dict:
        """Load configuration from file or create default"""
        if self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    config = json.load(f)
                    # Merge with defaults for any missing keys
                    return self._merge_config(self.DEFAULT_CONFIG, config)
            except Exception as e:
                spectre_log.error(f"Failed to load config: {e}")

        # Create default config
        self._save_config(self.DEFAULT_CONFIG)
        return self.DEFAULT_CONFIG

    def _merge_config(self, default: Dict, override: Dict) -> Dict:
        """Deep merge configuration"""
        result = default.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_config(result[key], value)
            else:
                result[key] = value
        return result

    def _save_config(self, config: Dict):
        """Save configuration to file"""
        kConfigPath.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2)

    def get(self, *keys, default=None):
        """Get nested config value"""
        value = self.config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

# =============================================================================
# Dependency Management
# =============================================================================

class DependencyManager:
    """Manages system dependencies across different Linux distributions"""

    # Package mappings for different distros
    PACKAGE_MAP = {
        "apk": {  # Alpine Linux
            "nmap": "nmap",
            "lynis": "lynis",
            "python3-pip": "py3-pip",
            "firewalld": "iptables",
            "curl": "curl",
            "jq": "jq",
            "rkhunter": "rkhunter",
            "chkrootkit": "chkrootkit",
            "audit": "audit",
            "procps": "procps",
            "lsof": "lsof",
            "findutils": "findutils",
        },
        "dnf": {  # RHEL/Rocky/Fedora
            "nmap": "nmap",
            "lynis": "lynis",
            "python3-pip": "python3-pip",
            "firewalld": "firewalld",
            "policycoreutils": "policycoreutils-python-utils",
            "yum-utils": "yum-utils",
            "curl": "curl",
            "jq": "jq",
            "aide": "aide",
            "rkhunter": "rkhunter",
            "clamav": "clamav",
            "audit": "audit",
        },
        "apt": {  # Debian/Ubuntu
            "nmap": "nmap",
            "lynis": "lynis",
            "python3-pip": "python3-pip",
            "curl": "curl",
            "jq": "jq",
            "aide": "aide",
            "rkhunter": "rkhunter",
            "chkrootkit": "chkrootkit",
            "clamav": "clamav-daemon",
            "audit": "auditd",
        }
    }

    REQUIRED_PIP = [
        "requests",
        "anthropic",
        "psutil",
        "watchdog",
        "python-dotenv"
    ]

    _pkg_mgr_cache = None

    @classmethod
    def ensure_dependencies(cls) -> bool:
        """Install missing dependencies"""
        spectre_log.info("Checking system dependencies...")

        pkg_mgr = cls._detect_package_manager()
        if not pkg_mgr:
            spectre_log.warning("No supported package manager found, skipping system packages")
            # Still try to check pip packages
        else:
            spectre_log.info(f"Detected package manager: {pkg_mgr}")
            packages = cls.PACKAGE_MAP.get(pkg_mgr, {})
            for pkg_name, pkg_actual in packages.items():
                if not cls._is_package_installed(pkg_actual, pkg_mgr):
                    spectre_log.audit(
                        "DEPENDENCY_INSTALL",
                        {"package": pkg_actual, "manager": pkg_mgr},
                        f"Package {pkg_actual} required for Spectre operation"
                    )
                    if not cls._install_package(pkg_mgr, pkg_actual):
                        spectre_log.debug(f"Optional package {pkg_actual} not installed")

        for pkg in cls.REQUIRED_PIP:
            try:
                __import__(pkg.replace("-", "_"))
            except ImportError:
                spectre_log.audit(
                    "PIP_DEPENDENCY_INSTALL",
                    {"package": pkg},
                    f"Python package {pkg} required for API integration"
                )
                cls._install_pip_package(pkg)

        spectre_log.info("Dependency check complete")
        return True

    @classmethod
    def _detect_package_manager(cls) -> Optional[str]:
        if cls._pkg_mgr_cache:
            return cls._pkg_mgr_cache

        # Check for Alpine first (most common in containers)
        if os.path.exists("/etc/alpine-release"):
            cls._pkg_mgr_cache = "apk"
            return "apk"

        # Check for various package managers
        for mgr in ["apk", "dnf", "yum", "apt-get"]:
            try:
                result = subprocess.run(
                    ["which", mgr],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0:
                    cls._pkg_mgr_cache = "apt" if mgr == "apt-get" else mgr
                    return cls._pkg_mgr_cache
            except Exception:
                continue
        return None

    @classmethod
    def _is_package_installed(cls, package: str, pkg_mgr: str = None) -> bool:
        if not pkg_mgr:
            pkg_mgr = cls._detect_package_manager()

        try:
            if pkg_mgr == "apk":
                result = subprocess.run(
                    ["apk", "info", "-e", package],
                    capture_output=True,
                    timeout=10
                )
            elif pkg_mgr in ["dnf", "yum"]:
                result = subprocess.run(
                    ["rpm", "-q", package],
                    capture_output=True,
                    timeout=10
                )
            elif pkg_mgr == "apt":
                result = subprocess.run(
                    ["dpkg", "-s", package],
                    capture_output=True,
                    timeout=10
                )
            else:
                return False
            return result.returncode == 0
        except Exception:
            return False

    @classmethod
    def _install_package(cls, pkg_mgr: str, package: str) -> bool:
        try:
            if pkg_mgr == "apk":
                cmd = ["apk", "add", "--no-cache", package]
            elif pkg_mgr in ["dnf", "yum"]:
                cmd = [pkg_mgr, "install", "-y", package]
            elif pkg_mgr == "apt":
                cmd = ["apt-get", "install", "-y", package]
            else:
                return False

            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=300
            )
            return result.returncode == 0
        except Exception as e:
            spectre_log.debug(f"Failed to install {package}: {e}")
            return False

    @staticmethod
    def _install_pip_package(package: str) -> bool:
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "--quiet", package],
                capture_output=True,
                timeout=120
            )
            return True
        except Exception as e:
            spectre_log.error(f"Failed to install pip package {package}: {e}")
            return False

# =============================================================================
# Threat Intelligence Integration
# =============================================================================

class ThreatIntel:
    """Threat intelligence gathering"""

    def __init__(self, anthropic_api_key: Optional[str] = None):
        self.kev_cache: Dict[str, Any] = {}
        self.kev_last_update: Optional[datetime] = None
        self.epss_cache: Dict[str, float] = {}
        self.nvd_cache: Dict[str, Any] = {}
        self.anthropic_key = anthropic_api_key or os.environ.get("ANTHROPIC_API_KEY")

    def fetch_cisa_kev(self) -> Dict[str, Any]:
        """Fetch CISA Known Exploited Vulnerabilities catalog"""
        if self.kev_last_update and datetime.utcnow() - self.kev_last_update < timedelta(hours=1):
            return self.kev_cache

        spectre_log.info("Fetching CISA KEV catalog...")
        try:
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(kCISA_KEV_URL, context=ctx, timeout=30) as response:
                data = json.loads(response.read().decode())

            self.kev_cache = {
                vuln["cveID"]: vuln
                for vuln in data.get("vulnerabilities", [])
            }
            self.kev_last_update = datetime.utcnow()

            spectre_log.audit(
                "THREAT_INTEL_UPDATE",
                {"source": "CISA_KEV", "count": len(self.kev_cache)},
                "Updated CISA Known Exploited Vulnerabilities catalog"
            )
            return self.kev_cache

        except Exception as e:
            spectre_log.error(f"Failed to fetch CISA KEV: {e}")
            return self.kev_cache

    def get_epss_score(self, cve_id: str) -> float:
        """Get EPSS score for CVE"""
        if cve_id in self.epss_cache:
            return self.epss_cache[cve_id]

        try:
            url = f"{kEPSS_API_URL}?cve={cve_id}"
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(url, context=ctx, timeout=10) as response:
                data = json.loads(response.read().decode())

            if data.get("data"):
                score = float(data["data"][0].get("epss", 0))
                self.epss_cache[cve_id] = score
                return score

        except Exception as e:
            spectre_log.debug(f"Failed to fetch EPSS for {cve_id}: {e}")

        return 0.0

    def get_nvd_data(self, cve_id: str) -> Optional[Dict]:
        """Get CVE details from NVD"""
        if cve_id in self.nvd_cache:
            return self.nvd_cache[cve_id]

        try:
            url = f"{kNVD_API_URL}?cveId={cve_id}"
            ctx = ssl.create_default_context()
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Spectre/2.0')

            with urllib.request.urlopen(req, context=ctx, timeout=15) as response:
                data = json.loads(response.read().decode())

            if data.get("vulnerabilities"):
                vuln_data = data["vulnerabilities"][0]["cve"]
                self.nvd_cache[cve_id] = vuln_data
                return vuln_data

        except Exception as e:
            spectre_log.debug(f"Failed to fetch NVD data for {cve_id}: {e}")

        return None

    def is_in_kev(self, cve_id: str) -> bool:
        """Check if CVE is in CISA KEV list"""
        kev = self.fetch_cisa_kev()
        return cve_id in kev

    def get_ai_analysis(self, vulnerability: Vulnerability, system_context: str) -> Optional[str]:
        """Use Anthropic API for intelligent vulnerability analysis"""
        if not self.anthropic_key:
            return None

        try:
            import anthropic
            client = anthropic.Anthropic(api_key=self.anthropic_key)

            prompt = f"""Analyze this vulnerability and recommend mitigation:

CVE: {vulnerability.cve_id}
Description: {vulnerability.description}
CVSS Score: {vulnerability.cvss_score}
EPSS Score: {vulnerability.epss_score}
In CISA KEV: {vulnerability.is_kev}
Affected Package: {vulnerability.affected_package} {vulnerability.affected_version}
Fixed Version: {vulnerability.fixed_version or 'Unknown'}

System Context:
{system_context}

Provide:
1. Risk assessment (1 sentence)
2. Recommended mitigation if no patch available
3. Verification command to confirm mitigation"""

            message = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=500,
                messages=[{"role": "user", "content": prompt}]
            )

            return message.content[0].text

        except Exception as e:
            spectre_log.debug(f"AI analysis unavailable: {e}")
            return None

# =============================================================================
# AI Security Engine - Intelligent Threat Analysis
# =============================================================================

class AISecurityEngine:
    """
    AI-powered security analysis engine using Claude.
    Provides intelligent threat correlation, attack pattern detection,
    and autonomous remediation decisions.
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.threat_history: List[Dict] = []
        self.correlation_window = timedelta(minutes=30)
        self.client = None

        if self.api_key:
            try:
                import anthropic
                self.client = anthropic.Anthropic(api_key=self.api_key)
                spectre_log.info("AI Security Engine initialized with Claude")
            except Exception as e:
                spectre_log.warning(f"AI Security Engine unavailable: {e}")

    def _call_claude(self, prompt: str, max_tokens: int = 1000) -> Optional[str]:
        """Make a call to Claude API"""
        if not self.client:
            return None
        try:
            message = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}]
            )
            return message.content[0].text
        except Exception as e:
            spectre_log.error(f"Claude API error: {e}")
            return None

    def correlate_threats(self, current_threat: Dict, recent_threats: List[Dict]) -> Dict:
        """
        Use AI to correlate multiple threats and detect attack patterns.
        Returns attack chain analysis if pattern detected.
        """
        if not self.client or len(recent_threats) < 2:
            return {"attack_chain_detected": False}

        # Build threat timeline
        threat_timeline = "\n".join([
            f"- {t.get('detected_at', 'unknown')}: {t.get('threat_type', 'unknown')} - {t.get('description', '')[:100]}"
            for t in recent_threats[-10:]  # Last 10 threats
        ])

        prompt = f"""Analyze these security events for attack patterns:

CURRENT THREAT:
Type: {current_threat.get('threat_type')}
Description: {current_threat.get('description')}
Source: {current_threat.get('source')}
Evidence: {json.dumps(current_threat.get('evidence', {}), default=str)[:500]}

RECENT THREAT TIMELINE (last 30 minutes):
{threat_timeline}

Analyze for:
1. Is this part of a multi-stage attack? (reconnaissance -> exploitation -> persistence -> exfiltration)
2. Attack pattern name if recognized (e.g., "reverse shell establishment", "privilege escalation chain", "lateral movement")
3. Predicted next attacker action
4. Recommended immediate response (1-2 sentences)

Respond in JSON format:
{{"attack_chain_detected": true/false, "pattern_name": "...", "confidence": 0.0-1.0, "stage": "...", "predicted_next": "...", "immediate_action": "..."}}"""

        response = self._call_claude(prompt, max_tokens=500)
        if response:
            try:
                # Extract JSON from response
                import re
                json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group())
            except Exception:
                pass

        return {"attack_chain_detected": False}

    def get_remediation_decision(self, threat: Dict, system_state: Dict) -> Dict:
        """
        Use AI to make intelligent remediation decisions based on context.
        """
        if not self.client:
            return {"action": "default", "reason": "AI unavailable"}

        prompt = f"""As an autonomous security system, decide the best remediation for this threat:

THREAT:
Type: {threat.get('threat_type')}
Severity: {threat.get('severity')}
Description: {threat.get('description')}
Evidence: {json.dumps(threat.get('evidence', {}), default=str)[:500]}

SYSTEM STATE:
Hostname: {system_state.get('hostname', 'unknown')}
Critical Services: {system_state.get('critical_services', [])}
Current Load: {system_state.get('load', 'unknown')}
Active Users: {system_state.get('active_users', 0)}

AVAILABLE ACTIONS:
1. kill_process - Terminate suspicious process
2. block_ip - Add firewall rule to block IP
3. quarantine_file - Move file to quarantine
4. disable_service - Stop and disable a service
5. lock_user - Lock a user account
6. alert_only - Just send alert, no action
7. isolate_network - Block all non-essential network traffic

Consider:
- False positive risk
- Business impact
- Attacker's potential next move
- Evidence strength

Respond in JSON:
{{"action": "...", "reason": "...", "confidence": 0.0-1.0, "additional_actions": [], "monitoring_recommendation": "..."}}"""

        response = self._call_claude(prompt, max_tokens=400)
        if response:
            try:
                import re
                json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group())
            except Exception:
                pass

        return {"action": "alert_only", "reason": "AI parsing failed, defaulting to alert"}

    def analyze_security_posture(self, scan_results: Dict) -> Dict:
        """
        Provide comprehensive AI security assessment and recommendations.
        """
        if not self.client:
            return {"recommendations": [], "risk_score": 0}

        prompt = f"""Analyze this Linux server's security posture:

SCAN SUMMARY:
Total Vulnerabilities: {scan_results.get('total_vulnerabilities', 0)}
Critical: {scan_results.get('critical', 0)}
High: {scan_results.get('high', 0)}
Medium: {scan_results.get('medium', 0)}
Unexpected Open Ports: {scan_results.get('unexpected_ports', [])}
Failed Mitigations: {scan_results.get('mitigations_failed', 0)}

SYSTEM INFO:
OS: {scan_results.get('os_version', 'unknown')}
Kernel: {scan_results.get('kernel_version', 'unknown')}

Provide:
1. Overall risk score (0-100)
2. Top 3 priority actions
3. Hardening recommendations
4. Compliance gaps (CIS, NIST)

Respond in JSON:
{{"risk_score": 0-100, "risk_level": "critical/high/medium/low", "priority_actions": ["...", "...", "..."], "hardening": ["...", "..."], "compliance_gaps": ["..."], "executive_summary": "..."}}"""

        response = self._call_claude(prompt, max_tokens=600)
        if response:
            try:
                import re
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group())
            except Exception:
                pass

        return {"recommendations": [], "risk_score": 50}

    def detect_anomaly(self, event_type: str, event_data: Dict, baseline: Dict) -> Dict:
        """
        Use AI to detect if an event is anomalous compared to baseline behavior.
        """
        if not self.client:
            return {"is_anomaly": False}

        prompt = f"""Determine if this event is anomalous:

EVENT TYPE: {event_type}
EVENT DATA: {json.dumps(event_data, default=str)[:400]}

BASELINE BEHAVIOR:
{json.dumps(baseline, default=str)[:400]}

Is this event suspicious or normal system behavior?
Consider: time of day, process lineage, network destination, file location

Respond in JSON:
{{"is_anomaly": true/false, "confidence": 0.0-1.0, "reason": "...", "threat_type": "..." or null}}"""

        response = self._call_claude(prompt, max_tokens=300)
        if response:
            try:
                import re
                json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group())
            except Exception:
                pass

        return {"is_anomaly": False}

    def generate_incident_report(self, threats: List[Dict], mitigations: List[Dict]) -> str:
        """
        Generate a comprehensive incident report using AI.
        """
        if not self.client:
            return "AI unavailable for report generation"

        prompt = f"""Generate a security incident report:

THREATS DETECTED ({len(threats)}):
{json.dumps(threats[:5], default=str, indent=2)[:1500]}

MITIGATIONS APPLIED ({len(mitigations)}):
{json.dumps(mitigations[:5], default=str, indent=2)[:1000]}

Generate a professional incident report with:
1. Executive Summary (2-3 sentences)
2. Timeline of Events
3. Impact Assessment
4. Actions Taken
5. Recommendations
6. Lessons Learned

Format as markdown."""

        response = self._call_claude(prompt, max_tokens=1500)
        return response or "Report generation failed"

    def add_threat_to_history(self, threat: Dict):
        """Add threat to history for correlation"""
        threat['recorded_at'] = datetime.utcnow().isoformat()
        self.threat_history.append(threat)

        # Keep only recent threats
        cutoff = datetime.utcnow() - self.correlation_window
        self.threat_history = [
            t for t in self.threat_history
            if datetime.fromisoformat(t.get('recorded_at', datetime.utcnow().isoformat())) > cutoff
        ]


# =============================================================================
# Continuous Monitoring - File Integrity
# =============================================================================

class FileMonitor:
    """Real-time file integrity monitoring using inotify"""

    def __init__(self, threat_queue: Queue, config: Config):
        self.threat_queue = threat_queue
        self.config = config
        self.running = False
        self.inotify_fd = None
        self.watch_descriptors: Dict[int, str] = {}
        self.file_hashes: Dict[str, str] = {}
        self.thread: Optional[threading.Thread] = None

    def _compute_hash(self, filepath: str) -> str:
        """Compute SHA256 hash of file"""
        try:
            with open(filepath, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return ""

    def _load_baseline(self):
        """Load or create baseline file hashes"""
        baseline_file = kSpectreBaselinePath / "file_hashes.json"

        if baseline_file.exists():
            try:
                with open(baseline_file) as f:
                    self.file_hashes = json.load(f)
                spectre_log.info(f"Loaded baseline with {len(self.file_hashes)} file hashes")
                return
            except Exception as e:
                spectre_log.warning(f"Failed to load baseline: {e}")

        # Create new baseline
        spectre_log.info("Creating file integrity baseline...")
        for path in kCriticalPaths:
            if os.path.isfile(path):
                self.file_hashes[path] = self._compute_hash(path)
            elif os.path.isdir(path):
                try:
                    for root, dirs, files in os.walk(path):
                        for fname in files:
                            fpath = os.path.join(root, fname)
                            self.file_hashes[fpath] = self._compute_hash(fpath)
                except Exception:
                    pass

        # Save baseline
        kSpectreBaselinePath.mkdir(parents=True, exist_ok=True)
        with open(baseline_file, 'w') as f:
            json.dump(self.file_hashes, f)
        spectre_log.audit(
            "BASELINE_CREATED",
            {"files": len(self.file_hashes)},
            "Created file integrity baseline"
        )

    def start(self):
        """Start file monitoring"""
        if not self.config.get("continuous_monitoring", "file_monitoring", default=True):
            spectre_log.info("File monitoring disabled in config")
            return

        self._load_baseline()

        try:
            # Initialize inotify
            import ctypes
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            self.inotify_fd = libc.inotify_init1(0)

            if self.inotify_fd < 0:
                spectre_log.warning("Failed to initialize inotify, using polling instead")
                self._start_polling()
                return

            # Add watches for critical paths
            for path in kCriticalPaths:
                if os.path.exists(path):
                    try:
                        wd = libc.inotify_add_watch(
                            self.inotify_fd,
                            path.encode(),
                            IN_MODIFY | IN_CREATE | IN_DELETE | IN_ATTRIB | IN_MOVED_TO
                        )
                        if wd >= 0:
                            self.watch_descriptors[wd] = path
                    except Exception as e:
                        spectre_log.debug(f"Failed to watch {path}: {e}")

            self.running = True
            self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.thread.start()
            spectre_log.info(f"File monitoring started for {len(self.watch_descriptors)} paths")

        except Exception as e:
            spectre_log.warning(f"inotify unavailable: {e}, using polling")
            self._start_polling()

    def _start_polling(self):
        """Fallback to polling-based file monitoring"""
        self.running = True
        self.thread = threading.Thread(target=self._polling_loop, daemon=True)
        self.thread.start()

    def _polling_loop(self):
        """Poll files for changes every 30 seconds"""
        while self.running:
            try:
                for filepath, old_hash in list(self.file_hashes.items()):
                    if not os.path.exists(filepath):
                        self._report_threat("file_deleted", filepath, {"old_hash": old_hash})
                        del self.file_hashes[filepath]
                    else:
                        new_hash = self._compute_hash(filepath)
                        if new_hash and new_hash != old_hash:
                            self._report_threat("file_modified", filepath, {
                                "old_hash": old_hash,
                                "new_hash": new_hash
                            })
                            self.file_hashes[filepath] = new_hash
                time.sleep(30)
            except Exception as e:
                spectre_log.error(f"Polling error: {e}")
                time.sleep(60)

    def _monitor_loop(self):
        """Main inotify monitoring loop"""
        while self.running and self.inotify_fd:
            try:
                ready, _, _ = select.select([self.inotify_fd], [], [], 1.0)
                if not ready:
                    continue

                data = os.read(self.inotify_fd, 4096)
                offset = 0

                while offset < len(data):
                    wd, mask, cookie, name_len = struct.unpack_from('iIII', data, offset)
                    offset += 16
                    name = data[offset:offset + name_len].rstrip(b'\x00').decode('utf-8', errors='replace')
                    offset += name_len

                    if wd in self.watch_descriptors:
                        path = self.watch_descriptors[wd]
                        full_path = os.path.join(path, name) if name else path

                        event_type = None
                        if mask & IN_MODIFY:
                            event_type = "file_modified"
                        elif mask & IN_CREATE:
                            event_type = "file_created"
                        elif mask & IN_DELETE:
                            event_type = "file_deleted"
                        elif mask & IN_ATTRIB:
                            event_type = "file_attributes_changed"
                        elif mask & IN_MOVED_TO:
                            event_type = "file_moved"

                        if event_type:
                            self._report_threat(event_type, full_path, {"mask": mask})

            except Exception as e:
                if self.running:
                    spectre_log.error(f"File monitor error: {e}")
                time.sleep(1)

    def _report_threat(self, event_type: str, filepath: str, evidence: Dict):
        """Report a file integrity threat"""
        # Determine severity based on file
        severity = Severity.MEDIUM
        if any(crit in filepath for crit in ['/etc/passwd', '/etc/shadow', '/etc/sudoers', '.ssh']):
            severity = Severity.CRITICAL
        elif '/etc/' in filepath or '/usr/lib/systemd' in filepath:
            severity = Severity.HIGH

        threat = Threat(
            threat_id=f"FILE-{hashlib.md5(f'{filepath}{datetime.utcnow()}'.encode()).hexdigest()[:8]}",
            threat_type=event_type,
            severity=severity,
            description=f"File integrity alert: {event_type} on {filepath}",
            source="file_monitor",
            detected_at=datetime.utcnow().isoformat(),
            evidence={**evidence, "path": filepath}
        )

        self.threat_queue.put(threat)
        spectre_log.alert(f"File integrity: {event_type} - {filepath}", threat)

    def stop(self):
        """Stop file monitoring"""
        self.running = False
        if self.inotify_fd:
            os.close(self.inotify_fd)
        if self.thread:
            self.thread.join(timeout=5)

# =============================================================================
# Continuous Monitoring - Process Monitor
# =============================================================================

class ProcessMonitor:
    """Real-time process monitoring for suspicious activity"""

    def __init__(self, threat_queue: Queue, config: Config):
        self.threat_queue = threat_queue
        self.config = config
        self.running = False
        self.known_pids: Set[int] = set()
        self.thread: Optional[threading.Thread] = None

    def start(self):
        """Start process monitoring"""
        if not self.config.get("continuous_monitoring", "process_monitoring", default=True):
            spectre_log.info("Process monitoring disabled in config")
            return

        # Get initial process list
        self._refresh_known_pids()

        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        spectre_log.info("Process monitoring started")

    def _refresh_known_pids(self):
        """Get current process list"""
        try:
            for pid in os.listdir('/proc'):
                if pid.isdigit():
                    self.known_pids.add(int(pid))
        except Exception:
            pass

    def _get_process_info(self, pid: int) -> Optional[Dict]:
        """Get detailed process information"""
        try:
            cmdline_path = f'/proc/{pid}/cmdline'
            exe_path = f'/proc/{pid}/exe'

            # Read command line
            with open(cmdline_path, 'rb') as f:
                cmdline = f.read().decode('utf-8', errors='replace').replace('\x00', ' ').strip()

            # Read executable path
            try:
                exe = os.readlink(exe_path)
            except Exception:
                exe = "unknown"

            # Read process status
            with open(f'/proc/{pid}/status') as f:
                status = f.read()

            # Parse UID
            uid_match = re.search(r'Uid:\s+(\d+)', status)
            uid = int(uid_match.group(1)) if uid_match else -1

            # Parse parent PID
            ppid_match = re.search(r'PPid:\s+(\d+)', status)
            ppid = int(ppid_match.group(1)) if ppid_match else -1

            return {
                "pid": pid,
                "cmdline": cmdline,
                "exe": exe,
                "uid": uid,
                "ppid": ppid
            }

        except Exception:
            return None

    def _is_suspicious(self, proc_info: Dict) -> Tuple[bool, str]:
        """Check if process is suspicious"""
        cmdline = proc_info.get("cmdline", "")
        exe = proc_info.get("exe", "")

        # Check against suspicious patterns
        for pattern in kSuspiciousProcessPatterns:
            if re.search(pattern, cmdline, re.IGNORECASE):
                return True, f"Matches suspicious pattern: {pattern}"

        # Check for processes running from /tmp or /dev/shm
        if exe.startswith('/tmp/') or exe.startswith('/dev/shm/') or exe.startswith('/var/tmp/'):
            return True, f"Executable running from suspicious location: {exe}"

        # Check for deleted executables (common for malware)
        if '(deleted)' in exe:
            return True, f"Running deleted executable: {exe}"

        # Check for shell spawned by web server
        if proc_info.get("ppid"):
            try:
                parent = self._get_process_info(proc_info["ppid"])
                if parent and any(web in parent.get("cmdline", "") for web in ["httpd", "nginx", "apache"]):
                    if any(shell in exe for shell in ["/bin/sh", "/bin/bash", "/bin/dash"]):
                        return True, "Shell spawned by web server process"
            except Exception:
                pass

        return False, ""

    def _monitor_loop(self):
        """Main process monitoring loop"""
        while self.running:
            try:
                current_pids = set()

                for pid in os.listdir('/proc'):
                    if not pid.isdigit():
                        continue

                    pid_int = int(pid)
                    current_pids.add(pid_int)

                    # Check new processes
                    if pid_int not in self.known_pids:
                        proc_info = self._get_process_info(pid_int)
                        if proc_info:
                            is_suspicious, reason = self._is_suspicious(proc_info)
                            if is_suspicious:
                                self._report_threat(proc_info, reason)

                self.known_pids = current_pids
                time.sleep(2)  # Check every 2 seconds

            except Exception as e:
                spectre_log.error(f"Process monitor error: {e}")
                time.sleep(10)

    def _report_threat(self, proc_info: Dict, reason: str):
        """Report a suspicious process"""
        threat = Threat(
            threat_id=f"PROC-{proc_info['pid']}-{int(time.time())}",
            threat_type="suspicious_process",
            severity=Severity.HIGH,
            description=f"Suspicious process detected: {reason}",
            source="process_monitor",
            detected_at=datetime.utcnow().isoformat(),
            evidence=proc_info
        )

        self.threat_queue.put(threat)
        spectre_log.alert(f"Suspicious process: PID {proc_info['pid']} - {reason}", threat)

    def stop(self):
        """Stop process monitoring"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)

# =============================================================================
# Continuous Monitoring - Network Monitor
# =============================================================================

class NetworkMonitor:
    """Monitor network connections for anomalies"""

    def __init__(self, threat_queue: Queue, config: Config):
        self.threat_queue = threat_queue
        self.config = config
        self.running = False
        self.known_connections: Set[str] = set()
        self.thread: Optional[threading.Thread] = None

        # Suspicious ports
        self.suspicious_ports = {
            4444, 4445, 5555, 6666, 6667,  # Common backdoor/IRC ports
            31337, 1337,  # Hacker culture ports
            12345, 54321,  # Common trojan ports
        }

    def start(self):
        """Start network monitoring"""
        if not self.config.get("continuous_monitoring", "network_monitoring", default=True):
            spectre_log.info("Network monitoring disabled in config")
            return

        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        spectre_log.info("Network monitoring started")

    def _get_connections(self) -> List[Dict]:
        """Get current network connections"""
        connections = []

        try:
            # Parse /proc/net/tcp and /proc/net/tcp6
            for proto_file in ['/proc/net/tcp', '/proc/net/tcp6']:
                if not os.path.exists(proto_file):
                    continue

                with open(proto_file) as f:
                    lines = f.readlines()[1:]  # Skip header

                for line in lines:
                    parts = line.split()
                    if len(parts) < 10:
                        continue

                    local_addr = parts[1]
                    remote_addr = parts[2]
                    state = int(parts[3], 16)
                    uid = int(parts[7])
                    inode = parts[9]

                    # Parse addresses
                    local_ip, local_port = self._parse_address(local_addr)
                    remote_ip, remote_port = self._parse_address(remote_addr)

                    # State 0A = LISTEN, 01 = ESTABLISHED
                    state_name = "LISTEN" if state == 0x0A else "ESTABLISHED" if state == 0x01 else "OTHER"

                    connections.append({
                        "local_ip": local_ip,
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "state": state_name,
                        "uid": uid,
                        "inode": inode
                    })

        except Exception as e:
            spectre_log.debug(f"Failed to read connections: {e}")

        return connections

    def _parse_address(self, addr: str) -> Tuple[str, int]:
        """Parse hex address from /proc/net/tcp"""
        try:
            ip_hex, port_hex = addr.split(':')
            port = int(port_hex, 16)

            # Convert IP (little-endian for IPv4)
            if len(ip_hex) == 8:
                ip_int = int(ip_hex, 16)
                ip = f"{ip_int & 0xff}.{(ip_int >> 8) & 0xff}.{(ip_int >> 16) & 0xff}.{(ip_int >> 24) & 0xff}"
            else:
                ip = ip_hex  # IPv6, keep as hex for now

            return ip, port
        except Exception:
            return "0.0.0.0", 0

    def _is_suspicious_connection(self, conn: Dict) -> Tuple[bool, str]:
        """Check if connection is suspicious"""
        # Check for suspicious ports
        if conn["remote_port"] in self.suspicious_ports:
            return True, f"Connection to suspicious port {conn['remote_port']}"

        if conn["local_port"] in self.suspicious_ports and conn["state"] == "LISTEN":
            return True, f"Listening on suspicious port {conn['local_port']}"

        # Check for reverse shell indicators (high port to external IP)
        if conn["state"] == "ESTABLISHED":
            if conn["remote_port"] > 1024 and not conn["remote_ip"].startswith(("127.", "10.", "172.", "192.168.")):
                # Outbound to high port on external IP - potential reverse shell
                if conn["local_port"] > 30000:
                    return True, f"Potential reverse shell: outbound to {conn['remote_ip']}:{conn['remote_port']}"

        return False, ""

    def _monitor_loop(self):
        """Main network monitoring loop"""
        while self.running:
            try:
                connections = self._get_connections()

                for conn in connections:
                    conn_key = f"{conn['local_ip']}:{conn['local_port']}-{conn['remote_ip']}:{conn['remote_port']}"

                    if conn_key not in self.known_connections:
                        is_suspicious, reason = self._is_suspicious_connection(conn)
                        if is_suspicious:
                            self._report_threat(conn, reason)
                        self.known_connections.add(conn_key)

                # Clean up old connections
                current_keys = {f"{c['local_ip']}:{c['local_port']}-{c['remote_ip']}:{c['remote_port']}"
                               for c in connections}
                self.known_connections = self.known_connections.intersection(current_keys)

                time.sleep(5)  # Check every 5 seconds

            except Exception as e:
                spectre_log.error(f"Network monitor error: {e}")
                time.sleep(30)

    def _report_threat(self, conn: Dict, reason: str):
        """Report a network anomaly"""
        threat = Threat(
            threat_id=f"NET-{hashlib.md5(str(conn).encode()).hexdigest()[:8]}",
            threat_type="network_anomaly",
            severity=Severity.HIGH,
            description=f"Network anomaly: {reason}",
            source="network_monitor",
            detected_at=datetime.utcnow().isoformat(),
            evidence=conn
        )

        self.threat_queue.put(threat)
        spectre_log.alert(f"Network anomaly: {reason}", threat)

    def stop(self):
        """Stop network monitoring"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)

# =============================================================================
# Continuous Monitoring - Auth Monitor
# =============================================================================

class AuthMonitor:
    """Monitor authentication events for brute force attacks"""

    def __init__(self, threat_queue: Queue, config: Config):
        self.threat_queue = threat_queue
        self.config = config
        self.running = False
        self.auth_failures: Dict[str, List[datetime]] = defaultdict(list)
        self.thread: Optional[threading.Thread] = None
        self.last_position = 0

    def start(self):
        """Start auth monitoring"""
        if not self.config.get("continuous_monitoring", "auth_monitoring", default=True):
            spectre_log.info("Auth monitoring disabled in config")
            return

        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        spectre_log.info("Auth monitoring started")

    def _monitor_loop(self):
        """Monitor auth logs for failures"""
        auth_log = "/var/log/secure"
        if not os.path.exists(auth_log):
            auth_log = "/var/log/auth.log"

        if not os.path.exists(auth_log):
            spectre_log.warning("No auth log found, using journalctl")
            self._monitor_journalctl()
            return

        while self.running:
            try:
                with open(auth_log) as f:
                    f.seek(self.last_position)

                    for line in f:
                        self._process_auth_line(line)

                    self.last_position = f.tell()

                time.sleep(2)

            except Exception as e:
                spectre_log.error(f"Auth monitor error: {e}")
                time.sleep(30)

    def _monitor_journalctl(self):
        """Monitor auth via journalctl"""
        try:
            proc = subprocess.Popen(
                ["journalctl", "-f", "-u", "sshd", "-o", "cat"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )

            while self.running:
                line = proc.stdout.readline()
                if line:
                    self._process_auth_line(line)

            proc.terminate()

        except Exception as e:
            spectre_log.error(f"Journalctl monitor error: {e}")

    def _process_auth_line(self, line: str):
        """Process a line from auth log"""
        # Failed password patterns
        failed_patterns = [
            r'Failed password for (?:invalid user )?(\S+) from (\S+)',
            r'authentication failure.*rhost=(\S+).*user=(\S+)',
            r'Invalid user (\S+) from (\S+)',
        ]

        for pattern in failed_patterns:
            match = re.search(pattern, line)
            if match:
                groups = match.groups()
                if len(groups) >= 2:
                    user = groups[0]
                    ip = groups[1] if len(groups) > 1 else groups[0]
                    self._record_failure(ip, user)
                break

    def _record_failure(self, ip: str, user: str):
        """Record an authentication failure"""
        now = datetime.utcnow()
        key = f"{ip}"

        # Clean old entries
        window = timedelta(minutes=self.config.get("thresholds", "auth_failures_window_minutes", default=10))
        self.auth_failures[key] = [t for t in self.auth_failures[key] if now - t < window]

        # Add new failure
        self.auth_failures[key].append(now)

        # Check threshold
        threshold = self.config.get("thresholds", "auth_failures_threshold", default=5)
        if len(self.auth_failures[key]) >= threshold:
            self._report_threat(ip, user, len(self.auth_failures[key]))
            self.auth_failures[key] = []  # Reset after reporting

    def _report_threat(self, ip: str, user: str, count: int):
        """Report a brute force attempt"""
        threat = Threat(
            threat_id=f"AUTH-{ip}-{int(time.time())}",
            threat_type="brute_force",
            severity=Severity.HIGH,
            description=f"Brute force attack detected: {count} failures from {ip}",
            source="auth_monitor",
            detected_at=datetime.utcnow().isoformat(),
            evidence={"ip": ip, "user": user, "failure_count": count}
        )

        self.threat_queue.put(threat)
        spectre_log.alert(f"Brute force: {count} failures from {ip} for user {user}", threat)

    def stop(self):
        """Stop auth monitoring"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)

# =============================================================================
# Intrusion Detection System
# =============================================================================

class IntrusionDetector:
    """
    Real-time Intrusion Detection System

    Detects:
    - Port scans (rapid connection attempts from single IP)
    - Brute force attacks (multiple auth failures)
    - Suspicious connection patterns
    - Service enumeration attempts
    """

    def __init__(self, threat_queue: Queue, config: Config):
        self.threat_queue = threat_queue
        self.config = config
        self.running = False
        self.thread: Optional[threading.Thread] = None

        # Connection tracking per IP
        self.connection_attempts: Dict[str, List[Tuple[datetime, int]]] = defaultdict(list)
        # Port access tracking per IP
        self.port_access: Dict[str, Set[int]] = defaultdict(set)
        # Blocked IPs
        self.blocked_ips: Set[str] = set()
        # Last alert time per IP (to avoid spam)
        self.last_alert: Dict[str, datetime] = {}

        # SSL/TLS connection tracking
        self.ssl_connections: Dict[str, List[datetime]] = defaultdict(list)
        self.ssl_alerted_ips: Set[str] = set()

        # Known/expected SSL ports on this system
        self.EXPECTED_SSL_PORTS: Set[int] = {443, 8443, 993, 995, 465, 636}
        # Ports that should NEVER have SSL (suspicious if SSL detected)
        self.NON_SSL_PORTS: Set[int] = {21, 22, 23, 25, 80, 110, 143}

        # Detection thresholds
        self.PORT_SCAN_THRESHOLD = 10  # ports accessed in window
        self.PORT_SCAN_WINDOW = 60  # seconds
        self.CONNECTION_RATE_THRESHOLD = 50  # connections per minute
        self.ALERT_COOLDOWN = 30  # seconds between alerts for same IP
        self.SSL_REPEAT_THRESHOLD = 20  # repeated SSL connections in window
        self.SSL_REPEAT_WINDOW = 60  # seconds

    def start(self):
        """Start intrusion detection"""
        self.running = True
        self.thread = threading.Thread(target=self._detection_loop, daemon=True)
        self.thread.start()
        spectre_log.info("=" * 60)
        spectre_log.info("INTRUSION DETECTION SYSTEM ACTIVATED")
        spectre_log.info("=" * 60)
        spectre_log.info("Monitoring for: Port scans, Brute force, Suspicious connections, SSL/TLS anomalies")

    def _detection_loop(self):
        """Main detection loop"""
        while self.running:
            try:
                # Get current connections
                connections = self._get_all_connections()

                # Analyze each connection
                for conn in connections:
                    self._analyze_connection(conn)

                # Check for port scans
                self._detect_port_scans()

                # Check for connection rate anomalies
                self._detect_connection_floods()

                # Check for SSL/TLS anomalies
                self._detect_ssl_anomalies()

                # Cleanup old data
                self._cleanup_old_data()

                time.sleep(1)  # Check every second for real-time detection

            except Exception as e:
                spectre_log.error(f"IDS error: {e}")
                time.sleep(5)

    def _get_all_connections(self) -> List[Dict]:
        """Get all current network connections"""
        connections = []

        try:
            # Use ss command for better connection info
            result = subprocess.run(
                ["ss", "-tunaH"],
                capture_output=True,
                text=True,
                timeout=5
            )

            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue

                parts = line.split()
                if len(parts) >= 5:
                    state = parts[0]
                    local = parts[3] if len(parts) > 3 else ""
                    remote = parts[4] if len(parts) > 4 else ""

                    # Parse addresses
                    local_ip, local_port = self._parse_ss_address(local)
                    remote_ip, remote_port = self._parse_ss_address(remote)

                    if remote_ip and remote_ip not in ("0.0.0.0", "*", "127.0.0.1", "::1"):
                        connections.append({
                            "state": state,
                            "local_ip": local_ip,
                            "local_port": local_port,
                            "remote_ip": remote_ip,
                            "remote_port": remote_port,
                            "timestamp": datetime.utcnow()
                        })

        except Exception as e:
            spectre_log.debug(f"Failed to get connections: {e}")

        return connections

    def _parse_ss_address(self, addr: str) -> Tuple[str, int]:
        """Parse ss address format"""
        try:
            if ']:' in addr:  # IPv6
                ip, port = addr.rsplit(':', 1)
                ip = ip.strip('[]')
            elif addr.count(':') == 1:  # IPv4
                ip, port = addr.rsplit(':', 1)
            else:
                return "", 0
            return ip, int(port) if port.isdigit() else 0
        except:
            return "", 0

    def _analyze_connection(self, conn: Dict):
        """Analyze a single connection for suspicious activity"""
        remote_ip = conn["remote_ip"]
        local_port = conn["local_port"]
        now = conn["timestamp"]

        if not remote_ip or remote_ip in self.blocked_ips:
            return

        # Track port access
        self.port_access[remote_ip].add(local_port)

        # Track connection attempts
        self.connection_attempts[remote_ip].append((now, local_port))

    def _detect_port_scans(self):
        """Detect port scanning activity"""
        now = datetime.utcnow()
        window = timedelta(seconds=self.PORT_SCAN_WINDOW)

        for ip, ports in list(self.port_access.items()):
            if ip in self.blocked_ips:
                continue

            # Count recent unique ports
            recent_attempts = [
                (t, p) for t, p in self.connection_attempts[ip]
                if now - t < window
            ]

            recent_ports = set(p for _, p in recent_attempts)

            if len(recent_ports) >= self.PORT_SCAN_THRESHOLD:
                self._alert_port_scan(ip, recent_ports)

    def _detect_connection_floods(self):
        """Detect connection flooding/DoS attempts"""
        now = datetime.utcnow()
        window = timedelta(seconds=60)

        for ip, attempts in list(self.connection_attempts.items()):
            if ip in self.blocked_ips:
                continue

            # Count connections in last minute
            recent = [t for t, _ in attempts if now - t < window]

            if len(recent) >= self.CONNECTION_RATE_THRESHOLD:
                self._alert_connection_flood(ip, len(recent))

    def _detect_ssl_anomalies(self):
        """Detect SSL/TLS connection anomalies - potential MITM or rogue certs"""
        try:
            # Check for SSL connections on unexpected ports
            self._check_unexpected_ssl()

            # Check for repeated SSL handshakes (potential enumeration/attack)
            self._check_repeated_ssl()

            # Check for SSL on ports that should never have SSL
            self._check_ssl_on_cleartext_ports()

        except Exception as e:
            spectre_log.debug(f"SSL detection error: {e}")

    def _check_unexpected_ssl(self):
        """Check for SSL listeners on unexpected ports"""
        try:
            result = subprocess.run(
                ["ss", "-tlnH"],
                capture_output=True,
                text=True,
                timeout=5
            )

            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    local = parts[3]
                    _, port = self._parse_ss_address(local)

                    # Check if this is an unexpected SSL port
                    if port not in self.EXPECTED_SSL_PORTS and port not in self.NON_SSL_PORTS:
                        # Try to detect if it's actually SSL
                        if self._is_ssl_port(port):
                            self._alert_unexpected_ssl_port(port)

        except Exception as e:
            spectre_log.debug(f"Unexpected SSL check error: {e}")

    def _is_ssl_port(self, port: int) -> bool:
        """Check if a port is serving SSL/TLS"""
        try:
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                with context.wrap_socket(sock) as ssock:
                    # If we get here, it's SSL
                    cert = ssock.getpeercert(binary_form=True)
                    return True
        except:
            return False

    def _check_repeated_ssl(self):
        """Check for repeated SSL connections from same IP (potential attack)"""
        now = datetime.utcnow()
        window = timedelta(seconds=self.SSL_REPEAT_WINDOW)

        # Track SSL connections to common SSL ports
        for ip, attempts in list(self.connection_attempts.items()):
            if ip in self.ssl_alerted_ips:
                continue

            # Count SSL port connections
            ssl_attempts = [
                t for t, p in attempts
                if now - t < window and p in self.EXPECTED_SSL_PORTS
            ]

            if len(ssl_attempts) >= self.SSL_REPEAT_THRESHOLD:
                self._alert_repeated_ssl(ip, len(ssl_attempts))
                self.ssl_alerted_ips.add(ip)

    def _check_ssl_on_cleartext_ports(self):
        """Detect SSL/TLS on ports that should be cleartext (MITM indicator)"""
        # Check if any connections to cleartext ports are actually SSL
        for ip, ports in list(self.port_access.items()):
            for port in ports:
                if port in self.NON_SSL_PORTS:
                    # This shouldn't have SSL - if it does, it's suspicious
                    if self._is_ssl_port(port):
                        self._alert_ssl_on_cleartext(ip, port)

    def _alert_unexpected_ssl_port(self, port: int):
        """Alert on SSL listener on unexpected port"""
        alert_key = f"ssl-port-{port}"
        if not self._can_alert(alert_key):
            return

        spectre_log.info("")
        spectre_log.info("🔐" + "=" * 58 + "🔐")
        spectre_log.info("🔐  SSL/TLS ALERT: UNEXPECTED SSL PORT DETECTED")
        spectre_log.info("🔐" + "=" * 58 + "🔐")
        spectre_log.info(f"🔐  Port: {port}")
        spectre_log.info("🔐  Risk: Rogue service or potential MITM intercept point")
        spectre_log.info("🔐  Action: Investigate unknown SSL listener")
        spectre_log.info("🔐" + "=" * 58 + "🔐")
        spectre_log.info("")

        threat = Threat(
            threat_id=f"IDS-SSL-UNEXPECTED-{port}-{int(time.time())}",
            threat_type="unexpected_ssl",
            severity=Severity.HIGH,
            description=f"Unexpected SSL/TLS service on port {port} - potential rogue certificate",
            source="intrusion_detector",
            detected_at=datetime.utcnow().isoformat(),
            evidence={"port": port, "risk": "MITM interception possible"}
        )
        self.threat_queue.put(threat)
        self.last_alert[alert_key] = datetime.utcnow()

    def _alert_repeated_ssl(self, ip: str, count: int):
        """Alert on repeated SSL connections"""
        if not self._can_alert(f"ssl-repeat-{ip}"):
            return

        spectre_log.info("")
        spectre_log.info("🔐" + "=" * 58 + "🔐")
        spectre_log.info("🔐  SSL/TLS ALERT: REPEATED SSL CONNECTIONS")
        spectre_log.info("🔐" + "=" * 58 + "🔐")
        spectre_log.info(f"🔐  Source IP: {ip}")
        spectre_log.info(f"🔐  SSL Connections: {count} in {self.SSL_REPEAT_WINDOW}s")
        spectre_log.info("🔐  Risk: SSL enumeration, cert harvesting, or brute force")
        spectre_log.info("🔐" + "=" * 58 + "🔐")
        spectre_log.info("")

        threat = Threat(
            threat_id=f"IDS-SSL-REPEAT-{ip}-{int(time.time())}",
            threat_type="ssl_enumeration",
            severity=Severity.MEDIUM,
            description=f"Repeated SSL connections from {ip}: {count} attempts - possible enumeration",
            source="intrusion_detector",
            detected_at=datetime.utcnow().isoformat(),
            evidence={"ip": ip, "ssl_connections": count, "window_seconds": self.SSL_REPEAT_WINDOW}
        )
        self.threat_queue.put(threat)
        self.last_alert[f"ssl-repeat-{ip}"] = datetime.utcnow()

    def _alert_ssl_on_cleartext(self, ip: str, port: int):
        """Alert on SSL detected where cleartext expected - MITM indicator"""
        alert_key = f"ssl-cleartext-{port}"
        if not self._can_alert(alert_key):
            return

        spectre_log.info("")
        spectre_log.info("🚨🔐" + "=" * 54 + "🔐🚨")
        spectre_log.info("🚨🔐  CRITICAL: SSL ON CLEARTEXT PORT - POSSIBLE MITM")
        spectre_log.info("🚨🔐" + "=" * 54 + "🔐🚨")
        spectre_log.info(f"🚨🔐  Port: {port} (should be cleartext)")
        spectre_log.info(f"🚨🔐  Source IP: {ip}")
        spectre_log.info("🚨🔐  Risk: ACTIVE MAN-IN-THE-MIDDLE ATTACK")
        spectre_log.info("🚨🔐  Action: IMMEDIATE INVESTIGATION REQUIRED")
        spectre_log.info("🚨🔐" + "=" * 54 + "🔐🚨")
        spectre_log.info("")

        threat = Threat(
            threat_id=f"IDS-SSL-MITM-{port}-{int(time.time())}",
            threat_type="ssl_mitm",
            severity=Severity.CRITICAL,
            description=f"SSL/TLS detected on cleartext port {port} - POTENTIAL MITM ATTACK",
            source="intrusion_detector",
            detected_at=datetime.utcnow().isoformat(),
            evidence={"port": port, "ip": ip, "risk": "Active interception with rogue certificate"}
        )
        self.threat_queue.put(threat)
        self.last_alert[alert_key] = datetime.utcnow()

    def _alert_port_scan(self, ip: str, ports: Set[int]):
        """Alert on detected port scan"""
        if not self._can_alert(ip):
            return

        # Create prominent alert
        port_list = sorted(list(ports))[:20]  # Show first 20 ports

        spectre_log.info("")
        spectre_log.info("🚨" + "=" * 58 + "🚨")
        spectre_log.info("🚨  INTRUSION ALERT: PORT SCAN DETECTED")
        spectre_log.info("🚨" + "=" * 58 + "🚨")
        spectre_log.info(f"🚨  Source IP: {ip}")
        spectre_log.info(f"🚨  Ports scanned: {len(ports)}")
        spectre_log.info(f"🚨  Ports: {port_list}")
        spectre_log.info("🚨  Action: Monitoring and logging")
        spectre_log.info("🚨" + "=" * 58 + "🚨")
        spectre_log.info("")

        threat = Threat(
            threat_id=f"IDS-PORTSCAN-{ip}-{int(time.time())}",
            threat_type="port_scan",
            severity=Severity.HIGH,
            description=f"Port scan detected from {ip}: {len(ports)} ports probed",
            source="intrusion_detector",
            detected_at=datetime.utcnow().isoformat(),
            evidence={"ip": ip, "ports_scanned": len(ports), "ports": list(ports)[:50]}
        )

        self.threat_queue.put(threat)
        self.last_alert[ip] = datetime.utcnow()

    def _alert_connection_flood(self, ip: str, count: int):
        """Alert on connection flooding"""
        if not self._can_alert(ip):
            return

        spectre_log.info("")
        spectre_log.info("🚨" + "=" * 58 + "🚨")
        spectre_log.info("🚨  INTRUSION ALERT: CONNECTION FLOOD DETECTED")
        spectre_log.info("🚨" + "=" * 58 + "🚨")
        spectre_log.info(f"🚨  Source IP: {ip}")
        spectre_log.info(f"🚨  Connections/min: {count}")
        spectre_log.info("🚨  Possible DoS or aggressive scanning")
        spectre_log.info("🚨" + "=" * 58 + "🚨")
        spectre_log.info("")

        threat = Threat(
            threat_id=f"IDS-FLOOD-{ip}-{int(time.time())}",
            threat_type="connection_flood",
            severity=Severity.CRITICAL,
            description=f"Connection flood from {ip}: {count} connections/min",
            source="intrusion_detector",
            detected_at=datetime.utcnow().isoformat(),
            evidence={"ip": ip, "connections_per_minute": count}
        )

        self.threat_queue.put(threat)
        self.last_alert[ip] = datetime.utcnow()

    def _can_alert(self, ip: str) -> bool:
        """Check if we can alert for this IP (cooldown)"""
        if ip not in self.last_alert:
            return True
        return (datetime.utcnow() - self.last_alert[ip]).seconds >= self.ALERT_COOLDOWN

    def _cleanup_old_data(self):
        """Clean up old tracking data"""
        now = datetime.utcnow()
        cutoff = timedelta(minutes=5)

        # Clean connection attempts
        for ip in list(self.connection_attempts.keys()):
            self.connection_attempts[ip] = [
                (t, p) for t, p in self.connection_attempts[ip]
                if now - t < cutoff
            ]
            if not self.connection_attempts[ip]:
                del self.connection_attempts[ip]
                if ip in self.port_access:
                    del self.port_access[ip]

    def report_auth_failure(self, ip: str, user: str):
        """Called by AuthMonitor to report auth failures for correlation"""
        spectre_log.info("")
        spectre_log.info("⚠️" + "=" * 58 + "⚠️")
        spectre_log.info(f"⚠️  AUTH FAILURE: {user}@{ip}")
        spectre_log.info("⚠️" + "=" * 58 + "⚠️")
        spectre_log.info("")

    def stop(self):
        """Stop intrusion detection"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        spectre_log.info("Intrusion Detection System stopped")


# =============================================================================
# Vulnerability Scanner
# =============================================================================

class Scanner:
    """Comprehensive vulnerability scanning"""

    def __init__(self, threat_intel: ThreatIntel, config: Config):
        self.threat_intel = threat_intel
        self.config = config

    def quick_scan(self) -> List[Vulnerability]:
        """Quick scan - fast checks only"""
        spectre_log.info("Running quick scan...")
        vulnerabilities = []

        # Check for critical security updates only
        vulnerabilities.extend(self._scan_critical_updates())

        # Quick SUID check
        vulnerabilities.extend(self._scan_suid_anomalies())

        return vulnerabilities

    def standard_scan(self) -> List[Vulnerability]:
        """Standard scan - package and port scanning"""
        spectre_log.info("Running standard scan...")
        vulnerabilities = []

        # Scan packages
        vulnerabilities.extend(self.scan_installed_packages())

        # Scan ports
        vulnerabilities.extend(self.scan_open_ports())

        # Check world-writable files
        vulnerabilities.extend(self._scan_world_writable())

        # Check SSH config
        vulnerabilities.extend(self._scan_ssh_config())

        return vulnerabilities

    def deep_scan(self) -> List[Vulnerability]:
        """Deep scan - comprehensive security audit"""
        spectre_log.info("Running deep scan...")
        vulnerabilities = []

        # All standard scans
        vulnerabilities.extend(self.standard_scan())

        # Lynis audit
        vulnerabilities.extend(self.scan_with_lynis())

        # Rootkit scan
        vulnerabilities.extend(self._scan_rootkits())

        # CIS benchmark checks
        vulnerabilities.extend(self._scan_cis_benchmarks())

        # User audit
        vulnerabilities.extend(self._scan_user_security())

        # Kernel vulnerabilities
        vulnerabilities.extend(self._scan_kernel_vulns())

        # Crontab audit
        vulnerabilities.extend(self._scan_crontabs())

        return vulnerabilities

    def scan_installed_packages(self) -> List[Vulnerability]:
        """Scan installed packages for known vulnerabilities"""
        spectre_log.info("Scanning installed packages...")
        vulnerabilities = []

        pkg_mgr = DependencyManager._detect_package_manager()

        try:
            if pkg_mgr == "apk":
                # Alpine: check for upgradable packages
                result = subprocess.run(
                    ["apk", "version", "-v", "-l", "<"],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                # Parse Alpine upgrade output
                for line in result.stdout.split("\n"):
                    if "<" in line:
                        parts = line.split("<")
                        if len(parts) >= 2:
                            pkg_name = parts[0].strip()
                            # Check for security-related packages
                            vuln = Vulnerability(
                                cve_id=f"ALPINE-UPDATE-{pkg_name}",
                                description=f"Package update available: {line.strip()}",
                                severity=Severity.MEDIUM,
                                cvss_score=0.0,
                                epss_score=0.0,
                                is_kev=False,
                                affected_package=pkg_name,
                                affected_version="current",
                                fixed_version="available",
                                discovered_at=datetime.utcnow().isoformat(),
                                evidence_hash=hashlib.sha256(line.encode()).hexdigest(),
                                scan_type=ScanType.STANDARD
                            )
                            vulnerabilities.append(vuln)

            elif pkg_mgr in ["dnf", "yum"]:
                # RHEL/Rocky: use dnf security updates
                result = subprocess.run(
                    ["dnf", "updateinfo", "list", "security", "--available"],
                    capture_output=True,
                    text=True,
                    timeout=120
                )

                for line in result.stdout.split("\n"):
                    match = re.search(r'(CVE-\d{4}-\d+)', line)
                    if match:
                        cve_id = match.group(1)
                        epss = self.threat_intel.get_epss_score(cve_id)
                        is_kev = self.threat_intel.is_in_kev(cve_id)

                        # Get NVD data for CVSS score
                        nvd_data = self.threat_intel.get_nvd_data(cve_id)
                        cvss_score = 0.0
                        if nvd_data:
                            metrics = nvd_data.get("metrics", {})
                            if "cvssMetricV31" in metrics:
                                cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                            elif "cvssMetricV2" in metrics:
                                cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

                        if is_kev or epss >= kEPSS_CRITICAL_THRESHOLD:
                            severity = Severity.CRITICAL
                        elif epss >= kEPSS_HIGH_THRESHOLD or cvss_score >= kCVSS_HIGH_THRESHOLD:
                            severity = Severity.HIGH
                        else:
                            severity = Severity.MEDIUM

                        vuln = Vulnerability(
                            cve_id=cve_id,
                            description=line.strip(),
                            severity=severity,
                            cvss_score=cvss_score,
                            epss_score=epss,
                            is_kev=is_kev,
                            affected_package=line.split()[0] if line.split() else "unknown",
                            affected_version="current",
                            fixed_version="available",
                            discovered_at=datetime.utcnow().isoformat(),
                            evidence_hash=hashlib.sha256(line.encode()).hexdigest(),
                            scan_type=ScanType.STANDARD
                        )
                        vulnerabilities.append(vuln)

            elif pkg_mgr == "apt":
                # Debian/Ubuntu: use apt-get
                result = subprocess.run(
                    ["apt-get", "-s", "upgrade"],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                for line in result.stdout.split("\n"):
                    if "Inst" in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            pkg_name = parts[1]
                            vuln = Vulnerability(
                                cve_id=f"APT-UPDATE-{pkg_name}",
                                description=f"Package update available: {line.strip()}",
                                severity=Severity.MEDIUM,
                                cvss_score=0.0,
                                epss_score=0.0,
                                is_kev=False,
                                affected_package=pkg_name,
                                affected_version="current",
                                fixed_version="available",
                                discovered_at=datetime.utcnow().isoformat(),
                                evidence_hash=hashlib.sha256(line.encode()).hexdigest(),
                                scan_type=ScanType.STANDARD
                            )
                            vulnerabilities.append(vuln)

            spectre_log.audit(
                "PACKAGE_SCAN_COMPLETE",
                {"vulnerabilities_found": len(vulnerabilities), "pkg_mgr": pkg_mgr},
                "Completed package vulnerability scan"
            )

        except Exception as e:
            spectre_log.error(f"Package scan failed: {e}")

        return vulnerabilities

    def scan_with_lynis(self) -> List[Vulnerability]:
        """Run Lynis security audit"""
        spectre_log.info("Running Lynis audit...")
        vulnerabilities = []

        try:
            result = subprocess.run(
                ["lynis", "audit", "system", "--quick", "--no-colors", "-Q"],
                capture_output=True,
                text=True,
                timeout=900
            )

            for line in result.stdout.split("\n"):
                if "Warning" in line or "suggestion" in line.lower():
                    severity = Severity.MEDIUM if "Warning" in line else Severity.LOW

                    vuln = Vulnerability(
                        cve_id=f"LYNIS-{hashlib.md5(line.encode()).hexdigest()[:8]}",
                        description=line.strip(),
                        severity=severity,
                        cvss_score=5.0 if "Warning" in line else 3.0,
                        epss_score=0.0,
                        is_kev=False,
                        affected_package="system",
                        affected_version="current",
                        fixed_version=None,
                        discovered_at=datetime.utcnow().isoformat(),
                        evidence_hash=hashlib.sha256(line.encode()).hexdigest(),
                        scan_type=ScanType.DEEP
                    )
                    vulnerabilities.append(vuln)

            spectre_log.audit(
                "LYNIS_SCAN_COMPLETE",
                {"findings": len(vulnerabilities)},
                "Completed Lynis security audit"
            )

        except FileNotFoundError:
            spectre_log.warning("Lynis not installed")
        except Exception as e:
            spectre_log.error(f"Lynis scan failed: {e}")

        return vulnerabilities

    def scan_open_ports(self) -> List[Vulnerability]:
        """Scan for unexpected open ports"""
        spectre_log.info("Scanning local ports...")
        vulnerabilities = []
        expected_ports = set(self.config.get("expected_ports", default=[22, 80, 443]))

        try:
            result = subprocess.run(
                ["ss", "-tlnp"],
                capture_output=True,
                text=True,
                timeout=30
            )

            for line in result.stdout.split("\n"):
                match = re.search(r':(\d+)\s+', line)
                if match:
                    port = int(match.group(1))
                    if port not in expected_ports and port > 0:
                        # Get service name
                        service_match = re.search(r'users:\(\("([^"]+)"', line)
                        service = service_match.group(1) if service_match else "unknown"

                        vuln = Vulnerability(
                            cve_id=f"SPECTRE-OPEN-PORT-{port}",
                            description=f"Unexpected open port {port} ({service})",
                            severity=Severity.MEDIUM,
                            cvss_score=5.0,
                            epss_score=0.0,
                            is_kev=False,
                            affected_package=service,
                            affected_version="running",
                            fixed_version=None,
                            discovered_at=datetime.utcnow().isoformat(),
                            evidence_hash=hashlib.sha256(f"{port}{service}".encode()).hexdigest(),
                            scan_type=ScanType.STANDARD
                        )
                        vulnerabilities.append(vuln)

            spectre_log.audit(
                "PORT_SCAN_COMPLETE",
                {"unexpected_ports": len(vulnerabilities)},
                "Completed local port scan"
            )

        except Exception as e:
            spectre_log.error(f"Port scan failed: {e}")

        return vulnerabilities

    def _scan_critical_updates(self) -> List[Vulnerability]:
        """Quick check for critical security updates"""
        vulnerabilities = []
        pkg_mgr = DependencyManager._detect_package_manager()

        try:
            if pkg_mgr == "apk":
                # Alpine: check for security updates
                result = subprocess.run(
                    ["apk", "upgrade", "--simulate"],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                # Count packages that would be upgraded
                upgrade_count = result.stdout.count("Upgrading")
                if upgrade_count > 0:
                    vuln = Vulnerability(
                        cve_id=f"ALPINE-CRITICAL-{upgrade_count}",
                        description=f"{upgrade_count} package updates available",
                        severity=Severity.HIGH,
                        cvss_score=7.0,
                        epss_score=0.0,
                        is_kev=False,
                        affected_package="multiple",
                        affected_version="current",
                        fixed_version="available",
                        discovered_at=datetime.utcnow().isoformat(),
                        evidence_hash=hashlib.sha256(result.stdout.encode()).hexdigest(),
                        scan_type=ScanType.QUICK
                    )
                    vulnerabilities.append(vuln)

            elif pkg_mgr in ["dnf", "yum"]:
                result = subprocess.run(
                    ["dnf", "updateinfo", "list", "security", "--available", "--sec-severity=Critical"],
                    capture_output=True,
                    text=True,
                    timeout=60
                )

                for line in result.stdout.split("\n"):
                    if "Critical" in line:
                        match = re.search(r'(CVE-\d{4}-\d+)', line)
                        cve_id = match.group(1) if match else f"CRITICAL-{hashlib.md5(line.encode()).hexdigest()[:8]}"

                        vuln = Vulnerability(
                            cve_id=cve_id,
                            description=f"Critical update available: {line.strip()}",
                            severity=Severity.CRITICAL,
                            cvss_score=9.0,
                            epss_score=0.0,
                            is_kev=False,
                            affected_package=line.split()[0] if line.split() else "unknown",
                            affected_version="current",
                            fixed_version="available",
                            discovered_at=datetime.utcnow().isoformat(),
                            evidence_hash=hashlib.sha256(line.encode()).hexdigest(),
                            scan_type=ScanType.QUICK
                        )
                        vulnerabilities.append(vuln)

            elif pkg_mgr == "apt":
                result = subprocess.run(
                    ["apt-get", "-s", "upgrade"],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                upgrade_count = result.stdout.count("Inst")
                if upgrade_count > 0:
                    vuln = Vulnerability(
                        cve_id=f"APT-CRITICAL-{upgrade_count}",
                        description=f"{upgrade_count} package updates available",
                        severity=Severity.HIGH,
                        cvss_score=7.0,
                        epss_score=0.0,
                        is_kev=False,
                        affected_package="multiple",
                        affected_version="current",
                        fixed_version="available",
                        discovered_at=datetime.utcnow().isoformat(),
                        evidence_hash=hashlib.sha256(result.stdout.encode()).hexdigest(),
                        scan_type=ScanType.QUICK
                    )
                    vulnerabilities.append(vuln)

        except Exception as e:
            spectre_log.debug(f"Critical update check failed: {e}")

        return vulnerabilities

    def _scan_suid_anomalies(self) -> List[Vulnerability]:
        """Check for suspicious SUID/SGID files"""
        vulnerabilities = []

        # Known safe SUID binaries
        safe_suid = {
            '/usr/bin/passwd', '/usr/bin/sudo', '/usr/bin/su',
            '/usr/bin/mount', '/usr/bin/umount', '/usr/bin/ping',
            '/usr/bin/chfn', '/usr/bin/chsh', '/usr/bin/newgrp',
            '/usr/bin/gpasswd', '/usr/sbin/unix_chkpwd',
            '/usr/lib/polkit-1/polkit-agent-helper-1',
        }

        try:
            result = subprocess.run(
                ["find", "/", "-perm", "-4000", "-type", "f", "-print"],
                capture_output=True,
                text=True,
                timeout=120,
                stderr=subprocess.DEVNULL
            )

            for line in result.stdout.strip().split("\n"):
                if line and line not in safe_suid:
                    vuln = Vulnerability(
                        cve_id=f"SPECTRE-SUID-{hashlib.md5(line.encode()).hexdigest()[:8]}",
                        description=f"Unusual SUID binary: {line}",
                        severity=Severity.HIGH,
                        cvss_score=7.0,
                        epss_score=0.0,
                        is_kev=False,
                        affected_package=line,
                        affected_version="current",
                        fixed_version=None,
                        discovered_at=datetime.utcnow().isoformat(),
                        evidence_hash=hashlib.sha256(line.encode()).hexdigest(),
                        scan_type=ScanType.QUICK
                    )
                    vulnerabilities.append(vuln)

        except Exception as e:
            spectre_log.debug(f"SUID scan failed: {e}")

        return vulnerabilities

    def _scan_world_writable(self) -> List[Vulnerability]:
        """Check for world-writable files in sensitive locations"""
        vulnerabilities = []
        sensitive_dirs = ['/etc', '/usr', '/var/www', '/opt']

        try:
            for dir_path in sensitive_dirs:
                if not os.path.exists(dir_path):
                    continue

                result = subprocess.run(
                    ["find", dir_path, "-type", "f", "-perm", "-002", "-print"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    stderr=subprocess.DEVNULL
                )

                for line in result.stdout.strip().split("\n"):
                    if line:
                        vuln = Vulnerability(
                            cve_id=f"SPECTRE-WRITABLE-{hashlib.md5(line.encode()).hexdigest()[:8]}",
                            description=f"World-writable file: {line}",
                            severity=Severity.MEDIUM,
                            cvss_score=5.0,
                            epss_score=0.0,
                            is_kev=False,
                            affected_package=line,
                            affected_version="current",
                            fixed_version=None,
                            discovered_at=datetime.utcnow().isoformat(),
                            evidence_hash=hashlib.sha256(line.encode()).hexdigest(),
                            scan_type=ScanType.STANDARD
                        )
                        vulnerabilities.append(vuln)

        except Exception as e:
            spectre_log.debug(f"World-writable scan failed: {e}")

        return vulnerabilities

    def _scan_ssh_config(self) -> List[Vulnerability]:
        """Audit SSH configuration"""
        vulnerabilities = []
        ssh_config = "/etc/ssh/sshd_config"

        if not os.path.exists(ssh_config):
            return vulnerabilities

        try:
            with open(ssh_config) as f:
                config = f.read()

            # Check for insecure settings
            checks = [
                ("PermitRootLogin yes", "Root login enabled", Severity.HIGH),
                ("PasswordAuthentication yes", "Password auth enabled (key-only recommended)", Severity.MEDIUM),
                ("PermitEmptyPasswords yes", "Empty passwords permitted", Severity.CRITICAL),
                ("X11Forwarding yes", "X11 forwarding enabled", Severity.LOW),
            ]

            for pattern, desc, severity in checks:
                if pattern in config:
                    vuln = Vulnerability(
                        cve_id=f"SPECTRE-SSH-{hashlib.md5(pattern.encode()).hexdigest()[:8]}",
                        description=f"SSH config issue: {desc}",
                        severity=severity,
                        cvss_score=6.0 if severity == Severity.HIGH else 4.0,
                        epss_score=0.0,
                        is_kev=False,
                        affected_package="openssh-server",
                        affected_version="current",
                        fixed_version=None,
                        discovered_at=datetime.utcnow().isoformat(),
                        evidence_hash=hashlib.sha256(pattern.encode()).hexdigest(),
                        scan_type=ScanType.STANDARD
                    )
                    vulnerabilities.append(vuln)

        except Exception as e:
            spectre_log.debug(f"SSH config scan failed: {e}")

        return vulnerabilities

    def _scan_rootkits(self) -> List[Vulnerability]:
        """Run rootkit detection"""
        vulnerabilities = []

        try:
            # Run rkhunter
            result = subprocess.run(
                ["rkhunter", "--check", "--skip-keypress", "--report-warnings-only"],
                capture_output=True,
                text=True,
                timeout=600
            )

            for line in result.stdout.split("\n"):
                if "Warning" in line:
                    vuln = Vulnerability(
                        cve_id=f"SPECTRE-ROOTKIT-{hashlib.md5(line.encode()).hexdigest()[:8]}",
                        description=f"Rootkit check warning: {line.strip()}",
                        severity=Severity.CRITICAL,
                        cvss_score=10.0,
                        epss_score=0.0,
                        is_kev=False,
                        affected_package="system",
                        affected_version="current",
                        fixed_version=None,
                        discovered_at=datetime.utcnow().isoformat(),
                        evidence_hash=hashlib.sha256(line.encode()).hexdigest(),
                        scan_type=ScanType.DEEP
                    )
                    vulnerabilities.append(vuln)

        except FileNotFoundError:
            spectre_log.debug("rkhunter not installed")
        except Exception as e:
            spectre_log.debug(f"Rootkit scan failed: {e}")

        return vulnerabilities

    def _scan_cis_benchmarks(self) -> List[Vulnerability]:
        """Check CIS benchmark compliance"""
        vulnerabilities = []

        # Simple CIS checks
        cis_checks = [
            ("/etc/passwd", lambda c: any(l.split(':')[2] == '0' and l.split(':')[0] != 'root'
                for l in c.split('\n') if l), "Non-root user with UID 0"),
            ("/etc/shadow", lambda c: any(':!!:' not in l and ':*:' not in l and l.split(':')[1] == ''
                for l in c.split('\n') if l and not l.startswith('#')), "Account without password"),
            ("/etc/securetty", lambda c: len(c.strip().split('\n')) > 2 if c.strip() else False,
                "Multiple terminals allow root login"),
        ]

        for filepath, check_func, description in cis_checks:
            try:
                if os.path.exists(filepath):
                    with open(filepath) as f:
                        content = f.read()
                    if check_func(content):
                        vuln = Vulnerability(
                            cve_id=f"SPECTRE-CIS-{hashlib.md5(description.encode()).hexdigest()[:8]}",
                            description=f"CIS benchmark fail: {description}",
                            severity=Severity.HIGH,
                            cvss_score=7.0,
                            epss_score=0.0,
                            is_kev=False,
                            affected_package=filepath,
                            affected_version="current",
                            fixed_version=None,
                            discovered_at=datetime.utcnow().isoformat(),
                            evidence_hash=hashlib.sha256(description.encode()).hexdigest(),
                            scan_type=ScanType.DEEP
                        )
                        vulnerabilities.append(vuln)
            except Exception:
                pass

        return vulnerabilities

    def _scan_user_security(self) -> List[Vulnerability]:
        """Audit user account security"""
        vulnerabilities = []

        try:
            # Check for users with shells that shouldn't have them
            with open('/etc/passwd') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 7:
                        user, _, uid, _, _, _, shell = parts
                        uid = int(uid)

                        # System accounts with shells
                        if uid < 1000 and uid != 0 and shell not in ['/sbin/nologin', '/bin/false', '/usr/sbin/nologin']:
                            vuln = Vulnerability(
                                cve_id=f"SPECTRE-USER-{hashlib.md5(user.encode()).hexdigest()[:8]}",
                                description=f"System account {user} has login shell: {shell}",
                                severity=Severity.MEDIUM,
                                cvss_score=5.0,
                                epss_score=0.0,
                                is_kev=False,
                                affected_package=user,
                                affected_version="current",
                                fixed_version=None,
                                discovered_at=datetime.utcnow().isoformat(),
                                evidence_hash=hashlib.sha256(line.encode()).hexdigest(),
                                scan_type=ScanType.DEEP
                            )
                            vulnerabilities.append(vuln)

        except Exception as e:
            spectre_log.debug(f"User security scan failed: {e}")

        return vulnerabilities

    def _scan_kernel_vulns(self) -> List[Vulnerability]:
        """Check kernel for known vulnerabilities"""
        vulnerabilities = []
        pkg_mgr = DependencyManager._detect_package_manager()

        try:
            result = subprocess.run(["uname", "-r"], capture_output=True, text=True)
            kernel_version = result.stdout.strip()
            update_available = False

            if pkg_mgr == "apk":
                # Alpine: check for kernel updates
                result = subprocess.run(
                    ["apk", "version", "-v", "-l", "<", "linux-*"],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                update_available = bool(result.stdout.strip())

            elif pkg_mgr in ["dnf", "yum"]:
                # Check if kernel updates are available
                result = subprocess.run(
                    ["dnf", "check-update", "kernel"],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                update_available = result.returncode == 100

            elif pkg_mgr == "apt":
                result = subprocess.run(
                    ["apt-get", "-s", "upgrade", "linux-image-*"],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                update_available = "Inst linux" in result.stdout

            if update_available:
                vuln = Vulnerability(
                    cve_id=f"SPECTRE-KERNEL-UPDATE",
                    description=f"Kernel update available (current: {kernel_version})",
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    epss_score=0.0,
                    is_kev=False,
                    affected_package="kernel",
                    affected_version=kernel_version,
                    fixed_version="available",
                    discovered_at=datetime.utcnow().isoformat(),
                    evidence_hash=hashlib.sha256(kernel_version.encode()).hexdigest(),
                    scan_type=ScanType.DEEP
                )
                vulnerabilities.append(vuln)

        except Exception as e:
            spectre_log.debug(f"Kernel vuln scan failed: {e}")

        return vulnerabilities

    def _scan_crontabs(self) -> List[Vulnerability]:
        """Audit crontab entries"""
        vulnerabilities = []
        cron_paths = ['/etc/crontab', '/etc/cron.d', '/var/spool/cron']

        suspicious_patterns = [
            r'curl.*\|.*sh',
            r'wget.*\|.*sh',
            r'base64.*decode',
            r'/dev/tcp/',
            r'nc\s+-[el]',
        ]

        for cron_path in cron_paths:
            try:
                if os.path.isfile(cron_path):
                    files = [cron_path]
                elif os.path.isdir(cron_path):
                    files = [os.path.join(cron_path, f) for f in os.listdir(cron_path)]
                else:
                    continue

                for filepath in files:
                    if not os.path.isfile(filepath):
                        continue
                    with open(filepath) as f:
                        content = f.read()

                    for pattern in suspicious_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            vuln = Vulnerability(
                                cve_id=f"SPECTRE-CRON-{hashlib.md5(filepath.encode()).hexdigest()[:8]}",
                                description=f"Suspicious cron entry in {filepath}",
                                severity=Severity.HIGH,
                                cvss_score=8.0,
                                epss_score=0.0,
                                is_kev=False,
                                affected_package=filepath,
                                affected_version="current",
                                fixed_version=None,
                                discovered_at=datetime.utcnow().isoformat(),
                                evidence_hash=hashlib.sha256(content.encode()).hexdigest(),
                                scan_type=ScanType.DEEP
                            )
                            vulnerabilities.append(vuln)
                            break

            except Exception:
                pass

        return vulnerabilities

# =============================================================================
# Auto-Remediation Engine
# =============================================================================

class Remediator:
    """Autonomous vulnerability and threat remediation"""

    def __init__(self, threat_intel: ThreatIntel, config: Config):
        self.threat_intel = threat_intel
        self.config = config

    def remediate_vulnerability(self, vuln: Vulnerability, context: ScanContext) -> Mitigation:
        """Remediate a vulnerability"""
        spectre_log.info(f"Remediating vulnerability {vuln.cve_id}...")

        if vuln.fixed_version and vuln.fixed_version not in ["Unknown", None]:
            if self.config.get("auto_remediation", "patch_critical", default=True):
                mitigation = self._apply_patch(vuln)
                if mitigation.success:
                    return mitigation

        if vuln.is_kev or vuln.epss_score >= kEPSS_CRITICAL_THRESHOLD:
            return self._apply_aggressive_mitigation(vuln, context)
        else:
            return self._apply_conservative_mitigation(vuln, context)

    def remediate_threat(self, threat: Threat) -> Mitigation:
        """Remediate a real-time detected threat"""
        spectre_log.info(f"Remediating threat {threat.threat_id}...")

        if threat.threat_type == "suspicious_process":
            return self._kill_process(threat)
        elif threat.threat_type == "brute_force":
            return self._block_ip(threat)
        elif threat.threat_type in ["file_modified", "file_created"]:
            return self._quarantine_file(threat)
        elif threat.threat_type == "network_anomaly":
            return self._block_connection(threat)
        else:
            return self._alert_only(threat)

    def _apply_patch(self, vuln: Vulnerability) -> Mitigation:
        """Apply official patch"""
        spectre_log.audit(
            "PATCH_ATTEMPT",
            {"cve": vuln.cve_id, "package": vuln.affected_package},
            f"Attempting to patch {vuln.cve_id}"
        )

        pkg_mgr = DependencyManager._detect_package_manager()

        try:
            # Build command based on package manager
            if pkg_mgr == "apk":
                cmd = ["apk", "upgrade", vuln.affected_package]
                rollback_cmd = f"apk add {vuln.affected_package}={vuln.affected_version}"
                action_details = f"apk upgrade {vuln.affected_package}"
            elif pkg_mgr in ["dnf", "yum"]:
                cmd = ["dnf", "update", "-y", "--security", vuln.affected_package]
                rollback_cmd = f"dnf downgrade {vuln.affected_package}"
                action_details = f"dnf update -y --security {vuln.affected_package}"
            elif pkg_mgr == "apt":
                cmd = ["apt-get", "install", "-y", "--only-upgrade", vuln.affected_package]
                rollback_cmd = f"apt-get install {vuln.affected_package}={vuln.affected_version}"
                action_details = f"apt-get install -y --only-upgrade {vuln.affected_package}"
            else:
                return self._manual_required(vuln.cve_id, f"Unknown package manager: {pkg_mgr}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            success = result.returncode == 0

            return Mitigation(
                vuln_id=vuln.cve_id,
                action_type=ActionType.PATCH_APPLIED,
                action_details=action_details,
                applied_at=datetime.utcnow().isoformat(),
                success=success,
                verification_result=result.stdout[-500:] if success else result.stderr[-500:],
                rollback_command=rollback_cmd
            )

        except Exception as e:
            return self._manual_required(vuln.cve_id, f"Patch failed: {e}")

    def _apply_aggressive_mitigation(self, vuln: Vulnerability, context: ScanContext) -> Mitigation:
        """Aggressive mitigation for high-risk vulnerabilities"""
        if "OPEN-PORT" in vuln.cve_id:
            return self._block_port(vuln)

        excluded = self.config.get("excluded_packages", default=["kernel", "glibc", "systemd"])
        if vuln.affected_package not in excluded:
            if self.config.get("auto_remediation", "disable_services", default=True):
                return self._disable_service(vuln)

        if self.config.get("auto_remediation", "selinux_policies", default=True):
            return self._apply_selinux_policy(vuln)

        return self._manual_required(vuln.cve_id, "No automatic remediation available")

    def _apply_conservative_mitigation(self, vuln: Vulnerability, context: ScanContext) -> Mitigation:
        """Conservative mitigation"""
        return Mitigation(
            vuln_id=vuln.cve_id,
            action_type=ActionType.NO_ACTION,
            action_details="Logged for manual review - below auto-remediation threshold",
            applied_at=datetime.utcnow().isoformat(),
            success=True,
            verification_result="Monitoring enabled",
            rollback_command=None
        )

    def _kill_process(self, threat: Threat) -> Mitigation:
        """Kill a suspicious process"""
        if not self.config.get("auto_remediation", "kill_suspicious_processes", default=True):
            return self._alert_only(threat)

        pid = threat.evidence.get("pid")
        if not pid:
            return self._manual_required(threat.threat_id, "No PID in threat evidence")

        spectre_log.audit(
            "PROCESS_KILL",
            {"pid": pid, "cmdline": threat.evidence.get("cmdline", "")[:100]},
            f"Killing suspicious process {pid}"
        )

        try:
            os.kill(pid, signal.SIGKILL)

            # Verify process is dead
            time.sleep(0.5)
            try:
                os.kill(pid, 0)
                success = False
            except ProcessLookupError:
                success = True

            return Mitigation(
                vuln_id=threat.threat_id,
                action_type=ActionType.PROCESS_KILLED,
                action_details=f"Killed process {pid}",
                applied_at=datetime.utcnow().isoformat(),
                success=success,
                verification_result=f"Process {'terminated' if success else 'still running'}",
                rollback_command=None
            )

        except Exception as e:
            return self._manual_required(threat.threat_id, f"Kill failed: {e}")

    def _block_ip(self, threat: Threat) -> Mitigation:
        """Block an attacking IP"""
        ip = threat.evidence.get("ip")
        if not ip:
            return self._manual_required(threat.threat_id, "No IP in threat evidence")

        spectre_log.audit(
            "IP_BLOCK",
            {"ip": ip},
            f"Blocking IP {ip} due to brute force attack"
        )

        try:
            # Add firewall rule
            subprocess.run(
                ["firewall-cmd", "--permanent", "--add-rich-rule",
                 f'rule family="ipv4" source address="{ip}" reject'],
                capture_output=True,
                timeout=30
            )
            subprocess.run(["firewall-cmd", "--reload"], capture_output=True, timeout=30)

            return Mitigation(
                vuln_id=threat.threat_id,
                action_type=ActionType.FIREWALL_RULE,
                action_details=f"Blocked IP {ip}",
                applied_at=datetime.utcnow().isoformat(),
                success=True,
                verification_result=f"IP {ip} blocked via firewalld",
                rollback_command=f'firewall-cmd --permanent --remove-rich-rule \'rule family="ipv4" source address="{ip}" reject\' && firewall-cmd --reload'
            )

        except Exception as e:
            return self._manual_required(threat.threat_id, f"IP block failed: {e}")

    def _quarantine_file(self, threat: Threat) -> Mitigation:
        """Quarantine a suspicious file"""
        if not self.config.get("auto_remediation", "quarantine_files", default=True):
            return self._alert_only(threat)

        filepath = threat.evidence.get("path")
        if not filepath or not os.path.exists(filepath):
            return self._manual_required(threat.threat_id, "File not found")

        spectre_log.audit(
            "FILE_QUARANTINE",
            {"path": filepath},
            f"Quarantining suspicious file {filepath}"
        )

        try:
            quarantine_dir = kSpectreDataPath / "quarantine"
            quarantine_dir.mkdir(parents=True, exist_ok=True)

            # Create quarantine name with timestamp
            quarantine_name = f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{os.path.basename(filepath)}"
            quarantine_path = quarantine_dir / quarantine_name

            # Move file to quarantine
            import shutil
            shutil.move(filepath, quarantine_path)

            # Remove execute permission
            os.chmod(quarantine_path, 0o400)

            return Mitigation(
                vuln_id=threat.threat_id,
                action_type=ActionType.FILE_QUARANTINED,
                action_details=f"Quarantined {filepath} to {quarantine_path}",
                applied_at=datetime.utcnow().isoformat(),
                success=True,
                verification_result=f"File moved to quarantine",
                rollback_command=f"mv {quarantine_path} {filepath}"
            )

        except Exception as e:
            return self._manual_required(threat.threat_id, f"Quarantine failed: {e}")

    def _block_connection(self, threat: Threat) -> Mitigation:
        """Block a suspicious network connection"""
        remote_ip = threat.evidence.get("remote_ip")
        remote_port = threat.evidence.get("remote_port")

        if not remote_ip:
            return self._manual_required(threat.threat_id, "No remote IP in evidence")

        spectre_log.audit(
            "CONNECTION_BLOCK",
            {"remote_ip": remote_ip, "remote_port": remote_port},
            f"Blocking connection to {remote_ip}:{remote_port}"
        )

        try:
            subprocess.run(
                ["firewall-cmd", "--permanent", "--add-rich-rule",
                 f'rule family="ipv4" destination address="{remote_ip}" reject'],
                capture_output=True,
                timeout=30
            )
            subprocess.run(["firewall-cmd", "--reload"], capture_output=True, timeout=30)

            return Mitigation(
                vuln_id=threat.threat_id,
                action_type=ActionType.FIREWALL_RULE,
                action_details=f"Blocked outbound to {remote_ip}",
                applied_at=datetime.utcnow().isoformat(),
                success=True,
                verification_result=f"Outbound to {remote_ip} blocked",
                rollback_command=f'firewall-cmd --permanent --remove-rich-rule \'rule family="ipv4" destination address="{remote_ip}" reject\' && firewall-cmd --reload'
            )

        except Exception as e:
            return self._manual_required(threat.threat_id, f"Connection block failed: {e}")

    def _block_port(self, vuln: Vulnerability) -> Mitigation:
        """Block unexpected port"""
        port_match = re.search(r'PORT-(\d+)', vuln.cve_id)
        if not port_match:
            return self._manual_required(vuln.cve_id, "Could not parse port")

        port = port_match.group(1)

        try:
            subprocess.run(
                ["firewall-cmd", "--permanent", "--remove-port", f"{port}/tcp"],
                capture_output=True,
                timeout=30
            )
            subprocess.run(["firewall-cmd", "--reload"], capture_output=True, timeout=30)

            return Mitigation(
                vuln_id=vuln.cve_id,
                action_type=ActionType.FIREWALL_RULE,
                action_details=f"Blocked port {port}/tcp",
                applied_at=datetime.utcnow().isoformat(),
                success=True,
                verification_result=f"Port {port} blocked",
                rollback_command=f"firewall-cmd --permanent --add-port={port}/tcp && firewall-cmd --reload"
            )

        except Exception as e:
            return self._manual_required(vuln.cve_id, f"Port block failed: {e}")

    def _disable_service(self, vuln: Vulnerability) -> Mitigation:
        """Disable vulnerable service"""
        service = vuln.affected_package

        try:
            subprocess.run(["systemctl", "stop", service], capture_output=True, timeout=30)
            subprocess.run(["systemctl", "disable", service], capture_output=True, timeout=30)

            result = subprocess.run(["systemctl", "is-active", service], capture_output=True, text=True)
            success = "inactive" in result.stdout or result.returncode != 0

            return Mitigation(
                vuln_id=vuln.cve_id,
                action_type=ActionType.SERVICE_DISABLED,
                action_details=f"Disabled service {service}",
                applied_at=datetime.utcnow().isoformat(),
                success=success,
                verification_result=f"Service {'stopped' if success else 'still running'}",
                rollback_command=f"systemctl enable --now {service}"
            )

        except Exception as e:
            return self._manual_required(vuln.cve_id, f"Service disable failed: {e}")

    def _apply_selinux_policy(self, vuln: Vulnerability) -> Mitigation:
        """Apply SELinux confinement"""
        try:
            result = subprocess.run(["getenforce"], capture_output=True, text=True, timeout=10)
            if "Enforcing" not in result.stdout:
                subprocess.run(["setenforce", "1"], capture_output=True, timeout=10)

            return Mitigation(
                vuln_id=vuln.cve_id,
                action_type=ActionType.SELINUX_POLICY,
                action_details="Ensured SELinux enforcing mode",
                applied_at=datetime.utcnow().isoformat(),
                success=True,
                verification_result="SELinux enforcing",
                rollback_command="setenforce 0"
            )

        except Exception as e:
            return self._manual_required(vuln.cve_id, f"SELinux failed: {e}")

    def _alert_only(self, threat: Threat) -> Mitigation:
        """Send alert only, no action"""
        self._send_alert(threat)

        return Mitigation(
            vuln_id=threat.threat_id,
            action_type=ActionType.ALERT_SENT,
            action_details="Alert sent, no automatic action taken",
            applied_at=datetime.utcnow().isoformat(),
            success=True,
            verification_result="Alert dispatched",
            rollback_command=None
        )

    def _send_alert(self, threat: Threat):
        """Send alert via configured channels"""
        if not self.config.get("alerting", "enabled", default=True):
            return

        webhook_url = self.config.get("alerting", "webhook_url")
        if webhook_url:
            try:
                payload = json.dumps({
                    "threat_id": threat.threat_id,
                    "severity": threat.severity.value,
                    "description": threat.description,
                    "detected_at": threat.detected_at,
                    "evidence": threat.evidence
                }).encode()

                req = urllib.request.Request(
                    webhook_url,
                    data=payload,
                    headers={"Content-Type": "application/json"}
                )
                urllib.request.urlopen(req, timeout=10)
            except Exception as e:
                spectre_log.error(f"Webhook alert failed: {e}")

    def _manual_required(self, vuln_id: str, reason: str) -> Mitigation:
        """Mark as requiring manual intervention"""
        spectre_log.warning(f"Manual intervention required for {vuln_id}: {reason}")

        return Mitigation(
            vuln_id=vuln_id,
            action_type=ActionType.MANUAL_REQUIRED,
            action_details=reason,
            applied_at=datetime.utcnow().isoformat(),
            success=False,
            verification_result="Manual review required",
            rollback_command=None
        )

# =============================================================================
# Main Daemon
# =============================================================================

class Spectre:
    """Main Spectre daemon with continuous monitoring"""

    def __init__(self):
        self.running = True
        self.config = Config()
        self.threat_queue: Queue = Queue()

        self.threat_intel = ThreatIntel()
        self.scanner = Scanner(self.threat_intel, self.config)
        self.remediator = Remediator(self.threat_intel, self.config)

        # AI Security Engine
        self.ai_engine = AISecurityEngine()

        # Continuous monitors
        self.file_monitor = FileMonitor(self.threat_queue, self.config)
        self.process_monitor = ProcessMonitor(self.threat_queue, self.config)
        self.network_monitor = NetworkMonitor(self.threat_queue, self.config)
        self.auth_monitor = AuthMonitor(self.threat_queue, self.config)
        self.intrusion_detector = IntrusionDetector(self.threat_queue, self.config)

        # Scan timing
        self.last_quick_scan = datetime.min
        self.last_standard_scan = datetime.min
        self.last_deep_scan = datetime.min

        # Signal handlers
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        signal.signal(signal.SIGINT, self._handle_shutdown)

        # Create directories
        kConfigPath.mkdir(parents=True, exist_ok=True)
        kSpectreDataPath.mkdir(parents=True, exist_ok=True)
        kSpectreBaselinePath.mkdir(parents=True, exist_ok=True)

    def _handle_shutdown(self, signum, frame):
        """Graceful shutdown"""
        spectre_log.info("Received shutdown signal...")
        self.running = False

    def _get_system_context(self) -> str:
        """Gather system context"""
        context_parts = []
        try:
            result = subprocess.run(["cat", "/etc/os-release"], capture_output=True, text=True)
            context_parts.append(f"OS: {result.stdout[:200]}")
            result = subprocess.run(["uname", "-r"], capture_output=True, text=True)
            context_parts.append(f"Kernel: {result.stdout.strip()}")
            result = subprocess.run(["getenforce"], capture_output=True, text=True)
            context_parts.append(f"SELinux: {result.stdout.strip()}")
        except Exception:
            pass
        return "\n".join(context_parts)

    def autorecon(self, scan_type: ScanType = ScanType.STANDARD) -> ScanContext:
        """Main autonomous reconnaissance function"""
        scan_id = hashlib.sha256(str(datetime.utcnow().timestamp()).encode()).hexdigest()[:12]

        context = ScanContext(
            scan_id=scan_id,
            scan_type=scan_type,
            started_at=datetime.utcnow().isoformat(),
            hostname=socket.gethostname(),
            ip_address=socket.gethostbyname(socket.gethostname()),
            kSpectreStatus="scanning"
        )

        spectre_log.info(f"Starting {scan_type.value} autorecon scan {scan_id}")
        spectre_log.audit(
            "AUTORECON_START",
            {"scan_id": scan_id, "scan_type": scan_type.value},
            f"Initiating {scan_type.value} security scan"
        )

        try:
            # Get system info
            context.os_version = subprocess.run(
                ["cat", "/etc/redhat-release"],
                capture_output=True, text=True
            ).stdout.strip()
            context.kernel_version = subprocess.run(
                ["uname", "-r"],
                capture_output=True, text=True
            ).stdout.strip()

            # Run appropriate scan level
            if scan_type == ScanType.QUICK:
                context.vulnerabilities.extend(self.scanner.quick_scan())
            elif scan_type == ScanType.STANDARD:
                context.vulnerabilities.extend(self.scanner.standard_scan())
            elif scan_type == ScanType.DEEP:
                context.vulnerabilities.extend(self.scanner.deep_scan())

            spectre_log.info(f"Discovered {len(context.vulnerabilities)} vulnerabilities")

            # Sort by risk
            context.vulnerabilities.sort(
                key=lambda v: (not v.is_kev, -v.epss_score, -v.cvss_score)
            )

            # Auto-remediate
            for vuln in context.vulnerabilities:
                should_remediate = (
                    vuln.is_kev or
                    vuln.epss_score >= kEPSS_HIGH_THRESHOLD or
                    vuln.severity in [Severity.CRITICAL, Severity.HIGH]
                )

                if should_remediate and self.config.get("auto_remediation", "enabled", default=True):
                    spectre_log.info(f"Remediating {vuln.cve_id}")

                    ai_analysis = self.threat_intel.get_ai_analysis(vuln, self._get_system_context())
                    if ai_analysis:
                        spectre_log.audit("AI_ANALYSIS", {"cve": vuln.cve_id}, ai_analysis[:500])

                    mitigation = self.remediator.remediate_vulnerability(vuln, context)
                    context.mitigations.append(mitigation)

            # Save report
            context.completed_at = datetime.utcnow().isoformat()
            context.kSpectreStatus = "completed"

            report_path = kSpectreDataPath / f"scan_{scan_id}.json"
            with open(report_path, "w") as f:
                report = {
                    "scan_id": context.scan_id,
                    "scan_type": scan_type.value,
                    "started_at": context.started_at,
                    "completed_at": context.completed_at,
                    "hostname": context.hostname,
                    "os_version": context.os_version,
                    "kernel_version": context.kernel_version,
                    "vulnerabilities": [asdict(v) for v in context.vulnerabilities],
                    "mitigations": [asdict(m) for m in context.mitigations],
                    "summary": {
                        "total_vulnerabilities": len(context.vulnerabilities),
                        "critical": sum(1 for v in context.vulnerabilities if v.severity == Severity.CRITICAL),
                        "high": sum(1 for v in context.vulnerabilities if v.severity == Severity.HIGH),
                        "medium": sum(1 for v in context.vulnerabilities if v.severity == Severity.MEDIUM),
                        "mitigations_applied": sum(1 for m in context.mitigations if m.success),
                        "mitigations_failed": sum(1 for m in context.mitigations if not m.success)
                    }
                }
                json.dump(report, f, indent=2, default=str)

            spectre_log.audit(
                "AUTORECON_COMPLETE",
                {
                    "scan_id": scan_id,
                    "scan_type": scan_type.value,
                    "vulnerabilities": len(context.vulnerabilities),
                    "mitigations": len(context.mitigations)
                },
                f"{scan_type.value} scan completed"
            )

            # AI Security Posture Analysis (on deep scans)
            if scan_type == ScanType.DEEP and self.ai_engine.client:
                spectre_log.info("Running AI security posture analysis...")
                posture = self.ai_engine.analyze_security_posture({
                    "total_vulnerabilities": len(context.vulnerabilities),
                    "critical": sum(1 for v in context.vulnerabilities if v.severity == Severity.CRITICAL),
                    "high": sum(1 for v in context.vulnerabilities if v.severity == Severity.HIGH),
                    "medium": sum(1 for v in context.vulnerabilities if v.severity == Severity.MEDIUM),
                    "mitigations_failed": sum(1 for m in context.mitigations if not m.success),
                    "os_version": context.os_version,
                    "kernel_version": context.kernel_version
                })

                if posture.get("risk_score"):
                    spectre_log.audit(
                        "AI_SECURITY_POSTURE",
                        {
                            "risk_score": posture.get("risk_score"),
                            "risk_level": posture.get("risk_level"),
                            "priority_actions": posture.get("priority_actions", [])
                        },
                        posture.get("executive_summary", "AI analysis complete")
                    )

                    # Save AI analysis to report
                    ai_report_path = kSpectreDataPath / f"ai_analysis_{scan_id}.json"
                    with open(ai_report_path, "w") as f:
                        json.dump(posture, f, indent=2, default=str)

            return context

        except Exception as e:
            context.autorecon_failure_count += 1
            context.kSpectreStatus = "error"
            spectre_log.error(f"Autorecon failed: {e}")
            raise

    def _process_threats(self):
        """Process threats from the queue with AI-powered analysis"""
        while self.running:
            try:
                threat = self.threat_queue.get(timeout=1)

                spectre_log.info(f"Processing threat: {threat.threat_id} ({threat.threat_type})")

                # Convert threat to dict for AI processing
                threat_dict = {
                    "threat_id": threat.threat_id,
                    "threat_type": threat.threat_type,
                    "severity": threat.severity.value if hasattr(threat.severity, 'value') else str(threat.severity),
                    "description": threat.description,
                    "source": threat.source,
                    "detected_at": threat.detected_at,
                    "evidence": threat.evidence
                }

                # Add to AI threat history for correlation
                self.ai_engine.add_threat_to_history(threat_dict)

                # AI threat correlation - detect attack chains
                if len(self.ai_engine.threat_history) >= 2:
                    correlation = self.ai_engine.correlate_threats(
                        threat_dict,
                        self.ai_engine.threat_history
                    )
                    if correlation.get("attack_chain_detected"):
                        spectre_log.alert(
                            f"ATTACK CHAIN DETECTED: {correlation.get('pattern_name', 'Unknown')} "
                            f"(confidence: {correlation.get('confidence', 0):.0%})"
                        )
                        spectre_log.audit(
                            "ATTACK_CHAIN_DETECTED",
                            correlation,
                            f"AI detected attack pattern: {correlation.get('pattern_name')}"
                        )

                # AI-powered remediation decision
                if self.config.get("auto_remediation", "enabled", default=True):
                    # Get system state for context
                    system_state = {
                        "hostname": socket.gethostname(),
                        "critical_services": ["sshd", "firewalld"],
                        "load": os.getloadavg()[0] if hasattr(os, 'getloadavg') else "unknown",
                        "active_users": len(set(open('/etc/passwd').read().split('\n'))) if os.path.exists('/etc/passwd') else 0
                    }

                    # Get AI recommendation
                    ai_decision = self.ai_engine.get_remediation_decision(threat_dict, system_state)

                    if ai_decision.get("action") != "default":
                        spectre_log.audit(
                            "AI_REMEDIATION_DECISION",
                            {
                                "threat_id": threat.threat_id,
                                "ai_action": ai_decision.get("action"),
                                "ai_confidence": ai_decision.get("confidence"),
                                "ai_reason": ai_decision.get("reason")
                            },
                            f"AI recommended: {ai_decision.get('action')} - {ai_decision.get('reason')}"
                        )

                    # Execute remediation
                    mitigation = self.remediator.remediate_threat(threat)
                    spectre_log.audit(
                        "THREAT_REMEDIATED",
                        {"threat_id": threat.threat_id, "action": mitigation.action_type.value},
                        f"Threat remediated: {mitigation.action_details}"
                    )

            except Empty:
                continue
            except Exception as e:
                spectre_log.error(f"Threat processing error: {e}")

    def run(self):
        """Main daemon loop"""
        spectre_log.info(f"Spectre v{kSpectreVersion} starting...")
        spectre_log.audit(
            "DAEMON_START",
            {"version": kSpectreVersion},
            "Spectre daemon initialized"
        )

        # Install dependencies
        DependencyManager.ensure_dependencies()

        # Start continuous monitors
        if self.config.get("continuous_monitoring", "enabled", default=True):
            spectre_log.info("Starting continuous monitoring...")
            self.file_monitor.start()
            self.process_monitor.start()
            self.network_monitor.start()
            self.auth_monitor.start()
            self.intrusion_detector.start()

        # Start threat processing thread
        threat_thread = threading.Thread(target=self._process_threats, daemon=True)
        threat_thread.start()

        # Run initial deep scan
        try:
            self.autorecon(ScanType.DEEP)
            self.last_deep_scan = datetime.utcnow()
            self.last_standard_scan = datetime.utcnow()
            self.last_quick_scan = datetime.utcnow()
        except Exception as e:
            spectre_log.error(f"Initial scan failed: {e}")

        # Main loop
        quick_interval = timedelta(minutes=self.config.get("spectre", "quick_scan_interval_minutes", default=5))
        standard_interval = timedelta(hours=self.config.get("spectre", "standard_scan_interval_hours", default=1))
        deep_interval = timedelta(hours=self.config.get("spectre", "deep_scan_interval_hours", default=4))

        while self.running:
            try:
                now = datetime.utcnow()

                # Check for scheduled scans
                if now - self.last_deep_scan >= deep_interval:
                    self.autorecon(ScanType.DEEP)
                    self.last_deep_scan = now
                    self.last_standard_scan = now
                    self.last_quick_scan = now
                elif now - self.last_standard_scan >= standard_interval:
                    self.autorecon(ScanType.STANDARD)
                    self.last_standard_scan = now
                    self.last_quick_scan = now
                elif now - self.last_quick_scan >= quick_interval:
                    self.autorecon(ScanType.QUICK)
                    self.last_quick_scan = now

                # Notify systemd watchdog
                self._notify_watchdog()

                time.sleep(30)

            except Exception as e:
                spectre_log.error(f"Main loop error: {e}")
                time.sleep(60)

        # Shutdown
        spectre_log.info("Stopping monitors...")
        self.file_monitor.stop()
        self.process_monitor.stop()
        self.network_monitor.stop()
        self.auth_monitor.stop()

        spectre_log.info("Spectre shutting down")
        spectre_log.audit("DAEMON_STOP", {}, "Daemon stopped")

    def _notify_watchdog(self):
        """Notify systemd watchdog"""
        try:
            notify_socket = os.environ.get("NOTIFY_SOCKET")
            if notify_socket:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                sock.connect(notify_socket)
                sock.send(b"WATCHDOG=1")
                sock.close()
        except Exception:
            pass

# =============================================================================
# Entry Point
# =============================================================================

def main():
    """Main entry point"""
    if os.geteuid() != 0:
        print(f"{kSpectrePrefix} ERROR: Must run as root")
        sys.exit(1)

    daemon = Spectre()
    daemon.run()

if __name__ == "__main__":
    main()
