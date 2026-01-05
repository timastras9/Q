# Sentinel Linux

**An AI-powered, self-healing, security-first Linux distribution.**

Sentinel Linux is built from scratch with security as the primary design principle. It features an autonomous security daemon powered by Claude AI that continuously monitors, detects threats, and automatically remediates vulnerabilities.

## Philosophy

- **Secure by Default** - Minimal attack surface, hardened kernel, strict defaults
- **Self-Healing** - Automatic vulnerability patching and threat remediation
- **AI-Powered** - Claude integration for intelligent threat analysis
- **Audit Everything** - Complete audit trail of all security events
- **Zero Trust** - Verify everything, trust nothing

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Sentinel Linux                           │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Sentinel Daemon (Core)                  │   │
│  │  • AI Security Engine (Claude)                       │   │
│  │  • Real-time File/Process/Network Monitoring         │   │
│  │  • Vulnerability Scanner                             │   │
│  │  • Auto-Remediation Engine                           │   │
│  └─────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│  Security Layer                                             │
│  • Hardened Kernel (custom config)                         │
│  • Mandatory Access Control (SELinux)                      │
│  • Secure Boot                                             │
│  • Full Disk Encryption                                    │
├─────────────────────────────────────────────────────────────┤
│  Base System                                                │
│  • musl libc (or glibc)                                    │
│  • BusyBox + core utilities                                │
│  • systemd (init)                                          │
│  • Python 3.11+ (for Sentinel)                             │
├─────────────────────────────────────────────────────────────┤
│  Linux Kernel 6.x (hardened)                               │
└─────────────────────────────────────────────────────────────┘
```

## Features

### Security
- Hardened Linux kernel with security patches
- SELinux in enforcing mode by default
- Secure boot with signed kernel/initramfs
- Full disk encryption (LUKS2)
- No root password by default (key-based auth only)
- Minimal installed packages

### AI-Powered Protection
- Real-time threat detection
- Attack chain correlation
- Intelligent remediation decisions
- Security posture analysis
- Incident report generation

### Monitoring
- File integrity monitoring (inotify)
- Process behavior analysis
- Network connection tracking
- Authentication monitoring
- Brute force detection

### Auto-Remediation
- Automatic security patching
- Suspicious process termination
- Malicious file quarantine
- Firewall rule injection
- IP blocking for attackers

## Build Requirements

- Linux host (for building)
- Docker (for isolated builds)
- 20GB+ disk space
- 4GB+ RAM
- Internet connection

## Quick Start

```bash
# Clone the repository
git clone https://github.com/pentestai/sentinel-linux.git
cd sentinel-linux

# Build the ISO
./scripts/build.sh

# Output: iso/sentinel-linux-1.0.0.iso
```

## Installation

1. Boot from ISO
2. Run installer: `sentinel-install`
3. Configure disk encryption passphrase
4. Set Anthropic API key (optional, for AI features)
5. Reboot into Sentinel Linux

## Configuration

After installation, configure via:
```bash
# Edit Sentinel config
nano /etc/sentinel/config.json

# View status
sentinelctl status

# View logs
journalctl -u sentinel -f

# Manual scan
sentinelctl scan --deep
```

## Directory Structure

```
sentinel-linux/
├── build/          # Build artifacts
├── config/         # System configuration
├── docs/           # Documentation
├── iso/            # Output ISO images
├── kernel/         # Kernel config and patches
├── packages/       # Package definitions
├── rootfs/         # Root filesystem overlay
└── scripts/        # Build and utility scripts
```

## License

MIT License - See LICENSE file

## Contributing

Contributions welcome! Please read CONTRIBUTING.md first.

---

**Sentinel Linux** - Security that thinks for itself.
