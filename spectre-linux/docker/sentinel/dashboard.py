#!/usr/bin/env python3
"""
Spectre Interactive Dashboard
==============================

Real-time security monitoring dashboard with live alerts,
system status, and threat visualization.

Usage:
    python dashboard.py              # Connect to running daemon
    python dashboard.py --demo       # Demo mode with simulated events
"""

import os
import sys
import json
import time
import threading
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from collections import deque
from typing import Optional, Dict, List, Any

try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.text import Text
    from rich.style import Style
    from rich import box
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.align import Align
except ImportError:
    print("Installing required package: rich")
    os.system("pip3 install rich")
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.text import Text
    from rich.style import Style
    from rich import box
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.align import Align

# Configuration
LOG_PATH = Path("/var/log/spectre/spectre.log")
ALERTS_PATH = Path("/var/log/spectre/alerts.log")
MAX_ALERTS = 50
REFRESH_RATE = 0.5  # seconds

console = Console()


class SpectreDashboard:
    """Interactive security monitoring dashboard"""

    def __init__(self, log_path: Path = LOG_PATH, demo_mode: bool = False):
        self.log_path = log_path
        self.demo_mode = demo_mode
        self.running = True
        self.alerts: deque = deque(maxlen=MAX_ALERTS)
        self.stats = {
            "total_alerts": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "port_scans": 0,
            "connection_floods": 0,
            "ssl_anomalies": 0,
            "auth_failures": 0,
            "files_monitored": 0,
            "uptime_start": datetime.now(),
        }
        self.last_position = 0
        self.selected_alert = 0
        self.view_mode = "dashboard"  # dashboard, alerts, details

        # Start log watcher thread
        self.watcher_thread = threading.Thread(target=self._watch_logs, daemon=True)
        self.watcher_thread.start()

        if demo_mode:
            self.demo_thread = threading.Thread(target=self._generate_demo_events, daemon=True)
            self.demo_thread.start()

    def _watch_logs(self):
        """Watch log file for new entries"""
        while self.running:
            try:
                if self.log_path.exists():
                    with open(self.log_path, 'r') as f:
                        f.seek(self.last_position)
                        for line in f:
                            self._parse_log_line(line)
                        self.last_position = f.tell()
            except Exception as e:
                pass
            time.sleep(0.2)

    def _parse_log_line(self, line: str):
        """Parse log line and extract alerts"""
        line = line.strip()
        if not line:
            return

        # Detect different alert types
        alert = None
        timestamp = datetime.now().strftime("%H:%M:%S")

        if "INTRUSION ALERT" in line or "🚨" in line:
            if "PORT SCAN" in line:
                alert = {
                    "time": timestamp,
                    "type": "PORT_SCAN",
                    "severity": "HIGH",
                    "message": "Port scan detected",
                    "raw": line
                }
                self.stats["port_scans"] += 1
            elif "CONNECTION FLOOD" in line:
                alert = {
                    "time": timestamp,
                    "type": "CONN_FLOOD",
                    "severity": "CRITICAL",
                    "message": "Connection flood detected",
                    "raw": line
                }
                self.stats["connection_floods"] += 1
            elif "Source IP:" in line:
                # Extract IP from the line
                ip = line.split("Source IP:")[-1].strip()
                if self.alerts and "ip" not in self.alerts[-1]:
                    self.alerts[-1]["ip"] = ip

        elif "SSL/TLS ALERT" in line or "🔐" in line:
            if "MITM" in line:
                alert = {
                    "time": timestamp,
                    "type": "SSL_MITM",
                    "severity": "CRITICAL",
                    "message": "Possible MITM attack detected",
                    "raw": line
                }
            elif "UNEXPECTED" in line:
                alert = {
                    "time": timestamp,
                    "type": "SSL_ROGUE",
                    "severity": "HIGH",
                    "message": "Unexpected SSL port detected",
                    "raw": line
                }
            elif "REPEATED" in line:
                alert = {
                    "time": timestamp,
                    "type": "SSL_ENUM",
                    "severity": "MEDIUM",
                    "message": "SSL enumeration attempt",
                    "raw": line
                }
            if alert:
                self.stats["ssl_anomalies"] += 1

        elif "AUTH" in line.upper() and ("FAIL" in line.upper() or "INVALID" in line.upper()):
            alert = {
                "time": timestamp,
                "type": "AUTH_FAIL",
                "severity": "MEDIUM",
                "message": "Authentication failure",
                "raw": line
            }
            self.stats["auth_failures"] += 1

        elif "File monitoring started" in line:
            try:
                count = int(line.split("for")[-1].split("paths")[0].strip())
                self.stats["files_monitored"] = count
            except:
                pass

        if alert:
            self.alerts.appendleft(alert)
            self.stats["total_alerts"] += 1
            severity = alert["severity"]
            if severity == "CRITICAL":
                self.stats["critical"] += 1
            elif severity == "HIGH":
                self.stats["high"] += 1
            elif severity == "MEDIUM":
                self.stats["medium"] += 1
            else:
                self.stats["low"] += 1

    def _generate_demo_events(self):
        """Generate demo events for testing"""
        import random
        demo_alerts = [
            ("PORT_SCAN", "HIGH", "Port scan from 192.168.1.100"),
            ("CONN_FLOOD", "CRITICAL", "Connection flood: 150 conn/min from 10.0.0.50"),
            ("SSL_MITM", "CRITICAL", "SSL on port 80 - possible MITM"),
            ("AUTH_FAIL", "MEDIUM", "Failed SSH login for root from 192.168.1.200"),
            ("SSL_ENUM", "MEDIUM", "Repeated SSL connections from 172.16.0.25"),
            ("SSL_ROGUE", "HIGH", "Unexpected SSL on port 8888"),
        ]

        while self.running:
            time.sleep(random.uniform(2, 5))
            alert_type, severity, message = random.choice(demo_alerts)
            alert = {
                "time": datetime.now().strftime("%H:%M:%S"),
                "type": alert_type,
                "severity": severity,
                "message": message,
                "ip": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            }
            self.alerts.appendleft(alert)
            self.stats["total_alerts"] += 1
            if severity == "CRITICAL":
                self.stats["critical"] += 1
            elif severity == "HIGH":
                self.stats["high"] += 1
            elif severity == "MEDIUM":
                self.stats["medium"] += 1

    def _make_header(self) -> Panel:
        """Create header panel"""
        title = Text()
        title.append("  SPECTRE  ", style="bold white on red")
        title.append("  Security Dashboard  ", style="bold cyan")

        uptime = datetime.now() - self.stats["uptime_start"]
        hours, remainder = divmod(int(uptime.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)

        status = Text()
        status.append(f"Uptime: {hours:02d}:{minutes:02d}:{seconds:02d}", style="green")
        status.append("  |  ", style="dim")
        status.append(f"Alerts: {self.stats['total_alerts']}", style="yellow")
        status.append("  |  ", style="dim")
        if self.demo_mode:
            status.append("DEMO MODE", style="bold yellow")
        else:
            status.append("LIVE", style="bold green")

        header_text = Text.assemble(title, "\n", status)
        return Panel(
            Align.center(header_text),
            box=box.DOUBLE,
            style="bold blue",
            height=5
        )

    def _make_stats_panel(self) -> Panel:
        """Create statistics panel"""
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Label", style="dim")
        table.add_column("Value", justify="right")

        table.add_row("Total Alerts", f"[bold yellow]{self.stats['total_alerts']}[/]")
        table.add_row("Critical", f"[bold red]{self.stats['critical']}[/]")
        table.add_row("High", f"[bold orange1]{self.stats['high']}[/]")
        table.add_row("Medium", f"[bold yellow]{self.stats['medium']}[/]")
        table.add_row("Low", f"[bold green]{self.stats['low']}[/]")

        return Panel(table, title="[bold]Statistics[/]", border_style="green")

    def _make_threat_panel(self) -> Panel:
        """Create threat breakdown panel"""
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Type", style="dim")
        table.add_column("Count", justify="right")

        table.add_row("Port Scans", f"[cyan]{self.stats['port_scans']}[/]")
        table.add_row("Conn Floods", f"[red]{self.stats['connection_floods']}[/]")
        table.add_row("SSL Anomalies", f"[yellow]{self.stats['ssl_anomalies']}[/]")
        table.add_row("Auth Failures", f"[orange1]{self.stats['auth_failures']}[/]")
        table.add_row("Files Watched", f"[green]{self.stats['files_monitored']}[/]")

        return Panel(table, title="[bold]Threat Types[/]", border_style="yellow")

    def _make_alerts_panel(self) -> Panel:
        """Create live alerts panel"""
        table = Table(box=box.SIMPLE, expand=True, show_edge=False)
        table.add_column("Time", style="dim", width=8)
        table.add_column("Sev", width=8)
        table.add_column("Type", width=12)
        table.add_column("Message", ratio=1)
        table.add_column("IP", width=15)

        severity_styles = {
            "CRITICAL": "bold white on red",
            "HIGH": "bold red",
            "MEDIUM": "bold yellow",
            "LOW": "green",
            "INFO": "dim"
        }

        for i, alert in enumerate(list(self.alerts)[:15]):
            sev = alert.get("severity", "INFO")
            style = severity_styles.get(sev, "dim")

            table.add_row(
                alert.get("time", ""),
                Text(sev[:4], style=style),
                alert.get("type", ""),
                alert.get("message", "")[:40],
                alert.get("ip", "-")
            )

        if not self.alerts:
            table.add_row("--:--:--", "---", "---", "No alerts yet - system secure", "-")

        return Panel(
            table,
            title="[bold red]Live Alerts[/]",
            border_style="red",
            subtitle="[dim]Most recent threats[/]"
        )

    def _make_status_bar(self) -> Panel:
        """Create status bar"""
        text = Text()
        text.append(" Q", style="bold cyan")
        text.append(":Quit  ", style="dim")
        text.append("R", style="bold cyan")
        text.append(":Refresh  ", style="dim")
        text.append("C", style="bold cyan")
        text.append(":Clear  ", style="dim")
        text.append("D", style="bold cyan")
        text.append(":Demo Toggle  ", style="dim")

        return Panel(text, style="dim", height=3)

    def make_layout(self) -> Layout:
        """Create the dashboard layout"""
        layout = Layout()

        layout.split_column(
            Layout(name="header", size=5),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3)
        )

        layout["main"].split_row(
            Layout(name="sidebar", size=25),
            Layout(name="content", ratio=1)
        )

        layout["sidebar"].split_column(
            Layout(name="stats", ratio=1),
            Layout(name="threats", ratio=1)
        )

        # Populate panels
        layout["header"].update(self._make_header())
        layout["stats"].update(self._make_stats_panel())
        layout["threats"].update(self._make_threat_panel())
        layout["content"].update(self._make_alerts_panel())
        layout["footer"].update(self._make_status_bar())

        return layout

    def run(self):
        """Run the interactive dashboard"""
        console.clear()

        try:
            with Live(self.make_layout(), console=console, refresh_per_second=2, screen=True) as live:
                while self.running:
                    live.update(self.make_layout())
                    time.sleep(REFRESH_RATE)
        except KeyboardInterrupt:
            self.running = False
            console.clear()
            console.print("[bold green]Spectre Dashboard closed.[/]")


def main():
    parser = argparse.ArgumentParser(description="Spectre Security Dashboard")
    parser.add_argument("--demo", action="store_true", help="Run in demo mode with simulated events")
    parser.add_argument("--log", type=str, default=str(LOG_PATH), help="Path to spectre log file")
    args = parser.parse_args()

    console.print("[bold cyan]Starting Spectre Dashboard...[/]")

    log_path = Path(args.log)
    if not log_path.exists() and not args.demo:
        console.print(f"[yellow]Warning: Log file not found at {log_path}[/]")
        console.print("[yellow]Starting in demo mode...[/]")
        args.demo = True

    dashboard = SpectreDashboard(log_path=log_path, demo_mode=args.demo)
    dashboard.run()


if __name__ == "__main__":
    main()
