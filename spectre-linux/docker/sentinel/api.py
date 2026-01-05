#!/usr/bin/env python3
"""
Spectre - Threat Intelligence API
==========================================

Provides REST API for threat intelligence data:
- CISA KEV lookup
- EPSS scores
- Vulnerability analysis via Anthropic
- Integration with PentestAI

Runs on port 8095
"""

import os
import json
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import urllib.request
import ssl
from typing import Optional, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[Spectre-API] %(asctime)s %(levelname)s: %(message)s'
)
log = logging.getLogger(__name__)

# Constants
API_PORT = 8095
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# Cache
kev_cache: Dict[str, Any] = {}
kev_cache_time: Optional[datetime] = None
epss_cache: Dict[str, float] = {}


class ThreatIntelHandler(BaseHTTPRequestHandler):
    """HTTP request handler for threat intel API"""

    def log_message(self, format, *args):
        log.info(f"{self.address_string()} - {format % args}")

    def _send_json(self, data: Dict, status: int = 200):
        """Send JSON response"""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _send_error(self, message: str, status: int = 400):
        """Send error response"""
        self._send_json({"error": message, "status": status}, status)

    def do_GET(self):
        """Handle GET requests"""
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        try:
            if path == "/health":
                self._handle_health()
            elif path == "/api/v1/kev":
                self._handle_kev(params)
            elif path == "/api/v1/kev/check":
                self._handle_kev_check(params)
            elif path == "/api/v1/epss":
                self._handle_epss(params)
            elif path == "/api/v1/analyze":
                self._handle_analyze(params)
            elif path == "/api/v1/scans":
                self._handle_scans()
            elif path == "/api/v1/stats":
                self._handle_stats()
            else:
                self._send_error("Not found", 404)

        except Exception as e:
            log.error(f"Request error: {e}")
            self._send_error(str(e), 500)

    def do_OPTIONS(self):
        """Handle CORS preflight"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def _handle_health(self):
        """Health check endpoint"""
        self._send_json({
            "status": "healthy",
            "service": "Spectre Threat Intel API",
            "version": "1.0.0",
            "timestamp": datetime.utcnow().isoformat()
        })

    def _handle_kev(self, params: Dict):
        """Get full CISA KEV catalog"""
        global kev_cache, kev_cache_time

        # Refresh cache if older than 1 hour
        if not kev_cache_time or (datetime.utcnow() - kev_cache_time).seconds > 3600:
            try:
                ctx = ssl.create_default_context()
                with urllib.request.urlopen(CISA_KEV_URL, context=ctx, timeout=30) as resp:
                    data = json.loads(resp.read().decode())
                    kev_cache = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
                    kev_cache_time = datetime.utcnow()
                    log.info(f"Refreshed KEV cache: {len(kev_cache)} vulnerabilities")
            except Exception as e:
                log.error(f"Failed to fetch KEV: {e}")

        # Return catalog stats or full list
        if params.get("full", ["false"])[0].lower() == "true":
            self._send_json({
                "count": len(kev_cache),
                "last_updated": kev_cache_time.isoformat() if kev_cache_time else None,
                "vulnerabilities": list(kev_cache.values())
            })
        else:
            self._send_json({
                "count": len(kev_cache),
                "last_updated": kev_cache_time.isoformat() if kev_cache_time else None,
                "sample": list(kev_cache.keys())[:10]
            })

    def _handle_kev_check(self, params: Dict):
        """Check if CVE is in KEV list"""
        cve = params.get("cve", [None])[0]
        if not cve:
            self._send_error("Missing 'cve' parameter")
            return

        # Ensure cache is populated
        self._handle_kev.__wrapped__(self, {}) if not kev_cache else None

        is_kev = cve.upper() in kev_cache
        result = {
            "cve": cve.upper(),
            "in_kev": is_kev,
            "checked_at": datetime.utcnow().isoformat()
        }

        if is_kev:
            kev_data = kev_cache[cve.upper()]
            result["kev_data"] = {
                "vendor": kev_data.get("vendorProject"),
                "product": kev_data.get("product"),
                "description": kev_data.get("shortDescription"),
                "date_added": kev_data.get("dateAdded"),
                "due_date": kev_data.get("dueDate"),
                "required_action": kev_data.get("requiredAction")
            }

        self._send_json(result)

    def _handle_epss(self, params: Dict):
        """Get EPSS score for CVE"""
        cve = params.get("cve", [None])[0]
        if not cve:
            self._send_error("Missing 'cve' parameter")
            return

        cve = cve.upper()

        # Check cache
        if cve in epss_cache:
            self._send_json({
                "cve": cve,
                "epss": epss_cache[cve],
                "cached": True
            })
            return

        # Fetch from API
        try:
            url = f"{EPSS_API_URL}?cve={cve}"
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(url, context=ctx, timeout=10) as resp:
                data = json.loads(resp.read().decode())

            if data.get("data"):
                score = float(data["data"][0].get("epss", 0))
                percentile = float(data["data"][0].get("percentile", 0))
                epss_cache[cve] = score

                self._send_json({
                    "cve": cve,
                    "epss": score,
                    "percentile": percentile,
                    "risk_level": "critical" if score >= 0.8 else "high" if score >= 0.4 else "medium" if score >= 0.1 else "low"
                })
            else:
                self._send_json({
                    "cve": cve,
                    "epss": 0.0,
                    "error": "CVE not found in EPSS database"
                })

        except Exception as e:
            log.error(f"EPSS lookup failed: {e}")
            self._send_error(f"EPSS lookup failed: {e}")

    def _handle_analyze(self, params: Dict):
        """Analyze vulnerability using Anthropic API"""
        cve = params.get("cve", [None])[0]
        if not cve:
            self._send_error("Missing 'cve' parameter")
            return

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            self._send_error("ANTHROPIC_API_KEY not configured", 503)
            return

        try:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)

            # Get KEV and EPSS data first
            is_kev = cve.upper() in kev_cache
            epss = epss_cache.get(cve.upper(), 0.0)

            prompt = f"""Analyze this vulnerability for a security team:

CVE: {cve}
In CISA KEV: {is_kev}
EPSS Score: {epss}

Provide:
1. Brief description (1-2 sentences)
2. Risk assessment for enterprise Linux systems
3. Recommended mitigation steps
4. Detection indicators

Keep response concise and actionable."""

            message = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=500,
                messages=[{"role": "user", "content": prompt}]
            )

            self._send_json({
                "cve": cve,
                "is_kev": is_kev,
                "epss": epss,
                "analysis": message.content[0].text,
                "analyzed_at": datetime.utcnow().isoformat()
            })

        except ImportError:
            self._send_error("anthropic package not installed", 503)
        except Exception as e:
            log.error(f"AI analysis failed: {e}")
            self._send_error(f"Analysis failed: {e}")

    def _handle_scans(self):
        """List recent Spectre scans"""
        data_path = Path("/opt/spectre/data")
        scans = []

        if data_path.exists():
            for scan_file in sorted(data_path.glob("scan_*.json"), reverse=True)[:10]:
                try:
                    with open(scan_file) as f:
                        scan_data = json.load(f)
                        scans.append({
                            "scan_id": scan_data.get("scan_id"),
                            "started_at": scan_data.get("started_at"),
                            "completed_at": scan_data.get("completed_at"),
                            "hostname": scan_data.get("hostname"),
                            "summary": scan_data.get("summary", {})
                        })
                except Exception as e:
                    log.warning(f"Failed to read scan file {scan_file}: {e}")

        self._send_json({"scans": scans, "count": len(scans)})

    def _handle_stats(self):
        """Get aggregated statistics"""
        data_path = Path("/opt/spectre/data")
        stats = {
            "total_scans": 0,
            "total_vulnerabilities": 0,
            "total_mitigations": 0,
            "successful_mitigations": 0,
            "kev_cache_size": len(kev_cache),
            "epss_cache_size": len(epss_cache)
        }

        if data_path.exists():
            for scan_file in data_path.glob("scan_*.json"):
                try:
                    with open(scan_file) as f:
                        scan_data = json.load(f)
                        stats["total_scans"] += 1
                        summary = scan_data.get("summary", {})
                        stats["total_vulnerabilities"] += summary.get("total_vulnerabilities", 0)
                        stats["total_mitigations"] += summary.get("mitigations_applied", 0) + summary.get("mitigations_failed", 0)
                        stats["successful_mitigations"] += summary.get("mitigations_applied", 0)
                except Exception:
                    pass

        self._send_json(stats)


def main():
    """Start the API server"""
    server = HTTPServer(('0.0.0.0', API_PORT), ThreatIntelHandler)
    log.info(f"Spectre Threat Intel API starting on port {API_PORT}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
