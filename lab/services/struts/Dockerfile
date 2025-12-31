# Apache Struts Vulnerable App (CVE-2017-5638 simulation)
# Simulates the Content-Type header parsing vulnerability
FROM python:3.9-slim

WORKDIR /app

# Install Flask to simulate the vulnerability
RUN pip install flask

# Create the vulnerable app
RUN cat > /app/struts_sim.py << 'PYTHON'
from flask import Flask, request, Response
import subprocess
import os
import re

app = Flask(__name__)

# Simulated Struts vulnerability - Content-Type OGNL injection
# Real CVE-2017-5638 allowed RCE via malicious Content-Type headers

def check_ognl_injection(content_type):
    """
    Simulates OGNL injection vulnerability in Struts Content-Type parser
    In real Struts, OGNL expressions in Content-Type could execute arbitrary code
    """
    if not content_type:
        return None

    # Pattern that simulates OGNL injection detection
    # Real exploit: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)...}
    ognl_patterns = [
        r'%\{.*\}',                    # Basic OGNL expression
        r'\$\{.*\}',                   # Alternative syntax
        r'#cmd=.*Runtime',             # Common exploit pattern
        r'getRuntime\(\)\.exec',       # Exec pattern
        r'ProcessBuilder',             # ProcessBuilder pattern
    ]

    for pattern in ognl_patterns:
        match = re.search(pattern, content_type, re.IGNORECASE)
        if match:
            # Extract command if present (simulated vulnerability)
            cmd_match = re.search(r"exec\('([^']+)'\)", content_type)
            if cmd_match:
                return cmd_match.group(1)
            cmd_match = re.search(r'cmd=([^&\)]+)', content_type)
            if cmd_match:
                return cmd_match.group(1)
            # Default command for detection
            return "id"
    return None

@app.route('/', methods=['GET', 'POST'])
def index():
    content_type = request.headers.get('Content-Type', '')

    # Check for OGNL injection in Content-Type
    cmd = check_ognl_injection(content_type)
    if cmd:
        try:
            # VULNERABLE: Execute injected command
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5)
            return Response(
                f"Struts2 Error: OGNL evaluation failed\n\n{result.decode('utf-8', errors='replace')}",
                status=500,
                content_type='text/plain'
            )
        except Exception as e:
            return Response(f"Struts2 Error: {str(e)}", status=500)

    html = """
    <!DOCTYPE html>
    <html>
    <head><title>Employee Portal</title></head>
    <body>
    <h1>Employee Self-Service Portal</h1>
    <p>Powered by Apache Struts 2.3.31</p>
    <form action="/upload" method="POST" enctype="multipart/form-data">
        <h3>Document Upload</h3>
        <input type="file" name="document">
        <button type="submit">Upload</button>
    </form>
    <h3>Quick Links</h3>
    <ul>
        <li><a href="/profile">My Profile</a></li>
        <li><a href="/timesheet">Timesheet</a></li>
        <li><a href="/expenses">Expense Reports</a></li>
    </ul>
    <footer><small>Internal Use Only - IT Security Contact: security@corp.local</small></footer>
    </body>
    </html>
    """
    return html

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    content_type = request.headers.get('Content-Type', '')

    # Check for OGNL injection
    cmd = check_ognl_injection(content_type)
    if cmd:
        try:
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5)
            return Response(
                f"Jakarta Multipart Parser Error\n\n{result.decode('utf-8', errors='replace')}",
                status=500,
                content_type='text/plain'
            )
        except Exception as e:
            return Response(f"Upload Error: {str(e)}", status=500)

    return "File upload endpoint - POST multipart/form-data"

@app.route('/profile')
def profile():
    return "<h1>Employee Profile</h1><p>Coming soon...</p>"

@app.route('/timesheet')
def timesheet():
    return "<h1>Timesheet System</h1><p>Coming soon...</p>"

@app.route('/expenses')
def expenses():
    return "<h1>Expense Reports</h1><p>Coming soon...</p>"

if __name__ == '__main__':
    print("Struts-like vulnerable app running on port 8091")
    print("Vulnerable to Content-Type header OGNL injection (CVE-2017-5638 simulation)")
    app.run(host='0.0.0.0', port=8091)
PYTHON

EXPOSE 8091

CMD ["python", "/app/struts_sim.py"]
