# SSRF Vulnerable Service for PentestAI Testing
# Multiple vulnerable endpoints with different behaviors

FROM python:3.9-slim

WORKDIR /app

RUN pip install flask requests

# Create the vulnerable SSRF service
RUN cat > /app/server.py << 'PYTHON'
from flask import Flask, request, jsonify
import requests
import subprocess

app = Flask(__name__)

@app.route('/')
def index():
    return '''<html>
<head><title>Corporate URL Proxy</title></head>
<body>
<h1>Internal URL Proxy Service</h1>
<p>This service allows fetching external content for internal processing.</p>

<h2>Available Endpoints:</h2>
<ul>
    <li><a href="/api/fetch?url=http://example.com">/api/fetch?url=</a> - Fetch any URL</li>
    <li><a href="/api/proxy?target=http://example.com">/api/proxy?target=</a> - Proxy requests</li>
    <li><a href="/api/preview?link=http://example.com">/api/preview?link=</a> - Preview URL content</li>
    <li><a href="/api/screenshot?site=http://example.com">/api/screenshot?site=</a> - Screenshot service</li>
    <li><a href="/api/pdf?source=http://example.com">/api/pdf?source=</a> - PDF generation</li>
    <li><a href="/api/import?file=http://example.com/data.json">/api/import?file=</a> - Import data</li>
    <li><a href="/api/webhook?callback=http://example.com">/api/webhook?callback=</a> - Webhook callback</li>
</ul>
</body>
</html>'''


@app.route('/api/fetch')
def fetch():
    """Classic SSRF - no validation"""
    url = request.args.get('url', '')
    if not url:
        return jsonify({'error': 'URL parameter required'}), 400

    try:
        resp = requests.get(url, timeout=5, allow_redirects=True)
        return jsonify({
            'url': url,
            'status': resp.status_code,
            'headers': dict(resp.headers),
            'content': resp.text[:5000]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/proxy')
def proxy():
    """SSRF via proxy parameter"""
    target = request.args.get('target', '')
    if not target:
        return jsonify({'error': 'target parameter required'}), 400

    try:
        resp = requests.get(target, timeout=5)
        return resp.text, resp.status_code, dict(resp.headers)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/preview')
def preview():
    """SSRF via link preview"""
    link = request.args.get('link', '')
    if not link:
        return jsonify({'error': 'link parameter required'}), 400

    try:
        resp = requests.get(link, timeout=5)
        # Extract title and description
        content = resp.text
        return jsonify({
            'url': link,
            'content': content[:3000],
            'status': resp.status_code
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/screenshot')
def screenshot():
    """SSRF via screenshot service - simulated"""
    site = request.args.get('site', '')
    if not site:
        return jsonify({'error': 'site parameter required'}), 400

    try:
        resp = requests.get(site, timeout=5)
        return jsonify({
            'site': site,
            'simulated': True,
            'status': resp.status_code,
            'fetched_content': resp.text[:2000]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/pdf')
def pdf():
    """SSRF via PDF generation"""
    source = request.args.get('source', '')
    if not source:
        return jsonify({'error': 'source parameter required'}), 400

    try:
        resp = requests.get(source, timeout=5)
        return jsonify({
            'source': source,
            'status': resp.status_code,
            'content': resp.text[:3000]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/import', methods=['GET', 'POST'])
def import_data():
    """SSRF via data import"""
    file_url = request.args.get('file', '') or request.form.get('file', '')
    if not file_url:
        return jsonify({'error': 'file parameter required'}), 400

    try:
        resp = requests.get(file_url, timeout=5)
        return jsonify({
            'file': file_url,
            'status': resp.status_code,
            'data': resp.text[:5000]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/webhook', methods=['GET', 'POST'])
def webhook():
    """SSRF via webhook callback"""
    callback = request.args.get('callback', '') or request.form.get('callback', '')
    if not callback:
        return jsonify({'error': 'callback parameter required'}), 400

    try:
        # Simulate webhook by fetching the callback URL
        resp = requests.post(callback, json={'event': 'test', 'data': 'pentestai'}, timeout=5)
        return jsonify({
            'callback': callback,
            'status': resp.status_code,
            'response': resp.text[:1000]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/avatar')
def avatar():
    """SSRF via avatar URL fetch"""
    url = request.args.get('url', '')
    if not url:
        return jsonify({'error': 'url parameter required'}), 400

    try:
        resp = requests.get(url, timeout=5)
        return jsonify({
            'url': url,
            'status': resp.status_code,
            'size': len(resp.content),
            'content_type': resp.headers.get('Content-Type', 'unknown'),
            'content_preview': resp.text[:500] if 'text' in resp.headers.get('Content-Type', '') else 'binary'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'service': 'ssrf-vuln'})


if __name__ == '__main__':
    print("SSRF Vulnerable Service running on port 8094")
    app.run(host='0.0.0.0', port=8094, debug=False)
PYTHON

EXPOSE 8094

CMD ["python", "/app/server.py"]
