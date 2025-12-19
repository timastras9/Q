#!/usr/bin/env python3
"""HTTPS API with sensitive data for SSL interception testing"""

import ssl
import json
import secrets
import hashlib
import subprocess
from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

# Simulated sensitive data
USERS_DB = {
    'admin': {'password': 'SuperSecret123!', 'api_key': 'sk-prod-abc123xyz789secret', 'role': 'admin'},
    'user1': {'password': 'Password123', 'api_key': 'sk-user-def456uvw012token', 'role': 'user'},
    'dbadmin': {'password': 'MySQLr00t!', 'api_key': 'sk-db-ghi789rst345key', 'role': 'dba'},
}

CONFIG = {
    'database': {
        'host': 'mysql.internal',
        'port': 3306,
        'user': 'root',
        'password': 'root123secret',
        'database': 'production'
    },
    'redis': {
        'host': 'redis.internal',
        'password': 'redis_secret_pass'
    },
    'aws': {
        'access_key': 'AKIAIOSFODNN7EXAMPLE',
        'secret_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        's3_bucket': 'company-prod-secrets'
    },
    'jwt_secret': 'super-secret-jwt-key-do-not-share-2024'
}

@app.route('/')
def index():
    resp = make_response('''
    <html>
    <head><title>Secure API Portal</title></head>
    <body>
    <h1>Welcome to Secure API</h1>
    <p>API Version: 2.1.0</p>
    <p>Environment: production</p>
    <!-- Debug: admin_token=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.secret -->
    </body>
    </html>
    ''')
    resp.set_cookie('session_id', secrets.token_hex(16), httponly=True, secure=True)
    resp.set_cookie('user_prefs', 'theme=dark;lang=en', secure=True)
    resp.set_cookie('tracking_id', 'trk_' + secrets.token_hex(8))
    return resp

@app.route('/api')
def api_root():
    return jsonify({
        'api_version': 'v2.1.0',
        'endpoints': ['/api/users', '/api/config', '/api/auth', '/api/admin'],
        'auth_methods': ['bearer_token', 'api_key', 'session'],
        'internal_note': 'Default API key: sk-default-testing-key-123'
    })

@app.route('/api/v1')
def api_v1():
    return jsonify({
        'deprecated': True,
        'message': 'Use /api/v2 instead',
        'legacy_token': 'old_token_still_works_abc123'
    })

@app.route('/api/users')
def api_users():
    users = []
    for username, data in USERS_DB.items():
        users.append({
            'username': username,
            'password_hash': hashlib.md5(data['password'].encode()).hexdigest(),
            'api_key': data['api_key'][:20] + '...',
            'role': data['role']
        })
    return jsonify({'users': users, 'total': len(users)})

@app.route('/api/config')
def api_config():
    return jsonify({
        'status': 'ok',
        'config': CONFIG,
        'warning': 'This endpoint should not be public!'
    })

@app.route('/api/auth', methods=['GET', 'POST'])
def api_auth():
    if request.method == 'POST':
        data = request.get_json() or {}
        username = data.get('username', '')
        password = data.get('password', '')
        if username in USERS_DB and USERS_DB[username]['password'] == password:
            resp = make_response(jsonify({
                'success': True,
                'token': 'Bearer eyJhbGciOiJIUzI1NiJ9.' + secrets.token_hex(32),
                'api_key': USERS_DB[username]['api_key'],
                'message': 'Login successful'
            }))
            resp.set_cookie('auth_token', USERS_DB[username]['api_key'], httponly=True, secure=True)
            return resp
    return jsonify({
        'endpoints': {
            'login': 'POST /api/auth with {username, password}',
            'test_creds': {'username': 'admin', 'password': 'SuperSecret123!'}
        }
    })

@app.route('/admin')
def admin():
    resp = make_response('''
    <html>
    <head><title>Admin Panel</title></head>
    <body>
    <h1>Admin Dashboard</h1>
    <p>Database Status: Connected to mysql://root:root123secret@mysql:3306/prod</p>
    <p>Redis: redis://:redis_secret_pass@redis:6379</p>
    <p>AWS Region: us-east-1</p>
    <script>var adminToken = "admin_secret_token_xyz789";</script>
    </body>
    </html>
    ''')
    resp.set_cookie('admin_session', 'adm_' + secrets.token_hex(16), httponly=True, secure=True)
    resp.set_cookie('admin_level', 'superuser')
    return resp

@app.route('/login')
def login():
    return '''
    <html>
    <head><title>Login</title></head>
    <body>
    <h1>Login</h1>
    <form action="/api/auth" method="POST">
    <input name="username" placeholder="Username">
    <input name="password" type="password" placeholder="Password">
    <button>Login</button>
    </form>
    <!-- Backup admin: admin / SuperSecret123! -->
    </body>
    </html>
    '''

@app.route('/robots.txt')
def robots():
    return '''User-agent: *
Disallow: /admin
Disallow: /api/config
Disallow: /backup
Disallow: /internal
# Secret paths: /api/debug, /api/internal/keys
'''

@app.route('/.well-known/')
def wellknown():
    return jsonify({
        'security': '/security.txt',
        'jwks': '/jwks.json',
        'openid-configuration': {
            'issuer': 'https://api.internal',
            'token_endpoint': '/oauth/token',
            'client_secret': 'oauth_secret_do_not_share'
        }
    })

@app.route('/graphql', methods=['GET', 'POST'])
def graphql():
    return jsonify({
        'data': {
            '__schema': {
                'types': [
                    {'name': 'User', 'fields': ['id', 'username', 'password', 'apiKey']},
                    {'name': 'Config', 'fields': ['database', 'secrets', 'awsKeys']},
                    {'name': 'Credential', 'fields': ['username', 'password', 'token']}
                ]
            }
        }
    })

if __name__ == '__main__':
    # Generate self-signed cert
    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
        '-keyout', '/tmp/key.pem', '-out', '/tmp/cert.pem',
        '-days', '365', '-nodes',
        '-subj', '/CN=api.internal/O=TestCorp/C=US'
    ], capture_output=True)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('/tmp/cert.pem', '/tmp/key.pem')

    print('HTTPS API running on port 8443')
    app.run(host='0.0.0.0', port=8443, ssl_context=context, debug=False)
