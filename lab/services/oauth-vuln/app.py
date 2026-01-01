"""
Vulnerable OAuth/OIDC Service for Security Testing
Contains: Open redirect, weak token validation, CSRF, implicit flow issues
"""

from flask import Flask, request, redirect, jsonify, render_template_string
import jwt
import time
import hashlib
import os

app = Flask(__name__)

# Weak secret - easily brutable
JWT_SECRET = "secret123"
CLIENT_SECRET = "client_secret_weak"

# Simulated registered clients
CLIENTS = {
    "webapp": {
        "secret": "client_secret_weak",
        "redirect_uris": ["http://localhost:3000/callback"],  # But we don't validate properly!
        "name": "Web Application"
    },
    "mobile": {
        "secret": "mobile_secret",
        "redirect_uris": ["myapp://callback"],
        "name": "Mobile App"
    }
}

# Simulated users
USERS = {
    "admin": {"password": "admin123", "email": "admin@corp.local", "role": "admin"},
    "user": {"password": "password", "email": "user@corp.local", "role": "user"},
}

# Active tokens (simulated database)
TOKENS = {}

@app.route('/')
def index():
    return '''
    <h1>OAuth 2.0 Authorization Server</h1>
    <p>Version: 1.0.0 (Vulnerable for Testing)</p>
    <h2>Endpoints:</h2>
    <ul>
        <li><a href="/authorize">/authorize</a> - Authorization endpoint</li>
        <li>/token - Token endpoint</li>
        <li><a href="/.well-known/openid-configuration">/.well-known/openid-configuration</a> - OIDC Discovery</li>
        <li><a href="/.well-known/jwks.json">/.well-known/jwks.json</a> - JWKS endpoint</li>
    </ul>
    '''

@app.route('/.well-known/openid-configuration')
def openid_config():
    """OIDC Discovery - exposes configuration"""
    base_url = request.host_url.rstrip('/')
    return jsonify({
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/authorize",
        "token_endpoint": f"{base_url}/token",
        "userinfo_endpoint": f"{base_url}/userinfo",
        "jwks_uri": f"{base_url}/.well-known/jwks.json",
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256", "none"],  # 'none' is vulnerable!
        "scopes_supported": ["openid", "profile", "email", "admin"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "email", "name", "role"],
        # Information disclosure
        "internal_note": "Debug mode enabled, JWT secret is 'secret123'"
    })

@app.route('/.well-known/jwks.json')
def jwks():
    """JWKS endpoint - but we use symmetric keys which shouldn't be here!"""
    return jsonify({
        "keys": [
            {
                "kty": "oct",  # Symmetric key exposed!
                "kid": "key1",
                "k": "c2VjcmV0MTIz",  # base64 of 'secret123'
                "alg": "HS256"
            }
        ]
    })

@app.route('/authorize')
def authorize():
    """Authorization endpoint with multiple vulnerabilities"""
    client_id = request.args.get('client_id', '')
    redirect_uri = request.args.get('redirect_uri', '')
    response_type = request.args.get('response_type', 'code')
    state = request.args.get('state', '')
    scope = request.args.get('scope', 'openid')

    # Vulnerability 1: No redirect_uri validation!
    # We should check if redirect_uri matches registered URIs
    # But we just accept any redirect_uri

    # Vulnerability 2: Implicit flow enabled (response_type=token)
    # Tokens in URL fragment can be leaked via Referer

    # Show login form
    return render_template_string('''
    <h1>Login</h1>
    <form method="POST" action="/authorize/submit">
        <input type="hidden" name="client_id" value="{{ client_id }}">
        <input type="hidden" name="redirect_uri" value="{{ redirect_uri }}">
        <input type="hidden" name="response_type" value="{{ response_type }}">
        <input type="hidden" name="state" value="{{ state }}">
        <input type="hidden" name="scope" value="{{ scope }}">
        <p>Username: <input type="text" name="username" value="admin"></p>
        <p>Password: <input type="password" name="password" value="admin123"></p>
        <button type="submit">Login</button>
    </form>
    <p><small>Debug: Accepting any redirect_uri (VULNERABLE)</small></p>
    ''', client_id=client_id, redirect_uri=redirect_uri, response_type=response_type, state=state, scope=scope)

@app.route('/authorize/submit', methods=['POST'])
def authorize_submit():
    """Process authorization - vulnerable to open redirect"""
    username = request.form.get('username')
    password = request.form.get('password')
    client_id = request.form.get('client_id')
    redirect_uri = request.form.get('redirect_uri')
    response_type = request.form.get('response_type', 'code')
    state = request.form.get('state', '')
    scope = request.form.get('scope', 'openid')

    # Check credentials
    if username in USERS and USERS[username]['password'] == password:
        user = USERS[username]

        if response_type == 'token' or response_type == 'id_token' or 'token' in response_type:
            # Implicit flow - token in URL (vulnerable)
            token = jwt.encode({
                "sub": username,
                "email": user['email'],
                "role": user['role'],
                "scope": scope,
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
                "iss": request.host_url.rstrip('/')
            }, JWT_SECRET, algorithm="HS256")

            # Open redirect vulnerability - no validation of redirect_uri!
            return redirect(f"{redirect_uri}#access_token={token}&token_type=bearer&state={state}")

        else:
            # Authorization code flow
            code = hashlib.md5(f"{username}{time.time()}".encode()).hexdigest()
            TOKENS[code] = {
                "username": username,
                "scope": scope,
                "redirect_uri": redirect_uri,
                "created": time.time()
            }

            # Open redirect vulnerability!
            return redirect(f"{redirect_uri}?code={code}&state={state}")

    return "Invalid credentials", 401

@app.route('/token', methods=['POST'])
def token():
    """Token endpoint with vulnerabilities"""
    grant_type = request.form.get('grant_type')
    code = request.form.get('code')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    redirect_uri = request.form.get('redirect_uri')

    # Vulnerability: No client authentication required!
    # We should verify client_secret but we don't

    if grant_type == 'authorization_code':
        if code in TOKENS:
            token_data = TOKENS[code]
            username = token_data['username']
            user = USERS.get(username, {})

            # Vulnerability: Code can be reused (no single-use check)

            access_token = jwt.encode({
                "sub": username,
                "email": user.get('email'),
                "role": user.get('role'),
                "scope": token_data['scope'],
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
                "iss": request.host_url.rstrip('/')
            }, JWT_SECRET, algorithm="HS256")

            # Vulnerability: Also return 'none' algorithm token for testing
            id_token = jwt.encode({
                "sub": username,
                "email": user.get('email'),
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
            }, JWT_SECRET, algorithm="HS256")

            return jsonify({
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": 3600,
                "id_token": id_token,
                "scope": token_data['scope'],
                # Information disclosure
                "debug_info": {
                    "jwt_secret": JWT_SECRET,
                    "algorithm": "HS256",
                    "note": "none algorithm also accepted"
                }
            })

    return jsonify({"error": "invalid_grant"}), 400

@app.route('/userinfo')
def userinfo():
    """Userinfo endpoint"""
    auth = request.headers.get('Authorization', '')

    if auth.startswith('Bearer '):
        token = auth[7:]
        try:
            # Vulnerability: Accept 'none' algorithm!
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256", "none"])
            return jsonify({
                "sub": payload.get('sub'),
                "email": payload.get('email'),
                "role": payload.get('role'),
                "scope": payload.get('scope')
            })
        except jwt.InvalidTokenError as e:
            pass

    return jsonify({"error": "invalid_token"}), 401

@app.route('/debug/tokens')
def debug_tokens():
    """Debug endpoint exposing all tokens"""
    return jsonify({
        "active_codes": TOKENS,
        "jwt_secret": JWT_SECRET,
        "registered_clients": CLIENTS
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
