#!/usr/bin/env python3
"""SECURED JSON-RPC server - patched by PentestAI autofix.
No longer exposes private keys or allows command injection."""

from flask import Flask, request, jsonify
import os

app = Flask(__name__)

# SECURITY: Use environment variables for secrets (not exposed via API)
API_KEY = os.environ.get('API_KEY', 'default-dev-key')

# Public wallet data only - NO private keys!
wallets = {
    "0x1234": {"balance": "100.5 ETH"},
    "0x5678": {"balance": "50.2 ETH"},
}

def require_auth(func):
    """SECURITY: Require API key for sensitive operations."""
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('X-API-Key')
        if auth_header != API_KEY:
            return jsonify({
                "jsonrpc": "2.0",
                "error": {"code": -32600, "message": "Authentication required"},
                "id": 1
            }), 401
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

@app.route("/", methods=["POST"])
def jsonrpc():
    try:
        data = request.get_json()
        method = data.get("method", "")
        params = data.get("params", [])
        rpc_id = data.get("id", 1)

        result = None

        if method == "eth_getBalance":
            addr = params[0] if params else "0x1234"
            if addr in wallets:
                result = wallets[addr]["balance"]
            else:
                result = "0 ETH"

        elif method == "eth_accounts":
            # SECURITY: Only return public addresses
            result = list(wallets.keys())

        elif method == "personal_unlockAccount":
            # SECURITY: Disabled - never expose private keys!
            return jsonify({
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": "Method disabled for security"},
                "id": rpc_id
            })

        elif method == "debug_traceCall":
            # SECURITY: Disabled - command injection risk!
            return jsonify({
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": "Debug methods disabled in production"},
                "id": rpc_id
            })

        elif method == "admin_nodeInfo":
            # SECURITY: Only return non-sensitive info
            result = {
                "version": "1.0.0-secured",
                "secured": True,
                "message": "Admin credentials are not exposed via API"
            }

        elif method == "web3_clientVersion":
            result = "SecuredNode/v1.0.0"

        else:
            return jsonify({
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": "Method not found"},
                "id": rpc_id
            })

        return jsonify({"jsonrpc": "2.0", "result": result, "id": rpc_id})
    except Exception as e:
        return jsonify({
            "jsonrpc": "2.0",
            "error": {"code": -32000, "message": "Internal error"},
            "id": 1
        })

if __name__ == "__main__":
    print("[SECURED] JSON-RPC server running on port 8087")
    print("[SECURED] Private keys and debug methods DISABLED")
    app.run(host="0.0.0.0", port=8087)
