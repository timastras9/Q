#!/usr/bin/env python3
"""Vulnerable JSON-RPC server simulating Ethereum/Web3 node for penetration testing."""

from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

# Fake wallet data with exposed private keys
wallets = {
    "0x1234": {"balance": "100.5 ETH", "private_key": "0xdeadbeef1234567890abcdef"},
    "0x5678": {"balance": "50.2 ETH", "private_key": "0xcafebabe0987654321fedcba"},
    "admin": {"balance": "1000 ETH", "private_key": "0xadmin_super_secret_key_do_not_share"}
}

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
            result = list(wallets.keys())

        elif method == "personal_unlockAccount":
            # VULNERABILITY: Exposes private keys!
            addr = params[0] if params else "0x1234"
            if addr in wallets:
                result = {"unlocked": True, "private_key": wallets[addr]["private_key"]}

        elif method == "debug_traceCall":
            # VULNERABILITY: Command injection in debug mode!
            cmd = params[0] if params else "id"
            result = subprocess.check_output(cmd, shell=True, text=True)

        elif method == "admin_nodeInfo":
            # VULNERABILITY: Exposes admin credentials!
            result = {
                "version": "1.0.0",
                "admin_password": "admin123",
                "rpc_secret": "super_secret_rpc_token_xyz789"
            }

        elif method == "web3_clientVersion":
            result = "VulnerableNode/v1.0.0"

        else:
            return jsonify({"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": rpc_id})

        return jsonify({"jsonrpc": "2.0", "result": result, "id": rpc_id})
    except Exception as e:
        return jsonify({"jsonrpc": "2.0", "error": {"code": -32000, "message": str(e)}, "id": 1})

if __name__ == "__main__":
    print("JSON-RPC server running on port 8087")
    app.run(host="0.0.0.0", port=8087)
