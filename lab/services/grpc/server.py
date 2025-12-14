#!/usr/bin/env python3
"""SECURED gRPC-like server - patched by PentestAI autofix.
No longer executes arbitrary commands."""

import socket
import os

# SECURITY: Allowlist of safe commands
ALLOWED_COMMANDS = {
    'status': 'Service status: OK',
    'health': 'Health: HEALTHY',
    'version': 'Version: 1.0.0-secured',
    'help': 'Available commands: status, health, version, help',
}

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 50051))
    s.listen(5)
    print("[SECURED] gRPC-like server on port 50051")
    print("[SECURED] Command execution DISABLED - only safe commands allowed")

    while True:
        conn, addr = s.accept()
        print(f"Connection from {addr}")
        try:
            data = conn.recv(4096)
            if data:
                cmd = data.decode().strip().lower()

                # SECURITY: Only allow pre-defined safe commands
                if cmd in ALLOWED_COMMANDS:
                    response = ALLOWED_COMMANDS[cmd]
                else:
                    response = f"Error: Command '{cmd}' not allowed. Type 'help' for available commands."

                conn.send(response.encode() + b'\n')
        except Exception as e:
            print(f"Connection error: {e}")
        finally:
            conn.close()

if __name__ == "__main__":
    main()
