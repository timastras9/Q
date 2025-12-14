#!/usr/bin/env python3
"""SECURED XML-RPC server - patched by PentestAI autofix."""

from xmlrpc.server import SimpleXMLRPCServer
import subprocess
import os
import re

# SECURITY: Allowlist of safe commands
ALLOWED_COMMANDS = ['status', 'health', 'version', 'uptime']

def ping(host):
    """SECURED: Validates IP format before ping."""
    # Only allow valid IP addresses
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host):
        return "Error: Invalid IP address format"
    # Use list form instead of shell=True
    try:
        result = subprocess.run(['ping', '-c', '1', host], capture_output=True, text=True, timeout=5)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "Error: Ping timeout"
    except Exception as e:
        return f"Error: {str(e)}"

def list_files(path):
    """SECURED: Only allows listing specific directories."""
    # Allowlist of safe directories
    allowed_dirs = ['/tmp', '/var/log']
    real_path = os.path.realpath(path)
    if not any(real_path.startswith(d) for d in allowed_dirs):
        return "Error: Access denied - directory not in allowlist"
    return os.listdir(path)

def get_file(path):
    """SECURED: Removed - arbitrary file read is too dangerous."""
    return "Error: This method has been disabled for security reasons"

def execute(cmd):
    """SECURED: Only allows safe, pre-defined commands."""
    if cmd not in ALLOWED_COMMANDS:
        return f"Error: Command '{cmd}' not allowed. Allowed: {ALLOWED_COMMANDS}"

    if cmd == 'status':
        return "Service status: OK"
    elif cmd == 'health':
        return "Health: HEALTHY"
    elif cmd == 'version':
        return "Version: 1.0.0-secured"
    elif cmd == 'uptime':
        try:
            result = subprocess.run(['uptime'], capture_output=True, text=True, timeout=5)
            return result.stdout
        except:
            return "Uptime: unavailable"
    return "Unknown command"

def get_users():
    """SECURED: Returns only non-sensitive user info."""
    return "Error: This method has been disabled for security reasons"

if __name__ == "__main__":
    server = SimpleXMLRPCServer(("0.0.0.0", 8086), allow_none=True)
    server.register_function(ping, "system.ping")
    server.register_function(list_files, "system.listFiles")
    server.register_function(get_file, "system.getFile")
    server.register_function(execute, "system.execute")
    server.register_function(get_users, "system.getUsers")
    server.register_introspection_functions()
    print("[SECURED] XML-RPC server running on port 8086")
    server.serve_forever()
