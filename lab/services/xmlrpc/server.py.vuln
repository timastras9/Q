#!/usr/bin/env python3
"""Vulnerable XML-RPC server for penetration testing training."""

from xmlrpc.server import SimpleXMLRPCServer
import subprocess
import os

def ping(host):
    """Command injection vulnerability - shell=True with user input!"""
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return result.stdout + result.stderr

def list_files(path):
    """Path traversal vulnerability - no sanitization!"""
    return os.listdir(path)

def get_file(path):
    """Arbitrary file read vulnerability!"""
    with open(path, "r") as f:
        return f.read()

def execute(cmd):
    """Remote Code Execution - intentionally vulnerable!"""
    return subprocess.check_output(cmd, shell=True, text=True)

def get_users():
    """Returns /etc/passwd - info disclosure"""
    return open("/etc/passwd").read()

if __name__ == "__main__":
    server = SimpleXMLRPCServer(("0.0.0.0", 8086), allow_none=True)
    server.register_function(ping, "system.ping")
    server.register_function(list_files, "system.listFiles")
    server.register_function(get_file, "system.getFile")
    server.register_function(execute, "system.execute")
    server.register_function(get_users, "system.getUsers")
    server.register_introspection_functions()
    print("XML-RPC server running on port 8086")
    server.serve_forever()
