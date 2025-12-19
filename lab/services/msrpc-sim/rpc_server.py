#!/usr/bin/env python3
"""MS-RPC Endpoint Mapper simulation"""

import socket
import struct
import os

# Simple DCE/RPC endpoint mapper simulation
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 135))
s.listen(5)
print("MS-RPC Endpoint Mapper simulation on port 135")

# Fake RPC endpoints
endpoints = [
    {"uuid": "e1af8308-5d1f-11c9-91a4-08002b14a0fa", "name": "EPM", "version": "3.0"},
    {"uuid": "12345778-1234-abcd-ef00-0123456789ab", "name": "LSARPC", "version": "0.0"},
    {"uuid": "12345678-1234-abcd-ef00-0123456789ac", "name": "SAMR", "version": "1.0"},
    {"uuid": "367abb81-9844-35f1-ad32-98f038001003", "name": "SVCCTL", "version": "2.0"},
    {"uuid": "338cd001-2244-31f1-aaaa-900038001003", "name": "WINREG", "version": "1.0"},
    {"uuid": "4b324fc8-1670-01d3-1278-5a47bf6ee188", "name": "SRVSVC", "version": "3.0"},
]

while True:
    try:
        conn, addr = s.accept()
        data = conn.recv(4096)
        # Return fake endpoint list
        response = "\n".join([f"{e['uuid']}: {e['name']} v{e['version']}" for e in endpoints])
        conn.send(response.encode())
        conn.close()
    except:
        pass
