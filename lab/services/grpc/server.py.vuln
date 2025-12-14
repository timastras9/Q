#!/usr/bin/env python3
"""Vulnerable gRPC-like server for penetration testing training.
This is a simplified TCP server that accepts commands directly - mimics a badly configured gRPC service."""

import socket
import subprocess

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 50051))
    s.listen(5)
    print("Vulnerable gRPC-like server on port 50051")

    while True:
        conn, addr = s.accept()
        print(f"Connection from {addr}")
        try:
            data = conn.recv(4096)
            if data:
                # VULNERABILITY: Direct command execution!
                cmd = data.decode().strip()
                if cmd:
                    try:
                        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
                        conn.send(result)
                    except subprocess.CalledProcessError as e:
                        conn.send(f"Error: {e.output}".encode())
                    except Exception as e:
                        conn.send(f"Error: {str(e)}".encode())
        except Exception as e:
            print(f"Connection error: {e}")
        finally:
            conn.close()

if __name__ == "__main__":
    main()
