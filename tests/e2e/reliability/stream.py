#!/usr/bin/env python3
"""Exercise mixed WebSocket bursts over one TCP connection."""

import argparse
import base64
import hashlib
import json
import socket
import struct
import sys
import time

PORT = 38923
ROUNDS = 50
SMALL_MESSAGES = 2100
LARGE_SIZES = (512, 1000, 120_000, 150_000, 1_048_576)
TIMEOUT = 10
KEY = b"dGhlIHNhbXBsZSBub25jZQ=="
ACCEPT = base64.b64encode(
    hashlib.sha1(KEY + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()
)


def read_exact(sock, length):
    parts = []
    while length:
        part = sock.recv(length)
        if not part:
            raise EOFError("connection closed before the transfer completed")
        parts.append(part)
        length -= len(part)
    return b"".join(parts)


def read_headers(sock):
    result = bytearray()
    while not result.endswith(b"\r\n\r\n"):
        if len(result) >= 8192:
            raise ValueError("WebSocket headers exceed 8192 bytes")
        result.extend(read_exact(sock, 1))
    return bytes(result)


def frame(payload, opcode=2):
    length = len(payload)
    if length < 126:
        size = bytes([length])
    elif length < 65536:
        size = b"\x7e" + struct.pack("!H", length)
    else:
        size = b"\x7f" + struct.pack("!Q", length)
    return bytes([0x80 | opcode]) + size + payload


def read_frame(sock):
    first, second = read_exact(sock, 2)
    if second & 0x80:
        raise ValueError("server frames must not be masked")
    length = second & 0x7f
    if length == 126:
        length = struct.unpack("!H", read_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", read_exact(sock, 8))[0]
    if length > max(LARGE_SIZES):
        raise ValueError("frame exceeds the test's maximum size")
    return first & 0x0f, read_exact(sock, length)


def messages():
    sequence = 0
    for _ in range(ROUNDS):
        for size in (64,) * SMALL_MESSAGES + LARGE_SIZES:
            fill = b"x" if size == 64 else b"z"
            yield struct.pack("!I", sequence) + fill * (size - 4)
            sequence += 1


def server(address):
    with socket.socket(socket.AF_INET6) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((address, PORT))
        listener.listen(1)
        listener.settimeout(60)
        with listener.accept()[0] as sock:
            sock.settimeout(TIMEOUT)
            request = read_headers(sock)
            if b"Sec-WebSocket-Key: " + KEY not in request:
                raise ValueError("missing WebSocket key")
            sock.sendall(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + ACCEPT + b"\r\n\r\n"
            )
            for payload in messages():
                sock.sendall(frame(payload))
            sock.sendall(frame(b"", 8))


def client(address, stall_ms=100):
    start = time.monotonic()
    count = total = 0
    waits = []
    error = None
    try:
        with socket.socket(socket.AF_INET6) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect((address, PORT))
            sock.sendall(
                b"GET / HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\n"
                b"Connection: Upgrade\r\nSec-WebSocket-Key: " + KEY
                + b"\r\nSec-WebSocket-Version: 13\r\n\r\n"
            )
            response = read_headers(sock)
            if b"101 Switching Protocols" not in response or ACCEPT not in response:
                raise ValueError("WebSocket upgrade failed")
            for expected in messages():
                frame_start = time.monotonic()
                try:
                    opcode, payload = read_frame(sock)
                finally:
                    waits.append((time.monotonic() - frame_start) * 1000)
                if opcode != 2 or payload != expected:
                    raise ValueError(f"incorrect frame {count}")
                count += 1
                total += len(payload)
            opcode, payload = read_frame(sock)
            if opcode != 8 or payload:
                raise ValueError("missing WebSocket close frame")
    except (OSError, EOFError, ValueError) as exc:
        error = str(exc)
    print(json.dumps({
        "frames": count,
        "bytes": total,
        "seconds": round(time.monotonic() - start, 3),
        "stall_threshold_ms": stall_ms,
        "stalls": sum(wait >= stall_ms for wait in waits),
        "best_frame_wait_ms": round(min(waits), 3) if waits else None,
        "worst_frame_wait_ms": round(max(waits), 3) if waits else None,
        "error": error,
    }), flush=True)
    return error is None


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=("server", "client"))
    parser.add_argument("address")
    parser.add_argument("--stall-ms", type=float, default=100,
                        help="report frame reads taking at least this many milliseconds")
    args = parser.parse_args()
    if args.role == "server":
        server(args.address)
    else:
        sys.exit(0 if client(args.address, args.stall_ms) else 1)
