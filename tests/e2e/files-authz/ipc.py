#!/usr/bin/env python3
"""Send one hand-built request to the local rayfish daemon and print its reply.

    ipc.py <Variant> [key=value ...] [--fd PATH]

Builds the frame the ray CLI would (a 4-byte big-endian length, then a msgpack
map {Variant: {key: value}}, the shape `rmp_serde::to_vec_named` gives an
externally tagged enum) so the scenario can send requests the CLI never makes:
a path send from a non-root user, an internal frame, a chosen file name.
`--fd PATH` opens PATH as the calling user and attaches the descriptor as
SCM_RIGHTS, the way `ray send` does.

Prints the reply as JSON. Exits 0 for Ok, 1 for Error, 2 for anything else.
Standard library only: the node image has python3 and nothing more.
"""
import array
import json
import os
import socket
import struct
import sys

SOCKET = os.environ.get("RAY_IPC_SOCKET", "/var/run/rayfish/rayfish.sock")


def pack(value):
    if isinstance(value, bool):
        return b"\xc3" if value else b"\xc2"
    if isinstance(value, int):
        if 0 <= value < 128:
            return bytes([value])
        return b"\xcf" + struct.pack(">Q", value)
    if isinstance(value, str):
        raw = value.encode("utf-8", "surrogateescape")
        n = len(raw)
        if n < 32:
            return bytes([0xA0 | n]) + raw
        if n < 256:
            return b"\xd9" + bytes([n]) + raw
        return b"\xda" + struct.pack(">H", n) + raw
    if isinstance(value, dict):
        n = len(value)
        out = bytes([0x80 | n]) if n < 16 else b"\xde" + struct.pack(">H", n)
        for key, item in value.items():
            out += pack(key) + pack(item)
        return out
    raise TypeError(f"cannot pack {type(value).__name__}")


class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, n):
        chunk = self.data[self.pos:self.pos + n]
        if len(chunk) != n:
            raise ValueError("truncated msgpack")
        self.pos += n
        return chunk

    def num(self, fmt):
        return struct.unpack(fmt, self.take(struct.calcsize(fmt)))[0]

    def read(self):
        b = self.take(1)[0]
        if b < 0x80:
            return b
        if b >= 0xE0:
            return b - 0x100
        if 0x80 <= b <= 0x8F:
            return self.map(b & 0x0F)
        if 0x90 <= b <= 0x9F:
            return self.array(b & 0x0F)
        if 0xA0 <= b <= 0xBF:
            return self.text(b & 0x1F)
        simple = {0xC0: None, 0xC2: False, 0xC3: True}
        if b in simple:
            return simple[b]
        sized = {
            0xC4: ("bytes", ">B"), 0xC5: ("bytes", ">H"), 0xC6: ("bytes", ">I"),
            0xD9: ("text", ">B"), 0xDA: ("text", ">H"), 0xDB: ("text", ">I"),
            0xDC: ("array", ">H"), 0xDD: ("array", ">I"),
            0xDE: ("map", ">H"), 0xDF: ("map", ">I"),
        }
        if b in sized:
            kind, fmt = sized[b]
            n = self.num(fmt)
            if kind == "bytes":
                return self.take(n).hex()
            return getattr(self, kind)(n)
        scalars = {
            0xCA: ">f", 0xCB: ">d", 0xCC: ">B", 0xCD: ">H", 0xCE: ">I",
            0xCF: ">Q", 0xD0: ">b", 0xD1: ">h", 0xD2: ">i", 0xD3: ">q",
        }
        if b in scalars:
            return self.num(scalars[b])
        raise ValueError(f"unsupported msgpack byte 0x{b:02x}")

    def text(self, n):
        return self.take(n).decode("utf-8", "replace")

    def array(self, n):
        return [self.read() for _ in range(n)]

    def map(self, n):
        out = {}
        for _ in range(n):
            key = self.read()
            out[str(key)] = self.read()
        return out


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("daemon closed the connection without a reply")
        buf += chunk
    return buf


def main(argv):
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    variant, fields, fd_path = argv[0], {}, None
    rest = argv[1:]
    while rest:
        arg = rest.pop(0)
        if arg == "--fd":
            fd_path = rest.pop(0)
            continue
        key, _, value = arg.partition("=")
        fields[key] = value
    body = pack({variant: fields}) if fields else pack(variant)
    frame = struct.pack(">I", len(body)) + body

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(60)
    sock.connect(SOCKET)
    if fd_path is not None:
        fd = os.open(fd_path, os.O_RDONLY)
        sock.sendmsg([frame], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))])
        os.close(fd)
    else:
        sock.sendall(frame)
    length = struct.unpack(">I", recv_exact(sock, 4))[0]
    reply = Reader(recv_exact(sock, length)).read()
    print(json.dumps(reply))
    if isinstance(reply, dict) and "Ok" in reply:
        return 0
    if isinstance(reply, dict) and "Error" in reply:
        return 1
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception as error:  # the scenario reads the message, not a traceback
        print(json.dumps({"HelperError": str(error)}))
        sys.exit(3)
