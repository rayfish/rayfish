#!/usr/bin/env python3
"""Exercise two ordinary-user daemons through their real mesh and proxies."""

import asyncio
import base64
import collections
import json
import os
from pathlib import Path
import re
import signal
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[3]
TARGET = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
if not TARGET.is_absolute():
    TARGET = ROOT / TARGET
BINARY = Path(os.environ.get("RAY_BIN", TARGET / "debug/ray")).expanduser().resolve()
NETWORK = "proxytest"


class Failure(Exception):
    pass


async def exact(reader, length):
    return await asyncio.wait_for(reader.readexactly(length), 45)


async def headers(reader):
    return await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 45)


async def close(writer):
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 5)
    except ConnectionError:
        pass  # A rejected authentication attempt may reset its connection.


async def echo_fixture(reader, writer):
    try:
        payload = await asyncio.wait_for(reader.read(), 45)
        writer.write(payload)
        await writer.drain()
    finally:
        await close(writer)


async def http_fixture(reader, writer):
    try:
        head = await headers(reader)
        assert head.startswith(b"POST /echo?query=value HTTP/1.1\r\n")
        assert b"proxy-authorization" not in head.lower()
        length = re.search(rb"content-length: (\d+)", head.lower())
        assert length is not None
        payload = await exact(reader, int(length.group(1)))
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Length: "
            + str(len(payload)).encode()
            + b"\r\nConnection: close\r\n\r\n"
            + payload
        )
        await writer.drain()
    finally:
        await close(writer)


class Fixtures:
    def __init__(self):
        self.servers = []
        self.tasks = set()
        self.errors = []
        self.accepted = 0

    async def start(self, handler):
        async def serve(reader, writer):
            self.accepted += 1
            try:
                await handler(reader, writer)
            except Exception as error:
                self.errors.append(type(error).__name__)

        def accept(reader, writer):
            task = asyncio.create_task(serve(reader, writer))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)

        server = await asyncio.start_server(accept, "127.0.0.1", 0)
        self.servers.append(server)
        return server.sockets[0].getsockname()[1]

    async def stop(self):
        for server in self.servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in self.servers))
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)


class Daemon:
    def __init__(self, directory, label):
        self.label = label
        self.directory = Path(directory)
        self.environment = dict(os.environ, RAYFISH_ROOTLESS_DIR=str(directory), RUST_LOG="rayfish=info", NO_COLOR="1")
        self.environment.pop("RAYFISH_CONFIG_DIR", None)
        self.ready = asyncio.Event()
        self.output = collections.deque(maxlen=200)
        self.socks = None
        self.http = None
        self.process = None
        self.readers = []

    async def read_logs(self, stream, stdout):
        while line := await stream.readline():
            text = line.decode(errors="replace")
            self.output.append(text)
            if stdout and "rootless SOCKS5 listening" in text:
                self.socks = self.address(text)
            if stdout and "rootless HTTP proxy listening" in text:
                self.http = self.address(text)
            if stdout and "rootless userspace networking ready" in text:
                self.ready.set()

    @staticmethod
    def address(line):
        address = re.search(r"address=([^\s]+)", line).group(1)
        host, port = address.rsplit(":", 1)
        return host.strip("[]"), int(port)

    async def start(self, exposed=()):
        arguments = [str(BINARY), "rootless", "--http", "127.0.0.1:0"]
        for port in exposed:
            arguments.extend(["--expose", f"{port}=127.0.0.1:{port}"])
        self.process = await asyncio.create_subprocess_exec(
            *arguments, env=self.environment,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        self.readers = [
            asyncio.create_task(self.read_logs(self.process.stdout, True)),
            asyncio.create_task(self.read_logs(self.process.stderr, False)),
        ]
        ready = asyncio.create_task(self.ready.wait())
        exited = asyncio.create_task(self.process.wait())
        try:
            done, _ = await asyncio.wait([ready, exited], timeout=45, return_when=asyncio.FIRST_COMPLETED)
            if ready not in done:
                raise Failure(f"{self.label}: daemon exited or did not become ready before the deadline")
        finally:
            ready.cancel()
            exited.cancel()
            await asyncio.gather(ready, exited, return_exceptions=True)
        assert self.socks is not None and self.http is not None
        status = json.loads(await self.cli("status", "--json", automatic=True))
        assert status["rootless"] is True and status["active"] is True
        firewall = json.loads(await self.cli("firewall", "show", "--json"))
        assert firewall["disabled"] is False

    async def cli(self, *arguments, timeout=90, automatic=False):
        # Mutations must never fall back to a system daemon if this process dies.
        selection = [] if automatic else ["--rootless"]
        process = await asyncio.create_subprocess_exec(
            str(BINARY), *selection, *arguments, env=self.environment,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
        except BaseException:
            if process.returncode is None:
                process.kill()
            await process.wait()
            raise
        if process.returncode:
            self.output.append(stderr.decode(errors="replace"))
            raise Failure(f"{self.label}: ray {arguments[0]} failed with exit {process.returncode}")
        return stdout.decode()

    @property
    def password(self):
        return (self.directory / "proxy-password").read_bytes()

    @property
    def authorization(self):
        return b"Proxy-Authorization: Basic " + base64.b64encode(b"ray:" + self.password) + b"\r\n"

    def diagnostics(self):
        # Raw logs can contain identities and addresses. Print only error categories.
        markers = ["WARN", "ERROR", "panicked", "timed out", "connection refused", "firewall denied"]
        counts = ", ".join(f"{marker}={sum(marker in line for line in self.output)}" for marker in markers)
        code = self.process.returncode if self.process else "not started"
        print(f"  {self.label}: ready={self.ready.is_set()}, exit={code}, {counts}", file=sys.stderr)

    async def stop(self):
        if self.process is None:
            return
        failure = None
        if self.process.returncode is None:
            try:
                await self.cli("stop", timeout=10)
                await asyncio.wait_for(self.process.wait(), 20)
            except BaseException as error:
                failure = error
                if self.process.returncode is None:
                    self.process.send_signal(signal.SIGINT)
                    try:
                        await asyncio.wait_for(self.process.wait(), 10)
                    except asyncio.TimeoutError:
                        self.process.kill()
                        await self.process.wait()
        await asyncio.gather(*self.readers)
        if failure:
            raise failure
        assert self.process.returncode == 0
        assert not (self.directory / "run/rayfish.sock").exists()


async def check_authentication(client):
    # No network exists yet. Missing credentials must fail before mesh lookup/dial.
    for auth in [b"", b"Proxy-Authorization: Basic cmF5Ondyb25n\r\n"]:
        reader, writer = await asyncio.open_connection(*client.http)
        try:
            writer.write(b"GET http://unjoined.proxytest.ray/ HTTP/1.1\r\nHost: unjoined.proxytest.ray\r\n" + auth + b"\r\n")
            await writer.drain()
            assert (await headers(reader)).startswith(b"HTTP/1.1 407")
        finally:
            await close(writer)
    reader, writer = await asyncio.open_connection(*client.socks)
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        assert await exact(reader, 2) == b"\x05\xff"
    finally:
        await close(writer)
    reader, writer = await asyncio.open_connection(*client.socks)
    try:
        writer.write(b"\x05\x01\x02")
        await writer.drain()
        assert await exact(reader, 2) == b"\x05\x02"
        writer.write(b"\x01\x03ray\x05wrong")
        await writer.drain()
        assert await exact(reader, 2) == b"\x01\x01"
    finally:
        await close(writer)


async def check_http(client, host, port):
    reader, writer = await asyncio.open_connection(*client.http)
    payload = b"rootless streamed HTTP body\n" * 8192
    try:
        writer.write(
            f"POST http://{host}:{port}/echo?query=value HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n".encode()
            + client.authorization + b"\r\n" + payload
        )
        await writer.drain()
        response = await headers(reader)
        assert response.startswith(b"HTTP/1.1 200"), response.split(b"\r\n", 1)[0]
        assert await exact(reader, len(payload)) == payload
        assert await asyncio.wait_for(reader.read(), 45) == b""
    finally:
        await close(writer)


async def check_socks(client, host, port):
    reader, writer = await asyncio.open_connection(*client.socks)
    try:
        writer.write(b"\x05\x01\x02")
        await writer.drain()
        assert await exact(reader, 2) == b"\x05\x02"
        writer.write(b"\x01\x03ray" + bytes([len(client.password)]) + client.password)
        await writer.drain()
        assert await exact(reader, 2) == b"\x01\x00"
        domain = host.encode()
        writer.write(b"\x05\x01\x00\x03" + bytes([len(domain)]) + domain + port.to_bytes(2, "big"))
        await writer.drain()
        response = await exact(reader, 22)
        assert response[:4] == b"\x05\x00\x00\x04", response[:4]
        payload = b"rootless SOCKS echo\n" * 8192
        writer.write(payload)
        await writer.drain()
        writer.write_eof()
        assert await exact(reader, len(payload)) == payload
        assert await asyncio.wait_for(reader.read(), 45) == b""
    finally:
        await close(writer)


async def check_connect(client, host, port):
    reader, writer = await asyncio.open_connection(*client.http)
    payload = b"\x16\x03\x03rootless opaque tunnel bytes\n" * 4096
    try:
        writer.write(
            f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n".encode()
            + client.authorization + b"\r\n" + payload
        )
        await writer.drain()
        response = await headers(reader)
        assert response.startswith(b"HTTP/1.1 200"), response.split(b"\r\n", 1)[0]
        writer.write_eof()
        assert await exact(reader, len(payload)) == payload
        assert await asyncio.wait_for(reader.read(), 45) == b""
    finally:
        await close(writer)


async def main():
    fixtures = Fixtures()
    stage = "startup"
    with tempfile.TemporaryDirectory(prefix="ray-rootless-e2e-") as directory:
        server = Daemon(Path(directory) / "server", "server")
        client = Daemon(Path(directory) / "client", "client")
        failure = None
        try:
            http_port = await fixtures.start(http_fixture)
            echo_port = await fixtures.start(echo_fixture)
            await server.start((http_port, echo_port))
            await client.start()
            print("PASS: private daemons, automatic IPC and enabled firewalls", flush=True)
            stage = "authentication before network join"
            await check_authentication(client)
            assert fixtures.accepted == 0
            print("PASS: missing and incorrect proxy credentials are rejected", flush=True)
            stage = "create, invite and join"
            await server.cli("create", "--name", NETWORK, "--hostname", "server")
            await server.cli("firewall", "add", "in", "allow", "--proto", "tcp", "--port", f"{http_port},{echo_port}", "--network", NETWORK)
            invite = await server.cli("invite", NETWORK)
            invite = re.sub(r"\x1b\[[0-9;]*m", "", invite)
            code = re.search(r"ray join (\S+)", invite).group(1)
            await client.cli("join", code, "--name", NETWORK, "--hostname", "client")
            print("PASS: private network creation and invite join", flush=True)
            host = f"server.{NETWORK}.ray"
            stage = "HTTP streaming"
            await check_http(client, host, http_port)
            print("PASS: authenticated HTTP streaming over the mesh", flush=True)
            stage = "SOCKS half-close"
            await check_socks(client, host, echo_port)
            print("PASS: authenticated SOCKS5 domain resolution, streaming and half-close", flush=True)
            stage = "CONNECT half-close"
            await check_connect(client, host, echo_port)
            print("PASS: authenticated CONNECT with early tunnel bytes and half-close", flush=True)
            assert not fixtures.errors
        except BaseException as error:
            failure = error
        finally:
            stopped = await asyncio.gather(client.stop(), server.stop(), return_exceptions=True)
            await fixtures.stop()
        if failure or any(isinstance(result, BaseException) for result in stopped):
            print(f"FAIL: {stage} ({type(failure).__name__ if failure else 'shutdown'})", file=sys.stderr)
            server.diagnostics()
            client.diagnostics()
            print(f"  fixtures: accepted={fixtures.accepted}, errors={fixtures.errors}", file=sys.stderr)
            raise failure or Failure("daemon shutdown failed")
        print("PASS: both daemons stopped and removed private IPC sockets", flush=True)


if __name__ == "__main__":
    try:
        if sys.platform != "linux":
            raise Failure("rootless E2E requires Linux")
        if os.geteuid() == 0:
            raise Failure("rootless E2E must run as an ordinary user, without sudo")
        if not BINARY.is_file() or not os.access(BINARY, os.X_OK):
            raise Failure("ray binary missing: run cargo -q build, or set RAY_BIN")
        asyncio.run(asyncio.wait_for(main(), 300))
    except Exception as error:
        print(f"FAIL: {error if isinstance(error, Failure) else type(error).__name__}", file=sys.stderr)
        raise SystemExit(1)
