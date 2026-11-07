#!/usr/bin/env python3
"""Simulated weak services for the team's hotspot lab.

Every service here is a fake. It sends just enough of a real banner or
protocol reply for `nmap -sV` to label it with the finding catalog's service
name (MASTERPLAN §3.2 "simulate, do not expose", §4.1). Nothing is behind them:

* no login ever succeeds, and client input is never executed, stored or logged;
* every connection has a byte budget, an idle timeout and a session timeout;
* the number of simultaneous connections per service is capped;
* the UDP (SSDP) responder only answers private source addresses, rate-limited.

Usage:
    fakesvc.py SERVICE [SERVICE ...] --bind ADDRESS [--port PORT]

Services: telnet, ftp, http, rtsp, redis, mqtt, jetdirect (TCP), ssdp (UDP).
Standard library only, Python 3.11+ (Raspberry Pi OS bookworm ships 3.11).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import html
import ipaddress
import logging
import re
import signal
import socket
import sys
import time
import uuid
from email.utils import formatdate

READ_LIMIT = 4096  # bytes read per connection before we hang up
IDLE_TIMEOUT = 10.0  # seconds without data before we hang up
SESSION_TIMEOUT = 60.0  # hard cap on one connection
MAX_CONNECTIONS = 32  # simultaneous connections per service
UDP_MAX_PACKET = 2048
UDP_MAX_REPLIES_PER_SECOND = 10

log = logging.getLogger("fakesvc")


class Hangup(Exception):
    """Ends a session: read budget used up, timeout, client gone or bad input."""


class Session:
    """One TCP connection, with a read budget and timeouts on every read."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.budget = READ_LIMIT

    def _spend(self, data: bytes) -> bytes:
        if not data:
            raise Hangup("client closed")
        self.budget -= len(data)
        if self.budget < 0:
            raise Hangup("read limit reached")
        return data

    async def _wait(self, coro):
        try:
            return await asyncio.wait_for(coro, IDLE_TIMEOUT)
        except TimeoutError as exc:
            raise Hangup("idle timeout") from exc

    async def read(self, n: int = 1024) -> bytes:
        return self._spend(await self._wait(self.reader.read(max(1, min(n, self.budget + 1)))))

    async def readline(self) -> bytes:
        try:
            data = await self._wait(self.reader.readline())
        except (ValueError, asyncio.LimitOverrunError) as exc:
            raise Hangup("line too long") from exc
        return self._spend(data)

    async def read_head(self) -> bytes:
        """Read an HTTP/RTSP request head, up to and including the blank line."""
        try:
            data = await self._wait(self.reader.readuntil(b"\r\n\r\n"))
        except asyncio.IncompleteReadError as exc:
            data = exc.partial
        except asyncio.LimitOverrunError as exc:
            raise Hangup("request head too long") from exc
        return self._spend(data)

    async def send(self, data: bytes) -> None:
        self.writer.write(data)
        await self._wait(self.writer.drain())


# --- telnet ---------------------------------------------------------------

# BusyBox telnetd's opening negotiation: DO ECHO, DO NAWS, WILL ECHO, WILL SGA.
TELNET_HELLO = bytes([255, 253, 1, 255, 253, 31, 255, 251, 1, 255, 251, 3])
TELNET_IAC = re.compile(rb"\xff(?:[\xfb-\xfe].|\xfa.*?\xff\xf0|[\xf0-\xfa])", re.S)


async def telnet(s: Session) -> None:
    await s.send(TELNET_HELLO)
    # nmap's NULL probe sends nothing, so it sees only the negotiation bytes.
    # A real client answers the negotiation; only then do we show a prompt.
    await s.read()
    await s.send(b"\r\n(none) login: ")
    for _ in range(3):
        await s.readline()
        await s.send(b"Password: ")
        await s.readline()
        await asyncio.sleep(1)
        await s.send(b"\r\nLogin incorrect\r\n(none) login: ")


# --- ftp ------------------------------------------------------------------


async def ftp(s: Session) -> None:
    await s.send(b"220 (vsFTPd 2.3.4)\r\n")
    while True:
        line = await s.readline()
        cmd = line.strip().split(b" ", 1)[0].upper()
        if cmd == b"USER":
            await s.send(b"331 Please specify the password.\r\n")
        elif cmd == b"PASS":
            await asyncio.sleep(1)
            await s.send(b"530 Login incorrect.\r\n")
        elif cmd == b"QUIT":
            await s.send(b"221 Goodbye.\r\n")
            return
        elif cmd == b"SYST":
            await s.send(b"215 UNIX Type: L8\r\n")
        elif cmd == b"FEAT":
            await s.send(b"211-Features:\r\n EPSV\r\n PASV\r\n SIZE\r\n UTF8\r\n211 End\r\n")
        elif cmd == b"NOOP":
            await s.send(b"200 NOOP ok.\r\n")
        else:
            await s.send(b"530 Please login with USER and PASS.\r\n")


# --- http -----------------------------------------------------------------

HTTP_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>{title}</title></head>
<body><h1>{title}</h1>
<p>{message}</p>
<form method="post" action="/">
<label>User <input name="user"></label>
<label>Password <input name="password" type="password"></label>
<button>Sign in</button>
</form></body></html>
"""


def make_http(title: str):
    safe_title = html.escape(title)

    async def http(s: Session) -> None:
        head = await s.read_head()
        request = head.split(b"\r\n", 1)[0].split()
        if len(request) != 3 or not request[2].startswith(b"HTTP/"):
            body = b"Bad Request\n"
            status = b"400 Bad Request"
        elif request[0] in (b"GET", b"HEAD"):
            body = HTTP_PAGE.format(title=safe_title, message="Please sign in.").encode()
            status = b"200 OK"
        else:
            # Never read or check what was posted: every sign-in fails.
            body = HTTP_PAGE.format(
                title=safe_title, message="Wrong user name or password."
            ).encode()
            status = b"401 Unauthorized"
        headers = (
            b"HTTP/1.1 " + status + b"\r\n"
            b"Server: lighttpd/1.4.59\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n"
        )
        await s.send(headers if request[:1] == [b"HEAD"] else headers + body)

    return http


# --- rtsp -----------------------------------------------------------------


async def rtsp(s: Session) -> None:
    while True:
        head = await s.read_head()
        lines = head.decode("latin-1").split("\r\n")
        request = lines[0].split()
        cseq = "0"
        for line in lines[1:]:
            name, _, value = line.partition(":")
            if name.strip().lower() == "cseq" and re.fullmatch(r"\d{1,9}", value.strip()):
                cseq = value.strip()
        reply = f"CSeq: {cseq}\r\nServer: GStreamer RTSP server\r\n"
        if len(request) != 3 or not request[2].startswith("RTSP/"):
            await s.send(f"RTSP/1.0 400 Bad Request\r\n{reply}\r\n".encode())
            return
        if request[0] == "OPTIONS":
            reply = (
                "RTSP/1.0 200 OK\r\n"
                + reply
                + "Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN\r\n\r\n"
            )
        elif request[0] in ("DESCRIBE", "SETUP", "PLAY"):
            # There is no stream: every request needs credentials that don't exist.
            reply = (
                "RTSP/1.0 401 Unauthorized\r\n"
                + reply
                + 'WWW-Authenticate: Basic realm="camera"\r\n\r\n'
            )
        else:
            reply = "RTSP/1.0 405 Method Not Allowed\r\n" + reply + "\r\n"
        await s.send(reply.encode())


# --- redis ----------------------------------------------------------------


async def redis(s: Session) -> None:
    while True:
        data = await s.read()
        if b"QUIT" in data.upper()[:32]:
            await s.send(b"+OK\r\n")
            return
        # Older Redis with requirepass answers this to everything before AUTH.
        # nmap -sV recognises it as redis; it doesn't match the newer "-NOAUTH".
        await s.send(b"-ERR operation not permitted\r\n")


# --- mqtt -----------------------------------------------------------------


async def mqtt(s: Session) -> None:
    data = await s.read(512)
    if data[0] >> 4 != 1:  # not a CONNECT packet
        return
    level = 4
    for name in (b"\x00\x04MQTT", b"\x00\x06MQIsdp"):
        at = data.find(name)
        if at != -1 and at + len(name) < len(data):
            level = data[at + len(name)]
            break
    if level == 5:
        await s.send(b"\x20\x03\x00\x87\x00")  # CONNACK: not authorized (MQTT 5)
    else:
        await s.send(b"\x20\x02\x00\x05")  # CONNACK: not authorized (MQTT 3.1/3.1.1)


# --- jetdirect (raw printing, PJL) ----------------------------------------

PJL_ID = b'@PJL INFO ID\r\n"LAB LASER PRINTER"\r\n\x0c'
PJL_STATUS = b'@PJL INFO STATUS\r\nCODE=10001\r\nDISPLAY="READY"\r\nONLINE=TRUE\r\n\x0c'


async def jetdirect(s: Session) -> None:
    while True:
        data = await s.read()
        # Print data is thrown away; only PJL info requests get an answer.
        if b"@PJL INFO ID" in data:
            await s.send(PJL_ID)
        elif b"@PJL INFO STATUS" in data:
            await s.send(PJL_STATUS)


# --- ssdp / upnp (UDP) ----------------------------------------------------

SSDP_UUID = uuid.uuid5(uuid.NAMESPACE_URL, "lab-smart-hub")


def _local_ip_for(peer: str) -> str:
    with contextlib.suppress(OSError), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((peer, 1900))
        return probe.getsockname()[0]
    return "0.0.0.0"  # noqa: S104 (a URL fallback, not a bind address)


def ssdp_reply(peer_ip: str) -> bytes:
    return (
        "HTTP/1.1 200 OK\r\n"
        "CACHE-CONTROL: max-age=1800\r\n"
        f"DATE: {formatdate(usegmt=True)}\r\n"
        "EXT:\r\n"
        f"LOCATION: http://{_local_ip_for(peer_ip)}:5000/rootDesc.xml\r\n"
        "SERVER: Linux/5.10 UPnP/1.0 MiniUPnPd/2.1\r\n"
        "ST: upnp:rootdevice\r\n"
        f"USN: uuid:{SSDP_UUID}::upnp:rootdevice\r\n\r\n"
    ).encode()


class SsdpResponder(asyncio.DatagramProtocol):
    """Answers unicast M-SEARCH from private addresses only, with a rate limit."""

    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self.window = 0.0
        self.replies = 0

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        if len(data) > UDP_MAX_PACKET or not data.startswith(b"M-SEARCH"):
            return
        try:
            peer = ipaddress.ip_address(addr[0])
        except ValueError:
            return
        if not peer.is_private or peer.is_multicast or peer.is_unspecified:
            return
        now = time.monotonic()
        if now - self.window >= 1.0:
            self.window, self.replies = now, 0
        if self.replies >= UDP_MAX_REPLIES_PER_SECOND:
            return
        self.replies += 1
        self.transport.sendto(ssdp_reply(addr[0]), addr)


# --- runner ---------------------------------------------------------------

TCP_SERVICES = {
    "telnet": 2323,
    "ftp": 21,
    "http": 80,
    "rtsp": 554,
    "redis": 6379,
    "mqtt": 1883,
    "jetdirect": 9100,
}
UDP_SERVICES = {"ssdp": 1900}
ALL_SERVICES = {**TCP_SERVICES, **UDP_SERVICES}


def tcp_handler(name: str, http_title: str):
    if name == "http":
        return make_http(http_title)
    return {
        "telnet": telnet,
        "ftp": ftp,
        "rtsp": rtsp,
        "redis": redis,
        "mqtt": mqtt,
        "jetdirect": jetdirect,
    }[name]


def _client_callback(name: str, handler):
    active = 0

    async def on_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal active
        if active >= MAX_CONNECTIONS:
            writer.close()
            return
        active += 1
        peer = writer.get_extra_info("peername")
        log.info("%s: connection from %s", name, peer[0] if peer else "?")
        try:
            async with asyncio.timeout(SESSION_TIMEOUT):
                await handler(Session(reader, writer))
        except (Hangup, TimeoutError, ConnectionError, OSError):
            pass
        except Exception:  # a bug must never take the whole service down
            log.exception("%s: handler error", name)
        finally:
            active -= 1
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    return on_client


async def start_service(
    name: str, bind: str, port: int | None = None, http_title: str = "Camera Login"
):
    """Start one fake service. Returns the asyncio server (TCP) or transport (UDP)."""
    port = ALL_SERVICES[name] if port is None else port
    if name in UDP_SERVICES:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(SsdpResponder, local_addr=(bind, port))
        return transport
    return await asyncio.start_server(
        _client_callback(name, tcp_handler(name, http_title)),
        host=bind,
        port=port,
        limit=READ_LIMIT,
    )


async def run(services: list[str], bind: str, port: int | None, http_title: str) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)
    started = []
    for name in services:
        started.append(await start_service(name, bind, port, http_title))
        proto = "udp" if name in UDP_SERVICES else "tcp"
        log.info(
            "%s: listening on %s:%s/%s (simulated)", name, bind, port or ALL_SERVICES[name], proto
        )
    await stop.wait()
    for item in started:
        item.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Simulated weak services for the hotspot lab.")
    parser.add_argument(
        "services",
        nargs="+",
        choices=sorted(ALL_SERVICES),
        metavar="SERVICE",
        help="one or more of: " + ", ".join(sorted(ALL_SERVICES)),
    )
    parser.add_argument("--bind", required=True, help="address to listen on (required, no default)")
    parser.add_argument("--port", type=int, help="override the port (only with a single service)")
    parser.add_argument(
        "--http-title", default="Camera Login", help="page title for the http service"
    )
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args(argv)
    if args.port is not None and len(args.services) != 1:
        parser.error("--port works with exactly one service")
    if len(set(args.services)) != len(args.services):
        parser.error("a service is listed twice")
    logging.basicConfig(
        level=args.log_level.upper(), format="%(asctime)s %(levelname)s %(message)s"
    )
    try:
        asyncio.run(run(args.services, args.bind, args.port, args.http_title))
    except OSError as exc:
        log.error("cannot start: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
