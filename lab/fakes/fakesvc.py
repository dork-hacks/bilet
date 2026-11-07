#!/usr/bin/env python3
"""Simulated weak services for the team's hotspot lab.

Every service here is a fake. It sends just enough of a real banner or
protocol reply for `nmap -sV` to label it with the finding catalog's service
name (MASTERPLAN §3.2 "simulate, do not expose", §4.1). Nothing is behind them:

* no login succeeds, except the camera's settings page (#144). Its password is the
  public device ID on the Pi's label, and behind it are only switches that turn this
  Pi's simulated services on or off (through the lab-switch helper, lab/switchd.py);
* client input is never executed, stored or logged;
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
import hmac
import html
import ipaddress
import logging
import re
import secrets
import signal
import socket
import sys
import time
import urllib.parse
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

# The settings page behind the login (#144). Each switch turns one of this Pi's
# simulated services on or off through the lab-switch helper; nothing else is behind
# it. The labels use the words of our own fix steps (src/tool/content/texts.py), so a
# juror who follows the tool's steps finds the switch they describe:
# service -> (English label, Romanian label). A test checks the words against texts.py.
SWITCHES = {
    "telnet": ("Telnet / remote access", "Telnet / acces la distanță"),
    "rtsp": ("Video stream (RTSP)", "Transmisie video (RTSP)"),
    "ftp": ("FTP / file-sharing", "FTP / partajare a fișierelor"),
    "redis": (
        "Database connections from other devices",
        "Conexiuni la baza de date de pe alte dispozitive",
    ),
    "smb": ("Folder sharing", "Partajare foldere"),
    "mqtt": ("MQTT", "MQTT"),
    "ssdp": ("UPnP", "UPnP"),
    "snmp": ("SNMP", "SNMP"),
    "jetdirect": (
        "Direct printing (JetDirect, RAW, 9100)",
        "Imprimarea directă (JetDirect, RAW, 9100)",
    ),
}

SETTINGS_PAGE = """<!doctype html>
<html lang="ro"><head><meta charset="utf-8"><title>Device settings</title>
<style>body{{font:18px/1.5 sans-serif;max-width:40em;margin:1em auto;padding:0 1em}}
fieldset{{margin:1em 0}}button{{font:inherit;padding:.3em 1em}}</style></head>
<body><h1>Setări / Settings</h1>
<p>{message}</p>
{switches}
<form method="post" action="/logout"><input type="hidden" name="csrf" value="{csrf}">
<button>Ieșire / Sign out</button></form>
</body></html>
"""

SWITCH_FORM = """<fieldset><legend>{ro} · {en}</legend>
<p>{state}</p>
<form method="post" action="/settings">
<input type="hidden" name="csrf" value="{csrf}">
<input type="hidden" name="service" value="{service}">
<input type="hidden" name="action" value="{action}">
<button>{button}</button></form></fieldset>
"""

LOGIN_USER = "admin"
LOGIN_FAIL_DELAY = 1.0  # seconds, the same for every failed sign-in
SESSION_TTL = 15 * 60.0  # seconds
MAX_SESSIONS = 8  # the oldest one is dropped when a ninth signs in
MAX_BODY = 1024  # bytes of form data we accept
SWITCH_TIMEOUT = 25.0  # seconds to wait for the helper (labctl may reconnect Wi-Fi)
DEVICE_ID = re.compile(r"[A-Z0-9-]{6,32}")


def read_device_id(path: str) -> str | None:
    """The device ID printed on the Pi's label (written by setup.sh). It is public on
    purpose, like a router's sticker password: never a MAC, never a real password.
    Without a valid one, no sign-in can succeed (the old fake's behaviour)."""
    try:
        with open(path, encoding="ascii") as f:
            value = f.read(64).strip()
    except (OSError, UnicodeDecodeError):
        return None
    return value if DEVICE_ID.fullmatch(value) else None


def _normalise_id(value: str) -> bytes:
    """Labels are read by people: ignore case, spaces and dashes."""
    return re.sub(r"[\s-]", "", value).upper().encode("utf-8", "replace")


async def ask_switch(socket_path: str | None, line: str) -> list[str] | None:
    """Send one request to the lab-switch helper. Returns its reply lines without the
    final "ok", or None when it refused or can't be reached."""
    if not socket_path:
        return None
    try:
        async with asyncio.timeout(SWITCH_TIMEOUT):
            reader, writer = await asyncio.open_unix_connection(socket_path)
            try:
                writer.write(line.encode("ascii") + b"\n")
                await writer.drain()
                reply = b""
                while len(reply) < 4096 and (chunk := await reader.read(4096)):
                    reply += chunk  # the helper closes the connection after its reply
            finally:
                writer.close()
    except (OSError, TimeoutError):
        return None
    lines = reply.decode("ascii", "replace").splitlines()
    if not lines or lines[-1] != "ok":
        return None
    return lines[:-1]


def _headers(status: bytes, extra: list[tuple[str, str]] = (), length: int = 0) -> bytes:
    head = [b"HTTP/1.1 " + status, b"Server: lighttpd/1.4.59"]
    head += [f"{k}: {v}".encode() for k, v in extra]
    head += [b"Content-Length: " + str(length).encode(), b"Connection: close"]
    return b"\r\n".join(head) + b"\r\n\r\n"


# Only on the new pages: the root page keeps the exact headers nmap -sV has always seen.
PAGE_HEADERS = [
    ("Content-Type", "text/html; charset=utf-8"),
    ("Cache-Control", "no-store"),
    ("X-Frame-Options", "DENY"),
    (
        "Content-Security-Policy",
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
    ),
]


def make_http(title: str, device_id: str | None = None, switch_socket: str | None = None):
    safe_title = html.escape(title)
    sessions: dict[str, tuple[float, str]] = {}  # token -> (expires, csrf token); memory only

    def login_page(message: str) -> bytes:
        return HTTP_PAGE.format(title=safe_title, message=message).encode()

    def session_of(headers: dict[str, str]) -> tuple[str, str] | None:
        now = time.monotonic()
        for token in [t for t, (exp, _) in sessions.items() if exp < now]:
            del sessions[token]
        for part in headers.get("cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == "session" and value in sessions:
                return value, sessions[value][1]
        return None

    def check_login(form: dict[str, str]) -> bool:
        if device_id is None:
            return False
        user_ok = hmac.compare_digest(
            form.get("user", "").strip().lower().encode("utf-8", "replace"), LOGIN_USER.encode()
        )
        pass_ok = hmac.compare_digest(
            _normalise_id(form.get("password", "")), _normalise_id(device_id)
        )
        return user_ok and pass_ok

    async def settings_page(csrf: str) -> bytes:
        message = ""
        state = await ask_switch(switch_socket, "status")
        if state is None:
            message = "Setările nu pot fi schimbate acum. · Settings can't be changed right now."
            state = []
        forms = []
        for line in state:
            words = line.split()
            # "SERVICE on|off [default]". A device shows the switches of its own preset
            # (#155), plus any other service someone turned on.
            if len(words) < 2 or words[0] not in SWITCHES:
                continue
            service, is_on = words[0], words[1] == "on"
            if not is_on and "default" not in words[2:]:
                continue
            en, ro = SWITCHES[service]
            forms.append(
                SWITCH_FORM.format(
                    ro=html.escape(ro),
                    en=html.escape(en),
                    state="Pornit · On" if is_on else "Oprit · Off",
                    csrf=csrf,
                    service=service,
                    action="fix" if is_on else "break",
                    button="Oprește · Turn off" if is_on else "Pornește · Turn on",
                )
            )
        return SETTINGS_PAGE.format(
            message=html.escape(message), switches="".join(forms), csrf=csrf
        ).encode()

    async def http(s: Session) -> None:
        head = await s.read_head()
        lines = head.split(b"\r\n")
        request = lines[0].split()
        if len(request) != 3 or not request[2].startswith(b"HTTP/"):
            body = b"Bad Request\n"
            await s.send(
                _headers(b"400 Bad Request", [("Content-Type", "text/plain")], len(body)) + body
            )
            return
        method, path = request[0], request[1].split(b"?", 1)[0]
        headers = {}
        for raw in lines[1:]:
            name, sep, value = raw.decode("latin-1").partition(":")
            if sep:
                headers[name.strip().lower()] = value.strip()

        if method in (b"GET", b"HEAD") and path != b"/settings":
            body = login_page("Please sign in.")
            status = b"200 OK" if path == b"/" else b"404 Not Found"
            reply = (
                b"HTTP/1.1 " + status + b"\r\n"
                b"Server: lighttpd/1.4.59\r\n"
                b"Content-Type: text/html; charset=utf-8\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n"
            )
            await s.send(reply if method == b"HEAD" else reply + body)
            return

        form: dict[str, str] = {}
        if method == b"POST":
            try:
                length = int(headers.get("content-length", "0"))
            except ValueError:
                length = -1
            if not 0 <= length <= MAX_BODY:
                raise Hangup("bad form length")
            data = b""
            while len(data) < length:
                data += await s.read(length - len(data))
            parsed = urllib.parse.parse_qs(data.decode("utf-8", "replace"), max_num_fields=8)
            form = {k: v[0][:64] for k, v in parsed.items()}

        session = session_of(headers)
        if method == b"POST" and path in (b"/", b"/login"):
            if not check_login(form):
                await asyncio.sleep(LOGIN_FAIL_DELAY)
                body = login_page("Wrong user name or password.")
                await s.send(_headers(b"401 Unauthorized", PAGE_HEADERS[:1], len(body)) + body)
                return
            while len(sessions) >= MAX_SESSIONS:
                del sessions[next(iter(sessions))]
            token = secrets.token_urlsafe(32)
            sessions[token] = (time.monotonic() + SESSION_TTL, secrets.token_urlsafe(32))
            cookie = f"session={token}; Path=/; HttpOnly; SameSite=Strict"
            await s.send(
                _headers(b"303 See Other", [("Location", "/settings"), ("Set-Cookie", cookie)])
            )
            return
        if session is None:
            await s.send(_headers(b"303 See Other", [("Location", "/")]))
            return
        token, csrf = session
        if method == b"POST" and not hmac.compare_digest(
            form.get("csrf", "").encode(), csrf.encode()
        ):
            body = b"Forbidden\n"
            await s.send(
                _headers(b"403 Forbidden", [("Content-Type", "text/plain")], len(body)) + body
            )
            return
        if method == b"POST" and path == b"/logout":
            sessions.pop(token, None)
            await s.send(_headers(b"303 See Other", [("Location", "/")]))
            return
        if method == b"POST" and path == b"/settings":
            service, action = form.get("service", ""), form.get("action", "")
            if service in SWITCHES and action in ("fix", "break"):
                # The helper checks the service again; the page then shows the real state.
                await ask_switch(switch_socket, f"{action} {service}")
            await s.send(_headers(b"303 See Other", [("Location", "/settings")]))
            return
        if path != b"/settings" or method not in (b"GET", b"HEAD"):
            body = b"Not Found\n"
            await s.send(
                _headers(b"404 Not Found", [("Content-Type", "text/plain")], len(body)) + body
            )
            return
        body = await settings_page(csrf)
        reply = _headers(b"200 OK", PAGE_HEADERS, len(body))
        await s.send(reply if method == b"HEAD" else reply + body)

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


def tcp_handler(name: str, http_title: str, **http_options):
    if name == "http":
        return make_http(http_title, **http_options)
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
    name: str,
    bind: str,
    port: int | None = None,
    http_title: str = "Camera Login",
    device_id: str | None = None,
    switch_socket: str | None = None,
):
    """Start one fake service. Returns the asyncio server (TCP) or transport (UDP).
    device_id and switch_socket only matter for http (the settings page, #144)."""
    port = ALL_SERVICES[name] if port is None else port
    if name in UDP_SERVICES:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(SsdpResponder, local_addr=(bind, port))
        return transport
    return await asyncio.start_server(
        _client_callback(
            name, tcp_handler(name, http_title, device_id=device_id, switch_socket=switch_socket)
        ),
        host=bind,
        port=port,
        limit=READ_LIMIT,
    )


async def run(
    services: list[str], bind: str, port: int | None, http_title: str, **http_options
) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)
    started = []
    for name in services:
        started.append(await start_service(name, bind, port, http_title, **http_options))
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
    parser.add_argument(
        "--device-id-file",
        default="/etc/lab/device-id",
        help="the label's device ID, the settings page password (http only)",
    )
    parser.add_argument(
        "--switch-socket",
        default="/run/lab-switch.sock",
        help="the lab-switch helper's socket, for the settings page switches (http only)",
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
        asyncio.run(
            run(
                args.services,
                args.bind,
                args.port,
                args.http_title,
                device_id=read_device_id(args.device_id_file) if "http" in args.services else None,
                switch_socket=args.switch_socket,
            )
        )
    except OSError as exc:
        log.error("cannot start: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
