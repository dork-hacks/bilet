#!/usr/bin/env python3
"""Lab manager (#155): one page on the Pi 5 that controls what every lab Pi plays.

For each Pi in the config file the page shows its preset (camera, hub, printer, ...), every
lab service with its catalog codes and points, and a button to turn each one on or off. It
also shows what the whole lab should score, from the points in services.tsv.

How it reaches the Pis: `ssh labmgr@<pi> "<request>"` with its own key. On the Pi that key
is restricted to lab/remote.py, which hands the request to the lab-switch helper. Requests
are checked here and again by the helper: "status", "fix SERVICE", "break SERVICE" and
"preset NAME", nothing else.

It listens on 127.0.0.1 only, so it never shows up in a scan of the hotspot and the router
keeps adding 0 points (MASTERPLAN §4.2). Open it from the laptop through SSH:
    ssh -L 8090:127.0.0.1:8090 <user>@<pi5>    then browse to http://127.0.0.1:8090/

Standard library only, Python 3.11+.
"""

from __future__ import annotations

import argparse
import html
import ipaddress
import re
import secrets
import subprocess
import sys
import threading
import urllib.parse
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG = Path("/etc/lab-manager/pis.conf")
STATE = Path("/var/lib/lab-manager")
SSH_TIMEOUT = 30.0  # seconds per request; a preset may reconnect a Pi's Wi-Fi
MAX_BODY = 2048
ROLES = ("camera", "server", "hub")
NAME = re.compile(r"[a-z][a-z0-9-]{0,15}")
SERVICE = re.compile(r"[a-z][a-z0-9]{0,15}")
CGNAT = ipaddress.ip_network("100.64.0.0/10")

Runner = Callable[[list[str], float], tuple[int, str]]


# --- the lab tables -------------------------------------------------------------------


@dataclass(frozen=True)
class Service:
    name: str
    role: str
    port: str
    codes: str
    points: int


def _rows(path: Path, min_cols: int) -> list[list[str]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        cols = line.split("\t")
        if not line.startswith("#") and len(cols) >= min_cols:
            rows.append(cols)
    return rows


def load_services(path: Path) -> list[Service]:
    return [Service(r[0], r[1], r[4], r[5], int(r[6])) for r in _rows(path, 8)]


def load_presets(services_path: Path, presets_path: Path) -> dict[str, list[str]]:
    """Preset name -> its services, as labctl reads them: the roles' default-on rows of
    services.tsv, then the rows of presets.tsv."""
    presets: dict[str, list[str]] = {role: [] for role in ROLES}
    for r in _rows(services_path, 8):
        if r[1] in presets and r[7] == "on":
            presets[r[1]].append(r[0])
    for r in _rows(presets_path, 3):
        presets[r[0]] = [s for s in r[1].split(",") if s != "-"]
    return presets


# --- the Pis --------------------------------------------------------------------------


@dataclass
class Pi:
    name: str
    address: str


class ConfigError(Exception):
    pass


def load_config(path: Path) -> list[Pi]:
    """One Pi per line: NAME ADDRESS (a private IP on the hotspot). # starts a comment."""
    pis: list[Pi] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 2 or not NAME.fullmatch(parts[0]):
            raise ConfigError(f"{path}:{number}: expected 'NAME ADDRESS'")
        try:
            address = ipaddress.ip_address(parts[1])
        except ValueError as exc:
            raise ConfigError(f"{path}:{number}: '{parts[1]}' isn't an IP address") from exc
        if not address.is_private or address.is_loopback or address in CGNAT:
            raise ConfigError(f"{path}:{number}: {address} isn't a private hotspot address")
        if any(p.name == parts[0] for p in pis):
            raise ConfigError(f"{path}:{number}: '{parts[0]}' is listed twice")
        pis.append(Pi(parts[0], str(address)))
    return pis


@dataclass
class PiState:
    pi: Pi
    reachable: bool = False
    preset: str = ""
    on: dict[str, bool] = field(default_factory=dict)
    default: set[str] = field(default_factory=set)
    error: str = ""


def parse_status(pi: Pi, reply: str, services: list[str], presets: dict) -> PiState:
    """Read the helper's status reply. Anything malformed means the Pi can't be read."""
    lines = reply.splitlines()
    state = PiState(pi)
    if not lines or lines[-1] != "ok":
        state.error = "the Pi refused or didn't answer"
        return state
    for line in lines[:-1]:
        words = line.split()
        if len(words) == 2 and words[0] == "preset" and words[1] in presets:
            state.preset = words[1]
        elif 2 <= len(words) <= 3 and words[0] in services and words[1] in ("on", "off"):
            state.on[words[0]] = words[1] == "on"
            if words[2:] == ["default"]:
                state.default.add(words[0])
    state.reachable = bool(state.preset)
    if not state.reachable:
        state.error = "the Pi's answer didn't name a preset"
    return state


class Manager:
    def __init__(
        self,
        pis: list[Pi],
        services: list[Service],
        presets: dict[str, list[str]],
        run: Runner,
        key: Path = STATE / "id_ed25519",
        known_hosts: Path = STATE / "known_hosts",
    ):
        self.pis = {p.name: p for p in pis}
        self.services = services
        self.names = [s.name for s in services]
        self.presets = presets
        self.run = run
        self.key, self.known_hosts = key, known_hosts
        self.locks = {p.name: threading.Lock() for p in pis}  # one request per Pi at a time
        self.csrf = secrets.token_urlsafe(32)

    def valid_request(self, request: str) -> bool:
        words = request.split(" ")
        if words == ["status"]:
            return True
        if len(words) == 2 and words[0] in ("fix", "break"):
            return words[1] in self.names
        if len(words) == 2 and words[0] == "preset":
            return words[1] in self.presets
        return False

    def ssh_argv(self, pi: Pi, request: str) -> list[str]:
        return [
            "ssh",
            "-F", "/dev/null",
            "-i", str(self.key),
            "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={self.known_hosts}",
            "-o", "ConnectTimeout=4",
            "-T",
            f"labmgr@{pi.address}",
            request,
        ]  # fmt: skip

    def ask(self, pi: Pi, request: str) -> str:
        if not self.valid_request(request):
            return "refused\n"
        with self.locks[pi.name]:
            try:
                _code, out = self.run(self.ssh_argv(pi, request), SSH_TIMEOUT)
            except (OSError, subprocess.SubprocessError):
                return "refused\n"
        return out

    def status(self, pi: Pi) -> PiState:
        return parse_status(pi, self.ask(pi, "status"), self.names, self.presets)

    def all_status(self) -> list[PiState]:
        pis = list(self.pis.values())
        if not pis:
            return []
        with ThreadPoolExecutor(max_workers=len(pis)) as pool:
            return list(pool.map(self.status, pis))

    def act(self, pi_name: str, op: str, arg: str) -> bool:
        """One button: fix, break, preset NAME, fixall (every service off) or reset (back
        to the Pi's preset). Returns False when the request was refused anywhere."""
        pi = self.pis.get(pi_name)
        if pi is None:
            return False
        if op in ("fix", "break", "preset"):
            return self.ask(pi, f"{op} {arg}").splitlines()[-1:] == ["ok"]
        if op in ("fixall", "reset"):
            state = self.status(pi)
            if not state.reachable:
                return False
            if op == "reset":
                return self.act(pi_name, "preset", state.preset)
            return all(self.act(pi_name, "fix", s) for s, on in state.on.items() if on)
        return False

    def expected_score(self, states: list[PiState]) -> tuple[int, int]:
        """(score, points) from services.tsv for the services that are on, on the Pis that
        answered. The Pi 5 adds 0 (key-only SSH)."""
        points_of = {s.name: s.points for s in self.services}
        points = sum(points_of[s] for st in states for s, on in st.on.items() if on)
        return max(0, 100 - points), points


# --- the page -------------------------------------------------------------------------

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lab manager</title>
<style>
body{{font:17px/1.5 system-ui,sans-serif;margin:0 auto;max-width:72em;padding:0 16px;color:#111;background:#fff}}
h1{{margin:.6em 0 .2em}} .score{{font-size:1.25em;margin:.2em 0 1em}}
.pis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(21em,1fr));gap:1em}}
section{{border:2px solid #555;border-radius:8px;padding:.2em 1em 1em}}
table{{border-collapse:collapse;width:100%}} td,th{{text-align:left;padding:.25em .3em;border-top:1px solid #ccc}}
button,select{{font:inherit;padding:.25em .7em}} .on{{font-weight:700}} .err{{color:#a00;font-weight:700}}
form{{display:inline}} .row{{margin:.5em 0}}
@media (prefers-color-scheme: dark){{body{{background:#111;color:#eee}} .err{{color:#f88}} section{{border-color:#999}}}}
</style></head>
<body><h1>Lab manager</h1>
<p class="score">What the lab should score: <strong>{score}</strong> ({points} points switched on{partial}).
The tool's own scan is the real answer; this only adds up <code>services.tsv</code>.</p>
<p>{message}</p>
<p><a href="/">Refresh</a></p>
<div class="pis">{cards}</div>
</body></html>
"""


def _button(csrf: str, pi: str, op: str, arg: str, label: str) -> str:
    return (
        '<form method="post" action="/do">'
        f'<input type="hidden" name="csrf" value="{csrf}">'
        f'<input type="hidden" name="pi" value="{html.escape(pi)}">'
        f'<input type="hidden" name="op" value="{op}">'
        f'<input type="hidden" name="arg" value="{html.escape(arg)}">'
        f"<button>{html.escape(label)}</button></form>"
    )


def render(manager: Manager, states: list[PiState], message: str = "") -> bytes:
    csrf = manager.csrf
    cards = []
    for st in states:
        name = html.escape(st.pi.name)
        head = (
            f'<section id="pi-{name}"><h2>{name} <small>{html.escape(st.pi.address)}</small></h2>'
        )
        if not st.reachable:
            cards.append(
                f'{head}<p class="err">Not reachable: {html.escape(st.error)}.</p></section>'
            )
            continue
        options = "".join(
            f'<option value="{p}"{" selected" if p == st.preset else ""}>{p}</option>'
            for p in manager.presets
        )
        preset_form = (
            '<form method="post" action="/do">'
            f'<input type="hidden" name="csrf" value="{csrf}">'
            f'<input type="hidden" name="pi" value="{name}"><input type="hidden" name="op" value="preset">'
            f'<label>Plays <select name="arg">{options}</select></label> '
            "<button>Switch device</button></form>"
        )
        rows = []
        for svc in manager.services:
            on = st.on.get(svc.name, False)
            state = '<span class="on">ON (weak)</span>' if on else "off (fixed)"
            mark = " · in preset" if svc.name in st.default else ""
            op, label = ("fix", "Turn off") if on else ("break", "Turn on")
            rows.append(
                f"<tr><td>{svc.name}</td><td>{html.escape(svc.port)}</td>"
                f"<td>{html.escape(svc.codes.replace('+', ' + '))}</td><td>{svc.points}</td>"
                f"<td>{state}{mark}</td><td>{_button(csrf, st.pi.name, op, svc.name, label)}</td></tr>"
            )
        cards.append(
            f"{head}<div class='row'>{preset_form}</div>"
            f"<div class='row'>{_button(csrf, st.pi.name, 'fixall', '-', 'Fix everything')} "
            f"{_button(csrf, st.pi.name, 'reset', '-', 'Back to the preset')}</div>"
            "<table><tr><th>Service</th><th>Port</th><th>Finding</th><th>Points</th>"
            f"<th>State</th><th></th></tr>{''.join(rows)}</table></section>"
        )
    score, points = manager.expected_score(states)
    partial = "" if all(s.reachable for s in states) else ", unreachable Pis not counted"
    if not states:
        cards.append("<p>No Pis configured. Add them to /etc/lab-manager/pis.conf.</p>")
    return PAGE.format(
        score=score,
        points=points,
        partial=partial,
        message=html.escape(message),
        cards="".join(cards),
    ).encode()


# --- HTTP ------------------------------------------------------------------------------

MESSAGES = {"done": "Done.", "refused": "That didn't work: the Pi refused or didn't answer."}


def make_handler(manager: Manager, port: int):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "lab-manager"
        sys_version = ""

        def log_message(self, fmt, *args):  # no request log; status comes from the Pis
            pass

        def _host_ok(self) -> bool:
            # Only a browser on this machine (through the SSH tunnel). This also stops DNS
            # rebinding: a page on another name can't drive the manager.
            if self.headers.get("Host", "") not in allowed_hosts:
                return False
            origin = self.headers.get("Origin")
            return origin is None or urllib.parse.urlsplit(origin).netloc in allowed_hosts

        def _send(self, status: int, body: bytes = b"", location: str | None = None):
            self.send_response(status)
            if location:
                self.send_header("Location", location)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
            )
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802 (http.server's name)
            if not self._host_ok():
                return self._send(403, b"Forbidden\n")
            url = urllib.parse.urlsplit(self.path)
            if url.path != "/":
                return self._send(404, b"Not Found\n")
            query = urllib.parse.parse_qs(url.query)
            message = MESSAGES.get(query.get("m", [""])[0], "")
            self._send(200, render(manager, manager.all_status(), message))

        def do_POST(self):  # noqa: N802
            if not self._host_ok():
                return self._send(403, b"Forbidden\n")
            if urllib.parse.urlsplit(self.path).path != "/do":
                return self._send(404, b"Not Found\n")
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if not 0 <= length <= MAX_BODY:
                return self._send(413, b"Too large\n")
            form = {
                k: v[0]
                for k, v in urllib.parse.parse_qs(
                    self.rfile.read(length).decode("utf-8", "replace"), max_num_fields=8
                ).items()
            }
            if not secrets.compare_digest(form.get("csrf", ""), manager.csrf):
                return self._send(403, b"Forbidden\n")
            pi, op, arg = form.get("pi", ""), form.get("op", ""), form.get("arg", "")
            ok = manager.act(pi, op, arg)
            anchor = f"#pi-{pi}" if NAME.fullmatch(pi) else ""
            self._send(303, location=f"/?m={'done' if ok else 'refused'}{anchor}")

    return Handler


def run_ssh(argv: list[str], timeout: float) -> tuple[int, str]:
    done = subprocess.run(  # noqa: S603 (fixed ssh argv; the request is checked first)
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    return done.returncode, done.stdout.decode("ascii", "replace")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Lab manager for the hotspot lab (#155).")
    parser.add_argument("--bind", default="127.0.0.1", choices=("127.0.0.1",))  # never the hotspot
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--lab-dir", type=Path, default=HERE)
    args = parser.parse_args(argv)
    try:
        pis = load_config(args.config)
        services = load_services(args.lab_dir / "services.tsv")
        presets = load_presets(args.lab_dir / "services.tsv", args.lab_dir / "presets.tsv")
    except (OSError, ConfigError) as exc:
        print(f"lab-manager: {exc}", file=sys.stderr)
        return 1
    manager = Manager(pis, services, presets, run_ssh)
    server = ThreadingHTTPServer((args.bind, args.port), make_handler(manager, args.port))
    print(f"lab-manager: http://{args.bind}:{args.port}/ ({len(pis)} Pis)", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
