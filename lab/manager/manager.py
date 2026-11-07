#!/usr/bin/env python3
"""Lab manager (#155): one page on the Pi 5 that controls what every lab Pi plays.

For each Pi in the config file the page shows its preset (camera, hub, printer, ...), every
lab service with its catalog codes and points, and a button to turn each one on or off. It
also shows what the whole lab should score, from the points in services.tsv.

How it reaches the Pis: `ssh labmgr@<pi> "<request>"` with its own key. On the Pi that key
is restricted to lab/remote.py, which hands the request to the lab-switch helper. Requests
are checked here and again by the helper: "status", "fix SERVICE", "break SERVICE" and
"preset NAME", nothing else.

By default it listens on 127.0.0.1 only; open it from the laptop through SSH:
    ssh -L 8090:127.0.0.1:8090 <user>@<pi5>    then browse to http://127.0.0.1:8090/
With --bind <the router's hotspot address> anyone on the hotspot can reach it, so every page
then needs the access code from --access-code-file (made by setup_openwrt.sh). It then shows
up in a scan as plain http whose page title is "Lab manager": no admin word, so no
HTTP_ADMIN_CLEARTEXT and the router still adds 0 points (MASTERPLAN §4.2).

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
import time
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
LOOPBACK = "127.0.0.1"
ACCESS_CODE = re.compile(r"LAB-[A-Z2-7]{4}-[A-Z2-7]{4}")
SESSION_TTL = 30 * 60.0  # seconds
MAX_SESSIONS = 8  # the oldest one is dropped when a ninth signs in
SIGNIN_FAIL_DELAY = 1.0  # seconds; slows down guessing
COOKIE = "lab-session"
POLL_INTERVAL = 10.0  # seconds between background status refreshes
POLL_IDLE = 300.0  # stop polling the Pis when nobody has opened the page for this long

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
        client: str = "openssh",
    ):
        self.pis = {p.name: p for p in pis}
        self.services = services
        self.names = [s.name for s in services]
        self.presets = presets
        self.run = run
        self.key, self.known_hosts = key, known_hosts
        self.client = client  # "openssh", or "dropbear" on the OpenWrt router
        self.locks = {p.name: threading.Lock() for p in pis}  # one request per Pi at a time
        self.csrf = secrets.token_urlsafe(32)
        # The last status of every Pi, so a page renders at once instead of waiting for
        # one SSH round trip per Pi (about a second each). poll() keeps it fresh.
        self.clock = time.monotonic
        self.cache: dict[str, tuple[PiState, float]] = {}
        self.cache_lock = threading.Lock()
        self.last_view = 0.0

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
        if self.client == "dropbear":
            # OpenWrt's own client. -y accepts a Pi's host key the first time and keeps it
            # in $HOME/.ssh/known_hosts (run_ssh sets HOME); a changed key is refused. With
            # no terminal it can't ask for a password, so only the key can log in.
            return ["dbclient", "-i", str(self.key), "-y", "-T", f"labmgr@{pi.address}", request]
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
        """Ask the Pi now, and remember the answer."""
        state = parse_status(pi, self.ask(pi, "status"), self.names, self.presets)
        with self.cache_lock:
            self.cache[pi.name] = (state, self.clock())
        return state

    def all_status(self) -> list[PiState]:
        """Ask every Pi now, in parallel."""
        pis = list(self.pis.values())
        if not pis:
            return []
        with ThreadPoolExecutor(max_workers=len(pis)) as pool:
            return list(pool.map(self.status, pis))

    def snapshot(self) -> tuple[list[PiState], float]:
        """The remembered status of every Pi (asking only those never asked yet), and the
        age in seconds of the oldest answer."""
        self.last_view = self.clock()
        with self.cache_lock:
            missing = [p for p in self.pis.values() if p.name not in self.cache]
        if missing:
            with ThreadPoolExecutor(max_workers=len(missing)) as pool:
                list(pool.map(self.status, missing))
        with self.cache_lock:
            entries = [self.cache[name] for name in self.pis]
        age = max((self.clock() - at for _, at in entries), default=0.0)
        return [state for state, _ in entries], age

    def poll(self, stop: threading.Event, interval: float = POLL_INTERVAL) -> None:
        """Refresh every Pi's status in the background while someone uses the page."""
        while not stop.wait(interval):
            if self.clock() - self.last_view < POLL_IDLE:
                self.all_status()

    def act(self, pi_name: str, op: str, arg: str) -> bool:
        """One button: fix, break, preset NAME, fixall (every service off) or reset (back
        to the Pi's preset). Returns False when the request was refused anywhere."""
        pi = self.pis.get(pi_name)
        if pi is None:
            return False
        if op in ("fix", "break", "preset"):
            if not self.valid_request(f"{op} {arg}"):
                return False
            ok = self.ask(pi, f"{op} {arg}").splitlines()[-1:] == ["ok"]
            if op == "preset":
                self.status(pi)  # many services change: show the Pi's real state
            else:
                # One switch: show it at once, and confirm with the Pi in the background
                # (a status round trip is about a second).
                if ok:
                    self._mark(pi, arg, op == "break")
                threading.Thread(target=self.status, args=(pi,), daemon=True).start()
            return ok
        if op in ("fixall", "reset"):
            with self.cache_lock:
                cached = self.cache.get(pi.name)
            state = cached[0] if cached and cached[0].reachable else self.status(pi)
            if not state.reachable:
                return False
            if op == "reset":
                return self.act(pi_name, "preset", state.preset)
            replies = [self.ask(pi, f"fix {s}") for s, on in state.on.items() if on]
            self.status(pi)
            return all(r.splitlines()[-1:] == ["ok"] for r in replies)
        return False

    def _mark(self, pi: Pi, service: str, on: bool) -> None:
        with self.cache_lock:
            if pi.name in self.cache:
                self.cache[pi.name][0].on[service] = on

    def expected_score(self, states: list[PiState]) -> tuple[int, int]:
        """(score, points) from services.tsv for the services that are on, on the Pis that
        answered. The Pi 5 adds 0 (key-only SSH)."""
        points_of = {s.name: s.points for s in self.services}
        points = sum(points_of[s] for st in states for s, on in st.on.items() if on)
        return max(0, 100 - points), points


# --- the page -------------------------------------------------------------------------

# What each service is, in words, for the cards.
LABELS = {
    "telnet": "Telnet",
    "http": "Admin web page",
    "rtsp": "Camera stream (RTSP)",
    "ftp": "FTP server (vsFTPd 2.3.4)",
    "redis": "Redis database",
    "smb": "Windows file sharing (SMB)",
    "mqtt": "MQTT broker",
    "ssdp": "UPnP discovery (SSDP)",
    "snmp": "SNMP",
    "jetdirect": "Printer port (JetDirect)",
    "unknown": "Hidden identity (no vendor, no hostname)",
}

CSS = """
:root{--bg:#f6f4ef;--card:#fff;--ink:#1d1b18;--muted:#5d5850;--line:#e2ddd3;--accent:#2f5d8a;
--bad:#a3261b;--bad-bg:#fbe9e6;--mid:#8a5a00;--mid-bg:#fdf1d8;--good:#1f6b3a;--good-bg:#e3f3e8;
--off:#d8d3ca;--knob:#fff}
@media (prefers-color-scheme: dark){:root{--bg:#161513;--card:#211f1c;--ink:#efebe4;--muted:#b3ab9f;
--line:#3a3631;--accent:#8db8e0;--bad:#ff9d90;--bad-bg:#3d1c18;--mid:#f2c46b;--mid-bg:#3a2d12;
--good:#8fd6a6;--good-bg:#173323;--off:#4a453e;--knob:#efebe4}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:17px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:76rem;margin:0 auto;padding:16px}
header{display:flex;flex-wrap:wrap;align-items:center;gap:12px 20px;margin:4px 0 18px}
h1{font-size:1.5rem;margin:0}
.score{display:flex;align-items:center;gap:12px;padding:8px 16px;border-radius:14px;font-weight:600}
.score b{font-size:2rem;line-height:1}
.score.bad{background:var(--bad-bg);color:var(--bad)} .score.mid{background:var(--mid-bg);color:var(--mid)}
.score.good{background:var(--good-bg);color:var(--good)}
.meta{color:var(--muted);font-size:.9rem}
.tools{margin-left:auto;display:flex;gap:8px;align-items:center}
.msg{padding:10px 14px;border-radius:10px;background:var(--card);border:1px solid var(--line);margin:0 0 16px}
.msg.bad{border-color:var(--bad);color:var(--bad)}
.pis{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,22rem),1fr));gap:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px;display:flex;flex-direction:column;gap:12px}
.card h2{margin:0;font-size:1.25rem}
.top{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap}
.pill{margin-left:auto;font-size:.85rem;font-weight:600;padding:3px 10px;border-radius:99px}
.pill.bad{background:var(--bad-bg);color:var(--bad)} .pill.good{background:var(--good-bg);color:var(--good)}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
select,button{font:inherit;font-size:.95rem;color:var(--ink);background:var(--card);border:1px solid var(--line);border-radius:10px;padding:6px 12px;cursor:pointer}
button:hover,select:hover{border-color:var(--accent)}
button:focus-visible,select:focus-visible,summary:focus-visible,a:focus-visible,input:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.primary{background:var(--accent);border-color:var(--accent);color:var(--card)}
ul{list-style:none;margin:0;padding:0}
li{display:flex;align-items:center;gap:12px;padding:9px 0;border-top:1px solid var(--line)}
li .what{flex:1;min-width:0}
li .name{font-weight:600}
li.on .name::after{content:" · weak";color:var(--bad);font-weight:600}
.switch{display:flex;align-items:center;gap:8px;border:0;background:none;padding:4px;border-radius:99px;min-width:5.2rem;justify-content:flex-end}
.switch .track{width:2.6rem;height:1.5rem;border-radius:99px;background:var(--off);position:relative;flex:none}
.switch .track::after{content:"";position:absolute;top:.2rem;left:.2rem;width:1.1rem;height:1.1rem;border-radius:50%;background:var(--knob)}
.switch[aria-pressed=true] .track{background:var(--bad)}
.switch[aria-pressed=true] .track::after{left:1.3rem}
.switch .label{font-size:.85rem;font-weight:600;width:1.8rem;text-align:left}
details summary{cursor:pointer;color:var(--muted);padding:6px 0}
form{display:inline;margin:0}
.err{color:var(--bad);font-weight:600}
a{color:var(--accent)}
.signin{max-width:26rem;margin:12vh auto 0}
.signin input{font:inherit;width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:var(--card);color:var(--ink);letter-spacing:.05em}
.signin label{display:block;margin:12px 0 6px;font-weight:600}
"""


def _page(body: str) -> bytes:
    # The title stays "Lab manager" on every page: no admin word for http-title (§4.2).
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>Lab manager</title><style>{CSS}</style></head>"
        f'<body><div class="wrap">{body}</div></body></html>\n'
    ).encode()


def _form(csrf: str, pi: str, op: str, arg: str, inner: str, cls: str = "", extra: str = "") -> str:
    return (
        '<form method="post" action="/do">'
        f'<input type="hidden" name="csrf" value="{csrf}">'
        f'<input type="hidden" name="pi" value="{html.escape(pi)}">'
        f'<input type="hidden" name="op" value="{op}">'
        f'<input type="hidden" name="arg" value="{html.escape(arg)}">'
        f'<button class="{cls}"{extra}>{inner}</button></form>'
    )


def _service(csrf: str, st: PiState, svc: Service) -> str:
    on = st.on.get(svc.name, False)
    op = "fix" if on else "break"
    action = f"Turn {svc.name} {'off' if on else 'on'} on {st.pi.name}"
    switch = _form(
        csrf,
        st.pi.name,
        op,
        svc.name,
        f'<span class="track"></span><span class="label">{"On" if on else "Off"}</span>',
        "switch",
        f' aria-pressed="{"true" if on else "false"}" aria-label="{html.escape(action)}"',
    )
    port = "" if svc.port == "-" else f"{html.escape(svc.port)} · "
    return (
        f'<li class="{"on" if on else "off"}"><div class="what">'
        f'<div class="name">{html.escape(LABELS.get(svc.name, svc.name))}</div>'
        f'<div class="meta">{port}{html.escape(svc.codes.replace("+", " + "))} · '
        f"{svc.points} points</div></div>{switch}</li>"
    )


def _card(manager: Manager, st: PiState) -> str:
    csrf = manager.csrf
    name = html.escape(st.pi.name)
    top = f'<div class="top"><h2>{name}</h2><span class="meta">{html.escape(st.pi.address)}</span>'
    if not st.reachable:
        return (
            f'<section class="card" id="pi-{name}">{top}</div>'
            f'<p class="err">Not reachable: {html.escape(st.error)}.</p></section>'
        )
    points_of = {s.name: s.points for s in manager.services}
    weak = [s for s, on in st.on.items() if on]
    points = sum(points_of[s] for s in weak)
    pill = (
        f'<span class="pill bad">{len(weak)} weak · {points} points</span>'
        if weak
        else '<span class="pill good">All fixed</span>'
    )
    options = "".join(
        f'<option value="{p}"{" selected" if p == st.preset else ""}>{p}</option>'
        for p in manager.presets
    )
    preset_form = (
        '<form method="post" action="/do">'
        f'<input type="hidden" name="csrf" value="{csrf}">'
        f'<input type="hidden" name="pi" value="{name}"><input type="hidden" name="op" value="preset">'
        f'<label class="meta" for="preset-{name}">Plays</label> '
        f'<select id="preset-{name}" name="arg">{options}</select> '
        "<button>Switch device</button></form>"
    )
    shown = [s for s in manager.services if st.on.get(s.name) or s.name in st.default]
    hidden = [s for s in manager.services if s not in shown]
    items = "".join(_service(csrf, st, s) for s in shown) or (
        '<li class="meta">Nothing in this preset. Turn services on below.</li>'
    )
    more = ""
    if hidden:
        more = (
            f"<details><summary>Other services ({len(hidden)})</summary>"
            f"<ul>{''.join(_service(csrf, st, s) for s in hidden)}</ul></details>"
        )
    actions = (
        f'<div class="row">{_form(csrf, st.pi.name, "fixall", "-", "Fix everything", "primary")}'
        f"{_form(csrf, st.pi.name, 'reset', '-', 'Back to the preset')}</div>"
    )
    return (
        f'<section class="card" id="pi-{name}">{top}{pill}</div>'
        f'<div class="row">{preset_form}</div><ul>{items}</ul>{more}{actions}</section>'
    )


def render(
    manager: Manager,
    states: list[PiState],
    message: str = "",
    sign_out: bool = False,
    age: float = 0.0,
    error: bool = False,
) -> bytes:
    csrf = manager.csrf
    score, points = manager.expected_score(states)
    level, word = (
        ("good", "Good") if score >= 80 else ("mid", "Fair") if score >= 50 else ("bad", "At risk")
    )
    partial = "" if all(s.reachable for s in states) else ", unreachable Pis not counted"
    signout = (
        '<form method="post" action="/signout">'
        f'<input type="hidden" name="csrf" value="{csrf}"><button>Sign out</button></form>'
        if sign_out
        else ""
    )
    updated = "just now" if age < 2 else f"{int(age)} s ago"
    header = (
        "<header><h1>Lab manager</h1>"
        f'<div class="score {level}"><b>{score}</b><span>{word}<br>'
        f'<span class="meta">What the lab should score</span></span></div>'
        f'<div class="meta">{points} points switched on{partial}.<br>'
        f"Status {updated}. The tool's own scan is the real answer.</div>"
        f'<div class="tools"><a href="/?refresh=1">Refresh</a>{signout}</div></header>'
    )
    note = (
        f'<p class="msg{" bad" if error else ""}" role="status">{html.escape(message)}</p>'
        if message
        else ""
    )
    cards = "".join(_card(manager, st) for st in states)
    if not states:
        cards = "<p>No Pis configured. Add them to /etc/lab-manager/pis.conf.</p>"
    return _page(f'{header}{note}<main class="pis">{cards}</main>')


def signin_page(csrf: str, message: str = "") -> bytes:
    err = f'<p class="err" role="alert">{html.escape(message)}</p>' if message else ""
    return _page(
        '<div class="signin card"><h1>Lab manager</h1>'
        '<p class="meta">Type the access code that the router\'s setup printed (LAB-XXXX-XXXX).</p>'
        f'{err}<form method="post" action="/signin">'
        f'<input type="hidden" name="csrf" value="{csrf}">'
        '<label for="code">Access code</label>'
        '<input id="code" name="code" autocomplete="off" autocapitalize="characters" spellcheck="false" autofocus>'
        '<div class="row" style="margin-top:14px"><button class="primary">Open</button></div>'
        "</form></div>"
    )


def check_bind(address: str) -> str:
    """--bind: loopback, or one private IPv4 address of this router (the hotspot side).
    Never 0.0.0.0, which would also listen on the uplink."""
    try:
        ip = ipaddress.IPv4Address(address)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{address!r} is not an IPv4 address") from None
    if str(ip) == LOOPBACK:
        return LOOPBACK
    if not ip.is_private or ip in CGNAT or ip.is_loopback or ip.is_link_local or ip.is_unspecified:
        raise argparse.ArgumentTypeError(f"{address} is not a private hotspot address")
    return str(ip)


def load_access_code(path: Path) -> str:
    code = path.read_text(encoding="ascii", errors="replace").strip().upper()
    if not ACCESS_CODE.fullmatch(code):
        raise ConfigError(f"{path}: no access code (LAB-XXXX-XXXX)")
    return code


class Access:
    """Sign-in for a manager that the hotspot can reach. code=None: loopback, no sign-in."""

    def __init__(self, code: str | None = None, clock: Callable[[], float] = time.monotonic):
        self.code = code
        self.clock = clock
        self.sessions: dict[str, float] = {}  # token -> expiry
        self.lock = threading.Lock()

    @property
    def required(self) -> bool:
        return self.code is not None

    def sign_in(self, code: str) -> str | None:
        """A new session token for the right code, else None."""
        if self.code is None:
            return None
        typed = code.strip().upper().encode("ascii", "replace")
        if not secrets.compare_digest(typed, self.code.encode("ascii")):
            return None
        token = secrets.token_urlsafe(32)
        with self.lock:
            self._expire()
            while len(self.sessions) >= MAX_SESSIONS:
                del self.sessions[min(self.sessions, key=self.sessions.get)]
            self.sessions[token] = self.clock() + SESSION_TTL
        return token

    def valid(self, token: str) -> bool:
        if self.code is None:
            return True
        with self.lock:
            self._expire()
            return any(secrets.compare_digest(token, t) for t in self.sessions)

    def sign_out(self, token: str) -> None:
        with self.lock:
            self.sessions.pop(token, None)

    def _expire(self) -> None:
        now = self.clock()
        for token in [t for t, until in self.sessions.items() if until <= now]:
            del self.sessions[token]


# --- HTTP ------------------------------------------------------------------------------

MESSAGES = {
    "done": "Done.",
    "refused": "That didn't work: the Pi refused or didn't answer.",
    "badcode": "That access code is wrong.",
}


def make_handler(manager: Manager, port: int, bind: str = LOOPBACK, access: Access | None = None):
    # Loopback names stay allowed for an SSH tunnel to the hotspot address.
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"{bind}:{port}"}
    access = access or Access()

    class Handler(BaseHTTPRequestHandler):
        server_version = "lab-manager"
        sys_version = ""

        def log_message(self, fmt, *args):  # no request log; status comes from the Pis
            pass

        def _host_ok(self) -> bool:
            # Only our own address names. This stops DNS rebinding: a page on another name
            # can't drive the manager.
            if self.headers.get("Host", "") not in allowed_hosts:
                return False
            origin = self.headers.get("Origin")
            return origin is None or urllib.parse.urlsplit(origin).netloc in allowed_hosts

        def _token(self) -> str:
            for part in self.headers.get("Cookie", "").split(";"):
                name, _, value = part.strip().partition("=")
                if name == COOKIE:
                    return value
            return ""

        def _signed_in(self) -> bool:
            return access.valid(self._token())

        def _send(
            self,
            status: int,
            body: bytes = b"",
            location: str | None = None,
            cookie: str | None = None,
        ):
            self.send_response(status)
            if location:
                self.send_header("Location", location)
            if cookie is not None:
                self.send_header("Set-Cookie", cookie)
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
            if not self._signed_in():
                return self._send(200, signin_page(manager.csrf, message))
            if "refresh" in query:
                manager.all_status()
            states, age = manager.snapshot()
            error = query.get("m", [""])[0] in ("refused", "badcode")
            self._send(200, render(manager, states, message, access.required, age, error))

        def do_POST(self):  # noqa: N802
            if not self._host_ok():
                return self._send(403, b"Forbidden\n")
            path = urllib.parse.urlsplit(self.path).path
            if path not in ("/do", "/signin", "/signout"):
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
            if path == "/signin":
                token = access.sign_in(form.get("code", ""))
                if token is None:
                    time.sleep(SIGNIN_FAIL_DELAY)
                    return self._send(303, location="/?m=badcode")
                cookie = f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict"
                return self._send(303, location="/", cookie=cookie)
            if path == "/signout":
                access.sign_out(self._token())
                cookie = f"{COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
                return self._send(303, location="/", cookie=cookie)
            if not self._signed_in():
                return self._send(403, b"Forbidden\n")
            pi, op, arg = form.get("pi", ""), form.get("op", ""), form.get("arg", "")
            ok = manager.act(pi, op, arg)
            anchor = f"#pi-{pi}" if NAME.fullmatch(pi) else ""
            self._send(303, location=f"/?m={'done' if ok else 'refused'}{anchor}")

    return Handler


def run_ssh(argv: list[str], timeout: float, home: Path | None = None) -> tuple[int, str]:
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}
    if home is not None:
        env["HOME"] = str(home)  # where dbclient keeps known_hosts
    done = subprocess.run(  # noqa: S603 (fixed ssh argv; the request is checked first)
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        check=False,
        env=env,
    )
    return done.returncode, done.stdout.decode("ascii", "replace")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Lab manager for the hotspot lab (#155).")
    parser.add_argument(
        "--bind",
        type=check_bind,
        default=LOOPBACK,
        help="127.0.0.1 (default, SSH tunnel) or the router's private hotspot address",
    )
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--lab-dir", type=Path, default=HERE)
    parser.add_argument(
        "--state-dir", type=Path, default=STATE, help="where the key and known hosts live"
    )
    parser.add_argument(
        "--access-code-file",
        type=Path,
        help="the sign-in code, needed unless --bind is 127.0.0.1 (default: STATE/access-code)",
    )
    parser.add_argument(
        "--ssh-client",
        choices=("openssh", "dropbear"),
        default="openssh",
        help="dropbear on the OpenWrt router (its own dbclient), openssh elsewhere",
    )
    args = parser.parse_args(argv)
    try:
        pis = load_config(args.config)
        services = load_services(args.lab_dir / "services.tsv")
        presets = load_presets(args.lab_dir / "services.tsv", args.lab_dir / "presets.tsv")
        code = None
        if args.bind != LOOPBACK:
            code = load_access_code(args.access_code_file or args.state_dir / "access-code")
    except (OSError, ConfigError) as exc:
        print(f"lab-manager: {exc}", file=sys.stderr)
        return 1
    key_name = "id_dropbear" if args.ssh_client == "dropbear" else "id_ed25519"
    manager = Manager(
        pis,
        services,
        presets,
        lambda cmd, timeout: run_ssh(cmd, timeout, home=args.state_dir),
        key=args.state_dir / key_name,
        known_hosts=args.state_dir / "known_hosts",
        client=args.ssh_client,
    )
    handler = make_handler(manager, args.port, args.bind, Access(code))
    server = ThreadingHTTPServer((args.bind, args.port), handler)
    stop = threading.Event()
    threading.Thread(target=manager.poll, args=(stop,), daemon=True).start()
    print(f"lab-manager: http://{args.bind}:{args.port}/ ({len(pis)} Pis)", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    stop.set()
    return 0


if __name__ == "__main__":
    sys.exit(main())
