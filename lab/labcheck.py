"""Shared code for `lab/verify` and `lab/sanitize` (#34).

`lab/verify` checks that nmap -sV names every simulated weak service on the lab Pis (two by
default, camera and hub, plus an optional server; #128) with the catalog's service name.
`lab/sanitize` turns a raw capture into a test fixture with the device half of every MAC and
every real hostname replaced.

Stdlib only, Python 3.11+, so it runs with the scanner laptop's plain `python3 -I`, with or
without the project's virtualenv:
- XML is parsed with defusedxml when it is installed, otherwise with the stdlib parser
  after refusing any DOCTYPE other than nmap's bare `<!DOCTYPE nmaprun>`, any ENTITY
  declaration, non-UTF-8 input and files over 20 MiB. The same pre-check runs either way.
- The connected subnet comes from the engine's own detection (`tool.network`, FR-01),
  which is stdlib-only and imported straight from `src/`. If it can't run, `--subnet`
  must be given.
- The engine's XML parser drops every port that isn't `open`, but a failed check needs
  the real state (`closed`, `open|filtered`) to say what went wrong, so this file reads
  the XML itself. `lab/sanitize` still runs the engine's parser on its output when it is
  importable (it needs defusedxml).

Only the guarded scan step runs nmap, as `sudo nmap ...`, so nothing else needs root.
"""

import argparse
import csv
import ipaddress
import os
import re
import shlex
import shutil
import subprocess  # noqa: S404 - fixed argument lists, never a shell
import sys
import unicodedata
import xml.etree.ElementTree as ET  # noqa: S405 - only after the pre-check in parse_tree
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

try:
    import defusedxml
    import defusedxml.ElementTree as _defused_et
except ImportError:  # the stdlib path below is used instead
    defusedxml = None
    _defused_et = None

LAB_DIR = Path(__file__).resolve().parent
REPO_DIR = LAB_DIR.parent
SERVICES_TSV = LAB_DIR / "services.tsv"
CAPTURES_DIR = LAB_DIR / "captures"
FIXTURES_DIR = REPO_DIR / "tests" / "fixtures" / "lab"

ROLES = ("camera", "server", "hub")
MAX_XML_BYTES = 20 * 1024 * 1024

HOME_RANGES = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
CGNAT = ipaddress.ip_network("100.64.0.0/10")
MAX_SUBNET_ADDRESSES = 256  # a /24; anything bigger is a venue or office network

# The lab codes from the brief's catalog: (severity, points). Kept here, not imported from
# the engine, so the expected rows are an independent answer key for the engine.
CODES = {
    "TELNET_OPEN": ("high", 20),
    "CAMERA_STREAM_EXPOSED": ("high", 20),
    "DB_EXPOSED": ("high", 20),
    "OUTDATED_SERVICE": ("high", 20),
    "FTP_CLEARTEXT": ("medium", 10),
    "HTTP_ADMIN_CLEARTEXT": ("medium", 10),
    "SMB_EXPOSED": ("medium", 10),
    "MQTT_EXPOSED": ("medium", 10),
    "UPNP_EXPOSED": ("medium", 10),
    "SNMP_EXPOSED": ("medium", 10),
    "PRINTER_RAW_EXPOSED": ("low", 5),
    "UNKNOWN_DEVICE": ("low", 5),
    "SSH_OPEN": ("info", 0),
}


class UsageError(Exception):
    """Bad arguments or a bad status file. Exit code 2."""


class Refused(Exception):
    """The guardrail said no. Nothing was scanned. Exit code 2."""


class ScanFileError(Exception):
    """The XML file can't be read safely. Exit code 2."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


# --- services.tsv ----------------------------------------------------------------------


@dataclass(frozen=True)
class Service:
    name: str
    role: str
    kind: str  # fake | real | identity | admin (the SSH server every Pi runs)
    port: int | None
    proto: str | None
    codes: tuple[str, ...]
    points: int
    default: bool

    @property
    def key(self) -> tuple[int, str] | None:
        return None if self.port is None else (self.port, self.proto or "tcp")


@dataclass(frozen=True)
class Expect:
    """What nmap -sV must report for one service."""

    names: tuple[str, ...]
    method: str | None = None  # the usual nmap `method`; None = either is normal
    product: str | None = None  # substring, case-insensitive
    version: str | None = None  # exact
    title: str | None = None  # http-title substring, case-insensitive
    also: tuple[tuple[int, str], ...] = ()  # other ports the service may open as well


EXPECT = {
    "telnet": Expect(("telnet",), "probed"),
    "http": Expect(("http",), "probed", title="login"),
    "rtsp": Expect(("rtsp",), "probed"),
    "ftp": Expect(("ftp",), "probed", product="vsftpd", version="2.3.4"),
    "redis": Expect(("redis",), "probed"),
    "smb": Expect(("microsoft-ds", "netbios-ssn"), also=((139, "tcp"),)),
    "mqtt": Expect(("mqtt",), "probed"),
    # nmap never version-probes TCP 9100-9107 and its UPnP probe has no match lines, so
    # these two are always named from the port table (see lab/README.md).
    "ssdp": Expect(("upnp",), "table"),
    "jetdirect": Expect(("jetdirect",), "table"),
    "snmp": Expect(("snmp",)),
    "ssh": Expect(("ssh",)),
}
TABLE_NOTE = (
    "jetdirect (9100/tcp) and upnp (1900/udp) show method=table by nmap's design, not a "
    "broken fake: nmap never probes 9100-9107 and has no UPnP match lines (lab/README.md)."
)


def load_services(path: Path = SERVICES_TSV) -> tuple[Service, ...]:
    """The rows of services.tsv, plus the admin SSH server every role runs (SSH_OPEN)."""
    services: list[Service] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) < 8:
            raise UsageError(f"{path}:{number}: expected 8 tab-separated fields")
        name, role, kind, _unit, port, codes, points, default = fields[:8]
        number_proto = None if port == "-" else port.split("/")
        services.append(
            Service(
                name=name,
                role=role,
                kind=kind,
                port=int(number_proto[0]) if number_proto else None,
                proto=number_proto[1] if number_proto else None,
                codes=tuple(codes.split("+")),
                points=int(points),
                default=default == "on",
            )
        )
    for role in ROLES:
        services.append(Service("ssh", role, "admin", 22, "tcp", ("SSH_OPEN",), 0, True))
    return tuple(services)


def toggleable(services: Iterable[Service]) -> dict[str, Service]:
    return {s.name: s for s in services if s.kind != "admin"}


def lab_ports(services: Iterable[Service]) -> list[tuple[int, str]]:
    """Every port a lab service can open, sorted by protocol then number."""
    ports: set[tuple[int, str]] = set()
    for s in services:
        if s.key:
            ports.add(s.key)
            ports.update(EXPECT[s.name].also)
    return sorted(ports, key=lambda p: (p[1], p[0]))


def nmap_command(
    nmap: str, ips: Iterable[str], out: Path, services: Iterable[Service]
) -> list[str]:
    """The capture command: only the lab's ports, rate-limited, in the brief's format."""
    ports = lab_ports(services)
    tcp = ",".join(str(p) for p, proto in ports if proto == "tcp")
    udp = ",".join(str(p) for p, proto in ports if proto == "udp")
    return [
        nmap,
        "-sS",
        "-sU",
        "-sV",
        "--script",
        "http-title",
        "--max-rate",
        "100",
        "-p",
        f"T:{tcp},U:{udp}",
        "-oX",
        str(out),
        *ips,
    ]


# --- toggles ---------------------------------------------------------------------------


def _names(values: Iterable[str]) -> list[str]:
    return [n.strip() for v in values for n in v.split(",") if n.strip()]


def parse_status(text: str, services: Iterable[Service]) -> dict[str, bool]:
    """Toggle states from one or more pasted `labctl status` outputs."""
    known = toggleable(services)
    states: dict[str, bool] = {}
    role = None
    for line in text.splitlines():
        stripped = line.strip()
        match = re.match(r"Role:\s*(\S+)", stripped)
        if match:
            role = match.group(1)
            if role not in ROLES:
                raise UsageError(f"status file: unknown role '{role}'")
            continue
        parts = stripped.split()
        if not parts or parts[0] not in known:
            continue
        if stripped.endswith("ON (weak)"):
            state = True
        elif stripped.endswith(("off (fixed)", "not installed")):
            state = False
        else:
            continue
        if role is not None and known[parts[0]].role != role:
            raise UsageError(f"status file: '{parts[0]}' listed under role {role}")
        states[parts[0]] = state
    if not states:
        raise UsageError("status file: no `labctl status` rows found")
    return states


def resolve_toggles(
    services: Iterable[Service],
    on: Iterable[str] = (),
    off: Iterable[str] = (),
    status_text: str | None = None,
) -> dict[str, bool]:
    """services.tsv defaults, then the status file, then --on / --off."""
    services = tuple(services)
    known = toggleable(services)
    states = {name: s.default for name, s in known.items()}
    if status_text is not None:
        states.update(parse_status(status_text, services))
    on_names, off_names = _names(on), _names(off)
    for name in on_names + off_names:
        if name not in known:
            raise UsageError(f"unknown service '{name}'. Known: {', '.join(known)}")
    both = set(on_names) & set(off_names)
    if both:
        raise UsageError(f"both --on and --off: {', '.join(sorted(both))}")
    states.update(dict.fromkeys(on_names, True))
    states.update(dict.fromkeys(off_names, False))
    return states


def is_on(service: Service, toggles: dict[str, bool]) -> bool:
    return True if service.kind == "admin" else toggles.get(service.name, False)


# --- guardrail -------------------------------------------------------------------------


def check_ip(label: str, text: str) -> ipaddress.IPv4Address:
    """A single private (RFC 1918) IPv4 address, or Refused. Names are never accepted."""
    try:
        addr = ipaddress.ip_address((text or "").strip())
    except ValueError:
        raise Refused(f"{label} {text!r}: not an IP address (names can resolve anywhere)") from None
    if addr.version != 4:
        raise Refused(f"{label} {addr}: the lab is IPv4 only")
    if addr.is_loopback:
        raise Refused(f"{label} {addr}: loopback is this computer, not a lab Pi")
    if addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        raise Refused(f"{label} {addr}: not a device address")
    if addr in CGNAT:
        raise Refused(f"{label} {addr}: 100.64.0.0/10 is the mobile operator's network")
    if not any(addr in net for net in HOME_RANGES):
        raise Refused(f"{label} {addr}: public address. Only our own hotspot may be scanned")
    return addr


def check_subnet(text: str) -> ipaddress.IPv4Network:
    try:
        net = ipaddress.ip_network((text or "").strip(), strict=False)
    except ValueError:
        raise Refused(f"subnet {text!r}: not a network like 10.42.0.0/24") from None
    if net.version != 4 or not any(net.subnet_of(home) for home in HOME_RANGES):
        raise Refused(f"subnet {net}: not a private RFC 1918 network")
    if net.num_addresses > MAX_SUBNET_ADDRESSES:
        raise Refused(f"subnet {net}: larger than a /24, so not our hotspot (venue network?)")
    return net


def resolve_subnet(
    arg: str | None, detected: tuple[str, str] | None
) -> tuple[ipaddress.IPv4Network, str | None, list[str]]:
    """The connected subnet and this computer's address. Detection wins over --subnet."""
    notes: list[str] = []
    if detected is None:
        if not arg:
            raise Refused(
                "can't detect the connected network here; pass --subnet (the hotspot's, "
                "e.g. 10.42.0.0/24) after checking it with `ip -4 addr` or `ifconfig`"
            )
        notes.append(f"connected network not detected; using --subnet {arg} as given")
        return check_subnet(arg), None, notes
    subnet_text, own_ip = detected
    subnet = check_subnet(subnet_text)
    if arg and check_subnet(arg) != subnet:
        raise Refused(f"--subnet {arg} is not the network this computer is on ({subnet})")
    return subnet, own_ip, notes


def authorize_scan(
    roles: dict[str, str],
    subnet: ipaddress.IPv4Network,
    own_ip: str | None,
    confirm: bool,
) -> list[str]:
    """Every check must pass before anything is scanned. Returns the IPs in role order."""
    if not roles:
        raise Refused("give at least one Pi: --camera IP, --server IP, --hub IP")
    ips: list[str] = []
    for role, text in roles.items():
        addr = check_ip(f"--{role}", text)
        if addr not in subnet:
            raise Refused(f"--{role} {addr}: outside the connected network {subnet}")
        if subnet.prefixlen <= 30 and addr in (subnet.network_address, subnet.broadcast_address):
            raise Refused(f"--{role} {addr}: the network or broadcast address of {subnet}")
        if own_ip and str(addr) == own_ip:
            raise Refused(f"--{role} {addr}: that is this computer, not a lab Pi")
        if str(addr) in ips:
            raise Refused(f"--{role} {addr}: the same IP is given for two roles")
        ips.append(str(addr))
    if not confirm:
        raise Refused(
            f"add --confirm to scan {', '.join(ips)} (or --print-only to see the command)"
        )
    return ips


def detect_network() -> tuple[str, str] | None:
    """(subnet, own address) from the engine's FR-01 detection, None if it can't run here.

    Refused when the computer is on no network or on several at once: the brief says the
    scanner must be on the hotspot and nothing else.
    """
    src = REPO_DIR / "src"
    if (src / "tool" / "network.py").is_file() and str(src) not in sys.path:
        sys.path.insert(0, str(src))
    try:
        from tool import network
    except ImportError:
        return None
    try:
        net = network.detect()
    except network.DetectError as exc:
        if exc.code == network.DETECT_FAILED:
            return None
        raise Refused(
            f"network check failed ({exc.code}: {exc.detail}). The scanner must be on the "
            "hotspot and on no other network: unplug Ethernet, leave other Wi-Fi, turn off VPNs"
        ) from None
    return net.subnet, net.address


# --- reading nmap XML ------------------------------------------------------------------

_DOCTYPE = re.compile(r"<!DOCTYPE")
_NMAP_DOCTYPE = re.compile(r"<!DOCTYPE\s+nmaprun\s*>")
_ENCODING = re.compile(r"""<\?xml[^>]*?encoding\s*=\s*["']([^"']+)["']""")


def parse_tree(data: bytes) -> ET.Element:
    """The root of an nmap XML document, or ScanFileError. Never resolves entities."""
    if not data:
        raise ScanFileError("EMPTY_FILE")
    if len(data) > MAX_XML_BYTES:
        raise ScanFileError("TOO_LARGE", f"over {MAX_XML_BYTES} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ScanFileError("NOT_XML", "not UTF-8 (nmap writes UTF-8)") from None
    declared = _ENCODING.match(text.lstrip("﻿"))
    if declared and declared.group(1).lower() not in ("utf-8", "utf8", "us-ascii", "ascii"):
        raise ScanFileError("NOT_XML", f"encoding {declared.group(1)!r}")
    if "<!ENTITY" in text:
        raise ScanFileError("UNSAFE_XML", "entity declaration")
    for match in _DOCTYPE.finditer(text):
        if not _NMAP_DOCTYPE.match(text, match.start()):
            raise ScanFileError("UNSAFE_XML", "DOCTYPE other than <!DOCTYPE nmaprun>")
    try:
        if _defused_et is not None:
            root = _defused_et.fromstring(
                data, forbid_dtd=False, forbid_entities=True, forbid_external=True
            )
        else:
            root = ET.fromstring(data)  # noqa: S314 - DOCTYPE and ENTITY refused above
    except ET.ParseError as exc:
        raise ScanFileError("NOT_XML", str(exc)) from None
    except (ValueError, LookupError) as exc:  # defusedxml's refusals are ValueErrors
        if defusedxml is not None and isinstance(exc, defusedxml.DefusedXmlException):
            raise ScanFileError("UNSAFE_XML", type(exc).__name__) from None
        raise ScanFileError("NOT_XML", f"{type(exc).__name__}: {exc}") from None
    if root.tag != "nmaprun":
        raise ScanFileError("NOT_NMAP", f"root element <{clean(root.tag, 40)}>")
    return root


def read_capture(path: Path) -> bytes:
    try:
        if path.stat().st_size > MAX_XML_BYTES:
            raise ScanFileError("TOO_LARGE", f"over {MAX_XML_BYTES} bytes")
        with path.open("rb") as fh:
            return fh.read(MAX_XML_BYTES + 1)
    except OSError as exc:
        raise ScanFileError("NOT_XML", f"cannot read {path}: {exc.strerror}") from None


@dataclass(frozen=True)
class Port:
    port: int
    proto: str
    state: str
    name: str | None
    product: str | None
    version: str | None
    tunnel: str | None
    method: str | None
    title: str | None


@dataclass(frozen=True)
class Host:
    ip: str
    up: bool
    mac: str | None
    vendor: str | None
    hostnames: tuple[str, ...]
    ports: dict[tuple[int, str], Port]

    @property
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports.values() if p.state == "open"]


def clean(value: str | None, limit: int = 256) -> str | None:
    """Untrusted text from the scan: no control or format characters, capped. Empty -> None."""
    if value is None:
        return None
    text = "".join(" " if unicodedata.category(c) in ("Cc", "Cf") else c for c in value)
    text = " ".join(text.split())[:limit]
    return text or None


_NOT_A_TITLE = ("did not follow redirect", "site doesn't have a title", "request failed")


def _title(port_el: ET.Element) -> str | None:
    for script in port_el.findall("script"):
        if script.get("id") != "http-title":
            continue
        elems = script.findall("elem")
        if elems:
            return next((clean(e.text) for e in elems if e.get("key") == "title"), None)
        output = clean(script.get("output"))
        if output and not output.lower().startswith(_NOT_A_TITLE):
            return output
    return None


def hosts_of(root: ET.Element) -> dict[str, Host]:
    """Every host with an IPv4 address, ports in any state. The first entry per IP wins."""
    hosts: dict[str, Host] = {}
    for el in root.iter("host"):
        status = el.find("status")
        ip = mac = vendor = None
        for addr in el.findall("address"):
            kind = addr.get("addrtype")
            if kind == "ipv4" and ip is None:
                ip = clean(addr.get("addr"), 15)
            elif kind == "mac" and mac is None:
                mac = clean(addr.get("addr"), 17)
                vendor = clean(addr.get("vendor"), 80)
        if ip is None or ip in hosts:
            continue
        ports: dict[tuple[int, str], Port] = {}
        for p in el.findall("ports/port"):
            try:
                number = int(p.get("portid", ""))
            except ValueError:
                continue
            state_el, svc = p.find("state"), p.find("service")
            sget = (lambda k, s=svc: clean(s.get(k), 80)) if svc is not None else (lambda k: None)
            port = Port(
                port=number,
                proto=p.get("protocol", ""),
                state=(state_el.get("state", "") if state_el is not None else "") or "unknown",
                name=sget("name"),
                product=sget("product"),
                version=sget("version"),
                tunnel=sget("tunnel"),
                method=sget("method"),
                title=_title(p),
            )
            ports.setdefault((port.port, port.proto), port)
        hosts[ip] = Host(
            ip=ip,
            up=status is None or status.get("state") == "up",
            mac=mac,
            vendor=vendor,
            hostnames=tuple(
                n for n in (clean(h.get("name"), 80) for h in el.findall("hostnames/hostname")) if n
            ),
            ports=ports,
        )
    return hosts


def mask_mac(mac: str | None) -> str:
    return "-" if not mac else mac.upper()[:8] + ":xx:xx:xx"


# --- checking a capture ----------------------------------------------------------------

PASS, FAIL, WARN, INFO = "PASS", "FAIL", "WARN", "INFO"


@dataclass(frozen=True)
class Row:
    role: str
    ip: str
    port: str  # "2323/tcp", or "identity"
    expected: str
    got: str
    method: str
    result: str
    note: str = ""


def _describe(p: Port | None) -> str:
    if p is None:
        return "not open (extraports)"
    parts = [p.state, p.name or "?"]
    detail = " ".join(x for x in (p.product, p.version) if x)
    if detail:
        parts.append(f"({detail})")
    if p.tunnel:
        parts.append(f"[{p.tunnel}]")
    return " ".join(parts)


def _match(svc: Service, p: Port) -> tuple[str, str]:
    """(result, note) for an open port that a switched-on service should own."""
    want = EXPECT[svc.name]
    problems: list[str] = []
    if p.name not in want.names:
        problems.append(f"service name {p.name!r}, catalog needs {' or '.join(want.names)}")
    if want.product and want.product not in (p.product or "").lower():
        problems.append(f"product {p.product!r}, needs {want.product}")
    if want.version and p.version != want.version:
        problems.append(f"version {p.version!r}, needs {want.version} (OUTDATED_SERVICE)")
    if svc.name == "http":
        if p.tunnel == "ssl":
            problems.append("served over SSL: HTTP_ADMIN_CLEARTEXT needs plain http")
        if want.title and want.title not in (p.title or "").lower():
            problems.append(f"title {clean(p.title, 40)!r} doesn't contain '{want.title}'")
    if problems:
        return FAIL, "; ".join(problems)
    notes = []
    if svc.name == "http":
        notes.append(f"title {clean(p.title, 40)!r}")
    if want.method and p.method and p.method != want.method:
        notes.append(f"method={p.method}, usually {want.method}")
        return WARN, "; ".join(notes)
    if want.method == "table" and p.method == "table":
        notes.append("table is expected (nmap design)")
    if svc.name == "smb" and p.version and " - " in p.version:
        notes.append(f"version range {p.version!r}: see #8 item 1")
    return PASS, "; ".join(notes)


def _closed_hint(svc: Service, p: Port | None) -> str:
    if p is not None and p.state == "open|filtered":
        return "no reply nmap could name (open|filtered); is the daemon up? `labctl status`"
    if p is not None and p.state == "filtered":
        return "filtered: a firewall on the Pi or client isolation on the hotspot?"
    return "not open: `labctl status` on the Pi, then `sudo labctl break " + svc.name + "`"


def _role_rows(
    role: str, host: Host, services: list[Service], toggles: dict[str, bool]
) -> list[Row]:
    rows: list[Row] = []
    owners: dict[tuple[int, str], tuple[Service, bool]] = {}  # port -> (service, primary)
    for svc in services:
        if svc.key:
            owners[svc.key] = (svc, True)
            for extra in EXPECT[svc.name].also:
                owners.setdefault(extra, (svc, False))
    keys = set(owners) | {k for k, p in host.ports.items() if p.state == "open"}
    for key in sorted(keys, key=lambda k: (k[1], k[0])):
        p = host.ports.get(key)
        is_open = p is not None and p.state == "open"
        label = f"{key[0]}/{key[1]}"

        def add(expected: str, result: str, note: str = "", p=p, label=label) -> None:
            method = (p.method or "-") if p else "-"
            rows.append(Row(role, host.ip, label, expected, _describe(p), method, result, note))

        owner = owners.get(key)
        if owner is None:
            if is_open:
                add("closed", FAIL, "unexpected open port: not a lab service of this role")
            continue
        svc, primary = owner
        names = "/".join(EXPECT[svc.name].names)
        if not is_on(svc, toggles):
            if is_open:
                add(
                    f"{svc.name} off",
                    FAIL,
                    f"toggled off but still open: sudo labctl fix {svc.name}",
                )
            else:
                add(f"{svc.name} off", PASS)
        elif not primary:  # e.g. smb's 139: may be open, need not be
            if is_open:
                add(f"{names} (optional)", *_match(svc, p))
        elif not is_open:
            add(f"open {names}", FAIL, _closed_hint(svc, p))
        else:
            add(f"open {names}", *_match(svc, p))
    return rows


def _would_be_unknown(host: Host) -> bool:
    return host.vendor is None and not host.hostnames and bool(host.open_ports)


def _identity(role: str, host: Host, toggles: dict[str, bool]) -> tuple[str, str, str]:
    """(expected, result, note) for the MAC vendor / hostname of one Pi."""
    if role == "hub" and toggles.get("unknown", False):
        expected = "no vendor, no hostname"
        if _would_be_unknown(host):
            note = "UNKNOWN_DEVICE expected"
            if host.mac is None:
                note += "; but no MAC at all: was the scan run from the hotspot?"
            return expected, PASS, note
        why = []
        if host.vendor:
            why.append("has a MAC vendor (random MAC not active? reboot the hub)")
        if host.hostnames:
            why.append("has a hostname (DHCP still sends it? reboot the hub)")
        if not host.open_ports:
            why.append("no open port")
        return expected, FAIL, "UNKNOWN_DEVICE won't appear: " + "; ".join(why)
    expected = "Raspberry Pi vendor"
    if _would_be_unknown(host):
        return expected, FAIL, "no vendor and no hostname: a false UNKNOWN_DEVICE"
    if "raspberry" not in (host.vendor or "").lower():
        return expected, WARN, "no Raspberry Pi vendor: random MAC on? scanned from elsewhere?"
    return expected, PASS, ""


def _identity_row(role: str, host: Host, toggles: dict[str, bool]) -> Row:
    names = ", ".join(host.hostnames) or "-"
    got = f"MAC {mask_mac(host.mac)}, vendor {host.vendor or '-'}, hostname {names}"
    expected, result, note = _identity(role, host, toggles)
    return Row(role, host.ip, "identity", expected, got, "-", result, note)


def check_capture(
    hosts: dict[str, Host],
    roles: dict[str, str],
    toggles: dict[str, bool],
    services: Iterable[Service],
    scanner_ip: str | None = None,
) -> list[Row]:
    services = tuple(services)
    rows: list[Row] = []
    for role, ip in roles.items():
        host = hosts.get(ip)
        if host is None or not host.up:
            rows.append(
                Row(
                    role,
                    ip,
                    "-",
                    "host up",
                    "not in scan" if host is None else "down",
                    "-",
                    FAIL,
                    "wrong IP? the hub's IP can change after a reboot",
                )
            )
            continue
        role_services = [s for s in services if s.role == role and s.key]
        rows.extend(_role_rows(role, host, role_services, toggles))
        rows.append(_identity_row(role, host, toggles))
    for ip, host in hosts.items():
        if ip in roles.values() or not host.up:
            continue
        open_ports = ", ".join(f"{p.port}/{p.proto}" for p in host.open_ports) or "none"
        got = f"open: {open_ports}; MAC {mask_mac(host.mac)}"
        if ip == scanner_ip and host.open_ports and host.mac is None:
            rows.append(
                Row(
                    "scanner",
                    ip,
                    "-",
                    "-",
                    got,
                    "-",
                    WARN,
                    "this laptop: open ports and no MAC, so a false UNKNOWN_DEVICE "
                    "unless the analyser skips the scanner's own IP",
                )
            )
        elif _would_be_unknown(host):
            rows.append(
                Row(
                    "other",
                    ip,
                    "-",
                    "-",
                    got,
                    "-",
                    WARN,
                    "not a lab Pi, would add UNKNOWN_DEVICE; sanitize drops it",
                )
            )
        else:
            rows.append(
                Row("other", ip, "-", "-", got, "-", INFO, "not a lab Pi; sanitize drops it")
            )
    return rows


def format_rows(rows: list[Row]) -> str:
    header = ("ROLE", "IP", "PORT", "EXPECTED", "GOT", "METHOD", "RESULT", "NOTE")
    table = [header] + [
        (r.role, r.ip, r.port, r.expected, r.got, r.method, r.result, r.note) for r in rows
    ]
    widths = [max(len(line[i]) for line in table) for i in range(len(header) - 1)]
    out = []
    for line in table:
        cells = [cell.ljust(widths[i]) for i, cell in enumerate(line[:-1])]
        out.append("  ".join([*cells, line[-1]]).rstrip())
    return "\n".join(out)


# --- the expected answer key -----------------------------------------------------------


def _ip_key(ip: str) -> int:
    return int(ipaddress.ip_address(ip))


def _port_key(port: str) -> int:
    return int(port) if port else -1  # UNKNOWN_DEVICE (empty port) sorts first, like the engine


def expected_rows(
    file: str, roles: dict[str, str], toggles: dict[str, bool], services: Iterable[Service]
) -> list[tuple[str, str, str, str, str]]:
    """findings.csv rows the lab should produce, from services.tsv and the toggles alone."""
    rows = []
    for svc in services:
        ip = roles.get(svc.role)
        if ip is None or not is_on(svc, toggles):
            continue
        for code in svc.codes:
            port = "" if code == "UNKNOWN_DEVICE" or svc.port is None else str(svc.port)
            rows.append((file, ip, port, code, CODES[code][0]))
    return sorted(rows, key=lambda r: (r[0], _ip_key(r[1]), _port_key(r[2]), r[3]))


def expected_score(rows: Iterable[tuple[str, ...]]) -> int:
    return max(0, 100 - sum(CODES[r[3]][1] for r in rows))


def missing_points(
    roles: dict[str, str], toggles: dict[str, bool], services: Iterable[Service]
) -> dict[str, int]:
    """Roles with no IP given that still have points switched on. A role whose services
    are all off (the optional third device in the default lab, #128) isn't missing."""
    missing: dict[str, int] = {}
    for svc in services:
        if svc.role not in roles and svc.points and is_on(svc, toggles):
            missing[svc.role] = missing.get(svc.role, 0) + svc.points
    return missing


def format_expected(rows: list[tuple[str, ...]], missing: dict[str, int] | None = None) -> str:
    codes = sorted({r[3] for r in rows})
    gaps = ", ".join(f"{role} ({pts} points switched on)" for role, pts in (missing or {}).items())
    lines = [
        f"Expected from services.tsv and the toggles: {len(rows)} findings, "
        f"{len(codes)} finding types, score {expected_score(rows)}"
        + (f". Not counted, no IP given: {gaps}" if gaps else ""),
        "Draft findings.csv rows (hand-check them; they don't come from the engine):",
        *(",".join(r) for r in rows),
    ]
    return "\n".join(lines)


def merge_expected(directory: Path, file: str, rows: list[tuple[str, ...]], score: int) -> None:
    """Replace `file`'s rows in expected_findings.csv / expected_scores.csv (CRLF, sorted)."""
    directory.mkdir(parents=True, exist_ok=True)
    findings_path = directory / "expected_findings.csv"
    scores_path = directory / "expected_scores.csv"
    findings = [r for r in _read_csv(findings_path) if r[0] != file] + [list(r) for r in rows]
    findings.sort(key=lambda r: (r[0], _ip_key(r[1]), _port_key(r[2]), r[3]))
    scores = [r for r in _read_csv(scores_path) if r[0] != file] + [[file, str(score)]]
    scores.sort(key=lambda r: r[0])
    _write_csv(findings_path, ["file", "ip", "port", "finding_code", "severity"], findings)
    _write_csv(scores_path, ["file", "network_score"], scores)


def _read_csv(path: Path) -> list[list[str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as fh:
        return [r for r in list(csv.reader(fh))[1:] if r]


def _write_csv(path: Path, header: list[str], rows: list[list[str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:  # csv writes \r\n
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerows(rows)


# --- sanitising a capture --------------------------------------------------------------

_MAC = re.compile(
    r"(?<![0-9A-Fa-f:-])((?:[0-9A-Fa-f]{2}[:-]){2}[0-9A-Fa-f]{2})[:-]"
    r"(?:[0-9A-Fa-f]{2}[:-]){2}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])"
)
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,80}\.xml")


def role_mac(mac: str, role: str) -> str:
    """Keep the OUI (vendor half), replace the device half with the role's number."""
    oui = mac.upper().replace("-", ":")[:8]
    return f"{oui}:00:00:{ROLES.index(role) + 1:02X}"


def _ipv4_of(el: ET.Element) -> str | None:
    for addr in el.findall("address"):
        if addr.get("addrtype") == "ipv4":
            return (addr.get("addr") or "").strip()
    return None


def sanitize_xml(data: bytes, roles: dict[str, str], name: str) -> tuple[str, list[str]]:
    """A fixture-safe copy of a capture: (XML text, notes). Raises ScanFileError/UsageError."""
    root = parse_tree(data)
    role_of = {ip: role for role, ip in roles.items()}
    notes: list[str] = []
    real_names: dict[str, str] = {}  # real hostname or label -> role name
    kept_macs: set[str] = set()

    for el in list(root):
        if el.tag not in ("host", "hosthint"):
            continue
        ip = _ipv4_of(el)
        role = role_of.get(ip or "")
        if role is None:
            root.remove(el)
            if el.tag == "host":
                notes.append(f"removed {ip or 'a host without IPv4'} (not a lab Pi)")
            continue
        for addr in el.findall("address"):
            if addr.get("addrtype") == "mac" and addr.get("addr"):
                addr.set("addr", role_mac(addr.get("addr", ""), role))
                kept_macs.add(addr.get("addr", ""))
        for n, hostname in enumerate(el.findall("hostnames/hostname")):
            real = (hostname.get("name") or "").strip()
            new = role if n == 0 else f"{role}-{n + 1}"
            if real:
                real_names.setdefault(real.lower(), new)
                label = real.split(".")[0]
                if len(label) >= 3:
                    real_names.setdefault(label.lower(), new)
            hostname.set("name", new)
    for ip, role in role_of.items():
        if not any(el.tag == "host" and _ipv4_of(el) == ip for el in root):
            notes.append(f"{role} {ip} is not in the capture")

    patterns = [
        (re.compile(r"(?<![A-Za-z0-9-])" + re.escape(real) + r"(?![A-Za-z0-9-])", re.I), new)
        for real, new in sorted(real_names.items(), key=lambda kv: -len(kv[0]))
    ]

    def scrub(text: str | None) -> str | None:
        if not text:
            return text
        for pattern, new in patterns:
            text = pattern.sub(new, text)
        return _MAC.sub(
            lambda m: m.group(0)
            if m.group(0).upper() in kept_macs
            else m.group(1).upper().replace("-", ":") + ":00:00:00",
            text,
        )

    for el in root.iter():
        el.text, el.tail = scrub(el.text), scrub(el.tail)
        for key, value in el.attrib.items():
            el.set(key, scrub(value) or "")
    root.set("args", re.sub(r"(-oX\s+)\S+", lambda m: m.group(1) + name, root.get("args", "")))
    hosts_el = root.find("runstats/hosts")
    if hosts_el is not None:
        up = sum(
            1
            for el in root.findall("host")
            if (el.find("status") is None or el.find("status").get("state") == "up")
        )
        down = int(hosts_el.get("down", "0") or 0)
        hosts_el.set("up", str(up))
        hosts_el.set("total", str(up + down))

    body = ET.tostring(root, encoding="unicode")
    text = f'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n{body}\n'
    _check_sanitized(text, roles, kept_macs, real_names)
    return text, notes


def _check_sanitized(
    text: str, roles: dict[str, str], kept_macs: set[str], real_names: dict[str, str]
) -> None:
    hosts = hosts_of(parse_tree(text.encode("utf-8")))
    stray = set(hosts) - set(roles.values())
    if stray:
        raise UsageError(f"sanitize left non-lab hosts: {', '.join(sorted(stray))}")
    for match in _MAC.finditer(text):
        mac = match.group(0).upper()
        if mac not in kept_macs and not mac.endswith(":00:00:00"):
            raise UsageError("sanitize left a raw MAC address")
    lowered = text.lower()
    for real in real_names:
        if real in lowered and real not in ROLES:
            # only a whole-word hit is a leak; a substring of another word is fine
            if re.search(r"(?<![a-z0-9-])" + re.escape(real) + r"(?![a-z0-9-])", lowered):
                raise UsageError("sanitize left a real hostname")


def engine_parse(text: str, name: str) -> str:
    """Run the engine's parser on sanitised output. Returns a status line."""
    src = REPO_DIR / "src"
    if (src / "tool").is_dir() and str(src) not in sys.path:
        sys.path.insert(0, str(src))
    try:
        from tool.engine.parser import ParseError, parse_bytes
    except ImportError as exc:  # no defusedxml outside the venv, or Python < 3.11
        return (
            f"engine parser not available here ({exc}); run `make setup` and use .venv/bin/python"
        )
    try:
        parsed = parse_bytes(text.encode("utf-8"), name)
    except ParseError as exc:
        raise UsageError(f"the engine's parser rejects the sanitised file: {exc}") from None
    return f"engine parser: OK, {len(parsed.hosts)} hosts"


# --- command line ----------------------------------------------------------------------


def _common_args(parser: argparse.ArgumentParser) -> None:
    for role in ROLES:
        parser.add_argument(f"--{role}", metavar="IP", help=f"IP of the {role} Pi")
    parser.add_argument(
        "--on",
        action="append",
        default=[],
        metavar="SVC[,SVC]",
        help="services switched on (default: services.tsv 'default')",
    )
    parser.add_argument(
        "--off", action="append", default=[], metavar="SVC[,SVC]", help="services switched off"
    )
    parser.add_argument(
        "--status-file",
        type=Path,
        metavar="FILE",
        help="pasted `labctl status` output from the Pis",
    )


def _roles(args: argparse.Namespace) -> dict[str, str]:
    return {r: getattr(args, r).strip() for r in ROLES if getattr(args, r)}


def _toggles(args: argparse.Namespace, services: tuple[Service, ...]) -> dict[str, bool]:
    status = None
    if args.status_file:
        try:
            status = args.status_file.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise UsageError(f"{args.status_file}: {exc.strerror}") from None
    return resolve_toggles(services, args.on, args.off, status)


def _check_roles_format(roles: dict[str, str]) -> None:
    for role, ip in roles.items():
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            raise UsageError(f"--{role} {ip!r}: not an IPv4 address") from None


def run_command(argv: list[str]) -> int:
    return subprocess.run(argv, check=False).returncode  # noqa: S603 - fixed argv, no shell


def verify_main(
    argv: list[str] | None = None,
    *,
    detector: Callable[[], tuple[str, str] | None] = detect_network,
    runner: Callable[[list[str]], int] = run_command,
    which: Callable[[str], str | None] = shutil.which,
    now: Callable[[], datetime] = datetime.now,
) -> int:
    parser = argparse.ArgumentParser(
        prog="lab/verify",
        description="Scan the lab Pis and check that nmap -sV names every weak "
        "service with the catalog's service name (#34). Only our own hotspot.",
    )
    _common_args(parser)
    parser.add_argument("--xml", type=Path, metavar="FILE", help="check this capture, no scan")
    parser.add_argument("--subnet", help="the hotspot subnet, checked against the detected one")
    parser.add_argument("--confirm", action="store_true", help="really scan (runs sudo nmap)")
    parser.add_argument("--print-only", action="store_true", help="print the nmap command only")
    parser.add_argument("--out", type=Path, help="capture file (default lab/captures/scan_*.xml)")
    parser.add_argument("--scanner-ip", help="this laptop's IP, for the self-scan warning")
    args = parser.parse_args(argv)
    services = load_services()
    try:
        roles = _roles(args)
        toggles = _toggles(args, services)
        if args.xml:
            _check_roles_format(roles)
            if not roles:
                raise UsageError("give the Pis' IPs: --camera IP --hub IP [--server IP]")
            scanner_ip = args.scanner_ip
            if scanner_ip is None:
                try:
                    found = detector()
                except Refused:
                    found = None
                scanner_ip = found[1] if found else None
            return _check_file(args.xml, roles, toggles, services, scanner_ip)
        subnet, own_ip, notes = resolve_subnet(args.subnet, detector())
        for note in notes:
            print(f"note: {note}")
        ips = authorize_scan(roles, subnet, own_ip, args.confirm or args.print_only)
    except UsageError as exc:
        print(f"lab/verify: {exc}", file=sys.stderr)
        return 2
    except Refused as exc:
        print(f"lab/verify: REFUSED, nothing scanned: {exc}", file=sys.stderr)
        return 2

    out = args.out or CAPTURES_DIR / f"scan_{now():%Y%m%d-%H%M%S}.xml"
    out = out.resolve()
    nmap = which("nmap")
    if nmap is None and not args.print_only:
        print(
            "lab/verify: nmap not found (Linux: apt install nmap, macOS: brew install nmap)",
            file=sys.stderr,
        )
        return 2
    command = nmap_command(nmap or "nmap", ips, out, services)
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        command = ["sudo", "--", *command]  # only nmap gets root, for -sS / -sU
    print(f"Scope OK: {', '.join(f'{r} {ip}' for r, ip in roles.items())} in {subnet}")
    print("nmap command:\n  " + shlex.join(command))
    if args.print_only:
        return 0
    if out.exists():
        print(f"lab/verify: {out} already exists", file=sys.stderr)
        return 2
    out.parent.mkdir(parents=True, exist_ok=True)
    code = runner(command)
    if code != 0 or not out.exists():
        print(f"lab/verify: nmap failed (exit {code}); no capture to check", file=sys.stderr)
        return 1
    print(f"\nCapture: {out}\n")
    return _check_file(out, roles, toggles, services, own_ip)


def _check_file(
    path: Path,
    roles: dict[str, str],
    toggles: dict[str, bool],
    services: tuple[Service, ...],
    scanner_ip: str | None,
) -> int:
    try:
        hosts = hosts_of(parse_tree(read_capture(path)))
    except ScanFileError as exc:
        print(f"lab/verify: {path}: unreadable ({exc})", file=sys.stderr)
        return 2
    rows = check_capture(hosts, roles, toggles, services, scanner_ip)
    on = sorted(n for n, v in toggles.items() if v)
    print(f"Checking {path.name}. Switched on: {', '.join(on) or 'nothing'} (+ ssh on every Pi)\n")
    print(format_rows(rows))
    print(f"\nNote: {TABLE_NOTE}")
    print()
    rows_expected = expected_rows(path.name, roles, toggles, services)
    print(format_expected(rows_expected, missing_points(roles, toggles, services)))
    fails = sum(r.result == FAIL for r in rows)
    warns = sum(r.result == WARN for r in rows)
    print(f"\n{'FAIL' if fails else 'PASS'}: {fails} failed, {warns} warnings, {len(rows)} checks")
    return 1 if fails else 0


def sanitize_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="lab/sanitize",
        description="Copy a capture to tests/fixtures/lab/ with MAC device halves and real "
        "hostnames replaced and non-lab hosts removed (NFR-02).",
    )
    parser.add_argument("capture", type=Path, help="raw capture, e.g. lab/captures/scan_*.xml")
    parser.add_argument("name", help="fixture file name, e.g. L1_default.xml")
    _common_args(parser)
    parser.add_argument("--out-dir", type=Path, default=FIXTURES_DIR)
    parser.add_argument("--force", action="store_true", help="overwrite an existing fixture")
    parser.add_argument(
        "--expected",
        action="store_true",
        help="also write this file's rows into expected_findings.csv / "
        "expected_scores.csv in --out-dir",
    )
    args = parser.parse_args(argv)
    services = load_services()
    try:
        if not _SAFE_NAME.fullmatch(args.name):
            raise UsageError(f"name {args.name!r}: a plain file name ending in .xml")
        roles = _roles(args)
        _check_roles_format(roles)
        if not roles:
            raise UsageError("give the Pis' IPs: --camera IP --hub IP [--server IP]")
        toggles = _toggles(args, services)
        target = args.out_dir / args.name
        if target.exists() and not args.force:
            raise UsageError(f"{target} exists (use --force to overwrite)")
        text, notes = sanitize_xml(read_capture(args.capture), roles, args.name)
        status = engine_parse(text, args.name)
    except (UsageError, ScanFileError) as exc:
        print(f"lab/sanitize: {exc}", file=sys.stderr)
        return 2
    args.out_dir.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".xml.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, target)
    for note in notes:
        print(f"note: {note}")
    print(f"Wrote {target}\n{status}\n")
    rows = expected_rows(args.name, roles, toggles, services)
    print(format_expected(rows, missing_points(roles, toggles, services)))
    if args.expected:
        merge_expected(args.out_dir, args.name, rows, expected_score(rows))
        print(f"\nUpdated {args.out_dir / 'expected_findings.csv'} and expected_scores.csv")
    return 0
