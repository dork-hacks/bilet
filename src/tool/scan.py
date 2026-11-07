"""`tool scan --confirm`: the live scan (FR-04, NFR-04, NFR-07). The only step that needs root.

Nothing runs before the previous step has passed:
1. the guardrail authorizes the targets (#18, in `tool.cli.scan_command`);
2. host discovery (`nmap -sn`) on the authorized ranges only;
3. a port scan of the live hosts that lie inside those ranges: the top 1,000 TCP ports
   from the installed nmap's own nmap-services file, plus the catalog ports outside them,
   plus UDP 53, 123, 161, 1900 and 5353, with -sV, http-title and --max-rate 100;
4. the XML is saved under scans/ for the unprivileged analyser (`analyze_file`).

Only the two nmap processes run with sudo. nmap writes its XML to stdout, so root never
creates a file: this process, as a normal user, saves it.

`--top-ports 1000` alone would miss MQTT on 1883 and Redis on 6379, and nmap applies
`--top-ports` inside a `-p` range rather than adding to it, so the port list is one
explicit `-p` built here (#20, agent-C's port-list comment).
"""

import ipaddress
import os
import shutil
import subprocess  # noqa: S404 - fixed argument lists only, never a shell
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path

from tool.engine.parser import ParseError, parse_bytes

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
# nmap arguments (without the binary) -> nmap's stdout, the XML
Runner = Callable[[list[str]], bytes]

TOP_TCP_PORTS = 1000
# Catalog services whose usual port isn't in nmap's top 1,000 TCP ports: MQTT, MQTT over
# TLS, Redis, Redis on 6380 (as in V5) and MongoDB.
EXTRA_TCP_PORTS = (1883, 6379, 6380, 8883, 27017)
UDP_PORTS = (53, 123, 161, 1900, 5353)
MAX_RATE = 100  # packets per second, the brief's polite rate
NMAP_TIMEOUT_S = 15 * 60  # a stuck nmap must not hang the demo forever

SERVICES_ENV = "TOOL_NMAP_SERVICES"  # explicit path to nmap-services, if not found
_SERVICES_DIRS = (
    "/usr/share/nmap",
    "/usr/local/share/nmap",
    "/opt/homebrew/share/nmap",  # Homebrew on Apple silicon
)

# Error codes. Their RO/EN texts are in tool.cli until area:content adopts them.
NMAP_NOT_FOUND = "NMAP_NOT_FOUND"
NMAP_DATA_NOT_FOUND = "NMAP_DATA_NOT_FOUND"
NMAP_FAILED = "NMAP_FAILED"
NO_LIVE_HOSTS = "NO_LIVE_HOSTS"
IPV6_NOT_SUPPORTED = "IPV6_NOT_SUPPORTED"


class ScanError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def run_nmap(args: list[str]) -> bytes:
    """Run nmap with admin rights (sudo asks for the password) and return its stdout.

    stdin and stderr stay on the terminal, so the password prompt and nmap's warnings
    reach the user. Only stdout, the XML, is captured.
    """
    nmap = shutil.which("nmap")
    if nmap is None:
        raise ScanError(NMAP_NOT_FOUND)
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    argv = ([nmap] if is_root else ["sudo", "--", nmap]) + args
    try:
        done = subprocess.run(argv, stdout=subprocess.PIPE, timeout=NMAP_TIMEOUT_S, check=False)  # noqa: S603
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScanError(NMAP_FAILED, f"{type(exc).__name__}: {exc}") from exc
    if done.returncode != 0:
        raise ScanError(NMAP_FAILED, f"exit code {done.returncode}")
    return done.stdout


def services_file(env: dict[str, str] | None = None) -> Path:
    """The installed nmap's nmap-services file: from the environment, next to the binary,
    or in the usual install folders."""
    env = env if env is not None else os.environ
    if env.get(SERVICES_ENV):
        candidates = [Path(env[SERVICES_ENV])]
    else:
        candidates = []
        nmap = shutil.which("nmap")
        if nmap:
            binary = Path(nmap).resolve()
            candidates += [binary.parent.parent / "share/nmap", binary.parent]  # Unix, Windows
        candidates += [Path(d) for d in _SERVICES_DIRS]
        candidates = [d / "nmap-services" for d in candidates]
    for path in candidates:
        if path.is_file():
            return path
    raise ScanError(NMAP_DATA_NOT_FOUND, ", ".join(str(p) for p in candidates))


def top_tcp_ports(services_text: str, count: int = TOP_TCP_PORTS) -> list[int]:
    """The `count` TCP ports with the highest open-frequency in an nmap-services file,
    which is what `nmap --top-ports` uses. Ties go to the lower port number."""
    best: dict[int, float] = {}
    for line in services_text.splitlines():
        fields = line.split("#", 1)[0].split()
        if len(fields) < 3 or not fields[1].endswith("/tcp"):
            continue
        try:
            port, freq = int(fields[1].split("/")[0]), float(fields[2])
        except ValueError:
            continue
        if 0 < port < 65536:
            best[port] = max(freq, best.get(port, 0.0))
    ranked = sorted(best, key=lambda p: (-best[p], p))
    return sorted(ranked[:count])


def port_spec(top_tcp: Iterable[int]) -> str:
    """One explicit nmap -p list: T:<top 1,000 + catalog extras>,U:<the brief's UDP ports>."""
    tcp = _ranges(sorted(set(top_tcp) | set(EXTRA_TCP_PORTS)))
    udp = ",".join(str(p) for p in UDP_PORTS)
    return f"T:{tcp},U:{udp}"


def discovery_args(networks: list[Network]) -> list[str]:
    """Host discovery only (ARP on the local network when run as root), no port scan."""
    return ["-sn", "-n", "--max-rate", str(MAX_RATE), "-oX", "-"] + [str(n) for n in networks]


def port_scan_args(hosts: list[str], spec: str) -> list[str]:
    """The same scan types as the standard data (`nmap -sS -sU -sV`), live hosts only."""
    return [
        "-sS",
        "-sU",
        "-sV",
        "--script",
        "http-title",
        "--max-rate",
        str(MAX_RATE),
        "-Pn",  # discovery already found these hosts up
        "-p",
        spec,
        "-oX",
        "-",
    ] + hosts


def live_hosts(
    discovery_xml: bytes, networks: list[Network], exclude: Iterable[str] = ()
) -> list[str]:
    """Up hosts from the discovery XML that lie inside an authorized range, in IP order.
    Anything else nmap reports is dropped, so the port scan never leaves the allowlist.

    `exclude` is the scanner's own address: scanning itself goes over loopback, past its
    own firewall, and nmap never sees its own MAC, so it would show up as an unknown device
    with ports the rest of the network can't reach (agent-E's review of #93)."""
    try:
        scan = parse_bytes(discovery_xml, "discovery.xml")
    except ParseError as exc:
        raise ScanError(NMAP_FAILED, f"discovery output: {exc.code}") from exc
    skip = {ipaddress.ip_address(a) for a in exclude}
    found = set()
    for host in scan.hosts:
        ip = ipaddress.ip_address(host.ip)
        if ip not in skip and any(ip.version == n.version and ip in n for n in networks):
            found.add(ip)
    return [str(ip) for ip in sorted(found)]


def run_scan(
    networks: list[Network],
    runner: Runner = run_nmap,
    scans_dir: Path = Path("scans"),
    services_text: str | None = None,
    now: datetime | None = None,
    exclude: Iterable[str] = (),
) -> Path:
    """Steps 2-4 for networks the guardrail has already authorized. Returns the saved XML.
    Addresses in `exclude` (this computer's own) are never port-scanned."""
    if not networks:
        raise ScanError(NO_LIVE_HOSTS)
    if any(n.version != 4 for n in networks):
        raise ScanError(IPV6_NOT_SUPPORTED, ", ".join(str(n) for n in networks if n.version != 4))
    if services_text is None:  # read before sudo asks for anything
        services_text = services_file().read_text(encoding="utf-8", errors="replace")
    spec = port_spec(top_tcp_ports(services_text))

    hosts = live_hosts(runner(discovery_args(networks)), networks, exclude)
    if not hosts:
        raise ScanError(NO_LIVE_HOSTS, ", ".join(str(n) for n in networks))
    xml = runner(port_scan_args(hosts, spec))
    return save_xml(xml, scans_dir, now or datetime.now(UTC))


def save_xml(xml: bytes, scans_dir: Path, now: datetime) -> Path:
    """Write the scan as scans/scan_<UTC time>.xml, readable only by this user: it holds
    real MACs and hostnames (NFR-02), and scans/ is git-ignored."""
    scans_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = now.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = scans_dir / f"scan_{stamp}.xml"
    n = 1
    while path.exists():  # two scans in the same second
        n += 1
        path = scans_dir / f"scan_{stamp}_{n}.xml"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(xml)
    return path


def _ranges(ports: list[int]) -> str:
    """[1, 2, 3, 7] -> "1-3,7": keeps the -p argument short."""
    parts: list[str] = []
    start = prev = None
    for port in ports:
        if prev is not None and port == prev + 1:
            prev = port
            continue
        if start is not None:
            parts.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = port
    if start is not None:
        parts.append(str(start) if start == prev else f"{start}-{prev}")
    return ",".join(parts)
