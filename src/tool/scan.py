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
import re
import shutil
import subprocess  # noqa: S404 - fixed argument lists only, never a shell
import threading
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path

from tool.engine.parser import MAX_FILE_BYTES, ParseError, parse_bytes

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
# (step code, percent done of that step, seconds left or None), see `step_for_task`
Progress = Callable[[str, float, int | None], None]
# nmap arguments (without the binary), optional progress callback -> nmap's stdout, the XML
Runner = Callable[[list[str], Progress | None], bytes]

TOP_TCP_PORTS = 1000
# Catalog services whose usual port isn't in nmap's top 1,000 TCP ports: MQTT, MQTT over
# TLS, Redis, Redis on 6380 (as in V5) and MongoDB.
EXTRA_TCP_PORTS = (1883, 6379, 6380, 8883, 27017)
UDP_PORTS = (53, 123, 161, 1900, 5353)
MAX_RATE = 100  # packets per second, the brief's polite rate
NMAP_TIMEOUT_S = 15 * 60  # a stuck nmap must not hang the demo forever
# nmap writes a <taskprogress> element into its XML this often (#107). The parser ignores
# the element, so the saved file reads the same as one without it.
STATS_EVERY = "5s"
_READ_CHUNK = 64 * 1024

# Progress steps (#107). Their RO/EN names are in tool.content (SCAN_STEPS).
STEP_DEVICES = "DEVICES"  # looking for devices
STEP_TCP = "TCP"  # checking TCP ports
STEP_UDP = "UDP"  # checking UDP ports
STEP_SERVICES = "SERVICES"  # identifying services
STEP_TITLES = "TITLES"  # reading web page titles
STEP_OTHER = "OTHER"  # anything else nmap reports

_TASK_PROGRESS = re.compile(rb"<taskprogress\b([^>]{0,512})>")
_ATTR = re.compile(rb'\b(task|percent|remaining)="([^"]{0,64})"')

SERVICES_ENV = "TOOL_NMAP_SERVICES"  # explicit path to nmap-services, if not found
_SERVICES_DIRS = (
    "/usr/share/nmap",
    "/usr/local/share/nmap",
    "/opt/homebrew/share/nmap",  # Homebrew on Apple silicon
)
# The nmap that runs as root, in this order (#119). Fixed paths, so a folder the user can
# write to earlier in PATH can't put another "nmap" under sudo.
_NMAP_PATHS = (
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",  # Homebrew on Intel Macs, source installs
    "/opt/homebrew/bin/nmap",  # Homebrew on Apple silicon
    "/usr/sbin/nmap",
)

# Error codes. Their RO/EN texts are in tool.content.texts.SCAN_MESSAGES.
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


def run_nmap(args: list[str], on_progress: Progress | None = None) -> bytes:
    """Run nmap with admin rights (sudo asks for the password) and return its stdout.

    stdin and stderr stay on the terminal, so the password prompt and nmap's warnings
    reach the user. Only stdout, the XML, is captured. It is read as it arrives, so each
    <taskprogress> element reaches `on_progress` while nmap is still working (#107).
    nmap is killed after NMAP_TIMEOUT_S, or once its output passes MAX_FILE_BYTES.
    """
    nmap = nmap_binary()
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    argv = ([nmap] if is_root else ["sudo", "--", nmap]) + args
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE)  # noqa: S603
    except OSError as exc:
        raise ScanError(NMAP_FAILED, f"{type(exc).__name__}: {exc}") from exc
    timed_out = threading.Event()

    def on_timeout() -> None:
        timed_out.set()
        _stop(proc)

    timer = threading.Timer(NMAP_TIMEOUT_S, on_timeout)
    timer.daemon = True
    timer.start()
    try:
        out = _read_output(proc, on_progress)
        returncode = proc.wait()
    finally:
        timer.cancel()
        if proc.poll() is None:  # an error or Ctrl+C: never leave nmap running
            _stop(proc)
    if timed_out.is_set():
        raise ScanError(NMAP_FAILED, f"timed out after {NMAP_TIMEOUT_S} s")
    if returncode != 0:
        raise ScanError(NMAP_FAILED, f"exit code {returncode}")
    return out


def nmap_binary() -> str:
    """The nmap to run with sudo: the first system install in _NMAP_PATHS, else the one on
    PATH, but never one that this user could have replaced (#119, agent-A's review of #93).
    """
    for path in _NMAP_PATHS:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    found = shutil.which("nmap")
    if found is None:
        raise ScanError(NMAP_NOT_FOUND)
    real = os.path.realpath(found)
    if _writable(real) or _writable(os.path.dirname(real)):
        raise ScanError(NMAP_NOT_FOUND, f"{found} could be replaced by this user, not run as root")
    return found


def _writable(path: str) -> bool:
    return os.access(path, os.W_OK)


def _stop(proc: subprocess.Popen) -> None:
    """SIGTERM first, because sudo passes it on to nmap (a SIGKILL would leave nmap
    running as root without sudo). SIGKILL only if it hasn't stopped after 5 s."""
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    except OSError:
        pass  # already gone


def _read_output(proc: subprocess.Popen, on_progress: Progress | None) -> bytes:
    """nmap's stdout, read line by line as it arrives, capped at MAX_FILE_BYTES."""
    if proc.stdout is None:
        raise ScanError(NMAP_FAILED, "no output pipe")
    chunks: list[bytes] = []
    size = 0
    while line := proc.stdout.readline(_READ_CHUNK):
        size += len(line)
        if size > MAX_FILE_BYTES:
            raise ScanError(NMAP_FAILED, f"output larger than {MAX_FILE_BYTES} bytes")
        chunks.append(line)
        if on_progress is not None and b"<taskprogress" in line:
            for update in progress_updates(line):
                on_progress(*update)
    return b"".join(chunks)


def progress_updates(xml_line: bytes) -> list[tuple[str, float, int | None]]:
    """(step, percent, seconds left) for each <taskprogress> element in a line of nmap's
    XML. Only three attributes are read, and the task name becomes a fixed STEP_* code,
    so nothing nmap writes is printed as is. An element without a valid percent is
    skipped."""
    updates: list[tuple[str, float, int | None]] = []
    for match in _TASK_PROGRESS.finditer(xml_line):
        attrs = {k.decode(): v.decode("ascii", "replace") for k, v in _ATTR.findall(match[1])}
        try:
            percent = float(attrs["percent"])
        except (KeyError, ValueError):
            continue
        if not 0.0 <= percent <= 100.0:  # also drops NaN
            continue
        try:
            left: int | None = max(0, int(attrs["remaining"]))
        except (KeyError, ValueError):
            left = None
        updates.append((step_for_task(attrs.get("task", "")), percent, left))
    return updates


def step_for_task(task: str) -> str:
    """nmap's task name (ARP Ping Scan, SYN Stealth Scan, UDP Scan, Service scan, NSE,
    ...) -> one of the STEP_* codes."""
    name = task.lower()
    if "udp" in name:
        return STEP_UDP
    if "syn" in name or "connect" in name:
        return STEP_TCP
    if "service" in name:
        return STEP_SERVICES
    if "nse" in name or "script" in name:
        return STEP_TITLES
    if "ping" in name or "arp" in name or "dns" in name:
        return STEP_DEVICES
    return STEP_OTHER


def services_file(env: dict[str, str] | None = None) -> Path:
    """The installed nmap's nmap-services file: from the environment, next to the binary
    that run_nmap uses, or in the usual install folders."""
    env = env if env is not None else os.environ
    if env.get(SERVICES_ENV):
        candidates = [Path(env[SERVICES_ENV])]
    else:
        candidates = []
        try:
            binary = Path(nmap_binary()).resolve()
            candidates += [binary.parent.parent / "share/nmap", binary.parent]  # Unix, Windows
        except ScanError:
            pass  # run_nmap reports the missing nmap; the usual folders may still have the file
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
    return [
        "-sn",
        "-n",
        "--max-rate",
        str(MAX_RATE),
        "--stats-every",
        STATS_EVERY,
        "-oX",
        "-",
    ] + [str(n) for n in networks]


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
        "--stats-every",
        STATS_EVERY,
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
    on_hosts: Callable[[list[str]], None] | None = None,
    on_progress: Progress | None = None,
) -> Path:
    """Steps 2-4 for networks the guardrail has already authorized. Returns the saved XML.
    Addresses in `exclude` (this computer's own) are never port-scanned.

    `on_hosts` gets the live hosts before the port scan starts, and `on_progress` gets
    nmap's progress in both steps, so the user can see that the scan isn't stuck (#107)."""
    if not networks:
        raise ScanError(NO_LIVE_HOSTS)
    if any(n.version != 4 for n in networks):
        raise ScanError(IPV6_NOT_SUPPORTED, ", ".join(str(n) for n in networks if n.version != 4))
    if services_text is None:  # read before sudo asks for anything
        services_text = services_file().read_text(encoding="utf-8", errors="replace")
    spec = port_spec(top_tcp_ports(services_text))

    hosts = live_hosts(runner(discovery_args(networks), on_progress), networks, exclude)
    if not hosts:
        raise ScanError(NO_LIVE_HOSTS, ", ".join(str(n) for n in networks))
    if on_hosts is not None:
        on_hosts(hosts)
    xml = runner(port_scan_args(hosts, spec), on_progress)
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
