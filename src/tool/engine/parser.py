"""Safe nmap XML parser (FR-05, NFR-03).

Turns one nmap XML file into plain host and port records, or raises ParseError
with one of the error codes from docs/contracts/data-model.md. Every string
copied from the file is RAW: capped and stripped of control and format
characters, nothing more. Callers must escape it before display and never pass
it to an LLM as is.
"""

import ipaddress
import os
import re
import unicodedata
import xml.etree.ElementTree as ET  # noqa: S405 - only for ParseError and type hints
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import defusedxml
import defusedxml.ElementTree as SafeET

MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_RAW_CHARS = 256
# Titles stay longer here so a keyword past character 256 still reaches the rules.
# Output (the contract's evidence) caps them to MAX_RAW_CHARS like every RAW field.
MAX_TITLE_CHARS = 4096

EMPTY_FILE = "EMPTY_FILE"
TOO_LARGE = "TOO_LARGE"
NOT_XML = "NOT_XML"
UNSAFE_XML = "UNSAFE_XML"
NOT_NMAP = "NOT_NMAP"


class ParseError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class RawPort:
    port: int
    protocol: str  # "tcp" | "udp"
    service_name: str | None
    product: str | None
    version: str | None
    tunnel: str | None
    method: str | None  # "probed" | "table" | None
    http_title: str | None  # capped at MAX_TITLE_CHARS, not MAX_RAW_CHARS


@dataclass(frozen=True)
class RawHost:
    ip: str
    mac: str | None  # upper case; never leaves the engine unmasked
    vendor: str | None
    hostnames: tuple[str, ...]
    ports: tuple[RawPort, ...]  # only state "open", in file order


@dataclass(frozen=True)
class ParsedScan:
    file: str
    scan_start: str | None
    hosts: tuple[RawHost, ...]


def parse_file(path: str | os.PathLike, max_bytes: int = MAX_FILE_BYTES) -> ParsedScan:
    """Parse one nmap XML file. Raises ParseError, never anything else for bad content."""
    path = Path(path)
    try:
        size = path.stat().st_size
        if size > max_bytes:
            raise ParseError(TOO_LARGE, f"{size} bytes")
        with path.open("rb") as fh:
            data = fh.read(max_bytes + 1)
    except OSError as exc:
        raise ParseError(NOT_XML, f"cannot read file: {exc.strerror}") from exc
    if len(data) > max_bytes:  # the file grew after stat
        raise ParseError(TOO_LARGE, f"over {max_bytes} bytes")
    return parse_bytes(data, path.name)


def parse_bytes(data: bytes, file: str) -> ParsedScan:
    if not data:
        raise ParseError(EMPTY_FILE)
    try:
        # Real nmap output carries a bare <!DOCTYPE nmaprun>, so DTDs are allowed.
        # Entity declarations (XXE, billion laughs) and external references are not.
        root = SafeET.fromstring(data, forbid_dtd=False, forbid_entities=True, forbid_external=True)
    except defusedxml.DefusedXmlException as exc:
        raise ParseError(UNSAFE_XML, type(exc).__name__) from exc
    except (ET.ParseError, ValueError, LookupError) as exc:
        # ValueError: e.g. a multi-byte encoding expat refuses. LookupError: unknown encoding.
        raise ParseError(NOT_XML, f"{type(exc).__name__}: {exc}") from exc
    if root.tag != "nmaprun":
        raise ParseError(NOT_NMAP, f"root element is <{_raw(root.tag)}>")

    hosts: dict[str, _Merged] = {}
    for host_el in root.iter("host"):
        host = _parse_host(host_el)
        if host is None:
            continue
        if host.ip in hosts:  # the same IP twice: keep the first, add ports it didn't have
            hosts[host.ip].add(host)
        else:
            hosts[host.ip] = _Merged(host)
    return ParsedScan(
        file=file,
        scan_start=_scan_start(root.get("start")),
        hosts=tuple(merged.host() for merged in hosts.values()),
    )


def _parse_host(el: ET.Element) -> RawHost | None:
    status = el.find("status")  # nmap always writes one; a host without it counts as up
    if status is not None and status.get("state") != "up":
        return None

    ipv4 = ipv6 = mac = vendor = None
    for addr in el.findall("address"):
        kind, value = addr.get("addrtype"), addr.get("addr", "")
        if kind == "ipv4" and ipv4 is None:
            ipv4 = _valid_ip(value, 4)
        elif kind == "ipv6" and ipv6 is None:
            ipv6 = _valid_ip(value, 6)
        elif kind == "mac" and mac is None:
            mac = _valid_mac(value)
            vendor = _raw(addr.get("vendor"))
    ip = ipv4 or ipv6  # prefer IPv4 when a host lists both
    if ip is None:
        return None

    hostnames = tuple(
        name
        for name in (_raw(h.get("name")) for h in el.findall("hostnames/hostname"))
        if name is not None
    )
    ports: list[RawPort] = []
    seen: set[tuple[str, int]] = set()
    for port_el in el.findall("ports/port"):
        port = _parse_port(port_el)
        if port is not None and (port.protocol, port.port) not in seen:
            seen.add((port.protocol, port.port))
            ports.append(port)
    return RawHost(ip=ip, mac=mac, vendor=vendor, hostnames=hostnames, ports=tuple(ports))


def _parse_port(el: ET.Element) -> RawPort | None:
    state = el.find("state")
    if state is None or state.get("state") != "open":  # not "open|filtered", not "filtered"
        return None
    protocol = el.get("protocol")
    if protocol not in ("tcp", "udp"):
        return None
    try:
        number = int(el.get("portid", ""))
    except ValueError:
        return None
    if not 0 < number <= 65535:
        return None

    service = el.find("service")
    get = (lambda key: _raw(service.get(key))) if service is not None else (lambda key: None)
    title = next(
        (_http_title(s) for s in el.findall("script") if s.get("id") == "http-title"), None
    )
    return RawPort(
        port=number,
        protocol=protocol,
        service_name=get("name"),
        product=get("product"),
        version=get("version"),
        tunnel=get("tunnel"),
        method=get("method"),
        http_title=title,
    )


# http-title writes these instead of a title. "Did not follow redirect to …/login.htm"
# must not count as an admin page title.
_NOT_A_TITLE = ("did not follow redirect", "site doesn't have a title", "request failed")
_TITLE_LINE_END = re.compile(r"[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]")


def _http_title(script: ET.Element) -> str | None:
    """The page title from an http-title script, or None if there is no real title."""
    elems = script.findall("elem")
    if elems:  # structured output: only an explicit title element is a title
        return next((_raw(e.text, MAX_TITLE_CHARS) for e in elems if e.get("key") == "title"), None)
    # Split before RAW normalization joins lines: later lines are diagnostics.
    raw = script.get("output") or ""
    end = _TITLE_LINE_END.search(raw)
    output = _raw(raw[: end.start()] if end else raw, MAX_TITLE_CHARS)
    if output is None or output.lower().startswith(_NOT_A_TITLE):
        return None
    return output


class _Merged:
    """Every <host> for one IP, merged in file order: the first MAC and vendor win, and
    later entries only add hostnames and ports not seen yet. Each add costs only the size
    of the entry added, so a file that repeats one IP thousands of times still parses in
    seconds (NFR-07, #185)."""

    def __init__(self, first: RawHost):
        self.ip, self.mac, self.vendor = first.ip, first.mac, first.vendor
        self.hostnames = list(first.hostnames)
        self.ports = list(first.ports)
        self._names = set(first.hostnames)
        self._ports = {(p.protocol, p.port) for p in first.ports}

    def add(self, other: RawHost) -> None:
        self.mac = self.mac or other.mac
        self.vendor = self.vendor or other.vendor
        new_names = [h for h in other.hostnames if h not in self._names]
        self.hostnames += new_names
        self._names.update(new_names)
        for p in other.ports:  # already unique within `other`
            if (p.protocol, p.port) not in self._ports:
                self._ports.add((p.protocol, p.port))
                self.ports.append(p)

    def host(self) -> RawHost:
        return RawHost(
            ip=self.ip,
            mac=self.mac,
            vendor=self.vendor,
            hostnames=tuple(self.hostnames),
            ports=tuple(self.ports),
        )


def _raw(value: str | None, limit: int = MAX_RAW_CHARS) -> str | None:
    """Cap and clean a string copied from the file. Empty becomes None.

    Control characters (Cc) and format characters (Cf: right-to-left override,
    zero-width spaces) become spaces, so a banner can't reorder or hide UI text.
    """
    if value is None:
        return None
    cleaned = "".join(" " if unicodedata.category(ch) in ("Cc", "Cf") else ch for ch in value)
    cleaned = " ".join(cleaned.split())[:limit]
    return cleaned or None


def _valid_ip(value: str, version: int) -> str | None:
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    return str(addr) if addr.version == version else None


def _valid_mac(value: str) -> str | None:
    parts = value.strip().upper().replace("-", ":").split(":")
    if len(parts) == 6 and all(
        len(p) == 2 and all(c in "0123456789ABCDEF" for c in p) for p in parts
    ):
        return ":".join(parts)
    return None


def _scan_start(value: str | None) -> str | None:
    try:
        stamp = int(value or "")
        return datetime.fromtimestamp(stamp, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError, OSError):
        return None
