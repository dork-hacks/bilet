"""Safe nmap XML parser (FR-05, NFR-03).

Turns one nmap XML file into plain host and port records, or raises ParseError
with one of the error codes from docs/contracts/data-model.md. Every string
copied from the file is RAW: capped and stripped of control characters, nothing
more. Callers must escape it before display and never pass it to an LLM as is.
"""

import ipaddress
import os
import unicodedata
import xml.etree.ElementTree as ET  # noqa: S405 - only for ParseError and type hints
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import defusedxml
import defusedxml.ElementTree as SafeET

MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_RAW_CHARS = 256

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
    http_title: str | None


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
    except ET.ParseError as exc:
        raise ParseError(NOT_XML, str(exc)) from exc
    if root.tag != "nmaprun":
        raise ParseError(NOT_NMAP, f"root element is <{_raw(root.tag)}>")

    hosts: dict[str, RawHost] = {}
    for host_el in root.iter("host"):
        host = _parse_host(host_el)
        if host is None:
            continue
        if host.ip in hosts:  # the same IP twice: keep the first, add ports it didn't have
            hosts[host.ip] = _merge(hosts[host.ip], host)
        else:
            hosts[host.ip] = host
    return ParsedScan(
        file=file, scan_start=_scan_start(root.get("start")), hosts=tuple(hosts.values())
    )


def _parse_host(el: ET.Element) -> RawHost | None:
    status = el.find("status")
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
    title = None
    for script in el.findall("script"):
        if script.get("id") == "http-title":
            title = _raw(script.get("output"))
            break
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


def _merge(first: RawHost, other: RawHost) -> RawHost:
    have = {(p.protocol, p.port) for p in first.ports}
    extra = tuple(p for p in other.ports if (p.protocol, p.port) not in have)
    return RawHost(
        ip=first.ip,
        mac=first.mac or other.mac,
        vendor=first.vendor or other.vendor,
        hostnames=first.hostnames + tuple(h for h in other.hostnames if h not in first.hostnames),
        ports=first.ports + extra,
    )


def _raw(value: str | None) -> str | None:
    """Cap and clean a string copied from the file. Empty becomes None."""
    if value is None:
        return None
    cleaned = "".join(" " if unicodedata.category(ch) == "Cc" else ch for ch in value)
    cleaned = " ".join(cleaned.split())[:MAX_RAW_CHARS]
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
