"""Assemble one file's ScanResult with the standard score (FR-09).

The shape is docs/contracts/data-model.md exactly. Everything here is deterministic:
the same file and the same salt give byte-identical JSON on every run (NFR-05).
"""

import ipaddress
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from tool.engine.device import device_key, guess_device_type, load_salt, mask_mac, risk_points
from tool.engine.ids import finding_id, match_key
from tool.engine.parser import (
    MAX_RAW_CHARS,
    NOT_XML,
    ParsedScan,
    ParseError,
    RawHost,
    RawPort,
    parse_file,
)
from tool.engine.rules import Hit, host_hits

SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ScanResult:
    file: str
    status: str  # "ok" | "error"
    error: dict | None = None
    scan_start: str | None = None
    score: int | None = None
    points_total: int = 0
    devices: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "file": self.file,
            "status": self.status,
            "error": self.error,
            "scan_start": self.scan_start,
            "score": self.score,
            "points_total": self.points_total,
            "devices": self.devices,
            "findings": self.findings,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n"


def standard_score(points_total: int) -> int:
    """The brief's formula: max(0, 100 - sum of all finding points)."""
    return max(0, 100 - points_total)


def analyze_file(path: str | os.PathLike, salt: bytes | None = None) -> ScanResult:
    """One nmap XML file -> ScanResult. Never raises on bad input: status "error" instead."""
    name = Path(path).name
    try:
        scan = parse_file(path)
    except ParseError as exc:
        return error_result(name, exc.code)
    return build_result(scan, load_salt() if salt is None else salt)


def error_result(file: str, code: str = NOT_XML) -> ScanResult:
    return ScanResult(file=file, status="error", error={"code": code})


def build_result(scan: ParsedScan, salt: bytes) -> ScanResult:
    devices, findings = [], []
    for host in sorted(scan.hosts, key=lambda h: _ip_key(h.ip)):
        key = device_key(salt, host.mac, host.ip)
        hits = sorted(host_hits(host), key=_hit_key)
        own = [_finding(scan.file, host, key, hit) for hit in hits]
        findings.extend(own)
        devices.append(_device(host, key, hits, own))
    findings.sort(key=lambda f: (_ip_key(f["ip"]), _port_key(f["port"]), f["code"]))
    total = sum(f["points"] for f in findings)
    return ScanResult(
        file=scan.file,
        status="ok",
        scan_start=scan.scan_start,
        score=standard_score(total),
        points_total=total,
        devices=devices,
        findings=findings,
    )


def _device(host: RawHost, key: str, hits: list[Hit], own: list[dict]) -> dict:
    return {
        "device_key": key,
        "ip": host.ip,
        "mac_masked": mask_mac(host.mac),
        "vendor": host.vendor,
        "hostname": host.hostnames[0] if host.hostnames else None,
        "device_type_guess": guess_device_type(host),
        "risk_points": risk_points(hits),
        "open_ports": [_port(p) for p in sorted(host.ports, key=lambda p: (p.protocol, p.port))],
        "finding_ids": [f["id"] for f in own],
    }


def _port(port: RawPort) -> dict:
    return {"port": port.port, "protocol": port.protocol, **_evidence(port)}


def _evidence(port: RawPort | None) -> dict:
    if port is None:  # UNKNOWN_DEVICE: a host-level finding
        keys = ("service_name", "product", "version", "tunnel", "http_title")
        return dict.fromkeys(keys)
    return {
        "service_name": port.service_name,
        "product": port.product,
        "version": port.version,
        "tunnel": port.tunnel,
        # The parser keeps titles longer so the rules see late keywords; the output
        # caps every RAW field at MAX_RAW_CHARS (contract).
        "http_title": port.http_title[:MAX_RAW_CHARS] if port.http_title else None,
    }


def _finding(file: str, host: RawHost, key: str, hit: Hit) -> dict:
    port = hit.port.port if hit.port else None
    protocol = hit.port.protocol if hit.port else None
    return {
        "id": finding_id(file, host.ip, port, hit.entry.code),
        "match_key": match_key(key, protocol, port, hit.entry.code),
        "code": hit.entry.code,
        "severity": hit.entry.severity,
        "points": hit.entry.points,
        "ip": host.ip,
        "port": port,
        "protocol": protocol,
        "device_key": key,
        "evidence": _evidence(hit.port),
    }


def _ip_key(ip: str) -> tuple[int, int]:
    addr = ipaddress.ip_address(ip)
    return (addr.version, int(addr))


def _port_key(port: int | None) -> int:
    return -1 if port is None else port


def _hit_key(hit: Hit) -> tuple[int, str]:
    return (_port_key(hit.port.port if hit.port else None), hit.entry.code)
