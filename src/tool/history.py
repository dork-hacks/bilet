"""Local scan history (FR-10, NFR-02): every scan kept, any two compared, one-click delete.

Everything stays on this computer in one SQLite file under the data folder. Rows hold
the ScanResult JSON as the engine produced it, so no raw MAC is ever stored.

Pairing devices across scans: the contract's `device_key` comes from the MAC, but MACs
are not stable. Phones randomise them, and the Validation Set's own before/after pair
(V6a -> V6b) has a different device half of the MAC for every device on the "same home".
So two scans' devices are paired in rounds, each only among devices not yet paired:
  1. the same device_key;
  2. the same IP, the same vendor half of the MAC, and hostnames that don't disagree;
  3. the same hostname and the same vendor half of the MAC (the IP changed).
Findings are then matched by (paired device, protocol, port, code), not by match_key.
"""

import hashlib
import ipaddress
import json
import os
import shutil
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from tool.config import data_dir
from tool.engine import ScanResult
from tool.engine.device import SALT_FILE

DB_FILE = "history.sqlite3"
# Everything "delete my history" removes from the data folder (the AI layer's files too).
PRIVATE_FILES = (DB_FILE, f"{DB_FILE}-wal", f"{DB_FILE}-shm", SALT_FILE, "ai_rejections.jsonl")
PRIVATE_DIRS = ("ai_cache",)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY,
    file        TEXT NOT NULL,
    scan_start  TEXT,
    added_at    TEXT NOT NULL,
    status      TEXT NOT NULL,
    score       INTEGER,
    digest      TEXT NOT NULL UNIQUE,
    result_json TEXT NOT NULL
)
"""


# Change alerts (FR-13). Codes only; the RO/EN text belongs to tool.content.
NEW_DEVICE = "NEW_DEVICE"
NEW_OPEN_PORT = "NEW_OPEN_PORT"


class HistoryError(Exception):
    pass


@dataclass(frozen=True)
class Alert:
    """Something appeared since the previous scan. `port`/`protocol` are None for devices."""

    code: str  # NEW_DEVICE | NEW_OPEN_PORT
    device_key: str
    ip: str
    protocol: str | None = None
    port: int | None = None

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "device_key": self.device_key,
            "ip": self.ip,
            "protocol": self.protocol,
            "port": self.port,
        }


@dataclass(frozen=True)
class ScanSummary:
    id: int
    file: str
    scan_start: str | None
    status: str
    score: int | None


@dataclass(frozen=True)
class PortChange:
    device: str  # the newer scan's device_key (the older one's for removed devices)
    ip: str
    protocol: str
    port: int


@dataclass(frozen=True)
class Diff:
    old: ScanSummary
    new: ScanSummary
    score_before: int
    score_after: int
    new_devices: list[dict] = field(default_factory=list)  # Device dicts from the newer scan
    removed_devices: list[dict] = field(default_factory=list)  # Device dicts from the older
    opened_ports: list[PortChange] = field(default_factory=list)
    closed_ports: list[PortChange] = field(default_factory=list)
    resolved_findings: list[dict] = field(default_factory=list)  # Finding dicts, older scan
    new_findings: list[dict] = field(default_factory=list)  # Finding dicts, newer scan

    @property
    def score_change(self) -> int:
        return self.score_after - self.score_before


class History:
    """The history database. Create one per request or per process; it's cheap."""

    def __init__(self, folder: Path | None = None):
        self.folder = folder or data_dir()
        self.path = self.folder / DB_FILE

    # -- writing -------------------------------------------------------------------

    def add(self, result: ScanResult | dict) -> int:
        """Store one scan; adding the very same result again returns the existing id."""
        data = result.to_dict() if isinstance(result, ScanResult) else result
        text = json.dumps(data, sort_keys=True, ensure_ascii=False)
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        with self._connect() as db:
            row = db.execute("SELECT id FROM scans WHERE digest = ?", (digest,)).fetchone()
            if row:
                return row[0]
            cur = db.execute(
                "INSERT INTO scans (file, scan_start, added_at, status, score, digest,"
                " result_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    data.get("file", ""),
                    data.get("scan_start"),
                    datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    data.get("status", "error"),
                    data.get("score"),
                    digest,
                    text,
                ),
            )
            return int(cur.lastrowid)

    def delete_all(self) -> None:
        """'Delete my history': the database, the device-key salt and the AI cache."""
        for name in PRIVATE_FILES:
            (self.folder / name).unlink(missing_ok=True)
        for name in PRIVATE_DIRS:
            shutil.rmtree(self.folder / name, ignore_errors=True)

    # -- reading -------------------------------------------------------------------

    def scans(self) -> list[ScanSummary]:
        """Oldest first, by nmap's start time; scans without one go last, by file name."""
        if not self.path.exists():
            return []
        with self._connect() as db:
            rows = db.execute(
                "SELECT id, file, scan_start, status, score FROM scans"
                " ORDER BY scan_start IS NULL, scan_start, file, id"
            ).fetchall()
        return [ScanSummary(*row) for row in rows]

    def result(self, scan_id: int) -> dict:
        with self._connect() as db:
            row = db.execute("SELECT result_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            raise HistoryError(f"no scan {scan_id}")
        return json.loads(row[0])

    def diff(self, old_id: int, new_id: int) -> Diff:
        """What changed between two stored scans (any two, in either order)."""
        return diff_results(
            self.result(old_id), self.result(new_id), self._summary(old_id), self._summary(new_id)
        )

    def latest_diff(self) -> Diff | None:
        """The newest readable scan against the one before it, or None."""
        ok = [s for s in self.scans() if s.status == "ok"]
        return self.diff(ok[-2].id, ok[-1].id) if len(ok) >= 2 else None

    def alerts_for(self, scan_id: int) -> list[Alert]:
        """What appeared in this scan since the readable scan before it (in scan order)."""
        ok = [s for s in self.scans() if s.status == "ok"]
        ids = [s.id for s in ok]
        if scan_id not in ids or ids.index(scan_id) == 0:
            return []
        previous = ids[ids.index(scan_id) - 1]
        return alerts_from_diff(self.diff(previous, scan_id))

    def score_trend(self) -> list[tuple[ScanSummary, int]]:
        return [(s, s.score) for s in self.scans() if s.status == "ok" and s.score is not None]

    # -- internals -----------------------------------------------------------------

    def _summary(self, scan_id: int) -> ScanSummary:
        for summary in self.scans():
            if summary.id == scan_id:
                return summary
        raise HistoryError(f"no scan {scan_id}")

    def _connect(self) -> sqlite3.Connection:
        new = not self.path.exists()
        self.folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        db = sqlite3.connect(self.path)
        if new:
            os.chmod(self.path, 0o600)  # private to this user (NFR-02)
        db.execute(_SCHEMA)
        return db


def diff_results(
    old: dict,
    new: dict,
    old_summary: ScanSummary | None = None,
    new_summary: ScanSummary | None = None,
) -> Diff:
    if old.get("status") != "ok" or new.get("status") != "ok":
        raise HistoryError("an unreadable scan can't be compared")
    old_summary = old_summary or _summary_of(old)
    new_summary = new_summary or _summary_of(new)
    pairs = pair_devices(old.get("devices", []), new.get("devices", []))  # new key -> old key
    old_devices = {d["device_key"]: d for d in old.get("devices", [])}
    new_devices = {d["device_key"]: d for d in new.get("devices", [])}
    paired_old = set(pairs.values())

    opened, closed = [], []
    for new_key, old_key in pairs.items():
        before = {(p["protocol"], p["port"]) for p in old_devices[old_key]["open_ports"]}
        after = {(p["protocol"], p["port"]) for p in new_devices[new_key]["open_ports"]}
        ip = new_devices[new_key]["ip"]
        opened += [PortChange(new_key, ip, *pp) for pp in sorted(after - before)]
        closed += [PortChange(new_key, ip, *pp) for pp in sorted(before - after)]

    # A finding's identity across scans: (device identity, protocol, port, code), where a
    # paired device takes the newer scan's key so both sides agree.
    old_to_new = {old_key: new_key for new_key, old_key in pairs.items()}

    def identity(finding: dict, side: str) -> tuple:
        key = finding["device_key"]
        if side == "old":
            key = old_to_new.get(key, "old:" + key)
        return (key, finding.get("protocol"), finding.get("port"), finding["code"])

    old_findings = {identity(f, "old"): f for f in old.get("findings", [])}
    new_findings = {identity(f, "new"): f for f in new.get("findings", [])}

    return Diff(
        old=old_summary,
        new=new_summary,
        score_before=int(old.get("score") or 0),
        score_after=int(new.get("score") or 0),
        new_devices=[d for key, d in new_devices.items() if key not in pairs],
        removed_devices=[d for key, d in old_devices.items() if key not in paired_old],
        opened_ports=opened,
        closed_ports=closed,
        resolved_findings=[f for k, f in old_findings.items() if k not in new_findings],
        new_findings=[f for k, f in new_findings.items() if k not in old_findings],
    )


def alerts_from_diff(d: Diff) -> list[Alert]:
    """A NEW_DEVICE for each device that wasn't there before, and a NEW_OPEN_PORT for each
    port that opened on a device that was. A new device's own ports aren't repeated."""
    devices = sorted(d.new_devices, key=lambda dev: _ip_key(dev["ip"]))
    alerts = [Alert(NEW_DEVICE, dev["device_key"], dev["ip"]) for dev in devices]
    ports = sorted(d.opened_ports, key=lambda p: (_ip_key(p.ip), p.protocol, p.port))
    alerts += [Alert(NEW_OPEN_PORT, p.device, p.ip, p.protocol, p.port) for p in ports]
    return alerts


def _ip_key(ip: str) -> tuple[int, int]:
    addr = ipaddress.ip_address(ip)
    return (addr.version, int(addr))


def pair_devices(old: list[dict], new: list[dict]) -> dict[str, str]:
    """Pair the same physical device across two scans: {new device_key: old device_key}."""
    pairs: dict[str, str] = {}
    left_old = {d["device_key"]: d for d in old}
    left_new = {d["device_key"]: d for d in new}

    def take(new_key: str, old_key: str) -> None:
        pairs[new_key] = old_key
        left_new.pop(new_key)
        left_old.pop(old_key)

    for key in [k for k in left_new if k in left_old]:  # round 1: same device_key
        take(key, key)
    for match in (_same_ip_and_vendor, _same_hostname_and_vendor):  # rounds 2 and 3
        for new_key, nd in list(left_new.items()):
            candidates = [k for k, od in left_old.items() if match(od, nd)]
            if len(candidates) == 1:  # ambiguous matches stay unpaired: never guess
                take(new_key, candidates[0])
    return pairs


def _vendor_half(device: dict) -> str | None:
    return device.get("mac_masked")  # "50:C7:BF:xx:xx:xx": the OUI only


def _same_ip_and_vendor(old: dict, new: dict) -> bool:
    hostnames_agree = (
        old.get("hostname") is None
        or new.get("hostname") is None
        or old.get("hostname") == new.get("hostname")
    )
    return (
        old["ip"] == new["ip"]
        and _vendor_half(old) is not None
        and _vendor_half(old) == _vendor_half(new)
        and hostnames_agree
    )


def _same_hostname_and_vendor(old: dict, new: dict) -> bool:
    return (
        old.get("hostname") is not None
        and old.get("hostname") == new.get("hostname")
        and _vendor_half(old) == _vendor_half(new)
    )


def _summary_of(result: dict) -> ScanSummary:
    return ScanSummary(
        0,
        result.get("file", ""),
        result.get("scan_start"),
        result.get("status", "error"),
        result.get("score"),
    )
