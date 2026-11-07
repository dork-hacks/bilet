"""Device identity (FR-03, NFR-02): masked MAC, stable device key, type guess, risk points.

The raw MAC never leaves the engine: outputs carry `mac_masked` and `device_key` only.
The device key is an HMAC with a salt that lives in the local data folder, so keys are
stable on one install and meaningless anywhere else (docs/contracts/data-model.md).
"""

import hashlib
import hmac
import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

from tool.config import data_dir
from tool.engine.parser import RawHost
from tool.engine.rules import Hit

SALT_FILE = "device_key.salt"


def mask_mac(mac: str | None) -> str | None:
    """Keep the vendor half only: B8:27:EB:12:34:56 -> B8:27:EB:xx:xx:xx."""
    if not mac:
        return None
    return ":".join(mac.upper().split(":")[:3]) + ":xx:xx:xx"


def device_key(salt: bytes, mac: str | None, ip: str) -> str:
    """d_ + 12 hex of HMAC-SHA256(salt, MAC in upper case), or of the IP without a MAC."""
    subject = (mac or ip).upper().encode()
    return "d_" + hmac.new(salt, subject, hashlib.sha256).hexdigest()[:12]


def load_salt(folder: Path | None = None) -> bytes:
    """The local device-key salt, created on first use. Private to this user (NFR-02)."""
    folder = folder or data_dir()
    path = folder / SALT_FILE
    if path.exists():
        return path.read_bytes().strip()
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    salt = secrets.token_hex(32).encode()
    # O_EXCL: if another process created it a moment ago, use theirs.
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return path.read_bytes().strip()
    with os.fdopen(fd, "wb") as fh:
        fh.write(salt)
    return salt


def risk_points(hits: list[Hit]) -> int:
    return sum(hit.entry.points for hit in hits)


@dataclass(frozen=True)
class TypeRule:
    """A device type and the evidence that suggests it. Any one signal is enough."""

    device_type: str
    services: frozenset[str] = frozenset()  # nmap service names on open ports
    vendors: tuple[str, ...] = ()  # lower-case substrings of the MAC vendor
    host_words: frozenset[str] = frozenset()  # whole hostname words ("tv" in "living-room-tv")
    host_parts: tuple[str, ...] = ()  # substrings, only for words that can't be part of a name


# First match wins, so the order is part of the rule: specific devices before generic ones.
# A cheap camera with telnet is still a camera; a Dell can be a PC or a server, so vendor
# alone never decides those two.
TYPE_RULES: tuple[TypeRule, ...] = (
    TypeRule(
        "camera",
        services=frozenset({"rtsp"}),
        vendors=("hikvision", "dahua", "axis communications", "reolink", "foscam", "amcrest"),
        host_words=frozenset({"cam", "ipcam", "nvr", "dvr", "camera", "doorbell"}),
        host_parts=("camera",),
    ),
    TypeRule(
        "printer",
        services=frozenset({"jetdirect", "ipp", "printer"}),
        vendors=("brother", "epson", "canon", "lexmark", "kyocera", "xerox"),
        host_words=frozenset({"printer", "print"}),
        host_parts=("printer",),
    ),
    TypeRule(
        "nas",
        vendors=("synology", "qnap", "western digital", "buffalo", "asustor"),
        host_words=frozenset({"nas", "diskstation"}),
    ),
    TypeRule(
        "tv",
        vendors=("roku", "vizio", "hisense"),
        host_words=frozenset({"tv", "chromecast", "firetv", "appletv", "bravia", "roku"}),
    ),
    TypeRule(
        "router",
        services=frozenset({"domain", "upnp"}),
        vendors=("tp-link", "netgear", "ubiquiti", "mikrotik", "zyxel", "d-link", "linksys"),
        host_words=frozenset({"router", "gateway", "ap", "modem", "fritz"}),
        host_parts=("router", "gateway", "access-point"),
    ),
    TypeRule(
        "iot_hub",
        services=frozenset({"mqtt"}),
        vendors=("espressif", "tuya", "shelly", "sonoff", "philips lighting", "signify"),
        host_words=frozenset({"hub", "smarthub", "plug", "bulb", "sensor", "thermostat", "esp"}),
        host_parts=("smarthub", "smartplug"),
    ),
    TypeRule(
        "pc",
        services=frozenset({"ms-wbt-server", "vnc"}),
        host_words=frozenset({"laptop", "desktop", "desk", "pc", "workstation", "macbook"}),
        host_parts=("laptop", "desktop", "macbook"),
    ),
    TypeRule(
        "server",
        services=frozenset({"mysql", "postgresql", "redis", "mongodb", "ftp"}),
        host_words=frozenset({"server", "srv", "db", "cache"}),
        host_parts=("server", "srv"),
    ),
    TypeRule(
        "phone",
        vendors=("apple", "samsung", "xiaomi", "oneplus", "oppo", "huawei", "motorola"),
        host_words=frozenset({"iphone", "android", "galaxy", "pixel", "phone"}),
        host_parts=("iphone", "android", "galaxy", "phone"),
    ),
)

_WORDS = re.compile(r"[a-z]+")


def guess_device_type(host: RawHost) -> str:
    """A best guess from services, vendor and hostname. "unknown" when nothing fits."""
    services = {(p.service_name or "").lower() for p in host.ports}
    vendor = (host.vendor or "").lower()
    names = [name.lower() for name in host.hostnames]
    words = {word for name in names for word in _WORDS.findall(name)}
    for rule in TYPE_RULES:
        if (
            services & rule.services
            or any(v in vendor for v in rule.vendors)
            or words & rule.host_words
            or any(part in name for part in rule.host_parts for name in names)
        ):
            return rule.device_type
    return "unknown"
