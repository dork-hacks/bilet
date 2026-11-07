"""Finding IDs and match keys, exactly as docs/contracts/data-model.md defines them."""

import hashlib


def _sha12(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def _part(value: object) -> str:
    return "" if value is None else str(value)


def finding_id(file: str, ip: str, port: int | None, code: str) -> str:
    """Unique within one scan, the same on every machine (no salt)."""
    return "f_" + _sha12(f"{file}|{ip}|{_part(port)}|{code}")


def match_key(device_key: str, protocol: str | None, port: int | None, code: str) -> str:
    """The same finding across scans on one install (depends on the salted device key)."""
    return "m_" + _sha12(f"{device_key}|{_part(protocol)}|{_part(port)}|{code}")
