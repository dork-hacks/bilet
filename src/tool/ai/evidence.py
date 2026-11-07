"""Evidence builder: the minimum the LLM may see about one scan (MASTERPLAN §5.4).

Sent: catalog codes, severities, ports, protocols, nmap's service name, product and
version (sanitised and marked untrusted), and the device-type guess.
Never sent: IPs, MACs (masked or not), hostnames, vendors, raw banners or page titles.
Devices become pseudonyms ("Device A"). The pseudonym -> device_key map stays local.
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from string import ascii_uppercase

# Product and version come from the scanned device, so they are attacker-controlled.
# Keep only characters a real product/version string needs, then cap the length.
_UNTRUSTED_KEEP = re.compile(r"[^A-Za-z0-9 ._+\-()/]")
_MAX_UNTRUSTED_CHARS = 40


def sanitise_untrusted(value: object) -> str | None:
    if value is None:
        return None
    cleaned = _UNTRUSTED_KEEP.sub("", str(value))
    cleaned = " ".join(cleaned.split())[:_MAX_UNTRUSTED_CHARS].strip()
    return cleaned or None


def pseudonym(index: int) -> str:
    """0 -> "Device A", 25 -> "Device Z", 26 -> "Device AA"."""
    letters = ""
    n = index
    while True:
        letters = ascii_uppercase[n % 26] + letters
        n = n // 26 - 1
        if n < 0:
            break
    return f"Device {letters}"


@dataclass(frozen=True)
class Evidence:
    """What may leave the device, plus the local-only map back to real devices."""

    payload: dict
    device_refs: dict[str, str] = field(default_factory=dict)  # pseudonym -> device_key
    finding_refs: dict[str, str] = field(default_factory=dict)  # evidence id -> finding id

    @property
    def digest(self) -> str:
        """Cache key: same evidence, same hash, on every run."""
        canonical = json.dumps(self.payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_evidence(result: dict) -> Evidence:
    """Turn one ScanResult (docs/contracts/data-model.md) into anonymised evidence."""
    devices = result.get("devices") or []
    findings = result.get("findings") or []
    by_device: dict[str, list[dict]] = {}
    for finding in findings:
        by_device.setdefault(finding.get("device_key"), []).append(finding)

    out_devices = []
    device_refs: dict[str, str] = {}
    finding_refs: dict[str, str] = {}
    counter = 0
    for index, device in enumerate(devices):
        ref = pseudonym(index)
        device_refs[ref] = device.get("device_key")
        items = []
        for finding in by_device.get(device.get("device_key"), []):
            counter += 1
            eid = f"E{counter}"
            finding_refs[eid] = finding.get("id")
            ev = finding.get("evidence") or {}
            items.append(
                {
                    "id": eid,
                    "code": finding.get("code"),
                    "severity": finding.get("severity"),
                    "points": finding.get("points"),  # the rules' ranking, see ranked_ids
                    "port": finding.get("port"),
                    "protocol": finding.get("protocol"),
                    "service_name": sanitise_untrusted(ev.get("service_name")),
                    "untrusted_product": sanitise_untrusted(ev.get("product")),
                    "untrusted_version": sanitise_untrusted(ev.get("version")),
                }
            )
        out_devices.append(
            {
                "device": ref,
                "type_guess": device.get("device_type_guess") or "unknown",
                "findings": items,
            }
        )

    payload = {"score": result.get("score"), "devices": out_devices}
    return Evidence(payload=payload, device_refs=device_refs, finding_refs=finding_refs)


def ranked_items(evidence: Evidence) -> list[tuple[dict, dict]]:
    """(device, finding) pairs in the rules' order: most points first.

    Ties keep evidence order (contract order: device, then port, then code), so the
    order is the same on every run. The AI may reword this plan but never reorder it.
    """
    pairs = [
        (device, item)
        for device in evidence.payload.get("devices", [])
        for item in device.get("findings", [])
    ]
    return sorted(pairs, key=lambda pair: -(pair[1].get("points") or 0))


def ranked_ids(evidence: Evidence) -> list[str]:
    return [item["id"] for _device, item in ranked_items(evidence)]
