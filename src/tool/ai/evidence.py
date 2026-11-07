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
    device_ips: dict[str, str] = field(default_factory=dict)  # pseudonym -> IP, local only
    # pseudonym -> hostname, local only: used to swap names out of the owner's question.
    device_hostnames: dict[str, str] = field(default_factory=dict)

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
    device_ips: dict[str, str] = {}
    device_hostnames: dict[str, str] = {}
    counter = 0
    for index, device in enumerate(devices):
        ref = pseudonym(index)
        device_refs[ref] = device.get("device_key")
        if isinstance(device.get("ip"), str) and device["ip"]:
            device_ips[ref] = device["ip"]
        if isinstance(device.get("hostname"), str) and device["hostname"].strip():
            device_hostnames[ref] = device["hostname"].strip()
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
    return Evidence(
        payload=payload,
        device_refs=device_refs,
        finding_refs=finding_refs,
        device_ips=device_ips,
        device_hostnames=device_hostnames,
    )


# What an IP in the owner's question becomes when it isn't one of the scanned devices.
UNKNOWN_ADDRESS = "[unknown address]"
_ANY_IP = re.compile(
    r"(?<![\w.:])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})(?![\w.:])",
    re.IGNORECASE,
)
# "Device C" (EN) or "Dispozitivul C" / "dispozitivului C" (RO), not already followed by "(".
_PSEUDONYM = re.compile(r"\b((?:[Dd]evice|[Dd]ispozitiv\w*)\s+)([A-Z]{1,2})\b(?!\s*\()")


# A hostname label shorter than this ("tv", "pc") is too likely to be an ordinary word.
_MIN_HOST_LABEL = 3


def _hostname_names(evidence: Evidence) -> dict[str, str]:
    """Lower-case name -> pseudonym: each full hostname and its first label.

    A name shared by two devices is dropped, because it can't say which one is meant.
    """
    names: dict[str, str] = {}
    shared: set[str] = set()
    for ref, hostname in evidence.device_hostnames.items():
        full = hostname.lower().rstrip(".")
        candidates = {full}
        label = full.split(".", 1)[0]
        if len(label) >= _MIN_HOST_LABEL:
            candidates.add(label)
        for name in candidates:
            if name in names and names[name] != ref:
                shared.add(name)
            names[name] = ref
    return {name: ref for name, ref in names.items() if name not in shared}


def localise_question(question: str, evidence: Evidence) -> str:
    """Replace every IP and device hostname in the owner's question before it leaves
    the computer (#150, #233).

    A scanned device's IP or hostname becomes its pseudonym ("Device C"), so the AI
    knows which device is meant. Any other IP becomes UNKNOWN_ADDRESS. No IP and no
    scanned hostname is ever sent.
    """
    by_ip = {ip.lower(): ref for ref, ip in evidence.device_ips.items()}

    def swap(match: re.Match) -> str:
        return by_ip.get(match.group(0).lower(), UNKNOWN_ADDRESS)

    question = _ANY_IP.sub(swap, question)
    names = _hostname_names(evidence)
    if not names:
        return question
    # Longest name first, so "tv.lan" wins over "tv"; never inside a longer word.
    pattern = re.compile(
        r"(?<![\w.-])("
        + "|".join(re.escape(name) for name in sorted(names, key=lambda n: (-len(n), n)))
        + r")(?![\w-]|\.\w)",
        re.IGNORECASE,
    )
    return pattern.sub(lambda m: names[m.group(1).lower()], question)


def restore_ips(text: str, evidence: Evidence) -> str:
    """Show the IP next to each pseudonym in an AI answer, locally: "Device C (192.168.1.5)".

    The device list shows IPs, so the owner can match the answer to a device. Runs only
    after the grounding check, on the text that is displayed.
    """

    def swap(match: re.Match) -> str:
        ip = evidence.device_ips.get(f"Device {match.group(2)}")
        return match.group(0) if ip is None else f"{match.group(1)}{match.group(2)} ({ip})"

    return _PSEUDONYM.sub(swap, text)


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
