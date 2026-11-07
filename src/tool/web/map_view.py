"""What the home screen's network map shows (#170): every device, linked to the router.

A pure function over one ScanResult dict (docs/contracts/data-model.md), no web framework.
The map is drawn in 3D by static/netmap.js and as a plain list in the page, both from this
data. Only fields picked here go into it, so a raw MAC or a device key never reaches the
browser. Hostnames are RAW: the page embeds this data with Jinja's `tojson` (which escapes
`<`, `>`, `&` and `'`), and the script only ever writes it with `textContent`.
"""

import re

from tool.content import DEVICE_TYPES, device_type_label, finding_text, severity_label
from tool.content.ui import MAP_LEVELS, UI
from tool.web.view import (
    RESULT_DATA_ERRORS,
    device_anchor,
    most_dangerous,
    pick_lang,
    scan_fields_ok,
)

# Worst first. A device's level is its worst finding's severity; "none" when it has no
# finding above "info" (an info finding scores 0 points and needs no fix).
LEVEL_ORDER = ("high", "medium", "low", "none")
MASKED_MAC = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){2}(:xx){3}$")
# The strings the script needs. Everything else in the map section is rendered by Jinja.
SCRIPT_TEXTS = (
    "map_fullscreen",
    "map_exit_fullscreen",
    "map_focus",
    "map_selected",
    "map_no_matches",
    "map_count",
    "map_canvas_label",
    "map_hub_virtual",
    "map_most_dangerous",
    "map_ip",
    "map_mac",
    "map_name",
    "map_no_findings",
    "map_go_problems",
    "map_go_device",
    "map_reset",
    "map_zoom_in",
    "map_zoom_out",
    "port",
)


def device_level(severities: list[str]) -> str:
    """The worst severity of a device's findings, or "none"."""
    for level in LEVEL_ORDER[:-1]:
        if level in severities:
            return level
    return "none"


def level_label(level: str, lang: str) -> dict:
    band = MAP_LEVELS.get(level, MAP_LEVELS["none"])
    return {"key": level, "icon": band["icon"], "label": band[lang]}


def safe_mac(value: object) -> str | None:
    """The masked MAC, or None. Anything that isn't in the masked shape is dropped, so a
    raw MAC can't reach the page even if a scan dict carried one by mistake."""
    return value if isinstance(value, str) and MASKED_MAC.match(value) else None


def _node(device: dict, findings: dict[str, dict], lang: str, worst_ip: str | None) -> dict:
    own = [findings[i] for i in device.get("finding_ids", []) if i in findings]
    own.sort(key=lambda f: -int(f.get("points", 0)))
    kind = device.get("device_type_guess", "unknown")
    kind = kind if kind in DEVICE_TYPES else "unknown"
    level = device_level([f.get("severity", "info") for f in own])
    items = []
    for finding in own:
        severity = finding.get("severity", "info")
        port, protocol = finding.get("port"), finding.get("protocol")
        items.append(
            {
                "title": finding_text(finding["code"], lang).title,
                "severity": severity if severity in ("high", "medium", "low") else "info",
                "severity_label": severity_label(severity, lang),
                "port": f"{port}/{protocol}" if port is not None else None,
            }
        )
    return {
        "id": device_anchor(device["ip"]),
        "ip": device["ip"],
        "type": kind,
        "type_label": device_type_label(kind, lang),
        "name": device.get("hostname") if isinstance(device.get("hostname"), str) else None,
        "mac": safe_mac(device.get("mac_masked")),
        "level": level_label(level, lang),
        "points": int(device.get("risk_points", 0)),
        "worst": device["ip"] == worst_ip,
        "has_problems": bool(own),
        "findings": items,
    }


def _hub_index(devices: list[dict]) -> int | None:
    """The router: the first device the rules guess is a router (contract order is by IP),
    else the one at the usual gateway address (.1). None: the map draws a plain "your
    Wi-Fi" centre instead of pretending some device is the router."""
    for i, device in enumerate(devices):
        if device.get("device_type_guess") == "router":
            return i
    for i, device in enumerate(devices):
        if str(device.get("ip", "")).endswith(".1"):
            return i
    return None


def network_map(result: dict | None, lang: str | None) -> dict | None:
    """Return no map for malformed saved data instead of exposing a partial map."""
    if not scan_fields_ok(result):
        return None
    try:
        return _network_map(result, lang)
    except RESULT_DATA_ERRORS:
        return None


def _network_map(result: dict, lang: str | None) -> dict | None:
    """The map data for a readable scan, or None (no scan, an unreadable file, no devices).

    `hub` is the router node, or None. `nodes` are the other devices in the device list's
    order: most risk points first, ties by level and then the contract's IP order, so the
    first node is the most dangerous device and the same scan always gives the same map.
    """
    lang = pick_lang(lang)
    if not result or result.get("status") != "ok" or not result.get("devices"):
        return None
    findings = {f["id"]: f for f in result.get("findings", [])}
    devices = [d for d in result["devices"] if isinstance(d, dict) and d.get("ip")]
    pick = most_dangerous(result)
    worst_ip = pick[0]["ip"] if pick else None
    nodes = [_node(d, findings, lang, worst_ip) for d in devices]
    hub_at = _hub_index(devices)
    hub = nodes.pop(hub_at) if hub_at is not None else None
    nodes.sort(key=lambda n: (-n["points"], LEVEL_ORDER.index(n["level"]["key"])))
    return {
        "lang": lang,
        "hub": hub,
        "nodes": nodes,
        "levels": [level_label(level, lang) for level in LEVEL_ORDER],
        "text": {key: UI[key][lang] for key in SCRIPT_TEXTS},
    }
