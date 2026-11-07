"""Built-in Romanian and English texts, keyed by the codes the engine outputs.

The engine outputs codes only (docs/contracts/data-model.md). The UI, the CLI and the
AI fallback get every user-facing text from here. Every lookup has a safe fallback, so
an unknown code never crashes a page.
"""

import re
from dataclasses import dataclass

from tool.content.device_steps import DEVICE_STEPS
from tool.content.texts import (
    ALERTS,
    DETECT_ERRORS,
    DEVICE_TYPES,
    FILE_ERRORS,
    FINDINGS,
    GENERIC_ALERT,
    GENERIC_FILE_ERROR,
    GENERIC_FINDING,
    GENERIC_REFUSAL,
    LANGS,
    REFUSALS,
    SCAN_MESSAGES,
    SCAN_STEPS,
    SCAN_TIME_LEFT,
    SEVERITIES,
)
from tool.content.ui import UI

DEFAULT_LANG = "ro"
_MAX_TARGET_CHARS = 64

__all__ = [
    "DEFAULT_LANG",
    "LANGS",
    "FindingText",
    "alert_message",
    "detect_error_message",
    "device_type_label",
    "file_error_message",
    "finding_text",
    "fix_steps",
    "refusal_message",
    "hosts_found_message",
    "scan_message",
    "scan_progress_message",
    "severity_label",
    "standards_line",
]


@dataclass(frozen=True)
class FindingText:
    code: str
    lang: str
    title: str
    explanation: str
    steps: tuple[str, ...]
    cis: tuple[str, ...]
    owasp_iot: tuple[str, ...]
    is_generic: bool  # True when the code has no entry and the generic text is shown


def _lang(lang: str | None) -> str:
    return lang if lang in LANGS else DEFAULT_LANG


def finding_text(code: str, lang: str | None = DEFAULT_LANG) -> FindingText:
    lang = _lang(lang)
    entry = FINDINGS.get(code)
    data = entry if entry is not None else GENERIC_FINDING
    return FindingText(
        code=code,
        lang=lang,
        title=data["title"][lang],
        explanation=data["explanation"][lang],
        steps=tuple(data["steps"][lang]),
        cis=tuple(data["cis"]),
        owasp_iot=tuple(data["owasp_iot"]),
        is_generic=entry is None,
    )


_STEP_FIELD = re.compile(r"\{(ip|url)\}")


def _settings_url(ip: str, web_port: int | None) -> str:
    host = f"[{ip}]" if ":" in ip else ip  # an IPv6 address needs brackets in a URL
    if web_port is None or web_port == 80:
        return f"http://{host}"
    return f"http://{host}:{web_port}"


def fix_steps(
    code: str,
    lang: str | None = DEFAULT_LANG,
    device_type: str | None = None,
    ip: str | None = None,
    web_port: int | None = None,
) -> tuple[str, ...]:
    """The fix steps for one finding on one device (#152). Never raises.

    A variant keyed by (code, device_type) names the device's IP address and its settings
    page (`web_port` is the port of its web page, when the scan saw one). Without a
    variant, or without an IP, the code's generic steps are returned. The IP comes from a
    scan file: it is cleaned, filled in one pass and never expanded as a placeholder.
    """
    lang = _lang(lang)
    variant = DEVICE_STEPS.get((code, device_type or "unknown"))
    if variant is None or not ip:
        return finding_text(code, lang).steps
    clean_ip = _clean_target(ip)
    port = web_port if isinstance(web_port, int) and 0 < web_port < 65536 else None
    values = {"ip": clean_ip, "url": _settings_url(clean_ip, port)}
    return tuple(_STEP_FIELD.sub(lambda m: values[m.group(1)], step) for step in variant[lang])


def standards_line(code: str, lang: str | None = DEFAULT_LANG) -> str | None:
    """The CIS Controls and OWASP IoT Top 10 references of a catalog code, as one line.

    The reference codes are the same in both languages; only the label is translated.
    None when the code has no references (the generic text), so nothing is shown.
    """
    lang = _lang(lang)
    entry = FINDINGS.get(code)
    if entry is None:
        return None
    parts = []
    if entry["cis"]:
        parts.append("CIS Controls v8: " + ", ".join(entry["cis"]))
    if entry["owasp_iot"]:
        parts.append("OWASP IoT Top 10: " + ", ".join(entry["owasp_iot"]))
    if not parts:
        return None
    return UI["standards"][lang] + " " + " · ".join(parts)


def severity_label(severity: str, lang: str | None = DEFAULT_LANG) -> str:
    lang = _lang(lang)
    return SEVERITIES.get(severity, SEVERITIES["info"])[lang]


def device_type_label(device_type: str, lang: str | None = DEFAULT_LANG) -> str:
    lang = _lang(lang)
    return DEVICE_TYPES.get(device_type, DEVICE_TYPES["unknown"])[lang]


def file_error_message(error_code: str, lang: str | None = DEFAULT_LANG) -> str:
    lang = _lang(lang)
    return FILE_ERRORS.get(error_code, GENERIC_FILE_ERROR)[lang]


def detect_error_message(code: str, lang: str | None = DEFAULT_LANG) -> str:
    """Plain-language text for a network detection error (FR-01). Never raises."""
    lang = _lang(lang)
    return DETECT_ERRORS.get(code, DETECT_ERRORS["DETECT_FAILED"])[lang]


def _clean_target(target: str) -> str:
    """The target is user input: keep printable characters only and cap the length."""
    cleaned = "".join(ch for ch in str(target) if ch.isprintable())
    if len(cleaned) > _MAX_TARGET_CHARS:
        cleaned = cleaned[: _MAX_TARGET_CHARS - 1] + "…"
    return cleaned


def refusal_message(code: str, target: str = "", lang: str | None = DEFAULT_LANG) -> str:
    """Plain-language guardrail refusal (FR-02). `target` is shown, never interpreted."""
    lang = _lang(lang)
    template = REFUSALS.get(code, GENERIC_REFUSAL)[lang]
    # str.replace, not str.format: braces in the target are only ever text.
    return template.replace("{target}", _clean_target(target))


_ALERT_FIELD = re.compile(r"\{(ip|port|protocol)\}")


def alert_message(
    code: str,
    ip: str,
    port: int | None = None,
    protocol: str | None = None,
    lang: str | None = DEFAULT_LANG,
) -> str:
    """Plain-language text for a change alert (FR-13). Never raises.

    The values come from scan files, so they are only ever text: one pass fills every
    placeholder, and a value that looks like a placeholder is never expanded.
    """
    lang = _lang(lang)
    template = ALERTS.get(code, GENERIC_ALERT)[lang]
    values = {
        "ip": _clean_target(ip),
        "port": "?" if port is None else _clean_target(str(port)),
        "protocol": "?" if protocol is None else _clean_target(protocol),
    }
    return _ALERT_FIELD.sub(lambda m: values[m.group(1)], template)


_SCAN_FIELD = re.compile(r"\{(targets|address|path|score|findings|count|hosts|step|percent|left)\}")
_MAX_SCAN_VALUE_CHARS = 300  # a saved scan path is longer than a target, so not 64


def _clean_value(value: object) -> str:
    cleaned = "".join(ch for ch in str(value) if ch.isprintable())
    if len(cleaned) > _MAX_SCAN_VALUE_CHARS:
        cleaned = cleaned[: _MAX_SCAN_VALUE_CHARS - 1] + "…"
    return cleaned


def scan_message(code: str, lang: str | None = DEFAULT_LANG, **values: object) -> str:
    """Plain-language text for a `tool scan` message or error (FR-04). Never raises.

    An unknown code is shown as NMAP_FAILED. One pass fills every placeholder, so a
    value that looks like a placeholder is never expanded, and a missing value is "?".
    """
    lang = _lang(lang)
    template = SCAN_MESSAGES.get(code, SCAN_MESSAGES["NMAP_FAILED"])[lang]
    filled = {name: _clean_value(value) for name, value in values.items()}
    return _SCAN_FIELD.sub(lambda m: filled.get(m.group(1), "?"), template)


def _time_left(seconds: int | None, lang: str) -> str:
    if seconds is None or seconds < 0:
        return SCAN_TIME_LEFT["UNKNOWN"][lang]
    if seconds < 60:
        return SCAN_TIME_LEFT["UNDER_A_MINUTE"][lang]
    minutes = round(seconds / 60)
    if minutes <= 1:
        return SCAN_TIME_LEFT["ONE_MINUTE"][lang]
    key = "MANY_MINUTES" if minutes >= 20 else "MINUTES"
    return SCAN_TIME_LEFT[key][lang].replace("{minutes}", str(minutes))


def scan_progress_message(
    step: str, percent: float, seconds_left: int | None, lang: str | None = DEFAULT_LANG
) -> str:
    """One progress line for `tool scan` (#107), for example "Checking ports (TCP): 40%
    done, about 2 minutes left." An unknown step is shown as OTHER. Never raises."""
    lang = _lang(lang)
    name = SCAN_STEPS.get(step, SCAN_STEPS["OTHER"])[lang]
    try:
        whole = str(int(min(100.0, max(0.0, float(percent)))))
    except (TypeError, ValueError):
        whole = "?"
    left = _time_left(seconds_left, lang)
    return scan_message("PROGRESS", lang, step=name, percent=whole, left=left)


def hosts_found_message(hosts: list[str], lang: str | None = DEFAULT_LANG) -> str:
    """The line printed after discovery: how many devices answered, their IP addresses,
    and that the port check takes a few minutes (#107). Never MACs or hostnames."""
    return scan_message("HOSTS_FOUND", lang, count=len(hosts), hosts=", ".join(hosts))
