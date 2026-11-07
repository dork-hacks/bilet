"""Built-in Romanian and English texts, keyed by the codes the engine outputs.

The engine outputs codes only (docs/contracts/data-model.md). The UI, the CLI and the
AI fallback get every user-facing text from here. Every lookup has a safe fallback, so
an unknown code never crashes a page.
"""

import re
from dataclasses import dataclass

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
    SEVERITIES,
)

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
    "refusal_message",
    "severity_label",
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
