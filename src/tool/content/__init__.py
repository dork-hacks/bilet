"""Built-in Romanian and English texts, keyed by the codes the engine outputs.

The engine outputs codes only (docs/contracts/data-model.md). The UI, the CLI and the
AI fallback get every user-facing text from here. Every lookup has a safe fallback, so
an unknown code never crashes a page.
"""

from dataclasses import dataclass

from tool.content.texts import (
    DEVICE_TYPES,
    FILE_ERRORS,
    FINDINGS,
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
