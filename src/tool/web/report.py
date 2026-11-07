"""Bounded, offline report projection: never pass the scan dict to the template."""

from tool.content import device_type_label, file_error_message, finding_text, severity_label
from tool.web.map_view import safe_mac
from tool.web.view import pick_lang, ranked_devices, score_band

MAX_FINDINGS = 3
MAX_DEVICES = 3


def _short(value: object, limit: int = 64) -> str:
    text = "".join(c for c in str(value) if c.isprintable())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def report_view(result: dict | None, lang: str | None = None) -> dict:
    """Use rules' scores and stable points order, with built-in fixes only.

    Omit file paths, hostnames, keys, evidence, banners and arbitrary metadata entirely.
    Limits apply before rendering; omitted content is never hidden in the HTML.
    """
    lang = pick_lang(lang)
    view = {"lang": lang, "kind": "empty"}
    if result is None:
        return view
    if result.get("status") != "ok":
        return {
            **view,
            "kind": "error",
            "error_message": file_error_message((result.get("error") or {}).get("code", ""), lang),
        }
    try:
        devices = ranked_devices(result)
        findings = sorted(result.get("findings", []), key=lambda f: -int(f.get("points", 0)))
        score = int(result.get("score") or 0)
        shown = []
        for finding in findings[:MAX_FINDINGS]:
            text = finding_text(finding.get("code", ""), lang)
            shown.append(
                {
                    "title": text.title,
                    "ip": _short(finding.get("ip", "?")),
                    "severity": severity_label(finding.get("severity", "info"), lang),
                    "points": int(finding.get("points", 0)),
                    "step": text.steps[0] if text.steps else text.explanation,
                }
            )
        return {
            **view,
            "kind": "ok",
            "score": score,
            "band": score_band(score, lang),
            "device_count": len(devices),
            "finding_count": len(findings),
            "devices": [
                {
                    "label": device_type_label(d.get("device_type_guess", "unknown"), lang),
                    "ip": _short(d.get("ip", "?")),
                    "mac": safe_mac(d.get("mac_masked")),
                    "points": int(d.get("risk_points", 0)),
                }
                for d in devices[:MAX_DEVICES]
            ],
            "findings": shown,
            "omitted_devices": max(0, len(devices) - MAX_DEVICES),
            "omitted_findings": max(0, len(findings) - MAX_FINDINGS),
        }
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError):
        return {**view, "kind": "error", "error_message": file_error_message("", lang)}
