"""Turns the local scan history (#21) into what the history screen shows (#65, FR-10).

Pure functions over `tool.history.History`, no web framework. Every text comes from
tool.content; RAW scan fields (file names, hostnames) are passed through as data and
escaped by the template, never here.
"""

import sqlite3
from dataclasses import dataclass

from tool.content import device_type_label, finding_text
from tool.history import Diff, History, HistoryError, ScanSummary
from tool.web.view import Band, pick_lang, score_band, t

# The trend chart's drawing area, in SVG user units (it scales with the page width).
CHART_W, CHART_H, CHART_PAD = 600, 220, 30
HISTORY_READ_ERRORS = (
    HistoryError,
    sqlite3.Error,
    OSError,
    ValueError,
    KeyError,
    TypeError,
    AttributeError,
    OverflowError,
)


@dataclass(frozen=True)
class ScanRow:
    id: int
    when: str  # "2026-11-07 09:00 UTC", or the file name's fallback text
    file: str  # RAW, escaped by the template
    ok: bool
    score: int | None
    band: Band | None


@dataclass(frozen=True)
class ChartPoint:
    x: float
    y: float
    score: int
    when: str


@dataclass(frozen=True)
class Chart:
    width: int
    height: int
    points: tuple[ChartPoint, ...]

    @property
    def polyline(self) -> str:
        return " ".join(f"{p.x:g},{p.y:g}" for p in self.points)

    def y_for(self, score: int) -> float:
        return _y(score)


@dataclass(frozen=True)
class Change:
    """One line of the comparison, already worded. `extra` is RAW (a hostname)."""

    text: str
    extra: str | None = None


@dataclass(frozen=True)
class Comparison:
    old: ScanRow
    new: ScanRow
    score_line: str
    sections: tuple[tuple[str, tuple[Change, ...]], ...]  # (heading, lines), non-empty only

    @property
    def unchanged(self) -> bool:
        return not self.sections


@dataclass(frozen=True)
class HistoryView:
    lang: str
    enabled: bool  # False when the app runs without a history database
    scans: tuple[ScanRow, ...] = ()  # oldest first, by nmap's start time
    trend_summary: str | None = None
    chart: Chart | None = None
    choices: tuple[ScanRow, ...] = ()  # readable scans only: what the picker offers
    old_id: int | None = None
    new_id: int | None = None
    comparison: Comparison | None = None
    message: str | None = None  # "pick two different scans", "history deleted", …
    confirm_delete: bool = False  # show the "are you sure?" step
    unavailable: bool = False  # a read/comparison failed; never claim the history is empty


def when_label(summary: ScanSummary, lang: str) -> str:
    return scan_time_label(summary.scan_start, lang)


def scan_time_label(start: str | None, lang: str) -> str:
    """nmap's start time as "YYYY-MM-DD HH:MM UTC" (the contract stores ISO 8601 UTC)."""
    if start and len(start) >= 16 and start[10] == "T":
        return f"{start[:10]} {start[11:16]} UTC"
    return t("history_no_time", lang)


def scan_row(summary: ScanSummary, lang: str) -> ScanRow:
    ok = summary.status == "ok" and summary.score is not None
    return ScanRow(
        id=summary.id,
        when=when_label(summary, lang),
        file=summary.file,
        ok=ok,
        score=summary.score if ok else None,
        band=score_band(summary.score, lang) if ok else None,
    )


def _y(score: int) -> float:
    clamped = max(0, min(100, score))
    return round(CHART_PAD + (100 - clamped) * (CHART_H - 2 * CHART_PAD) / 100, 1)


def trend_chart(rows: list[ScanRow]) -> Chart | None:
    """A line from the oldest readable scan to the newest. None with fewer than two."""
    ok = [r for r in rows if r.ok]
    if len(ok) < 2:
        return None
    step = (CHART_W - 2 * CHART_PAD) / (len(ok) - 1)
    points = tuple(
        ChartPoint(round(CHART_PAD + i * step, 1), _y(r.score), r.score, r.when)
        for i, r in enumerate(ok)
    )
    return Chart(CHART_W, CHART_H, points)


def trend_summary(rows: list[ScanRow], lang: str) -> str | None:
    ok = [r for r in rows if r.ok]
    if len(ok) < 2:
        return None
    first, last = ok[0].score, ok[-1].score
    key = "trend_up" if last > first else "trend_down" if last < first else "trend_same"
    return t(key, lang).replace("{a}", str(first)).replace("{b}", str(last))


def _device_label(device: dict | None, ip: str, lang: str) -> str:
    kind = device_type_label((device or {}).get("device_type_guess", "unknown"), lang)
    return t("device_at", lang).replace("{device}", kind).replace("{ip}", ip)


def _finding_line(finding: dict, devices: dict[str, dict], lang: str) -> Change:
    device = devices.get(finding.get("device_key", ""))
    title = finding_text(finding["code"], lang).title
    line = f"{title}: {_device_label(device, finding.get('ip', ''), lang)}"
    if finding.get("port") is not None:
        port = f"{finding['port']}/{finding.get('protocol')}"
        line += " · " + t("port", lang).replace("{port}", port)
    return Change(line)


def comparison(history: History, diff: Diff, lang: str) -> Comparison:
    old_result = history.result(diff.old.id)
    new_result = history.result(diff.new.id)
    old_devices = {d["device_key"]: d for d in old_result.get("devices", [])}
    new_devices = {d["device_key"]: d for d in new_result.get("devices", [])}

    def device_change(device: dict) -> Change:
        return Change(_device_label(device, device["ip"], lang), device.get("hostname"))

    def port_change(change, devices: dict[str, dict]) -> Change:
        label = _device_label(devices.get(change.device), change.ip, lang)
        port = t("port", lang).replace("{port}", f"{change.port}/{change.protocol}")
        return Change(f"{label} · {port}")

    resolved = tuple(_finding_line(f, old_devices, lang) for f in diff.resolved_findings)
    appeared = tuple(_finding_line(f, new_devices, lang) for f in diff.new_findings)
    sections = (
        ("diff_resolved", resolved),
        ("diff_new_findings", appeared),
        ("diff_new_devices", tuple(device_change(d) for d in diff.new_devices)),
        ("diff_removed_devices", tuple(device_change(d) for d in diff.removed_devices)),
        ("diff_opened", tuple(port_change(c, new_devices) for c in diff.opened_ports)),
        ("diff_closed", tuple(port_change(c, new_devices) for c in diff.closed_ports)),
    )
    key = (
        "diff_score_up"
        if diff.score_change > 0
        else "diff_score_down"
        if diff.score_change < 0
        else "diff_score_same"
    )
    score_line = (
        t(key, lang).replace("{a}", str(diff.score_before)).replace("{b}", str(diff.score_after))
    )
    return Comparison(
        old=scan_row(diff.old, lang),
        new=scan_row(diff.new, lang),
        score_line=score_line,
        sections=tuple((t(heading, lang), lines) for heading, lines in sections if lines),
    )


def _as_id(value: str | None) -> int | None:
    if value is None or not value.isascii() or not value.isdigit() or len(value) > 12:
        return None
    return int(value)


def history_view(
    history: History | None,
    lang: str | None = None,
    old: str | None = None,
    new: str | None = None,
    message_key: str | None = None,
    confirm_delete: bool = False,
) -> HistoryView:
    """The history screen. `old` / `new` are the picker's raw query values (untrusted)."""
    lang = pick_lang(lang)
    message = t(message_key, lang) if message_key else None
    if history is None:
        return HistoryView(lang=lang, enabled=False, message=message)
    try:
        rows = [scan_row(s, lang) for s in history.scans()]
    except HISTORY_READ_ERRORS:
        return HistoryView(
            lang=lang,
            enabled=True,
            message=message or t("history_read_failed", lang),
            confirm_delete=confirm_delete,
            unavailable=True,
        )
    choices = [r for r in rows if r.ok]
    base = {
        "lang": lang,
        "enabled": True,
        "scans": tuple(rows),
        "trend_summary": trend_summary(rows, lang),
        "chart": trend_chart(rows),
        "choices": tuple(choices),
        "confirm_delete": confirm_delete,
    }
    if len(choices) < 2:
        return HistoryView(message=message, **base)

    # Default: the two newest readable scans. Unknown ids fall back to the default.
    ids = [r.id for r in choices]
    old_id, new_id = _as_id(old), _as_id(new)
    old_id = old_id if old_id in ids else ids[-2]
    new_id = new_id if new_id in ids else ids[-1]
    if old_id == new_id:
        return HistoryView(old_id=old_id, new_id=new_id, message=t("compare_same", lang), **base)
    try:
        diff = history.diff(old_id, new_id)
        changes = comparison(history, diff, lang)
    except HISTORY_READ_ERRORS:
        return HistoryView(
            old_id=old_id,
            new_id=new_id,
            message=message or t("history_read_failed", lang),
            unavailable=True,
            **base,
        )
    return HistoryView(
        old_id=old_id,
        new_id=new_id,
        comparison=changes,
        message=message,
        **base,
    )
