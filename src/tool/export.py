"""`tool analyze <folder>`: the standard results files for a folder of scans (FR-15).

findings.csv: file,ip,port,finding_code,severity   one row per finding
scores.csv:   file,network_score                   one row per file, ERROR if unreadable

Offline and unprivileged. Files are read in name order and rows come out in the
engine's order, so the same folder gives byte-identical files on every run (NFR-05).
Lines end in CRLF and there is no BOM, exactly like the organizers' answer key.
"""

import csv
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from tool.engine import ScanResult, analyze_file
from tool.engine.device import load_salt
from tool.engine.result import error_result

FINDINGS_HEADER = ("file", "ip", "port", "finding_code", "severity")
SCORES_HEADER = ("file", "network_score")
ERROR = "ERROR"
ANALYSIS_FAILED = "ANALYSIS_FAILED"
JSON_WRITE_FAILED = "JSON_WRITE_FAILED"
LOCAL_SALT_UNAVAILABLE = "LOCAL_SALT_UNAVAILABLE"


@dataclass
class Report:
    files: int = 0
    findings: int = 0
    errors: list[tuple[str, str]] = field(default_factory=list)  # (file, error code)
    results: list[ScanResult] = field(default_factory=list)  # in file order
    warnings: list[tuple[str, str]] = field(default_factory=list)  # optional-output problems


# Folder exclusions, even with --all-files: our own results, answer keys and notes.
NOT_SCANS = frozenset({".csv", ".md"})


def scan_files(folder: Path, all_files: bool = False) -> list[Path]:
    """An explicit file, or selected scans directly in a folder, in name order.

    Explicit files are read regardless of suffix; folder selection skips hidden files.

    `all_files` (#203) reads every other visible file too, except CSVs (our results and
    answer keys) and *.md notes, so a Test Set file without the .xml ending still gets
    its ERROR row."""
    if folder.is_file():  # An explicit file path is an intentional selection.
        return [folder]
    return sorted(
        (p for p in _visible_files(folder) if _is_scan(p, all_files)),
        key=lambda p: p.name,
    )


def skipped_files(folder: Path, all_files: bool = False) -> list[str]:
    """Visible files in `folder` that look like they could be scans but aren't read, in
    name order. CSV/Markdown folder entries are excluded; explicit files are selected."""
    if folder.is_file():
        return []
    return sorted(
        p.name
        for p in _visible_files(folder)
        if not _is_scan(p, all_files) and p.suffix.lower() not in NOT_SCANS
    )


def _visible_files(folder: Path) -> list[Path]:
    return [p for p in folder.iterdir() if p.is_file() and not p.name.startswith(".")]


def _is_scan(path: Path, all_files: bool) -> bool:
    if path.suffix.lower() == ".xml":
        return True
    return all_files and path.suffix.lower() not in NOT_SCANS


def finding_rows(result: ScanResult) -> list[tuple[str, str, str, str, str]]:
    return [
        (
            result.file,
            f["ip"],
            "" if f["port"] is None else str(f["port"]),  # UNKNOWN_DEVICE: empty port
            f["code"],
            f["severity"],
        )
        for f in result.findings
    ]


def score_row(result: ScanResult) -> tuple[str, str]:
    return (result.file, ERROR if result.status != "ok" else str(result.score))


def analyze_folder(
    folder: Path,
    out: Path,
    json_dir: Path | None = None,
    salt: bytes | None = None,
    all_files: bool = False,
) -> Report:
    """Analyse every scan in `folder` and write findings.csv and scores.csv into `out`.

    An unreadable file becomes an ERROR row and the run carries on with the others.
    `json_dir`, if given, also gets one ScanResult JSON per readable or unreadable file.
    """
    report = Report()
    findings: list[tuple[str, ...]] = []
    scores: list[tuple[str, ...]] = []
    # Resolve one salt for the whole batch. CSV-only runs do not touch local data.
    if salt is None:
        if json_dir is None:
            salt = b""
        else:
            try:
                salt = load_salt()
            except OSError:
                salt = secrets.token_bytes(32)
                report.warnings.append(("", LOCAL_SALT_UNAVAILABLE))
    for path in scan_files(folder, all_files):
        try:
            result = analyze_file(path, salt=salt)
            rows = finding_rows(result)
            score = score_row(result)
        except Exception:  # isolate one internal failure; interrupts still propagate
            result = error_result(path.name, ANALYSIS_FAILED)
            rows, score = [], score_row(result)
        report.files += 1
        report.results.append(result)
        if result.status != "ok":
            report.errors.append((result.file, (result.error or {}).get("code", "")))
        report.findings += len(rows)
        findings.extend(rows)
        scores.append(score)
        if json_dir is not None:
            try:
                _write_text(json_dir / f"{Path(result.file).stem}.json", result.to_json())
            except Exception:  # optional JSON must not suppress known standard results
                report.warnings.append((result.file, JSON_WRITE_FAILED))

    _write_csv(out / "findings.csv", FINDINGS_HEADER, findings)
    _write_csv(out / "scores.csv", SCORES_HEADER, scores)
    return report


def _write_csv(path: Path, header: tuple[str, ...], rows: list[tuple[str, ...]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:  # csv's own \r\n line ends
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerows(rows)
    os.replace(tmp, path)  # never leave a half-written results file


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
