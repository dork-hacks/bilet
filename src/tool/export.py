"""`tool analyze <folder>`: the standard results files for a folder of scans (FR-15).

findings.csv: file,ip,port,finding_code,severity   one row per finding
scores.csv:   file,network_score                   one row per file, ERROR if unreadable

Offline and unprivileged. Files are read in name order and rows come out in the
engine's order, so the same folder gives byte-identical files on every run (NFR-05).
Lines end in CRLF and there is no BOM, exactly like the organizers' answer key.
"""

import csv
import os
from dataclasses import dataclass, field
from pathlib import Path

from tool.engine import ScanResult, analyze_file

FINDINGS_HEADER = ("file", "ip", "port", "finding_code", "severity")
SCORES_HEADER = ("file", "network_score")
ERROR = "ERROR"


@dataclass
class Report:
    files: int = 0
    findings: int = 0
    errors: list[tuple[str, str]] = field(default_factory=list)  # (file, error code)


def scan_files(folder: Path) -> list[Path]:
    """The nmap XML files directly in `folder`, in name order. Hidden files are skipped."""
    return sorted(
        (
            p
            for p in folder.iterdir()
            if p.is_file() and p.suffix.lower() == ".xml" and not p.name.startswith(".")
        ),
        key=lambda p: p.name,
    )


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
    folder: Path, out: Path, json_dir: Path | None = None, salt: bytes | None = None
) -> Report:
    """Analyse every scan in `folder` and write findings.csv and scores.csv into `out`.

    An unreadable file becomes an ERROR row and the run carries on with the others.
    `json_dir`, if given, also gets one ScanResult JSON per readable or unreadable file.
    """
    report = Report()
    findings: list[tuple[str, ...]] = []
    scores: list[tuple[str, ...]] = []
    # The CSVs never contain device keys, so a salt is only needed for the JSON files.
    salt = salt if salt is not None else (None if json_dir else b"")
    for path in scan_files(folder):
        result = analyze_file(path, salt=salt)
        report.files += 1
        if result.status != "ok":
            report.errors.append((result.file, (result.error or {}).get("code", "")))
        rows = finding_rows(result)
        report.findings += len(rows)
        findings.extend(rows)
        scores.append(score_row(result))
        if json_dir is not None:
            _write_text(json_dir / f"{Path(result.file).stem}.json", result.to_json())

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
