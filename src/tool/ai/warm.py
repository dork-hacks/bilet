"""Pre-generate AI explanations for known scans (MASTERPLAN §5.2).

    python -m tool.ai.warm <ScanResult JSON or folder of them> [...]

Runs the normal `Explainer` over every finding, so each accepted answer lands in the
same on-disk cache that `tool serve` reads. Later page views are then instant and
identical, even on a slow hotspot. Nothing is bypassed: every answer still goes through
the grounding checker, and rejected or timed-out answers are never cached.

Offline helper: it reads JSON files only, never calls nmap and never needs root.
The input is what `tool analyze <folder> --json` writes. Output lines carry only the
file name, the evidence id, the catalog code and the outcome: no IP, MAC, hostname,
banner or AI text.
"""

import argparse
import json
import os
import sys
from collections.abc import Iterator
from pathlib import Path

from tool.ai.evidence import build_evidence
from tool.ai.explain import Explainer
from tool.ai.provider import provider_from_env
from tool.config import data_dir

MAX_RESULT_BYTES = 5 * 1024 * 1024  # same limit as the web UI


def default_explainer() -> Explainer:
    """The same provider, cache and rejection log that `tool serve` uses."""
    return Explainer(
        provider_from_env(),
        cache_dir=data_dir() / "ai_cache",
        rejection_log=data_dir() / "ai_rejections.jsonl",
    )


def result_files(paths: list[Path]) -> Iterator[Path]:
    """Each path as given, or the *.json files of a folder in name order."""
    for path in paths:
        if path.is_dir():
            yield from sorted(p for p in path.glob("*.json") if p.is_file())
        else:
            yield path


def _load(path: Path) -> dict | None:
    """Like `tool.web.app.load_json_file`, without importing FastAPI."""
    try:
        if path.stat().st_size > MAX_RESULT_BYTES:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _outcome(source: str, reason: str) -> str:
    if reason == "cache":
        return "cache"
    if source == "ai":
        return "ai"
    return f"template:{reason}"


def _eid_order(eid: str) -> int:
    return int(eid[1:]) if eid[1:].isdigit() else 0


def warm(paths: list[Path], explainer: Explainer, out=sys.stdout) -> dict[str, int]:
    """Explain every finding of every readable scan. Returns a count per outcome."""
    counts: dict[str, int] = {}
    for path in result_files(paths):
        result = _load(path)
        if result is None or result.get("status") != "ok":
            print(f"{path.name}: skipped (not a readable ScanResult)", file=out)
            counts["skipped"] = counts.get("skipped", 0) + 1
            continue
        evidence = build_evidence(result)
        codes = {
            item["id"]: item.get("code") or ""
            for device in evidence.payload["devices"]
            for item in device["findings"]
        }
        for eid in sorted(evidence.finding_refs, key=_eid_order):
            answer = explainer.explain_finding(evidence, eid)
            outcome = _outcome(answer.source, answer.reason)
            print(f"{path.name} {eid} {codes.get(eid, '')}: {outcome}", file=out)
            key = outcome.split(":", 1)[0]
            counts[key] = counts.get(key, 0) + 1
    return counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tool.ai.warm",
        description="Pre-generate AI explanations for analysed scans (fills the local cache).",
    )
    parser.add_argument("paths", nargs="+", type=Path, help="ScanResult JSON files or folders")
    args = parser.parse_args(argv)

    # Least privilege (MASTERPLAN §3.7): only the live scan step may run as root.
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print("Refusing to run as root. Run it as a normal user.", file=sys.stderr)
        return 2

    explainer = default_explainer()
    if explainer.provider is None:
        print("AI is off (LLM_PROVIDER is none or no key is set). Nothing to pre-generate.")
        return 0

    counts = warm(args.paths, explainer)
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "no findings"
    print(f"done: {summary}; the AI blocked {explainer.rejection_count()} answers so far")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
