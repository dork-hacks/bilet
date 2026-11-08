"""Command-line entry point: `bilet` (or `tool`) analyze | detect | scan | serve."""

import argparse
import json
import os
import secrets
import sys
import time
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path

from tool import __version__
from tool.config import DISPLAY_NAME
from tool.content.cli import cli_text, parser_error

COMMANDS = {name: cli_text(name, "en") for name in ("analyze", "detect", "scan", "serve")}


# The commands that start this CLI (#101). --help shows the one that was typed.
PROGRAM_NAMES = ("bilet", "tool")


def program_name() -> str:
    name = Path(sys.argv[0]).name if sys.argv and sys.argv[0] else ""
    return name if name in PROGRAM_NAMES else "tool"


class LocalizedParser(argparse.ArgumentParser):
    """Translate this parser only; never mutate argparse's process-wide gettext."""

    def __init__(self, *args, lang="ro", **kwargs):
        self.lang = lang
        super().__init__(*args, add_help=False, **kwargs)
        self._positionals.title = cli_text("positionals", lang)
        self._optionals.title = cli_text("options", lang)
        self.add_argument("-h", "--help", action="help", help=cli_text("help", lang))

    def format_usage(self):
        return self._localized_usage(super().format_usage())

    def format_help(self):
        return self._localized_usage(super().format_help())

    def _localized_usage(self, text):
        return cli_text("usage", self.lang) + text.removeprefix("usage: ")

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(
            2,
            f"{self.prog}: {cli_text('error', self.lang)}: "
            f"{parser_error(message, self.lang)}\n",
        )


def selected_language(argv: list[str]) -> str:
    """Read language before argparse handles early exits such as --help.

    The preliminary parser honours -- and --lang=value. Full validation remains
    with the actual command parser, including invalid/missing language values.
    """
    selector = argparse.ArgumentParser(add_help=False, exit_on_error=False)
    selector.add_argument("--lang", action="append", default=[])
    args = argparse.Namespace(lang=[])
    try:
        selector.parse_known_args(argv, namespace=args)
    except argparse.ArgumentError:
        pass  # Keep earlier choices when a trailing --lang is missing its value.
    return next((lang for lang in reversed(args.lang) if lang in ("ro", "en")), "ro")


def build_parser(lang: str = "ro") -> argparse.ArgumentParser:
    parser = LocalizedParser(
        prog=program_name(),
        lang=lang,
        description=f"{DISPLAY_NAME}: {cli_text('description', lang)}",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help=cli_text("version", lang),
    )
    parser.add_argument("--lang", choices=("ro", "en"), default=lang, help=cli_text("lang", lang))
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    for name in COMMANDS:
        cmd = sub.add_parser(
            name, lang=lang, help=cli_text(name, lang), description=cli_text(name, lang)
        )
        cmd.add_argument(
            "--lang", choices=("ro", "en"), default=argparse.SUPPRESS, help=cli_text("lang", lang)
        )
        if name == "serve":
            cmd.add_argument("--result", type=Path, help=cli_text("result", lang))
            cmd.add_argument("--host", default="127.0.0.1", help=cli_text("host", lang))
            cmd.add_argument("--port", type=int, default=8000, help=cli_text("port", lang))
        if name == "scan":
            cmd.add_argument("targets", nargs="*", help=cli_text("targets", lang))
            cmd.add_argument("--confirm", action="store_true", help=cli_text("confirm", lang))
            cmd.add_argument(
                "--scans-dir", type=Path, default=None, help=cli_text("scans_dir", lang)
            )
        if name == "analyze":
            cmd.add_argument("folder", type=Path, help=cli_text("folder", lang))
            cmd.add_argument("--out", type=Path, default=Path("out"), help=cli_text("out", lang))
            cmd.add_argument("--json", action="store_true", help=cli_text("json_results", lang))
            cmd.add_argument("--save", action="store_true", help=cli_text("save", lang))
            cmd.add_argument("--all-files", action="store_true", help=cli_text("all_files", lang))
        if name == "detect":
            cmd.add_argument("--json", action="store_true", help=cli_text("json", lang))
    return parser


_DETECT_LABELS = {
    "ro": ("Interfață", "Adresa acestui calculator", "Rețea", "Router (gateway)"),
    "en": ("Interface", "This computer's address", "Network", "Router (gateway)"),
}


PROGRESS_EVERY_S = 15.0  # at most one progress line this often, unless the step changes


class ProgressPrinter:
    """Prints nmap's progress as plain RO/EN lines (#107): when the step changes, and
    otherwise at most once every PROGRESS_EVERY_S seconds, so the user sees the scan
    isn't stuck without the screen filling up."""

    def __init__(
        self,
        lang: str,
        clock: Callable[[], float] = time.monotonic,
        out: Callable[[str], None] | None = None,
    ):
        self.lang, self.clock = lang, clock
        self.out = out or (lambda line: print(line, flush=True))
        self.step: str | None = None
        self.last = 0.0

    def __call__(self, step: str, percent: float, seconds_left: int | None) -> None:
        from tool.content import scan_progress_message

        now = self.clock()
        if step == self.step and now - self.last < PROGRESS_EVERY_S:
            return
        self.step, self.last = step, now
        self.out(scan_progress_message(step, percent, seconds_left, self.lang))


def scan_command(args: argparse.Namespace) -> int:
    """Guardrail first (FR-02): nothing is scanned unless every check passes."""
    from tool import scan as live
    from tool.content import (
        detect_error_message,
        file_error_message,
        hosts_found_message,
        refusal_message,
        scan_message,
    )
    from tool.engine import analyze_file
    from tool.guardrail import Refused, authorize, build_allowlist, extra_ranges_from_env
    from tool.network import DetectError, detect

    # Least privilege (MASTERPLAN §3.7): only the nmap subprocess gets admin rights.
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print(scan_message("RUN_AS_ROOT", args.lang), file=sys.stderr)
        return 2
    try:
        net = detect()
    except DetectError as exc:
        print(detect_error_message(exc.code, args.lang), file=sys.stderr)
        return 1
    try:
        allowlist = build_allowlist(net.subnet, extra_ranges_from_env())
        networks = authorize(args.targets or [net.subnet], allowlist, args.confirm)
    except Refused as exc:
        print(refusal_message(exc.code, exc.target, args.lang), file=sys.stderr)
        print(f"({exc.code})", file=sys.stderr)
        return 3
    targets = ", ".join(str(n) for n in networks)
    print(scan_message("START", args.lang, targets=targets), flush=True)
    print(scan_message("SELF_SKIPPED", args.lang, address=net.address), flush=True)
    try:
        path = live.run_scan(
            networks,
            runner=live.run_nmap,
            scans_dir=args.scans_dir,
            exclude=[net.address],
            on_hosts=lambda hosts: print(hosts_found_message(hosts, args.lang), flush=True),
            on_progress=ProgressPrinter(args.lang),
        )
    except live.ScanError as exc:
        print(scan_message(exc.code, args.lang, targets=targets), file=sys.stderr)
        print(f"({exc.code}{': ' + exc.detail if exc.detail else ''})", file=sys.stderr)
        return 4
    result = analyze_file(path)  # unprivileged, the same engine as `tool analyze`
    if result.status != "ok":
        code = result.error["code"]
        print(f"{path}: {file_error_message(code, args.lang)} ({code})", file=sys.stderr)
        save_and_alert([result], args.lang)
        return 1
    print(
        scan_message(
            "DONE", args.lang, path=path, score=result.score, findings=len(result.findings)
        )
    )
    save_and_alert([result], args.lang)
    return 0


def analyze_command(args: argparse.Namespace) -> int:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print(cli_text("analyze_root", args.lang), file=sys.stderr)
        return 2

    from tool.content import file_error_message, history_error_message
    from tool.engine.device import load_salt
    from tool.export import analyze_folder, skipped_files

    folder: Path = args.folder
    if not folder.is_dir():
        print(f"{folder}: {cli_text('not_folder', args.lang)}", file=sys.stderr)
        return 2
    json_dir = args.out / "json" if args.json else None
    # History keys devices with the private local salt; CSV-only runs never need it.
    salt = None
    if args.save or args.json:
        try:
            salt = load_salt()
        except OSError as exc:
            if args.save:
                print(f"{history_error_message(args.lang)} ({type(exc).__name__})", file=sys.stderr)
            print(cli_text("LOCAL_SALT_UNAVAILABLE", args.lang), file=sys.stderr)
            args.save = False  # ephemeral keys must never be stored as stable history
            salt = secrets.token_bytes(32) if args.json else b""
    try:
        report = analyze_folder(
            folder, args.out, json_dir=json_dir, salt=salt, all_files=args.all_files
        )
    except OSError:
        print(cli_text("export_failed", args.lang), file=sys.stderr)
        return 2
    for file, code in report.warnings:
        prefix = f"{file}: " if file else ""
        print(f"{prefix}{cli_text(code, args.lang)} ({code})", file=sys.stderr)
    skipped = skipped_files(folder, args.all_files)
    if skipped:
        print(cli_text("skipped", args.lang, names=", ".join(skipped)), file=sys.stderr)
    for file, code in report.errors:  # a broken file is reported, never fatal
        print(f"{file}: {file_error_message(code, args.lang)} ({code})", file=sys.stderr)
    print(
        cli_text(
            "totals",
            args.lang,
            files=report.files,
            findings=report.findings,
            errors=len(report.errors),
        )
        + f" -> {args.out / 'findings.csv'}, {args.out / 'scores.csv'}"
    )
    if args.save:
        save_and_alert(report.results, args.lang)
    return 0


def save_and_alert(results: list, lang: str) -> bool:
    """Store every result in the history (unreadable ones as error rows, which are never
    compared) and print what appeared since the previous readable scan.

    A history problem (a database from a newer version, a locked or corrupt file, a full
    disk) never ends the command with a traceback: the scan or the CSVs are already
    saved, so it prints one plain line and returns False (#132)."""
    import sqlite3

    from tool.content import history_error_message
    from tool.history import HistoryError

    try:
        _save_and_alert(results, lang)
    except (HistoryError, sqlite3.Error, OSError) as exc:
        print(f"{history_error_message(lang)} ({type(exc).__name__}: {exc})", file=sys.stderr)
        return False
    return True


def _save_and_alert(results: list, lang: str) -> None:
    from tool.content import alert_message
    from tool.history import History

    history = History()
    ids = [history.add(r) for r in results]
    print(cli_text("saved", lang, count=len(ids)))
    readable = [i for i, r in zip(ids, results, strict=True) if r.status == "ok"]
    if not readable:
        return
    newest = max(readable, key=[s.id for s in history.scans()].index)
    for alert in history.alerts_for(newest):
        text = alert_message(alert.code, alert.ip, alert.port, alert.protocol, lang)
        print(text, f"({alert.code})")


def detect_command(args: argparse.Namespace) -> int:
    from tool.content import detect_error_message
    from tool.network import DetectError, detect

    try:
        net = detect()
    except DetectError as exc:
        message = detect_error_message(exc.code, args.lang)
        if args.json:
            print(json.dumps({"error": {"code": exc.code, "detail": exc.detail}}))
        else:
            print(message, file=sys.stderr)
            if exc.detail:
                print(f"({exc.code}: {exc.detail})", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(asdict(net)))
        return 0
    labels = _DETECT_LABELS[args.lang]
    for label, value in zip(
        labels, (net.interface, net.address, net.subnet, net.gateway), strict=True
    ):
        print(f"{label}: {value}")
    return 0


def serve(args: argparse.Namespace) -> int:
    # Least privilege (MASTERPLAN §3.7): only the live scan step may run as root.
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print(
            cli_text("serve_root", getattr(args, "lang", "ro")),
            file=sys.stderr,
        )
        return 2
    import uvicorn

    from tool.ai.explain import Explainer
    from tool.ai.provider import provider_from_env
    from tool.config import data_dir
    from tool.web.app import create_app, load_json_file

    # The provider comes from LLM_PROVIDER / LLM_API_KEY; with none set, AI stays off.
    # Cache and rejection log are local data (NFR-02), never committed.
    explainer = Explainer(
        provider_from_env(),
        cache_dir=data_dir() / "ai_cache",
        rejection_log=data_dir() / "ai_rejections.jsonl",
    )
    from tool.history import History
    from tool.scan_runner import ScanRunner

    result_path = args.result
    history = History()  # local SQLite in the data folder (#21), read by /history
    app = create_app(
        lambda: load_json_file(result_path) if result_path else None,
        explainer=explainer,
        history=history,
        # "Check again" (#135): the page only offers it to this computer (loopback), and
        # each new scan lands in the same history the pages read.
        scan_runner=ScanRunner(history=lambda: history),
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser(selected_language(argv))
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    return HANDLERS[args.command](args)


HANDLERS: dict[str, Callable[[argparse.Namespace], int]] = {
    "analyze": analyze_command,
    "detect": detect_command,
    "scan": scan_command,
    "serve": serve,
}


if __name__ == "__main__":
    raise SystemExit(main())
