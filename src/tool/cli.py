"""Command-line entry point. Each subcommand is filled in by its own issue."""

import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from tool import __version__
from tool.config import DISPLAY_NAME

# subcommand -> (help text, issue that implements it)
COMMANDS = {
    "analyze": ("analyse a folder of nmap XML files and write findings.csv / scores.csv", 16),
    "detect": ("show the network this computer is connected to", 19),
    "scan": ("scan your own network (needs --confirm and admin rights)", 20),
    "serve": ("start the web interface", 29),
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tool", description=f"{DISPLAY_NAME}: a home network security checker"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    for name, (help_text, _issue) in COMMANDS.items():
        cmd = sub.add_parser(name, help=help_text)
        if name == "serve":
            cmd.add_argument(
                "--result", type=Path, help="show this ScanResult JSON (until history lands)"
            )
            cmd.add_argument("--host", default="127.0.0.1", help="default: this computer only")
            cmd.add_argument("--port", type=int, default=8000)
        if name == "analyze":
            cmd.add_argument("folder", type=Path, help="folder with nmap XML files")
            cmd.add_argument(
                "--out", type=Path, default=Path("out"), help="where to write the CSVs"
            )
            cmd.add_argument(
                "--json", action="store_true", help="also write one ScanResult JSON per file"
            )
            cmd.add_argument("--lang", choices=("ro", "en"), default="ro")
        if name == "detect":
            cmd.add_argument("--lang", choices=("ro", "en"), default="ro")
            cmd.add_argument("--json", action="store_true", help="machine-readable output")
    return parser


_DETECT_LABELS = {
    "ro": ("Interfață", "Adresa acestui calculator", "Rețea", "Router (gateway)"),
    "en": ("Interface", "This computer's address", "Network", "Router (gateway)"),
}


def analyze_command(args: argparse.Namespace) -> int:
    from tool.content import file_error_message
    from tool.export import analyze_folder

    folder: Path = args.folder
    if not folder.is_dir():
        print(f"{folder}: not a folder", file=sys.stderr)
        return 2
    json_dir = args.out / "json" if args.json else None
    report = analyze_folder(folder, args.out, json_dir=json_dir)
    for file, code in report.errors:  # a broken file is reported, never fatal
        print(f"{file}: {file_error_message(code, args.lang)} ({code})", file=sys.stderr)
    print(
        f"{report.files} files, {report.findings} findings, {len(report.errors)} unreadable"
        f" -> {args.out / 'findings.csv'}, {args.out / 'scores.csv'}"
    )
    return 0


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
            "Refusing to start the web interface as root. Run it as a normal user.",
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

    result_path = args.result
    app = create_app(
        lambda: load_json_file(result_path) if result_path else None,
        explainer=explainer,
        history=History(),  # local SQLite in the data folder (#21), read by /history
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "serve":
        return serve(args)
    if args.command == "analyze":
        return analyze_command(args)
    if args.command == "detect":
        return detect_command(args)
    _help, issue = COMMANDS[args.command]
    where = f" (see issue #{issue})" if issue else ""
    print(f"'{args.command}' is not implemented yet{where}.", file=sys.stderr)
    return 2
