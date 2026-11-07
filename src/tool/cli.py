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
        if name == "detect":
            cmd.add_argument("--lang", choices=("ro", "en"), default="ro")
            cmd.add_argument("--json", action="store_true", help="machine-readable output")
    return parser


# Until area:content adds these to tool.content (asked on #18), so the CLI is usable now.
_DETECT_ERRORS = {
    "NO_NETWORK": {
        "ro": (
            "Calculatorul nu pare conectat la nicio rețea. "
            "Conectați-l la hotspot și încercați din nou."
        ),
        "en": "This computer doesn't seem to be on any network. Join the hotspot and try again.",
    },
    "SEVERAL_NETWORKS": {
        "ro": "Calculatorul este conectat la mai multe rețele deodată. Lăsați-l doar pe hotspot.",
        "en": "This computer is on several networks at once. Leave it on the hotspot only.",
    },
    "DETECT_FAILED": {
        "ro": "Nu am putut afla la ce rețea este conectat calculatorul.",
        "en": "Couldn't work out which network this computer is on.",
    },
}
_DETECT_LABELS = {
    "ro": ("Interfață", "Adresa acestui calculator", "Rețea", "Router (gateway)"),
    "en": ("Interface", "This computer's address", "Network", "Router (gateway)"),
}


def detect_command(args: argparse.Namespace) -> int:
    from tool.network import DetectError, detect

    try:
        net = detect()
    except DetectError as exc:
        message = _DETECT_ERRORS.get(exc.code, _DETECT_ERRORS["DETECT_FAILED"])[args.lang]
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
    result_path = args.result
    app = create_app(
        lambda: load_json_file(result_path) if result_path else None, explainer=explainer
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
    if args.command == "detect":
        return detect_command(args)
    _help, issue = COMMANDS[args.command]
    where = f" (see issue #{issue})" if issue else ""
    print(f"'{args.command}' is not implemented yet{where}.", file=sys.stderr)
    return 2
