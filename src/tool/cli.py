"""Command-line entry point. Each subcommand is filled in by its own issue."""

import argparse
import os
import sys
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
    return parser


def serve(args: argparse.Namespace) -> int:
    # Least privilege (MASTERPLAN §3.7): only the live scan step may run as root.
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print(
            "Refusing to start the web interface as root. Run it as a normal user.",
            file=sys.stderr,
        )
        return 2
    import uvicorn

    from tool.web.app import create_app, load_json_file

    result_path = args.result
    app = create_app(lambda: load_json_file(result_path) if result_path else None)
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
    _help, issue = COMMANDS[args.command]
    where = f" (see issue #{issue})" if issue else ""
    print(f"'{args.command}' is not implemented yet{where}.", file=sys.stderr)
    return 2
