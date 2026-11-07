"""Command-line entry point. Each subcommand is filled in by its own issue."""

import argparse
import sys

from tool import __version__
from tool.config import DISPLAY_NAME

# subcommand -> (help text, issue that implements it)
COMMANDS = {
    "analyze": ("analyse a folder of nmap XML files and write findings.csv / scores.csv", 16),
    "detect": ("show the network this computer is connected to", 19),
    "scan": ("scan your own network (needs --confirm and admin rights)", 20),
    "serve": ("start the web interface", None),
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tool", description=f"{DISPLAY_NAME}: a home network security checker"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    for name, (help_text, _issue) in COMMANDS.items():
        sub.add_parser(name, help=help_text)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    _help, issue = COMMANDS[args.command]
    where = f" (see issue #{issue})" if issue else ""
    print(f"'{args.command}' is not implemented yet{where}.", file=sys.stderr)
    return 2
