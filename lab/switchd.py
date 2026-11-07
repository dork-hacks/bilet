#!/usr/bin/env python3
"""lab-switch: the one privileged entry point for flipping this Pi's weak services.

Two clients use it, both in the lab-web group:
- the settings page of a fake device (#144), which runs sandboxed as an unprivileged
  dynamic user, so it can't call `sudo labctl`;
- remote.py, the forced command of the lab manager's SSH key (#155).
Each writes one request line to the unix socket of `lab-switch.socket` (root-owned,
group lab-web, mode 0660). systemd starts this script once per connection, as root,
with the connection on stdin and stdout.

A request is exactly one line, at most MAX_LINE bytes:

    status          "preset NAME", then one "SERVICE on|off [default]" line per service
    fix SERVICE     turn a weak service off
    break SERVICE   turn it on
    preset NAME     play another device: its services on, every other service off

SERVICE must be a row of services.tsv and NAME a preset (camera, server, hub or a row of
presets.tsv). Anything else is refused. labctl runs with a fixed argv and no shell, so
the request can never be more than one of these commands. The reply ends with "ok" or
"refused".

Standard library only, Python 3.11+.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

LABCTL = "/usr/local/sbin/labctl"
LAB_DIR = Path(os.environ.get("LAB_DIR", "/opt/lab"))
SERVICES = Path(os.environ.get("LAB_SERVICES", LAB_DIR / "services.tsv"))
PRESETS = Path(os.environ.get("LAB_PRESETS", LAB_DIR / "presets.tsv"))
MAX_LINE = 64  # bytes, newline included
LABCTL_TIMEOUT = 20  # seconds; systemd's RuntimeMaxSec is the hard cap

REQUEST = re.compile(r"(status)|(fix|break) ([a-z][a-z0-9]{0,15})|(preset) ([a-z][a-z0-9-]{0,15})")
STATE_LINE = re.compile(r"([a-z][a-z0-9]{0,15}) (on|off)( default)?")
ROLES = ("camera", "server", "hub")

Runner = Callable[[list[str]], subprocess.CompletedProcess]


class Names:
    """The service and preset names a request may use (as labctl reads them)."""

    def __init__(self, services: list[str], presets: list[str]):
        self.services, self.presets = services, presets

    @classmethod
    def load(cls, services: Path = SERVICES, presets: Path = PRESETS) -> Names:
        return cls(_column(services, 8), [*ROLES, *_column(presets, 3)])


def _column(path: Path, min_cols: int) -> list[str]:
    """The first column of a lab TSV, skipping comments and short rows."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    return [
        line.split("\t")[0]
        for line in text.splitlines()
        if not line.startswith("#") and len(line.split("\t")) >= min_cols
    ]


def parse(line: bytes, names: Names) -> list[str] | None:
    """The labctl arguments for one request line, or None when it must be refused."""
    if len(line) > MAX_LINE or not line.endswith(b"\n"):
        return None
    try:
        text = line[:-1].decode("ascii")
    except UnicodeDecodeError:
        return None
    match = REQUEST.fullmatch(text)
    if not match:
        return None
    if match.group(1):
        return ["state"]
    if match.group(4):
        return ["preset", match.group(5)] if match.group(5) in names.presets else None
    verb, service = match.group(2), match.group(3)
    return [verb, service] if service in names.services else None


def handle(line: bytes, names: Names, run: Runner) -> bytes:
    """Answer one request. `run` gets labctl's full argv (a list, never a shell)."""
    args = parse(line, names)
    if args is None:
        return b"refused\n"
    try:
        done = run([LABCTL, *args])
    except (OSError, subprocess.SubprocessError):
        return b"refused\n"
    if done.returncode != 0:
        return b"refused\n"
    if args == ["state"]:
        # Only pass on well-formed lines about known services and presets.
        lines = []
        for ln in done.stdout.decode("ascii", "replace").splitlines():
            word = ln.split(" ", 1)[0]
            if (STATE_LINE.fullmatch(ln) and word in names.services) or (
                ln.startswith("preset ") and ln[7:] in names.presets
            ):
                lines.append(ln)
        return "".join(f"{ln}\n" for ln in lines).encode() + b"ok\n"
    return b"ok\n"


def run_labctl(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 (argv is LABCTL plus parse()'s fixed words)
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=LABCTL_TIMEOUT,
        check=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
    )


def main() -> int:
    line = sys.stdin.buffer.readline(MAX_LINE + 1)
    names = Names.load()
    reply = handle(line, names, run_labctl)
    # One journal line per request: what was asked (only if it parsed) and the answer.
    args = parse(line, names)
    asked = " ".join(args) if args else "(refused input)"
    print(f"lab-switch: {asked} -> {reply.split()[-1].decode()}", file=sys.stderr)
    sys.stdout.buffer.write(reply)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
