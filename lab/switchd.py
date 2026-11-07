#!/usr/bin/env python3
"""lab-switch: the one privileged entry point for flipping this Pi's weak services.

The settings page of a fake device (#144) runs sandboxed as an unprivileged dynamic
user, so it can't call `sudo labctl`. Instead it writes one request line to the
unix socket of `lab-switch.socket` (root-owned, group lab-web, mode 0660). systemd
starts this script once per connection, as root, with the connection on stdin and
stdout.

A request is exactly one line, at most MAX_LINE bytes:

    status          one "SERVICE on|off" line per service of this Pi's role
    fix SERVICE     turn a weak service off
    break SERVICE   turn it back on

SERVICE must be a service of this Pi's role in services.tsv. Anything else is
refused. labctl runs with a fixed argv and no shell, so the request can never be
more than one of these commands. The reply ends with "ok" or "refused".

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
ROLE_FILE = Path(os.environ.get("LAB_ROLE_FILE", "/etc/lab/role"))
MAX_LINE = 64  # bytes, newline included
LABCTL_TIMEOUT = 20  # seconds; systemd's RuntimeMaxSec is the hard cap

REQUEST = re.compile(r"(status)|(fix|break) ([a-z][a-z0-9]{0,15})")
ROLE = re.compile(r"camera|server|hub")

Runner = Callable[[list[str]], subprocess.CompletedProcess]


def role_services(role: str, services: Path = SERVICES) -> list[str]:
    """The services of one role, in services.tsv order (as `labctl rows` reads them)."""
    names = []
    for line in services.read_text(encoding="utf-8").splitlines():
        cols = line.split("\t")
        if line.startswith("#") or len(cols) < 8:
            continue
        if cols[1] == role:
            names.append(cols[0])
    return names


def read_role(role_file: Path = ROLE_FILE) -> str | None:
    try:
        role = role_file.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return role if ROLE.fullmatch(role) else None


def parse(line: bytes, allowed: list[str]) -> list[str] | None:
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
    verb, service = match.group(2), match.group(3)
    return [verb, service] if service in allowed else None


def handle(line: bytes, allowed: list[str], run: Runner) -> bytes:
    """Answer one request. `run` gets labctl's full argv (a list, never a shell)."""
    args = parse(line, allowed)
    if args is None:
        return b"refused\n"
    try:
        done = run([LABCTL, *args])
    except (OSError, subprocess.SubprocessError):
        return b"refused\n"
    if done.returncode != 0:
        return b"refused\n"
    if args == ["state"]:
        # Only pass on well-formed lines about this role's services.
        lines = [
            ln
            for ln in done.stdout.decode("ascii", "replace").splitlines()
            if re.fullmatch(r"([a-z][a-z0-9]{0,15}) (on|off)", ln) and ln.split()[0] in allowed
        ]
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
    role = read_role()
    allowed = role_services(role) if role else []
    reply = handle(line, allowed, run_labctl)
    # One journal line per request: what was asked (only if it parsed) and the answer.
    args = parse(line, allowed)
    asked = " ".join(args) if args else "(refused input)"
    print(f"lab-switch: {asked} -> {reply.split()[-1].decode()}", file=sys.stderr)
    sys.stdout.buffer.write(reply)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
