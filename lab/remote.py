#!/usr/bin/env python3
"""lab-remote: the forced command of the lab manager's SSH key (#155).

The lab manager on the Pi 5 runs `ssh labmgr@<pi> "<request>"`. The key in labmgr's
authorized_keys is restricted to this script (`restrict,command=...`), so whatever the
manager asks arrives here in SSH_ORIGINAL_COMMAND and never reaches a shell. The request
is passed on, as one line, to the lab-switch helper (switchd.py), which checks it against
its own grammar (status, fix SERVICE, break SERVICE, preset NAME) and runs labctl.

This script only refuses what can't be a request at all, so the grammar lives in one
place. It prints the helper's reply and exits 0 for "ok", 1 otherwise.

Standard library only, Python 3.11+.
"""

from __future__ import annotations

import os
import re
import socket
import sys

SOCKET = os.environ.get("LAB_SWITCH_SOCKET", "/run/lab-switch.sock")
TIMEOUT = 25.0  # seconds; a preset may reconnect the Wi-Fi
REQUEST = re.compile(r"[a-z][a-z0-9 -]{0,62}")


def forward(request: str, path: str = SOCKET) -> str:
    """Send one request to the helper and return its reply ("refused" when unreachable)."""
    if not REQUEST.fullmatch(request):
        return "refused\n"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect(path)
            sock.sendall(request.encode("ascii") + b"\n")
            reply = b""
            while len(reply) < 4096 and (chunk := sock.recv(4096)):
                reply += chunk
    except OSError:
        return "refused\n"
    return reply.decode("ascii", "replace")


def main() -> int:
    reply = forward(os.environ.get("SSH_ORIGINAL_COMMAND", ""))
    sys.stdout.write(reply)
    return 0 if reply.splitlines()[-1:] == ["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
