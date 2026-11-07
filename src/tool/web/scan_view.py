"""Page projection for the desktop runner (#135), without any scan implementation."""

from ipaddress import ip_address
from typing import Protocol
from urllib.parse import urlsplit

from fastapi import Request

from tool.content import (
    detect_error_message,
    file_error_message,
    history_error_message,
    scan_message,
    scan_progress_message,
)
from tool.content.texts import DETECT_ERRORS, FILE_ERRORS, REFUSALS, SCAN_STEPS
from tool.content.ui import UI


class ScanRunner(Protocol):
    """The page's agreed runner interface; the scan owner supplies the implementation."""

    def start_scan(self, lang: str): ...
    def state(self): ...
    def cancel(self): ...


def local_scan_client(request: Request) -> bool:
    """Require both a loopback peer and a literal loopback Host (DNS rebinding guard).

    Forwarded headers and localhost DNS names never grant scan access.
    """
    try:
        peer = ip_address(request.client.host) if request.client else None
        authority = request.headers.get("host", "")
        parsed = urlsplit("//" + authority)
        host = ip_address(parsed.hostname or "")
        # Accessing port validates malformed/out-of-range values too.
        port = parsed.port
        return bool(
            peer
            and peer.is_loopback
            and host.is_loopback
            and not parsed.username
            and not parsed.password
            and not parsed.path
            and not parsed.query
            and not parsed.fragment
            and (port is None or 0 < port < 65536)
        )
    except ValueError:
        return False


def scan_status(runner: ScanRunner | None, lang: str) -> dict:
    """Only localized presentation leaves the backend; no paths, banners or exceptions."""
    state = runner.state() if runner else None
    running = bool(state and state.running)
    outcome = state.outcome if state else None
    if runner is None:
        message = UI["scan_unavailable"][lang]
    elif running:
        if state.percent is not None:
            message = scan_progress_message(state.step, state.percent, state.seconds_left, lang)
        else:
            message = SCAN_STEPS.get(state.step, SCAN_STEPS["OTHER"])[lang]
    elif outcome == "DONE":
        message = UI["scan_complete"][lang]
    elif outcome in (
        "CANCELLED",
        "AUTH_CANCELLED",
        "NO_AUTH_DIALOG",
        "NO_LIVE_HOSTS",
        "UNEXPECTED",
    ):
        message = UI["scan_" + outcome.lower()][lang]
    elif outcome == "HISTORY_FAILED":
        message = history_error_message(lang)
    elif outcome in FILE_ERRORS:
        message = file_error_message(outcome, lang)
    elif outcome in REFUSALS:
        message = UI["scan_refused"][lang]
    elif outcome in DETECT_ERRORS:
        message = detect_error_message(outcome, lang)
    elif outcome:
        message = scan_message(outcome, lang)
    else:
        message = UI["scan_ready"][lang]
    return {
        "running": running,
        "done": outcome == "DONE",
        "message": message,
        "result_url": f"/?lang={lang}",
    }
