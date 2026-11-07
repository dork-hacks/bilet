"""The web UI's "Check again" (#135): the same live scan as `tool scan --confirm`, started
from the browser, with the operating system's own password window instead of sudo.

What is the same as the CLI, so the findings are identical (the parity test pins it):
the detected subnet only (no target input), the same guardrail, `scan.run_scan` with the
same nmap arguments, the scanner's own address excluded, `analyze_file` and the history.

What differs is how nmap gets admin rights. The password never reaches bilet:
- Linux: `pkexec /bin/sh -c <script>`, which asks through the desktop's polkit agent.
- macOS: `osascript … do shell script <script> with administrator privileges`.

Only `<script>` runs as root, and it is fixed text with every argument `shlex.quote`d
(`elevated_script`). It runs nmap into a root-owned temporary folder and supervises it:
- it stops nmap when the user-owned cancel file appears, or after NMAP_TIMEOUT_S, because
  this process can't signal a root process;
- it streams nmap's <taskprogress> lines as `P …` (Linux shows them live; macOS hands
  the output over only at the end, so the page shows no percentage there);
- after a line `X`, it prints the XML and removes its folder.
Root never writes into a folder this user owns, so a planted symlink can't redirect it,
and nmap runs with an empty environment (`env -i`), so a user-writable $NMAPDIR or
~/.nmap can't load scripts into the root process (agent-E's review).
Analysis, saving and the history stay unprivileged, as in the CLI.
"""

import os
import shlex
import shutil
import subprocess  # noqa: S404 - fixed argument lists only; the one shell script is fixed text
import sys
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

from tool import scan as live
from tool.engine.parser import MAX_FILE_BYTES

# Launchers. "sh" runs the same script without elevation, for tests only: pick_launcher
# never returns it.
PKEXEC = "pkexec"
OSASCRIPT = "osascript"
PLAIN_SH = "sh"

# Outcome codes the page turns into RO/EN text (area:content). The runner can also end
# with DONE, a guardrail refusal code, a network detection code, a scan.ScanError code
# or a file error code from analyze_file.
DONE = "DONE"
AUTH_CANCELLED = "AUTH_CANCELLED"  # the password window was closed or refused
NO_AUTH_DIALOG = "NO_AUTH_DIALOG"  # no pkexec / polkit agent (no desktop session)
CANCELLED = "CANCELLED"  # the user pressed Cancel
RUN_AS_ROOT = "RUN_AS_ROOT"
HISTORY_FAILED = "HISTORY_FAILED"  # the scan is saved, the history couldn't be updated
UNEXPECTED = "UNEXPECTED"  # a bug: never a traceback on the page

TIMEOUT_EXIT = 124  # the script's exit code when NMAP_TIMEOUT_S ran out
_PKEXEC_DISMISSED = 126  # pkexec: the dialog was dismissed or authorization failed
_PKEXEC_NO_AGENT = 127  # pkexec: no authentication agent, or not allowed at all
_MARKER = b"X\n"

# Runs as root. {placeholders} are filled with shlex-quoted values only.
_SCRIPT = """set -u
d=$(mktemp -d) || exit 70
trap 'rm -rf "$d"' EXIT
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/ {nmap} {args} >/dev/null 2>&1 &
p=$!
t=0
stop=-1
late=0
seen=0
while kill -0 "$p" 2>/dev/null; do
  if [ "$stop" -lt 0 ] && [ -e {cancel} ]; then
    stop=$t
    kill "$p" 2>/dev/null
  elif [ "$stop" -lt 0 ] && [ "$t" -ge {limit} ]; then
    stop=$t
    late=1
    kill "$p" 2>/dev/null
  fi
  if [ "$stop" -ge 0 ] && [ "$t" -ge $((stop + {grace})) ]; then
    kill -9 "$p" 2>/dev/null
  fi
  if [ -f "$d/out.xml" ]; then
    n=$(grep -c '<taskprogress' "$d/out.xml")
    if [ "$n" -gt "$seen" ]; then
      grep '<taskprogress' "$d/out.xml" | tail -n +$((seen + 1)) | sed 's/^/P /'
      seen=$n
    fi
  fi
  sleep {poll}
  t=$((t + 1))
done
wait "$p"
rc=$?
if [ "$late" -eq 1 ]; then rc={timeout_exit}; fi
echo X
if [ -f "$d/out.xml" ]; then cat "$d/out.xml"; fi
exit "$rc"
"""


def elevated_script(
    nmap: str,
    args: list[str],
    cancel_file: Path,
    timeout_s: int = live.NMAP_TIMEOUT_S,
    poll_s: float = 1.0,
    grace_s: int = 5,
) -> str:
    """The root shell script for one nmap run. `args` must contain `-oX -`, as the scan
    module builds them: the `-` becomes the script's own root-owned output file."""
    try:
        out = args.index("-oX") + 1
    except ValueError:
        raise ValueError("nmap arguments must contain -oX -") from None
    if out >= len(args) or args[out] != "-":
        raise ValueError("nmap arguments must contain -oX -")
    quoted = [shlex.quote(a) for a in args]
    quoted[out] = '"$d/out.xml"'
    polls = max(1, round(timeout_s / poll_s))
    return _SCRIPT.format(
        nmap=shlex.quote(nmap),
        args=" ".join(quoted),
        cancel=shlex.quote(str(cancel_file)),
        limit=polls,
        grace=max(1, round(grace_s / poll_s)),
        poll=f"{poll_s:g}",
        timeout_exit=TIMEOUT_EXIT,
    )


def launcher_argv(kind: str, script: str) -> list[str]:
    """How the script gets admin rights. The script is passed as one argument, never
    pasted into another language's source text."""
    if kind == PKEXEC:
        return ["pkexec", "/bin/sh", "-c", script]
    if kind == OSASCRIPT:
        return [
            "osascript",
            "-e",
            "on run argv",
            "-e",
            "do shell script (item 1 of argv) with administrator privileges"
            " without altering line endings",
            "-e",
            "end run",
            script,
        ]
    if kind == PLAIN_SH:
        return ["/bin/sh", "-c", script]
    raise ValueError(f"unknown launcher {kind!r}")


def pick_launcher(
    platform: str = sys.platform, which: Callable[[str], str | None] = shutil.which
) -> str:
    """The OS password window for this computer, or NO_AUTH_DIALOG."""
    if platform == "darwin":
        return OSASCRIPT
    if platform.startswith("linux") and which("pkexec"):
        return PKEXEC
    raise live.ScanError(NO_AUTH_DIALOG, f"no password window on {platform}")


Spawn = Callable[..., subprocess.Popen]


class ElevatedRunner:
    """A `scan.Runner` that runs each nmap step through the OS password window.

    `cancel()` creates the cancel file that the root script watches, so a scan stops
    within a couple of seconds. The file can only ever stop this run's nmap."""

    def __init__(
        self,
        kind: str,
        work_dir: Path,
        nmap: str | None = None,
        spawn: Spawn = subprocess.Popen,
        timeout_s: int = live.NMAP_TIMEOUT_S,
        poll_s: float = 1.0,
    ):
        self.kind, self.spawn = kind, spawn
        self.nmap = nmap
        self.cancel_file = work_dir / "cancel"
        self.timeout_s, self.poll_s = timeout_s, poll_s

    def cancel(self) -> None:
        self.cancel_file.touch()

    @property
    def cancelled(self) -> bool:
        return self.cancel_file.exists()

    def __call__(self, args: list[str], on_progress: live.Progress | None = None) -> bytes:
        if self.cancelled:
            raise live.ScanError(CANCELLED)
        nmap = self.nmap or live.nmap_binary()
        script = elevated_script(nmap, args, self.cancel_file, self.timeout_s, self.poll_s)
        try:
            proc = self.spawn(
                launcher_argv(self.kind, script),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as exc:
            raise live.ScanError(NO_AUTH_DIALOG, f"{type(exc).__name__}: {exc}") from exc
        try:
            xml = _read_protocol(proc, on_progress)
        except BaseException:
            self.cancel()  # our own error or Ctrl+C: the root script stops nmap
            proc.communicate()
            raise
        _, err = proc.communicate()  # the script itself ends within timeout + grace
        self._check(proc.returncode, err or b"")
        return xml

    def _check(self, returncode: int, err: bytes) -> None:
        if self.cancelled:
            raise live.ScanError(CANCELLED)
        if returncode == 0:
            return
        if self.kind == PKEXEC and returncode == _PKEXEC_DISMISSED:
            raise live.ScanError(AUTH_CANCELLED)
        if self.kind == PKEXEC and returncode == _PKEXEC_NO_AGENT:
            raise live.ScanError(NO_AUTH_DIALOG, "no polkit authentication agent")
        if self.kind == OSASCRIPT and b"(-128)" in err:  # "User canceled."
            raise live.ScanError(AUTH_CANCELLED)
        if returncode == TIMEOUT_EXIT:
            raise live.ScanError(live.NMAP_FAILED, f"timed out after {self.timeout_s} s")
        raise live.ScanError(live.NMAP_FAILED, f"exit code {returncode}")


def _read_protocol(proc: subprocess.Popen, on_progress: live.Progress | None) -> bytes:
    """`P <taskprogress …>` lines until the `X` line, then the XML, capped in size."""
    if proc.stdout is None:
        raise live.ScanError(live.NMAP_FAILED, "no output pipe")
    while line := proc.stdout.readline(64 * 1024):
        if line == _MARKER:
            xml = proc.stdout.read(MAX_FILE_BYTES + 1)
            if len(xml) > MAX_FILE_BYTES:
                raise live.ScanError(live.NMAP_FAILED, f"output larger than {MAX_FILE_BYTES} bytes")
            return xml
        if on_progress is not None and line.startswith(b"P "):
            for update in live.progress_updates(line):
                on_progress(*update)
    return b""  # no marker: the script never ran (dialog refused); the exit code says why


@dataclass(frozen=True)
class RunState:
    """What the page shows. `outcome` is None while running, then DONE or an error code;
    `scan_id` is the new history row, for "See your new score"."""

    running: bool = False
    step: str | None = None
    percent: float | None = None
    seconds_left: int | None = None
    outcome: str | None = None
    scan_id: int | None = None


RunnerFactory = Callable[[str, Path], live.Runner]


class ScanRunner:
    """One "Check again" scan at a time, in a background thread. Every method is safe to
    call from request handlers and returns a snapshot."""

    def __init__(
        self,
        scans_dir: Path = Path("scans"),
        make_runner: RunnerFactory | None = None,
        launcher: Callable[[], str] = pick_launcher,
        history: Callable[[], object] | None = None,
    ):
        self.scans_dir = scans_dir
        self.make_runner = make_runner or (lambda kind, folder: ElevatedRunner(kind, folder))
        self.launcher = launcher
        self.history = history
        self._lock = threading.Lock()
        self._state = RunState()
        self._runner: live.Runner | None = None
        self._cancel_requested = False
        self._thread: threading.Thread | None = None

    def state(self) -> RunState:
        with self._lock:
            return self._state

    def start_scan(self, lang: str = "ro") -> RunState:
        """Start a scan, or return the running one: a second press never starts another."""
        with self._lock:
            if self._state.running:
                return self._state
            self._state = RunState(running=True)
            self._runner = None
            self._cancel_requested = False
            self._thread = threading.Thread(target=self._run, name="bilet-scan", daemon=True)
            self._thread.start()
            return self._state

    def cancel(self) -> RunState:
        """Stop the running scan. Pressed before nmap starts, it stops the scan there."""
        with self._lock:
            if self._state.running:
                self._cancel_requested = True
            runner = self._runner
        _cancel(runner)
        return self.state()

    def wait(self, timeout: float | None = None) -> RunState:
        """For tests and the CLI-style callers: block until the current scan ends."""
        thread = self._thread
        if thread is not None:
            thread.join(timeout)
        return self.state()

    def _set(self, **changes: object) -> None:
        with self._lock:
            self._state = replace(self._state, **changes)

    def _progress(self, step: str, percent: float, seconds_left: int | None) -> None:
        self._set(step=step, percent=percent, seconds_left=seconds_left)

    def _run(self) -> None:
        try:
            outcome, scan_id = self._scan()
        except Exception:  # noqa: BLE001 - a bug must end the run, not leave it "running"
            outcome, scan_id = UNEXPECTED, None
        self._set(running=False, outcome=outcome, scan_id=scan_id)

    def _scan(self) -> tuple[str, int | None]:
        # The same steps, in the same order, as tool.cli.scan_command.
        from tool.engine import analyze_file
        from tool.guardrail import Refused, authorize, build_allowlist, extra_ranges_from_env
        from tool.network import DetectError, detect

        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return RUN_AS_ROOT, None
        try:
            net = detect()
        except DetectError as exc:
            return exc.code, None
        try:
            allowlist = build_allowlist(net.subnet, extra_ranges_from_env())
            networks = authorize([net.subnet], allowlist, True)  # the page is the confirmation
        except Refused as exc:
            return exc.code, None
        try:
            kind = self.launcher()
        except live.ScanError as exc:
            return exc.code, None
        with tempfile.TemporaryDirectory(prefix="bilet-scan-") as folder:  # 0700, ours
            runner = self.make_runner(kind, Path(folder))
            with self._lock:
                self._runner = runner
                cancelled = self._cancel_requested
            if cancelled:
                _cancel(runner)
            try:
                path = live.run_scan(
                    networks,
                    runner=runner,
                    scans_dir=self.scans_dir,
                    exclude=[net.address],
                    on_progress=self._progress,
                )
            except live.ScanError as exc:
                return exc.code, None
        result = analyze_file(path)  # unprivileged, the same engine as `tool analyze`
        try:
            scan_id = self._history().add(result)
        except Exception:  # noqa: BLE001 - HistoryError, sqlite3.Error, OSError (#132)
            return HISTORY_FAILED, None
        if result.status != "ok":
            return result.error["code"], scan_id
        return DONE, scan_id

    def _history(self):
        if self.history is not None:
            return self.history()
        from tool.history import History

        return History()


def _cancel(runner: object) -> None:
    stop = getattr(runner, "cancel", None)
    if callable(stop):
        stop()


# The page's entry points: one runner per server process.
_default = ScanRunner()


def start_scan(lang: str = "ro") -> RunState:
    return _default.start_scan(lang)


def state() -> RunState:
    return _default.state()


def cancel() -> RunState:
    return _default.cancel()
