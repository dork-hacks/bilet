"""The "Check again" runner (#135). No test elevates or scans: the root script runs under
plain /bin/sh with a fake nmap, and pkexec / osascript are only ever faked."""

import io
import stat
import threading
import time
from pathlib import Path

import pytest

from tool import guardrail as g
from tool import scan as live
from tool import scan_runner as sr
from tool.cli import main
from tool.history import History
from tool.network import Network

VALIDATION = Path(__file__).parent / "fixtures" / "validation"
V1 = (VALIDATION / "V1_home_basic.xml").read_bytes()  # 192.168.1.0/24, scores 90
V1_NET = "192.168.1.0/24"
SERVICES = "telnet\t23/tcp\t0.22\nhttp\t80/tcp\t0.48\nssh\t22/tcp\t0.18\n"
FAST = 0.05  # the script's poll interval in these tests, in seconds


def discovery(*ips):
    hosts = "".join(
        f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/></host>' for ip in ips
    )
    return f'<?xml version="1.0"?><nmaprun scanner="nmap">{hosts}</nmaprun>'.encode()


# --- the root script, run for real without elevation --------------------------------------


def fake_nmap(tmp_path: Path, body: str) -> str:
    """An executable "nmap" that logs its arguments and writes to the -oX file."""
    path = tmp_path / "bin" / "nmap"
    path.parent.mkdir(exist_ok=True)
    path.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$@" > {tmp_path}/args.log\n'
        'out=""; while [ $# -gt 0 ]; do [ "$1" = -oX ] && out=$2; shift; done\n' + body
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


PROGRESSING = """
echo '<?xml version="1.0"?><nmaprun scanner="nmap">' > "$out"
echo '<taskprogress task="SYN Stealth Scan" percent="40.00" remaining="20"/>' >> "$out"
sleep 0.3
echo '<taskprogress task="UDP Scan" percent="90.00" remaining="2"/>' >> "$out"
sleep 0.3
echo '</nmaprun>' >> "$out"
"""


def runner_for(tmp_path, nmap, **kw):
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    return sr.ElevatedRunner(sr.PLAIN_SH, work, nmap=nmap, poll_s=FAST, **kw)


def test_the_script_streams_progress_and_returns_the_xml(tmp_path):
    runner = runner_for(tmp_path, fake_nmap(tmp_path, PROGRESSING))
    seen = []
    xml = runner(["-sS", "-oX", "-", "192.168.1.1"], lambda *u: seen.append(u))
    assert xml.startswith(b'<?xml version="1.0"?><nmaprun') and b"</nmaprun>" in xml
    assert (live.STEP_TCP, 40.0, 20) in seen and (live.STEP_UDP, 90.0, 2) in seen
    # nmap got the same arguments, with -oX pointing into the script's own folder.
    args = (tmp_path / "args.log").read_text().split("\n")
    assert args[:2] == ["-sS", "-oX"] and args[3] == "192.168.1.1"
    assert args[2].endswith("/out.xml") and not args[2].startswith(str(tmp_path))


def test_root_output_never_lands_in_a_folder_this_user_owns(tmp_path):
    script = sr.elevated_script("/usr/bin/nmap", ["-sn", "-oX", "-", "10.0.0.0/24"], Path("/c"))
    assert "d=$(mktemp -d)" in script and '-oX "$d/out.xml"' in script
    assert "trap 'rm -rf \"$d\"' EXIT" in script
    runner = runner_for(tmp_path, fake_nmap(tmp_path, PROGRESSING))
    runner(["-sn", "-oX", "-", "10.0.0.0/24"])
    assert list((tmp_path / "work").iterdir()) == []  # nothing written into our folder
    out = Path((tmp_path / "args.log").read_text().split("\n")[2])
    assert not out.parent.exists()  # and the script removed its own


def test_cancel_stops_nmap_within_seconds(tmp_path):
    runner = runner_for(tmp_path, fake_nmap(tmp_path, 'echo "<nmaprun>" > "$out"; sleep 30\n'))
    errors = []

    def scan():
        try:
            runner(["-sS", "-oX", "-", "192.168.1.1"])
        except live.ScanError as exc:
            errors.append(exc.code)

    thread = threading.Thread(target=scan)
    start = time.monotonic()
    thread.start()
    time.sleep(0.3)
    runner.cancel()
    thread.join(10)
    assert not thread.is_alive() and errors == [sr.CANCELLED]
    assert time.monotonic() - start < 5


def test_the_script_enforces_the_timeout_itself(tmp_path):
    runner = runner_for(tmp_path, fake_nmap(tmp_path, "sleep 30\n"), timeout_s=0.3)
    start = time.monotonic()
    with pytest.raises(live.ScanError) as exc:
        runner(["-sS", "-oX", "-", "192.168.1.1"])
    assert exc.value.code == live.NMAP_FAILED and "timed out" in exc.value.detail
    assert time.monotonic() - start < 5


def test_nmaps_own_failure_is_reported(tmp_path):
    runner = runner_for(tmp_path, fake_nmap(tmp_path, "exit 3\n"))
    with pytest.raises(live.ScanError) as exc:
        runner(["-sS", "-oX", "-", "192.168.1.1"])
    assert (exc.value.code, exc.value.detail) == (live.NMAP_FAILED, "exit code 3")


def test_arguments_reach_nmap_literally_and_are_never_run_as_shell(tmp_path):
    runner = runner_for(tmp_path, fake_nmap(tmp_path, PROGRESSING))
    evil = ["$(touch pwned)", "; touch pwned2", "`touch pwned3`", "a b"]
    runner(["-sS", *evil, "-oX", "-"])
    assert not list(Path.cwd().glob("pwned*")) and not list(tmp_path.glob("pwned*"))
    assert (tmp_path / "args.log").read_text().split("\n")[1:5] == evil


def test_the_arguments_must_name_stdout_as_the_xml_output():
    for args in (["-sS", "10.0.0.1"], ["-oX"], ["-oX", "file.xml"]):
        with pytest.raises(ValueError):
            sr.elevated_script("/usr/bin/nmap", args, Path("/c"))


# --- launchers and what their exit codes mean ---------------------------------------------


def test_launchers_pass_the_script_as_one_argument():
    assert sr.launcher_argv(sr.PKEXEC, "S") == ["pkexec", "/bin/sh", "-c", "S"]
    argv = sr.launcher_argv(sr.OSASCRIPT, 'S "with" quotes')
    assert argv[0] == "osascript" and argv[-1] == 'S "with" quotes'
    assert "with administrator privileges without altering line endings" in " ".join(argv)
    with pytest.raises(ValueError):
        sr.launcher_argv("sudo", "S")


@pytest.mark.parametrize(
    ("platform", "pkexec", "expected"),
    [("darwin", None, sr.OSASCRIPT), ("linux", "/usr/bin/pkexec", sr.PKEXEC)],
)
def test_pick_launcher(platform, pkexec, expected):
    assert sr.pick_launcher(platform, lambda _name: pkexec) == expected


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_no_password_window_is_a_plain_error(platform):
    with pytest.raises(live.ScanError) as exc:
        sr.pick_launcher(platform, lambda _name: None)
    assert exc.value.code == sr.NO_AUTH_DIALOG


class FakeProc:
    def __init__(self, returncode, out=b"", err=b""):
        self.returncode, self.stdout, self._err = returncode, io.BytesIO(out), err

    def poll(self):
        return self.returncode

    def communicate(self):
        return b"", self._err


@pytest.mark.parametrize(
    ("kind", "returncode", "err", "code"),
    [
        (sr.PKEXEC, 126, b"", sr.AUTH_CANCELLED),
        (sr.PKEXEC, 127, b"No authentication agent found.", sr.NO_AUTH_DIALOG),
        (sr.OSASCRIPT, 1, b"execution error: User canceled. (-128)", sr.AUTH_CANCELLED),
        (sr.OSASCRIPT, 1, b"some other error", live.NMAP_FAILED),
        (sr.PKEXEC, sr.TIMEOUT_EXIT, b"", live.NMAP_FAILED),
    ],
)
def test_exit_codes_map_to_plain_outcomes(tmp_path, kind, returncode, err, code):
    runner = sr.ElevatedRunner(
        kind, tmp_path, nmap="/usr/bin/nmap", spawn=lambda *a, **k: FakeProc(returncode, err=err)
    )
    with pytest.raises(live.ScanError) as exc:
        runner(["-sn", "-oX", "-", "10.0.0.0/24"])
    assert exc.value.code == code


def test_a_missing_launcher_binary_is_no_password_window(tmp_path):
    def spawn(*_a, **_k):
        raise FileNotFoundError("pkexec")

    runner = sr.ElevatedRunner(sr.PKEXEC, tmp_path, nmap="/usr/bin/nmap", spawn=spawn)
    with pytest.raises(live.ScanError) as exc:
        runner(["-sn", "-oX", "-", "10.0.0.0/24"])
    assert exc.value.code == sr.NO_AUTH_DIALOG


def test_oversized_output_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(sr, "MAX_FILE_BYTES", 10)
    proc = FakeProc(0, out=b"X\n" + b"<" * 50)
    runner = sr.ElevatedRunner(sr.PKEXEC, tmp_path, nmap="/n", spawn=lambda *a, **k: proc)
    with pytest.raises(live.ScanError) as exc:
        runner(["-sn", "-oX", "-", "10.0.0.0/24"])
    assert exc.value.code == live.NMAP_FAILED


# --- ScanRunner: the same steps as `tool scan --confirm` ----------------------------------


class Recorder:
    """A scan.Runner that records its arguments: discovery finds .1 and this computer."""

    def __init__(self, gate: threading.Event | None = None):
        self.calls, self.gate, self.cancelled = [], gate, False

    def cancel(self):
        self.cancelled = True

    def __call__(self, args, on_progress=None):
        if self.gate is not None:
            self.gate.wait(5)
        if self.cancelled:
            raise live.ScanError(sr.CANCELLED)
        self.calls.append(args)
        if on_progress is not None:
            on_progress(live.STEP_TCP, 50.0, 10)
        return discovery("192.168.1.1", "192.168.1.30") if args[0] == "-sn" else V1


@pytest.fixture
def lab(tmp_path, monkeypatch):
    """This computer is 192.168.1.30 on V1's network; data and scans go to tmp_path."""
    monkeypatch.setattr(
        "tool.network.detect", lambda: Network("wlan0", "192.168.1.30", V1_NET, "192.168.1.1")
    )
    monkeypatch.delenv(g.ALLOWLIST_ENV, raising=False)
    monkeypatch.setenv("TOOL_DATA_DIR", str(tmp_path / "data"))
    services = tmp_path / "nmap-services"
    services.write_text(SERVICES)
    monkeypatch.setenv(live.SERVICES_ENV, str(services))
    monkeypatch.setattr(sr.os, "geteuid", lambda: 1000, raising=False)
    return tmp_path


def make(tmp_path, recorder, launcher=lambda: sr.PKEXEC):
    return sr.ScanRunner(
        scans_dir=tmp_path / "scans", make_runner=lambda kind, folder: recorder, launcher=launcher
    )


def test_a_scan_ends_in_the_history_with_its_id(lab):
    recorder = Recorder()
    runner = make(lab, recorder)
    assert runner.start_scan("en").running
    done = runner.wait(10)
    assert (done.running, done.outcome) == (False, sr.DONE)
    scans = History(lab / "data").scans()
    assert [s.id for s in scans] == [done.scan_id] and scans[0].score == 90
    assert (done.step, done.percent, done.seconds_left) == (live.STEP_TCP, 50.0, 10)
    assert len(list((lab / "scans").glob("scan_*.xml"))) == 1


def test_same_nmap_arguments_as_the_cli(lab, monkeypatch):
    cli = Recorder()
    monkeypatch.setattr("tool.scan.run_nmap", cli)
    assert main(["scan", "--confirm", "--scans-dir", str(lab / "cli-scans")]) == 0
    page = Recorder()
    runner = make(lab, page)
    runner.start_scan()
    assert runner.wait(10).outcome == sr.DONE
    assert page.calls == cli.calls  # discovery, then the port scan
    assert cli.calls[1][-1] == "192.168.1.1"  # and this computer is never port-scanned


def test_a_second_press_joins_the_running_scan(lab):
    gate = threading.Event()
    recorder = Recorder(gate)
    runner = make(lab, recorder)
    first = runner.start_scan()
    second = runner.start_scan()
    assert first.running and second.running
    gate.set()
    assert runner.wait(10).outcome == sr.DONE
    assert [a[0] for a in recorder.calls] == ["-sn", "-sS"]  # one discovery, one port scan


def test_cancel_ends_the_run_as_cancelled(lab):
    gate = threading.Event()
    recorder = Recorder(gate)
    runner = make(lab, recorder)
    runner.start_scan()
    time.sleep(0.1)
    runner.cancel()
    gate.set()
    done = runner.wait(10)
    assert (done.running, done.outcome, done.scan_id) == (False, sr.CANCELLED, None)
    assert History(lab / "data").scans() == []


def test_cancel_before_nmap_starts_still_stops_it(lab):
    gate = threading.Event()
    recorder = Recorder()

    def slow_launcher():
        gate.wait(5)
        return sr.PKEXEC

    runner = make(lab, recorder, slow_launcher)
    runner.start_scan()
    runner.cancel()  # while the launcher is still being picked
    gate.set()
    assert runner.wait(10).outcome == sr.CANCELLED and recorder.calls == []


def test_the_guardrail_still_decides(lab, monkeypatch):
    monkeypatch.setattr(
        "tool.network.detect", lambda: Network("wlan0", "8.8.8.30", "8.8.8.0/24", "8.8.8.1")
    )
    recorder = Recorder()
    runner = make(lab, recorder)
    runner.start_scan()
    assert runner.wait(10).outcome == g.PUBLIC_ADDRESS
    assert recorder.calls == []


def test_no_password_window_is_an_outcome_not_a_crash(lab):
    def none():
        raise live.ScanError(sr.NO_AUTH_DIALOG)

    runner = make(lab, Recorder(), none)
    runner.start_scan()
    assert runner.wait(10).outcome == sr.NO_AUTH_DIALOG


def test_a_bug_ends_the_run_instead_of_hanging_it(lab):
    def broken(_args, _progress=None):
        raise RuntimeError("bug")

    runner = sr.ScanRunner(
        scans_dir=lab / "scans", make_runner=lambda k, f: broken, launcher=lambda: sr.PKEXEC
    )
    runner.start_scan()
    done = runner.wait(10)
    assert (done.running, done.outcome) == (False, sr.UNEXPECTED)


def test_refuses_to_run_as_root(lab, monkeypatch):
    monkeypatch.setattr(sr.os, "geteuid", lambda: 0, raising=False)
    recorder = Recorder()
    runner = make(lab, recorder)
    runner.start_scan()
    assert runner.wait(10).outcome == sr.RUN_AS_ROOT and recorder.calls == []


def test_a_history_problem_keeps_the_saved_scan(lab, monkeypatch):
    def broken_history():
        raise OSError("read-only")

    runner = sr.ScanRunner(
        scans_dir=lab / "scans",
        make_runner=lambda k, f: Recorder(),
        launcher=lambda: sr.PKEXEC,
        history=broken_history,
    )
    runner.start_scan()
    assert runner.wait(10).outcome == sr.HISTORY_FAILED
    assert len(list((lab / "scans").glob("scan_*.xml"))) == 1


def test_module_entry_points_share_one_runner():
    assert sr.state() == sr._default.state()
    assert isinstance(sr.state(), sr.RunState) and not sr.state().running
