"""The live scan (#20) with nmap faked: no test starts a subprocess or sends a packet."""

import ipaddress
import os
import subprocess
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tool import guardrail as g
from tool import scan as live
from tool.cli import main
from tool.history import History
from tool.network import Network

VALIDATION = Path(__file__).parent / "fixtures" / "validation"
V1 = (VALIDATION / "V1_home_basic.xml").read_bytes()  # 192.168.1.0/24, scores 90
V1_NET = "192.168.1.0/24"

# A slice of nmap-services: name, port/proto, open-frequency, comment.
SERVICES = """\
# Fields in this file are: Service name, portnum/protocol, open-frequency, optional comments
#
tcpmux\t1/tcp\t0.001995\t# TCP Port Service Multiplexer [rfc-1078]
ftp\t21/tcp\t0.197667\t# File Transfer [Control]
ssh\t22/tcp\t0.182286\t# Secure Shell Login
telnet\t23/tcp\t0.221265
domain\t53/udp\t0.213496\t# Domain Name Server
http\t80/tcp\t0.484143\t# World Wide Web HTTP
https\t443/tcp\t0.208669\t# secure http (SSL)
mqtt\t1883/tcp\t0.000013\t# rare enough to fall outside a short top list
broken line
nope\tabc/tcp\t0.5
"""


def net(text):
    return ipaddress.ip_network(text)


def discovery(*ips, down=()):
    hosts = "".join(
        f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/></host>' for ip in ips
    ) + "".join(
        f'<host><status state="down"/><address addr="{ip}" addrtype="ipv4"/></host>' for ip in down
    )
    return f'<?xml version="1.0"?><nmaprun scanner="nmap">{hosts}</nmaprun>'.encode()


class FakeNmap:
    """Returns the discovery XML for -sn and the port-scan XML otherwise. Each call
    first reports the `progress` updates, as run_nmap does while nmap works."""

    def __init__(self, found=b"", scan=V1, progress=()):
        self.found, self.scan, self.progress, self.calls = found, scan, progress, []

    def __call__(self, args, on_progress=None):
        self.calls.append(args)
        if on_progress is not None:
            for update in self.progress:
                on_progress(*update)
        return self.found if args[0] == "-sn" else self.scan


def taskprogress(task, percent, remaining=None):
    left = f' remaining="{remaining}"' if remaining is not None else ""
    return (
        f'<taskprogress task="{task}" time="1762525805" percent="{percent}"{left}'
        f' etc="1762525900"/>\n'
    ).encode()


class FakeStdout:
    """nmap's stdout pipe: hands out the lines one by one, then EOF. `block` makes it
    wait (like a stuck nmap) until the process is stopped."""

    def __init__(self, lines, block=None):
        self.lines, self.block = list(lines), block

    def readline(self, limit=-1):
        if self.lines:
            return self.lines.pop(0)
        if self.block is not None:
            self.block.wait(5)
        return b""


class FakePopen:
    """A Popen stand-in: nothing is started. Records the argv and the stop signals."""

    def __init__(self, lines, returncode=0, block=False):
        self.stopped = threading.Event()
        self.stdout = FakeStdout(lines, self.stopped if block else None)
        self.code, self.argv, self.kwargs, self.signals = returncode, None, None, []

    def __call__(self, argv, **kwargs):
        self.argv, self.kwargs = argv, kwargs
        return self

    def terminate(self):
        self.signals.append("TERM")
        self.stopped.set()

    def kill(self):
        self.signals.append("KILL")
        self.stopped.set()

    def poll(self):
        return self.code if (self.stopped.is_set() or not self.stdout.lines) else None

    def wait(self, timeout=None):
        return -15 if self.signals else self.code


# --- the port list --------------------------------------------------------------------


def test_top_tcp_ports_ranks_by_frequency_and_ignores_udp_and_junk():
    assert live.top_tcp_ports(SERVICES, count=3) == [23, 80, 443]  # 0.48, 0.22, 0.21
    assert 53 not in live.top_tcp_ports(SERVICES)  # 53/udp only in this slice
    assert live.top_tcp_ports("") == []


def test_port_spec_adds_the_catalog_ports_and_the_udp_ports():
    spec = live.port_spec([21, 22, 23, 80])
    assert spec == "T:21-23,80,1883,6379-6380,8883,27017,U:53,123,161,1900,5353"


def test_port_scan_args_match_the_brief_and_never_use_top_ports():
    args = live.port_scan_args(["192.168.1.1"], "T:80,U:53")
    for flag in ("-sS", "-sU", "-sV", "-Pn"):
        assert flag in args
    assert args[args.index("--script") + 1] == "http-title"
    assert args[args.index("--max-rate") + 1] == "100"
    assert args[args.index("-p") + 1] == "T:80,U:53"
    assert args[args.index("-oX") + 1] == "-"  # XML to stdout: root never writes a file
    assert "--top-ports" not in args and args[-1] == "192.168.1.1"


def test_discovery_args_only_name_the_authorized_ranges():
    args = live.discovery_args([net("172.20.10.0/28")])
    assert args[:2] == ["-sn", "-n"] and args[-1] == "172.20.10.0/28"
    assert args[args.index("--max-rate") + 1] == "100"


# --- discovery and the port scan --------------------------------------------------------


def test_live_hosts_keeps_only_up_hosts_inside_the_ranges():
    xml = discovery("192.168.1.20", "192.168.1.1", "10.0.0.5", "8.8.8.8", down=("192.168.1.9",))
    assert live.live_hosts(xml, [net(V1_NET)]) == ["192.168.1.1", "192.168.1.20"]


def test_live_hosts_skips_the_scanners_own_address():
    xml = discovery("192.168.1.1", "192.168.1.30")
    assert live.live_hosts(xml, [net(V1_NET)], exclude=["192.168.1.30"]) == ["192.168.1.1"]


def test_live_hosts_rejects_unreadable_discovery_output():
    with pytest.raises(live.ScanError) as exc:
        live.live_hosts(b"not xml", [net(V1_NET)])
    assert exc.value.code == live.NMAP_FAILED


def test_run_scan_scans_only_live_hosts_and_saves_private_xml(tmp_path):
    fake = FakeNmap(found=discovery("192.168.1.1", "192.168.1.50", "10.9.9.9"))
    when = datetime(2026, 11, 7, 14, 30, 5, tzinfo=UTC)
    path = live.run_scan([net(V1_NET)], fake, tmp_path / "scans", SERVICES, when)

    assert [c[0] for c in fake.calls] == ["-sn", "-sS"]
    assert fake.calls[1][-2:] == ["192.168.1.1", "192.168.1.50"]  # never 10.9.9.9
    assert "1883" in fake.calls[1][fake.calls[1].index("-p") + 1]
    assert path == tmp_path / "scans" / "scan_20261107T143005Z.xml"
    assert path.read_bytes() == V1
    assert os.stat(path).st_mode & 0o777 == 0o600
    # A second scan in the same second gets its own file.
    again = live.run_scan([net(V1_NET)], fake, tmp_path / "scans", SERVICES, when)
    assert again.name == "scan_20261107T143005Z_2.xml"


def test_run_scan_stops_when_nobody_answers(tmp_path):
    fake = FakeNmap(found=discovery(down=("192.168.1.1",)))
    with pytest.raises(live.ScanError) as exc:
        live.run_scan([net(V1_NET)], fake, tmp_path, SERVICES)
    assert exc.value.code == live.NO_LIVE_HOSTS
    assert len(fake.calls) == 1  # no port scan


def test_run_scan_refuses_ipv6_before_running_anything(tmp_path):
    fake = FakeNmap()
    with pytest.raises(live.ScanError) as exc:
        live.run_scan([net("fd00::/120")], fake, tmp_path, SERVICES)
    assert exc.value.code == live.IPV6_NOT_SUPPORTED and fake.calls == []


# --- finding nmap and its data file ----------------------------------------------------------


def test_services_file_from_the_environment(tmp_path):
    f = tmp_path / "nmap-services"
    f.write_text(SERVICES)
    assert live.services_file({live.SERVICES_ENV: str(f)}) == f


def test_services_file_missing_is_a_clear_error(tmp_path, monkeypatch):
    monkeypatch.setattr(live, "_SERVICES_DIRS", ())
    monkeypatch.setattr(live.shutil, "which", lambda _name: None)
    with pytest.raises(live.ScanError) as exc:
        live.services_file({live.SERVICES_ENV: str(tmp_path / "missing")})
    assert exc.value.code == live.NMAP_DATA_NOT_FOUND


def _nmap_file(path: Path, mode: int = 0o755) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n")
    path.chmod(mode)
    return path


def test_nmap_binary_prefers_a_system_path_over_path(tmp_path, monkeypatch):
    system = _nmap_file(tmp_path / "usr/bin/nmap")
    planted = _nmap_file(tmp_path / "home/bin/nmap")  # earlier in PATH, writable by the user
    monkeypatch.setattr(live, "_NMAP_PATHS", (str(tmp_path / "missing/nmap"), str(system)))
    monkeypatch.setenv("PATH", str(planted.parent))
    assert live.nmap_binary() == str(system)


def test_nmap_binary_skips_a_system_path_that_is_not_executable(tmp_path, monkeypatch):
    on_path = _nmap_file(tmp_path / "opt/nmap/bin/nmap")
    monkeypatch.setattr(live, "_NMAP_PATHS", (str(_nmap_file(tmp_path / "usr/bin/nmap", 0o644)),))
    monkeypatch.setenv("PATH", str(on_path.parent))
    monkeypatch.setattr(live, "_writable", lambda _path: False)  # as if root owned it
    assert live.nmap_binary() == str(on_path)


def test_nmap_binary_refuses_an_nmap_the_user_could_replace(tmp_path, monkeypatch):
    planted = _nmap_file(tmp_path / "home/bin/nmap")
    monkeypatch.setattr(live, "_NMAP_PATHS", ())
    monkeypatch.setenv("PATH", str(planted.parent))
    monkeypatch.setattr(live, "_writable", lambda path: path == str(planted.parent))
    with pytest.raises(live.ScanError) as exc:
        live.nmap_binary()
    assert exc.value.code == live.NMAP_NOT_FOUND and "replaced" in exc.value.detail


def test_nmap_binary_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(live, "_NMAP_PATHS", ())
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(live.ScanError) as exc:
        live.nmap_binary()
    assert exc.value.code == live.NMAP_NOT_FOUND and exc.value.detail == ""


def test_services_file_is_found_next_to_the_nmap_that_runs(tmp_path, monkeypatch):
    binary = _nmap_file(tmp_path / "prefix/bin/nmap")
    data = tmp_path / "prefix/share/nmap/nmap-services"
    data.parent.mkdir(parents=True)
    data.write_text(SERVICES)
    monkeypatch.setattr(live, "_NMAP_PATHS", (str(binary),))
    monkeypatch.setattr(live, "_SERVICES_DIRS", ())
    assert live.services_file({}) == data


@pytest.fixture
def popen(monkeypatch):
    """Install a FakePopen: `popen(lines, ...)` returns it. Nothing is ever started."""
    monkeypatch.setattr(live, "nmap_binary", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(live.os, "geteuid", lambda: 1000, raising=False)

    def install(lines, **kwargs):
        fake = FakePopen(lines, **kwargs)
        monkeypatch.setattr(live.subprocess, "Popen", fake)
        return fake

    return install


def test_run_nmap_puts_only_nmap_under_sudo(popen):
    fake = popen([b"<nmaprun>\n", b"</nmaprun>\n"])
    assert live.run_nmap(["-sn", "192.168.1.0/24"]) == b"<nmaprun>\n</nmaprun>\n"
    assert fake.argv == ["sudo", "--", "/usr/bin/nmap", "-sn", "192.168.1.0/24"]
    assert fake.kwargs == {"stdout": subprocess.PIPE}  # no shell, stdin/stderr on the tty
    assert fake.signals == []


def test_run_nmap_reports_progress_while_reading(popen):
    lines = [
        b"<nmaprun>\n",
        taskprogress("SYN Stealth Scan", "39.90", 11),
        taskprogress("UDP Scan", "5.00"),  # no remaining yet
        b"</nmaprun>\n",
    ]
    popen(lines)
    seen = []
    out = live.run_nmap(["-sS"], lambda *update: seen.append(update))
    assert seen == [(live.STEP_TCP, 39.9, 11), (live.STEP_UDP, 5.0, None)]
    assert out == b"".join(lines)  # the XML is kept exactly as nmap wrote it


def test_run_nmap_errors(monkeypatch, popen):
    def no_nmap():
        raise live.ScanError(live.NMAP_NOT_FOUND)

    fake = popen([b""], returncode=1)
    monkeypatch.setattr(live, "nmap_binary", no_nmap)
    with pytest.raises(live.ScanError) as exc:
        live.run_nmap(["-sn"])
    assert exc.value.code == live.NMAP_NOT_FOUND and fake.argv is None  # nothing started

    monkeypatch.setattr(live, "nmap_binary", lambda: "/usr/bin/nmap")
    with pytest.raises(live.ScanError) as exc:
        live.run_nmap(["-sn"])
    assert exc.value.code == live.NMAP_FAILED and "exit code 1" in exc.value.detail


def test_run_nmap_stops_nmap_when_the_output_is_too_large(monkeypatch, popen):
    monkeypatch.setattr(live, "MAX_FILE_BYTES", 10)
    fake = popen([b"<nmaprun>\n", b"x" * 20 + b"\n", b"</nmaprun>\n"])
    with pytest.raises(live.ScanError) as exc:
        live.run_nmap(["-sS"])
    assert exc.value.code == live.NMAP_FAILED and "larger than" in exc.value.detail
    assert fake.signals[0] == "TERM"  # sudo passes SIGTERM on to nmap


def test_run_nmap_times_out_and_stops_nmap(monkeypatch, popen):
    monkeypatch.setattr(live, "NMAP_TIMEOUT_S", 0.05)
    fake = popen([b"<nmaprun>\n"], block=True)  # then hangs, like a stuck nmap
    with pytest.raises(live.ScanError) as exc:
        live.run_nmap(["-sS"])
    assert exc.value.code == live.NMAP_FAILED and "timed out" in exc.value.detail
    assert fake.signals[0] == "TERM"


def test_run_nmap_stops_nmap_when_a_callback_fails(popen):
    fake = popen([taskprogress("UDP Scan", "1"), b"</nmaprun>\n"])

    def broken(*_update):
        raise KeyboardInterrupt  # what Ctrl+C looks like

    with pytest.raises(KeyboardInterrupt):
        live.run_nmap(["-sS"], broken)
    assert fake.signals == ["TERM"]


# --- progress (#107) ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("task", "step"),
    [
        ("ARP Ping Scan", live.STEP_DEVICES),
        ("Ping Scan", live.STEP_DEVICES),
        ("Parallel DNS resolution of 5 hosts.", live.STEP_DEVICES),
        ("SYN Stealth Scan", live.STEP_TCP),
        ("Connect Scan", live.STEP_TCP),
        ("UDP Scan", live.STEP_UDP),
        ("Service scan", live.STEP_SERVICES),
        ("NSE", live.STEP_TITLES),
        ("Something new", live.STEP_OTHER),
        ("", live.STEP_OTHER),
    ],
)
def test_step_for_task(task, step):
    assert live.step_for_task(task) == step


def test_progress_updates_reads_only_valid_numbers():
    line = (
        taskprogress("Service scan", "80.00", 30)
        + taskprogress("UDP Scan", "abc", 30)  # bad percent: skipped
        + taskprogress("UDP Scan", "250", 30)  # out of range: skipped
        + taskprogress("UDP Scan", "nan", 30)
        + taskprogress("NSE", "10", "soon")  # bad remaining: unknown
        + b'<taskprogress task="UDP Scan"/>'  # no percent
    )
    assert live.progress_updates(line) == [
        (live.STEP_SERVICES, 80.0, 30),
        (live.STEP_TITLES, 10.0, None),
    ]
    assert live.progress_updates(b"<host><status state='up'/></host>") == []


def test_both_nmap_steps_ask_for_progress():
    for args in (
        live.discovery_args([net(V1_NET)]),
        live.port_scan_args(["192.168.1.1"], "T:80"),
    ):
        assert args[args.index("--stats-every") + 1] == live.STATS_EVERY


def test_taskprogress_elements_do_not_change_the_results(tmp_path):
    from tool.engine import analyze_file

    noisy = V1.replace(b"<host", taskprogress("SYN Stealth Scan", "50", 20) + b"<host", 1)
    assert noisy != V1
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "V1.xml").write_bytes(V1)
    (tmp_path / "b" / "V1.xml").write_bytes(noisy)
    plain = analyze_file(tmp_path / "a" / "V1.xml")
    with_progress = analyze_file(tmp_path / "b" / "V1.xml")
    assert with_progress.status == plain.status == "ok"
    assert with_progress.score == plain.score == 90
    assert with_progress.findings == plain.findings


def test_run_scan_reports_hosts_before_the_port_scan_and_passes_progress(tmp_path):
    fake = FakeNmap(found=discovery("192.168.1.1"), progress=[(live.STEP_TCP, 50.0, 60)])
    events = []
    live.run_scan(
        [net(V1_NET)],
        fake,
        tmp_path,
        SERVICES,
        on_hosts=lambda hosts: events.append(("hosts", hosts, len(fake.calls))),
        on_progress=lambda *u: events.append(("progress", *u)),
    )
    assert events == [
        ("progress", live.STEP_TCP, 50.0, 60),  # during discovery
        ("hosts", ["192.168.1.1"], 1),  # after discovery, before the port scan
        ("progress", live.STEP_TCP, 50.0, 60),  # during the port scan
    ]


# --- the command --------------------------------------------------------------------------


@pytest.fixture
def lab(tmp_path, monkeypatch):
    """This computer is on 192.168.1.0/24 (V1's network); data and scans go to tmp_path."""
    monkeypatch.setattr(
        "tool.network.detect", lambda: Network("wlan0", "192.168.1.30", V1_NET, "192.168.1.1")
    )
    monkeypatch.delenv(g.ALLOWLIST_ENV, raising=False)
    monkeypatch.setenv("TOOL_DATA_DIR", str(tmp_path / "data"))
    services = tmp_path / "nmap-services"
    services.write_text(SERVICES)
    monkeypatch.setenv(live.SERVICES_ENV, str(services))
    fake = FakeNmap(found=discovery("192.168.1.1", "192.168.1.30"))
    monkeypatch.setattr("tool.scan.run_nmap", fake)
    return fake


def scan(tmp_path, *args):
    return main(["scan", *args, "--scans-dir", str(tmp_path / "scans")])


def test_scan_saves_analyses_and_stores_in_history(lab, tmp_path, capsys):
    assert scan(tmp_path, "--confirm", "--lang", "en") == 0
    out = capsys.readouterr().out
    saved = list((tmp_path / "scans").glob("scan_*.xml"))
    assert len(saved) == 1
    # The same score the answer key gives V1, so the live path and `analyze` agree.
    assert "Score: 90/100" in out and str(saved[0]) in out
    assert "saved 1 scans to the local history" in out
    assert len(History(tmp_path / "data").scans()) == 1
    # This computer (192.168.1.30) answered discovery but is never port-scanned.
    assert lab.calls[1][-1] == "192.168.1.1" and "192.168.1.30" in out


@pytest.mark.parametrize(
    "args",
    [
        ["--lang", "en"],  # no --confirm
        ["8.8.8.8", "--confirm"],  # public address
        ["192.168.2.0/24", "--confirm"],  # private, but not the network we're on
        ["100.64.0.1", "--confirm"],  # the operator's CGNAT side of a hotspot
        ["192.168.0.0/16", "--confirm"],  # larger than a /24
        ["router.lan", "--confirm"],  # a name
    ],
)
def test_a_refused_target_never_reaches_nmap(lab, tmp_path, args):
    assert scan(tmp_path, *args) == 3
    assert lab.calls == []
    assert not (tmp_path / "scans").exists()


def test_scan_refuses_to_run_as_root(lab, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("tool.cli.os.geteuid", lambda: 0, raising=False)
    assert scan(tmp_path, "--confirm", "--lang", "en") == 2
    assert "normal user" in capsys.readouterr().err and lab.calls == []


@pytest.mark.parametrize(("lang", "word"), [("en", "No device"), ("ro", "Niciun dispozitiv")])
def test_scan_reports_nmap_errors_in_both_languages(lab, tmp_path, capsys, lang, word):
    lab.found = discovery()
    assert scan(tmp_path, "--confirm", "--lang", lang) == 4
    err = capsys.readouterr().err
    assert word in err and "NO_LIVE_HOSTS" in err


def test_scan_with_unreadable_output_stores_an_error_row(lab, tmp_path, capsys):
    lab.scan = b"<html>not nmap</html>"
    assert scan(tmp_path, "--confirm", "--lang", "en") == 1
    assert "NOT_NMAP" in capsys.readouterr().err
    assert len(History(tmp_path / "data").scans()) == 1


def test_scan_texts_exist_in_both_languages():
    from tool.content.texts import SCAN_MESSAGES

    codes = {
        live.NMAP_NOT_FOUND,
        live.NMAP_DATA_NOT_FOUND,
        live.NMAP_FAILED,
        live.NO_LIVE_HOSTS,
        live.IPV6_NOT_SUPPORTED,
    }
    assert codes <= SCAN_MESSAGES.keys()
    for texts in SCAN_MESSAGES.values():
        assert texts["ro"] and texts["en"] and texts["ro"] != texts["en"]


# --- progress on the command line (#107) --------------------------------------------------


def test_progress_printer_prints_on_step_change_and_at_most_every_15_s():
    from tool.cli import ProgressPrinter

    now = [0.0]
    lines = []
    printer = ProgressPrinter("en", clock=lambda: now[0], out=lines.append)
    for t, step, pct in [
        (100.0, live.STEP_TCP, 10),  # first update: printed
        (105.0, live.STEP_TCP, 20),  # same step, 5 s later: skipped
        (110.0, live.STEP_UDP, 1),  # new step: printed at once
        (120.0, live.STEP_UDP, 30),  # 10 s: skipped
        (125.0, live.STEP_UDP, 40),  # 15 s: printed
    ]:
        now[0] = t
        printer(step, pct, 120)
    assert lines == [
        "Checking ports (TCP): 10% done, about 2 minutes left.",
        "Checking ports (UDP): 1% done, about 2 minutes left.",
        "Checking ports (UDP): 40% done, about 2 minutes left.",
    ]


def test_scan_prints_the_devices_found_and_the_progress(lab, tmp_path, capsys):
    lab.progress = [(live.STEP_TCP, 40.0, 90)]
    assert scan(tmp_path, "--confirm", "--lang", "en") == 0
    out = capsys.readouterr().out
    # 192.168.1.30 is this computer, so only the router is listed.
    assert "Devices found: 1 (192.168.1.1). Now checking their ports" in out
    assert "Checking ports (TCP): 40% done, about 2 minutes left." in out
    assert out.index("Devices found") < out.index("Score: 90/100")


def _break_history(folder, how):
    import sqlite3

    folder.mkdir(parents=True, exist_ok=True)
    db = folder / "history.sqlite3"
    if how == "newer":
        with sqlite3.connect(db) as conn:
            conn.execute("PRAGMA user_version = 99")
    else:
        db.write_bytes(b"this is not a database" * 100)


@pytest.mark.parametrize("how", ["newer", "corrupt"])
def test_a_broken_history_never_breaks_the_scan(lab, tmp_path, capsys, how):
    # #132: the XML is saved and the score printed; the history problem is one plain line.
    _break_history(tmp_path / "data", how)
    assert scan(tmp_path, "--confirm", "--lang", "en") == 0
    captured = capsys.readouterr()
    assert "Score: 90/100" in captured.out
    assert len(list((tmp_path / "scans").glob("scan_*.xml"))) == 1
    assert "the history couldn't be updated" in captured.err
    assert "Traceback" not in captured.err


def test_default_cli_captures_follow_data_dir_and_are_deleted_with_history(lab, tmp_path):
    assert main(["scan", "--confirm", "--lang", "en"]) == 0
    folder = tmp_path / "data"
    capture = list((folder / "scans").glob("scan_*.xml"))
    assert len(capture) == 1
    assert capture[0].read_bytes() == V1
    assert capture[0].stat().st_mode & 0o777 == 0o600
    History(folder).delete_all()
    assert not capture[0].exists()
    assert not (tmp_path / "scans").exists()


def test_default_run_scan_resolves_current_data_dir_at_call_time(tmp_path, monkeypatch):
    selected = tmp_path / "selected"
    monkeypatch.setenv("TOOL_DATA_DIR", str(selected))
    saved = live.run_scan(
        [net(V1_NET)], runner=FakeNmap(found=discovery("192.168.1.1")), services_text=SERVICES
    )
    assert saved.parent == selected / "scans"
    assert saved.parent.stat().st_mode & 0o777 == 0o700


def test_custom_capture_directory_survives_history_deletion(lab, tmp_path):
    assert scan(tmp_path, "--confirm", "--lang", "en") == 0
    capture = next((tmp_path / "scans").glob("scan_*.xml"))
    History(tmp_path / "data").delete_all()
    assert capture.read_bytes() == V1
