"""The live scan (#20) with nmap faked: no test starts a subprocess or sends a packet."""

import ipaddress
import os
import subprocess
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
    """Returns the discovery XML for -sn and the port-scan XML otherwise."""

    def __init__(self, found=b"", scan=V1):
        self.found, self.scan, self.calls = found, scan, []

    def __call__(self, args):
        self.calls.append(args)
        return self.found if args[0] == "-sn" else self.scan


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


def test_run_nmap_puts_only_nmap_under_sudo(monkeypatch):
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"], seen["kwargs"] = argv, kwargs
        return subprocess.CompletedProcess(argv, 0, stdout=b"<nmaprun/>")

    monkeypatch.setattr(live.shutil, "which", lambda _name: "/usr/bin/nmap")
    monkeypatch.setattr(live.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(live.subprocess, "run", fake_run)
    assert live.run_nmap(["-sn", "192.168.1.0/24"]) == b"<nmaprun/>"
    assert seen["argv"] == ["sudo", "--", "/usr/bin/nmap", "-sn", "192.168.1.0/24"]
    assert seen["kwargs"]["stdout"] == subprocess.PIPE and "shell" not in seen["kwargs"]


def test_run_nmap_errors(monkeypatch):
    monkeypatch.setattr(live.shutil, "which", lambda _name: None)
    with pytest.raises(live.ScanError) as exc:
        live.run_nmap(["-sn"])
    assert exc.value.code == live.NMAP_NOT_FOUND

    monkeypatch.setattr(live.shutil, "which", lambda _name: "/usr/bin/nmap")
    monkeypatch.setattr(
        live.subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 1, b"")
    )
    with pytest.raises(live.ScanError) as exc:
        live.run_nmap(["-sn"])
    assert exc.value.code == live.NMAP_FAILED


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
