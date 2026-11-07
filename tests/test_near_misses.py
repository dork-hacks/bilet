"""The near-miss report (#187): flags what a human should double-check, changes nothing."""

import importlib.util
import shutil
from pathlib import Path

import pytest

from tool.engine import analyze_file

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
TRAPS, VALIDATION = FIXTURES / "traps", FIXTURES / "validation"

_spec = importlib.util.spec_from_file_location("near_misses", ROOT / "scripts" / "near_misses.py")
nm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nm)


def items(path: Path) -> set[tuple[str, str, str]]:
    return {(i.ip, i.where, i.check) for i in nm.report_file(path).items}


# Every item each fixture must give, exactly: one file per trap the report is meant for.
EXPECTED = {
    VALIDATION / "V1_home_basic.xml": {("192.168.1.1", "443/tcp", "ssl-tunnel")},
    VALIDATION / "V4_legacy.xml": {("192.168.1.99", "-", "unknown-1-port")},
    TRAPS / "T01_https_admin.xml": {
        ("192.168.1.1", "443/tcp", "ssl-tunnel"),
        ("192.168.1.1", "8443/tcp", "ssl-tunnel"),
        ("192.168.1.5", "5001/tcp", "ssl-tunnel"),
    },
    TRAPS / "T02_http_admin_titles.xml": {
        ("192.168.1.2", "80/tcp", "title-inside-word"),  # "WebAdmin"
        ("192.168.1.9", "5000/tcp", "title-near"),  # "Dashboard"
    },
    TRAPS / "T03_filtered_ports.xml": {
        ("192.168.1.20", "161/udp", "open-filtered"),
        ("192.168.1.20", "1900/udp", "open-filtered"),
        ("192.168.1.20", "5900/tcp", "open-filtered"),
    },
    TRAPS / "T04_ipv6.xml": {
        ("fd00:1:2:3::10", "-", "no-ipv4"),
        ("fd00:1:2:3::99", "-", "no-ipv4"),
        ("fd00:1:2:3::99", "-", "unknown-1-port"),
    },
    TRAPS / "T20_upnp_snmp_tcp_udp.xml": {
        ("192.168.1.1", "1900/tcp", "udp-only"),
        ("192.168.1.1", "5000/tcp", "udp-only"),
        ("192.168.1.2", "161/tcp", "table-guess"),
        ("192.168.1.2", "161/tcp", "udp-only"),
        ("192.168.1.3", "161/udp", "open-filtered"),
        ("192.168.1.3", "1900/udp", "open-filtered"),
    },
    TRAPS / "T24_service_name_lookalikes.xml": {
        ("192.168.1.50", "23/tcp", "catalog-port"),  # tcpwrapped
        ("192.168.1.50", "5800/tcp", "name-lookalike"),  # vnc-http
        ("192.168.1.50", "8883/tcp", "name-lookalike"),  # secure-mqtt
        ("192.168.1.50", "8883/tcp", "table-guess"),
    },
    TRAPS / "T27_samba_3x_4x.xml": {
        ("192.168.1.20", "139/tcp", "version-unsure"),
        ("192.168.1.20", "445/tcp", "version-unsure"),
    },
    TRAPS / "T28_method_table_catalog.xml": {
        ("192.168.1.30", "23/tcp", "table-guess"),
        ("192.168.1.30", "161/udp", "table-guess"),
        ("192.168.1.30", "3389/tcp", "table-guess"),
    },
    TRAPS / "T29_http_name_variants.xml": {
        (ip, port, check)
        for ip in ["192.168.1.40"]
        for port in ["443/tcp", "8000/tcp", "8080/tcp"]
        for check in ["name-lookalike", "table-guess"]
    },
    TRAPS / "T32_http_title_edge_cases.xml": {
        ("192.168.1.1", "80/tcp", "redirect-title"),
        ("192.168.1.2", "80/tcp", "title-near"),  # "Log in"
    },
}
NOTHING_TO_CHECK = [
    VALIDATION / "V2_smart_home.xml",
    VALIDATION / "V3_small_office.xml",
    VALIDATION / "V6a_before.xml",
    TRAPS / "T05_multiple_hostnames.xml",
    TRAPS / "T14_openssh_versions.xml",
    TRAPS / "T17_ftp_samba_versions.xml",
    TRAPS / "T22_no_hosts_up.xml",
    TRAPS / "T31_outdated_samba_139_and_445.xml",
]


@pytest.mark.parametrize("path", EXPECTED, ids=lambda p: p.name)
def test_fixture_gives_exactly_its_near_misses(path):
    assert items(path) == EXPECTED[path]


@pytest.mark.parametrize("path", NOTHING_TO_CHECK, ids=lambda p: p.name)
def test_plain_files_have_nothing_to_check(path):
    assert items(path) == set()


@pytest.mark.parametrize("folder", [VALIDATION, TRAPS], ids=lambda p: p.name)
def test_engine_column_is_what_analyze_reports(folder):
    for path in nm.scan_files(folder):
        result = analyze_file(path, salt=b"")
        for item in nm.report_file(path).items:
            if item.where == "-" or item.engine == "not a title":
                continue
            number, protocol = item.where.split("/")
            codes = sorted(
                f["code"]
                for f in result.findings
                if (f["ip"], f["port"], f["protocol"]) == (item.ip, int(number), protocol)
            )
            assert item.engine == ("+".join(codes) if codes else "no finding"), (path, item)


def test_report_never_writes_anything(tmp_path):
    folder = tmp_path / "set"
    shutil.copytree(VALIDATION, folder)
    before = {p.name: p.read_bytes() for p in folder.iterdir()}
    nm.main([str(folder)])
    assert {p.name: p.read_bytes() for p in folder.iterdir()} == before


def test_unreadable_and_skipped_files_are_named(tmp_path, capsys):
    shutil.copy(VALIDATION / "V7_broken.xml", tmp_path)
    shutil.copy(VALIDATION / "V1_home_basic.xml", tmp_path / "V1.XML")
    (tmp_path / "notes.txt").write_text("x")
    (tmp_path / ".hidden.xml").write_text("x")
    assert nm.main([str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "V7_broken.xml: ERROR (NOT_XML: ParseError: unclosed token" in out
    assert "V1.XML: 1 findings, score 90, 1 to check" in out  # upper-case .XML is read
    assert "notes.txt: not analysed" in out and ".hidden.xml: not analysed" in out
    assert "2 files, 1 unreadable, 1 items to check, 2 skipped" in out


def test_bad_arguments_give_usage(tmp_path, capsys):
    assert nm.main([]) == 2
    assert nm.main([str(tmp_path / "missing")]) == 2
    assert "usage" in capsys.readouterr().err


def nmap(hosts: str) -> str:
    return f'<?xml version="1.0"?>\n<nmaprun scanner="nmap" start="1794042000">{hosts}</nmaprun>'


def test_vendor_placeholder_and_host_without_address(tmp_path):
    path = tmp_path / "x.xml"
    path.write_text(
        nmap(
            '<host><status state="up"/><address addr="192.168.1.5" addrtype="ipv4"/>'
            '<address addr="02:00:00:00:00:05" addrtype="mac" vendor="Unknown"/>'
            '<ports><port protocol="tcp" portid="80"><state state="open"/>'
            '<service name="http"/></port></ports></host>'
            '<host><status state="up"/><address addr="nonsense" addrtype="ipv4"/></host>'
        )
    )
    assert items(path) == {
        ("192.168.1.5", "-", "vendor-text"),
        ("(none)", "-", "no-ipv4"),
    }


@pytest.mark.parametrize(
    ("name", "target"),
    [
        ("microsoft-ds?", "microsoft-ds"),
        ("ssl/http", "http"),
        ("https", "http"),
        ("http-proxy", "http"),
        ("ibm-mqisdp", "mqtt"),
        ("redis-sentinel", "redis"),
        ("http", None),
        ("netbios-ns", None),
        ("", None),
    ],
)
def test_lookalike(name, target):
    assert nm.lookalike(name) == target


@pytest.mark.parametrize(
    ("title", "word"),
    [
        ("Admn panel", "admn"),
        ("Routr", "routr"),
        ("Please sign in", "sign in"),
        ("Autentificare", "autentificare"),
        ("Welcome to nginx!", None),
    ],
)
def test_near_title_word(title, word):
    assert nm.near_title_word(title) == word


def test_keyword_inside_word():
    assert nm.keyword_inside_word("Blogin page") == "Blogin"
    assert nm.keyword_inside_word("Router Configuration") is None


@pytest.mark.parametrize(
    ("product", "version", "flagged"),
    [
        ("Samba smbd", "3.X - 4.X", True),
        ("OpenSSH", None, True),
        ("Apache httpd", "2.2.x", True),
        ("vsftpd", "unknown", True),
        ("OpenSSH", "7.2p2 Ubuntu 4ubuntu2.10", False),
        ("Linux telnetd", None, False),
    ],
)
def test_version_doubt(product, version, flagged):
    port = nm.RawPort(22, "tcp", "ssh", product, version, None, "probed", None)
    assert bool(nm.version_doubt(port)) is flagged
