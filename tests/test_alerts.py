from pathlib import Path

import pytest

from tool.cli import main
from tool.engine import analyze_file
from tool.engine.parser import parse_bytes
from tool.engine.result import build_result
from tool.history import NEW_DEVICE, NEW_OPEN_PORT, Alert, History

VALIDATION = Path(__file__).parent / "fixtures" / "validation"
SALT = b"test-salt"

EXTRA_HOST = (
    '<host><status state="up"/><address addr="192.168.1.77" addrtype="ipv4"/>'
    '<address addr="B8:27:EB:00:00:77" addrtype="mac" vendor="Raspberry Pi Foundation"/>'
    '<hostnames><hostname name="stranger" type="PTR"/></hostnames><ports>'
    '<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>'
    "</ports></host>"
)


def scan(name: str) -> dict:
    return analyze_file(VALIDATION / name, salt=SALT).to_dict()


def v6b_plus_a_host() -> dict:
    # A later scan of the V6b home with one more device on it.
    xml = (VALIDATION / "V6b_after.xml").read_text()
    xml = xml.replace("<runstats>", EXTRA_HOST + "<runstats>", 1).replace('start="', 'start="9', 1)
    return build_result(parse_bytes(xml.encode(), "V6c_new_device.xml"), SALT).to_dict()


@pytest.fixture
def history(tmp_path):
    return History(tmp_path / "data")


def test_a_new_host_gives_one_new_device_alert(history):
    history.add(scan("V6b_after.xml"))
    later = history.add(v6b_plus_a_host())
    alerts = history.alerts_for(later)
    assert [(a.code, a.ip) for a in alerts] == [(NEW_DEVICE, "192.168.1.77")]
    # Its open port isn't repeated as a separate NEW_OPEN_PORT.
    assert all(a.code != NEW_OPEN_PORT for a in alerts)


def test_v6a_to_v6b_gives_only_the_new_https_port(history):
    history.add(scan("V6a_before.xml"))
    after = history.add(scan("V6b_after.xml"))
    # Every MAC changed between these files, but the devices pair up: no false NEW_DEVICE.
    assert history.alerts_for(after) == [
        Alert(
            NEW_OPEN_PORT,
            history.result(after)["devices"][0]["device_key"],
            "192.168.1.1",
            "tcp",
            443,
        )
    ]


def test_first_scan_has_no_alerts(history):
    assert history.alerts_for(history.add(scan("V6a_before.xml"))) == []


def test_unreadable_scans_are_skipped_as_the_previous_one(history):
    history.add(scan("V6b_after.xml"))
    history.add(scan("V7_broken.xml"))
    later = history.add(v6b_plus_a_host())
    assert [a.code for a in history.alerts_for(later)] == [NEW_DEVICE]
    assert history.alerts_for(999) == []


def test_alert_record_is_codes_only():
    alert = Alert(NEW_OPEN_PORT, "d_123456789abc", "192.168.1.1", "tcp", 443)
    assert alert.to_dict() == {
        "code": "NEW_OPEN_PORT",
        "device_key": "d_123456789abc",
        "ip": "192.168.1.1",
        "protocol": "tcp",
        "port": 443,
    }


@pytest.mark.parametrize(("lang", "word"), [("en", "new service"), ("ro", "serviciu nou")])
def test_analyze_save_prints_the_alerts(tmp_path, monkeypatch, capsys, lang, word):
    monkeypatch.setenv("TOOL_DATA_DIR", str(tmp_path / "data"))
    scans = tmp_path / "scans"
    scans.mkdir()
    for name in ("V6a_before.xml", "V6b_after.xml"):
        (scans / name).write_bytes((VALIDATION / name).read_bytes())
    assert (
        main(["analyze", str(scans), "--out", str(tmp_path / "out"), "--save", "--lang", lang]) == 0
    )
    out = capsys.readouterr().out
    assert "saved 2 scans" in out and word in out and "NEW_OPEN_PORT" in out
    assert len(History(tmp_path / "data").scans()) == 2


def test_save_stores_unreadable_files_as_error_rows(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("TOOL_DATA_DIR", str(tmp_path / "data"))
    scans = tmp_path / "scans"
    scans.mkdir()
    for name in ("V6b_after.xml", "V7_broken.xml"):
        (scans / name).write_bytes((VALIDATION / name).read_bytes())
    assert main(["analyze", str(scans), "--out", str(tmp_path / "out"), "--save"]) == 0
    rows = {s.file: s.status for s in History(tmp_path / "data").scans()}
    assert rows == {"V6b_after.xml": "ok", "V7_broken.xml": "error"}


def test_save_leaves_the_csvs_byte_identical(tmp_path, monkeypatch):
    # #75: the Test Set upload must not change because the history is on.
    monkeypatch.setenv("TOOL_DATA_DIR", str(tmp_path / "data"))
    main(["analyze", str(VALIDATION), "--out", str(tmp_path / "plain")])
    main(["analyze", str(VALIDATION), "--out", str(tmp_path / "saved"), "--save"])
    for name in ("findings.csv", "scores.csv"):
        assert (tmp_path / "plain" / name).read_bytes() == (tmp_path / "saved" / name).read_bytes()
        assert (tmp_path / "saved" / name).read_bytes() == (
            VALIDATION / f"expected_{name}"
        ).read_bytes()
