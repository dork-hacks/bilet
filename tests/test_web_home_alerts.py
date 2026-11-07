"""Change alerts on the home screen (#78, FR-13): new device, new open port."""

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from markupsafe import escape

from tool.content import alert_message
from tool.content.ui import UI
from tool.engine import analyze_file
from tool.engine.parser import parse_bytes
from tool.engine.result import build_result
from tool.history import NEW_DEVICE, NEW_OPEN_PORT, Alert, History
from tool.web.app import create_app, latest_with_alerts
from tool.web.view import home_view

VALIDATION = Path(__file__).parent / "fixtures" / "validation"
SALT = b"test-salt"
EXTRA_MAC = "B8:27:EB:00:00:77"
EXTRA_HOST = (
    '<host><status state="up"/><address addr="192.168.1.77" addrtype="ipv4"/>'
    f'<address addr="{EXTRA_MAC}" addrtype="mac" vendor="Raspberry Pi Foundation"/>'
    '<hostnames><hostname name="stranger" type="PTR"/></hostnames><ports>'
    '<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>'
    "</ports></host>"
)


def heading(lang: str) -> str:
    return str(escape(UI["alerts_heading"][lang]))


def scan(name: str) -> dict:
    return analyze_file(VALIDATION / name, salt=SALT).to_dict()


def v6b_plus_a_host() -> dict:
    # A later scan of the V6b home with one more device on it (same trick as test_alerts).
    xml = (VALIDATION / "V6b_after.xml").read_text()
    xml = xml.replace("<runstats>", EXTRA_HOST + "<runstats>", 1).replace('start="', 'start="9', 1)
    return build_result(parse_bytes(xml.encode(), "V6c_new_device.xml"), SALT).to_dict()


@pytest.fixture
def history(tmp_path):
    return History(tmp_path / "data")


def home(history, lang="en", load_result=lambda: None) -> str:
    client = TestClient(create_app(load_result, history=history), base_url="http://127.0.0.1")
    res = client.get("/", params={"lang": lang})
    assert res.status_code == 200
    return res.text


def test_new_device_is_shown(history):
    history.add(scan("V6b_after.xml"))
    history.add(v6b_plus_a_host())
    page = home(history)
    assert heading("en") in page
    assert str(escape(alert_message(NEW_DEVICE, "192.168.1.77", lang="en"))) in page
    # Only the IP is shown: never the MAC or the hostname from the scan.
    start = page.index('class="alerts"')
    box = page[start : page.index("</section>", start)]
    assert EXTRA_MAC not in box and "stranger" not in box


def test_new_open_port_is_shown_in_both_languages(history):
    history.add(scan("V6a_before.xml"))
    history.add(scan("V6b_after.xml"))
    for lang in ("en", "ro"):
        page = home(history, lang)
        assert heading(lang) in page
        text = alert_message(NEW_OPEN_PORT, "192.168.1.1", port=443, protocol="tcp", lang=lang)
        assert str(escape(text)) in page


def test_a_single_scan_shows_no_box(history):
    history.add(scan("V6a_before.xml"))
    page = home(history)
    assert 'class="alerts"' not in page and heading("en") not in page


def test_no_alerts_shows_no_box(history):
    first = scan("V6b_after.xml")
    history.add(first)
    # The same network checked again later: nothing new appeared.
    history.add(first | {"scan_start": "9" + str(first["scan_start"])})
    assert 'class="alerts"' not in home(history)


def test_no_history_shows_no_box():
    page = home(None)
    assert 'class="alerts"' not in page


def test_a_result_file_shows_no_alerts(history):
    # Alerts belong to the history's newest scan, not to a `--result` file.
    history.add(scan("V6a_before.xml"))
    history.add(scan("V6b_after.xml"))
    page = home(history, load_result=lambda: scan("V6a_before.xml"))
    assert 'class="alerts"' not in page


def test_a_corrupt_history_never_breaks_the_home_screen(tmp_path):
    folder = tmp_path / "data"
    folder.mkdir()
    (folder / History(folder).path.name).write_bytes(b"this is not a database" * 100)
    history = History(folder)
    assert latest_with_alerts(history) == (None, [])
    assert 'class="alerts"' not in home(history)


def test_an_alerts_error_keeps_the_scan_and_drops_the_box(history, monkeypatch):
    history.add(scan("V6a_before.xml"))
    history.add(scan("V6b_after.xml"))

    def broken(scan_id):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(history, "alerts_for", broken)
    data, alerts = latest_with_alerts(history)
    assert data["file"] == "V6b_after.xml" and alerts == []
    assert 'class="alerts"' not in home(history)


def test_hostile_values_are_escaped(history, monkeypatch):
    history.add(scan("V6a_before.xml"))
    history.add(scan("V6b_after.xml"))
    hostile = Alert(NEW_OPEN_PORT, "k", "<script>alert(1)</script>", "<b>tcp</b>", 80)
    monkeypatch.setattr(history, "alerts_for", lambda scan_id: [hostile])
    page = home(history)
    assert heading("en") in page
    assert "<script>alert(1)</script>" not in page and "<b>tcp</b>" not in page


def test_error_scan_ignores_alerts():
    view = home_view(scan("V7_broken.xml"), "en", alerts=[Alert(NEW_DEVICE, "k", "192.168.1.9")])
    assert view.kind == "error" and view.alerts == ()
