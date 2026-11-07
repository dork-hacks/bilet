"""The home screen follows the newest readable scan in the history (#87)."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from markupsafe import escape

from tool.content.ui import UI
from tool.engine import analyze_file
from tool.history import History
from tool.web.app import create_app, latest_from_history

VALIDATION = Path(__file__).parent / "fixtures" / "validation"
TRAPS = Path(__file__).parent / "fixtures" / "traps"
SALT = b"test-salt"
NO_SCAN = str(escape(UI["no_scan"]["en"]))


def scan(path: Path) -> dict:
    return analyze_file(path, salt=SALT).to_dict()


@pytest.fixture
def history(tmp_path):
    return History(tmp_path / "data")


def home(history, load_result=lambda: None) -> str:
    client = TestClient(create_app(load_result, history=history))
    res = client.get("/", params={"lang": "en"})
    assert res.status_code == 200
    return res.text


def test_newest_scan_by_nmap_start_time_wins(history):
    # Added in the wrong order on purpose: the order comes from nmap's start time.
    history.add(scan(VALIDATION / "V6b_after.xml"))
    history.add(scan(VALIDATION / "V6a_before.xml"))
    assert latest_from_history(history)["file"] == "V6b_after.xml"
    assert NO_SCAN not in home(history)


def test_a_scan_saved_while_running_shows_on_the_next_load(history):
    client = TestClient(create_app(lambda: None, history=history))
    assert NO_SCAN in client.get("/", params={"lang": "en"}).text
    history.add(scan(VALIDATION / "V6a_before.xml"))
    assert NO_SCAN not in client.get("/", params={"lang": "en"}).text


def test_result_file_wins_over_the_history(history):
    history.add(scan(VALIDATION / "V6b_after.xml"))
    given = scan(VALIDATION / "V6a_before.xml")
    seen = []

    def load():
        seen.append(True)
        return given

    assert NO_SCAN not in home(history, load)
    assert seen  # the --result loader was asked first
    # The page shows V6a's score, not V6b's.
    assert f">{given['score']}<" in home(history, load).replace(" ", "")


def test_empty_history_shows_the_empty_state(history):
    assert latest_from_history(history) is None
    assert NO_SCAN in home(history)


def test_no_history_object_shows_the_empty_state():
    assert latest_from_history(None) is None
    assert NO_SCAN in home(None)


def test_error_only_history_shows_the_empty_state(history):
    history.add(scan(TRAPS / "T09_empty.xml"))
    history.add(scan(TRAPS / "T11_truncated.xml"))
    assert [s.status for s in history.scans()] == ["error", "error"]
    assert latest_from_history(history) is None
    assert NO_SCAN in home(history)


def test_error_scan_newer_than_a_good_one_is_skipped(history):
    history.add(scan(VALIDATION / "V6a_before.xml"))
    history.add(scan(TRAPS / "T09_empty.xml"))
    assert latest_from_history(history)["file"] == "V6a_before.xml"


def test_corrupt_database_never_breaks_the_home_screen(history):
    history.folder.mkdir(parents=True, exist_ok=True)
    history.path.write_bytes(b"this is not a sqlite database" * 100)
    assert latest_from_history(history) is None
    assert NO_SCAN in home(history)


def test_corrupt_stored_row_never_breaks_the_home_screen(history):
    import sqlite3

    history.add(scan(VALIDATION / "V6a_before.xml"))
    with sqlite3.connect(history.path) as db:
        db.execute("UPDATE scans SET result_json = '{not json'")
    assert latest_from_history(history) is None
    assert NO_SCAN in home(history)
