"""The history screen (#65): trend, compare two scans, delete my history."""

import copy
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from markupsafe import escape

from tool.content.ui import UI
from tool.engine import analyze_file
from tool.history import History
from tool.web.app import create_app
from tool.web.history_view import history_view, trend_chart, when_label

VALIDATION = Path(__file__).parent / "fixtures" / "validation"
SALT = b"test-salt"


def scan(name: str) -> dict:
    return analyze_file(VALIDATION / name, salt=SALT).to_dict()


@pytest.fixture
def history(tmp_path):
    return History(tmp_path / "data")


@pytest.fixture
def before_after(history):
    """V6a (before) and V6b (after), added in the wrong order on purpose."""
    after = history.add(scan("V6b_after.xml"))
    before = history.add(scan("V6a_before.xml"))
    return history, before, after


def client(history):
    return TestClient(create_app(lambda: None, history=history), base_url="http://127.0.0.1")


def text_of(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


# --- view logic -------------------------------------------------------------------------


def test_scans_are_listed_by_nmap_start_time(before_after):
    history, before, after = before_after
    view = history_view(history, "en")
    assert [row.id for row in view.scans] == [before, after]
    assert [row.file for row in view.scans] == ["V6a_before.xml", "V6b_after.xml"]


def test_default_comparison_is_the_two_newest_scans(before_after):
    history, before, after = before_after
    view = history_view(history, "en")
    assert (view.old_id, view.new_id) == (before, after)
    v6a, v6b = scan("V6a_before.xml")["score"], scan("V6b_after.xml")["score"]
    assert v6b > v6a
    assert view.comparison.score_line == f"The score went up from {v6a} to {v6b}."
    assert view.trend_summary == f"Your score went up from {v6a} to {v6b}."
    headings = dict(view.comparison.sections)
    assert len(headings["Problems you fixed"]) == 3  # the brief's V6a -> V6b pair
    assert "New problems" not in headings


def test_reverse_comparison_shows_the_problems_coming_back(before_after):
    history, before, after = before_after
    view = history_view(history, "en", old=str(after), new=str(before))
    headings = dict(view.comparison.sections)
    assert len(headings["New problems"]) == 3
    assert view.comparison.score_line.startswith("The score went down")


def test_hostile_picker_values_fall_back_to_the_default(before_after):
    history, before, after = before_after
    for bad in ("x", "-1", "999999", "1 OR 1=1", "9" * 40, ""):
        view = history_view(history, "en", old=bad, new=bad)
        assert (view.old_id, view.new_id) == (before, after)


def test_same_scan_twice_asks_for_two_different_ones(before_after):
    history, before, _ = before_after
    view = history_view(history, "en", old=str(before), new=str(before))
    assert view.comparison is None
    assert view.message == UI["compare_same"]["en"]


def test_chart_needs_two_readable_scans_and_goes_up_when_the_score_does(before_after):
    history, *_ = before_after
    history.add(scan("V7_broken.xml"))  # an unreadable scan is listed but not charted
    view = history_view(history, "en")
    assert len(view.scans) == 3 and len(view.chart.points) == 2
    first, last = view.chart.points
    assert last.score > first.score and last.y < first.y  # SVG y grows downwards
    assert trend_chart(list(view.scans[:1])) is None


def test_time_label():
    from tool.history import ScanSummary

    summary = ScanSummary(1, "a.xml", "2026-11-07T09:05:00Z", "ok", 50)
    assert when_label(summary, "en") == "2026-11-07 09:05 UTC"
    assert when_label(ScanSummary(1, "a.xml", None, "ok", 50), "ro") == "Oră necunoscută"


# --- the page ---------------------------------------------------------------------------


@pytest.mark.parametrize("lang", ["ro", "en"])
def test_page_renders_in_both_languages(before_after, lang):
    history, *_ = before_after
    res = client(history).get("/history", params={"lang": lang})
    assert res.status_code == 200
    html = res.text
    assert f'<html lang="{lang}">' in html
    for key in ("history_title", "trend_heading", "compare_heading", "delete_heading"):
        assert UI[key][lang] in html
    assert "<svg" in html and "<table>" in html  # the chart has a table next to it
    assert "<script" not in html  # works without JavaScript


def test_empty_history_shows_a_message_not_an_error(history):
    res = client(history).get("/history", params={"lang": "en"})
    assert res.status_code == 200
    assert UI["history_empty"]["en"] in res.text
    assert "<svg" not in res.text


def test_single_scan_shows_a_helpful_message(history):
    history.add(scan("V6a_before.xml"))
    res = client(history).get("/history", params={"lang": "en"})
    assert res.status_code == 200
    assert UI["history_one"]["en"] in res.text
    assert 'id="compare-heading"' not in res.text


def test_app_without_history_says_it_is_off():
    res = TestClient(create_app(lambda: None), base_url="http://127.0.0.1").get(
        "/history", params={"lang": "en"}
    )
    assert res.status_code == 200
    assert UI["history_off"]["en"] in res.text


def test_home_links_to_the_history_screen():
    res = TestClient(create_app(lambda: None), base_url="http://127.0.0.1").get(
        "/", params={"lang": "en"}
    )
    assert 'href="/history?lang=en"' in res.text
    assert UI["history_link"]["en"] in res.text


def test_hostile_hostname_and_file_name_are_escaped(history):
    before = scan("V6a_before.xml")
    after = copy.deepcopy(scan("V6b_after.xml"))
    after["file"] = '<img src=x onerror="alert(1)">.xml'
    newcomer = copy.deepcopy(after["devices"][0])
    newcomer.update(
        device_key="dk_injected",
        ip="192.168.1.250",
        mac_masked=None,
        hostname="<script>alert('x')</script>",
        open_ports=[],
        finding_ids=[],
        risk_points=0,
    )
    after["devices"].append(newcomer)
    history.add(before)
    history.add(after)
    html = client(history).get("/history", params={"lang": "en"}).text
    assert "<script>alert" not in html and "<img src=x" not in html
    assert "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;" in html
    assert "New devices (1)" in text_of(html)


def test_no_raw_mac_on_the_page(before_after):
    history, *_ = before_after
    html = client(history).get("/history", params={"lang": "en"}).text
    raw_macs = re.findall(
        rb'addr="([0-9A-F]{2}(?::[0-9A-F]{2}){5})"', (VALIDATION / "V6a_before.xml").read_bytes()
    )
    assert raw_macs
    for mac in raw_macs:
        assert mac.decode() not in html


# --- delete my history ------------------------------------------------------------------


def test_delete_is_never_a_get(before_after):
    history, *_ = before_after
    c = client(history)
    assert c.get("/history/delete").status_code == 405
    assert c.get("/history", params={"confirm": "yes"}).status_code == 200
    assert len(history.scans()) == 2


def test_delete_asks_first_then_deletes(before_after):
    history, *_ = before_after
    c = client(history)
    res = c.post("/history/delete", data={"lang": "en"})
    assert res.status_code == 200
    assert str(escape(UI["delete_confirm"]["en"])) in res.text  # Jinja's own escaping
    assert 'name="confirm" value="yes"' in res.text
    assert len(history.scans()) == 2  # nothing deleted yet

    res = c.post("/history/delete", data={"lang": "en", "confirm": "yes"}, follow_redirects=False)
    assert res.status_code == 303
    assert res.headers["location"] == "/history?lang=en&done=1"
    assert history.scans() == []
    page = c.get(res.headers["location"])
    assert UI["deleted_done"]["en"] in page.text
    assert UI["history_empty"]["en"] in page.text


def test_cross_site_post_cannot_delete(before_after):
    history, *_ = before_after
    c = client(history)
    for headers in (
        {"origin": "http://evil.example"},
        {"sec-fetch-site": "cross-site"},
        {"sec-fetch-site": "same-site"},
    ):
        res = c.post("/history/delete", data={"confirm": "yes"}, headers=headers)
        assert res.status_code == 403
    assert len(history.scans()) == 2
    res = c.post(
        "/history/delete",
        data={"confirm": "yes"},
        headers={"origin": "http://127.0.0.1", "sec-fetch-site": "same-origin"},
        follow_redirects=False,
    )
    assert res.status_code == 303 and history.scans() == []


def test_oversized_delete_form_is_refused(before_after):
    history, *_ = before_after
    res = client(history).post("/history/delete", data={"confirm": "yes", "pad": "x" * 5000})
    assert res.status_code == 413
    assert len(history.scans()) == 2
