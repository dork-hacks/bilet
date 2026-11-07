import copy
import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tool.cli import main
from tool.web.app import create_app, load_json_file
from tool.web.view import home_view, most_dangerous, score_band

FIXTURES = Path(__file__).parent / "fixtures" / "contract"
SCAN = json.loads((FIXTURES / "example_scan.json").read_text(encoding="utf-8"))
ERROR = json.loads((FIXTURES / "example_error.json").read_text(encoding="utf-8"))


def client_for(result):
    return TestClient(create_app(lambda: result))


# --- view logic -------------------------------------------------------------------------


def test_most_dangerous_is_the_camera_in_the_fixture():
    device, finding = most_dangerous(SCAN)
    assert device["device_type_guess"] == "camera"
    assert device["risk_points"] == 30
    assert finding["device_key"] == device["device_key"]
    assert finding["points"] == max(
        f["points"] for f in SCAN["findings"] if f["device_key"] == device["device_key"]
    )


def test_tie_goes_to_the_first_device():
    scan = copy.deepcopy(SCAN)
    for device in scan["devices"]:
        device["risk_points"] = 30 if device["finding_ids"] else 0
    first_with_findings = next(d for d in scan["devices"] if d["finding_ids"])
    assert most_dangerous(scan)[0]["ip"] == first_with_findings["ip"]


def test_no_findings_means_nothing_to_fix():
    scan = copy.deepcopy(SCAN)
    scan["findings"], scan["score"], scan["points_total"] = [], 100, 0
    for device in scan["devices"]:
        device["risk_points"], device["finding_ids"] = 0, []
    view = home_view(scan, "en")
    assert view.first is None
    assert view.band.key == "good"


@pytest.mark.parametrize(
    ("score", "band"),
    [(100, "good"), (80, "good"), (79, "warn"), (50, "warn"), (49, "bad"), (0, "bad")],
)
def test_score_bands(score, band):
    assert score_band(score, "en").key == band


def test_unknown_language_falls_back_to_romanian():
    assert home_view(SCAN, "xx").lang == "ro"


# --- rendered page ----------------------------------------------------------------------


@pytest.mark.parametrize("lang", ["ro", "en"])
def test_home_answers_the_jury_question(lang):
    html = client_for(SCAN).get("/", params={"lang": lang}).text
    view = home_view(SCAN, lang)
    assert f'<html lang="{lang}">' in html
    assert ">35<" in html
    assert view.band.label in html and view.band.icon in html  # never colour alone
    assert "192.168.1.40" in html
    assert view.first.finding_title in html


def test_english_sentence():
    html = client_for(SCAN).get("/?lang=en").text
    assert "Most dangerous device:" in html
    assert "Do this first:" in html
    assert "Network at risk" in html


def test_broken_file_shows_a_friendly_message():
    response = client_for(ERROR).get("/?lang=en")
    assert response.status_code == 200
    assert "We could not read this check" in response.text
    assert 'role="alert"' in response.text


def test_no_scan_yet():
    response = client_for(None).get("/?lang=en")
    assert response.status_code == 200
    assert "There is no check yet" in response.text


def test_raw_fields_are_escaped():
    scan = copy.deepcopy(SCAN)
    camera = next(d for d in scan["devices"] if d["device_type_guess"] == "camera")
    camera["hostname"] = '<script>alert("x")</script>'
    scan["file"] = "<img src=x onerror=alert(1)>.xml"
    html = client_for(scan).get("/").text
    assert "<script>alert" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html


def test_no_full_mac_on_the_page():
    html = client_for(SCAN).get("/").text
    assert not re.search(r"(?i)\b[0-9a-f]{2}(:[0-9a-f]{2}){5}\b", html)


def test_bad_lang_parameter_is_not_reflected():
    html = client_for(SCAN).get("/", params={"lang": '"><script>x</script>'}).text
    assert "<script>x" not in html


# --- loading and the CLI ----------------------------------------------------------------


def test_load_json_file(tmp_path):
    good = tmp_path / "scan.json"
    good.write_text(json.dumps(SCAN), encoding="utf-8")
    assert load_json_file(good)["score"] == 35
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert load_json_file(bad) is None
    assert load_json_file(tmp_path / "missing.json") is None
    listed = tmp_path / "list.json"
    listed.write_text("[]", encoding="utf-8")
    assert load_json_file(listed) is None


def test_serve_refuses_root(monkeypatch, capsys):
    monkeypatch.setattr("os.geteuid", lambda: 0)
    assert main(["serve"]) == 2
    assert "ca root" in capsys.readouterr().err
