"""Offline report selection, bounded content, privacy and rendering regressions."""

import copy
import json
import re
from pathlib import Path
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient
from markupsafe import escape

from tool.content import finding_text
from tool.content.ui import UI
from tool.engine.result import analyze_file
from tool.history import History
from tool.web.app import create_app
from tool.web.report import MAX_DEVICES, MAX_FINDINGS, report_view

FIXTURES = Path(__file__).parent / "fixtures"
SCAN = json.loads((FIXTURES / "contract/example_scan.json").read_text())


@pytest.mark.parametrize("lang", ["ro", "en"])
def test_report_priorities_counts_language_and_no_ai(lang):
    explainer = Mock()
    client = TestClient(create_app(lambda: SCAN, explainer=explainer))
    response = client.get(f"/report?lang={lang}&ai=1")
    html = response.text
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert f'<html lang="{lang}">' in html
    assert '<span class="number">35</span>' in html
    assert html.count("<article>") == MAX_FINDINGS
    assert html.index(finding_text("CAMERA_STREAM_EXPOSED", lang).title) < html.index(
        finding_text("HTTP_ADMIN_CLEARTEXT", lang).title
    )
    assert (
        str(
            escape(
                UI["report_omissions"][lang].replace("{devices}", "1").replace("{findings}", "3")
            )
        )
        in html
    )
    assert not explainer.mock_calls
    assert "<script" not in html and 'src="http' not in html
    assert "@page { size: A4" in html and "@media print" in html
    assert "font: 16px/" in html
    assert 'onclick="window.print()"' in html
    assert f"/report?lang={lang}" in client.get(f"/?lang={lang}").text


def test_only_whitelisted_fields_reach_html_and_projection_does_not_mutate():
    scan = copy.deepcopy(SCAN)
    scan["file"] = "/private/secret.xml"
    scan["metadata"] = "hidden-secret"
    for device in scan["devices"]:
        device["hostname"] = "private-host"
        device["mac"] = "AA:BB:CC:DD:EE:FF"
        device["mac_masked"] = "AA:BB:CC:DD:EE:FF"
    scan["devices"][1]["mac_masked"] = "B8:27:EB:xx:xx:xx"
    before = copy.deepcopy(scan)
    html = TestClient(create_app(lambda: scan)).get("/report?lang=en").text
    assert "B8:27:EB:xx:xx:xx" in html
    for secret in [
        "/private/",
        "hidden-secret",
        "private-host",
        "AA:BB:CC:DD:EE:FF",
        "Hikvision",
        "Router Login",
        "device_key",
        "match_key",
        "evidence",
    ]:
        assert secret not in html
    for device in scan["devices"]:
        assert device["device_key"] not in html
    assert scan == before


def test_jinja_escapes_untrusted_display_values():
    scan = copy.deepcopy(SCAN)
    scan["findings"][3]["ip"] = '<img src=x onerror="x">'
    html = TestClient(create_app(lambda: scan)).get("/report").text
    assert "<img src=x" not in html
    assert "&lt;img src=x" in html


@pytest.mark.parametrize(
    "result, message",
    [
        (None, "There is no check yet"),
        ({"status": "error", "error": {"code": "NOT_XML"}}, "We could not read this check"),
        ({"status": "ok", "devices": None}, "We could not read this check"),
    ],
)
def test_empty_error_and_malformed_results_are_graceful(result, message):
    response = TestClient(create_app(lambda: result)).get("/report?lang=en")
    assert response.status_code == 200
    assert message in response.text


def test_empty_readable_scan_and_language_fallback():
    scan = {"status": "ok", "score": 100, "devices": [], "findings": []}
    client = TestClient(create_app(lambda: scan))
    assert "We found no problems" in client.get("/report?lang=en").text
    assert '<html lang="ro">' in client.get("/report?lang=xx").text


def test_large_report_is_bounded_and_ties_keep_contract_order():
    scan = copy.deepcopy(SCAN)
    scan["devices"] *= 100
    scan["findings"] *= 100
    view = report_view(scan, "en")
    assert len(view["devices"]) == MAX_DEVICES
    assert len(view["findings"]) == MAX_FINDINGS
    assert view["omitted_devices"] == 400 - MAX_DEVICES
    assert view["omitted_findings"] == 600 - MAX_FINDINGS
    assert view["findings"] == report_view(scan, "en")["findings"]
    ties = copy.deepcopy(SCAN)
    for finding in ties["findings"]:
        finding["points"] = 10
    assert (
        report_view(ties, "en")["findings"][0]["title"]
        == finding_text(ties["findings"][0]["code"], "en").title
    )


def test_loaded_result_wins_and_latest_history_refreshes(tmp_path):
    history = History(tmp_path / "history")
    before = analyze_file(FIXTURES / "validation/V6a_before.xml", salt=b"test").to_dict()
    after = analyze_file(FIXTURES / "validation/V6b_after.xml", salt=b"test").to_dict()
    client = TestClient(create_app(lambda: None, history=history))
    history.add(before)
    assert f'>{before["score"]}</span>' in client.get("/report").text
    history.add(after)
    assert f'>{after["score"]}</span>' in client.get("/report").text
    loaded = TestClient(create_app(lambda: SCAN, history=history))
    assert ">35</span>" in loaded.get("/report").text


def test_opened_scan_report_stays_selected_and_tokens_expire():
    client = TestClient(create_app(lambda: SCAN))
    data = (FIXTURES / "validation/V6b_after.xml").read_bytes()

    def open_report_link():
        html = client.post(
            "/open", data={"lang": "en"}, files={"file": ("opened.xml", data, "text/xml")}
        ).text
        return re.search(r'href="(/report\?lang=en&amp;scan=[^"]+)"', html)[1].replace("&amp;", "&")

    link = open_report_link()
    expected = analyze_file(FIXTURES / "validation/V6b_after.xml", salt=b"test").score
    html = client.get(link).text
    assert f">{expected}</span>" in html
    assert ">35</span>" not in html
    token = link.split("scan=")[1]
    assert f"/report?lang=ro&amp;scan={token}" in html
    assert '<html lang="ro">' in client.get(link.replace("lang=en", "lang=ro")).text
    for _ in range(16):
        open_report_link()
    assert "There is no check yet" in client.get(link).text
    assert "There is no check yet" in client.get("/report?lang=en&scan=unknown").text


@pytest.mark.parametrize(
    "lang,counts", [("en", "1 device · 1 finding"), ("ro", "1 dispozitiv · 1 constatare")]
)
def test_one_finding_report_uses_singular_and_has_no_omissions(lang, counts):
    scan = analyze_file(FIXTURES / "validation/V1_home_basic.xml", salt=b"test").to_dict()
    # One actionable device/finding, with all matching IDs retained.
    finding = scan["findings"][0]
    device = next(d for d in scan["devices"] if finding["id"] in d["finding_ids"])
    scan["devices"] = [device]
    html = TestClient(create_app(lambda: scan)).get(f"/report?lang={lang}").text
    assert counts in html
    assert UI["report_omissions"][lang].split(":")[0] + ":" not in html
    assert f'{finding["port"]}/{finding["protocol"]}' in html
    assert finding["code"] in html
    assert UI["report_action"][lang].replace("{n}", "1") in html


def test_zero_point_device_is_not_a_report_priority():
    scan = analyze_file(FIXTURES / "validation/V6b_after.xml", salt=b"test").to_dict()
    view = report_view(scan, "en")
    assert view["devices"] == []
    assert view["findings"] == []
    assert view["omitted_devices"] == 0
    assert view["omitted_findings"] == 0
