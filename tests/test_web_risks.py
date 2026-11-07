"""The "every risk explained" page (#83): all 15 catalog codes with their RO/EN texts."""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from markupsafe import escape

from tool.content import LANGS, finding_text, severity_label
from tool.content.ui import UI
from tool.engine import analyze_file
from tool.engine.catalog import CATALOG
from tool.web.app import create_app
from tool.web.risks_view import risks_view

VALIDATION = Path(__file__).parent / "fixtures" / "validation"


def page(lang: str | None = None, load=lambda: None) -> str:
    client = TestClient(create_app(load))
    url = "/risks" if lang is None else f"/risks?lang={lang}"
    response = client.get(url)
    assert response.status_code == 200
    return response.text


def test_view_lists_every_catalog_code_once():
    view = risks_view("en")
    codes = [risk.code for risk in view.risks]
    assert len(CATALOG) == 15
    assert sorted(codes) == sorted(CATALOG)


def test_order_is_points_then_code_and_stable():
    codes = [risk.code for risk in risks_view("ro").risks]
    expected = sorted(CATALOG, key=lambda code: (-CATALOG[code].points, code))
    assert codes == expected
    assert codes[0] == "CAMERA_STREAM_EXPOSED"
    assert codes[-1] == "SSH_OPEN"
    assert [risk.code for risk in risks_view("en").risks] == codes


def test_view_texts_come_from_content():
    for risk in risks_view("en").risks:
        text = finding_text(risk.code, "en")
        assert not text.is_generic, risk.code
        assert risk.title == text.title
        assert risk.explanation == text.explanation
        assert risk.steps == text.steps
        assert risk.points == CATALOG[risk.code].points
        assert risk.severity_label == severity_label(CATALOG[risk.code].severity, "en")


@pytest.mark.parametrize("lang", LANGS)
def test_page_shows_every_code_in_both_languages(lang):
    html = page(lang)
    assert f'<html lang="{lang}">' in html
    for code in CATALOG:
        text = finding_text(code, lang)
        assert f'id="{code}"' in html, code
        assert str(escape(text.title)) in html, code
        assert str(escape(text.explanation)) in html, code
        for step in text.steps:
            assert str(escape(step)) in html, (code, step)
    assert str(escape(UI["risks_title"][lang])) in html


def test_page_shows_standards_references():
    html = page("en")
    assert "CIS Controls v8:" in html
    assert "OWASP IoT Top 10:" in html


def test_anchors_appear_in_the_page_order():
    html = page("en")
    anchors = re.findall(r'<section class="finding sev-\w+" id="([A-Z_]+)"', html)
    assert anchors == [risk.code for risk in risks_view("en").risks]


@pytest.mark.parametrize("bad", ["xx", "", "<script>", "EN"])
def test_unknown_lang_falls_back_to_default(bad):
    html = page(bad)
    assert '<html lang="ro">' in html
    assert "<script>" not in html  # the value is never echoed into the page


def test_no_lang_uses_default_and_needs_no_scan():
    calls = []

    def load():
        calls.append(1)
        return None

    html = page(None, load)
    assert '<html lang="ro">' in html
    assert calls == []  # the page never reads a scan


def test_page_links_home_and_language_switch_stays_here():
    html = page("en")
    assert 'href="/?lang=en"' in html
    assert 'href="/risks?lang=ro"' in html
    assert 'href="/risks?lang=en"' in html


def test_home_links_to_risks_and_each_finding_links_to_its_entry():
    result = analyze_file(VALIDATION / "V2_smart_home.xml", salt=b"test-salt").to_dict()
    client = TestClient(create_app(lambda: result))
    html = client.get("/?lang=en").text
    assert 'href="/risks?lang=en"' in html
    codes = {finding["code"] for finding in result["findings"]}
    assert codes
    for code in codes:
        assert f'href="/risks?lang=en#{code}"' in html, code


def test_history_links_to_risks():
    client = TestClient(create_app(lambda: None))
    assert 'href="/risks?lang=en"' in client.get("/history?lang=en").text
