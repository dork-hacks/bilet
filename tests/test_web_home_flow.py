"""The first fixing task precedes optional exploration, including without JavaScript."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tool.content.ui import UI
from tool.engine import analyze_file
from tool.web.app import create_app
from tool.web.history_view import scan_time_label

FIXTURE = Path(__file__).parent / "fixtures/validation/V2_smart_home.xml"


@pytest.mark.parametrize("lang", ["en", "ro"])
def test_home_gives_saved_context_then_score_then_fixing_steps(lang):
    result = analyze_file(FIXTURE, salt=b"flow-test").to_dict()
    client = TestClient(create_app(lambda: result), base_url="http://127.0.0.1")
    html = client.get("/", params={"lang": lang}).text
    positions = [
        html.index(token)
        for token in (
            'class="scan-context"',
            'class="score ',
            'class="first"',
            'id="network-map"',  # PR 3 of #273: the map shares the first screen
            'id="fixing-steps"',
            'class="ask chat"',
        )
    ]
    assert positions == sorted(positions)
    assert UI["scan_snapshot"][lang] in html
    assert (
        f'<time datetime="{result["scan_start"]}">'
        f'{scan_time_label(result["scan_start"], lang)}</time>'
    ) in html
    assert " UTC</time>" in html
    assert '<a class="button secondary" href="#fixing-steps">' in html
    # The first finding opens to its actual steps. Other findings stay discoverable.
    findings = html.split('<div class="finding ')[1:]
    assert "<details open>" in findings[0]
    assert all("<details open>" not in finding for finding in findings[1:])
    assert html.count('class="finding ') == len(result["findings"])


@pytest.mark.parametrize("start", [None, 123, '<img src=x onerror="alert(1)">'])
def test_scan_time_never_invents_current_time_or_interprets_input(start):
    result = analyze_file(FIXTURE, salt=b"flow-test").to_dict()
    result["scan_start"] = start
    client = TestClient(create_app(lambda: result), base_url="http://127.0.0.1")
    html = client.get("/?lang=en").text
    if isinstance(start, str):
        assert "<img src=x" not in html
        assert "&lt;img" in html
        assert UI["history_no_time"]["en"] in html
    else:
        assert UI["history_no_time"]["en"] in html
        assert "<time>" not in html


@pytest.mark.parametrize("lang", ["en", "ro"])
def test_the_map_is_the_hero_next_to_the_answer_not_hidden(lang):
    # #273 PR 3: the map is open beside the answer, and the answer comes first in the page.
    result = analyze_file(FIXTURE, salt=b"flow-test").to_dict()
    html = (
        TestClient(create_app(lambda: result), base_url="http://127.0.0.1")
        .get("/", params={"lang": lang})
        .text
    )
    hero = html[html.index('<div class="hero has-map">') : html.index('class="support-links"')]
    assert hero.index('class="first"') < hero.index('id="network-map"')
    before_map = html[: html.index('id="network-map"')]
    assert before_map.rfind("<details") <= before_map.rfind("</details>")  # not inside one
