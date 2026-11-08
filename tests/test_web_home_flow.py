"""The first fixing task precedes optional exploration, including without JavaScript."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tool.content.ui import UI
from tool.engine import analyze_file
from tool.web.app import create_app

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
            'id="fixing-steps"',
            'id="network-map"',
            'class="ask chat"',
        )
    ]
    assert positions == sorted(positions)
    assert UI["scan_snapshot"][lang] in html
    assert f'<time>{result["scan_start"]}</time>' in html
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
    else:
        assert UI["history_no_time"]["en"] in html
        assert "<time>" not in html
