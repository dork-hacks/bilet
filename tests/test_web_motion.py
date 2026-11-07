"""Gentle motion (#162 part 2): decoration only, and off for prefers-reduced-motion."""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tool.engine import analyze_file
from tool.history import History
from tool.web.app import create_app

VALIDATION = Path(__file__).parent / "fixtures" / "validation"
SALT = b"test-salt"
STYLE = (
    Path(__file__).parent.parent / "src" / "tool" / "web" / "templates" / "_style.html"
).read_text()


def scan(name: str) -> dict:
    return analyze_file(VALIDATION / name, salt=SALT).to_dict()


GUARD = "@media (prefers-reduced-motion: no-preference)"


def outside_reduced_motion_guard(css: str) -> str:
    """The stylesheet with every prefers-reduced-motion: no-preference block cut out.
    There can be more than one (the page motion from #169, the chat's from #172)."""
    assert GUARD in css
    while GUARD in css:
        start = css.index(GUARD)
        depth, i = 0, css.index("{", start)
        while True:
            depth += {"{": 1, "}": -1}.get(css[i], 0)
            if depth == 0:
                css = css[:start] + css[i + 1 :]
                break
            i += 1
    return css


def test_every_animation_and_transition_sits_behind_the_reduced_motion_guard():
    rest = outside_reduced_motion_guard(STYLE)
    for word in ("animation", "transition", "@keyframes", "transform"):
        assert word not in rest, word


@pytest.mark.parametrize("lang", ["en", "ro"])
def test_the_real_score_stays_visible_and_accessible_without_a_count_up(lang):
    client = TestClient(create_app(lambda: scan("V6a_before.xml")))
    html = client.get("/", params={"lang": lang}).text
    score = scan("V6a_before.xml")["score"]
    assert f'<span class="number">{score}</span>' in html
    # The numeric score remains ordinary accessible text throughout page load.
    # Motion is CSS-only: no script may touch the score (the chat from #172 has a
    # script, but it never reads or rewrites the score).
    for script in re.findall(r"<script\b[^>]*>(.*?)</script>", html, re.DOTALL):
        assert "score" not in script.lower() and ".number" not in script, script[:80]
    assert f'<span class="number" aria-hidden="true">{score}</span>' not in html


@pytest.mark.parametrize("lang", ["en", "ro"])
def test_resolved_findings_get_a_hidden_check_mark(tmp_path, lang):
    history = History(tmp_path / "data")
    history.add(scan("V6a_before.xml"))
    history.add(scan("V6b_after.xml"))
    client = TestClient(create_app(lambda: None, history=history))
    html = client.get("/history", params={"lang": lang}).text
    marks = html.count('<span class="done-mark" aria-hidden="true">✓</span>')
    assert marks == 3  # the brief's V6a -> V6b pair fixes three problems
