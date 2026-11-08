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


def outside_reduced_motion_guard(css: str) -> str:
    """The stylesheet with the prefers-reduced-motion: no-preference block cut out."""
    start = css.find("@media (prefers-reduced-motion: no-preference)")
    if start == -1:
        return css
    depth, i = 0, css.index("{", start)
    while True:
        depth += {"{": 1, "}": -1}.get(css[i], 0)
        if depth == 0:
            return outside_reduced_motion_guard(css[:start] + css[i + 1 :])
        i += 1


def test_every_animation_and_transition_sits_behind_the_reduced_motion_guard():
    rest = outside_reduced_motion_guard(STYLE)
    # A map's will-change: transform is only a rendering hint, not motion.
    assert not re.search(r"(?:^|[;{])\s*(?:animation|transition|transform)\s*:", rest)
    assert "@keyframes" not in rest


@pytest.mark.parametrize("lang", ["en", "ro"])
def test_the_real_score_stays_visible_and_accessible_without_a_count_up(lang):
    client = TestClient(create_app(lambda: scan("V6a_before.xml")), base_url="http://127.0.0.1")
    html = client.get("/", params={"lang": lang}).text
    score = scan("V6a_before.xml")["score"]
    assert f'<span class="number">{score}</span>' in html
    # The numeric score remains ordinary accessible text throughout page load.
    # Motion is CSS-only: no script may replace it with zero/intermediate values.
    scripts = re.findall(r"<script\b[^>]*>(.*?)</script>", html, re.S)
    for script in scripts:
        assert not re.search(r"[\"']\.score\s+\.number[\"']", script)
    for script in (Path(__file__).parent.parent / "src/tool/web/static").glob("*.js"):
        assert not re.search(r"[\"']\.score\s+\.number[\"']", script.read_text())
    assert f'<span class="number" aria-hidden="true">{score}</span>' not in html


@pytest.mark.parametrize("lang", ["en", "ro"])
def test_resolved_findings_get_a_hidden_check_mark(tmp_path, lang):
    history = History(tmp_path / "data")
    history.add(scan("V6a_before.xml"))
    history.add(scan("V6b_after.xml"))
    client = TestClient(create_app(lambda: None, history=history), base_url="http://127.0.0.1")
    html = client.get("/history", params={"lang": lang}).text
    marks = html.count('<span class="done-mark" aria-hidden="true">✓</span>')
    assert marks == 3  # the brief's V6a -> V6b pair fixes three problems


def test_page_transitions_and_the_map_entrance_only_without_reduced_motion():
    # #273 PR 4: CSS only, so nothing moves for visitors who asked for less motion.
    css = STYLE
    rest = outside_reduced_motion_guard(css)
    assert "@view-transition { navigation: auto; }" in css
    assert "@view-transition" not in rest
    assert ".hero.has-map > .netmap { animation:" in css
    assert ".hero.has-map > .netmap" not in rest
