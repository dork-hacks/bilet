"""Browser scan controls use only an injected fake; these tests never launch a scan."""

from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from markupsafe import escape

from tool.content.texts import DETECT_ERRORS, FILE_ERRORS, REFUSALS, SCAN_MESSAGES
from tool.content.ui import UI
from tool.engine import analyze_file
from tool.history import History
from tool.web.app import MAX_FORM_BYTES, create_app


@dataclass(frozen=True)
class State:
    running: bool = False
    step: str | None = None
    percent: float | None = None
    seconds_left: int | None = None
    outcome: str | None = None
    scan_id: int | None = None


class FakeRunner:
    def __init__(self):
        self.current = State()
        self.starts = []
        self.cancels = 0

    def state(self):
        return self.current

    def start_scan(self, lang):
        if not self.current.running:
            self.starts.append(lang)
            self.current = State(running=True, step="DEVICES")
        return self.current

    def cancel(self):
        self.cancels += 1
        self.current = State(outcome="CANCELLED")
        return self.current


def client(runner=None, *, peer="127.0.0.1", host="127.0.0.1:8000", history=None):
    app = create_app(lambda: None, scan_runner=runner, history=history)

    async def with_peer(scope, receive, send):
        # Starlette's pinned TestClient has no client= option. Supply the ASGI peer
        # directly, without trusting any forwarded header in the application.
        if scope["type"] == "http":
            scope = {**scope, "client": (peer, 12345)}
        await app(scope, receive, send)

    return TestClient(with_peer, base_url="http://127.0.0.1:8000", headers={"host": host})


@pytest.mark.parametrize("lang", ["ro", "en"])
@pytest.mark.parametrize("path", ["/", "/history"])
def test_local_home_and_history_offer_a_translated_post_button(path, lang):
    html = client(FakeRunner()).get(path, params={"lang": lang}).text
    assert '<form method="post" action="/scan">' in html
    assert str(escape(UI["scan_check_again"][lang])) in html
    assert 'name="target"' not in html


@pytest.mark.parametrize("path", ["/", "/history"])
def test_no_runner_hides_controls_and_shows_honest_unavailable_state(path):
    browser = client()
    assert 'action="/scan"' not in browser.get(path).text
    assert UI["scan_unavailable"]["en"] in browser.get("/scan?lang=en").text
    assert browser.post("/scan", data={"lang": "en"}).status_code == 503


@pytest.mark.parametrize("peer", ["192.0.2.8", "not-an-ip"])
@pytest.mark.parametrize("path", ["/scan", "/scan/cancel", "/scan/status"])
def test_nonlocal_peer_cannot_read_or_act_even_with_forwarded_headers(peer, path):
    runner = FakeRunner()
    browser = client(runner, peer=peer)
    headers = {"x-forwarded-for": "127.0.0.1", "x-forwarded-host": "127.0.0.1"}
    response = (
        browser.get(path, headers=headers)
        if path == "/scan/status"
        else browser.post(path, headers=headers)
    )
    assert response.status_code == 403
    assert browser.get("/scan").status_code == 403
    assert 'action="/scan"' not in browser.get("/").text
    assert runner.starts == [] and runner.cancels == 0


@pytest.mark.parametrize(
    "host",
    [
        "evil.example",
        "localhost",
        "192.0.2.8",
        "127.0.0.1.evil.example",
        "evil.example@127.0.0.1",
        "127.0.0.1:bad",
        "127.0.0.1:65536",
        "127.0.0.1/path",
        "127.0.0.1?query",
        "127.0.0.1#fragment",
        "[broken",
    ],
)
def test_host_must_be_a_literal_loopback_address(host):
    runner = FakeRunner()
    browser = client(runner, host=host)
    assert browser.get("/scan").status_code == 403
    assert browser.get("/scan/status").status_code == 403
    assert browser.post("/scan").status_code == 403
    assert browser.post("/scan/cancel").status_code == 403
    assert runner.starts == [] and runner.cancels == 0


def test_ipv6_loopback_peer_and_host_are_allowed():
    runner = FakeRunner()
    browser = client(runner, peer="::1", host="[::1]:8000")
    response = browser.post("/scan", data={"lang": "en"}, follow_redirects=False)
    assert response.status_code == 303
    assert runner.starts == ["en"]


@pytest.mark.parametrize("path", ["/scan", "/scan/cancel"])
@pytest.mark.parametrize(
    "headers",
    [
        {"origin": "http://evil.example"},
        {"origin": "null"},
        {"sec-fetch-site": "cross-site"},
        {"sec-fetch-site": "same-site"},
    ],
)
def test_cross_site_posts_never_touch_the_runner(path, headers):
    runner = FakeRunner()
    assert client(runner).post(path, headers=headers).status_code == 403
    assert runner.starts == [] and runner.cancels == 0


def test_get_is_read_only_and_repeated_posts_reuse_the_running_scan():
    runner = FakeRunner()
    browser = client(runner)
    browser.get("/scan")
    browser.get("/scan/status")
    assert runner.starts == []
    for _ in range(2):
        response = browser.post(
            "/scan",
            data={"lang": "ro"},
            headers={"origin": "http://127.0.0.1:8000", "sec-fetch-site": "same-origin"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/scan?lang=ro"
    assert runner.starts == ["ro"]
    assert browser.get("/scan/status").json()["running"] is True
    assert browser.post("/scan/cancel", data={"lang": "en"}).status_code == 200
    assert runner.cancels == 1
    assert browser.get("/scan/status?lang=en").json()["message"] == UI["scan_cancelled"]["en"]


@pytest.mark.parametrize("path", ["/scan", "/scan/cancel"])
def test_scope_fields_and_large_or_malformed_forms_are_refused(path):
    runner = FakeRunner()
    browser = client(runner)
    assert browser.post(path, data={"target": "192.0.2.0/24"}).status_code == 400
    assert browser.post(path + "?target=192.0.2.0/24").status_code == 400
    assert browser.post(path, content="&".join(f"x{i}=a" for i in range(11))).status_code == 400
    assert browser.post(path, content="x" * (MAX_FORM_BYTES + 1)).status_code == 413
    assert runner.starts == [] and runner.cancels == 0


OUTCOMES = sorted(
    set(DETECT_ERRORS)
    | set(FILE_ERRORS)
    | set(REFUSALS)
    | (set(SCAN_MESSAGES) - {"START", "HOSTS_FOUND", "PROGRESS", "SELF_SKIPPED"})
    | {"AUTH_CANCELLED", "NO_AUTH_DIALOG", "CANCELLED", "HISTORY_FAILED", "UNEXPECTED"}
)


@pytest.mark.parametrize("outcome", OUTCOMES)
@pytest.mark.parametrize("lang", ["ro", "en"])
def test_all_runner_outcomes_have_safe_translated_messages(outcome, lang):
    runner = FakeRunner()
    runner.current = State(outcome=outcome)
    browser = client(runner)
    status = browser.get(f"/scan/status?lang={lang}")
    assert status.status_code == 200
    assert status.headers["cache-control"] == "no-store"
    payload = status.json()
    assert payload["message"] and "?" not in payload["message"]
    assert "{" not in payload["message"] and "Traceback" not in payload["message"]
    assert payload["running"] is False
    assert payload["done"] == (outcome == "DONE")
    assert str(escape(payload["message"])) in browser.get(f"/scan?lang={lang}").text


@pytest.mark.parametrize("percent", [None, 37.8])
@pytest.mark.parametrize("lang", ["ro", "en"])
def test_progress_with_or_without_percent_has_a_live_region_and_manual_refresh(percent, lang):
    runner = FakeRunner()
    runner.current = State(running=True, step="TCP", percent=percent, seconds_left=120)
    browser = client(runner)
    html = browser.get(f"/scan?lang={lang}").text
    assert 'role="status" aria-live="polite" aria-atomic="true"' in html
    assert 'http-equiv="refresh"' not in html
    assert 'id="scan-cancel" method="post"' in html
    assert str(escape(UI["scan_refresh"][lang])) in html
    message = browser.get(f"/scan/status?lang={lang}").json()["message"]
    assert ("37%" in message) == (percent is not None)


def test_completed_fake_scan_is_read_from_history_on_the_home_page(tmp_path):
    history = History(tmp_path / "data")
    runner = FakeRunner()
    browser = client(runner, history=history)
    assert browser.post("/scan", data={"lang": "en"}).status_code == 200
    fixture = Path(__file__).parent / "fixtures/validation/V6b_after.xml"
    result = analyze_file(fixture, salt=b"test-salt").to_dict()
    scan_id = history.add(result)
    runner.current = replace(runner.current, running=False, outcome="DONE", scan_id=scan_id)
    status = browser.get("/scan/status?lang=en").json()
    assert status["done"] is True
    html = browser.get(status["result_url"]).text
    assert f'<span class="number">{result["score"]}</span>' in html
    assert browser.get("/scan?lang=en").headers["cache-control"] == "no-store"
