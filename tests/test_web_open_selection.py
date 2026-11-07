"""An opened file stays selected across controls, independently of stored history."""

import re
from html import unescape
from pathlib import Path
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from tool.ai.explain import Explainer
from tool.ai.provider import ProviderUnavailable
from tool.engine.result import analyze_file
from tool.history import History
from tool.web.app import create_app

FIXTURES = Path(__file__).parent / "fixtures/validation"


@pytest.mark.parametrize("filename", ["V6b_after.xml", "V7_broken.xml"])
def test_opened_selection_survives_language_and_ai_controls(tmp_path, filename):
    history = History(tmp_path / "history")
    history.add(analyze_file(FIXTURES / "V6a_before.xml", salt=b"test").to_dict())
    provider = Mock(name="offline", complete=Mock(side_effect=ProviderUnavailable("offline")))
    client = TestClient(
        create_app(lambda: None, history=history, explainer=Explainer(provider)),
        base_url="http://127.0.0.1",
    )
    html = client.post(
        "/open",
        data={"lang": "en"},
        files={"file": ("opened.xml", (FIXTURES / filename).read_bytes(), "text/xml")},
    ).text
    link = unescape(re.search(r'href="(/\?lang=ro&amp;ai=0&amp;scan=[^"]+)"', html)[1])
    token = link.split("scan=")[1]
    for lang, ai in [("ro", "0"), ("en", "1"), ("en", "0")]:
        response = client.get("/", params={"lang": lang, "ai": ai, "scan": token})
        assert response.status_code == 200
        assert '<html lang="' + lang + '">' in response.text
        assert "opened.xml" in response.text
        assert "V6a_before.xml" not in response.text
        assert "scan=" + token in response.text
        assert response.headers["cache-control"] == "no-store"
        if filename != "V7_broken.xml":
            next_ai = "0" if ai == "1" else "1"
            assert f'href="/?lang={lang}&amp;ai={next_ai}&amp;scan={token}"' in response.text
    # Returning to history is deliberate and does not retain the selection token.
    assert 'href="/?lang=en&amp;ai=0"' in client.get(link.replace("lang=ro", "lang=en")).text
    assert "V6a_before.xml" in client.get("/?lang=en").text


def test_missing_or_evicted_opened_selection_never_falls_back_to_current_scan():
    current = analyze_file(FIXTURES / "V6a_before.xml", salt=b"test").to_dict()
    client = TestClient(create_app(lambda: current), base_url="http://127.0.0.1")

    def open_file():
        html = client.post(
            "/open",
            data={"lang": "en"},
            files={"file": ("opened.xml", (FIXTURES / "V6b_after.xml").read_bytes())},
        ).text
        return unescape(re.search(r'href="(/\?lang=en&amp;ai=0&amp;scan=[^"]+)"', html)[1])

    first = open_file()
    for _ in range(16):
        open_file()
    for url in (first, "/?lang=en&scan=unknown"):
        html = client.get(url).text
        assert "There is no check yet" in html
        assert "V6a_before.xml" not in html
