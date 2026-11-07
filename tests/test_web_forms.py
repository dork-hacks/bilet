"""Malformed browser forms fail before AI calls or history deletion."""

from pathlib import Path
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from tool.ai.explain import Explainer
from tool.engine import analyze_file
from tool.history import History
from tool.web import app as web_app


@pytest.mark.parametrize("path", ["/ask", "/history/delete"])
def test_excess_form_fields_are_refused_without_side_effects(tmp_path, path):
    history = History(tmp_path)
    fixture = Path(__file__).parent / "fixtures/validation/V6a_before.xml"
    result = analyze_file(fixture, salt=b"test").to_dict()
    history.add(result)
    provider = Mock(name="offline")
    browser = TestClient(
        web_app.create_app(lambda: result, history=history, explainer=Explainer(provider)),
        base_url="http://127.0.0.1",
    )
    original = history.path.read_bytes()
    payload = "lang=en&ai=1&q=Help&confirm=yes&" + "&".join(f"x{i}=a" for i in range(7))
    response = browser.post(
        path,
        content=payload,
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 400
    assert response.text == "Invalid form"
    provider.complete.assert_not_called()
    assert history.path.read_bytes() == original
    assert browser.get("/history").status_code == 200


@pytest.mark.parametrize("path", ["/ask", "/history/delete"])
@pytest.mark.parametrize(
    "headers", [{"origin": "http://other.example"}, {"sec-fetch-site": "cross-site"}]
)
def test_cross_site_requests_are_refused_before_reading_the_form(path, headers, monkeypatch):
    read_form = Mock(side_effect=AssertionError("untrusted form must not be read"))
    monkeypatch.setattr(web_app, "read_form", read_form)
    browser = TestClient(web_app.create_app(lambda: None), base_url="http://127.0.0.1")
    assert browser.post(path, content="broken", headers=headers).status_code == 403
    read_form.assert_not_called()
