"""Damaged saved results stay local and show a read error, never a partial score."""

import copy
import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from markupsafe import escape

from tool.content.ui import UI
from tool.engine import analyze_file
from tool.history import History
from tool.web.app import create_app, load_json_file

FIXTURE = Path(__file__).parent / "fixtures/validation/V6a_before.xml"


def damaged_result(case):
    result = analyze_file(FIXTURE, salt=b"saved-result-test").to_dict()
    if case == "score-text":
        result["score"] = "damaged"
    elif case == "score-missing":
        del result["score"]
    elif case == "score-boolean":
        result["score"] = True
    elif case == "score-range":
        result["score"] = 101
    elif case == "devices-null":
        result["devices"] = None
    elif case == "findings-null":
        result["findings"] = None
    elif case == "device-not-mapping":
        result["devices"][0] = []
    elif case == "device-ip-null":
        result["devices"][0]["ip"] = None
    elif case == "finding-missing-id":
        del result["findings"][0]["id"]
    elif case == "finding-points-text":
        result["findings"][0]["points"] = "damaged"
    elif case == "error-not-mapping":
        result.update(status="error", error=["damaged"])
    return result


@pytest.mark.parametrize("lang", ["ro", "en"])
@pytest.mark.parametrize("source", ["json", "history"])
@pytest.mark.parametrize(
    "case",
    [
        "score-text",
        "score-missing",
        "score-boolean",
        "score-range",
        "devices-null",
        "findings-null",
        "device-not-mapping",
        "device-ip-null",
        "finding-missing-id",
        "finding-points-text",
        "error-not-mapping",
    ],
)
def test_saved_result_errors_are_readable_without_rewriting_data(tmp_path, lang, source, case):
    result = damaged_result(case)
    original = copy.deepcopy(result)
    if source == "json":
        path = tmp_path / "saved.json"
        path.write_text(json.dumps(result), encoding="utf-8")
        app = create_app(lambda: load_json_file(path))
    else:
        history = History(tmp_path)
        scan_id = history.add(analyze_file(FIXTURE, salt=b"saved-result-test").to_dict())
        with sqlite3.connect(history.path) as db:
            db.execute(
                "UPDATE scans SET result_json = ? WHERE id = ?", (json.dumps(result), scan_id)
            )
        path = history.path
        app = create_app(lambda: None, history=history)
    contents = path.read_bytes()
    browser = TestClient(app, base_url="http://127.0.0.1")
    responses = [
        browser.get("/", params={"lang": lang}),
        browser.post("/ask", data={"lang": lang, "q": "What should I fix?"}),
        browser.get("/report", params={"lang": lang}),
    ]
    for response in responses:
        assert response.status_code == 200
        assert str(escape(UI["error_heading"][lang])) in response.text
        assert '<span class="number">' not in response.text
        assert 'id="netmap-data"' not in response.text
        assert "Traceback" not in response.text
    assert browser.get("/map.json").json() is None
    assert path.read_bytes() == contents
    assert result == original
