"""'Open a scan file' on the home screen (#92): live checks 2 and 5 in the browser."""

import csv
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from markupsafe import escape  # what Jinja's autoescape writes (&#39;, not &#x27;)

from tool.content import file_error_message
from tool.content.ui import UI
from tool.history import History
from tool.web import app as web_app
from tool.web.app import MAX_UPLOAD_BYTES, create_app, safe_name

FIXTURES = Path(__file__).parent / "fixtures"
VALIDATION = FIXTURES / "validation"
TRAPS = FIXTURES / "traps"


def expected_scores(folder: Path) -> dict[str, str]:
    with (folder / "expected_scores.csv").open(newline="", encoding="utf-8") as fh:
        return {row["file"]: row["network_score"] for row in csv.DictReader(fh)}


@pytest.fixture
def history(tmp_path):
    return History(tmp_path / "data")


@pytest.fixture
def client(history):
    return TestClient(create_app(lambda: None, history=history))


def open_file(client, name: str, data: bytes, lang: str = "en", **headers):
    return client.post(
        f"/open?lang={lang}",
        data={"lang": lang, "ai": "0"},
        files={"file": (name, data, "text/xml")},
        headers=headers,
    )


def score_in(html: str) -> str:
    start = html.index('<span class="number">') + len('<span class="number">')
    return html[start : html.index("</span>", start)]


@pytest.mark.parametrize("name", sorted(expected_scores(VALIDATION)))
def test_score_matches_the_csv_for_every_validation_file(client, name):
    expected = expected_scores(VALIDATION)[name]
    res = open_file(client, name, (VALIDATION / name).read_bytes())
    assert res.status_code == 200
    if expected == "ERROR":
        assert escape(UI["error_heading"]["en"]) in res.text
    else:
        assert score_in(res.text) == expected


@pytest.mark.parametrize(
    "name, code",
    [
        ("T09_empty.xml", "EMPTY_FILE"),
        ("T11_truncated.xml", "NOT_XML"),
        ("T10_not_nmap.xml", "NOT_NMAP"),
        ("T07_xxe_external_entity.xml", "UNSAFE_XML"),
        ("T08_entity_expansion.xml", "UNSAFE_XML"),
    ],
)
@pytest.mark.parametrize("lang", ["ro", "en"])
def test_broken_files_show_a_plain_message_never_a_500(client, name, code, lang):
    data = (TRAPS / name).read_bytes()
    res = open_file(client, name, data, lang=lang)
    assert res.status_code == 200
    assert str(escape(UI["error_heading"][lang])) in res.text
    assert str(escape(file_error_message(code, lang))) in res.text
    assert "Traceback" not in res.text


def test_too_large_is_refused_before_reading_it_all(client):
    res = client.post(
        "/open?lang=ro",
        content=b"x" * (MAX_UPLOAD_BYTES + 1),
        headers={"content-type": "multipart/form-data; boundary=b"},
    )
    assert res.status_code == 413
    assert str(escape(file_error_message("TOO_LARGE", "ro"))) in res.text


def test_too_large_body_without_content_length_is_cut_off(client, monkeypatch):
    monkeypatch.setattr(web_app, "MAX_UPLOAD_BYTES", 1000)

    def chunks():
        for _ in range(100):
            yield b"y" * 100

    res = client.post(
        "/open?lang=en",
        content=chunks(),
        headers={"content-type": "multipart/form-data; boundary=b"},
    )
    assert res.status_code == 413


def test_not_a_multipart_form_is_a_400_with_the_error_page(client):
    res = client.post("/open?lang=en", content=b"hello", headers={"content-type": "text/plain"})
    assert res.status_code == 400
    assert str(escape(UI["error_heading"]["en"])) in res.text


def test_a_form_without_a_file_is_a_400(client):
    res = client.post("/open?lang=en", data={"lang": "en"}, files={"other": ("a", b"x")})
    assert res.status_code == 400
    assert str(escape(file_error_message("EMPTY_FILE", "en"))) in res.text


def test_cross_site_post_is_refused(client):
    data = (VALIDATION / "V1_home_basic.xml").read_bytes()
    res = open_file(client, "V1_home_basic.xml", data, origin="http://evil.example")
    assert res.status_code == 403


def test_opening_a_file_never_adds_it_to_the_history(client, history):
    data = (VALIDATION / "V1_home_basic.xml").read_bytes()
    assert open_file(client, "V1_home_basic.xml", data).status_code == 200
    assert history.scans() == []


def test_the_temp_file_is_deleted_after_analysis(client, monkeypatch):
    made = []
    real = tempfile.TemporaryDirectory

    def tracking(*args, **kwargs):
        folder = real(*args, **kwargs)
        made.append(Path(folder.name))
        return folder

    monkeypatch.setattr(web_app.tempfile, "TemporaryDirectory", tracking)
    data = (VALIDATION / "V1_home_basic.xml").read_bytes()
    assert open_file(client, "V1_home_basic.xml", data).status_code == 200
    assert len(made) == 1
    assert not made[0].exists()


def test_the_page_says_it_shows_the_opened_file_and_links_back(client):
    res = open_file(client, "V2_smart_home.xml", (VALIDATION / "V2_smart_home.xml").read_bytes())
    assert str(escape(UI["open_showing"]["en"])) in res.text
    assert str(escape(UI["open_back"]["en"])) in res.text
    assert "V2_smart_home.xml" in res.text


def test_romanian_is_kept_from_the_form(client):
    data = (VALIDATION / "V1_home_basic.xml").read_bytes()
    res = open_file(client, "V1_home_basic.xml", data, "ro")
    assert '<html lang="ro">' in res.text
    assert str(escape(UI["open_showing"]["ro"])) in res.text


@pytest.mark.parametrize(
    "name, expected",
    [
        ("V1_home_basic.xml", "V1_home_basic.xml"),
        ("../../etc/passwd", "passwd"),
        ("C:\\Users\\x\\scan 1.xml", "scan_1.xml"),
        ("..", "scan.xml"),
        ("", "scan.xml"),
        (".hidden.xml", "hidden.xml"),
        # "/" is a path separator, so only "script>.xml" is left.
        ("<script>alert(1)</script>.xml", "script_.xml"),
        ("a" * 300, "a" * 100),
    ],
)
def test_safe_name(name, expected):
    assert safe_name(name) == expected


def test_hostile_file_name_is_escaped_in_the_page(client):
    data = (VALIDATION / "V1_home_basic.xml").read_bytes()
    res = open_file(client, '"><img src=x onerror=alert(1)>.xml', data)
    assert res.status_code == 200
    assert "<img src=x" not in res.text


def test_home_screen_has_a_labelled_keyboard_usable_form(client):
    html = client.get("/", params={"lang": "en"}).text
    assert 'action="/open?lang=en"' in html
    assert 'enctype="multipart/form-data"' in html
    assert '<label for="open-file">' in html
    assert 'id="open-file"' in html
    assert str(escape(UI["open_hint"]["en"])) in html
