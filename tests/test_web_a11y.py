"""Accessibility checks for every page (#99, MASTERPLAN §6.5).

Text of at least 16 px, WCAG AA contrast, keyboard navigation (labels, no positive
tabindex) and one page heading. Colour is never the only signal: that part is covered by
the per-feature tests (the band label and severity are always written as text).
"""

import re
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tool.content import LANGS
from tool.engine import analyze_file
from tool.history import History
from tool.web.app import create_app

STYLE = Path(__file__).parents[1] / "src" / "tool" / "web" / "templates" / "_style.html"
VALIDATION = Path(__file__).parent / "fixtures" / "validation"
SALT = b"test-salt"
ROOT_PX = 18
MIN_PX = 16
AA_TEXT = 4.5
WHITE = "#ffffff"


def css() -> str:
    text = STYLE.read_text(encoding="utf-8")
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def luminance(hex_colour: str) -> float:
    h = hex_colour.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    channels = [int(h[i : i + 2], 16) / 255 for i in (0, 2, 4)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def contrast(a: str, b: str) -> float:
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def full_hex(colour: str) -> str:
    colour = colour.lower()
    return colour if len(colour) == 7 else "#" + "".join(c * 2 for c in colour[1:])


def colours(prop: str) -> set[str]:
    pattern = rf"(?<![-\w]){prop}\s*:\s*(#[0-9a-fA-F]{{3,6}})\b"
    return {full_hex(m) for m in re.findall(pattern, css())}


def test_contrast_ratio_matches_known_values():
    assert contrast("#000000", "#ffffff") == pytest.approx(21.0)
    assert contrast("#777777", "#ffffff") == pytest.approx(4.48, abs=0.01)


def test_every_text_colour_passes_aa_on_every_background():
    """A superset of the real pairs: any text colour may end up on any background.

    Light backgrounds carry dark text, and dark backgrounds (tags, chips, score icons)
    carry white text. Checking every combination means a new rule can't pair them badly.
    """
    text = colours("color") | colours("fill")
    backgrounds = colours("background") | colours("background-color") | {WHITE}
    light = {b for b in backgrounds if luminance(b) > 0.5}
    dark = backgrounds - light
    dark_text = {t for t in text if t != WHITE}
    assert dark_text and light and dark, "the colour parser found nothing"
    failures = [
        f"{t} on {b}: {contrast(t, b):.2f}"
        for pairs in ((dark_text, light), ({WHITE}, dark))
        for t in pairs[0]
        for b in pairs[1]
        if contrast(t, b) < AA_TEXT
    ]
    assert not failures, failures


def test_no_text_smaller_than_16px():
    sizes = re.findall(r"font-size\s*:\s*([\d.]+)\s*([a-z%]+)", css())
    assert sizes, "the font-size parser found nothing"
    for value, unit in sizes:
        # em and % compound with the parent, so only rem and px are allowed here.
        assert unit in ("rem", "px"), f"font-size in {unit}: use rem or px"
        px = float(value) * (ROOT_PX if unit == "rem" else 1)
        assert px >= MIN_PX, f"font-size {value}{unit} is {px:.1f}px"


def test_root_font_size_is_the_one_the_test_assumes():
    assert re.search(rf":root\s*\{{[^}}]*font-size:\s*{ROOT_PX}px", css())


class PageAudit(HTMLParser):
    """Collects what the structure checks need from one rendered page."""

    def __init__(self):
        super().__init__()
        self.lang = None
        self.h1 = 0
        self.label_for: set[str] = set()
        self.label_depth = 0
        self.controls: list[dict] = []
        self.bad_tabindex: list[str] = []
        self.unlabelled_svgs = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "html":
            self.lang = a.get("lang")
        if tag == "h1":
            self.h1 += 1
        if tag == "label":
            self.label_depth += 1
            if a.get("for"):
                self.label_for.add(a["for"])
        if "tabindex" in a and int(a["tabindex"] or 0) > 0:
            self.bad_tabindex.append(tag)
        if tag in ("input", "select", "textarea"):
            kind = (a.get("type") or "text").lower()
            if kind not in ("hidden", "submit", "button", "reset"):
                self.controls.append({**a, "_tag": tag, "_wrapped": self.label_depth > 0})
        if tag == "svg" and not (a.get("aria-label") or a.get("aria-labelledby")):
            if a.get("aria-hidden") != "true":
                self.unlabelled_svgs += 1

    def handle_endtag(self, tag):
        if tag == "label" and self.label_depth:
            self.label_depth -= 1

    def unlabelled(self) -> list[str]:
        return [
            f"<{c['_tag']} name={c.get('name')!r}>"
            for c in self.controls
            if not (
                c["_wrapped"]
                or c.get("aria-label")
                or c.get("aria-labelledby")
                or (c.get("id") and c["id"] in self.label_for)
            )
        ]


def audit(html: str) -> PageAudit:
    page = PageAudit()
    page.feed(html)
    page.close()
    return page


def scan(name: str) -> dict:
    return analyze_file(VALIDATION / name, salt=SALT).to_dict()


@pytest.fixture
def client(tmp_path):
    history = History(tmp_path / "data")
    history.add(scan("V6a_before.xml"))
    history.add(scan("V6b_after.xml"))
    return TestClient(create_app(lambda: None, history=history))


def upload(client, lang: str, name: str, data: bytes):
    form = {"lang": lang, "ai": "0"}
    return client.post(f"/open?lang={lang}", data=form, files={"file": (name, data)})


def pages(client, lang):
    good = (VALIDATION / "V6a_before.xml").read_bytes()
    yield "home", client.get(f"/?lang={lang}")
    yield "risks", client.get(f"/risks?lang={lang}")
    yield "history", client.get(f"/history?lang={lang}")
    yield "open", upload(client, lang, "V6a_before.xml", good)
    yield "open-error", upload(client, lang, "empty.xml", b"")


@pytest.mark.parametrize("lang", LANGS)
def test_every_page_is_keyboard_and_screen_reader_friendly(client, lang):
    controls = 0
    for name, res in pages(client, lang):
        assert res.status_code == 200, name
        page = audit(res.text)
        controls += len(page.controls)
        assert page.lang == lang, f"{name}: <html lang={page.lang!r}>"
        assert page.h1 == 1, f"{name}: {page.h1} <h1> elements"
        assert not page.unlabelled(), f"{name}: {page.unlabelled()}"
        assert not page.bad_tabindex, f"{name}: positive tabindex on {page.bad_tabindex}"
        assert page.unlabelled_svgs == 0, f"{name}: <svg> without aria-label"
    # The file picker, the question box and the history picker must have been seen.
    assert controls >= 3, "the form-control parser found almost nothing"
