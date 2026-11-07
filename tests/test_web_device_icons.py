"""Small device-type icons on the device cards (#162). They are decorative only."""

import copy
import json
import re
from pathlib import Path

from fastapi.testclient import TestClient

from tool.content import device_type_label
from tool.web.app import create_app
from tool.web.view import device_list

FIXTURES = Path(__file__).parent / "fixtures" / "contract"
SCAN = json.loads((FIXTURES / "example_scan.json").read_text(encoding="utf-8"))


def page(result, lang="en"):
    """The home page without the network map (#170), which draws its own icons."""
    html = TestClient(create_app(lambda: result)).get("/", params={"lang": lang}).text
    return re.sub(r'<section class="netmap".*?</section>', "", html, flags=re.S)


def test_device_item_carries_the_rules_guess():
    risky, safe = device_list(SCAN, "en")
    guesses = {d["ip"]: d.get("device_type_guess", "unknown") for d in SCAN["devices"]}
    for item in risky + safe:
        assert item.device_type == guesses[item.ip]


def test_every_device_gets_one_hidden_icon_and_keeps_its_text_label():
    html = page(SCAN)
    icons = re.findall(r"<svg class=\"dev-icon\"[^>]*>", html)
    assert len(icons) == len(SCAN["devices"])
    for tag in icons:
        assert 'aria-hidden="true"' in tag
        assert 'focusable="false"' in tag
    # Colour and shape are never the only signal: the type is still written out.
    for device in SCAN["devices"]:
        assert device_type_label(device.get("device_type_guess", "unknown"), "en") in html


def test_an_odd_device_type_gets_the_unknown_icon_and_is_never_echoed():
    scan = copy.deepcopy(SCAN)
    scan["devices"][0]["device_type_guess"] = '"><script>alert(1)</script>'
    html = page(scan)
    assert "<script>alert(1)" not in html
    assert len(re.findall(r"<svg class=\"dev-icon\"", html)) == len(SCAN["devices"])
