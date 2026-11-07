"""The home screen's network map (#170): its data, the page around it and its files."""

import copy
import hashlib
import html
import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tool.content import LANGS
from tool.content.ui import MAP_LEVELS, UI
from tool.web.app import create_app
from tool.web.map_view import LEVEL_ORDER, SCRIPT_TEXTS, device_level, network_map, safe_mac

FIXTURES = Path(__file__).parent / "fixtures" / "contract"
SCAN = json.loads((FIXTURES / "example_scan.json").read_text(encoding="utf-8"))
ERROR = json.loads((FIXTURES / "example_error.json").read_text(encoding="utf-8"))
STATIC = Path(__file__).parents[1] / "src" / "tool" / "web" / "static"
THREE = STATIC / "vendor" / "three-0.170.0.module.min.js"
THREE_SHA256 = "08fd7545d13d2c7fb65ab691530a802dafefd638596501854f267d0fb13c39e7"
NODE_KEYS = {
    "id", "ip", "type", "type_label", "name", "mac", "level", "points", "worst",
    "has_problems", "findings",
}  # fmt: skip


def client_for(result):
    return TestClient(create_app(lambda: result))


def embedded(page: str) -> dict:
    tag = '<script type="application/json" id="netmap-data">'
    match = re.search(re.escape(tag) + r"(.*?)</script>", page, re.S)
    assert match, "the map data is not in the page"
    return json.loads(match.group(1))


# --- the data ---------------------------------------------------------------------------


def test_router_in_the_middle_and_the_most_dangerous_device_first():
    data = network_map(SCAN, "en")
    assert data["hub"]["ip"] == "192.168.1.1"
    assert data["hub"]["type"] == "router"
    ips = [n["ip"] for n in data["nodes"]]
    assert ips == ["192.168.1.40", "192.168.1.41", "192.168.1.99", "192.168.1.50"]
    first = data["nodes"][0]
    assert first["type"] == "camera" and first["worst"] is True
    assert [n["ip"] for n in data["nodes"] + [data["hub"]] if n["worst"]] == ["192.168.1.40"]


def test_each_device_has_its_worst_level_as_text_and_a_sign():
    data = network_map(SCAN, "en")
    levels = {n["ip"]: n["level"]["key"] for n in data["nodes"]}
    assert levels == {
        "192.168.1.40": "high",
        "192.168.1.41": "medium",
        "192.168.1.99": "low",
        "192.168.1.50": "none",
    }
    assert data["hub"]["level"]["key"] == "medium"
    for node in data["nodes"] + [data["hub"]]:
        level = node["level"]
        assert level["label"] == MAP_LEVELS[level["key"]]["en"]
        assert level["icon"] == MAP_LEVELS[level["key"]]["icon"]
    # The legend lists every level, worst first.
    assert [lv["key"] for lv in data["levels"]] == list(LEVEL_ORDER)


def test_device_level_ignores_info_findings():
    assert device_level(["info", "low", "high"]) == "high"
    assert device_level(["info"]) == "none"
    assert device_level([]) == "none"


def test_findings_are_listed_most_points_first_with_their_port():
    camera = network_map(SCAN, "en")["nodes"][0]
    assert [f["severity"] for f in camera["findings"]] == ["high", "medium"]
    assert camera["findings"][0]["port"] == "554/tcp"
    unknown = next(n for n in network_map(SCAN, "en")["nodes"] if n["type"] == "unknown")
    assert unknown["findings"][0]["port"] is None  # UNKNOWN_DEVICE has no port


def test_only_picked_fields_reach_the_browser():
    data = network_map(SCAN, "en")
    text = json.dumps(data)
    for node in data["nodes"] + [data["hub"]]:
        assert set(node) == NODE_KEYS
    for device in SCAN["devices"]:
        assert device["device_key"] not in text
        if device.get("vendor"):
            assert device["vendor"] not in text


def test_a_raw_mac_never_reaches_the_map():
    scan = copy.deepcopy(SCAN)
    scan["devices"][1]["mac_masked"] = "B8:27:EB:12:34:56"
    data = network_map(scan, "en")
    assert "12:34:56" not in json.dumps(data)
    assert data["nodes"][0]["mac"] is None
    assert safe_mac("B8:27:EB:xx:xx:xx") == "B8:27:EB:xx:xx:xx"
    for bad in ("B8:27:EB:12:34:56", "b8:27:eb:xx:xx:xx", "", None, 42):
        assert safe_mac(bad) is None


def test_without_a_router_the_gateway_address_is_the_middle():
    scan = copy.deepcopy(SCAN)
    scan["devices"][0]["device_type_guess"] = "unknown"
    assert network_map(scan, "en")["hub"]["ip"] == "192.168.1.1"


def test_without_any_router_the_middle_is_just_the_wifi():
    scan = copy.deepcopy(SCAN)
    scan["devices"] = scan["devices"][1:]
    data = network_map(scan, "en")
    assert data["hub"] is None
    assert len(data["nodes"]) == len(scan["devices"])


def test_an_odd_device_type_becomes_unknown():
    scan = copy.deepcopy(SCAN)
    scan["devices"][1]["device_type_guess"] = "<img src=x>"
    node = next(n for n in network_map(scan, "en")["nodes"] if n["ip"] == "192.168.1.40")
    assert node["type"] == "unknown"


@pytest.mark.parametrize("result", [None, ERROR, {**SCAN, "devices": []}])
def test_no_map_without_a_readable_scan_with_devices(result):
    assert network_map(result, "en") is None


def test_the_map_is_the_same_on_every_run():
    assert json.dumps(network_map(SCAN, "ro")) == json.dumps(network_map(SCAN, "ro"))


@pytest.mark.parametrize("lang", LANGS)
def test_every_map_text_exists_in_both_languages(lang):
    data = network_map(SCAN, lang)
    assert set(data["text"]) == set(SCRIPT_TEXTS)
    assert all(data["text"].values())
    for key in [k for k in UI if k.startswith("map_")]:
        assert UI[key]["ro"] and UI[key]["en"], key
    for level in MAP_LEVELS.values():
        assert level["ro"] and level["en"] and level["icon"]


# --- the page and the endpoint ----------------------------------------------------------


@pytest.mark.parametrize("lang", LANGS)
def test_home_page_embeds_the_map_and_its_plain_list(lang):
    page = client_for(SCAN).get("/", params={"lang": lang}).text
    data = embedded(page)
    assert data == network_map(SCAN, lang)
    assert UI["map_heading"][lang] in page
    assert '<script type="module" src="/static/netmap.js"></script>' in page
    # The list works without JS: one link per device, to an anchor that is on the page.
    for device in SCAN["devices"]:
        anchor = "device-" + device["ip"].replace(".", "-")
        assert f'href="#{anchor}"' in page
        assert f'id="{anchor}"' in page
    # Every level in the legend is written out next to its sign.
    for key, level in MAP_LEVELS.items():
        assert f'class="lvl lvl-{key}"' in page
        assert html.escape(level[lang]) in page


def test_the_most_dangerous_device_is_named_on_the_map():
    page = client_for(SCAN).get("/", params={"lang": "en"}).text
    badge = f'<span class="worst">{UI["map_most_dangerous"]["en"]}</span>'
    assert page.count(badge) == 1


def test_a_hostile_hostname_is_escaped_in_the_embedded_data():
    scan = copy.deepcopy(SCAN)
    evil = "</script><script>alert(1)</script><!--"
    scan["devices"][1]["hostname"] = evil
    page = client_for(scan).get("/", params={"lang": "en"}).text
    assert "<script>alert(1)" not in page
    camera = next(n for n in embedded(page)["nodes"] if n["ip"] == "192.168.1.40")
    assert camera["name"] == evil  # still the same text once the browser parses it


def test_no_map_on_the_error_and_empty_pages():
    assert 'id="network-map"' not in client_for(ERROR).get("/").text
    assert 'id="network-map"' not in client_for(None).get("/").text


def test_map_json_endpoint():
    res = client_for(SCAN).get("/map.json", params={"lang": "en"})
    assert res.status_code == 200
    assert res.json() == network_map(SCAN, "en")
    assert client_for(None).get("/map.json").json() is None
    # An odd language falls back like every other page.
    assert client_for(SCAN).get("/map.json", params={"lang": "xx"}).json()["lang"] == "ro"


# --- the static files -------------------------------------------------------------------


def test_script_and_three_js_are_served_locally():
    client = client_for(SCAN)
    res = client.get("/static/netmap.js")
    assert res.status_code == 200
    assert "javascript" in res.headers["content-type"]
    assert client.get(f"/static/vendor/{THREE.name}").status_code == 200
    assert client.get("/static/../app.py").status_code == 404


def test_vendored_three_js_is_the_pinned_file():
    assert hashlib.sha256(THREE.read_bytes()).hexdigest() == THREE_SHA256
    script = (STATIC / "netmap.js").read_text(encoding="utf-8")
    assert f'from "./vendor/{THREE.name}"' in script
    assert "http://" not in script and "https://" not in script  # offline: no CDN


def test_script_writes_text_never_html_and_respects_reduced_motion():
    script = (STATIC / "netmap.js").read_text(encoding="utf-8")
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert sink not in script, sink
    assert "prefers-reduced-motion: reduce" in script


@pytest.mark.parametrize("asset", ["netmap.css", "netmap-models.js", "netmap-layout.js"])
def test_map_modules_and_styles_are_served_locally(asset):
    response = client_for(SCAN).get(f"/static/{asset}")
    assert response.status_code == 200
    assert response.content
    assert ("text/css" if asset.endswith(".css") else "javascript") in response.headers[
        "content-type"
    ]


@pytest.mark.parametrize("lang", LANGS)
def test_device_explorer_has_translated_controls_and_progressive_fallback(lang):
    page = client_for(SCAN).get("/", params={"lang": lang}).text
    assert '<link rel="stylesheet" href="/static/netmap.css">' in page
    for key in ("map_fullscreen", "map_search", "map_search_hint", "map_previous", "map_next"):
        assert html.escape(UI[key][lang], quote=True) in page
    data = embedded(page)
    for key in ("map_focus", "map_exit_fullscreen", "map_no_matches", "map_count"):
        assert data["text"][key] == UI[key][lang]
    # Without enhancement, the real device links remain available, not empty placeholders.
    assert '<div class="netmap-3d" hidden>' in page
    assert '<div class="netmap-list">' in page
    assert f'href="#{data["nodes"][0]["id"]}"' in page


@pytest.mark.parametrize("lang", LANGS)
def test_map_panel_shortcuts_have_focusable_destinations(lang):
    page = client_for(SCAN).get("/", params={"lang": lang}).text
    for target in ("map-selected-panel", "map-device-directory"):
        assert f'aria-controls="{target}"' in page
        assert f'id="{target}" tabindex="-1"' in page
    assert 'class="netmap-panel-links" hidden' in page
