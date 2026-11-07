"""The devices and findings list under the home summary (#55)."""

import copy
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from markupsafe import escape

from tool.content import finding_text, fix_steps, severity_label
from tool.web.app import create_app
from tool.web.view import device_fix_steps, device_list, home_view

FIXTURES = Path(__file__).parent / "fixtures" / "contract"
SCAN = json.loads((FIXTURES / "example_scan.json").read_text(encoding="utf-8"))


def page(result, lang="en"):
    return (
        TestClient(create_app(lambda: result), base_url="http://127.0.0.1")
        .get("/", params={"lang": lang})
        .text
    )


# --- view logic -------------------------------------------------------------------------


def test_devices_are_most_dangerous_first():
    risky, safe = device_list(SCAN, "en")
    assert [d.ip for d in risky] == [
        "192.168.1.40",  # camera, 30
        "192.168.1.1",  # router, 20
        "192.168.1.41",  # hub, 10
        "192.168.1.99",  # unknown, 5
    ]
    assert [d.risk_points for d in risky] == [30, 20, 10, 5]
    assert [d.ip for d in safe] == ["192.168.1.50"]  # the TV has no findings


def test_equal_totals_and_peak_findings_keep_the_scan_order():
    scan = copy.deepcopy(SCAN)
    for device in scan["devices"]:
        if device["finding_ids"]:
            device["risk_points"] = 10
    for finding in scan["findings"]:
        finding["points"] = 10
    risky, _ = device_list(scan, "en")
    assert [d.ip for d in risky] == ["192.168.1.1", "192.168.1.40", "192.168.1.41", "192.168.1.99"]


def test_findings_are_highest_points_first():
    risky, _ = device_list(SCAN, "en")
    camera = risky[0]
    assert [f.code for f in camera.findings] == ["CAMERA_STREAM_EXPOSED", "HTTP_ADMIN_CLEARTEXT"]
    assert [f.points for f in camera.findings] == [20, 10]


def test_finding_item_carries_texts_from_content():
    risky, _ = device_list(SCAN, "ro")
    item = risky[0].findings[0]
    text = finding_text("CAMERA_STREAM_EXPOSED", "ro")
    assert item.title == text.title
    assert item.explanation == text.explanation
    # The camera's own steps (#152): they name its IP, not the generic text.
    assert item.steps == fix_steps("CAMERA_STREAM_EXPOSED", "ro", "camera", "192.168.1.40", 80)
    assert item.steps != text.steps
    assert "192.168.1.40" in item.steps[0]
    assert 1 <= len(item.steps) <= 5
    assert item.severity == "high"
    assert item.severity_label == severity_label("high", "ro")
    assert item.port_label == "554/tcp"


def test_unknown_device_has_no_port():
    risky, _ = device_list(SCAN, "en")
    unknown = next(d for d in risky if d.ip == "192.168.1.99")
    assert unknown.findings[0].code == "UNKNOWN_DEVICE"
    assert unknown.findings[0].port_label is None


def test_device_fields_are_passed_through():
    risky, _ = device_list(SCAN, "en")
    router = risky[1]
    assert router.label == "Router"
    assert router.mac_masked == "50:C7:BF:xx:xx:xx"
    assert router.hostname == "router.lan"


def test_missing_finding_ids_are_skipped():
    scan = copy.deepcopy(SCAN)
    scan["devices"][0]["finding_ids"].append("f_doesnotexist")
    risky, _ = device_list(scan, "en")
    router = next(d for d in risky if d.ip == "192.168.1.1")
    assert len(router.findings) == 2


def test_home_view_has_the_lists_and_errors_do_not():
    view = home_view(SCAN, "en")
    assert len(view.devices) == 4 and len(view.safe_devices) == 1
    assert home_view({"status": "error", "error": {"code": "NOT_XML"}}, "en").devices == ()
    assert home_view(None, "en").devices == ()


# --- rendered page ----------------------------------------------------------------------


@pytest.mark.parametrize("lang", ["ro", "en"])
def test_page_lists_every_finding_with_its_steps(lang):
    html = page(SCAN, lang)
    devices = {d["ip"]: d for d in SCAN["devices"]}
    for finding in SCAN["findings"]:
        text = finding_text(finding["code"], lang)
        assert str(escape(text.title)) in html  # autoescape turns ' into &#39;
        for step in device_fix_steps(devices[finding["ip"]], finding["code"], lang):
            assert str(escape(step)) in html
    assert "<ol" in html


def test_page_order_matches_the_view():
    html = page(SCAN)
    camera = html.index('id="device-192-168-1-40"')
    router = html.index('id="device-192-168-1-1"')
    hub = html.index('id="device-192-168-1-41"')
    assert camera < router < hub


def test_severity_is_written_as_text():
    html = page(SCAN)
    assert severity_label("high", "en") in html
    assert severity_label("medium", "en") in html


def test_safe_devices_are_collapsed():
    html = page(SCAN)
    assert "<details" in html
    assert "No problems found" in html
    assert "192.168.1.50" in html


def test_unknown_device_shows_no_port_on_the_page():
    html = page(SCAN)
    start = html.index('id="device-192-168-1-99"')
    block = html[start : html.index("</article>", start)]
    assert "Port" not in block


def test_hostile_hostname_and_vendor_are_escaped():
    scan = copy.deepcopy(SCAN)
    scan["devices"][0]["hostname"] = "<b onmouseover=alert(1)>x</b>"
    scan["devices"][3]["hostname"] = "<script>alert(2)</script>"
    html = page(scan)
    assert "<b onmouseover" not in html
    assert "<script>alert(2)" not in html
    assert "&lt;script&gt;alert(2)" in html


# --- device-specific steps (#152) -------------------------------------------------------


def _camera():
    return copy.deepcopy(next(d for d in SCAN["devices"] if d["ip"] == "192.168.1.40"))


@pytest.mark.parametrize("lang", ["ro", "en"])
def test_do_this_first_shows_the_fix_instead_of_settings_navigation(lang):
    view = home_view(SCAN, lang)
    assert view.first is not None
    assert "192.168.1.40" in view.first.device
    assert "RTSP" in view.first.step
    assert "http://" not in view.first.step
    assert "This is the step" not in view.first.step
    assert "Acesta este pasul" not in view.first.step


@pytest.mark.parametrize("lang", ["ro", "en"])
def test_first_action_keeps_generic_fallback_when_no_variant_exists(lang):
    scan = copy.deepcopy(SCAN)
    for device in scan["devices"]:
        device["device_type_guess"] = "unknown"
    view = home_view(scan, lang)
    assert view.first.step == finding_text("CAMERA_STREAM_EXPOSED", lang).steps[0]


def test_the_settings_url_uses_the_devices_plain_http_port():
    camera = _camera()
    for port in camera["open_ports"]:
        if port["service_name"] == "http":
            port["port"] = 8080
    steps = device_fix_steps(camera, "HTTP_ADMIN_CLEARTEXT", "en")
    assert "http://192.168.1.40:8080 " in steps[0]


def test_an_https_only_device_is_not_sent_to_an_unobserved_http_page():
    camera = _camera()
    for port in camera["open_ports"]:
        if port["service_name"] == "http":
            port["port"], port["tunnel"] = 8443, "ssl"
    steps = device_fix_steps(camera, "TELNET_OPEN", "en")
    assert "http://192.168.1.40" not in steps[0]
    assert "192.168.1.40" in steps[0]


def test_a_hostile_ip_in_the_steps_is_escaped_on_the_page():
    scan = copy.deepcopy(SCAN)
    camera = next(d for d in scan["devices"] if d["ip"] == "192.168.1.40")
    camera["ip"] = "<img src=x onerror=alert(3)>"
    html = page(scan)
    assert "<img src=x" not in html


@pytest.mark.parametrize("lang", ["ro", "en"])
def test_outdated_camera_ftp_action_uses_the_affected_service(lang):
    from tool.engine import analyze_file

    scan = analyze_file(
        Path(__file__).parents[1] / "lab/tests/fixtures/default_lab.xml",
        salt=b"camera-ftp-action",
    ).to_dict()
    view = home_view(scan, lang)
    assert "FTP /" in view.first.step
    assert "vsftpd" not in view.first.step
    camera = next(d for d in scan["devices"] if d["device_type_guess"] == "camera")
    outdated = next(f for f in scan["findings"] if f["code"] == "OUTDATED_SERVICE")
    steps = device_fix_steps(camera, outdated["code"], lang, outdated)
    assert steps == device_fix_steps(camera, "FTP_CLEARTEXT", lang)
    # Another old service must not receive an unrelated FTP fix.
    other = {**outdated, "port": 22}
    fallback = device_fix_steps(camera, other["code"], lang, other)
    assert "FTP /" not in " ".join(fallback)
    assert "vsftpd" not in " ".join(fallback)
