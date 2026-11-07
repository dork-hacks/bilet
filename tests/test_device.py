import json
import stat
from dataclasses import replace
from pathlib import Path

import pytest

from tool.config import data_dir
from tool.engine.device import device_key, guess_device_type, load_salt, mask_mac, risk_points
from tool.engine.parser import RawHost, RawPort, parse_file
from tool.engine.rules import host_hits

FIXTURES = Path(__file__).parent / "fixtures"
TEST_SALT = b"test-salt"


def make_host(services=(), vendor=None, hostnames=(), mac=None, ip="192.168.1.10"):
    ports = tuple(
        RawPort(1000 + i, "tcp", name, None, None, None, "probed", None)
        for i, name in enumerate(services)
    )
    return RawHost(ip, mac, vendor, tuple(hostnames), ports)


# --- MAC masking and device keys -------------------------------------------------------


def test_mask_mac_keeps_vendor_half_only():
    assert mask_mac("b8:27:eb:12:34:56") == "B8:27:EB:xx:xx:xx"
    assert mask_mac(None) is None


def test_device_key_matches_the_contract_fixture():
    scan = json.loads((FIXTURES / "contract" / "example_scan.json").read_text())
    router, *_, mystery = scan["devices"]
    assert device_key(TEST_SALT, "50:C7:BF:12:34:56", "192.168.1.1") == router["device_key"]
    # No MAC: keyed on the IP.
    assert device_key(TEST_SALT, None, "192.168.1.99") == mystery["device_key"]


def test_device_key_is_case_insensitive_and_salted():
    assert device_key(TEST_SALT, "aa:bb:cc:dd:ee:ff", "x") == device_key(
        TEST_SALT, "AA:BB:CC:DD:EE:FF", "y"
    )
    assert device_key(TEST_SALT, "AA:BB:CC:DD:EE:FF", "x") != device_key(
        b"other", "AA:BB:CC:DD:EE:FF", "x"
    )


# --- the local salt --------------------------------------------------------------------


def test_salt_is_created_once_and_private(tmp_path):
    folder = tmp_path / "data"
    first = load_salt(folder)
    assert load_salt(folder) == first  # stable on one install
    assert len(first) == 64  # 32 random bytes, hex
    path = folder / "device_key.salt"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(folder.stat().st_mode) == 0o700


def test_different_installs_get_different_salts(tmp_path):
    assert load_salt(tmp_path / "a") != load_salt(tmp_path / "b")


@pytest.mark.parametrize("value", ["", None])
def test_empty_data_dir_env_falls_back_to_data(monkeypatch, value):
    # .env.example ships TOOL_DATA_DIR= (empty); that must not mean the current directory.
    if value is None:
        monkeypatch.delenv("TOOL_DATA_DIR", raising=False)
    else:
        monkeypatch.setenv("TOOL_DATA_DIR", value)
    assert data_dir() == Path("data")


def test_data_dir_env_is_used(monkeypatch, tmp_path):
    monkeypatch.setenv("TOOL_DATA_DIR", str(tmp_path))
    assert data_dir() == tmp_path


# --- device type guess -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"services": ["rtsp", "http"]}, "camera"),
        ({"vendor": "Hangzhou Hikvision Digital Technology"}, "camera"),
        ({"hostnames": ["nvr"], "services": ["http"]}, "camera"),
        ({"services": ["ipp", "jetdirect"], "vendor": "HP"}, "printer"),
        ({"vendor": "Synology", "services": ["ssh", "microsoft-ds"]}, "nas"),
        ({"hostnames": ["living-room-tv"], "vendor": "Google"}, "tv"),
        ({"services": ["domain", "http"]}, "router"),
        ({"vendor": "Ubiquiti", "hostnames": ["access-point"]}, "router"),
        ({"services": ["mqtt"], "vendor": "Raspberry Pi Foundation"}, "iot_hub"),
        ({"vendor": "Espressif", "services": ["telnet"]}, "iot_hub"),
        ({"services": ["ms-wbt-server"], "vendor": "Dell"}, "pc"),
        ({"hostnames": ["laptop-ana"], "vendor": "Dell"}, "pc"),
        ({"services": ["ssh", "mysql"], "hostnames": ["srv-db"]}, "server"),
        ({"hostnames": ["oldsrv"], "services": ["ftp"]}, "server"),
        ({"vendor": "Samsung", "hostnames": ["galaxy-s23"]}, "phone"),
        ({"services": ["sun-answerbook"]}, "unknown"),
        ({}, "unknown"),
    ],
)
def test_guess_device_type(kwargs, expected):
    assert guess_device_type(make_host(**kwargs)) == expected


def test_short_words_only_match_whole_hostname_words():
    # Short words match whole hostname words only: "ap" (router) isn't found in "laptop".
    assert guess_device_type(make_host(hostnames=["laptop-ioana"])) == "pc"
    assert guess_device_type(make_host(hostnames=["jonas"])) == "unknown"  # not "nas"


# Every Validation Set device, against the brief's own description of each network.
VALIDATION_TYPES = {
    "V1_home_basic.xml": ["router", "pc", "phone"],
    "V2_smart_home.xml": ["router", "camera", "iot_hub", "tv"],
    "V3_small_office.xml": ["printer", "nas", "pc", "server"],
    "V4_legacy.xml": ["router", "server", "unknown"],
    "V5_nonstandard_ports.xml": ["iot_hub", "camera", "server", "router", "server"],
    "V6a_before.xml": ["router", "pc", "iot_hub"],
    "V6b_after.xml": ["router", "pc", "iot_hub"],
}


@pytest.mark.parametrize(("file", "expected"), sorted(VALIDATION_TYPES.items()))
def test_validation_set_devices(file, expected):
    scan = parse_file(FIXTURES / "validation" / file)
    assert [guess_device_type(h) for h in scan.hosts] == expected


def test_risk_points_sum_the_hits():
    host = make_host(services=["telnet", "ssh", "mqtt"], vendor="Acme", hostnames=["box"])
    assert risk_points(host_hits(host)) == 20 + 0 + 10
    # No vendor and no hostname adds UNKNOWN_DEVICE (5).
    assert risk_points(host_hits(make_host(services=["telnet"]))) == 20 + 5


@pytest.mark.parametrize("title", ["Camera Login", "IPCAM setup", "NVR", "dVr Admin", "Doorbell"])
def test_camera_http_title_wins_over_generic_ftp_server(title):
    host = make_host(services=("ftp", "telnet"), hostnames=("pi2.lan",))
    page = RawPort(80, "tcp", "http", None, None, None, "probed", title)
    assert guess_device_type(replace(host, ports=host.ports + (page,))) == "camera"


@pytest.mark.parametrize("title", [None, "Admin Login", "CameraShop", "discovery", "ipcameraShop"])
def test_camera_title_requires_a_specific_whole_word(title):
    host = make_host(services=("ftp",), hostnames=("pi2.lan",))
    page = RawPort(80, "tcp", "http", None, None, None, "probed", title)
    assert guess_device_type(replace(host, ports=host.ports + (page,))) == "server"


def test_camera_title_does_not_apply_to_non_http_services():
    page = RawPort(21, "tcp", "ftp", None, None, None, "probed", "Camera Login")
    assert guess_device_type(replace(make_host(), ports=(page,))) == "server"


def test_lab_camera_with_generic_pi_hostname_is_a_camera_without_score_changes(tmp_path):
    from tool.engine import analyze_file

    fixture = Path(__file__).parents[1] / "lab/tests/fixtures/default_lab.xml"
    original = analyze_file(fixture, salt=TEST_SALT).to_dict()
    path = tmp_path / fixture.name
    path.write_text(fixture.read_text().replace("cam-pi.lan", "pi2.lan"))
    result = analyze_file(path, salt=TEST_SALT).to_dict()
    camera = next(d for d in result["devices"] if d["ip"] == "10.42.0.11")
    assert camera["device_type_guess"] == "camera"
    assert result["score"] == original["score"] == 25
    assert result["findings"] == original["findings"]
