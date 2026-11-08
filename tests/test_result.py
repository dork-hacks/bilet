import csv
import json
import re
from pathlib import Path

import pytest

from tool.engine import analyze_file, standard_score
from tool.engine.parser import parse_bytes
from tool.engine.result import build_result

FIXTURES = Path(__file__).parent / "fixtures"
VALIDATION = FIXTURES / "validation"
CONTRACT = FIXTURES / "contract"
SALT = b"test-salt"


def expected_scores() -> dict[str, str]:
    with (VALIDATION / "expected_scores.csv").open() as fh:
        return {row["file"]: row["network_score"] for row in csv.DictReader(fh)}


@pytest.mark.parametrize(("file", "score"), sorted(expected_scores().items()))
def test_validation_set_scores(file, score):
    result = analyze_file(VALIDATION / file, salt=SALT)
    if score == "ERROR":
        assert result.status == "error" and result.score is None
    else:
        assert result.status == "ok" and result.score == int(score)


def test_validation_set_findings_match_the_answer_key_exactly():
    with (VALIDATION / "expected_findings.csv").open() as fh:
        expected = [tuple(row.values()) for row in csv.DictReader(fh)]
    got = []
    for xml in sorted(VALIDATION.glob("*.xml")):
        for f in analyze_file(xml, salt=SALT).findings:
            port = "" if f["port"] is None else str(f["port"])
            got.append((xml.name, f["ip"], port, f["code"], f["severity"]))
    assert got == expected  # same rows, same order, nothing extra


def test_standard_score_floors_at_zero():
    assert standard_score(0) == 100
    assert standard_score(35) == 65
    assert standard_score(250) == 0


# --- the contract shape ----------------------------------------------------------------


def keys_in_order(obj: dict) -> list[str]:
    return list(obj)


def test_shape_matches_the_contract_fixture_key_for_key():
    fixture = json.loads((CONTRACT / "example_scan.json").read_text())
    result = analyze_file(VALIDATION / "V2_smart_home.xml", salt=SALT).to_dict()
    assert keys_in_order(result) == keys_in_order(fixture)
    assert keys_in_order(result["devices"][0]) == keys_in_order(fixture["devices"][0])
    assert keys_in_order(result["devices"][0]["open_ports"][0]) == keys_in_order(
        fixture["devices"][0]["open_ports"][0]
    )
    assert keys_in_order(result["findings"][0]) == keys_in_order(fixture["findings"][0])
    assert keys_in_order(result["findings"][0]["evidence"]) == keys_in_order(
        fixture["findings"][0]["evidence"]
    )


def test_error_result_matches_the_contract_fixture():
    fixture = json.loads((CONTRACT / "example_error.json").read_text())
    result = analyze_file(VALIDATION / "V7_broken.xml", salt=SALT).to_dict()
    assert result == {**fixture, "file": "V7_broken.xml"}


def test_missing_file_is_an_error_not_a_crash(tmp_path):
    result = analyze_file(tmp_path / "nope.xml", salt=SALT)
    assert result.status == "error" and result.error == {"code": "NOT_XML"}


# --- content of a real result ----------------------------------------------------------


def test_v4_result():
    result = analyze_file(VALIDATION / "V4_legacy.xml", salt=SALT).to_dict()
    assert result["score"] == 25 and result["points_total"] == 75
    assert result["scan_start"] is not None
    rows = [(f["ip"], f["port"], f["code"]) for f in result["findings"]]
    assert rows == [
        ("192.168.1.1", 23, "TELNET_OPEN"),
        ("192.168.1.1", 80, "HTTP_ADMIN_CLEARTEXT"),
        ("192.168.1.1", 161, "SNMP_EXPOSED"),
        ("192.168.1.60", 21, "FTP_CLEARTEXT"),
        ("192.168.1.60", 21, "OUTDATED_SERVICE"),
        ("192.168.1.99", None, "UNKNOWN_DEVICE"),
    ]
    unknown = result["findings"][-1]
    assert unknown["protocol"] is None and set(unknown["evidence"].values()) == {None}
    by_ip = {d["ip"]: d for d in result["devices"]}
    assert by_ip["192.168.1.1"]["risk_points"] == 40
    assert by_ip["192.168.1.99"]["device_type_guess"] == "unknown"


def test_devices_finding_ids_and_masked_macs_line_up():
    result = analyze_file(VALIDATION / "V3_small_office.xml", salt=SALT).to_dict()
    ids = {f["id"]: f for f in result["findings"]}
    for device in result["devices"]:
        own = [ids[i] for i in device["finding_ids"]]
        assert all(f["device_key"] == device["device_key"] for f in own)
        assert device["risk_points"] == sum(f["points"] for f in own)
        assert device["mac_masked"] is None or device["mac_masked"].endswith(":xx:xx:xx")
    assert len(ids) == len(result["findings"])  # IDs are unique within the scan


def test_raw_mac_never_appears_in_the_output():
    xml = (VALIDATION / "V1_home_basic.xml").read_text()
    result_json = analyze_file(VALIDATION / "V1_home_basic.xml", salt=SALT).to_json()
    for mac in re.findall(r'addr="([0-9A-Fa-f:]{17})" addrtype="mac"', xml):
        assert mac.upper() not in result_json.upper()


# --- ordering and determinism ----------------------------------------------------------


def nmap(hosts: str) -> bytes:
    return f'<?xml version="1.0"?><nmaprun start="1794042000">{hosts}</nmaprun>'.encode()


def host(ip: str, ports: str, extra: str = "") -> str:
    return (
        f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/>{extra}'
        f"<ports>{ports}</ports></host>"
    )


def port(num: int, name: str, title: str | None = None) -> str:
    script = f'<script id="http-title" output="{title}"/>' if title else ""
    return (
        f'<port protocol="tcp" portid="{num}"><state state="open"/>'
        f'<service name="{name}"/>{script}</port>'
    )


def test_devices_and_findings_sort_by_ip_numerically_then_port():
    named = '<hostnames><hostname name="box"/></hostnames>'
    data = nmap(
        host("192.168.1.10", port(23, "telnet"), named)
        + host("192.168.1.9", port(21, "ftp") + port(22, "ssh"), named)
        + host("192.168.1.100", port(8888, "unknown"))  # unknown device: null port first
    )
    result = build_result(parse_bytes(data, "x.xml"), SALT).to_dict()
    assert [d["ip"] for d in result["devices"]] == ["192.168.1.9", "192.168.1.10", "192.168.1.100"]
    assert [(f["ip"][-3:], f["port"], f["code"]) for f in result["findings"]] == [
        ("1.9", 21, "FTP_CLEARTEXT"),
        ("1.9", 22, "SSH_OPEN"),
        (".10", 23, "TELNET_OPEN"),
        ("100", None, "UNKNOWN_DEVICE"),
    ]


def test_same_file_and_salt_give_byte_identical_json():
    first = analyze_file(VALIDATION / "V2_smart_home.xml", salt=SALT).to_json()
    second = analyze_file(VALIDATION / "V2_smart_home.xml", salt=SALT).to_json()
    assert first == second


def test_salt_changes_keys_but_not_ids():
    a = analyze_file(VALIDATION / "V2_smart_home.xml", salt=b"one").to_dict()
    b = analyze_file(VALIDATION / "V2_smart_home.xml", salt=b"two").to_dict()
    assert [f["id"] for f in a["findings"]] == [f["id"] for f in b["findings"]]
    assert [f["match_key"] for f in a["findings"]] != [f["match_key"] for f in b["findings"]]


def test_output_caps_long_titles_at_256_but_the_rule_still_fires():
    data = nmap(host("192.168.1.1", port(80, "http", "x" * 300 + " Router Login")))
    result = build_result(parse_bytes(data, "x.xml"), SALT).to_dict()
    (finding,) = [f for f in result["findings"] if f["code"] == "HTTP_ADMIN_CLEARTEXT"]
    assert len(finding["evidence"]["http_title"]) == 256
    assert len(result["devices"][0]["open_ports"][0]["http_title"]) == 256


def test_embedded_mac_is_absent_from_result_and_identity_stays_stable():
    extra = '<address addr="AA:BB:CC:12:34:56" addrtype="mac" vendor="Example"/>'
    plain = build_result(parse_bytes(nmap(host("192.168.1.10", "", extra)), "x.xml"), SALT)
    extra += '<hostnames><hostname name="device-aabbcc123456"/></hostnames>'
    ports = (
        '<port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http" product="AA-BB-CC-12-34-56"/>'
    )
    ports += '<script id="http-title" output="Admin aabb.cc12.3456"/></port>'
    result = build_result(parse_bytes(nmap(host("192.168.1.10", ports, extra)), "x.xml"), SALT)
    assert result.devices[0]["device_key"] == plain.devices[0]["device_key"]
    assert result.devices[0]["mac_masked"] == "AA:BB:CC:xx:xx:xx"
    for mac in ("AA:BB:CC:12:34:56", "AA-BB-CC-12-34-56", "aabb.cc12.3456", "aabbcc123456"):
        assert mac.lower() not in result.to_json().lower()
    assert result.score == 90


def test_embedded_mac_trap_has_only_masked_result_text():
    result = analyze_file(FIXTURES / "traps" / "T34_embedded_mac_text.xml", salt=SALT)
    text = result.to_json().lower()
    for mac in ("aa:bb:cc:12:34:56", "aa-bb-cc-12-34-56", "aabb.cc12.3456", "aabbcc123456"):
        assert mac not in text
    assert result.score == 90
