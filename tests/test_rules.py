import hashlib
import hmac

import pytest

from tool.engine.catalog import CATALOG, SERVICE_RULES
from tool.engine.ids import finding_id, match_key
from tool.engine.parser import RawHost, RawPort
from tool.engine.rules import service_hits

# Severity and points exactly as the brief's catalog table.
BRIEF = {
    "TELNET_OPEN": ("high", 20),
    "RDP_EXPOSED": ("high", 20),
    "VNC_EXPOSED": ("high", 20),
    "DB_EXPOSED": ("high", 20),
    "CAMERA_STREAM_EXPOSED": ("high", 20),
    "OUTDATED_SERVICE": ("high", 20),
    "FTP_CLEARTEXT": ("medium", 10),
    "HTTP_ADMIN_CLEARTEXT": ("medium", 10),
    "SMB_EXPOSED": ("medium", 10),
    "MQTT_EXPOSED": ("medium", 10),
    "UPNP_EXPOSED": ("medium", 10),
    "SNMP_EXPOSED": ("medium", 10),
    "PRINTER_RAW_EXPOSED": ("low", 5),
    "UNKNOWN_DEVICE": ("low", 5),
    "SSH_OPEN": ("info", 0),
}


def make_port(port: int, name: str | None, protocol: str = "tcp") -> RawPort:
    return RawPort(port, protocol, name, None, None, None, "probed", None)


def codes(*ports: RawPort) -> list[tuple[int, str]]:
    host = RawHost("192.168.1.10", None, None, (), ports)
    return [(hit.port.port, hit.entry.code) for hit in service_hits(host)]


def test_catalog_matches_the_brief():
    assert {code: (e.severity, e.points) for code, e in CATALOG.items()} == BRIEF


def test_every_service_rule_uses_a_catalog_code():
    assert all(rule.code in CATALOG for rule in SERVICE_RULES)


@pytest.mark.parametrize(
    ("service", "code"),
    [
        ("telnet", "TELNET_OPEN"),
        ("ms-wbt-server", "RDP_EXPOSED"),
        ("vnc", "VNC_EXPOSED"),
        ("mysql", "DB_EXPOSED"),
        ("postgresql", "DB_EXPOSED"),
        ("redis", "DB_EXPOSED"),
        ("mongodb", "DB_EXPOSED"),
        ("rtsp", "CAMERA_STREAM_EXPOSED"),
        ("ftp", "FTP_CLEARTEXT"),
        ("mqtt", "MQTT_EXPOSED"),
        ("jetdirect", "PRINTER_RAW_EXPOSED"),
        ("ssh", "SSH_OPEN"),
    ],
)
def test_service_name_rules(service, code):
    assert codes(make_port(4000, service)) == [(4000, code)]


@pytest.mark.parametrize(("service", "code"), [("upnp", "UPNP_EXPOSED"), ("snmp", "SNMP_EXPOSED")])
def test_udp_only_rules(service, code):
    assert codes(make_port(1900, service, "udp")) == [(1900, code)]
    assert codes(make_port(1900, service, "tcp")) == []


def test_decided_by_service_name_not_port_number():
    # V5: telnet on 2323 and redis on 6380 count.
    assert codes(make_port(2323, "telnet"), make_port(6380, "redis")) == [
        (2323, "TELNET_OPEN"),
        (6380, "DB_EXPOSED"),
    ]
    # A well-known port number with another service name doesn't.
    assert codes(make_port(23, "http"), make_port(3306, "unknown")) == []


def test_ports_outside_the_catalog_give_nothing():
    # V2: TV ports 8008/8009. V3: printer IPP on 631. Plus a port with no service name.
    assert codes(make_port(8009, "ajp13"), make_port(631, "ipp"), make_port(9, None)) == []


def test_service_name_case_is_ignored():
    assert codes(make_port(22, "SSH")) == [(22, "SSH_OPEN")]


def test_hits_follow_port_order_and_keep_the_port():
    host = RawHost("192.168.1.10", None, None, (), (make_port(22, "ssh"), make_port(21, "ftp")))
    hits = service_hits(host)
    assert [h.entry.code for h in hits] == ["SSH_OPEN", "FTP_CLEARTEXT"]
    assert hits[1].port.service_name == "ftp"


# Values from tests/fixtures/contract/example_scan.json (#26), built from the contract formulas.
def test_finding_id_matches_the_contract_fixture():
    file = "example_smart_home.xml"
    assert finding_id(file, "192.168.1.40", 554, "CAMERA_STREAM_EXPOSED") == "f_851ea5e10492"
    assert finding_id(file, "192.168.1.99", None, "UNKNOWN_DEVICE") == "f_1d7d82482769"


def test_match_key_matches_the_contract_fixture():
    # The fixture's router device_key: HMAC-SHA256 with the test salt over its MAC.
    router = "d_" + hmac.new(b"test-salt", b"50:C7:BF:12:34:56", hashlib.sha256).hexdigest()[:12]
    assert match_key(router, "tcp", 80, "HTTP_ADMIN_CLEARTEXT") == "m_c0236143a83f"
    assert match_key(router, None, None, "UNKNOWN_DEVICE").startswith("m_")
