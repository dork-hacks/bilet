import time
from pathlib import Path

import pytest

from tool.engine import parser
from tool.engine.parser import ParseError, parse_bytes, parse_file

FIXTURES = Path(__file__).parent / "fixtures" / "parser"


def nmap(hosts: str, start: str = "1794042000", doctype: bool = True) -> bytes:
    head = '<?xml version="1.0"?>\n' + ("<!DOCTYPE nmaprun>\n" if doctype else "")
    return f'{head}<nmaprun scanner="nmap" start="{start}">{hosts}</nmaprun>'.encode()


def host(ports: str = "", ip: str = "192.168.1.10", extra: str = "", state: str = "up") -> str:
    return (
        f'<host><status state="{state}"/><address addr="{ip}" addrtype="ipv4"/>{extra}'
        f"<ports>{ports}</ports></host>"
    )


def port(
    num: int = 80, proto: str = "tcp", state: str = "open", service: str = 'name="http"'
) -> str:
    return (
        f'<port protocol="{proto}" portid="{num}"><state state="{state}"/>'
        f"<service {service}/></port>"
    )


def error_code(data: bytes) -> str:
    with pytest.raises(ParseError) as exc:
        parse_bytes(data, "x.xml")
    return exc.value.code


# --- the sample file -------------------------------------------------------------------


def test_sample_file():
    scan = parse_file(FIXTURES / "home_sample.xml")
    assert scan.file == "home_sample.xml"
    assert scan.scan_start == "2026-11-07T09:00:00Z"
    assert [h.ip for h in scan.hosts] == ["192.168.1.1", "192.168.1.99"]  # the down host is skipped

    router, mystery = scan.hosts
    assert router.mac == "50:C7:BF:12:34:56"
    assert router.vendor == "TP-LINK TECHNOLOGIES"
    assert router.hostnames == ("router.lan",)
    # closed 8080 and open|filtered 123/udp are dropped
    assert [(p.protocol, p.port) for p in router.ports] == [
        ("tcp", 80),
        ("tcp", 443),
        ("udp", 53),
        ("udp", 1900),
    ]
    http, https, dns, upnp = router.ports
    assert (http.service_name, http.tunnel, http.http_title) == ("http", None, "Router Login")
    assert (https.service_name, https.tunnel) == ("http", "ssl")
    assert (dns.product, dns.version, dns.method) == ("dnsmasq", "2.80", "probed")
    assert upnp.service_name == "upnp"

    assert mystery.vendor is None and mystery.hostnames == ()
    assert [(p.port, p.method) for p in mystery.ports] == [(8888, "table")]  # filtered 3306 dropped


# --- error codes -----------------------------------------------------------------------


def test_empty_file():
    assert error_code(b"") == parser.EMPTY_FILE


def test_truncated_file():
    data = nmap(host(port()))
    assert error_code(data[: len(data) // 2]) == parser.NOT_XML


def test_not_xml_at_all():
    assert error_code(b"Starting Nmap 7.94 ( https://nmap.org )") == parser.NOT_XML


def test_not_an_nmap_file():
    assert error_code(b'<?xml version="1.0"?><html><body>hi</body></html>') == parser.NOT_NMAP


def test_xxe_entity_is_refused():
    data = (
        b'<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        b'<nmaprun><host><hostnames><hostname name="&xxe;"/></hostnames></host></nmaprun>'
    )
    assert error_code(data) == parser.UNSAFE_XML


def test_billion_laughs_is_refused():
    data = (
        b'<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY a "aaaaaaaaaa">'
        b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><nmaprun>&b;</nmaprun>'
    )
    assert error_code(data) == parser.UNSAFE_XML


def test_bare_doctype_from_real_nmap_is_accepted():
    assert parse_bytes(nmap(host(port()), doctype=True), "x.xml").hosts


def test_too_large(tmp_path):
    big = tmp_path / "big.xml"
    big.write_bytes(nmap(host(port())))
    with pytest.raises(ParseError) as exc:
        parse_file(big, max_bytes=50)
    assert exc.value.code == parser.TOO_LARGE


def test_missing_file_is_a_parse_error(tmp_path):
    with pytest.raises(ParseError):
        parse_file(tmp_path / "nope.xml")


# --- hosts and ports -------------------------------------------------------------------


@pytest.mark.parametrize("state", ["filtered", "open|filtered", "closed", "unfiltered"])
def test_only_exactly_open_ports_are_kept(state):
    scan = parse_bytes(nmap(host(port(state=state))), "x.xml")
    assert scan.hosts[0].ports == ()


def test_down_host_is_skipped():
    assert parse_bytes(nmap(host(port(), state="down")), "x.xml").hosts == ()


def test_host_without_status_counts_as_up():
    data = nmap('<host><address addr="10.0.0.5" addrtype="ipv4"/></host>')
    assert [h.ip for h in parse_bytes(data, "x.xml").hosts] == ["10.0.0.5"]


def test_ipv4_preferred_over_ipv6_and_ipv6_only_host_kept():
    both = (
        '<host><status state="up"/><address addr="fe80::1" addrtype="ipv6"/>'
        '<address addr="192.168.1.7" addrtype="ipv4"/></host>'
    )
    v6 = '<host><status state="up"/><address addr="fe80::2" addrtype="ipv6"/></host>'
    assert [h.ip for h in parse_bytes(nmap(both + v6), "x.xml").hosts] == [
        "192.168.1.7",
        "fe80::2",
    ]


def test_host_with_invalid_ip_is_skipped():
    assert parse_bytes(nmap(host(port(), ip="999.1.1.1")), "x.xml").hosts == ()


def test_duplicate_port_and_duplicate_host_are_merged():
    data = nmap(host(port(80) + port(80)) + host(port(22, service='name="ssh"')))
    (h,) = parse_bytes(data, "x.xml").hosts
    assert [p.port for p in h.ports] == [80, 22]


def test_merged_host_keeps_first_values_and_file_order():
    hostnames = '<hostnames><hostname name="{}"/><hostname name="{}"/></hostnames>'
    data = nmap(
        host(port(80, service='name="http" product="first"'), extra=hostnames.format("a", "b"))
        + host(
            port(80, service='name="http" product="later"') + port(161, proto="udp"),
            extra='<address addr="02:00:00:00:00:01" addrtype="mac"/>' + hostnames.format("b", "c"),
        )
        + host(
            port(22) + port(161),
            extra='<address addr="02:00:00:00:00:02" addrtype="mac" vendor="Acme"/>'
            + hostnames.format("a", "d"),
        )
    )
    (h,) = parse_bytes(data, "x.xml").hosts
    assert (h.mac, h.vendor) == ("02:00:00:00:00:01", "Acme")  # the first one seen of each
    assert h.hostnames == ("a", "b", "c", "d")
    assert [(p.protocol, p.port) for p in h.ports] == [
        ("tcp", 80),
        ("udp", 161),
        ("tcp", 22),
        ("tcp", 161),
    ]
    assert h.ports[0].product == "first"


def test_a_file_repeating_one_ip_parses_quickly():
    # NFR-07 (#185): merging used to be quadratic, so a file under the size limit that
    # lists one IP thousands of times took 90 s. 6,000 entries took about 50 s then.
    entries = "".join(host("".join(port(i * 10 + n) for n in range(1, 11))) for i in range(6000))
    start = time.perf_counter()
    (h,) = parse_bytes(nmap(entries), "x.xml").hosts
    assert time.perf_counter() - start < 10
    assert len(h.ports) == 60000


@pytest.mark.parametrize("num", ["0", "70000", "abc"])
def test_invalid_port_numbers_are_dropped(num):
    data = nmap(host(f'<port protocol="tcp" portid="{num}"><state state="open"/></port>'))
    assert parse_bytes(data, "x.xml").hosts[0].ports == ()


def test_sctp_ports_are_dropped():
    assert parse_bytes(nmap(host(port(proto="sctp"))), "x.xml").hosts[0].ports == ()


def test_port_without_service_has_no_name():
    data = nmap(host('<port protocol="tcp" portid="9"><state state="open"/></port>'))
    assert parse_bytes(data, "x.xml").hosts[0].ports[0].service_name is None


def test_invalid_mac_is_dropped():
    extra = '<address addr="not-a-mac" addrtype="mac" vendor="Acme"/>'
    h = parse_bytes(nmap(host(extra=extra)), "x.xml").hosts[0]
    assert h.mac is None


# --- RAW strings -----------------------------------------------------------------------


def test_raw_strings_are_capped_and_cleaned():
    product = "evil&#10;&#9;line&#127;[31m&#133;" + "x" * 400
    data = nmap(host(port(service=f'name="http" product="{product}"')))
    value = parse_bytes(data, "x.xml").hosts[0].ports[0].product
    assert len(value) == parser.MAX_RAW_CHARS
    assert value.startswith("evil line [31m")
    assert not any(ord(c) < 32 for c in value)


def test_blank_strings_become_none():
    data = nmap(host(port(service='name="  " product=""')))
    p = parse_bytes(data, "x.xml").hosts[0].ports[0]
    assert p.service_name is None and p.product is None


@pytest.mark.parametrize("start", ["", "soon", "99999999999999999999"])
def test_invalid_start_gives_no_scan_start(start):
    assert parse_bytes(nmap(host(), start=start), "x.xml").scan_start is None


# --- review on #35 ---------------------------------------------------------------------


@pytest.mark.parametrize("encoding", ["shift_jis", "bogus-enc", "utf-7"])
def test_odd_encoding_declarations_never_crash(encoding):
    data = f'<?xml version="1.0" encoding="{encoding}"?><nmaprun/>'.encode()
    try:
        parse_bytes(data, "x.xml")
    except ParseError as exc:
        assert exc.code == parser.NOT_XML


def test_unknown_and_multibyte_encodings_are_not_xml():
    for encoding in ("shift_jis", "bogus-enc"):
        data = f'<?xml version="1.0" encoding="{encoding}"?><nmaprun/>'.encode()
        assert error_code(data) == parser.NOT_XML


def test_long_http_title_keeps_a_keyword_past_256_characters():
    title = "x" * 300 + " Router Login"
    data = nmap(
        host(
            '<port protocol="tcp" portid="80"><state state="open"/><service name="http"/>'
            f'<script id="http-title" output="{title}"/></port>'
        )
    )
    kept = parse_bytes(data, "x.xml").hosts[0].ports[0].http_title
    assert kept.endswith("Router Login")
    assert len(kept) <= parser.MAX_TITLE_CHARS


def test_format_characters_are_stripped():
    # U+202E right-to-left override, U+200B zero-width space
    data = nmap(host(port(service='name="http" product="ab&#x202E;cd&#x200B;ef"')))
    assert parse_bytes(data, "x.xml").hosts[0].ports[0].product == "ab cd ef"
