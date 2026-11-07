import pytest

from tool.engine.parser import RawHost, RawPort, parse_bytes
from tool.engine.rules import host_hits, http_admin_hits, smb_hits, unknown_device_hits


def make_port(port, name, protocol="tcp", tunnel=None, title=None):
    return RawPort(port, protocol, name, None, None, tunnel, "probed", title)


def make_host(*ports, vendor="Acme", hostnames=("box",), ip="192.168.1.10"):
    return RawHost(ip, None, vendor, hostnames, ports)


def summary(hits):
    return [(h.port.port if h.port else None, h.entry.code) for h in hits]


# --- HTTP_ADMIN_CLEARTEXT --------------------------------------------------------------


@pytest.mark.parametrize(
    "title",
    ["Router Login", "ADMIN panel", "Configuration", "Setup wizard", "router", "Settings"],
)
def test_http_admin_title_words(title):
    assert summary(http_admin_hits(make_host(make_port(80, "http", title=title)))) == [
        (80, "HTTP_ADMIN_CLEARTEXT")
    ]


def test_https_is_not_http_admin():
    # V1: router HTTPS admin on 443. V5: .8:8443.
    host = make_host(
        make_port(443, "http", tunnel="ssl", title="Router Login"),
        make_port(8443, "https", title="Admin"),
    )
    assert http_admin_hits(host) == []


@pytest.mark.parametrize("title", [None, "Welcome", "My photos"])
def test_http_without_admin_title_is_not_a_finding(title):
    assert http_admin_hits(make_host(make_port(8008, "http", title=title))) == []


def test_only_exact_http_service_counts():
    assert http_admin_hits(make_host(make_port(8080, "http-proxy", title="Admin Login"))) == []


def test_http_admin_on_nonstandard_port():
    # V5: .6:8081
    assert summary(http_admin_hits(make_host(make_port(8081, "http", title="Admin")))) == [
        (8081, "HTTP_ADMIN_CLEARTEXT")
    ]


# --- SMB_EXPOSED -----------------------------------------------------------------------


def test_smb_one_finding_per_device_on_445():
    host = make_host(make_port(139, "netbios-ssn"), make_port(445, "microsoft-ds"))
    assert summary(smb_hits(host)) == [(445, "SMB_EXPOSED")]


def test_smb_falls_back_to_139():
    assert summary(smb_hits(make_host(make_port(139, "netbios-ssn")))) == [(139, "SMB_EXPOSED")]


def test_smb_on_another_port_uses_the_lowest():
    host = make_host(make_port(4445, "microsoft-ds"), make_port(1445, "microsoft-ds"))
    assert summary(smb_hits(host)) == [(1445, "SMB_EXPOSED")]


def test_no_smb_service_no_finding():
    assert smb_hits(make_host(make_port(445, "unknown"))) == []


# --- UNKNOWN_DEVICE --------------------------------------------------------------------


def test_unknown_device():
    host = make_host(make_port(8888, "sun-answerbook"), vendor=None, hostnames=())
    hits = unknown_device_hits(host)
    assert summary(hits) == [(None, "UNKNOWN_DEVICE")]
    assert hits[0].port is None


@pytest.mark.parametrize(
    ("vendor", "hostnames", "ports"),
    [
        ("Acme", (), (make_port(80, "http"),)),  # has a vendor
        (None, ("cam",), (make_port(80, "http"),)),  # has a hostname
        (None, (), ()),  # no open ports
    ],
)
def test_not_unknown(vendor, hostnames, ports):
    assert unknown_device_hits(make_host(*ports, vendor=vendor, hostnames=hostnames)) == []


# --- all rules together ----------------------------------------------------------------


def test_host_hits_combines_every_rule():
    host = make_host(
        make_port(80, "http", title="Camera Login"),
        make_port(554, "rtsp"),
        make_port(445, "microsoft-ds"),
        vendor=None,
        hostnames=(),
    )
    assert sorted(summary(host_hits(host)), key=str) == sorted(
        [
            (554, "CAMERA_STREAM_EXPOSED"),
            (80, "HTTP_ADMIN_CLEARTEXT"),
            (445, "SMB_EXPOSED"),
            (None, "UNKNOWN_DEVICE"),
        ],
        key=str,
    )


# --- http-title parsing (feeds HTTP_ADMIN_CLEARTEXT) -----------------------------------


def title_of(script: str) -> str | None:
    data = (
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        '<address addr="192.168.1.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="80">'
        f'<state state="open"/><service name="http"/>{script}</port></ports></host></nmaprun>'
    ).encode()
    return parse_bytes(data, "x.xml").hosts[0].ports[0].http_title


def test_title_element_wins_over_output():
    script = '<script id="http-title" output="ignored"><elem key="title">Admin</elem></script>'
    assert title_of(script) == "Admin"


def test_redirect_is_not_a_title():
    script = (
        '<script id="http-title" output="Did not follow redirect to http://192.168.1.1/login.htm">'
        '<elem key="redirect_url">http://192.168.1.1/login.htm</elem></script>'
    )
    assert title_of(script) is None


@pytest.mark.parametrize(
    "output",
    [
        "Did not follow redirect to http://192.168.1.1/login.htm",
        "Site doesn't have a title (text/html).",
    ],
)
def test_status_messages_without_elements_are_not_titles(output):
    assert title_of(f'<script id="http-title" output="{output}"/>') is None


def test_output_only_title_is_used():
    assert title_of('<script id="http-title" output="Router Settings"/>') == "Router Settings"
