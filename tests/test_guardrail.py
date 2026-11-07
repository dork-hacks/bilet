import ipaddress

import pytest

from tool import guardrail as g
from tool.cli import main
from tool.content.texts import REFUSALS
from tool.network import DETECT_FAILED, DetectError, Network

HOTSPOT = "172.20.10.0/28"  # an iPhone hotspot


def refused(fn, *args):
    with pytest.raises(g.Refused) as exc:
        fn(*args)
    return exc.value.code


def allowlist(subnet=HOTSPOT, extra=()):
    return g.build_allowlist(subnet, extra)


# --- every refusal code ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("target", "code"),
    [
        ("8.8.8.8", g.PUBLIC_ADDRESS),
        ("1.1.1.0/24", g.PUBLIC_ADDRESS),
        ("192.0.2.10", g.PUBLIC_ADDRESS),  # a TEST-NET: Python calls it "private", we don't
        ("198.18.0.1", g.PUBLIC_ADDRESS),  # benchmark range, same
        ("2001:4860:4860::8888", g.PUBLIC_ADDRESS),
        ("100.64.0.1", g.CGNAT_ADDRESS),  # the mobile operator's side of the hotspot
        ("100.127.255.254", g.CGNAT_ADDRESS),
        ("127.0.0.1", g.LOOPBACK_ADDRESS),
        ("::1", g.LOOPBACK_ADDRESS),
        ("169.254.10.20", g.LINK_LOCAL_ADDRESS),
        ("fe80::1", g.LINK_LOCAL_ADDRESS),
        ("224.0.0.251", g.MULTICAST_ADDRESS),
        ("239.255.255.250", g.MULTICAST_ADDRESS),
        ("router.lan", g.HOSTNAME_NOT_ALLOWED),
        ("example.com", g.HOSTNAME_NOT_ALLOWED),
        ("localhost", g.HOSTNAME_NOT_ALLOWED),
        ("192.168.0.0/16", g.RANGE_TOO_LARGE),
        ("10.0.0.0/8", g.RANGE_TOO_LARGE),
        ("172.20.10.0/23", g.RANGE_TOO_LARGE),
        ("192.168.1.0/24", g.OUTSIDE_ALLOWLIST),  # e.g. the venue Wi-Fi
        ("10.0.0.5", g.OUTSIDE_ALLOWLIST),
        ("172.20.10.16/28", g.OUTSIDE_ALLOWLIST),  # the next /28 over
        ("", g.INVALID_TARGET),
        ("1.2.3", g.INVALID_TARGET),
        ("192.168.1.1-50", g.INVALID_TARGET),  # nmap ranges aren't accepted
        ("0.0.0.0", g.INVALID_TARGET),  # noqa: S104 - a refused target, not a bind address
        ("240.0.0.1", g.INVALID_TARGET),  # reserved
    ],
)
def test_refused_targets(target, code):
    assert refused(g.check_target, target, allowlist()) == code


def test_every_refusal_code_has_ro_and_en_text():
    codes = {v for k, v in vars(g).items() if k.isupper() and isinstance(v, str) and k == v}
    assert codes <= set(REFUSALS)
    assert all(REFUSALS[c]["ro"] and REFUSALS[c]["en"] for c in codes)


# --- what is allowed -------------------------------------------------------------------


@pytest.mark.parametrize("target", ["172.20.10.0/28", "172.20.10.3", "172.20.10.8/29"])
def test_iphone_hotspot_slash_28_is_allowed(target):
    net = g.check_target(target, allowlist(HOTSPOT))
    assert net.subnet_of(ipaddress.ip_network(HOTSPOT))


@pytest.mark.parametrize("target", ["192.168.43.0/24", "192.168.43.1", "192.168.43.128/25"])
def test_android_hotspot_slash_24_is_allowed(target):
    assert g.check_target(target, allowlist("192.168.43.0/24"))


def test_host_address_becomes_a_single_address_network():
    assert str(g.check_target(" 172.20.10.3 ", allowlist())) == "172.20.10.3/32"


def test_extra_ranges_only_by_explicit_config():
    lab = allowlist(HOTSPOT, extra=["192.168.50.0/24"])
    assert g.check_target("192.168.50.7", lab)
    assert refused(g.check_target, "192.168.50.7", allowlist()) == g.OUTSIDE_ALLOWLIST


def test_extra_ranges_from_env():
    env = {g.ALLOWLIST_ENV: " 192.168.50.0/24 , ,10.9.9.0/24"}
    assert g.extra_ranges_from_env(env) == ["192.168.50.0/24", "10.9.9.0/24"]
    assert g.extra_ranges_from_env({}) == []


@pytest.mark.parametrize(
    ("extra", "code"),
    [
        ("8.8.8.0/24", g.PUBLIC_ADDRESS),
        ("10.0.0.0/8", g.RANGE_TOO_LARGE),
        ("lab", g.HOSTNAME_NOT_ALLOWED),
    ],
)
def test_configured_ranges_are_checked_like_targets(extra, code):
    assert refused(g.build_allowlist, HOTSPOT, [extra]) == code


def test_connected_to_a_big_network_allows_nothing():
    # On a venue or office /16 the default allowlist itself is refused.
    assert refused(g.build_allowlist, "10.20.0.0/16", []) == g.RANGE_TOO_LARGE


def test_connected_to_the_operator_network_allows_nothing():
    assert refused(g.build_allowlist, "100.64.0.0/24", []) == g.CGNAT_ADDRESS


# --- the whole request -----------------------------------------------------------------


def test_confirm_is_required_and_the_message_names_the_target():
    with pytest.raises(g.Refused) as exc:
        g.authorize([HOTSPOT], allowlist(), confirm=False)
    assert exc.value.code == g.CONFIRM_REQUIRED and exc.value.target == HOTSPOT


def test_one_bad_target_refuses_the_whole_request():
    assert refused(g.authorize, ["172.20.10.3", "8.8.8.8"], allowlist(), True) == g.PUBLIC_ADDRESS


def test_authorized_request():
    nets = g.authorize(["172.20.10.3", "172.20.10.4"], allowlist(), confirm=True)
    assert [str(n) for n in nets] == ["172.20.10.3/32", "172.20.10.4/32"]


def test_empty_request_is_refused():
    assert refused(g.authorize, [], allowlist(), True) == g.INVALID_TARGET


# --- the command (detect is faked: no real network needed) ------------------------------


@pytest.fixture
def on_hotspot(monkeypatch):
    net = Network("en0", "172.20.10.3", HOTSPOT, "172.20.10.1")
    monkeypatch.setattr("tool.network.detect", lambda: net)
    monkeypatch.delenv(g.ALLOWLIST_ENV, raising=False)


def test_scan_without_confirm_explains_what_it_would_scan(on_hotspot, capsys):
    assert main(["scan", "--lang", "en"]) == 3
    err = capsys.readouterr().err
    assert HOTSPOT in err and "--confirm" in err and "CONFIRM_REQUIRED" in err


@pytest.mark.parametrize(
    ("target", "code"),
    [("8.8.8.8", "PUBLIC_ADDRESS"), ("192.168.1.0/24", "OUTSIDE_ALLOWLIST")],
)
def test_scan_refuses_public_ip_and_venue_network(on_hotspot, capsys, target, code):
    # The two live checks the jury runs (brief, live check 4).
    assert main(["scan", target, "--confirm", "--lang", "ro"]) == 3
    err = capsys.readouterr().err
    assert code in err and target in err


def test_scan_allowed_target_reaches_nmap_with_only_that_range(on_hotspot, monkeypatch):
    calls = []

    def runner(args):  # stands in for nmap: records the call, scans nothing
        calls.append(args)
        raise SystemExit(0)

    monkeypatch.setattr("tool.scan.run_nmap", runner)
    monkeypatch.setenv("TOOL_NMAP_SERVICES", __file__)  # any readable file will do here
    with pytest.raises(SystemExit):
        main(["scan", "--confirm", "--lang", "en"])
    assert calls[0][0] == "-sn" and calls[0][-1] == HOTSPOT


def test_scan_refuses_when_the_network_is_unclear(monkeypatch, capsys):
    def fail():
        raise DetectError(DETECT_FAILED, "x")

    monkeypatch.setattr("tool.network.detect", fail)
    assert main(["scan", "172.20.10.3", "--confirm"]) == 1
