import json

import pytest

from tool.cli import main
from tool.network import (
    DETECT_FAILED,
    NO_NETWORK,
    SEVERAL_NETWORKS,
    DetectError,
    Network,
    detect,
)


def runner_for(outputs: dict[tuple[str, ...], str | Exception]):
    """A fake command runner: argv -> recorded output (or a DetectError to raise)."""

    def run(argv):
        value = outputs.get(tuple(argv))
        if value is None:
            raise DetectError(DETECT_FAILED, f"{argv} not recorded")
        if isinstance(value, Exception):
            raise value
        return value

    return run


def linux(routes, addrs: dict[str, list] | None = None):
    outputs = {("ip", "-j", "-4", "route", "show", "default"): json.dumps(routes)}
    for dev, addr_info in (addrs or {}).items():
        outputs[("ip", "-j", "-4", "addr", "show", "dev", dev)] = json.dumps(
            [{"ifname": dev, "addr_info": addr_info}]
        )
    return runner_for(outputs)


def inet(local, prefixlen):
    return {"family": "inet", "local": local, "prefixlen": prefixlen}


def error_code(runner, system):
    with pytest.raises(DetectError) as exc:
        detect(runner, system)
    return exc.value.code


# --- Linux -----------------------------------------------------------------------------


def test_linux_android_hotspot():
    run = linux(
        [{"dst": "default", "gateway": "192.168.43.1", "dev": "wlan0"}],
        {"wlan0": [inet("192.168.43.27", 24)]},
    )
    assert detect(run, "Linux") == Network(
        "wlan0", "192.168.43.27", "192.168.43.0/24", "192.168.43.1"
    )


def test_linux_iphone_hotspot_is_a_slash_28():
    run = linux(
        [{"dst": "default", "gateway": "172.20.10.1", "dev": "wlp2s0"}],
        {"wlp2s0": [inet("172.20.10.4", 28)]},
    )
    assert detect(run, "Linux").subnet == "172.20.10.0/28"


def test_linux_same_interface_twice_is_one_network():
    # Recorded on the dev VM: a static and a DHCP default route on one interface.
    run = linux(
        [
            {"dst": "default", "gateway": "10.0.0.1", "dev": "enp0s6", "flags": []},
            {"dst": "default", "gateway": "10.0.0.1", "dev": "enp0s6", "protocol": "dhcp"},
        ],
        {"enp0s6": [inet("10.0.0.43", 24)]},
    )
    assert detect(run, "Linux") == Network("enp0s6", "10.0.0.43", "10.0.0.0/24", "10.0.0.1")


def test_linux_several_networks_refused():
    run = linux(
        [
            {"dst": "default", "gateway": "172.20.10.1", "dev": "wlan0"},
            {"dst": "default", "gateway": "192.168.1.1", "dev": "eth0"},
        ]
    )
    assert error_code(run, "Linux") == SEVERAL_NETWORKS


def test_linux_offline():
    assert error_code(linux([]), "Linux") == NO_NETWORK


def test_linux_interface_without_ipv4():
    run = linux([{"dst": "default", "gateway": "10.1.1.1", "dev": "wlan0"}], {"wlan0": []})
    assert error_code(run, "Linux") == NO_NETWORK


def test_linux_unreadable_output():
    run = runner_for({("ip", "-j", "-4", "route", "show", "default"): "not json"})
    assert error_code(run, "Linux") == DETECT_FAILED


# --- macOS -----------------------------------------------------------------------------

MAC_ROUTE = """   route to: default
destination: default
       mask: default
    gateway: 172.20.10.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
"""
MAC_EN0 = """en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether 3c:22:fb:00:00:01
	inet6 fe80::1c3a:4f1b:2b2e:91a%en0 prefixlen 64 secured scopeid 0xe
	inet 172.20.10.3 netmask 0xfffffff0 broadcast 172.20.10.15
	status: active
"""
MAC_EN5 = """en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether ac:de:48:00:11:22
	inet6 fe80::aede:48ff:fe00:1122%en5 prefixlen 64 scopeid 0x4
	status: active
"""


def macos(extra: dict | None = None):
    outputs = {
        ("route", "-n", "get", "default"): MAC_ROUTE,
        ("ifconfig", "-l"): "lo0 gif0 stf0 en0 en5 bridge0 awdl0 llw0 utun0",
        ("ifconfig", "en0"): MAC_EN0,
        ("ifconfig", "en5"): MAC_EN5,
        ("ifconfig", "gif0"): "gif0: flags=8010<POINTOPOINT,MULTICAST> mtu 1280\n",
        ("ifconfig", "stf0"): "stf0: flags=0<> mtu 1280\n",
    }
    outputs.update(extra or {})
    return runner_for(outputs)


def test_macos_iphone_hotspot():
    assert detect(macos(), "Darwin") == Network(
        "en0", "172.20.10.3", "172.20.10.0/28", "172.20.10.1"
    )


def test_macos_second_network_refused():
    en5_with_ip = MAC_EN5 + "\tinet 192.168.1.44 netmask 0xffffff00 broadcast 192.168.1.255\n"
    run = macos({("ifconfig", "en5"): en5_with_ip})
    assert error_code(run, "Darwin") == SEVERAL_NETWORKS


def test_macos_link_local_only_interface_is_not_another_network():
    en5_link_local = MAC_EN5 + "\tinet 169.254.10.20 netmask 0xffff0000 broadcast 169.254.255.255\n"
    run = macos({("ifconfig", "en5"): en5_link_local})
    assert detect(run, "Darwin").interface == "en0"


def test_macos_offline():
    run = macos({("route", "-n", "get", "default"): DetectError(DETECT_FAILED, "exit 1")})
    assert error_code(run, "Darwin") == NO_NETWORK


def test_unsupported_os():
    assert error_code(runner_for({}), "Windows") == DETECT_FAILED


# --- the command -----------------------------------------------------------------------


def test_detect_command_prints_the_network(monkeypatch, capsys):
    net = Network("en0", "172.20.10.3", "172.20.10.0/28", "172.20.10.1")
    monkeypatch.setattr("tool.network.detect", lambda: net)
    assert main(["detect", "--lang", "en"]) == 0
    out = capsys.readouterr().out
    assert "Network: 172.20.10.0/28" in out and "Router (gateway): 172.20.10.1" in out


def test_detect_command_json(monkeypatch, capsys):
    net = Network("en0", "172.20.10.3", "172.20.10.0/28", "172.20.10.1")
    monkeypatch.setattr("tool.network.detect", lambda: net)
    assert main(["detect", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["subnet"] == "172.20.10.0/28"


@pytest.mark.parametrize("lang", ["ro", "en"])
def test_detect_command_explains_errors(monkeypatch, capsys, lang):
    def fail():
        raise DetectError(SEVERAL_NETWORKS, "eth0, wlan0")

    monkeypatch.setattr("tool.network.detect", fail)
    assert main(["detect", "--lang", lang]) == 1
    err = capsys.readouterr().err
    assert ("hotspot" in err) and "SEVERAL_NETWORKS" in err
