"""Detect the network this computer is on (FR-01): interface, subnet and gateway.

Read-only and unprivileged. It only asks the operating system for its own routing table
(`ip` on Linux, `route` and `ifconfig` on macOS) and sends no packets. The subnet is
never hard-coded: iPhone hotspots use 172.20.10.0/28, Android ones vary.

The result is the guardrail's default allowlist (#18), so when the answer is unclear
(no network, or several at once) this refuses rather than guesses.
"""

import ipaddress
import json
import platform
import re
import subprocess  # noqa: S404 - fixed argument lists only, never a shell
from collections.abc import Callable
from dataclasses import dataclass

# Error codes. Their RO/EN texts live in tool.content (area:content).
NO_NETWORK = "NO_NETWORK"
SEVERAL_NETWORKS = "SEVERAL_NETWORKS"
DETECT_FAILED = "DETECT_FAILED"

Runner = Callable[[list[str]], str]


class DetectError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Network:
    interface: str
    address: str  # this computer's address on the network
    subnet: str  # e.g. "172.20.10.0/28"
    gateway: str


def run(argv: list[str]) -> str:
    """Run a system command (no shell) and return its output."""
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=10, check=False)  # noqa: S603
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DetectError(DETECT_FAILED, f"{argv[0]}: {exc}") from exc
    if done.returncode != 0:
        raise DetectError(DETECT_FAILED, f"{' '.join(argv)} exited {done.returncode}")
    return done.stdout


def detect(runner: Runner = run, system: str | None = None) -> Network:
    """The one network this computer uses to reach the outside, or DetectError."""
    system = system or platform.system()
    if system == "Linux":
        return _detect_linux(runner)
    if system == "Darwin":
        return _detect_macos(runner)
    raise DetectError(DETECT_FAILED, f"unsupported operating system: {system}")


# --- Linux (iproute2) ----------------------------------------------------------------


def _detect_linux(runner: Runner) -> Network:
    routes = _json(runner(["ip", "-j", "-4", "route", "show", "default"]))
    # The same interface can appear twice (e.g. a static and a DHCP route). Several
    # interfaces with a default route means several networks at once.
    by_dev: dict[str, str] = {}
    for route in routes:
        dev, gateway = route.get("dev"), route.get("gateway")
        if dev and gateway:
            by_dev.setdefault(dev, gateway)
    if not by_dev:
        raise DetectError(NO_NETWORK, "no default route")
    if len(by_dev) > 1:
        raise DetectError(SEVERAL_NETWORKS, ", ".join(sorted(by_dev)))
    ((interface, gateway),) = by_dev.items()

    links = _json(runner(["ip", "-j", "-4", "addr", "show", "dev", interface]))
    for link in links:
        for info in link.get("addr_info", []):
            if info.get("family") == "inet" and info.get("local") and info.get("prefixlen"):
                return _network(interface, f"{info['local']}/{info['prefixlen']}", gateway)
    raise DetectError(NO_NETWORK, f"{interface} has no IPv4 address")


# --- macOS (BSD route + ifconfig) ----------------------------------------------------

_ROUTE_FIELD = re.compile(r"^\s*(gateway|interface):\s*(\S+)\s*$", re.M)
_INET = re.compile(r"^\s*inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]{8})", re.M)


def _detect_macos(runner: Runner) -> Network:
    try:
        text = runner(["route", "-n", "get", "default"])
    except DetectError as exc:  # `route` exits non-zero when there is no default route
        raise DetectError(NO_NETWORK, exc.detail) from exc
    fields = dict(_ROUTE_FIELD.findall(text))
    interface, gateway = fields.get("interface"), fields.get("gateway")
    if not interface or not gateway:
        raise DetectError(NO_NETWORK, "no default route")

    # Several networks at once: another interface (Wi-Fi + Ethernet, or a second
    # Wi-Fi) also has an IPv4 address outside loopback and link-local.
    others = []
    for line in runner(["ifconfig", "-l"]).split():
        if line == interface or line.startswith(("lo", "utun", "awdl", "llw", "bridge")):
            continue
        if _macos_inet(runner, line) is not None:
            others.append(line)
    if others:
        raise DetectError(SEVERAL_NETWORKS, ", ".join(sorted([interface, *others])))

    found = _macos_inet(runner, interface)
    if found is None:
        raise DetectError(NO_NETWORK, f"{interface} has no IPv4 address")
    address, mask = found
    return _network(interface, f"{address}/{mask}", _clean_gateway(gateway))


def _macos_inet(runner: Runner, interface: str) -> tuple[str, str] | None:
    try:
        text = runner(["ifconfig", interface])
    except DetectError:
        return None
    for address, mask in _INET.findall(text):
        ip = ipaddress.ip_address(address)
        if not (ip.is_loopback or ip.is_link_local):
            return address, str(ipaddress.IPv4Address(int(mask, 16)))
    return None


def _clean_gateway(gateway: str) -> str:
    return gateway.split("%")[0]  # drop a zone suffix such as "%en0"


# --- shared --------------------------------------------------------------------------


def _network(interface: str, cidr: str, gateway: str) -> Network:
    try:
        iface = ipaddress.ip_interface(cidr)
        ipaddress.ip_address(gateway)
    except ValueError as exc:
        raise DetectError(DETECT_FAILED, str(exc)) from exc
    return Network(
        interface=interface,
        address=str(iface.ip),
        subnet=str(iface.network),
        gateway=gateway,
    )


def _json(text: str) -> list[dict]:
    try:
        data = json.loads(text or "[]")
    except ValueError as exc:
        raise DetectError(DETECT_FAILED, f"unreadable ip output: {exc}") from exc
    return data if isinstance(data, list) else []
