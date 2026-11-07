"""Scan guardrail (FR-02): what the live scan may touch. Demonstrated live to the jury.

A target is scanned only if every check passes, in this order:
1. it is an address or a CIDR range, never a name (a name can resolve anywhere);
2. it is not loopback, link-local, multicast, the mobile operator's 100.64.0.0/10 or
   any other non-home range: only RFC 1918 (10/8, 172.16/12, 192.168/16) and IPv6 ULA
   (fc00::/7) count, because Python's `is_private` also admits test and benchmark nets;
3. it covers at most 256 addresses (a /24);
4. it lies inside the allowlist: by default the subnet this computer is on (detect,
   #19), plus extra ranges only when configured explicitly;
5. and the user passed --confirm.

Refusals carry a code; the RO/EN text for each comes from tool.content.
"""

import ipaddress
import os
import re
from collections.abc import Iterable

Network = ipaddress.IPv4Network | ipaddress.IPv6Network

PUBLIC_ADDRESS = "PUBLIC_ADDRESS"
CGNAT_ADDRESS = "CGNAT_ADDRESS"
LOOPBACK_ADDRESS = "LOOPBACK_ADDRESS"
LINK_LOCAL_ADDRESS = "LINK_LOCAL_ADDRESS"
MULTICAST_ADDRESS = "MULTICAST_ADDRESS"
HOSTNAME_NOT_ALLOWED = "HOSTNAME_NOT_ALLOWED"
RANGE_TOO_LARGE = "RANGE_TOO_LARGE"
OUTSIDE_ALLOWLIST = "OUTSIDE_ALLOWLIST"
CONFIRM_REQUIRED = "CONFIRM_REQUIRED"
INVALID_TARGET = "INVALID_TARGET"

MAX_ADDRESSES = 256  # a /24
ALLOWLIST_ENV = "TOOL_SCAN_ALLOWLIST"  # extra ranges, comma-separated; empty by default

HOME_RANGES: tuple[Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)
CGNAT = ipaddress.ip_network("100.64.0.0/10")

_NAME = re.compile(r"[a-z]", re.IGNORECASE)


class Refused(Exception):
    def __init__(self, code: str, target: str):
        super().__init__(f"{code}: {target}")
        self.code = code
        self.target = target


def parse_target(text: str) -> Network:
    """An address or CIDR range. A host address becomes a /32 (or /128)."""
    target = (text or "").strip()
    if not target:
        raise Refused(INVALID_TARGET, text or "")
    try:
        return ipaddress.ip_network(target, strict=False)
    except ValueError:
        pass
    # Letters that don't parse as IPv6 mean a name ("router.lan", "example.com").
    if _NAME.search(target) and ":" not in target:
        raise Refused(HOSTNAME_NOT_ALLOWED, target)
    raise Refused(INVALID_TARGET, target)


def check_range(net: Network, label: str | None = None) -> Network:
    """Rules 2 and 3: a home range of at most 256 addresses, or Refused."""
    label = label or str(net)
    if net.is_loopback:
        raise Refused(LOOPBACK_ADDRESS, label)
    if net.is_link_local:
        raise Refused(LINK_LOCAL_ADDRESS, label)
    if net.is_multicast:
        raise Refused(MULTICAST_ADDRESS, label)
    if net.version == 4 and net.overlaps(CGNAT):
        raise Refused(CGNAT_ADDRESS, label)
    if net.is_unspecified or net.is_reserved:
        raise Refused(INVALID_TARGET, label)
    if not any(net.version == home.version and net.subnet_of(home) for home in HOME_RANGES):
        raise Refused(PUBLIC_ADDRESS, label)
    if net.num_addresses > MAX_ADDRESSES:
        raise Refused(RANGE_TOO_LARGE, label)
    return net


def build_allowlist(connected_subnet: str | None, extra: Iterable[str] = ()) -> list[Network]:
    """The connected subnet plus explicitly configured ranges, each checked like a target.

    If the computer sits on a network larger than a /24 (a venue or office network),
    the default allowlist itself is refused, so nothing can be scanned from there.
    """
    allowlist: list[Network] = []
    for entry in ([connected_subnet] if connected_subnet else []) + list(extra):
        allowlist.append(check_range(parse_target(entry), entry))
    return allowlist


def extra_ranges_from_env(env: dict[str, str] | None = None) -> list[str]:
    raw = (env if env is not None else os.environ).get(ALLOWLIST_ENV) or ""
    return [part.strip() for part in raw.split(",") if part.strip()]


def check_target(text: str, allowlist: list[Network]) -> Network:
    """Rules 1-4 for one target. Returns the network to scan, or raises Refused."""
    net = check_range(parse_target(text), text.strip())
    if not any(net.version == allowed.version and net.subnet_of(allowed) for allowed in allowlist):
        raise Refused(OUTSIDE_ALLOWLIST, text.strip())
    return net


def authorize(targets: list[str], allowlist: list[Network], confirm: bool) -> list[Network]:
    """All of rules 1-5 for a scan request. Every target must pass, or nothing is scanned."""
    networks = [check_target(t, allowlist) for t in targets]
    if not networks:
        raise Refused(INVALID_TARGET, "")
    if not confirm:
        raise Refused(CONFIRM_REQUIRED, ", ".join(str(n) for n in networks))
    return networks
