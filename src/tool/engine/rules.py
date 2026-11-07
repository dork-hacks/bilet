"""Apply the catalog rules to parsed hosts. Deterministic: no LLM, no randomness."""

import re
from dataclasses import dataclass

from tool.engine.catalog import (
    ADMIN_TITLE_WORDS,
    CATALOG,
    HTTP_SERVICE,
    OUTDATED_RULES,
    SERVICE_RULES,
    SMB_PREFERRED_PORTS,
    SMB_SERVICES,
    CatalogEntry,
    OutdatedRule,
)
from tool.engine.parser import RawHost, RawPort


@dataclass(frozen=True)
class Hit:
    """One catalog match on a host. `port` is None for host-level findings (UNKNOWN_DEVICE)."""

    entry: CatalogEntry
    port: RawPort | None


def host_hits(host: RawHost) -> list[Hit]:
    """Every catalog finding for one host."""
    return (
        service_hits(host)
        + http_admin_hits(host)
        + smb_hits(host)
        + outdated_hits(host)
        + unknown_device_hits(host)
    )


def service_hits(host: RawHost) -> list[Hit]:
    """Findings that are a plain service-name match, in the host's port order."""
    hits = []
    for port in host.ports:
        name = _name(port)
        for rule in SERVICE_RULES:
            if name in rule.services and (
                rule.protocols is None or port.protocol in rule.protocols
            ):
                hits.append(Hit(CATALOG[rule.code], port))
    return hits


def http_admin_hits(host: RawHost) -> list[Hit]:
    """Plain-HTTP port whose page title looks like an admin or login page."""
    return [
        Hit(CATALOG["HTTP_ADMIN_CLEARTEXT"], port)
        for port in host.ports
        if _name(port) == HTTP_SERVICE
        and (port.tunnel or "").lower() != "ssl"
        and any(word in (port.http_title or "").lower() for word in ADMIN_TITLE_WORDS)
    ]


def smb_hits(host: RawHost) -> list[Hit]:
    """One SMB finding per device: on 445 if open, else 139, else the lowest SMB port."""
    smb = [port for port in host.ports if _name(port) in SMB_SERVICES]
    return [Hit(CATALOG["SMB_EXPOSED"], _smb_port(smb))] if smb else []


def outdated_hits(host: RawHost) -> list[Hit]:
    """OUTDATED_SERVICE, in addition to the service's own finding (if it has one).

    One per outdated port, except SMB: like SMB_EXPOSED it is one per device, on the
    same port SMB_EXPOSED would use among the outdated SMB ports.
    """
    entry = CATALOG["OUTDATED_SERVICE"]
    outdated = [port for port in host.ports if is_outdated(port.product, port.version)]
    smb = [port for port in outdated if _name(port) in SMB_SERVICES]
    hits = [Hit(entry, port) for port in outdated if port not in smb]
    if smb:
        hits.append(Hit(entry, _smb_port(smb)))
    return hits


def is_outdated(product: str | None, version: str | None) -> bool:
    """True only when the product is on the outdated list and the version clearly matches."""
    name = (product or "").lower()
    rule = next((r for r in OUTDATED_RULES if r.product in name), None)
    if rule is None:
        return False
    numbers = _version_numbers(version, rule.parts)
    if numbers is None:
        return False  # missing or unreadable version: never guess
    return _compare(numbers, rule)


def unknown_device_hits(host: RawHost) -> list[Hit]:
    """No MAC vendor, no hostname and at least one open port. A host-level finding."""
    if host.vendor is None and not host.hostnames and host.ports:
        return [Hit(CATALOG["UNKNOWN_DEVICE"], None)]
    return []


def _smb_port(ports: list[RawPort]) -> RawPort:
    """445 if present, else 139, else the lowest port: the SMB_EXPOSED choice."""
    preferred = [p for number in SMB_PREFERRED_PORTS for p in ports if p.port == number]
    return preferred[0] if preferred else min(ports, key=lambda p: (p.port, p.protocol))


_LEADING_NUMBERS = re.compile(r"\d+(?:\.\d+)*")


def _version_numbers(version: str | None, parts: int) -> tuple[int, ...] | None:
    """The first `parts` numbers of a version, e.g. "7.2p2 Ubuntu" -> (7, 2).

    A range such as nmap's "3.X - 4.X" is judged by its upper bound, so it only counts
    as old when even the newest version it allows is old (#8 item 1 default).
    """
    if not version:
        return None
    text = version.split(" - ")[-1].strip()
    match = _LEADING_NUMBERS.match(text)
    if match is None:
        return None
    numbers = tuple(int(n) for n in match.group().split("."))
    return numbers[:parts] if len(numbers) >= parts else None


def _compare(numbers: tuple[int, ...], rule: OutdatedRule) -> bool:
    if rule.test == "eq":
        return numbers == rule.bound
    if rule.test == "lt":
        return numbers < rule.bound
    return numbers <= rule.bound


def _name(port: RawPort) -> str:
    return (port.service_name or "").lower()
