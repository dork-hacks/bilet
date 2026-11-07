"""Apply the catalog rules to parsed hosts. Deterministic: no LLM, no randomness."""

from dataclasses import dataclass

from tool.engine.catalog import (
    ADMIN_TITLE_WORDS,
    CATALOG,
    HTTP_SERVICE,
    SERVICE_RULES,
    SMB_PREFERRED_PORTS,
    SMB_SERVICES,
    CatalogEntry,
)
from tool.engine.parser import RawHost, RawPort


@dataclass(frozen=True)
class Hit:
    """One catalog match on a host. `port` is None for host-level findings (UNKNOWN_DEVICE)."""

    entry: CatalogEntry
    port: RawPort | None


def host_hits(host: RawHost) -> list[Hit]:
    """Every catalog finding for one host."""
    return service_hits(host) + http_admin_hits(host) + smb_hits(host) + unknown_device_hits(host)


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
    if not smb:
        return []
    preferred = [p for number in SMB_PREFERRED_PORTS for p in smb if p.port == number]
    chosen = preferred[0] if preferred else min(smb, key=lambda p: (p.port, p.protocol))
    return [Hit(CATALOG["SMB_EXPOSED"], chosen)]


def unknown_device_hits(host: RawHost) -> list[Hit]:
    """No MAC vendor, no hostname and at least one open port. A host-level finding."""
    if host.vendor is None and not host.hostnames and host.ports:
        return [Hit(CATALOG["UNKNOWN_DEVICE"], None)]
    return []


def _name(port: RawPort) -> str:
    return (port.service_name or "").lower()
