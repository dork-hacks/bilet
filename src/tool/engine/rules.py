"""Apply the catalog rules to parsed hosts. Deterministic: no LLM, no randomness."""

from dataclasses import dataclass

from tool.engine.catalog import CATALOG, SERVICE_RULES, CatalogEntry
from tool.engine.parser import RawHost, RawPort


@dataclass(frozen=True)
class Hit:
    """One catalog match on a host. `port` is None for host-level findings (UNKNOWN_DEVICE)."""

    entry: CatalogEntry
    port: RawPort | None


def service_hits(host: RawHost) -> list[Hit]:
    """Findings that are a plain service-name match, in the host's port order."""
    hits = []
    for port in host.ports:
        name = (port.service_name or "").lower()
        for rule in SERVICE_RULES:
            if name in rule.services and (
                rule.protocols is None or port.protocol in rule.protocols
            ):
                hits.append(Hit(CATALOG[rule.code], port))
    return hits
