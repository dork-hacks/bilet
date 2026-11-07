"""The official finding catalog (brief, Part B) as data. Change it only to match the brief."""

from dataclasses import dataclass

POINTS = {"high": 20, "medium": 10, "low": 5, "info": 0}


@dataclass(frozen=True)
class CatalogEntry:
    code: str
    severity: str  # "high" | "medium" | "low" | "info"

    @property
    def points(self) -> int:
        return POINTS[self.severity]


CATALOG: dict[str, CatalogEntry] = {
    e.code: e
    for e in (
        CatalogEntry("TELNET_OPEN", "high"),
        CatalogEntry("RDP_EXPOSED", "high"),
        CatalogEntry("VNC_EXPOSED", "high"),
        CatalogEntry("DB_EXPOSED", "high"),
        CatalogEntry("CAMERA_STREAM_EXPOSED", "high"),
        CatalogEntry("OUTDATED_SERVICE", "high"),
        CatalogEntry("FTP_CLEARTEXT", "medium"),
        CatalogEntry("HTTP_ADMIN_CLEARTEXT", "medium"),
        CatalogEntry("SMB_EXPOSED", "medium"),
        CatalogEntry("MQTT_EXPOSED", "medium"),
        CatalogEntry("UPNP_EXPOSED", "medium"),
        CatalogEntry("SNMP_EXPOSED", "medium"),
        CatalogEntry("PRINTER_RAW_EXPOSED", "low"),
        CatalogEntry("UNKNOWN_DEVICE", "low"),
        CatalogEntry("SSH_OPEN", "info"),
    )
}


@dataclass(frozen=True)
class ServiceRule:
    """Report `code` for every open port whose nmap service name is in `services`."""

    code: str
    services: frozenset[str]
    protocols: frozenset[str] | None = None  # None: any protocol


# Decided by the service name nmap reports, never by the port number alone.
SERVICE_RULES: tuple[ServiceRule, ...] = (
    ServiceRule("TELNET_OPEN", frozenset({"telnet"})),
    ServiceRule("RDP_EXPOSED", frozenset({"ms-wbt-server"})),
    ServiceRule("VNC_EXPOSED", frozenset({"vnc"})),
    ServiceRule("DB_EXPOSED", frozenset({"mysql", "postgresql", "redis", "mongodb"})),
    ServiceRule("CAMERA_STREAM_EXPOSED", frozenset({"rtsp"})),
    ServiceRule("FTP_CLEARTEXT", frozenset({"ftp"})),
    ServiceRule("MQTT_EXPOSED", frozenset({"mqtt"})),
    ServiceRule("UPNP_EXPOSED", frozenset({"upnp"}), frozenset({"udp"})),
    ServiceRule("SNMP_EXPOSED", frozenset({"snmp"}), frozenset({"udp"})),
    ServiceRule("PRINTER_RAW_EXPOSED", frozenset({"jetdirect"})),
    ServiceRule("SSH_OPEN", frozenset({"ssh"})),
)

# HTTP_ADMIN_CLEARTEXT: service exactly "http", no SSL tunnel, title contains one of these.
HTTP_SERVICE = "http"
ADMIN_TITLE_WORDS = ("login", "admin", "config", "setup", "router", "settings")

# SMB_EXPOSED: one finding per device, on the first of these ports that is open.
SMB_SERVICES = frozenset({"microsoft-ds", "netbios-ssn"})
SMB_PREFERRED_PORTS = (445, 139)
