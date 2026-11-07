"""Near-miss report (`make near-misses DIR=...`): Test Set cases a human should double-check.

For every nmap XML file in a folder, list what sits right next to a catalog rule, where
the engine's answer rests on a reading of the brief:
  - service names close to a catalog name but not exact (http-proxy, https, ssl/http,
    names ending in "?", microsoft-ds variants), and catalog ports with another name;
  - catalog services that nmap only guessed from the port number (method="table");
  - products on the outdated list whose version is missing, unreadable or a range;
  - UNKNOWN_DEVICE hosts with only one open port, and vendors such as "Unknown";
  - open|filtered ports with catalog names (only "open" counts);
  - hosts without an IPv4 address;
  - http titles that almost match an admin keyword, or match only inside a longer word.
It also names the files `tool analyze` skips and why each unreadable file is unreadable.

Read-only: it uses the engine's own parser and rules, writes nothing and never changes a
finding. The ENGINE column is what `tool analyze` reports at that place; settle each line
against the brief's catalog (docs/test-set-runbook.md, step 7).
"""

import ipaddress
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import defusedxml.ElementTree as SafeET

from tool.engine.catalog import (
    ADMIN_TITLE_WORDS,
    HTTP_SERVICE,
    OUTDATED_RULES,
    SERVICE_RULES,
    SMB_SERVICES,
)
from tool.engine.parser import ParseError, RawHost, RawPort, _raw, _valid_ip, parse_file
from tool.engine.result import build_result
from tool.engine.rules import Hit, host_hits, is_outdated
from tool.export import scan_files

CATALOG_NAMES = (
    frozenset().union(*(rule.services for rule in SERVICE_RULES)) | SMB_SERVICES | {HTTP_SERVICE}
)
UDP_ONLY_NAMES = frozenset().union(
    *(rule.services for rule in SERVICE_RULES if rule.protocols == {"udp"})
)

# Other names nmap (or an older nmap) uses for a catalog service.
ALIASES = {
    "https": "http",
    "ftps": "ftp",
    "telnets": "telnet",
    "smb": "microsoft-ds",
    "ibm-mqisdp": "mqtt",
    "mqtts": "mqtt",
    "postgres": "postgresql",
    "mongod": "mongodb",
    "rtsps": "rtsp",
    "ssdp": "upnp",
    "pdl-datastream": "jetdirect",
    "ms-term-serv": "ms-wbt-server",
}

# The usual port of each catalog service: another name there deserves a look.
CATALOG_PORTS = {
    ("tcp", 21): "ftp",
    ("tcp", 22): "ssh",
    ("tcp", 23): "telnet",
    ("tcp", 139): "netbios-ssn",
    ("tcp", 445): "microsoft-ds",
    ("tcp", 554): "rtsp",
    ("tcp", 1883): "mqtt",
    ("tcp", 3306): "mysql",
    ("tcp", 3389): "ms-wbt-server",
    ("tcp", 5432): "postgresql",
    ("tcp", 5900): "vnc",
    ("tcp", 6379): "redis",
    ("tcp", 9100): "jetdirect",
    ("tcp", 27017): "mongodb",
    ("udp", 161): "snmp",
    ("udp", 1900): "upnp",
}

# Words that mean "admin or login page" but contain none of the catalog's keywords.
NEAR_TITLE_WORDS = (
    "log in",
    "log-in",
    "logon",
    "log on",
    "sign in",
    "sign-in",
    "signin",
    "password",
    "auth",
    "manage",
    "control panel",
    "console",
    "dashboard",
    "portal",
    "webui",
    "web ui",
    "gateway",
    "modem",
    "set up",
    "set-up",
    "preferences",
    "autentificare",
    "conectare",
    "administrare",
    "setări",
    "setari",
    "parola",
    "anmelden",
    "connexion",
)
NOT_A_TITLE = "did not follow redirect"
DETAIL_CHARS = 110
QUOTE_CHARS = 50

# Check name -> what it means and what the engine does about it (printed as a legend).
CHECKS = {
    "name-lookalike": "service name close to a catalog name; the engine needs the exact name",
    "ssl-tunnel": "catalog service behind SSL; http over SSL isn't cleartext, the others count",
    "catalog-port": "the usual port of a catalog service, but nmap names another service",
    "udp-only": "upnp and snmp count only on UDP; this one is on TCP",
    "table-guess": 'nmap guessed the name from the port number (method="table"); it counts (#8)',
    "version-unsure": "outdated-list product with no clear version; a range is judged by its "
    "upper bound (#8)",
    "unknown-1-port": "UNKNOWN_DEVICE that rests on a single open port",
    "vendor-text": 'the vendor is a placeholder such as "Unknown"; it still counts as a vendor',
    "open-filtered": 'catalog service whose port is "open|filtered"; only "open" counts',
    "no-ipv4": "host without an IPv4 address",
    "title-near": "http title that almost matches an admin keyword; titles match literally",
    "title-inside-word": "admin keyword found only inside a longer word; it still matches",
    "redirect-title": "http-title shows a redirect to a login-like URL instead of a title; "
    "a redirect isn't a title (#8)",
}


@dataclass(frozen=True)
class Item:
    ip: str
    where: str  # "80/tcp", or "-" for the host
    check: str
    engine: str
    detail: str


@dataclass
class FileReport:
    file: str
    error: str | None = None  # "CODE: detail" when unreadable
    score: int | None = None
    findings: int = 0
    items: list[Item] = field(default_factory=list)


def report_folder(folder: Path) -> tuple[list[FileReport], list[str]]:
    """One report per file `tool analyze` reads, plus the names of the files it skips."""
    files = scan_files(folder)
    read = {p.name for p in files}
    skipped = sorted(p.name for p in folder.iterdir() if p.name not in read)
    return [report_file(path) for path in files], skipped


def report_file(path: Path) -> FileReport:
    try:
        scan = parse_file(path)
    except ParseError as exc:
        detail = _raw(exc.detail, DETAIL_CHARS)
        return FileReport(path.name, error=f"{exc.code}: {detail}" if detail else exc.code)
    result = build_result(scan, salt=b"")
    report = FileReport(path.name, score=result.score, findings=len(result.findings))
    for host in scan.hosts:
        report.items += host_items(host)
    # Parsed only after parse_file accepted it, so it is within the size limit and safe.
    root = SafeET.fromstring(
        path.read_bytes(), forbid_dtd=False, forbid_entities=True, forbid_external=True
    )
    report.items += raw_items(root, {h.ip: h for h in scan.hosts})
    report.items.sort(key=lambda i: (_ip_key(i.ip), _where_key(i.where), i.check))
    return report


# --- checks on the parsed hosts (what the engine sees) ----------------------------------


def host_items(host: RawHost) -> list[Item]:
    hits = host_hits(host)
    items = []
    for port in host.ports:
        items += port_items(host, port, _engine(hits, port))
    host_codes = _engine(hits, None)
    if any(hit.entry.code == "UNKNOWN_DEVICE" for hit in hits) and len(host.ports) == 1:
        (port,) = host.ports
        items.append(
            Item(
                host.ip,
                "-",
                "unknown-1-port",
                host_codes,
                f"no vendor, no hostname, only {_where(port)} {_name(port) or '(no name)'} open",
            )
        )
    if (host.vendor or "").strip().lower() in ("unknown", "private") and host.ports:
        items.append(
            Item(
                host.ip,
                "-",
                "vendor-text",
                host_codes,
                f'vendor is "{host.vendor}"; hostnames: {len(host.hostnames)}',
            )
        )
    return items


def port_items(host: RawHost, port: RawPort, engine: str) -> list[Item]:
    def item(check: str, detail: str) -> Item:
        return Item(host.ip, _where(port), check, engine, detail)

    name, title = _name(port), port.http_title or ""
    admin = _admin_word(title)
    items = []

    target = lookalike(name)
    if target == HTTP_SERVICE:  # only matters when the page looks like an admin page
        if admin:
            items.append(
                item("name-lookalike", f'nmap says "{port.service_name}", title {_q(title)}')
            )
    elif target:
        items.append(
            item("name-lookalike", f'nmap says "{port.service_name}", close to "{target}"')
        )

    ssl = (port.tunnel or "").lower() == "ssl"
    if ssl and name == HTTP_SERVICE and admin:
        items.append(item("ssl-tunnel", f"http over SSL, title {_q(title)}"))
    elif ssl and name in CATALOG_NAMES and name != HTTP_SERVICE:
        items.append(item("ssl-tunnel", f'"{name}" with tunnel="ssl"'))

    usual = CATALOG_PORTS.get((port.protocol, port.port))
    if usual and name not in CATALOG_NAMES and target is None:
        items.append(
            item("catalog-port", f'usually "{usual}", nmap says "{port.service_name or ""}"')
        )

    if port.protocol == "tcp" and name in UDP_ONLY_NAMES:
        items.append(item("udp-only", f'"{name}" on TCP'))

    if (port.method or "").lower() == "table" and (name in CATALOG_NAMES or target):
        items.append(item("table-guess", f'"{port.service_name}" guessed from the port number'))

    unsure = version_doubt(port)
    if unsure:
        items.append(item("version-unsure", unsure))

    if name == HTTP_SERVICE and not ssl and title:
        if not admin:
            near = near_title_word(title)
            if near:
                items.append(item("title-near", f"title {_q(title)} has {_q(near)}"))
        else:
            inside = keyword_inside_word(title)
            if inside:
                items.append(item("title-inside-word", f"title {_q(title)}: {_q(inside)}"))
    return items


def lookalike(name: str) -> str | None:
    """The catalog name `name` resembles without being it, or None."""
    if not name or name in CATALOG_NAMES:
        return None
    base = name.removeprefix("ssl/").rstrip("?")
    if base != name and base in CATALOG_NAMES:
        return base
    if base in ALIASES:
        return ALIASES[base]
    return next((t for t in re.split(r"[-/_.]", base) if t in CATALOG_NAMES), None)


def version_doubt(port: RawPort) -> str | None:
    """Why the version of an outdated-list product deserves a look, or None."""
    product = (port.product or "").lower()
    if not any(rule.product in product for rule in OUTDATED_RULES):
        return None
    version = port.version or ""
    if not version:
        why = "no version"
    elif " - " in version or re.search(r"\d\.x\b", version.lower()):
        why = "a version range"
    elif not re.match(r"\d", version):
        why = "an unreadable version"
    else:
        return None
    verdict = "outdated" if is_outdated(port.product, port.version) else "not outdated"
    return f'{port.product} "{version}": {why}, engine says {verdict}'


def near_title_word(title: str) -> str | None:
    """A login/admin-like word that isn't a catalog keyword, or a near-typo of one."""
    lower = title.lower()
    word = next((w for w in NEAR_TITLE_WORDS if w in lower), None)
    if word:
        return word
    for token in re.findall(r"\w+", lower):
        for keyword in ADMIN_TITLE_WORDS:
            if len(token) >= 4 and _one_edit(token, keyword):
                return token
    return None


def keyword_inside_word(title: str) -> str | None:
    """A word that contains an admin keyword only in its middle or end, e.g. "Blogin"."""
    for token in re.findall(r"\w+", title):
        lower = token.lower()
        hits = [k for k in ADMIN_TITLE_WORDS if k in lower]
        if hits and not any(lower.startswith(k) for k in hits):
            return token
    return None


# --- checks on the raw XML (what the parser drops) --------------------------------------


def raw_items(root, parsed: dict[str, RawHost]) -> list[Item]:
    items = []
    for host_el in root.iter("host"):
        status = host_el.find("status")
        if status is not None and status.get("state") != "up":
            continue
        ipv4 = ipv6 = None
        for addr in host_el.findall("address"):
            kind, value = addr.get("addrtype"), addr.get("addr", "")
            if kind == "ipv4" and ipv4 is None:
                ipv4 = _valid_ip(value, 4)
            elif kind == "ipv6" and ipv6 is None:
                ipv6 = _valid_ip(value, 6)
        ip = ipv4 or ipv6 or "(none)"
        if ipv4 is None:
            if ipv6:
                host = parsed.get(ipv6)
                engine = _codes(host_hits(host)) if host else "no finding"
                detail = "IPv6 only: reported by its IPv6 address"
            else:
                engine, detail = "skipped", "no valid IP address at all: the engine skips it"
            items.append(Item(ip, "-", "no-ipv4", engine, detail))
        for port_el in host_el.findall("ports/port"):
            items += raw_port_items(ip, port_el)
    return items


def raw_port_items(ip: str, port_el) -> list[Item]:
    state_el = port_el.find("state")
    state = state_el.get("state") if state_el is not None else None
    where = f"{port_el.get('portid')}/{port_el.get('protocol')}"
    service = port_el.find("service")
    name = ((service.get("name") if service is not None else "") or "").lower()
    items = []
    if state == "open|filtered" and (name in CATALOG_NAMES or lookalike(name)):
        items.append(Item(ip, where, "open-filtered", "no finding", f'"{name}" is open|filtered'))
    if state == "open":
        for script in port_el.findall("script"):
            output = _raw(script.get("output")) or ""
            if script.get("id") == "http-title" and output.lower().startswith(NOT_A_TITLE):
                if _admin_word(output) or near_title_word(output):
                    items.append(
                        Item(ip, where, "redirect-title", "not a title", f"output {_q(output)}")
                    )
    return items


# --- output -----------------------------------------------------------------------------


def render(reports: list[FileReport], skipped: list[str]) -> str:
    lines = []
    seen_checks: set[str] = set()
    for rep in reports:
        if rep.error:
            lines.append(f"{rep.file}: ERROR ({rep.error})")
            lines.append("  Check by hand that it really can't be read (step 6 of the runbook).")
            lines.append("")
            continue
        count = f"{len(rep.items)} to check" if rep.items else "nothing to check"
        lines.append(f"{rep.file}: {rep.findings} findings, score {rep.score}, {count}")
        if rep.items:
            lines += _table(rep.items)
            seen_checks.update(i.check for i in rep.items)
        lines.append("")
    for name in skipped:
        lines.append(f"{name}: not analysed (tool analyze reads only visible .xml files)")
    if skipped:
        lines.append("")
    items = sum(len(r.items) for r in reports)
    errors = sum(1 for r in reports if r.error)
    lines.append(
        f"{len(reports)} files, {errors} unreadable, {items} items to check, "
        f"{len(skipped)} skipped"
    )
    if seen_checks:
        lines.append("")
        lines.append("Checks:")
        width = max(len(c) for c in seen_checks)
        lines += [f"  {c:<{width}}  {CHECKS[c]}" for c in CHECKS if c in seen_checks]
    return "\n".join(lines) + "\n"


def _table(items: list[Item]) -> list[str]:
    head = ("IP", "PORT", "CHECK", "ENGINE", "DETAIL")
    rows = [(i.ip, i.where, i.check, i.engine, _cut(i.detail, DETAIL_CHARS)) for i in items]
    widths = [max(len(r[n]) for r in [head, *rows]) for n in range(4)]
    return [
        "  " + "  ".join(c.ljust(w) for c, w in zip(row[:4], widths, strict=True)) + "  " + row[4]
        for row in [head, *rows]
    ]


# --- helpers ----------------------------------------------------------------------------


def _engine(hits: list[Hit], port: RawPort | None) -> str:
    """The codes the engine reports at `port` (None: the host-level ones)."""
    return _codes(h for h in hits if h.port is port)


def _codes(hits) -> str:
    codes = sorted({h.entry.code for h in hits})
    return "+".join(codes) if codes else "no finding"


def _admin_word(text: str) -> str | None:
    lower = text.lower()
    return next((w for w in ADMIN_TITLE_WORDS if w in lower), None)


def _one_edit(a: str, b: str) -> bool:
    """True if `a` and `b` differ by exactly one insertion, deletion or substitution."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b, strict=True)) == 1
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    return any(long_[:i] + long_[i + 1 :] == short for i in range(len(long_)))


def _name(port: RawPort) -> str:
    return (port.service_name or "").lower()


def _where(port: RawPort) -> str:
    return f"{port.port}/{port.protocol}"


def _q(text: str) -> str:
    return f'"{_cut(text, QUOTE_CHARS)}"'


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _ip_key(ip: str) -> tuple:
    try:
        addr = ipaddress.ip_address(ip)
        return (addr.version, int(addr))
    except ValueError:
        return (9, 0)


def _where_key(where: str) -> tuple:
    number, _, proto = where.partition("/")
    return (0, 0, "") if where == "-" else (1, int(number) if number.isdigit() else 0, proto)


def main(argv: list[str]) -> int:
    if len(argv) != 1 or not Path(argv[0]).is_dir():
        print("usage: near_misses.py <folder of nmap XML files>", file=sys.stderr)
        return 2
    reports, skipped = report_folder(Path(argv[0]))
    sys.stdout.write(render(reports, skipped))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
