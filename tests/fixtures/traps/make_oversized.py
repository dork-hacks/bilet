"""Write the oversized trap file (issue #23). The file itself is never committed.

The parser's size limit is 20 MiB (MAX_FILE_BYTES = 20 * 1024 * 1024 = 20,971,520 bytes,
from #10 and docs/contracts/data-model.md). This writes a file just over 21 MiB, so the
expected result is TOO_LARGE, which scores.csv shows as:

    T26_oversized.xml,ERROR

Apart from its size it is a valid nmap file with a telnet finding, so an engine that
skips the size check reports TELNET_OPEN and a score of 80 instead of ERROR.

Usage (Python 3.12, stdlib only):

    python3 tests/fixtures/traps/make_oversized.py            # into a new temp folder
    python3 tests/fixtures/traps/make_oversized.py --out DIR  # into DIR (keep it out of git)

It prints the path of the file it wrote.
"""

import argparse
import tempfile
from pathlib import Path

NAME = "T26_oversized.xml"
LIMIT_BYTES = 20 * 1024 * 1024
DEFAULT_BYTES = 21 * 1024 * 1024

HEAD = "\n".join(
    (
        '<?xml version="1.0" encoding="UTF-8"?>',
        "<!DOCTYPE nmaprun>",
        "<!-- Generated trap file for issue #23 (make_oversized.py)."
        " Trap: bigger than the 20 MiB limit. Must give ERROR. -->",
        '<nmaprun scanner="nmap" args="nmap -sS -sV -oX T26_oversized.xml 192.168.1.0/24"'
        ' start="1794057600" startstr="Sat Nov  7 13:20:00 2026" version="7.94SVN"'
        ' xmloutputversion="1.05">',
        '<scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>',
        '<host starttime="1794057602" endtime="1794057697">'
        '<status state="up" reason="arp-response" reason_ttl="0"/>',
        '<address addr="192.168.1.1" addrtype="ipv4"/>',
        '<address addr="50:C7:BF:00:00:01" addrtype="mac" vendor="Tp-link Technologies"/>',
        "<hostnames>",
        '<hostname name="router.lan" type="PTR"/>',
        "</hostnames>",
        "<ports>",
        '<port protocol="tcp" portid="23">'
        '<state state="open" reason="syn-ack" reason_ttl="64"/>'
        '<service name="telnet" product="BusyBox telnetd" method="probed" conf="10"/></port>',
        "</ports>",
        "</host>",
        "<!-- padding",
        "",
    )
)
PAD_LINE = "x" * 1023 + "\n"
TAIL = "\n".join(
    (
        "-->",
        '<runstats><finished time="1794057900" timestr="Sat Nov  7 13:25:00 2026"'
        ' elapsed="298.41" exit="success"/><hosts up="1" down="255" total="256"/>',
        "</runstats>",
        "</nmaprun>",
        "",
    )
)


def write_oversized(out_dir: Path, size: int = DEFAULT_BYTES) -> Path:
    if size <= LIMIT_BYTES:
        raise ValueError(f"size must be over the {LIMIT_BYTES}-byte limit")
    path = out_dir / NAME
    pad_lines = -(-(size - len(HEAD) - len(TAIL)) // len(PAD_LINE))  # round up
    with path.open("w", encoding="ascii", newline="\n") as fh:
        fh.write(HEAD)
        for _ in range(pad_lines):
            fh.write(PAD_LINE)
        fh.write(TAIL)
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, help="folder to write into (default: a temp folder)")
    parser.add_argument("--size", type=int, default=DEFAULT_BYTES, help="minimum size in bytes")
    args = parser.parse_args()
    out_dir = args.out or Path(tempfile.mkdtemp(prefix="traps-oversized-"))
    out_dir.mkdir(parents=True, exist_ok=True)
    path = write_oversized(out_dir, args.size)
    print(f"{path} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
