"""Golden test (`make validate`): the CSV export against every answer key we have.

For each fixture folder that holds expected_findings.csv and expected_scores.csv:
  - analyse the folder twice, exactly as `tool analyze` does;
  - the two runs must be byte-identical (NFR-05);
  - every row must match the answer key: no missing row, no extra row, the same order;
  - for the organizers' Validation Set the files must also be byte-identical to theirs.
Prints what differs and exits 1 on any failure, so CI shows the reason.
"""

import csv
import io
import sys
import tempfile
from pathlib import Path

from tool.export import analyze_folder

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
# folder -> must the CSVs be byte-identical to the answer key?
GOLDEN = {
    FIXTURES / "validation": True,  # the organizers' files, CRLF and all
    FIXTURES / "traps": False,  # our own traps (#23): rows must match, line ends may differ
}
SALT = b"golden"  # the CSVs contain no device keys; any fixed salt will do


def rows(data: bytes) -> list[tuple[str, ...]]:
    return [tuple(row) for row in csv.reader(io.StringIO(data.decode("utf-8-sig")))]


def compare(name: str, expected: bytes, got: bytes, exact: bool) -> list[str]:
    problems = []
    want, have = rows(expected), rows(got)
    for row in [r for r in want if r not in have]:
        problems.append(f"  missing {name}: {','.join(row)}")
    for row in [r for r in have if r not in want]:
        problems.append(f"  extra   {name}: {','.join(row)}")
    if not problems and want != have:
        problems.append(f"  {name}: same rows, different order")
    if not problems and exact and expected != got:
        problems.append(f"  {name}: same rows, but not byte-identical (line ends or encoding)")
    return problems


def check(folder: Path, exact: bool) -> list[str]:
    with tempfile.TemporaryDirectory() as tmp:
        first, second = Path(tmp) / "1", Path(tmp) / "2"
        analyze_folder(folder, first, salt=SALT)
        analyze_folder(folder, second, salt=SALT)
        problems = []
        for name in ("findings.csv", "scores.csv"):
            got = (first / name).read_bytes()
            if got != (second / name).read_bytes():
                problems.append(f"  {name}: two runs differ (not deterministic)")
            expected = (folder / f"expected_{name}").read_bytes()
            problems += compare(name, expected, got, exact)
        return problems


def main() -> int:
    failed = False
    for folder, exact in GOLDEN.items():
        if not (folder / "expected_findings.csv").exists():
            print(f"skip {folder.relative_to(ROOT)} (no answer key yet)")
            continue
        problems = check(folder, exact)
        status = "FAIL" if problems else "ok"
        print(f"{status:4} {folder.relative_to(ROOT)}")
        for line in problems:
            print(line)
        failed |= bool(problems)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
