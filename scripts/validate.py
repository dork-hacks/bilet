"""Golden test (`make validate`): the CSV export against every answer key we have.

For each fixture folder that holds expected_findings.csv and expected_scores.csv:
  - analyse the folder twice, exactly as `tool analyze` does;
  - the two runs must be byte-identical (NFR-05);
  - every row must match the answer key: no missing row, no extra row, the same order;
  - for the organizers' Validation Set the files must also be byte-identical to theirs.
Some trap files are too big to commit (T26 is over the 20 MiB limit): they are generated
into a temporary copy of their folder, and their expected row is added to that copy.
Prints what differs and exits 1 on any failure, so CI shows the reason.
"""

import csv
import io
import shutil
import subprocess  # noqa: S404 - a fixed argv: the repo's own generator, run isolated
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
    FIXTURES / "lab": False,  # our own lab captures (#34): the before/after pair
}
SALT = b"golden"  # the CSVs contain no device keys; any fixed salt will do
# folder -> files generated at test time: (generator script, file it writes, expected score)
GENERATED = {
    FIXTURES / "traps": [("make_oversized.py", "T26_oversized.xml", "ERROR")],
}


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


def with_generated(folder: Path, tmp: Path) -> tuple[Path, dict[str, bytes]]:
    """The folder to analyse and its answer key, with generated files added if it has any.

    The repo is never touched: the scan files and the answer key are copied to `tmp`,
    each generator writes its file there, and its expected score row is added."""
    expected = {n: (folder / f"expected_{n}").read_bytes() for n in ("findings.csv", "scores.csv")}
    generated = GENERATED.get(folder, [])
    if not generated:
        return folder, expected
    work = tmp / "input"
    work.mkdir()
    for path in folder.glob("*.xml"):
        shutil.copy2(path, work / path.name)
    score_rows = rows(expected["scores.csv"])
    for script, name, score in generated:
        subprocess.run(  # noqa: S603
            [sys.executable, "-I", str(folder / script), "--out", str(work)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        if not (work / name).exists():
            raise SystemExit(f"{script} did not write {name}")
        score_rows.append((name, score))
    header, body = score_rows[0], sorted(score_rows[1:], key=lambda r: r[0])
    eol = "\r\n" if b"\r\n" in expected["scores.csv"] else "\n"
    expected["scores.csv"] = "".join(",".join(r) + eol for r in [header, *body]).encode()
    return work, expected


def check(folder: Path, exact: bool) -> list[str]:
    with tempfile.TemporaryDirectory() as tmp:
        source, expected = with_generated(folder, Path(tmp))
        first, second = Path(tmp) / "1", Path(tmp) / "2"
        analyze_folder(source, first, salt=SALT)
        analyze_folder(source, second, salt=SALT)
        problems = []
        for name in ("findings.csv", "scores.csv"):
            got = (first / name).read_bytes()
            if got != (second / name).read_bytes():
                problems.append(f"  {name}: two runs differ (not deterministic)")
            problems += compare(name, expected[name], got, exact)
        return problems


def main() -> int:
    failed = False
    for folder, exact in GOLDEN.items():
        if not (folder / "expected_findings.csv").exists():
            print(f"skip {folder.relative_to(ROOT)} (no answer key yet)")
            continue
        problems = check(folder, exact)
        status = "FAIL" if problems else "ok"
        extra = [name for _, name, _ in GENERATED.get(folder, [])]
        note = f" (+ generated {', '.join(extra)})" if extra else ""
        print(f"{status:4} {folder.relative_to(ROOT)}{note}")
        for line in problems:
            print(line)
        failed |= bool(problems)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
