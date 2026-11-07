import sqlite3
from pathlib import Path

import pytest

from tool.cli import main

VALIDATION = Path(__file__).parent / "fixtures" / "validation"


def break_history(folder: Path, how: str) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    db = folder / "history.sqlite3"
    if how == "newer":
        with sqlite3.connect(db) as conn:
            conn.execute("PRAGMA user_version = 99")
    else:
        db.write_bytes(b"this is not a database" * 100)


@pytest.mark.parametrize("how", ["newer", "corrupt"])
@pytest.mark.parametrize(("lang", "words"), [("en", "couldn't be updated"), ("ro", "nu a putut")])
def test_analyze_save_with_a_broken_history(tmp_path, monkeypatch, capsys, how, lang, words):
    # #132: the CSVs are written, the exit code is the same as without --save, no traceback.
    monkeypatch.setenv("TOOL_DATA_DIR", str(tmp_path / "data"))
    break_history(tmp_path / "data", how)
    out = tmp_path / "out"
    assert main(["analyze", str(VALIDATION), "--out", str(out), "--save", "--lang", lang]) == 0
    err = capsys.readouterr().err
    assert words in err and "Traceback" not in err
    assert (out / "findings.csv").read_bytes() == (
        VALIDATION / "expected_findings.csv"
    ).read_bytes()


def test_a_newer_history_is_left_untouched(tmp_path, monkeypatch):
    monkeypatch.setenv("TOOL_DATA_DIR", str(tmp_path / "data"))
    break_history(tmp_path / "data", "newer")
    before = (tmp_path / "data" / "history.sqlite3").read_bytes()
    main(["analyze", str(VALIDATION), "--out", str(tmp_path / "out"), "--save"])
    assert (tmp_path / "data" / "history.sqlite3").read_bytes() == before
