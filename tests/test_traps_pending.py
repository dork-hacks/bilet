"""The pending traps (#38) stay out of the golden test until #8 answers their questions,
but their answer keys must still say what the engine does today (#147). When a ruling
changes a default, change the engine and the CSV together, then move the file out of
pending/."""

import csv
from pathlib import Path

from tool.export import analyze_folder

PENDING = Path(__file__).parent / "fixtures" / "traps" / "pending"


def read_rows(path: Path) -> list[list[str]]:
    with path.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.reader(f))


def test_pending_traps_match_their_answer_keys_row_for_row(tmp_path):
    analyze_folder(PENDING, tmp_path)
    for name in ("findings.csv", "scores.csv"):
        assert read_rows(tmp_path / name) == read_rows(PENDING / f"expected_{name}"), name


def test_a_redirect_message_is_not_an_admin_title_until_8_says_otherwise(tmp_path):
    # #8 item 7: "Did not follow redirect to http://…/login.htm" contains "login".
    analyze_folder(PENDING, tmp_path)
    p06 = [r for r in read_rows(tmp_path / "findings.csv") if r[0].startswith("P06_")]
    assert p06 == []
    assert ["P06_http_title_edge_cases.xml", "100"] in read_rows(tmp_path / "scores.csv")
