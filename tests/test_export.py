import json
import shutil
from pathlib import Path

import pytest

from tool.cli import main
from tool.export import analyze_folder, scan_files

VALIDATION = Path(__file__).parent / "fixtures" / "validation"


def test_validation_set_matches_the_answer_key_byte_for_byte(tmp_path):
    report = analyze_folder(VALIDATION, tmp_path)
    assert (tmp_path / "findings.csv").read_bytes() == (
        VALIDATION / "expected_findings.csv"
    ).read_bytes()
    assert (tmp_path / "scores.csv").read_bytes() == (
        VALIDATION / "expected_scores.csv"
    ).read_bytes()
    assert (report.files, report.findings) == (8, 24)
    assert report.errors == [("V7_broken.xml", "NOT_XML")]


def test_two_runs_are_byte_identical(tmp_path):
    analyze_folder(VALIDATION, tmp_path / "a")
    analyze_folder(VALIDATION, tmp_path / "b")
    for name in ("findings.csv", "scores.csv"):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()


def test_unreadable_files_become_error_rows_and_the_run_continues(tmp_path):
    folder = tmp_path / "scans"
    folder.mkdir()
    shutil.copy(VALIDATION / "V1_home_basic.xml", folder / "a_good.xml")
    (folder / "b_empty.xml").write_bytes(b"")
    (folder / "c_xxe.xml").write_text(
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>'
    )
    shutil.copy(VALIDATION / "V2_smart_home.xml", folder / "d_good.xml")
    report = analyze_folder(folder, tmp_path / "out")
    assert (tmp_path / "out" / "scores.csv").read_text().splitlines() == [
        "file,network_score",
        "a_good.xml,90",
        "b_empty.xml,ERROR",
        "c_xxe.xml,ERROR",
        "d_good.xml,40",
    ]
    assert report.errors == [("b_empty.xml", "EMPTY_FILE"), ("c_xxe.xml", "UNSAFE_XML")]


def test_unknown_device_has_an_empty_port_column(tmp_path):
    analyze_folder(VALIDATION, tmp_path)
    rows = (tmp_path / "findings.csv").read_text().splitlines()
    assert "V4_legacy.xml,192.168.1.99,,UNKNOWN_DEVICE,low" in rows


def test_only_visible_xml_files_are_read(tmp_path):
    folder = tmp_path / "scans"
    folder.mkdir()
    for name in ("b.xml", "A.XML", ".hidden.xml", "notes.txt", "c.xml.bak"):
        (folder / name).write_text("x")
    (folder / "sub").mkdir()
    (folder / "sub" / "deep.xml").write_text("x")
    assert [p.name for p in scan_files(folder)] == ["A.XML", "b.xml"]


def test_empty_folder_writes_headers_only(tmp_path):
    (tmp_path / "scans").mkdir()
    analyze_folder(tmp_path / "scans", tmp_path / "out")
    # Bytes, not read_text(): that would turn the CRLF line ends into \n.
    assert (tmp_path / "out" / "findings.csv").read_bytes() == (
        b"file,ip,port,finding_code,severity\r\n"
    )
    assert (tmp_path / "out" / "scores.csv").read_bytes() == b"file,network_score\r\n"


def test_no_temporary_files_are_left(tmp_path):
    analyze_folder(VALIDATION, tmp_path)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["findings.csv", "scores.csv"]


def test_csv_only_run_creates_no_private_data(tmp_path, monkeypatch):
    monkeypatch.setenv("TOOL_DATA_DIR", str(tmp_path / "data"))
    analyze_folder(VALIDATION, tmp_path / "out")
    assert not (tmp_path / "data").exists()  # no salt needed: CSVs hold no device keys


def test_json_option_writes_one_result_per_file(tmp_path, monkeypatch):
    monkeypatch.setenv("TOOL_DATA_DIR", str(tmp_path / "data"))
    analyze_folder(VALIDATION, tmp_path / "out", json_dir=tmp_path / "out" / "json")
    files = sorted(p.name for p in (tmp_path / "out" / "json").iterdir())
    assert len(files) == 8 and "V7_broken.json" in files
    v2 = json.loads((tmp_path / "out" / "json" / "V2_smart_home.json").read_text())
    assert v2["score"] == 40 and v2["schema_version"] == 1
    broken = json.loads((tmp_path / "out" / "json" / "V7_broken.json").read_text())
    assert broken["status"] == "error"
    assert (tmp_path / "data" / "device_key.salt").exists()  # JSON keys need the salt


# --- the command -----------------------------------------------------------------------


def test_analyze_command(tmp_path, capsys):
    assert main(["analyze", str(VALIDATION), "--out", str(tmp_path), "--lang", "en"]) == 0
    captured = capsys.readouterr()
    assert "8 files, 24 findings, 1 unreadable" in captured.out
    assert "V7_broken.xml" in captured.err and "NOT_XML" in captured.err
    assert (tmp_path / "findings.csv").exists()


@pytest.mark.parametrize("lang", ["ro", "en"])
def test_analyze_command_explains_broken_files_in_both_languages(tmp_path, capsys, lang):
    main(["analyze", str(VALIDATION), "--out", str(tmp_path), "--lang", lang])
    err = capsys.readouterr().err
    assert err.startswith("V7_broken.xml: ") and len(err.split(": ", 1)[1]) > 20


def test_analyze_command_missing_folder(tmp_path, capsys):
    assert main(["analyze", str(tmp_path / "nope"), "--out", str(tmp_path)]) == 2
    assert "not a folder" in capsys.readouterr().err
