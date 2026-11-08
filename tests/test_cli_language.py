"""Language changes human text only, including argparse's early exits."""

from pathlib import Path

import pytest

from tool.cli import COMMANDS, HANDLERS, main, selected_language
from tool.network import DetectError, Network

VALIDATION = Path(__file__).parent / "fixtures" / "validation"


@pytest.mark.parametrize("command", [None, *COMMANDS])
@pytest.mark.parametrize("lang", ["ro", "en"])
@pytest.mark.parametrize("after", [False, True])
def test_help_language(capsys, command, lang, after):
    argv = [command] if command else []
    argv = argv + ["--lang", lang] if after else ["--lang", lang] + argv
    # Language also works after --help, before argparse's early exit.
    argv = [*argv, "--help"] if not after else [*argv[:-2], "--help", *argv[-2:]]
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert out.startswith("utilizare: " if lang == "ro" else "usage: ")
    assert ("arată acest ajutor" if lang == "ro" else "show this help") in out
    assert "--lang {ro,en}" in out
    if lang == "ro":
        for english in ("positional arguments", "options:", "show this", "default:"):
            assert english not in out


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [
        ([], [], "ro"),
        (["--lang", "en"], [], "en"),
        ([], ["--lang=en"], "en"),
        (["--lang=en"], ["--lang", "ro"], "ro"),
        (["--lang", "ro"], ["--lang=en", "--lang=ro", "--lang=en"], "en"),
    ],
)
def test_language_reaches_every_handler(monkeypatch, command, before, after, expected):
    seen = []
    monkeypatch.setitem(HANDLERS, command, lambda args: seen.append(args.lang) or 7)
    positional = ["folder"] if command == "analyze" else []
    assert main([*before, command, *positional, *after]) == 7
    assert seen == [expected]


def test_language_selector_honours_end_of_options():
    assert selected_language(["scan", "--", "--lang=en"]) == "ro"


@pytest.mark.parametrize(
    ("argv", "ro", "en"),
    [
        (["frobnicate"], "valoare nevalidă", "invalid choice"),
        (["analyze"], "sunt obligatorii", "are required"),
        (["detect", "--bad"], "nerecunoscute", "unrecognized arguments"),
        (["detect", "--lang", "fr"], "valoare nevalidă", "invalid choice"),
        (["detect", "--lang"], "se așteaptă un argument", "expected one argument"),
        (["serve", "--port", "nope"], "număr întreg nevalid", "invalid int value"),
        (["detect", "--json=yes"], "neacceptată", "ignored explicit argument"),
        (["serve", "--h", "x"], "opțiune ambiguă", "ambiguous option"),
    ],
)
@pytest.mark.parametrize("lang", ["ro", "en"])
def test_parser_errors(capsys, argv, ro, en, lang):
    with pytest.raises(SystemExit) as exc:
        main(["--lang", lang, *argv])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert (ro if lang == "ro" else en) in err
    assert ("eroare:" if lang == "ro" else "error:") in err


@pytest.mark.parametrize("lang", ["ro", "en"])
def test_missing_folder(capsys, tmp_path, lang):
    folder = tmp_path / "not a folder"
    assert main(["--lang", lang, "analyze", str(folder)]) == 2
    err = capsys.readouterr().err
    assert str(folder) in err
    assert ("nu este un dosar" if lang == "ro" else "not a folder") in err


@pytest.mark.parametrize("lang", ["ro", "en"])
def test_totals_and_history(tmp_path, monkeypatch, capsys, lang):
    monkeypatch.setenv("TOOL_DATA_DIR", str(tmp_path / "data"))
    assert (
        main(["--lang", lang, "analyze", str(VALIDATION), "--out", str(tmp_path / "out"), "--save"])
        == 0
    )
    captured = capsys.readouterr()
    assert (
        "8 fișiere, 24 constatări, 1 imposibil de citit"
        if lang == "ro"
        else "8 files, 24 findings, 1 unreadable"
    ) in captured.out
    assert ("S-au salvat 8 verificări" if lang == "ro" else "saved 8 scans") in captured.out
    assert "V7_broken.xml" in captured.err and "NOT_XML" in captured.err


def test_analyze_exports_are_identical_across_languages(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("TOOL_DATA_DIR", str(tmp_path / "data"))
    outputs = []
    for lang in ("ro", "en"):
        out = tmp_path / lang
        assert main(["analyze", str(VALIDATION), "--lang", lang, "--out", str(out), "--json"]) == 0
        outputs.append(
            {str(p.relative_to(out)): p.read_bytes() for p in out.rglob("*") if p.is_file()}
        )
    capsys.readouterr()
    assert outputs[0] == outputs[1]
    for name in ("findings.csv", "scores.csv"):
        assert outputs[0][name] == (VALIDATION / f"expected_{name}").read_bytes()


@pytest.mark.parametrize("failure", [False, True])
def test_detect_json_is_identical_across_languages(monkeypatch, capsys, failure):
    def detect():
        if failure:
            raise DetectError("DETECT_FAILED", "technical detail")
        return Network("eth0", "192.168.1.2", "192.168.1.0/24", "192.168.1.1")

    monkeypatch.setattr("tool.network.detect", detect)
    outputs = []
    for lang in ("ro", "en"):
        assert main(["--lang", lang, "detect", "--json"]) == int(failure)
        outputs.append(capsys.readouterr())
    assert outputs[0] == outputs[1]
    assert not outputs[0].err


@pytest.mark.parametrize("lang", ["ro", "en"])
def test_serve_root_refusal(monkeypatch, capsys, lang):
    monkeypatch.setattr("tool.cli.os.geteuid", lambda: 0)
    assert main(["serve", "--lang", lang]) == 2
    err = capsys.readouterr().err
    assert ("utilizator obișnuit" if lang == "ro" else "normal user") in err


@pytest.mark.parametrize("lang", ["ro", "en"])
@pytest.mark.parametrize("options", [[], ["--save"], ["--json"], ["--save", "--json"]])
def test_analyze_root_refusal_precedes_all_data_writes(
    monkeypatch, capsys, tmp_path, lang, options
):
    monkeypatch.setattr("tool.cli.os.geteuid", lambda: 0)
    data, out = tmp_path / "data", tmp_path / "out"
    monkeypatch.setenv("TOOL_DATA_DIR", str(data))

    def unexpected(*args, **kwargs):
        pytest.fail("root refusal must precede salt/history/export access")

    monkeypatch.setattr("tool.engine.device.load_salt", unexpected)
    monkeypatch.setattr("tool.export.analyze_folder", unexpected)
    assert main(["analyze", str(VALIDATION), "--out", str(out), "--lang", lang, *options]) == 2
    captured = capsys.readouterr()
    assert ("utilizator obișnuit" if lang == "ro" else "normal user") in captured.err
    assert not captured.out
    assert not data.exists()
    assert not out.exists()


def test_analyze_still_runs_as_normal_user(monkeypatch, tmp_path):
    monkeypatch.setattr("tool.cli.os.geteuid", lambda: 1000)
    out = tmp_path / "out"
    assert main(["analyze", str(VALIDATION), "--out", str(out)]) == 0
    for name in ("findings.csv", "scores.csv"):
        assert (out / name).read_bytes() == (VALIDATION / f"expected_{name}").read_bytes()
