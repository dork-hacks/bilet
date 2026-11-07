import pytest

from tool import __version__
from tool.cli import main


def test_no_command_prints_help(capsys):
    assert main([]) == 0
    assert "COMMAND" in capsys.readouterr().out


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


@pytest.mark.parametrize(
    ("argv0", "shown"),
    [("/x/.venv/bin/bilet", "bilet"), ("/x/.venv/bin/tool", "tool"), ("-c", "tool"), ("", "tool")],
)
def test_both_command_names_work_and_help_shows_the_one_typed(monkeypatch, capsys, argv0, shown):
    monkeypatch.setattr("sys.argv", [argv0])
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.startswith(f"{shown} ")
