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


def test_every_command_has_a_handler_and_reaches_it(monkeypatch):
    import tool.cli as cli

    assert cli.HANDLERS.keys() == cli.COMMANDS.keys()
    called = []
    for name in cli.COMMANDS:
        monkeypatch.setitem(cli.HANDLERS, name, lambda args, n=name: called.append(n) or 7)
    argv = {"analyze": ["analyze", "x"], "detect": ["detect"], "scan": ["scan"], "serve": ["serve"]}
    assert [main(argv[n]) for n in cli.COMMANDS] == [7] * len(cli.COMMANDS)
    assert called == list(cli.COMMANDS)


def test_an_unknown_command_is_rejected_by_argparse(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["frobnicate"])
    assert exc.value.code == 2
    assert "invalid choice" in capsys.readouterr().err
