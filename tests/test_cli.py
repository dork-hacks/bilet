import pytest

from tool import __version__
from tool.cli import COMMANDS, main


def test_no_command_prints_help(capsys):
    assert main([]) == 0
    assert "COMMAND" in capsys.readouterr().out


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


@pytest.mark.parametrize("command", sorted(set(COMMANDS) - {"serve", "detect"}))
def test_unimplemented_commands_fail_clearly(command, capsys):
    assert main([command]) == 2
    assert "not implemented yet" in capsys.readouterr().err
