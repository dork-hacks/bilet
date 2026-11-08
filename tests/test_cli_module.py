"""Exercise actual module dispatch without touching the network."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tool import __version__

ROOT = Path(__file__).resolve().parents[1]


def run_module(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(  # noqa: S603 - fixed Python module, offline arguments only
        [sys.executable, "-m", "tool.cli", *args],
        env=env,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )


@pytest.mark.parametrize("lang", ["ro", "en"])
def test_module_help_and_version(lang):
    help_result = run_module("--lang", lang, "--help")
    assert help_result.returncode == 0
    assert "COMMAND" in help_result.stdout
    assert not help_result.stderr
    version = run_module("--version")
    assert version.returncode == 0
    assert version.stdout.strip() == f"tool {__version__}"


def test_module_invalid_command_exit_code():
    result = run_module("--lang", "en", "not-a-command")
    assert result.returncode == 2
    assert "invalid choice" in result.stderr


def test_module_offline_analyze_exports_standard_csvs(tmp_path):
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("offline analyze intentionally refuses root")
    fixtures = ROOT / "tests" / "fixtures" / "validation"
    out = tmp_path / "out"
    result = run_module("analyze", str(fixtures), "--out", str(out))
    assert result.returncode == 0, result.stderr
    for name in ("findings.csv", "scores.csv"):
        assert (out / name).read_bytes() == (fixtures / f"expected_{name}").read_bytes()
