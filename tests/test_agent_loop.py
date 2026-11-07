"""Exercise the real loop with fake GitHub and CLI commands; no agent/API calls."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "runtime,result", [("codex", "ACTIVE"), ("codex", "IDLE"), ("claude", "ACTIVE")]
)
def test_one_tick_uses_runtime_and_records_result(tmp_path, runtime, result):
    binary = tmp_path / "bin"
    binary.mkdir()
    work = tmp_path / "clone"
    (work / ".git/hooks").mkdir(parents=True)
    capture = tmp_path / "args.json"
    stubs = {
        "git": 'case "$*" in *"show origin/main:agents/worker.md"*) echo "Worker {{TAG}}";; esac',
        "gh": 'case "$*" in *"repo view"*) echo dork-hacks/bilet;; *) echo false;; esac',
    }
    for name, body in stubs.items():
        path = binary / name
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o755)
    for name in ("codex", "claude"):
        path = binary / name
        path.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "args = sys.argv[1:]\n"
            "Path(os.environ['CAPTURE']).write_text(json.dumps(args))\n"
            "message = 'TICK-RESULT: ' + os.environ['RESULT']\n"
            "if '--output-last-message' in args:\n"
            "    Path(args[args.index('--output-last-message') + 1]).write_text(message)\n"
            "    print(json.dumps({'type': 'turn.completed', 'usage': {'input_tokens': 10}}))\n"
            "else:\n"
            "    print(json.dumps({'result': message, 'num_turns': 1}))\n"
        )
        path.chmod(0o755)
    env = {
        **os.environ,
        "PATH": str(binary) + os.pathsep + os.environ["PATH"],
        "XDG_STATE_HOME": str(tmp_path / "state"),
        "AGENT_RUNTIME": runtime,
        "AGENT_MODEL": "",
        "TICK_BUDGET_USD": "",
        "AGENT_EXTRA_TOOLS": "",
        "ONE_TICK": "1",
        "CAPTURE": str(capture),
        "RESULT": result,
    }
    script = "run-codex-loop.sh" if runtime == "codex" else "run-loop.sh"
    completed = subprocess.run(  # noqa: S603 — fixed script, isolated stub commands
        ["/bin/bash", str(ROOT / "agents" / script), "agent-G", str(work)],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert completed.returncode == 0, completed.stderr
    args = json.loads(capture.read_text())
    assert f"result={result}" in completed.stdout
    state = tmp_path / "state/bilet-agents/agent-G"
    assert not (state / "lock").exists()
    assert (work / ".git/hooks/pre-push").exists()
    if runtime == "codex":
        assert args[:4] == ["--approve-for-me", "exec", "--sandbox", "workspace-write"]
        assert "--dangerously-bypass-approvals-and-sandbox" not in args
        assert "--allowedTools" not in args
        assert "tokens=" in completed.stdout
        assert "read AGENTS.md" in args[-1]
    else:
        assert args[0] == "-p"
        assert "--allowedTools" in args
