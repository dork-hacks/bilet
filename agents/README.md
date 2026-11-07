# Worker loops

Claude (unchanged):

```bash
caffeinate -i agents/run-loop.sh agent-B ~/bilet-agents/agent-B
```

Codex (`codex login` and `gh auth login` must already work):

```bash
caffeinate -i agents/run-codex-loop.sh agent-G ~/bilet-agents/agent-G
```

Use a dedicated clone for each tag. The runner creates it if missing. Do not run an
interactive session and a loop under the same tag at the same time. Agent G continues
Eduard's backup assignment recorded in issue #1; Agent B's return does not grant G
permission to keep claiming B's work.

Each Codex tick runs `codex --approve-for-me exec --sandbox workspace-write --json`.
This requires a CLI version with `--approve-for-me` (check `codex --help`). Automatic
approval review can reject operations; a rejected action must be reported, never
bypassed. The Claude allowlist/denylist does not apply to Codex. Project instructions,
workspace sandbox, approval review and the shared pre-push hook still apply.

Both runners use the latest merged `agents/worker.md`, a per-tag lock, issue #1's
`agents:paused` label, timeouts and idle backoff. A startup snapshot protects a running
loop when the source checkout changes branches. Codex logs contain JSONL events,
stderr, a final readable report and token usage; they do not report dollar cost.
`TICK_BUDGET_USD` and `AGENT_EXTRA_TOOLS` are Claude settings (the dollar cap is refused
for Codex). `AGENT_MODEL` overrides the configured model only when provided.

Try one tick first:

```bash
ONE_TICK=1 caffeinate -i agents/run-codex-loop.sh agent-G ~/bilet-agents/agent-G
```

Stop with Ctrl+C, or from another terminal:

```bash
touch ~/.local/state/bilet-agents/agent-G/STOP
```

Logs: `~/.local/state/bilet-agents/agent-G/loop.log` and `logs/` (or the equivalent
under `XDG_STATE_HOME`). Other settings match `run-loop.sh`, including `MAX_HOURS`,
`TICK_TIMEOUT`, `INTERVAL_MIN`, `INTERVAL_MAX`, and `IDLE_STOP_TICKS`.
