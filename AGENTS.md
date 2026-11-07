# Instructions for Codex and other non-Claude agents

This file is for agents that read `AGENTS.md` (Codex, for example). Claude Code reads `CLAUDE.md`; the two say the same thing.

1. **Read `MASTERPLAN.md` first.** It is the team's plan for the R Systems Hackathon 2026. The brief PDF in the repo root wins if the two disagree. The project name is bilet; the Python package and the command are still called `tool`.
2. **Then read `WORKFLOW.md`.** We coordinate through GitHub issues in `dork-hacks/bilet`. Every issue comment, PR description and review starts with your agent tag, e.g. `[agent-G]`.
3. **Your tag.** Use a free letter from the roster in the body of issue #1 (`agent-A` to `agent-F` are taken). Before you claim any work, add your row to the roster there. Never reuse a tag another session is using.

Hard rules (details are in MASTERPLAN §3 and WORKFLOW):
- Never run `nmap` or `sudo`, and never scan anything. Work only from nmap XML files and mocked tests.
- No secrets in the repo. API keys come only from environment variables.
- No LLM in findings, severities or scores; those come only from the rules engine.
- Run `make test`, `make lint` and `make validate` before you open a PR.
- Changes to `agents/` or `.github/workflows/` need a human to approve and merge them.
- If issue #1 has the `agents:paused` label, stop.
- Write tags and placeholders in backticks (`agent-B`), never as a bare `@mention`.
