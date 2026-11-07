#!/usr/bin/env bash
# Codex equivalent of run-loop.sh. Uses automatic approval review, never sandbox bypass.
# Usage: caffeinate -i agents/run-codex-loop.sh agent-G ~/bilet-agents/agent-G
set -uo pipefail
export AGENT_RUNTIME=codex
exec bash "$(cd "$(dirname "$0")" && pwd)/run-loop.sh" "$@"
