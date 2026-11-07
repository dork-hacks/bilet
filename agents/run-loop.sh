#!/usr/bin/env bash
# Run one autonomous agent loop (WORKFLOW.md §10).
#
#   agents/run-loop.sh orchestrator orchestrator ~/bilet-agents/orchestrator
#   agents/run-loop.sh worker       agent-C      ~/bilet-agents/agent-C
#
# <workdir> is this agent's OWN clone of the repo. It is created if missing.
# Never point it at a checkout someone works in by hand.
#
# Each tick is a fresh headless `claude -p` session with an allowlist of tools.
# There is no permission bypass. All state lives in GitHub, so a killed tick loses nothing.
#
# Stop or pause:
#   - Add the label `agents:paused` to issue #1 to pause every loop, everywhere.
#     Remove it to resume.
#   - `touch ~/.local/state/bilet-agents/<tag>/STOP` stops this loop for good.
#   - Ctrl+C, or kill the PID in ~/.local/state/bilet-agents/<tag>/lock/pid.
#   - Loops also stop on their own after MAX_HOURS, or after IDLE_STOP_TICKS
#     idle ticks in a row.
set -uo pipefail

usage() { echo "usage: $0 <orchestrator|worker> <tag> <workdir>" >&2; exit 2; }
[[ $# -eq 3 ]] || usage
ROLE="$1"; TAG="$2"; WORKDIR="$3"
case "$ROLE" in orchestrator|worker) ;; *) usage ;; esac
[[ "$TAG" =~ ^(orchestrator|agent-[A-Z])$ ]] || { echo "tag must be 'orchestrator' or 'agent-<LETTER>'" >&2; exit 2; }

if [[ "$ROLE" == orchestrator ]]; then
  IDLE_STOP_DEFAULT=12
else
  IDLE_STOP_DEFAULT=8
fi
SYNC_ISSUE="${SYNC_ISSUE:-1}"
INTERVAL_MIN="${INTERVAL_MIN:-300}"            # seconds between ticks while active
INTERVAL_MAX="${INTERVAL_MAX:-1800}"           # idle backoff cap
IDLE_STOP_TICKS="${IDLE_STOP_TICKS:-$IDLE_STOP_DEFAULT}"
MAX_HOURS="${MAX_HOURS:-12}"
TICK_TIMEOUT="${TICK_TIMEOUT:-1500}"           # seconds before a tick is killed
AGENT_MODEL="${AGENT_MODEL:-}"                 # optional: --model
TICK_BUDGET_USD="${TICK_BUDGET_USD:-}"         # optional: --max-budget-usd per tick
AGENT_EXTRA_TOOLS="${AGENT_EXTRA_TOOLS:-}"     # optional: comma-separated, e.g. "Bash(docker:*)"
# ONE_TICK=1 runs a single tick and exits (for trying out a prompt change).

STATE="${XDG_STATE_HOME:-$HOME/.local/state}/bilet-agents/$TAG"
mkdir -p "$STATE/logs" "$STATE/bin"

# One loop per tag per machine. Take the lock once; exec keeps the same PID.
if [[ "${RUN_LOOP_SNAPSHOT:-}" != 1 ]]; then
  if ! mkdir "$STATE/lock" 2>/dev/null; then
    pid="$(cat "$STATE/lock/pid" 2>/dev/null || true)"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      echo "a loop for $TAG is already running (pid $pid)" >&2; exit 1
    fi
    rm -rf "$STATE/lock"; mkdir "$STATE/lock"
  fi
  echo $$ > "$STATE/lock/pid"
  rm -f "$STATE/STOP"
  # Run from a snapshot, so switching branches in the source checkout can't
  # change or delete this script while bash is still reading it.
  SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
  cp "$SRC_DIR/run-loop.sh" "$SRC_DIR/orchestrator.md" "$SRC_DIR/worker.md" "$STATE/bin/"
  ORIGIN_URL="$(git -C "$SRC_DIR" remote get-url origin 2>/dev/null || true)" \
    RUN_LOOP_SNAPSHOT=1 exec bash "$STATE/bin/run-loop.sh" "$@"
fi
trap 'rm -rf "$STATE/lock"' EXIT

log() { printf '%s [%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$TAG" "$*" | tee -a "$STATE/loop.log"; }

# The agent's own clone.
if [[ ! -d "$WORKDIR/.git" ]]; then
  url="${ORIGIN_URL:-}"
  [[ -n "$url" ]] || { echo "can't find the origin URL to clone; clone into $WORKDIR yourself" >&2; exit 1; }
  log "cloning $url into $WORKDIR"
  git clone -q "$url" "$WORKDIR" || exit 1
fi
WORKDIR="$(cd "$WORKDIR" && pwd)"
REPO="$(cd "$WORKDIR" && gh repo view --json nameWithOwner --jq .nameWithOwner)" || { echo "gh can't see the repo; run gh auth login" >&2; exit 1; }

COMMON_TOOLS=(
  "Bash(gh issue:*)" "Bash(gh pr:*)" "Bash(gh run list:*)" "Bash(gh run view:*)"
  "Bash(gh label list:*)" "Bash(gh search:*)" "Bash(gh repo view:*)"
  "Bash(git log:*)" "Bash(git show:*)" "Bash(git diff:*)" "Bash(git status:*)" "Bash(git fetch:*)"
  "Bash(date:*)" "Read" "Grep" "Glob" "Skill"
)
WORKER_TOOLS=(
  "Bash(git:*)" "Bash(python:*)" "Bash(python3:*)" "Bash(pip:*)" "Bash(pip3:*)" "Bash(uv:*)"
  "Bash(pytest:*)" "Bash(make:*)" "Bash(gitleaks:*)" "Bash(ls:*)" "Bash(mkdir:*)"
  "Edit" "Write"
)
DENY_TOOLS=(
  "Bash(nmap:*)" "Bash(sudo:*)" "Bash(gh issue delete:*)" "Bash(gh issue transfer:*)"
  "Bash(gh repo delete:*)" "Bash(git push --force:*)" "Bash(git push -f:*)" "Bash(git push origin main:*)"
)
TOOLS=("${COMMON_TOOLS[@]}")
[[ "$ROLE" == worker ]] && TOOLS+=("${WORKER_TOOLS[@]}")
if [[ -n "$AGENT_EXTRA_TOOLS" ]]; then
  IFS=',' read -r -a extra <<< "$AGENT_EXTRA_TOOLS"
  TOOLS+=("${extra[@]}")
fi

load_prompt() {
  # The latest merged prompt wins, so improvements reach every laptop.
  # Before the prompts are merged, use the snapshot taken at start.
  local text
  text="$(git -C "$WORKDIR" show "origin/main:agents/$ROLE.md" 2>/dev/null)" || text="$(cat "$STATE/bin/$ROLE.md")"
  printf '%s' "${text//\{\{TAG\}\}/$TAG}"
}

paused() {  # prints yes / no / unknown
  local out
  out="$(gh issue view "$SYNC_ISSUE" --repo "$REPO" --json labels --jq '[.labels[].name] | index("agents:paused") != null' 2>/dev/null)" || { echo unknown; return; }
  [[ "$out" == true ]] && echo yes || echo no
}

deadline=$(( $(date +%s) + MAX_HOURS * 3600 ))
sleep_s="$INTERVAL_MIN"; idle=0; errors=0
log "start role=$ROLE repo=$REPO workdir=$WORKDIR max_hours=$MAX_HOURS"

while :; do
  [[ -f "$STATE/STOP" ]] && { log "STOP file found, exiting"; break; }
  (( $(date +%s) >= deadline )) && { log "MAX_HOURS reached, exiting"; break; }

  case "$(paused)" in
    yes)     log "paused (label agents:paused on #$SYNC_ISSUE)"; sleep "$INTERVAL_MAX"; continue ;;
    unknown) log "can't reach GitHub, retrying later"; sleep "$INTERVAL_MIN"; continue ;;
  esac

  git -C "$WORKDIR" fetch -q origin 2>/dev/null || log "git fetch failed"
  if [[ "$ROLE" == orchestrator ]] && [[ -z "$(git -C "$WORKDIR" status --porcelain)" ]]; then
    git -C "$WORKDIR" checkout -q --detach origin/main 2>/dev/null || true
  fi

  tick_log="$STATE/logs/$(date -u +%Y%m%dT%H%M%SZ).log"
  args=(-p "$(load_prompt)" --output-format text)
  [[ -n "$AGENT_MODEL" ]] && args+=(--model "$AGENT_MODEL")
  [[ -n "$TICK_BUDGET_USD" ]] && args+=(--max-budget-usd "$TICK_BUDGET_USD")
  args+=(--disallowedTools "${DENY_TOOLS[@]}" --allowedTools "${TOOLS[@]}")

  log "tick start"
  ( cd "$WORKDIR" && perl -e 'alarm shift; exec @ARGV' "$TICK_TIMEOUT" claude "${args[@]}" ) > "$tick_log" 2>&1
  rc=$?
  result="$(grep -Eo 'TICK-RESULT: (ACTIVE|IDLE)' "$tick_log" | tail -1 | cut -d' ' -f2)"
  log "tick end rc=$rc result=${result:-NONE} log=$tick_log"
  [[ "${ONE_TICK:-}" == 1 ]] && { log "ONE_TICK=1, exiting after one tick"; break; }

  if [[ -z "$result" ]]; then
    errors=$((errors + 1)); sleep_s="$INTERVAL_MAX"
    (( errors >= 3 )) && { log "3 failed ticks in a row, exiting; see $tick_log"; break; }
  elif [[ "$result" == ACTIVE ]]; then
    errors=0; idle=0; sleep_s="$INTERVAL_MIN"
  else
    errors=0; idle=$((idle + 1))
    (( idle >= IDLE_STOP_TICKS )) && { log "$idle idle ticks in a row, exiting"; break; }
    sleep_s=$(( sleep_s * 2 )); (( sleep_s > INTERVAL_MAX )) && sleep_s="$INTERVAL_MAX"
  fi

  ls -1t "$STATE/logs" | tail -n +51 | while read -r old; do rm -f "$STATE/logs/$old"; done
  sleep "$sleep_s"
done
