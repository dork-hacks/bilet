#!/usr/bin/env bash
# Run one autonomous worker loop (WORKFLOW.md §10).
#
#   agents/run-loop.sh agent-C ~/bilet-agents/agent-C
#
# <workdir> is this agent's OWN clone of the repo. It is created if missing.
# Never point it at a checkout someone works in by hand.
#
# Each tick is a fresh headless Claude (default) or Codex session.
# Claude uses tool lists; Codex uses workspace-write and automatic approval review.
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

usage() { echo "usage: $0 <agent-tag> <workdir>   e.g. $0 agent-C ~/bilet-agents/agent-C" >&2; exit 2; }
[[ $# -eq 2 ]] || usage
TAG="$1"; WORKDIR="$2"
AGENT_RUNTIME="${AGENT_RUNTIME:-claude}"
case "$AGENT_RUNTIME" in claude|codex) ;; *) echo "AGENT_RUNTIME must be claude or codex" >&2; exit 2 ;; esac
if [[ "$AGENT_RUNTIME" == codex && -n "${TICK_BUDGET_USD:-}" ]]; then
  echo "TICK_BUDGET_USD is Claude-only; Codex does not expose a per-tick dollar cap" >&2; exit 2
fi
command -v "$AGENT_RUNTIME" >/dev/null || { echo "$AGENT_RUNTIME is not installed" >&2; exit 1; }
[[ "$TAG" =~ ^agent-[A-Z]$ ]] || { echo "tag must be 'agent-<LETTER>', e.g. agent-C" >&2; exit 2; }
SYNC_ISSUE="${SYNC_ISSUE:-1}"
INTERVAL_MIN="${INTERVAL_MIN:-300}"            # seconds between ticks while active
INTERVAL_MAX="${INTERVAL_MAX:-1800}"           # idle backoff cap
IDLE_STOP_TICKS="${IDLE_STOP_TICKS:-8}"           # stop after this many idle ticks in a row
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
  cp "$SRC_DIR/run-loop.sh" "$SRC_DIR/worker.md" "$STATE/bin/"
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

# Defence in depth for the agent's clone: refuse pushes to main, branch
# deletions, non-fast-forward pushes and branch names outside `<n>-slug`.
# This is not a hard control (a hook can be skipped), only a safety net.
cat > "$WORKDIR/.git/hooks/pre-push" <<'HOOK'
#!/usr/bin/env bash
zero=0000000000000000000000000000000000000000
while read -r local_ref local_sha remote_ref remote_sha; do
  if [[ "$local_sha" == "$zero" ]]; then echo "pre-push: refusing to delete $remote_ref" >&2; exit 1; fi
  if [[ ! "$remote_ref" =~ ^refs/heads/[0-9]+-[A-Za-z0-9._-]+$ ]]; then
    echo "pre-push: agents push only to <n>-slug branches, not $remote_ref" >&2; exit 1
  fi
  if [[ "$remote_sha" != "$zero" ]] && ! git merge-base --is-ancestor "$remote_sha" "$local_sha" 2>/dev/null; then
    echo "pre-push: refusing a non-fast-forward push to $remote_ref (fetch, then merge the remote branch into yours; never rebase a pushed branch)" >&2; exit 1
  fi
done
exit 0
HOOK
chmod +x "$WORKDIR/.git/hooks/pre-push"
REPO="$(cd "$WORKDIR" && gh repo view --json nameWithOwner --jq .nameWithOwner)" || { echo "gh can't see the repo; run gh auth login" >&2; exit 1; }

TOOLS=(
  "Bash(gh issue:*)" "Bash(gh pr:*)" "Bash(gh run list:*)" "Bash(gh run view:*)"
  "Bash(gh label list:*)" "Bash(gh search:*)" "Bash(gh repo view:*)"
  "Bash(git status:*)" "Bash(git log:*)" "Bash(git diff:*)" "Bash(git show:*)" "Bash(git fetch:*)"
  "Bash(git add:*)" "Bash(git commit:*)" "Bash(git switch:*)" "Bash(git checkout:*)" "Bash(git branch:*)"
  "Bash(git rebase:*)" "Bash(git merge:*)" "Bash(git pull:*)" "Bash(git push -u origin:*)" "Bash(git push -q -u origin:*)" "Bash(git push origin:*)"
  "Bash(.venv/bin/python:*)" "Bash(.venv/bin/pytest:*)" "Bash(.venv/bin/tool:*)"
  "Bash(grep:*)" "Bash(head:*)" "Bash(tail:*)" "Bash(wc:*)" "Bash(cat:*)" "Bash(sort:*)" "Bash(uniq:*)"
  "Bash(git restore:*)" "Bash(git stash:*)" "Bash(git rev-parse:*)"
  "Bash(python:*)" "Bash(python3:*)" "Bash(pip:*)" "Bash(pip3:*)" "Bash(uv:*)"
  "Bash(pytest:*)" "Bash(make:*)" "Bash(gitleaks:*)" "Bash(ls:*)" "Bash(mkdir:*)" "Bash(date:*)"
  "Bash(gh api repos/{owner}/{repo}/issues/comments -X GET:*)"
  "Read" "Edit" "Write" "Grep" "Glob" "Skill"
)
DENY_TOOLS=(
  "Bash(nmap:*)" "Bash(sudo:*)" "Bash(gh issue delete:*)" "Bash(gh issue transfer:*)"
  "Bash(gh repo delete:*)" "Bash(git push --force:*)" "Bash(git push -f:*)" "Bash(git push origin main:*)"
  "Bash(git push -u origin main:*)" "Bash(git push -u origin +*)" "Bash(git push origin +*)" "Bash(git push * +*)" "Bash(git push * main*)"
  "Bash(git push -u origin HEAD:main:*)" "Bash(git push -u origin --delete:*)" "Bash(git push -u origin -d:*)"
  "Bash(git push -u origin --force:*)" "Bash(git push -u origin -f:*)" "Bash(git push -u origin --no-verify:*)"
  "Bash(git push * --force*)" "Bash(git push * --no-verify*)" "Bash(git push * --delete*)" "Bash(git push *:main*)"
  "Bash(git branch -D:*)" "Bash(git config:*)"
  "Bash(gh api * -X DELETE*)" "Bash(gh api * -X PATCH*)" "Bash(gh api * -X POST*)" "Bash(gh api * -X PUT*)"
  "Bash(gh api * --method*)" "Bash(gh api * --input*)"
)
# The lists above only cover direct commands. They are NOT a sandbox: an allowed
# interpreter (python, make) can still run anything. The real guards are the
# worker prompt's hard limits, the pre-push hook below, and branch protection
# on `main` in GitHub (a repo admin has to turn that on).
if [[ -n "$AGENT_EXTRA_TOOLS" ]]; then
  IFS=',' read -r -a extra <<< "$AGENT_EXTRA_TOOLS"
  TOOLS+=("${extra[@]}")
fi

load_prompt() {
  # The latest merged prompt wins, so improvements reach every laptop.
  # Before the prompt is merged, use the snapshot taken at start.
  local text
  text="$(git -C "$WORKDIR" show "origin/main:agents/worker.md" 2>/dev/null)" || text="$(cat "$STATE/bin/worker.md")"
  if [[ "$AGENT_RUNTIME" == codex ]]; then
    printf '%s\n\n' 'Codex worker: read AGENTS.md, MASTERPLAN.md and WORKFLOW.md before working. You are taking one autonomous tick; use available tools rather than Claude-specific tool names. If permissions or automatic approval review block an operation, report it honestly; never bypass the sandbox or approval review. For agent-G, continue only the backup work assigned by Eduard in issue #1; do not take agent-B claims back after it returns without a human assignment.'
  fi
  printf '%s' "${text//\{\{TAG\}\}/$TAG}"
}

paused() {  # prints yes / no / unknown
  local out
  out="$(gh issue view "$SYNC_ISSUE" --repo "$REPO" --json labels --jq '[.labels[].name] | index("agents:paused") != null' 2>/dev/null)" || { echo unknown; return; }
  [[ "$out" == true ]] && echo yes || echo no
}

deadline=$(( $(date +%s) + MAX_HOURS * 3600 ))
sleep_s="$INTERVAL_MIN"; idle=0; errors=0
log "start repo=$REPO workdir=$WORKDIR max_hours=$MAX_HOURS"

while :; do
  [[ -f "$STATE/STOP" ]] && { log "STOP file found, exiting"; break; }
  (( $(date +%s) >= deadline )) && { log "MAX_HOURS reached, exiting"; break; }

  case "$(paused)" in
    yes)     log "paused (label agents:paused on #$SYNC_ISSUE)"; sleep "$INTERVAL_MAX"; continue ;;
    unknown) log "can't reach GitHub, retrying later"; sleep "$INTERVAL_MIN"; continue ;;
  esac

  git -C "$WORKDIR" fetch -q origin 2>/dev/null || log "git fetch failed"

  tick_log="$STATE/logs/$(date -u +%Y%m%dT%H%M%SZ).log"
  if [[ "$AGENT_RUNTIME" == codex ]]; then
    args=(--approve-for-me exec --sandbox workspace-write --json
          --output-last-message "$tick_log" "$(load_prompt)")
    [[ -n "$AGENT_MODEL" ]] && args+=(--model "$AGENT_MODEL")
  else
    args=(-p "$(load_prompt)" --output-format json)
    [[ -n "$AGENT_MODEL" ]] && args+=(--model "$AGENT_MODEL")
    [[ -n "$TICK_BUDGET_USD" ]] && args+=(--max-budget-usd "$TICK_BUDGET_USD")
    args+=(--disallowedTools "${DENY_TOOLS[@]}" --allowedTools "${TOOLS[@]}")
  fi

  log "tick start"
  ( cd "$WORKDIR" && perl -e 'alarm shift; exec @ARGV' "$TICK_TIMEOUT" "$AGENT_RUNTIME" "${args[@]}" ) > "$tick_log.json" 2> "$tick_log.err"
  rc=$?
  # Keep the readable report in .log; record Claude cost/turns or Codex tokens.
  usage="$(python3 - "$tick_log.json" "$tick_log" "$AGENT_RUNTIME" <<'PY' 2>/dev/null
import json, sys
if sys.argv[3] == "codex":
    usage = {}
    with open(sys.argv[1]) as stream:
        for line in stream:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get("type") == "turn.completed":
                usage = event.get("usage", {})
    print("tokens=" + json.dumps(usage, separators=(",", ":")))
    sys.exit(0)
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(1)
open(sys.argv[2], "w").write(str(d.get("result") or "") + "\n")
print(f"cost_usd={d.get('total_cost_usd', 0):.2f} turns={d.get('num_turns', '?')}")
PY
)" || usage="unparsed"
  result="$(grep -Eo 'TICK-RESULT: (ACTIVE|IDLE)' "$tick_log" 2>/dev/null | tail -1 | cut -d' ' -f2)"
  log "tick end rc=$rc result=${result:-NONE} $usage log=$tick_log"
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

  ls -1t "$STATE/logs" | tail -n +151 | while read -r old; do rm -f "$STATE/logs/$old"; done
  sleep "$sleep_s"
done
