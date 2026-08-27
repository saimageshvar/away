#!/bin/bash
# Away-mode guard. One script serves three hook events; $1 is the event name.
#
# Bash owns the fast path because PreToolUse fires on EVERY tool call: the
# common case must never pay for a python interpreter start.
set -u

AWAY_HOME="${AWAY_HOME:-$HOME/.claude/away}"
STATE="$AWAY_HOME/state"
FLAG="$STATE/active.json"
ENDED="$STATE/ended.json"
EVENT="${1:-}"

input=$(cat 2>/dev/null || true)

# A broken guard must never widen permissions, so the decision events fail
# closed (exit 2 blocks). UserPromptSubmit fails open: exit 2 there would
# swallow the operator's prompt.
# Stop fails open too: a broken guard must never wedge an agent that wants to
# finish, and blocking a stop is a nudge rather than a safety control.
case "$EVENT" in
  pretooluse|permissionrequest) FAILSAFE=2 ;;
  *)                            FAILSAFE=0 ;;
esac

# A session can be armed on its own, so the fast path needs the session id. Match
# the key BEFORE extracting: without the guard, a payload lacking session_id
# leaves sid set to the whole input, which strips down to "{" and passes a naive
# path check.
# Both spacings are matched: a space after the colon would otherwise leave sid
# empty, and an empty sid reads as "not armed" for every session-scoped absence.
case "$input" in
  *'"session_id":"'*)  sid=${input#*\"session_id\":\"};  sid=${sid%%\"*} ;;
  *'"session_id": "'*) sid=${input#*\"session_id\": \"}; sid=${sid%%\"*} ;;
  *)                   sid="" ;;
esac
case "$sid" in *[/\"{}]*|"") sid="" ;; esac

armed=0
if [ -f "$FLAG" ]; then
  armed=1
elif [ -n "$sid" ] && [ -f "$STATE/sessions/$sid.json" ]; then
  armed=1
fi

need_python=0
if [ "$armed" = "1" ]; then
  if [ "$EVENT" = "pretooluse" ]; then
    # Only three tools can yield a decision while away, so Read, Grep, Edit and
    # the rest must not pay for a python start on every call in every agent.
    case "$input" in
      *'"tool_name"'*'"Bash"'*|*'"tool_name"'*'"AskUserQuestion"'*|*'"tool_name"'*'"ExitPlanMode"'*)
        need_python=1 ;;
      # Any tool at all that reaches for away mode's own machinery must be seen,
      # or an Edit could rewrite the guard without the guard ever running.
      *.claude/away*|*.claude/settings.json*|*.claude/settings.local.json*)
        need_python=1 ;;
    esac
  else
    need_python=1
  fi
elif [ "$EVENT" = "pretooluse" ]; then
  # Away is OFF, so only one job is left: reproduce the `ask` on deletes that we
  # removed from the permission list to give this hook sole authority.
  case "$input" in
    *'"tool_name"'*'"Bash"'*)
      case "$input" in
        *rm*|*RM*|*unlink*|*shred*|*-delete*) need_python=1 ;;
      esac ;;
  esac
elif [ "$EVENT" = "userpromptsubmit" ]; then
  # A session that armed itself with --here ends alone, so the global file is
  # not written and only its own marker says the absence is over.
  if [ -f "$ENDED" ]; then
    need_python=1
  elif [ -n "$sid" ] && [ -f "$STATE/sessions-ended/$sid.json" ]; then
    need_python=1
  fi
fi

[ "$need_python" = "1" ] || exit 0

PY=""
for c in /opt/homebrew/bin/python3 /usr/bin/python3 python3; do
  if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then
  echo "away-guard: no python3 found; failing closed" >&2
  exit "$FAILSAFE"
fi

mkdir -p "$STATE" 2>/dev/null
err="$STATE/guard.err"
out=$(printf '%s' "$input" | "$PY" "$AWAY_HOME/hooks/guard.py" "$EVENT" 2>>"$err")
rc=$?
if [ "$rc" -ne 0 ] && [ -f "$AWAY_HOME/hooks/guard.py.good" ]; then
  # A broken guard blocks EVERY tool call in EVERY session, and no agent may
  # repair it: the tamper rule denies writes to this directory while away mode
  # is on. The last copy that passed the selftest is a better answer than a
  # machine-wide stall, and it is loud about being a fallback.
  out=$(printf '%s' "$input" | "$PY" "$AWAY_HOME/hooks/guard.py.good" "$EVENT" 2>>"$err")
  if [ "$?" -eq 0 ]; then
    rc=0
    echo "away-guard: guard.py is broken (see $err); running the last copy that" >&2
    echo "away-guard: passed the selftest. Fix it, then run \`away doctor\`." >&2
  fi
fi
if [ "$rc" -ne 0 ]; then
  echo "away-guard: guard.py exited $rc (see $err); failing closed" >&2
  exit "$FAILSAFE"
fi

[ -n "$out" ] && printf '%s' "$out"
exit 0
