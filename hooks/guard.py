#!/usr/bin/env python3
"""Away-mode decision engine. stdin is the hook JSON, argv[1] is the event name.

Only guard.sh calls this, and only after its fast path decides a decision is
actually needed. Everything on stdout is hook JSON; diagnostics go to stderr so
a noisy failure can never corrupt a decision.
"""

import fcntl
import json
import os
import re
import shlex
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_AWAY = Path.home() / ".claude" / "away"
AWAY = Path(os.environ.get("AWAY_HOME") or DEFAULT_AWAY)

# The log is global, so a test that writes into it reads as a real incident in
# every other session. Adversarial tests fire commands that look exactly like an
# attack, so they must be labelled at the source rather than remembered about.
SYNTHETIC = bool(os.environ.get("AWAY_TEST")) or AWAY != DEFAULT_AWAY
STATE = AWAY / "state"
FLAG = STATE / "active.json"
EVENTS = STATE / "events.jsonl"
ENDED = STATE / "ended.json"
SESSION_ENDED = STATE / "sessions-ended"
RULES = AWAY / "rules.md"

# Slack Ping: a Slack workflow webhook that DMs the operator. Opt-in by the two
# files existing; the URL is the operator's own, so it never lives in this repo.
PING = Path(os.environ.get("SLACK_PING_HOME") or (Path.home() / ".config" / "slack-ping"))
PING_TIMEOUT = 8

NAG_AFTER_HOURS = 8
MAX_ASK_RETRIES = 3

SEPARATORS = {"&&", "||", ";", "|", "&"}

# git global options that consume the following token, so the subcommand parser
# does not mistake their argument for the subcommand.
GIT_OPTS_WITH_ARG = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}

DELETE_BINS = {"rm", "unlink", "shred", "srm"}

ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z_0-9]*=")

# Words that stand in front of the real command without being it.
CMD_PREFIXES = {"sudo", "env", "nice", "time", "nohup", "command", "builtin",
                "exec", "timeout", "stdbuf", "then", "do", "else", "{", "!"}

# Away mode is worthless if an agent can switch it off, so the guard protects its
# own machinery. Only the operator, from their own terminal, may disarm it.
AWAY_TOGGLE = re.compile(r"\baway\s+(on|off)\b")
SELF_PATHS = re.compile(r"\.claude/(away\b|settings\.json|settings\.local\.json)")
# An interpreter can do anything, so treat one as a mutation of whatever it names.
MUTATES = re.compile(
    r">>?|\brm\b|\bmv\b|\bcp\b|\btee\b|\btruncate\b|\bsed\s+-i|\bchmod\b|\bln\b|"
    r"\bunlink\b|\bpython3?\b|\bnode\b|\bperl\b|\bruby\b|\bdd\b")
TAMPER_TOOLS = ("Edit", "Write", "NotebookEdit", "MultiEdit")

# The subcommands rules.md promises an agent: read state, record a decision.
# None of them can change enforcement, and `away on|off` is not among them -- it
# is caught earlier by AWAY_TOGGLE, which this exemption never reaches.
AWAY_CLI_SAFE = {"decision", "report", "status", "trash", "perms"}

# Any token that starts a redirect, in every form a shell accepts: `>`, `>>`,
# `2>`, `&>`, `<`, `<<`, and each of them glued to its target.
REDIRECT_TOKEN = re.compile(r"^(\d*>>?|&>>?|<<?|>\|)")

# ---------------------------------------------------------------- primitives

def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_local(ts):
    """Timestamps are stored in UTC. An agent reports them to a local operator.

    Deliberately duplicated from report.py rather than imported: a failed import
    here exits non-zero, guard.sh then fails closed, and every Bash call in every
    agent is blocked. A pure formatter is not worth that risk.
    """
    try:
        stamp = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc).astimezone()
    except Exception:
        return (ts or "")[11:19]
    if stamp.date() != datetime.now().astimezone().date():
        return stamp.strftime("%d %b %H:%M:%S")
    return stamp.strftime("%H:%M:%S")


def run(args, cwd=None, timeout=10):
    try:
        proc = subprocess.run(args, cwd=cwd, capture_output=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except Exception:
        return 1, b"", b""


def git_out(args, cwd):
    rc, out, _ = run(["git"] + args, cwd=cwd)
    return out.decode("utf-8", "replace").strip() if rc == 0 else ""


_GIT_INFO = {}


def git_info(cwd):
    """Repo root and branch in one call, memoised. Each git spawn costs ~16ms,
    and several code paths want these, so they must not each pay for them."""
    if cwd not in _GIT_INFO:
        lines = git_out(["rev-parse", "--show-toplevel", "--abbrev-ref", "HEAD"],
                        cwd).splitlines()
        _GIT_INFO[cwd] = (lines[0] if lines else "",
                          lines[1] if len(lines) > 1 else "")
    return _GIT_INFO[cwd]


def log_event(rec):
    """Append one JSON line under an exclusive lock. macOS ships no flock(1)."""
    if SYNTHETIC:
        rec = dict(rec, synthetic=True)
    try:
        STATE.mkdir(parents=True, exist_ok=True)
        line = json.dumps(rec, ensure_ascii=False) + "\n"
        with open(EVENTS, "a", encoding="utf-8") as handle:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            except OSError:
                pass
            handle.write(line)
            handle.flush()
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
    except Exception as exc:
        print("away-guard: log failed: %s" % exc, file=sys.stderr)


def tail_lines(path, count):
    try:
        with open(path, "rb") as handle:
            text = handle.read().decode("utf-8", "replace")
        return text.splitlines()[-count:]
    except Exception:
        return []


def flag_state():
    try:
        return json.loads(FLAG.read_text(encoding="utf-8"))
    except Exception:
        return {}


def session_flag(session):
    """This session's own flag file, or None when the id is unusable."""
    if not session or "/" in session or session in (".", ".."):
        return None
    return STATE / "sessions" / ("%s.json" % session)


def away_on(session=None):
    """Global first: arming globally deletes the session layer, so it always wins."""
    if FLAG.exists():
        return True
    marker = session_flag(session)
    return bool(marker and marker.exists())


def scope_state(session=None):
    """The state that governs this session, global taking precedence."""
    if FLAG.exists():
        return flag_state()
    marker = session_flag(session)
    if marker and marker.exists():
        try:
            return json.loads(marker.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def note_suffix(session=None):
    """The operator's note, attached to whatever an agent is about to read.

    A note only reached the per-prompt banner before, which needs the operator to
    be typing. During a real absence nobody types, so the note reached no one. A
    denial is the one thing a working agent always reads.
    """
    note = scope_state(session).get("note")
    return '\nOperator note: "%s"' % note if note else ""


def session_ctx(hook):
    cwd = hook.get("cwd") or os.getcwd()
    sid = hook.get("session_id") or "unknown"
    return {
        "session": sid,
        "label": "%s/%s" % (Path(cwd).name, sid[:6]),
        "cwd": cwd,
        "branch": git_info(cwd)[1] or None,
        "agent": hook.get("agent_id") or "main",
        "agent_type": hook.get("agent_type"),
        "pid": os.getpid(),
    }


def emit_pretool(decision, reason=None):
    payload = {"hookEventName": "PreToolUse", "permissionDecision": decision}
    if reason:
        payload["permissionDecisionReason"] = reason
    print(json.dumps({"hookSpecificOutput": payload}))


def emit_permreq(behavior, message=None):
    # Never `interrupt`: it stops Claude, which would end the turn mid-absence.
    decision = {"behavior": behavior}
    if message:
        decision["message"] = message
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PermissionRequest",
        "decision": decision,
    }}))


def emit_context(text):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "UserPromptSubmit",
        "additionalContext": text,
    }}))

# ---------------------------------------------------------------- parsing

def segments(cmd):
    """[[token, ...]] per shell segment, or None when the command does not parse.

    Newlines are split BEFORE shlex, so a script's second line is its own segment.
    Without that, `echo hi\\nrm -rf src` reads as one segment whose command is
    `echo`, and the rm on line two would never be judged.
    """
    out = []
    for line in re.split(r"[\n\r]+", cmd):
        if not line.strip():
            continue
        try:
            toks = shlex.split(line)
        except ValueError:
            return None
        current = []
        for tok in toks:
            if tok in SEPARATORS:
                out.append(current)
                current = []
            else:
                current.append(tok)
        out.append(current)
    return [seg for seg in out if seg]

def command_index(toks):
    """Index of the token that actually runs, past env assignments and prefixes.

    `FOO=1 timeout 5 rm -rf x` runs rm, and an agent writes that form often
    enough that missing it would be a hole rather than a nicety.
    """
    for index, tok in enumerate(toks):
        if ENV_ASSIGN.match(tok) or tok in CMD_PREFIXES:
            continue
        if tok.startswith("-") or tok.isdigit():
            continue        # an option or its numeric argument (nice -n 10 ...)
        return index
    return None

def command_word(toks):
    index = command_index(toks)
    return toks[index] if index is not None else None

# ------------------------------------------------------------- ask reasoning

def ask_reason(tool_input, retries, session=None):
    """Deny AskUserQuestion, but hand the agent everything it needs to decide."""
    lines = ["AWAY MODE. The operator is not at the keyboard, so you cannot ask."]
    for question in (tool_input.get("questions") or []):
        lines.append("")
        lines.append('Your question: "%s"' % question.get("question", ""))
        options = question.get("options") or []
        if not options:
            continue
        lines.append("Your options:")
        marked = None
        for index, option in enumerate(options, 1):
            label = option.get("label", "")
            tag = ""
            if "recommended" in label.lower():
                tag = "   [RECOMMENDED - you marked it so]"
                if marked is None:  # the first marked option wins, not the last
                    marked = index
            lines.append("  %d. %s%s" % (index, label, tag))
        if marked is None:
            # Option order is not a reliable signal from an arbitrary caller, so
            # naming a positional default here would push an arbitrary choice.
            lines.append("  (You marked none of these as recommended.)")
            lines.append(
                "Decide on the merits, not on the order they appear in. Take the "
                "best-supported option, and record in one line why you took it.")
        else:
            lines.append(
                "Take option %d unless you hold evidence against it. "
                "If you do, take the best-supported option instead." % marked)
    note = note_suffix(session).strip()
    if note:
        lines += ["", note]
    lines += [
        "",
        "State the assumption in one line, then continue. Do not re-ask.",
        "This question and its options are logged, so the operator reviews your choice.",
    ]
    if retries >= MAX_ASK_RETRIES:
        lines += [
            "",
            "You have now been denied %d times this session. Stop asking. Write your "
            "remaining open questions into your final summary, and finish every part "
            "of the work that does not depend on them." % retries,
        ]
    return "\n".join(lines)


def ask_retry_count(session):
    """Denied questions in THIS absence only.

    Counting a session's whole history meant a long-lived session opened every
    later absence already at the "stop asking" escalation.
    """
    since = scope_state(session).get("since_epoch") or 0
    count = 0
    for line in tail_lines(EVENTS, 600):
        try:
            rec = json.loads(line)
            stamp = datetime.strptime(rec.get("ts", ""), "%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            continue
        if stamp.replace(tzinfo=timezone.utc).timestamp() < since:
            continue
        if rec.get("session") == session and rec.get("event") == "decision_forced":
            count += 1
    return count

# ------------------------------------------------------------------ handlers

def away_cli_segment(toks):
    """True when this segment is one of away's own agent-facing subcommands.

    Nothing inside it may reach a shell: a quoted `>` inside a longer token is
    data an agent wrote, but a bare `>` token is a redirect and `$(`/backtick is
    a substitution the shell would run before away ever saw it.
    """
    index = command_index(toks)
    if index is None or toks[index].rsplit("/", 1)[-1] != "away":
        return False
    if index + 1 >= len(toks) or toks[index + 1] not in AWAY_CLI_SAFE:
        return False
    # Bare `>` was the only redirect checked, so `away decision x >~/…/guard.py`
    # and `2>~/…/guard.py` both walked through the exemption: shlex keeps the
    # glued form as ONE token, which matched nothing in that list.
    return not any(REDIRECT_TOKEN.match(t) or "$(" in t or "`" in t for t in toks)

def strip_away_cli(cmd):
    """The command with its sanctioned `away` calls removed, for the tamper check.

    rules.md tells agents to record decisions as
    `~/.claude/away/bin/away decision "..."`. That absolute path matches
    SELF_PATHS, and MUTATES then matched an ordinary word in the DECISION TEXT --
    python3, ruby, rm, cp, a `>` -- so recording a decision read as tampering
    with away mode itself. Five of six realistic decision texts were denied, and
    they were biased toward the decisions most worth keeping, because those are
    the ones that mention files and tools.

    Stripping per segment rather than skipping the check wholesale: a compound
    like `away decision "x" && rm -rf ~/.claude/away` still has to die.
    """
    segs = segments(cmd)
    if segs is None:
        return cmd                      # unparseable: judge all of it, as before
    kept = [" ".join(toks) for toks in segs if not away_cli_segment(toks)]
    return "\n".join(kept)

def away_toggle_scope(cmd):
    """None when no toggle, "here" when every toggle is session-scoped, else "global".

    Checked per segment on purpose. A single search for "--here" anywhere would let
    `away off --here && away off` disarm the global flag on the strength of the
    first segment's flag.
    """
    found = False
    for segment in re.split(r"&&|\|\||;|\||&", cmd):
        if AWAY_TOGGLE.search(segment):
            found = True
            if "--here" not in segment:
                return "global"
    return "here" if found else None

TAMPER_REASON = (
    "this changes away mode's own enforcement, which no agent may do while away "
    "mode is on. Reading those files is fine; changing them is the operator's. "
    "If a rule is blocking necessary work, defer the work and say so in your "
    "summary with the exact command and why you needed it.")

def deny(hook, tool, reason, event="deferred", detail=None):
    ctx = session_ctx(hook)
    rec = {"ts": now_iso(), "event": event, "tool": tool,
           "tool_use_id": hook.get("tool_use_id"),
           "detail": detail if detail is not None
           else {"command": (hook.get("tool_input") or {}).get("command")},
           "rule": reason}
    rec.update(ctx)
    log_event(rec)
    emit_pretool("deny", "AWAY MODE. %s%s"
                 % (reason, note_suffix(hook.get("session_id"))))

def handle_pretooluse(hook):
    tool = hook.get("tool_name") or ""
    tool_input = hook.get("tool_input") or {}
    on = away_on(hook.get("session_id"))

    if on and tool in TAMPER_TOOLS:
        if SELF_PATHS.search(json.dumps(tool_input)):
            deny(hook, tool, TAMPER_REASON, detail={"tool_input": tool_input})
        return

    if not on:
        return

    # The harness decides what runs. Away guards only its own switch and files.
    if tool == "Bash":
        cmd = tool_input.get("command") or ""
        # A session may scope away mode to itself. Only the operator may touch
        # the global flag, and the resolver checks that flag first, so a
        # session can never free itself from a real absence.
        if away_toggle_scope(cmd) == "global":
            deny(hook, tool,
                 "only the operator may switch away mode on or off globally, and "
                 "they do it from their own terminal. `away on --here` and "
                 "`away off --here` scope it to this session, and `away report`, "
                 "`away status`, `away perms` and `away decision` are yours too.")
            return
        rest = strip_away_cli(cmd)
        if SELF_PATHS.search(rest) and MUTATES.search(rest):
            deny(hook, tool, TAMPER_REASON)
        return

    if tool == "AskUserQuestion":
        ctx = session_ctx(hook)
        retries = ask_retry_count(ctx["session"])
        rec = {"ts": now_iso(), "event": "decision_forced", "tool": tool,
               "tool_use_id": hook.get("tool_use_id"),
               "detail": tool_input.get("questions"), "retry_index": retries,
               "rule": "away: cannot ask"}
        rec.update(ctx)
        log_event(rec)
        emit_pretool("deny", ask_reason(tool_input, retries, ctx["session"]))
        return

    if tool == "ExitPlanMode":
        ctx = session_ctx(hook)
        rec = {"ts": now_iso(), "event": "plan_self_approved", "tool": tool,
               "tool_use_id": hook.get("tool_use_id"),
               "detail": {"plan": tool_input.get("plan")},
               "rule": "away: plan approved for you"}
        rec.update(ctx)
        log_event(rec)
        emit_pretool("allow", "AWAY MODE. Plan approval is automatic, and your plan "
                              "is logged for review. Proceed.")


DENY_MESSAGES = {
    "push": "AWAY MODE. This push needs an approval nobody is here to give. Do not "
            "retry it. Keep committing locally and carry on; the branch stays unpushed "
            "for the operator.",
    "delete": "AWAY MODE. This delete needs an approval nobody is here to give. Do not "
              "retry it. Leave the files, record it with `%s decision \"not done: "
              "<command> - <why>\"`, and carry on." % (AWAY / "bin" / "away"),
    "other": "AWAY MODE. This needs an approval nobody is here to give. Do not retry "
             "it. Route around it, or defer it with evidence, options and your "
             "recommendation, and carry on with everything it does not block.",
}
DEGRADED = ("\nAuto mode has likely paused after repeated blocks, so this session is "
            "degraded: land your work, record what is not done, and stop.")
DENIAL_EVENTS = ("deferred", "auto_denied")
DEGRADED_TOTAL = 20
DEGRADED_BURST = 3
DEGRADED_BURST_SECONDS = 120


def denial_kind(cmd):
    """push beats delete beats other, across every segment of the command."""
    kinds = set()
    for toks in segments(cmd) or []:
        index = command_index(toks)
        if index is None:
            continue
        word = toks[index].rsplit("/", 1)[-1].lower()
        if word == "git":
            j = index + 1
            while j < len(toks) and toks[j].startswith("-"):
                j += 2 if toks[j] in GIT_OPTS_WITH_ARG else 1
            if j < len(toks) and toks[j] == "push":
                kinds.add("push")
        elif word in DELETE_BINS or word == "rmdir":
            kinds.add("delete")
    return next((k for k in ("push", "delete") if k in kinds), "other")


def degraded(session):
    """Auto mode pauses after 3 blocks in a row or 20 in total.

    ponytail: away cannot see the calls that succeed between blocks, so "in a row"
    is approximated as 3 blocks within two minutes.
    """
    since = scope_state(session).get("since_epoch") or 0
    stamps = []
    for line in tail_lines(EVENTS, 6000):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if rec.get("session") != session or rec.get("event") not in DENIAL_EVENTS:
            continue
        if rec.get("synthetic") and not SYNTHETIC:
            continue
        try:
            when = datetime.strptime(rec.get("ts", ""), "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc).timestamp()
        except Exception:
            continue
        if when >= since:
            stamps.append(when)
    burst = stamps[-DEGRADED_BURST:]
    return len(stamps) >= DEGRADED_TOTAL or (
        len(burst) == DEGRADED_BURST and burst[-1] - burst[0] <= DEGRADED_BURST_SECONDS)


def handle_permissionrequest(hook):
    session = hook.get("session_id")
    if not away_on(session):
        return
    tool = hook.get("tool_name") or ""
    tool_input = hook.get("tool_input") or {}
    ctx = session_ctx(hook)
    if tool == "ExitPlanMode":
        rec = {"ts": now_iso(), "event": "plan_self_approved", "tool": tool,
               "tool_use_id": hook.get("tool_use_id"),
               "detail": {"plan": tool_input.get("plan")},
               "rule": "away: plan approved for you"}
        rec.update(ctx)
        log_event(rec)
        emit_permreq("allow")
        return
    # Nobody can answer a prompt, so it dies here with a way forward rather than
    # stalling the absence.
    kind = denial_kind(tool_input.get("command") or "") if tool == "Bash" else "other"
    rec = {"ts": now_iso(), "event": "deferred", "tool": tool,
           "tool_use_id": hook.get("tool_use_id"), "detail": tool_input,
           "rule": "away: nothing can be approved (%s)" % kind}
    rec.update(ctx)
    log_event(rec)
    message = DENY_MESSAGES[kind] + (DEGRADED if degraded(session) else "")
    emit_permreq("deny", message + note_suffix(session))


def handle_permissiondenied(hook):
    """Auto mode refused a call. Nothing can be said back to the model, so log it."""
    if not away_on(hook.get("session_id")):
        return
    rec = {"ts": now_iso(), "event": "auto_denied", "tool": hook.get("tool_name"),
           "tool_use_id": hook.get("tool_use_id"), "detail": hook.get("tool_input"),
           "rule": "auto mode: denied"}
    rec.update(session_ctx(hook))
    log_event(rec)


STOP_EVENTS = ("stop_blocked", "ping_requested", "ping_sent", "ping_failed",
               "ping_skipped")


def handle_stop(hook):
    """Block an early hand-back once, when a denial went unresolved this session,
    then ask for a Slack Ping status report before the stop that is accepted.

    The nudge is capped at one per session and the report at one per hand-back,
    so a misjudgement here can never trap an agent in a loop.
    """
    session = hook.get("session_id") or "unknown"
    if not away_on(session):
        return
    denied = blocked = False
    last_stop = None
    for line in tail_lines(EVENTS, 800):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if rec.get("session") != session:
            continue
        if rec.get("event") in ("deferred", "deferred_by_model", "decision_forced",
                                "auto_denied"):
            denied = True
        if rec.get("event") == "stop_blocked":
            blocked = True
        if rec.get("event") in STOP_EVENTS:
            last_stop = rec.get("event")
    if not denied or blocked:
        ping_on_stop(hook, session, last_stop)
        return
    ctx = session_ctx(hook)
    rec = {"ts": now_iso(), "event": "stop_blocked", "tool": "Stop",
           "detail": None, "rule": "away: one nudge to finish the unblocked work"}
    rec.update(ctx)
    log_event(rec)
    print(json.dumps({
        "decision": "block",
        "reason": (
            "AWAY MODE. A command was denied earlier in this session, and the "
            "operator cannot answer. Do not stop yet. Finish every part of the "
            "work that the denial does not block. Then state, in your summary, "
            "what you deferred, the evidence, and your recommendation. This "
            "nudge fires only once, so your next stop will be accepted."
            + note_suffix(session)),
    }))


def ping_config():
    """(webhook, user id) when the operator has set Slack Ping up, else None."""
    try:
        url = (PING / "webhook_url").read_text(encoding="utf-8").strip()
        uid = (PING / "user_id").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return (url, uid) if url and uid else None


def send_ping(url, uid, message):
    body = json.dumps({"message": message, "userId": uid}).encode("utf-8")
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=PING_TIMEOUT) as resp:
        return resp.status == 200


def last_assistant_text(hook):
    """The agent's final message, from the hook field or the transcript's tail."""
    text = hook.get("last_assistant_message")
    if isinstance(text, str) and text.strip():
        return text.strip()
    for line in reversed(tail_lines(hook.get("transcript_path") or "", 200)):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if rec.get("type") != "assistant":
            continue
        content = (rec.get("message") or {}).get("content")
        if isinstance(content, str):
            parts = [content]
        else:
            parts = [c.get("text", "") for c in content or []
                     if isinstance(c, dict) and c.get("type") == "text"]
        joined = "\n".join(p for p in parts if p).strip()
        if joined:
            return joined
    return ""


def ping_on_stop(hook, session, last_stop):
    """Have the agent end on a status report, then send that message from here.

    The hook sends it, not the agent: an agent's own POST to a webhook is exactly
    the outward write this guard denies, and the recipient stays pinned to the
    operator instead of whatever id the agent passes.
    """
    config = ping_config()
    if not config:
        return
    ctx = session_ctx(hook)

    def log(event):
        rec = {"ts": now_iso(), "event": event, "tool": "Stop", "detail": None,
               "rule": "away: status report to Slack Ping"}
        rec.update(ctx)
        log_event(rec)

    if hook.get("stop_hook_active") and last_stop == "ping_requested":
        text = last_assistant_text(hook)
        if not text:
            log("ping_skipped")
            return
        try:
            ok = send_ping(config[0], config[1], text)
        except Exception as exc:
            print("away-guard: slack ping failed: %s" % exc, file=sys.stderr)
            ok = False
        log("ping_sent" if ok else "ping_failed")
        return
    log("ping_requested")
    print(json.dumps({
        "decision": "block",
        "reason": (
            "AWAY MODE. Before you stop, end your turn with one final message "
            "that is a status report for the operator, and nothing else. This "
            "hook sends that message to them as a Slack DM, so do not send it "
            "yourself.\n"
            "Plain text only: Slack formatting such as *bold*, backticks, > and "
            "markdown headings shows literally. It is read on a phone, so keep it "
            "crisp: at most 5 lines, no headings, no filler. Line 1: ✅ done, ❌ "
            "failed or ⏸️ needs input, then the repo or task and the outcome in "
            "one clause. Then only what the operator must know or act on, one • "
            "bullet each: a blocker or deferred call with your recommendation, "
            "or a mistake you made. Nothing to add means line 1 alone. No secrets "
            "or customer data. Your next stop will be accepted."
            + (DEGRADED if degraded(hook.get("session_id")) else "")),
    }))


def events_for(session, since, until=None):
    """This session's events only.

    The log is shared by every agent. Anything injected into a session's context
    must be scoped to that session, or an idle agent starts reporting on work it
    never did.
    """
    mine = []
    for line in tail_lines(EVENTS, 6000):
        try:
            rec = json.loads(line)
            stamp = datetime.strptime(rec.get("ts", ""), "%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            continue
        when = stamp.replace(tzinfo=timezone.utc).timestamp()
        if when < since or (until is not None and when > until):
            continue
        if rec.get("session") != session or rec.get("synthetic"):
            continue
        mine.append(rec)
    return mine


RULES_REFRESH_SECONDS = 3600


def needs_full_rules(session, hook=None):
    """Full rules on a session's first prompt, then hourly.

    Steering repeatedly should not re-inject 500 tokens every time. The hourly
    refresh exists because context compaction can summarise the rules away, and
    a short reminder alone would then be pointing at nothing.

    The marker doubles as a roster. A compliant agent that simply never asks
    produces no log events at all, so without this there is no record that it
    operated under away mode.
    """
    marker = STATE / "greeted" / session
    now = time.time()
    try:
        if now - json.loads(marker.read_text()).get("at", 0) < RULES_REFRESH_SECONDS:
            return False
    except Exception:
        pass
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        entry = {"at": now, "session": session}
        if hook:
            ctx = session_ctx(hook)
            entry.update({"label": ctx["label"], "cwd": ctx["cwd"],
                          "branch": ctx["branch"]})
        marker.write_text(json.dumps(entry))
    except Exception:
        pass
    return True


def handle_userpromptsubmit(hook):
    session = hook.get("session_id") or "unknown"
    if away_on(session):
        state = scope_state(session)
        started = state.get("since_epoch") or time.time()
        elapsed = max(0, int(time.time() - started))
        hours, minutes = elapsed // 3600, (elapsed % 3600) // 60
        head = ["=== AWAY MODE IS ON ===",
                "Elapsed: %dh %dm. This session has logged %d event(s)." % (
                    hours, minutes, len(events_for(session, started)))]
        if state.get("note"):
            head.append('Operator note: "%s"' % state["note"])
        if hours >= NAG_AFTER_HOURS:
            head.append("Away mode has been on for over %dh. If the operator is back, "
                        "they should run `away off`." % NAG_AFTER_HOURS)
        if needs_full_rules(session, hook):
            head.append("Run `away report` to read what happened. Follow these rules:")
            try:
                head.append("")
                head.append(RULES.read_text(encoding="utf-8"))
                rc, out, _ = run([sys.executable, str(AWAY / "bin" / "perms.py"), "--brief"],
                                 cwd=hook.get("cwd"))
                if rc == 0 and out.strip():
                    head += ["", "Rules the harness applies (all denied while away; "
                             "`away perms \"<cmd>\"` checks one):",
                             out.decode("utf-8", "replace").rstrip()]
            except Exception:
                head.append("(rules.md unreadable: deny every question, never wait.)")
        else:
            head.append("The away rules already in your context still apply: never "
                        "ask, decide and note the assumption, defer with evidence. "
                        "Re-read %s if they are no longer in context." % RULES)
        emit_context("\n".join(head))
        return

    # Away mode has ended. Tell this session what IT deferred, not what every
    # other agent did: the operator reads the global digest in their terminal.
    # A session that armed itself with --here ends alone, so its own file is
    # checked first; without it, `away off --here` produced no hand-back at all.
    ended = None
    own = SESSION_ENDED / ("%s.json" % session) if session else None
    for source in (own, ENDED):
        if source is None:
            continue
        try:
            ended = json.loads(source.read_text(encoding="utf-8"))
            break
        except Exception:
            continue
    if ended is None:
        return
    marker = STATE / "consumed" / session
    if marker.exists():
        return
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(str(time.time()))
    except Exception:
        pass
    mine = events_for(session, ended.get("since", 0), ended.get("until"))
    if not mine:
        return              # this session deferred nothing, so say nothing
    lines = ["=== AWAY MODE ENDED ===",
             "It ran for %s. YOUR session logged %d event(s):"
             % (ended.get("duration", "?"), len(mine))]
    for rec in mine:
        detail = rec.get("detail") or {}
        what = detail.get("command") if isinstance(detail, dict) else None
        lines.append("  %s  %-22s %s" % (to_local(rec.get("ts")),
                                         rec.get("event"), (what or "")[:80]))
    lines.append("Report these to the operator: what you deferred, the evidence, "
                 "and your recommendation. Do not report other agents' work.")
    emit_context("\n".join(lines))


def main():
    event = (sys.argv[1] if len(sys.argv) > 1 else "").lower()
    raw = sys.stdin.read()
    try:
        hook = json.loads(raw) if raw.strip() else {}
    except Exception as exc:
        print("away-guard: unparseable hook JSON: %s" % exc, file=sys.stderr)
        raise SystemExit(1)
    if event == "pretooluse":
        handle_pretooluse(hook)
    elif event == "permissionrequest":
        handle_permissionrequest(hook)
    elif event == "permissiondenied":
        handle_permissiondenied(hook)
    elif event == "userpromptsubmit":
        handle_userpromptsubmit(hook)
    elif event == "stop":
        handle_stop(hook)
    raise SystemExit(0)


if __name__ == "__main__":
    main()
