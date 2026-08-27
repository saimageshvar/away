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
import shutil
import subprocess
import sys
import tarfile
import time
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
TRASH = STATE / "trash"
ENDED = STATE / "ended.json"
SESSION_ENDED = STATE / "sessions-ended"
RULES = AWAY / "rules.md"

NAG_AFTER_HOURS = 8
MAX_SNAPSHOT_BYTES = 50 * 1024 * 1024
MAX_ASK_RETRIES = 3

# Deleting these regenerates them, so they need no snapshot. Segment names only.
EPHEMERAL = {
    "node_modules", "tmp", "temp", "log", "logs", "reports", "coverage",
    "dist", "build", "target", ".cache", ".next", ".turbo", ".venv",
    ".pytest_cache", "__pycache__", ".sass-cache", ".parcel-cache",
}

# Outward or irreversible, and not expressible as a git subcommand.
OUTWARD = [
    (r"--no-verify\b", "Never bypass the commit gate."),
    (r"\baws\s", "Cloud calls need the operator."),
    (r"\bterraform\s", "Infrastructure changes need the operator."),
    (r"\bsudo\s", "sudo needs the operator."),
    (r"\b(npm|pnpm|yarn)\s+publish\b", "Publishing needs the operator."),
    (r"\bgem\s+push\b", "Publishing needs the operator."),
    (r"\bdocker\s+push\b", "Publishing needs the operator."),
    (r"\bgh\s+(pr\s+merge|release\s+create)\b",
     "Merging and releasing need the operator."),
    (r"\b(tee|mv|cp)\b[^|;&]*\s/(etc|usr|boot|sys)/",
     "Writes to system paths need the operator."),
]

# Matched against a parsed git subcommand, so `git -C /path push` cannot slip by
# on adjacency the way a plain regex allowed.
GIT_OUTWARD = {
    "push": "git push is never yours while away. Commit the work and leave it unpushed.",
    "remote": "Remote surgery needs the operator.",
}

# git config reads are fine; a write is not. An alias is the sharpest case:
# `git config alias.x '!rm -rf /'` arms a delete that no later scan would see.
GIT_CONFIG_READS = {"--get", "--get-all", "--get-regexp", "--get-urlmatch",
                    "--list", "-l", "--show-origin", "--show-scope"}

# gh is deny-by-default: it reaches GitHub, and a read allowlist is auditable in
# a way that chasing every write verb across gh's growing surface is not.
GH_READS = {
    "pr": {"view", "list", "diff", "status", "checks"},
    "issue": {"view", "list", "status"},
    "release": {"view", "list", "download"},
    "repo": {"view", "list", "clone"},
    "run": {"view", "list", "watch", "download"},
    "workflow": {"view", "list"},
    "cache": {"list"},
    "secret": {"list"},
    "variable": {"list"},
    "search": None,     # every subcommand reads
    "browse": None,
    "status": None,
    "auth": {"status"},
    "label": {"list"},
    "gist": {"view", "list"},
}

# -f/-F/--input switch gh api to POST with no -X at all, so the method flag
# alone is not a safe predicate.
GH_API_WRITE_FLAGS = {"-f", "--raw-field", "-F", "--field", "--input"}
GH_OPTS_WITH_ARG = {"-R", "--repo", "--hostname", "--template", "--jq", "-q"}

# A path we cannot resolve statically is a path we must not delete.
UNRESOLVABLE = re.compile(r"[*?\[\]]|\$\(|\$\{|\$[A-Za-z_]|`")

SEPARATORS = {"&&", "||", ";", "|", "&"}

# git global options that consume the following token, so the subcommand parser
# does not mistake their argument for the subcommand.
GIT_OPTS_WITH_ARG = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}

# Cheap pre-filter over the raw string: it decides only whether the command is
# worth reasoning about, never whether it is allowed. Deliberately loose, because
# every real decision below is gated behind it.
DELETION_HINT = re.compile(r"\b(rm|unlink|shred|srm)\b|-delete\b|-exec\s+rm\b", re.I)

# These forms of "rm" remove packages or containers, never files on disk.
NON_FS_RM = re.compile(
    r"\b(git|docker(\s+(compose|container|image|volume|network))?|npm|pnpm|yarn|"
    r"brew|apt|apt-get|gem|pip|pip3|cargo|kubectl|helm)\s+rm\b", re.I)

DELETE_BINS = {"rm", "unlink", "shred", "srm"}

# Commands that only ever READ their arguments. `grep -n rm README` names rm
# without running it; without this the guard read README as a delete target and
# handed the whole command an explicit allow.
DATA_CONSUMERS = {"echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "cat",
                  "head", "tail", "man", "which", "type", "wc", "sort", "uniq"}

# A payload handed to one of these is opaque to us, so a delete inside it is
# invisible to token parsing. sed and awk are absent on purpose: both can shell
# out, so neither is safe to exempt.
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}
INTERPRETERS = {"python", "python3", "perl", "ruby", "node", "php", "osascript"}

# Command substitution and here-docs build a command we never get to see.
CONDUIT_CHARS = re.compile(r"\$\(|`|<<")

ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z_0-9]*=")

# Words that stand in front of the real command without being it.
CMD_PREFIXES = {"sudo", "env", "nice", "time", "nohup", "command", "builtin",
                "exec", "timeout", "stdbuf", "then", "do", "else", "{", "!"}

# The hook is handed the session cwd, not the cd target. A single leading `cd`
# into the tree is still resolvable, so effective_base() handles it rather than
# denying outright; anything more complicated is not scopable.
CWD_CHANGE = re.compile(r"\b(cd|pushd|popd)\b")

# Away mode is worthless if an agent can switch it off, so the guard protects its
# own machinery. Only the operator, from their own terminal, may disarm it.
AWAY_TOGGLE = re.compile(r"\baway\s+(on|off)\b")
SELF_PATHS = re.compile(r"\.claude/(away\b|settings\.json|settings\.local\.json)")
# An interpreter can do anything, so treat one as a mutation of whatever it names.
MUTATES = re.compile(
    r">>?|\brm\b|\bmv\b|\bcp\b|\btee\b|\btruncate\b|\bsed\s+-i|\bchmod\b|\bln\b|"
    r"\bunlink\b|\bpython3?\b|\bnode\b|\bperl\b|\bruby\b|\bdd\b")
TAMPER_TOOLS = ("Edit", "Write", "NotebookEdit", "MultiEdit")

# The delete runs on another filesystem, so host-tree containment says nothing
# about it. Bind mounts mean it can still reach host files, so it is not free.
CONTAINER_EXEC = re.compile(
    r"^\s*(docker\s+compose\s+exec|docker\s+exec|docker-compose\s+exec|"
    r"kubectl\s+exec|podman\s+exec)\b", re.I)


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


def emit_permreq(behavior):
    # PermissionRequest documents only behavior and updatedInput, so no reason
    # field is sent. PreToolUse carries every reason the agent needs to read.
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PermissionRequest",
        "decision": {"behavior": behavior},
    }}))


def emit_context(text):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "UserPromptSubmit",
        "additionalContext": text,
    }}))


# -------------------------------------------------------------- rm reasoning

def git_calls(cmd):
    """Return [(subcommand, args)] per git invocation, or None if unparseable."""
    try:
        toks = shlex.split(cmd)
    except ValueError:
        return None
    calls, i = [], 0
    while i < len(toks):
        if toks[i] != "git" and not toks[i].endswith("/git"):
            i += 1
            continue
        j = i + 1
        while j < len(toks) and toks[j].startswith("-"):
            j += 2 if toks[j] in GIT_OPTS_WITH_ARG else 1
        sub = toks[j] if j < len(toks) and toks[j] not in SEPARATORS else None
        args, k = [], j + 1
        while k < len(toks) and toks[k] not in SEPARATORS:
            args.append(toks[k])
            k += 1
        if sub:
            calls.append((sub, args))
        i = max(k, i + 1)
    return calls


def gh_calls(cmd):
    """[(group, verb, args)] per gh invocation, or None if unparseable."""
    segs = segments(cmd)
    if segs is None:
        return None
    calls = []
    for toks in segs:
        for index, tok in enumerate(toks):
            if tok.rsplit("/", 1)[-1].lower() != "gh":
                continue
            words, rest, j = [], [], index + 1
            while j < len(toks):
                item = toks[j]
                if item in GH_OPTS_WITH_ARG:
                    j += 2
                    continue
                if item.startswith("-"):
                    rest.append(item)
                elif len(words) < 2:
                    words.append(item)
                else:
                    rest.append(item)
                j += 1
            calls.append((words[0] if words else None,
                          words[1] if len(words) > 1 else None, rest))
            break
    return calls


def gh_outward(group, verb, args):
    """Why this gh call needs the operator, or None when it only reads."""
    if group is None:
        return None                     # bare `gh`, or only flags: harmless
    if group == "api":
        method = None
        for index, arg in enumerate(args):
            if arg in ("-X", "--method"):
                method = args[index + 1] if index + 1 < len(args) else ""
            elif arg.startswith("-X"):
                method = arg[2:]        # glued form: -XPOST
            elif arg.startswith("--method="):
                method = arg.split("=", 1)[1]
        if any(a.split("=")[0] in GH_API_WRITE_FLAGS for a in args):
            return ("gh api sends a POST as soon as a field flag is present, so "
                    "this writes to GitHub.")
        if method and method.upper() not in ("GET", "HEAD"):
            return "gh api with %s writes to GitHub." % method.upper()
        return None
    if group not in GH_READS:
        return "gh %s reaches GitHub, and only read commands are yours while away." % group
    allowed = GH_READS[group]
    if allowed is None or (verb in allowed):
        return None
    return ("gh %s %s writes to GitHub, and that needs the operator."
            % (group, verb or ""))


def git_destructive(sub, args):
    """True when this git subcommand can destroy uncommitted work."""
    flags = [a for a in args if a.startswith("-")]
    joined = " ".join(flags)
    if sub == "reset":
        return "--hard" in args
    if sub == "restore":
        return True
    if sub == "checkout":
        # A path-mode checkout overwrites the work tree; a branch switch does not.
        return "--" in args or "." in args or "-f" in flags or "--force" in flags
    if sub == "switch":
        return "--discard-changes" in args or "-f" in flags or "--force" in flags
    if sub == "clean":
        return any("f" in f.lstrip("-") for f in flags if not f.startswith("--")) \
            or "--force" in flags
    if sub == "stash":
        return bool(args) and args[0] in ("drop", "clear")
    if sub == "rm":
        return "--cached" not in args and bool(joined or args)
    return False


def is_recursive(flags):
    """True for -r, -R, --recursive, and bundles like -rf or -Rf."""
    for flag in flags:
        if flag in ("--recursive", "-r", "-R"):
            return True
        if flag.startswith("-") and not flag.startswith("--") and "r" in flag.lower():
            return True
    return False


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


def shell_payloads(toks):
    """Payload strings of any `shell -c` / `interpreter -e` pair, at ANY position.

    Position-independent on purpose: `docker compose exec web sh -lc "rm -rf …"`
    hides the delete behind four tokens, and combined flags like -lc or -euc are
    the normal way that gets written.
    """
    found = []
    for index, tok in enumerate(toks):
        base = tok.rsplit("/", 1)[-1].lower()
        if base in SHELLS:
            wanted = ("c",)
        elif base in INTERPRETERS:
            wanted = ("c", "e")
        else:
            continue
        for j in range(index + 1, len(toks)):
            flag = toks[j]
            if not flag.startswith("-"):
                break
            if any(letter in flag.lstrip("-") for letter in wanted):
                found.append(toks[j + 1] if j + 1 < len(toks) else "")
                break
    return found


def delete_shaped(cmd):
    """(shaped, conduit_reason). Shape decides only that we must REASON.

    Fail-closed by construction: anything the parser cannot see through is
    shaped, because the fallthrough for an unshaped command is defer, and defer
    runs the command.
    """
    if not DELETION_HINT.search(NON_FS_RM.sub("", cmd)):
        return False, None
    segs = segments(cmd)
    if segs is None:
        return True, "the command does not parse"
    for toks in segs:
        if shell_payloads(toks):
            return True, "a shell or interpreter payload the guard cannot parse"
        word = (command_word(toks) or "").rsplit("/", 1)[-1].lower()
        if word in SHELLS or word in INTERPRETERS or word == "eval":
            return True, "%s, which runs a payload the guard cannot parse" % word
    if CONDUIT_CHARS.search(cmd):
        return True, ("command substitution or a here-doc, which builds a "
                      "command the guard cannot parse")
    for toks in segs:
        word = (command_word(toks) or "").rsplit("/", 1)[-1].lower()
        if word in DATA_CONSUMERS:
            continue            # names a delete in its arguments, never runs one
        for tok in toks:
            if tok.startswith("-"):
                continue
            # APFS is case-insensitive, so `RM` really does execute /bin/rm.
            if tok.rsplit("/", 1)[-1].lower() in DELETE_BINS:
                return True, None
        if "-delete" in toks or "-exec" in toks:
            return True, None
    return False, None


def rm_invocations(cmd):
    """Return [(flags, paths)] for real rm calls, or None if unparseable.

    An rm only counts in COMMAND position for its segment. As an argument it is
    data: `grep -n rm README` once had README classified as a delete target, and
    the misreading granted the whole command an explicit allow.
    """
    segs = segments(cmd)
    if segs is None:
        return None
    found = []
    for toks in segs:
        index = command_index(toks)
        if index is None or toks[index].rsplit("/", 1)[-1].lower() not in DELETE_BINS:
            continue
        flags, paths, end_of_flags = [], [], False
        for tok in toks[index + 1:]:
            if tok == "--" and not end_of_flags:
                end_of_flags = True          # every later token is a path
            elif not end_of_flags and tok.startswith("-") and len(tok) > 1:
                flags.append(tok)
            else:
                paths.append(tok)
        found.append((flags, paths))
    return found


def scratch_roots():
    """Temp roots whose contents are as regenerable as node_modules.

    Resolved, because /tmp is a symlink to /private/tmp on macOS and $TMPDIR is
    handed out under /private/var/folders. Only these two: the rest of
    /var/folders holds live per-user launchd and app state.
    """
    roots = []
    for raw in (os.environ.get("TMPDIR"), "/tmp"):
        if not raw:
            continue
        try:
            roots.append(Path(raw).resolve())
        except Exception:
            continue
    return roots


def under_scratch(target):
    """True for a path strictly BELOW a temp root, so `rm -rf /tmp` still dies.

    resolve() has already followed symlinks, so /tmp/link -> ~/work lands outside
    the root and falls through to the normal containment check.
    """
    for root in scratch_roots():
        if target != root and root in target.parents:
            return True
    return False


def classify_static(raw, cwd):
    """Classify what needs no git query. None means "ask git about this one"."""
    if UNRESOLVABLE.search(raw):
        return "unresolvable", None
    # The shell expands ~ before rm ever sees it. Resolving the literal against
    # cwd made ~/logs read as an in-tree path and allowed a delete in $HOME.
    raw = os.path.expanduser(raw)
    if raw.startswith("~"):
        # expanduser leaves ~nosuchuser untouched, and that must not become a
        # relative path either.
        return "unresolvable", None
    try:
        target = (Path(cwd) / raw).resolve()
        base = Path(cwd).resolve()
    except Exception:
        return "unresolvable", None
    if target == base or target in base.parents:
        return "outside", target
    try:
        rel = target.relative_to(base)
    except ValueError:
        # Scratch is checked only out here, so it can widen "outside the tree"
        # without ever weakening a working tree that happens to live under
        # $TMPDIR — which is exactly where a worktree or a test fixture lands.
        return ("scratch" if under_scratch(target) else "outside"), target
    parts = set(rel.parts)
    if ".git" in parts:
        return "git-internal", target
    if parts & EPHEMERAL:
        return "ephemeral", target
    return None, target


def classify_git(target, cwd):
    """Ask git about one path. Two calls, and both fail loudly.

    A batched form is possible, but it has to reconcile ls-files (cwd-relative)
    against diff (root-relative) and survive the /var -> /private/var symlink.
    Break either invariant and a file is misclassified SILENTLY, then deleted
    with no snapshot. These per-path calls carry no such invariant, and the
    batched version saved nothing for a one-path delete, which is the common case.

    `git status --porcelain` cannot replace either call: it omits clean tracked
    files AND ignored files alike, so an ignored file would read as clean-tracked
    and lose its snapshot.
    """
    if run(["git", "ls-files", "--error-unmatch", "--", str(target)],
           cwd=cwd)[0] != 0:
        return "untracked"
    # A tracked file with uncommitted edits is only half recoverable: git restores
    # the committed version and loses the diff, so it still needs a snapshot.
    if run(["git", "diff", "--quiet", "HEAD", "--", str(target)], cwd=cwd)[0] != 0:
        return "tracked-dirty"
    return "tracked"


def size_within(path, cap):
    if path.is_file() or path.is_symlink():
        try:
            size = path.stat().st_size
            return size <= cap, size
        except OSError:
            return False, 0
    total = 0
    for root, _dirs, files in os.walk(path, onerror=lambda _e: None):
        for name in files:
            try:
                total += (Path(root) / name).stat().st_size
            except OSError:
                continue
            if total > cap:
                return False, total
    return True, total


def new_bundle(ctx, kind):
    """Claim a unique bundle dir. Concurrent agents can collide within a second."""
    base = "%s-%s-%s" % (time.strftime("%Y%m%d-%H%M%S"), ctx["session"][:6], kind)
    TRASH.mkdir(parents=True, exist_ok=True)
    for suffix in [""] + ["-%d" % n for n in range(1, 1000)]:
        candidate = TRASH / (base + suffix)
        try:
            candidate.mkdir(parents=False, exist_ok=False)
            return candidate
        except FileExistsError:
            continue
    raise RuntimeError("cannot claim a bundle dir under %s" % TRASH)


def snapshot_paths(targets, ctx, cmd, best_effort=()):
    """Copy unrecoverable targets into trash so the delete stays reversible.

    best_effort holds scratch paths: worth keeping when they are small, never
    worth blocking a delete over, because a temp dir is regenerable by definition.
    """
    bundle = new_bundle(ctx, "rm")
    saved, skipped = [], []
    for target in targets:
        optional = target in best_effort
        ok, size = size_within(target, MAX_SNAPSHOT_BYTES)
        if not ok:
            if optional:
                skipped.append(str(target))
                continue
            shutil.rmtree(bundle, ignore_errors=True)
            return None, "%s exceeds the %dMB snapshot cap" % (
                target, MAX_SNAPSHOT_BYTES // 1048576)
        dest = bundle / "files" / str(target).lstrip("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            if target.is_dir() and not target.is_symlink():
                shutil.copytree(target, dest, symlinks=True, dirs_exist_ok=True)
            else:
                shutil.copy2(target, dest, follow_symlinks=False)
        except Exception as exc:
            if optional:
                skipped.append(str(target))
                continue
            shutil.rmtree(bundle, ignore_errors=True)
            return None, "snapshot of %s failed: %s" % (target, exc)
        saved.append({"path": str(target), "bytes": size})
    manifest = {"kind": "rm", "at": now_iso(), "command": cmd, "saved": saved,
                "not_saved": skipped}
    manifest.update(ctx)
    (bundle / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
    return bundle, None


def git_undo_bundle(ctx, cmd):
    """Capture a full undo bundle before a destructive git op runs."""
    cwd = ctx["cwd"]
    root = git_info(cwd)[0]
    if not root:
        return None, "the command does not run inside a git work tree"
    bundle = new_bundle(ctx, "git")
    rc, patch, _ = run(["git", "-C", root, "diff", "HEAD"], timeout=30)
    (bundle / "tracked.patch").write_bytes(patch if rc == 0 else b"")
    (bundle / "status.txt").write_text(
        git_out(["-C", root, "status", "--porcelain"], cwd) + "\n", encoding="utf-8")
    untracked = [
        line for line in git_out(
            ["-C", root, "ls-files", "-o", "--exclude-standard"], cwd).splitlines()
        if line
    ]
    kept, total = [], 0
    if untracked:
        with tarfile.open(bundle / "untracked.tar", "w") as tar:
            for rel in untracked:
                src = Path(root) / rel
                try:
                    size = src.stat().st_size
                except OSError:
                    continue
                if total + size > MAX_SNAPSHOT_BYTES:
                    continue
                total += size
                tar.add(src, arcname=rel)
                kept.append(rel)
    manifest = {"kind": "git", "at": now_iso(), "command": cmd, "repo": root,
                "untracked_saved": kept, "untracked_bytes": total}
    manifest.update(ctx)
    (bundle / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
    return bundle, None


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

def hidden_delete(cmd):
    """The construct hiding a delete from static scoping, or None.

    Narrower than the old blanket `find`/`xargs` match: a `find` that only lists
    is not a delete, and naming it as the blocker sent agents chasing the wrong
    clause while the real denial was an out-of-tree rm elsewhere in the script.
    """
    segs = segments(cmd)
    if segs is None:
        return "a command that does not parse"
    for toks in segs:
        if shell_payloads(toks):
            return "a shell or interpreter payload"
        word = (command_word(toks) or "").rsplit("/", 1)[-1].lower()
        if word == "eval":
            return "eval"
        if word == "find" and ("-delete" in toks or "-exec" in toks):
            return "find -delete or find -exec"
        for index, tok in enumerate(toks):
            if tok.rsplit("/", 1)[-1].lower() != "xargs":
                continue
            rest = [t for t in toks[index + 1:] if not t.startswith("-")]
            if rest and rest[0].rsplit("/", 1)[-1].lower() in DELETE_BINS:
                return "xargs"
    if CONDUIT_CHARS.search(cmd):
        return "command substitution or a here-doc"
    return None


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


def container_inner(cmd):
    """The inner shell script of a container exec, or None if this is not one."""
    if not CONTAINER_EXEC.match(cmd):
        return None
    try:
        toks = shlex.split(cmd)
    except ValueError:
        return None
    for index, tok in enumerate(toks):
        if tok.rsplit("/", 1)[-1] not in ("sh", "bash", "zsh", "dash"):
            continue
        j = index + 1
        while j < len(toks) and toks[j].startswith("-"):
            if "c" in toks[j]:
                return toks[j + 1] if j + 1 < len(toks) else None
            j += 1
        return None
    return None


def effective_base(cmd, cwd):
    """(base, error). One leading `cd` into the tree just moves the base."""
    if not CWD_CHANGE.search(cmd):
        return cwd, None
    try:
        toks = shlex.split(cmd)
    except ValueError:
        return None, "the command does not parse, so its targets cannot be scoped."
    changes = [i for i, t in enumerate(toks) if t in ("cd", "pushd", "popd")]
    if len(changes) != 1 or changes[0] != 0 or toks[0] != "cd":
        return None, ("the command changes directory more than once, or not at the "
                      "start, so its relative paths cannot be resolved.")
    if len(toks) < 2 or toks[1] in SEPARATORS or toks[1] == "-":
        return None, "the cd target cannot be determined."
    if UNRESOLVABLE.search(toks[1]):
        return None, "the cd target uses a glob or a variable."
    # Same hole as classify_static: an unexpanded ~ made `cd ~/elsewhere` look
    # like a move deeper into the working tree.
    dest = os.path.expanduser(toks[1])
    if dest.startswith("~"):
        return None, "the cd target names a home directory that does not exist."
    try:
        target = (Path(cwd) / dest).resolve()
        base = Path(cwd).resolve()
    except Exception:
        return None, "the cd target cannot be resolved."
    # Keep the containment guarantee: a cd out of the tree is still a denial.
    if target != base and base not in target.parents:
        return None, "the cd target is outside the working tree."
    return str(target), None


def unscopable(cmd, calls):
    """Why a delete-shaped command cannot be scoped, or None when it can be."""
    hidden = hidden_delete(cmd)
    if hidden:
        return ("the delete is reached through %s, so its targets cannot be "
                "scoped." % hidden)
    if calls is None:
        return "the command does not parse, so its targets cannot be scoped."
    if not calls:
        return ("a delete was detected but no explicit target could be parsed "
                "from it.")
    if any(not paths for _flags, paths in calls):
        return "a delete has no explicit target path."
    return None


TAMPER_REASON = (
    "this changes away mode's own enforcement, which no agent may do while away "
    "mode is on. Reading those files is fine; changing them is the operator's. "
    "If a rule is blocking necessary work, defer the work and say so in your "
    "summary with the exact command and why you needed it.")


def outward_reason(why):
    return ("%s Route around it or defer it with evidence. Do not retry: the "
            "denial will not change while the operator is away." % why)


def single_segment(cmd):
    """True when the command is one command, so an allow cannot cover a chain."""
    try:
        toks = shlex.split(cmd)
    except ValueError:
        return False
    return not any(tok in SEPARATORS for tok in toks)


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


def handle_container_delete(hook, cmd, inner):
    """A delete inside a container. Host containment cannot be checked, so only
    regenerable targets pass: a bind mount can still reach host files."""
    icalls = rm_invocations(inner)
    ok = bool(icalls) and all(paths for _flags, paths in icalls) and all(
        set(Path(p).parts) & EPHEMERAL
        for _flags, paths in icalls for p in paths)
    if not ok:
        deny(hook, "Bash",
             "this deletes inside a container, where the host working tree cannot "
             "be checked, and not every target is regenerable. Only paths such as "
             "node_modules, dist, or tmp are allowed through a container exec.",
             detail={"command": cmd, "inner": inner})
        return
    ctx = session_ctx(hook)
    rec = {"ts": now_iso(), "event": "container_delete_allowed", "tool": "Bash",
           "tool_use_id": hook.get("tool_use_id"),
           "detail": {"command": cmd, "inner": inner},
           "rule": "away: container delete targets only regenerable paths"}
    rec.update(ctx)
    log_event(rec)
    # defer, so the rest of the command still meets the normal permission rules


def handle_rm(hook, cmd, calls, base=None):
    ctx = session_ctx(hook)
    if base:
        # A leading `cd` moved the root that relative paths resolve against.
        ctx = dict(ctx, cwd=base)

    # Pass 1: everything decidable without git, so a blocker short-circuits
    # before any subprocess runs.
    staged, blockers = [], {
        "unresolvable": "a target uses a glob or a variable, so it cannot be scoped",
        "outside": "a target sits outside the working tree",
        "git-internal": "a target is inside .git",
    }
    for flags, paths in calls:
        recursive = is_recursive(flags)
        for raw in paths:
            kind, target = classify_static(raw, ctx["cwd"])
            if kind in blockers:
                deny(hook, "Bash",
                     "%s (%s). Delete only resolvable paths inside the working tree."
                     % (blockers[kind], raw),
                     detail={"command": cmd, "target": raw, "class": kind})
                return
            staged.append((raw, kind, target, recursive))

    # Pass 2: only the paths that still need git pay for it.
    verdicts, to_snapshot, optional, bad_recursive = [], [], [], None
    for raw, kind, target, recursive in staged:
        if kind is None:
            kind = classify_git(target, ctx["cwd"])
        verdicts.append((raw, kind, target))
        if kind in ("untracked", "tracked-dirty"):
            to_snapshot.append(target)
        elif kind == "scratch":
            to_snapshot.append(target)
            optional.append(target)
        # Recursion is judged per call, so one cleanup in a chain cannot condemn
        # an unrelated single-file delete beside it.
        if recursive and kind not in ("ephemeral", "scratch"):
            bad_recursive = raw
    if bad_recursive:
        deny(hook, "Bash",
             "a recursive delete may only target regenerable paths, and %s is not "
             "one." % bad_recursive,
             detail={"command": cmd,
                     "verdicts": [[r, k] for r, k, _t in verdicts]})
        return
    if not verdicts:
        deny(hook, "Bash", "a delete has no explicit target path.",
             detail={"command": cmd})
        return

    bundle = None
    if to_snapshot:
        bundle, err = snapshot_paths(to_snapshot, ctx, cmd, best_effort=optional)
        if err:
            deny(hook, "Bash", "the delete is unrecoverable and %s." % err,
                 detail={"command": cmd})
            return
    rec = {"ts": now_iso(), "event": "rm_allowed", "tool": "Bash",
           "tool_use_id": hook.get("tool_use_id"),
           "detail": {"command": cmd,
                      "verdicts": [[r, k] for r, k, _t in verdicts],
                      "snapshot": str(bundle) if bundle else None},
           "rule": "away: delete is inside the tree and recoverable"}
    rec.update(ctx)
    log_event(rec)
    # An explicit allow covers the WHOLE command, so a chain only ever defers to
    # the normal rules. rm is no longer in the ask list, so defer still runs it.
    if not single_segment(cmd):
        return
    note = " A snapshot is saved at %s." % bundle if bundle else ""
    where = ("the working tree or a temp directory"
             if any(k == "scratch" for _r, k, _t in verdicts)
             else "the working tree")
    emit_pretool("allow", "AWAY MODE. Delete allowed: every target is inside %s "
                          "and recoverable.%s" % (where, note))


def handle_git_destructive(hook, cmd):
    ctx = session_ctx(hook)
    bundle, err = git_undo_bundle(ctx, cmd)
    if err:
        deny(hook, "Bash", "this destroys uncommitted work and %s." % err,
             detail={"command": cmd})
        return
    rec = {"ts": now_iso(), "event": "git_destructive_allowed", "tool": "Bash",
           "tool_use_id": hook.get("tool_use_id"),
           "detail": {"command": cmd, "snapshot": str(bundle)},
           "rule": "away: undo bundle captured first"}
    rec.update(ctx)
    log_event(rec)
    if not single_segment(cmd):
        return
    emit_pretool("allow", "AWAY MODE. Allowed, and an undo bundle is saved at %s. "
                          "Recover it with `away trash`." % bundle)


def handle_pretooluse(hook):
    tool = hook.get("tool_name") or ""
    tool_input = hook.get("tool_input") or {}
    on = away_on(hook.get("session_id"))

    if on and tool in TAMPER_TOOLS:
        if SELF_PATHS.search(json.dumps(tool_input)):
            deny(hook, tool, TAMPER_REASON, detail={"tool_input": tool_input})
        return

    if tool == "Bash":
        cmd = tool_input.get("command") or ""
        if on:
            # A session may scope away mode to itself. Only the operator may touch
            # the global flag, and the resolver checks that flag first, so a
            # session can never free itself from a real absence.
            if away_toggle_scope(cmd) == "global":
                deny(hook, tool,
                     "only the operator may switch away mode on or off globally, and "
                     "they do it from their own terminal. `away on --here` and "
                     "`away off --here` scope it to this session, and `away report`, "
                     "`away status`, `away trash` and `away decision` are yours too.")
                return
            if SELF_PATHS.search(cmd) and MUTATES.search(cmd):
                deny(hook, tool, TAMPER_REASON)
                return
        deletes, _conduit = delete_shaped(cmd)
        calls = rm_invocations(cmd)

        if not on:
            # Away is OFF and we only reached python for rm, so reproduce the
            # `ask` rule this hook replaced. Everything else defers untouched.
            if deletes or calls:
                emit_pretool("ask", "This deletes files. Away mode is off, so it is "
                                    "the operator's call.")
            return

        # Outward ops are checked first and across the whole command, so an rm
        # early in a chain can never carry an approval for what follows it.
        for pattern, why in OUTWARD:
            if re.search(pattern, cmd):
                deny(hook, tool, outward_reason(why))
                return
        gcalls = git_calls(cmd)
        if gcalls is None:
            if deletes:
                deny(hook, tool, "the command does not parse, so its deletes "
                                 "cannot be scoped.")
            return
        for sub, _args in gcalls:
            if sub in GIT_OUTWARD:
                deny(hook, tool, outward_reason(GIT_OUTWARD[sub]))
                return
            # Any config WRITE, not just a scoped one: an unscoped
            # `git config alias.x '!rm -rf /'` used to pass untouched.
            if sub == "config" and not any(a in GIT_CONFIG_READS for a in _args):
                deny(hook, tool, outward_reason("Config changes need the operator."))
                return
        ghcalls = gh_calls(cmd)
        for group, verb, args in (ghcalls or []):
            why = gh_outward(group, verb, args)
            if why:
                deny(hook, tool, outward_reason(why))
                return

        # Anything delete-shaped that we cannot fully resolve must die here. The
        # fallthrough is `defer`, and Bash(*) turns defer into allow.
        base = ctx_cwd = hook.get("cwd") or os.getcwd()
        if deletes:
            inner = container_inner(cmd)
            if inner is not None:
                handle_container_delete(hook, cmd, inner)
                return
            base, err = effective_base(cmd, ctx_cwd)
            if err:
                deny(hook, tool, "%s Re-run it as an explicit `rm <path>` inside "
                                 "the working tree, or defer it." % err)
                return
            blocker = unscopable(cmd, calls)
            if blocker:
                deny(hook, tool, "%s Re-run it as an explicit `rm <path>` inside "
                                 "the working tree, or defer it." % blocker)
                return

        for sub, args in gcalls:
            if git_destructive(sub, args):
                handle_git_destructive(hook, cmd)
                return
        if calls:
            handle_rm(hook, cmd, calls, base)
            return
        return  # defer to the normal permission flow

    if not on:
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


def handle_permissionrequest(hook):
    if not away_on(hook.get("session_id")):
        return
    tool = hook.get("tool_name") or ""
    ctx = session_ctx(hook)
    if tool == "ExitPlanMode":
        rec = {"ts": now_iso(), "event": "plan_self_approved", "tool": tool,
               "tool_use_id": hook.get("tool_use_id"),
               "detail": {"plan": (hook.get("tool_input") or {}).get("plan")},
               "rule": "away: plan approved for you"}
        rec.update(ctx)
        log_event(rec)
        emit_permreq("allow")
        return
    # Anything still reaching a prompt would stall the whole absence, so it dies
    # here rather than waiting for an operator who cannot answer.
    rec = {"ts": now_iso(), "event": "deferred", "tool": tool,
           "tool_use_id": hook.get("tool_use_id"),
           "detail": hook.get("tool_input"),
           "rule": "away: nothing can be approved"}
    rec.update(ctx)
    log_event(rec)
    emit_permreq("deny")


def handle_stop(hook):
    """Block an early hand-back once, when a denial went unresolved this session.

    Capped at one block per session. A second attempt always succeeds, so a
    misjudgement here can never trap an agent in a loop.
    """
    session = hook.get("session_id") or "unknown"
    if not away_on(session):
        return
    denied = blocked = False
    for line in tail_lines(EVENTS, 800):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        if rec.get("session") != session:
            continue
        if rec.get("event") in ("deferred", "decision_forced"):
            denied = True
        if rec.get("event") == "stop_blocked":
            blocked = True
    if not denied or blocked:
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
    elif event == "userpromptsubmit":
        handle_userpromptsubmit(hook)
    elif event == "stop":
        handle_stop(hook)
    raise SystemExit(0)


if __name__ == "__main__":
    main()
