#!/usr/bin/env python3
"""Wire away mode into Claude Code, and diagnose that wiring.

Two entry points share one set of checks so `away setup` and `away doctor` can
never disagree about what a correct install looks like:

    setup.py setup [--yes]   apply the wiring, then report
    setup.py check           report only, exit non-zero on a hard failure

Everything here is idempotent. Re-running setup after moving AWAY_HOME rewrites
the hook paths in place rather than appending a second copy.
"""

import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

AWAY = Path(os.environ.get("AWAY_HOME") or (Path.home() / ".claude" / "away"))
CLAUDE = Path(os.environ.get("CLAUDE_CONFIG_DIR") or (Path.home() / ".claude"))
SETTINGS = CLAUDE / "settings.json"
SETTINGS_LOCAL = CLAUDE / "settings.local.json"
SKILL_DIR = CLAUDE / "skills" / "away"
BIN_DIR = Path(os.environ.get("AWAY_BIN_DIR") or (Path.home() / ".local" / "bin"))

# The four events the guard serves, and the timeout each one gets. PreToolUse is
# the widest because it fires on every tool call in every agent.
HOOK_EVENTS = [
    ("PreToolUse", "pretooluse", "*", 30),
    ("PermissionRequest", "permissionrequest", "*", 20),
    ("Stop", "stop", None, 15),
    ("UserPromptSubmit", "userpromptsubmit", None, 15),
]

# A permission mode that still raises prompts is fatal to away mode: nobody is
# there to answer, so the agent stalls instead of routing around.
SAFE_MODES = {"auto", "bypassPermissions", "dontAsk"}

# Token boundaries, not substrings: matching "rm" anywhere flagged
# `Bash(terraform *)` as a delete rule, and setup offered to remove it. The same
# shape as guard.py's own DELETION_HINT, deliberately.
DELETION_HINT = re.compile(r"\b(rm|rmdir|unlink|shred|srm)\b|(?:^|\s)-delete\b", re.I)

RED, YEL, GRN, DIM, OFF = "\033[31m", "\033[33m", "\033[32m", "\033[2m", "\033[0m"
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    RED = YEL = GRN = DIM = OFF = ""


class Findings:
    """Collects results so setup and doctor render the same report."""

    def __init__(self):
        self.rows = []

    def ok(self, what, detail=""):
        self.rows.append(("ok", what, detail, None))

    def warn(self, what, detail="", fix=None):
        self.rows.append(("warn", what, detail, fix))

    def fail(self, what, detail="", fix=None):
        self.rows.append(("fail", what, detail, fix))

    @property
    def failed(self):
        return any(r[0] == "fail" for r in self.rows)

    @property
    def warned(self):
        return any(r[0] == "warn" for r in self.rows)

    def render(self):
        mark = {"ok": GRN + "  ok  " + OFF, "warn": YEL + " warn " + OFF,
                "fail": RED + " FAIL " + OFF}
        for level, what, detail, fix in self.rows:
            print("%s %s" % (mark[level], what))
            if detail:
                for line in detail.splitlines():
                    print("       %s%s%s" % (DIM, line, OFF))
            if fix:
                print("       %s→ %s%s" % (YEL, fix, OFF))


def read_json(path):
    """Missing file is empty config; unreadable is an error worth surfacing."""
    if not path.exists():
        return {}, None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, "cannot read %s: %s" % (path, exc)
    if not text.strip():
        return {}, None
    try:
        return json.loads(text), None
    except json.JSONDecodeError as exc:
        return None, "%s is not valid JSON (line %d): %s" % (path, exc.lineno, exc.msg)


def write_json(path, data):
    """Back up before every write: this file is the user's whole Claude config."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        shutil.copy2(path, path.with_suffix(path.suffix + ".away-backup"))
    tmp = path.with_suffix(path.suffix + ".away-tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def guard_cmd(event):
    return "bash '%s' %s" % (AWAY / "hooks" / "guard.sh", event)


def hook_event_arg(entry):
    cmd = entry.get("command") or ""
    return cmd.rsplit(None, 1)[-1] if cmd.strip() else ""


OUR_EVENT_ARGS = {arg for _e, arg, _m, _t in HOOK_EVENTS}


def is_our_hook(entry):
    """Ours by shape, not by exact path, so a moved or renamed install is
    recognised and repointed rather than registered a second time.

    Matching on the directory name was wrong: AWAY_HOME is configurable, and an
    install in ~/tools/claude-away then read as somebody else's hook.
    """
    cmd = entry.get("command") or ""
    return "/hooks/guard.sh" in cmd and hook_event_arg(entry) in OUR_EVENT_ARGS


# ---------------------------------------------------------------- hooks


def audit_hooks(settings, f):
    """Every event must be registered exactly once, pointing at THIS away home."""
    hooks = settings.get("hooks") or {}
    for event, arg, matcher, _timeout in HOOK_EVENTS:
        groups = hooks.get(event) or []
        mine = []
        for group in groups:
            for entry in group.get("hooks") or []:
                if is_our_hook(entry) and hook_event_arg(entry) == arg:
                    mine.append((group, entry))
        if not mine:
            f.fail("hook %s is not registered" % event,
                   "away mode cannot enforce anything on this event.",
                   "run `away setup`")
            continue
        if len(mine) > 1:
            f.warn("hook %s is registered %d times" % (event, len(mine)),
                   "the guard will run more than once per call.",
                   "run `away setup` to collapse the duplicates")
        group, entry = mine[0]
        want = guard_cmd(arg)
        if entry.get("command") != want:
            f.fail("hook %s points somewhere else" % event,
                   "found: %s\nwant:  %s" % (entry.get("command"), want),
                   "run `away setup` to repoint it")
            continue
        if matcher and group.get("matcher") not in (matcher, None):
            f.warn("hook %s has matcher %r" % (event, group.get("matcher")),
                   "away mode expects %r so it sees every tool." % matcher,
                   "run `away setup`")
            continue
        f.ok("hook %s registered" % event)

    # A second copy in settings.local.json wins or doubles depending on merge
    # order, and the user cannot tell which from either file alone.
    local, err = read_json(SETTINGS_LOCAL)
    if local and not err:
        for event, arg, _m, _t in HOOK_EVENTS:
            for group in (local.get("hooks") or {}).get(event) or []:
                for entry in group.get("hooks") or []:
                    if is_our_hook(entry) and hook_event_arg(entry) == arg:
                        f.warn("hook %s is ALSO in settings.local.json" % event,
                               "two registrations of the same guard.",
                               "remove it from settings.local.json by hand")


def apply_hooks(settings):
    """Returns a list of human-readable changes made."""
    changes = []
    hooks = settings.setdefault("hooks", {})
    for event, arg, matcher, timeout in HOOK_EVENTS:
        groups = hooks.setdefault(event, [])
        found = None
        # Walk backwards so removing duplicates cannot shift the index we keep.
        for gi in range(len(groups) - 1, -1, -1):
            entries = groups[gi].get("hooks") or []
            for ei in range(len(entries) - 1, -1, -1):
                if is_our_hook(entries[ei]) and hook_event_arg(entries[ei]) == arg:
                    if found is None:
                        found = (gi, ei)
                    else:
                        entries.pop(ei)
                        changes.append("removed a duplicate %s hook" % event)
        want = {"type": "command", "command": guard_cmd(arg), "timeout": timeout}
        if found is None:
            group = {"hooks": [want]}
            if matcher:
                group["matcher"] = matcher
            groups.append(group)
            changes.append("registered the %s hook" % event)
        else:
            gi, ei = found
            if groups[gi]["hooks"][ei] != want:
                groups[gi]["hooks"][ei] = want
                changes.append("repointed the %s hook at %s" % (event, AWAY))
            if matcher and groups[gi].get("matcher") != matcher:
                groups[gi]["matcher"] = matcher
                changes.append("set the %s matcher to %r" % (event, matcher))
        # Drop groups we emptied while collapsing duplicates.
        hooks[event] = [g for g in groups if g.get("hooks")]
    return changes


def remove_hooks(settings):
    changes = []
    hooks = settings.get("hooks") or {}
    for event, arg, _m, _t in HOOK_EVENTS:
        groups = hooks.get(event) or []
        for group in groups:
            entries = group.get("hooks") or []
            keep = [e for e in entries if not (is_our_hook(e) and hook_event_arg(e) == arg)]
            if len(keep) != len(entries):
                group["hooks"] = keep
                changes.append("unregistered the %s hook" % event)
        hooks[event] = [g for g in groups if g.get("hooks")]
        if not hooks[event]:
            hooks.pop(event, None)
    if not hooks:
        settings.pop("hooks", None)
    return changes


# ---------------------------------------------------------- permissions


def rule_tool(rule):
    return rule.split("(", 1)[0].strip() if isinstance(rule, str) else ""


def rule_arg(rule):
    if not isinstance(rule, str) or "(" not in rule:
        return ""
    return rule[rule.index("(") + 1:].rstrip(")")


def is_broad_bash(rule):
    """A rule that catches every Bash call, however it is spelled."""
    if rule_tool(rule) != "Bash":
        return False
    arg = rule_arg(rule).strip()
    return arg in ("", "*", ":*", "*:*")


def touches_deletion(rule):
    if rule_tool(rule) not in ("Bash", ""):
        return False
    return bool(DELETION_HINT.search(rule_arg(rule)))


def audit_permissions(settings, f, source="settings.json"):
    perms = settings.get("permissions") or {}
    mode = perms.get("defaultMode")

    if mode is None:
        f.warn("permissions.defaultMode is not set",
               "Claude Code will prompt for anything not on the allow list, and\n"
               "an away agent has nobody to answer those prompts.",
               "set it to \"auto\" (setup can do this)")
    elif mode not in SAFE_MODES:
        f.fail("permissions.defaultMode is %r" % mode,
               "this mode raises approval prompts. While away nobody answers\n"
               "them, so agents stall instead of deciding or routing around.\n"
               "Away mode needs one of: %s." % ", ".join(sorted(SAFE_MODES)),
               "set it to \"auto\" (setup can do this)")
    else:
        f.ok("permissions.defaultMode is %r" % mode)

    ask = [r for r in (perms.get("ask") or []) if isinstance(r, str)]
    deny = [r for r in (perms.get("deny") or []) if isinstance(r, str)]

    # The guard owns deletes in BOTH directions: it snapshots to away trash
    # before allowing one, and it is the only `ask` on the path. A permission
    # `ask` rule on the same commands fires a prompt the guard cannot answer.
    delete_asks = [r for r in ask if touches_deletion(r)]
    if delete_asks:
        f.fail("%d `ask` rule(s) collide with the guard on deletes" % len(delete_asks),
               "%s\nThe guard already gates deletes and snapshots them to away\n"
               "trash. A second `ask` here prompts with nobody there to answer."
               % "\n".join("  " + r for r in delete_asks),
               "remove these from permissions.ask (setup can do this)")
    else:
        f.ok("no `ask` rule collides with the guard on deletes")

    broad_ask = [r for r in ask if is_broad_bash(r)]
    if broad_ask:
        f.fail("`ask` matches every Bash command",
               "%s\nEvery shell command an away agent runs would wait for an\n"
               "answer that never comes." % "\n".join("  " + r for r in broad_ask),
               "narrow or remove these (setup can do this)")

    broad_deny = [r for r in deny if is_broad_bash(r)]
    if broad_deny:
        f.warn("`deny` matches every Bash command",
               "%s\nThis is stricter than away mode, not looser, so it is safe --\n"
               "but an away agent can do almost nothing."
               % "\n".join("  " + r for r in broad_deny))

    if deny:
        f.ok("%d `deny` rule(s) left alone" % len(deny),
             "deny is stricter than the guard, so it never conflicts.")

    # Allow rules are not a hazard: PreToolUse fires on every tool call, and a
    # hook denial outranks an allow. Say so, because it looks alarming.
    allow = perms.get("allow") or []
    if allow:
        f.ok("%d `allow` rule(s) left alone" % len(allow),
             "the guard runs before the tool either way, and its deny wins.")

    if source == "settings.json" and SETTINGS_LOCAL.exists():
        local, err = read_json(SETTINGS_LOCAL)
        if err:
            f.warn("settings.local.json is unreadable", err)
        elif local.get("permissions"):
            lp = local["permissions"]
            problems = []
            if lp.get("defaultMode") and lp["defaultMode"] not in SAFE_MODES:
                problems.append("defaultMode: %r" % lp["defaultMode"])
            problems += ["ask: " + r for r in (lp.get("ask") or [])
                         if isinstance(r, str) and (touches_deletion(r) or is_broad_bash(r))]
            if problems:
                f.fail("settings.local.json overrides these with conflicts",
                       "\n".join("  " + p for p in problems) +
                       "\nProject-local settings win, so fixing settings.json is\n"
                       "not enough here.",
                       "fix settings.local.json by hand")


def apply_permissions(settings):
    changes = []
    perms = settings.setdefault("permissions", {})
    if perms.get("defaultMode") not in SAFE_MODES:
        was = perms.get("defaultMode")
        perms["defaultMode"] = "auto"
        changes.append("set permissions.defaultMode to \"auto\" (was %r)" % was)
    ask = perms.get("ask")
    if isinstance(ask, list):
        keep = [r for r in ask
                if not (isinstance(r, str) and (touches_deletion(r) or is_broad_bash(r)))]
        for r in ask:
            if r not in keep:
                changes.append("removed permissions.ask rule %r" % r)
        if keep != ask:
            perms["ask"] = keep
    return changes


# --------------------------------------------------------------- payload


def audit_payload(f):
    for rel in ("hooks/guard.sh", "hooks/guard.py", "bin/away", "bin/report.py",
                "bin/setup.py", "bin/update.py", "rules.md"):
        p = AWAY / rel
        if not p.exists():
            f.fail("missing %s" % rel, "install is incomplete at %s" % AWAY,
                   "reinstall: see README")
        elif rel.endswith((".sh", "/away")) and not os.access(p, os.X_OK):
            f.fail("%s is not executable" % rel, fix="chmod +x '%s'" % p)
    if (AWAY / "hooks" / "guard.py.good").exists():
        f.ok("fallback guard present",
             "guard.sh uses it if the live guard ever crashes.")
    else:
        f.warn("no fallback guard blessed yet",
               "a crash in guard.py would block every armed session with no\n"
               "safety net.",
               "run `away doctor` (it blesses a passing guard)")

    state = AWAY / "state"
    try:
        state.mkdir(parents=True, exist_ok=True)
        probe = state / ".write-probe"
        probe.write_text("x")
        probe.unlink()
        f.ok("state directory is writable")
    except OSError as exc:
        f.fail("state directory is not writable", str(exc),
               "fix permissions on %s" % state)


def audit_path(f):
    found = shutil.which("away")
    if not found:
        f.warn("`away` is not on PATH",
               "agents fall back to the absolute path, which rules.md tells them\n"
               "to use -- but your own shell will not find it.",
               "add %s to PATH, then restart your shell" % BIN_DIR)
        return
    real = Path(found).resolve()
    want = (AWAY / "bin" / "away").resolve()
    if real != want:
        f.warn("`away` on PATH is a different install",
               "PATH:      %s -> %s\nthis home: %s" % (found, real, want),
               "run `away setup` from the install you want to keep")
    else:
        f.ok("`away` resolves to this install", found)


def audit_skill(f):
    target = SKILL_DIR / "SKILL.md"
    source = AWAY / "skills" / "away" / "SKILL.md"
    if not target.exists():
        f.fail("the /away skill is not installed",
               "sessions cannot scope away mode to themselves without it.",
               "run `away setup`")
    elif source.exists() and target.read_bytes() != source.read_bytes():
        f.warn("the installed /away skill differs from this version",
               "an older or hand-edited copy is in %s" % SKILL_DIR,
               "run `away setup` to refresh it")
    else:
        f.ok("the /away skill is installed")


def audit_python(f):
    f.ok("python3 is %s" % sys.version.split()[0], sys.executable)


def audit_version(f):
    vf = AWAY / "VERSION"
    installed = vf.read_text().strip() if vf.exists() else "unknown"
    cache = AWAY / "state" / "update-check.json"
    latest = None
    if cache.exists():
        try:
            latest = json.loads(cache.read_text()).get("latest")
        except (OSError, json.JSONDecodeError):
            latest = None
    if latest and latest.lstrip("v") != installed.lstrip("v"):
        f.warn("version %s installed, %s available" % (installed, latest),
               "from the cached release check; no network was used.",
               "run `away update`")
    else:
        f.ok("version %s" % installed)


def run_checks(settings, f):
    audit_python(f)
    audit_payload(f)
    audit_path(f)
    audit_skill(f)
    audit_hooks(settings, f)
    audit_permissions(settings, f)
    audit_version(f)


# ------------------------------------------------------------------ main


def confirm(question, assume_yes):
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        return False
    try:
        return input("%s [y/N] " % question).strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def link_cli():
    """Symlink rather than copy, so `away update` needs no relinking."""
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    link = BIN_DIR / "away"
    target = AWAY / "bin" / "away"
    if link.is_symlink() and link.resolve() == target.resolve():
        return []
    if link.exists() or link.is_symlink():
        link.unlink()
    link.symlink_to(target)
    return ["linked %s -> %s" % (link, target)]


def install_skill():
    source = AWAY / "skills" / "away" / "SKILL.md"
    if not source.exists():
        return []
    SKILL_DIR.mkdir(parents=True, exist_ok=True)
    target = SKILL_DIR / "SKILL.md"
    if target.exists() and target.read_bytes() == source.read_bytes():
        return []
    shutil.copy2(source, target)
    return ["installed the /away skill into %s" % SKILL_DIR]


def make_executable():
    for rel in ("bin/away", "bin/report.py", "bin/setup.py", "bin/update.py",
                "hooks/guard.sh", "hooks/guard.py", "tests/policy_cases.py"):
        p = AWAY / rel
        if p.exists():
            p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def cmd_setup(argv):
    assume_yes = "--yes" in argv or "-y" in argv
    settings, err = read_json(SETTINGS)
    if err:
        print("%saway: %s%s" % (RED, err, OFF), file=sys.stderr)
        print("Fix that file first -- setup will not overwrite unreadable JSON.",
              file=sys.stderr)
        return 1

    print("away setup  (home: %s)" % AWAY)
    print()

    make_executable()
    changes = link_cli() + install_skill()

    hook_changes = apply_hooks(settings)

    # Permission edits are the only part that changes how Claude Code behaves
    # when away mode is OFF, so they are the only part that asks first.
    probe = Findings()
    audit_permissions(settings, probe)
    perm_changes = []
    if probe.failed or probe.warned:
        conflicts = [r for r in probe.rows if r[0] in ("warn", "fail")]
        fixable = [r for r in conflicts if r[3] and "setup can do this" in r[3]]
        if fixable:
            print("Permission settings that would block away mode:")
            print()
            for _level, what, detail, _fix in fixable:
                print("  - %s" % what)
                for line in (detail or "").splitlines():
                    print("    %s%s%s" % (DIM, line, OFF))
            print()
            if confirm("Fix these in %s?" % SETTINGS, assume_yes):
                perm_changes = apply_permissions(settings)
            else:
                print("%sLeft alone. Away mode will stall on these until fixed.%s"
                      % (YEL, OFF))
            print()

    if hook_changes or perm_changes:
        write_json(SETTINGS, settings)
        changes += hook_changes + perm_changes

    if changes:
        print("Changed:")
        for c in changes:
            print("  %s+%s %s" % (GRN, OFF, c))
    else:
        print("Nothing to change -- already wired.")
    print()

    settings, _ = read_json(SETTINGS)
    f = Findings()
    run_checks(settings or {}, f)
    f.render()
    print()
    if f.failed:
        print("%saway: setup incomplete -- see FAIL above.%s" % (RED, OFF))
        return 1
    print("%saway: ready.%s  Arm it with `away on`, or `/away on` inside a session."
          % (GRN, OFF))
    if changes:
        print("Restart running Claude Code sessions to pick up the hook changes.")
    return 0


def cmd_check(argv):
    settings, err = read_json(SETTINGS)
    f = Findings()
    if err:
        f.fail("settings.json is unreadable", err, "fix the JSON by hand")
        settings = {}
    run_checks(settings, f)
    f.render()
    return 1 if f.failed else 0


def cmd_unwire(argv):
    """Used by uninstall.sh: pull the hooks back out, leave permissions alone."""
    settings, err = read_json(SETTINGS)
    if err:
        print("away: %s" % err, file=sys.stderr)
        return 1
    changes = remove_hooks(settings)
    if changes:
        write_json(SETTINGS, settings)
    link = BIN_DIR / "away"
    if link.is_symlink() and str(AWAY) in str(link.resolve()):
        link.unlink()
        changes.append("removed %s" % link)
    if (SKILL_DIR / "SKILL.md").exists():
        shutil.rmtree(SKILL_DIR, ignore_errors=True)
        changes.append("removed the /away skill")
    for c in changes:
        print("  - %s" % c)
    if not changes:
        print("  (nothing was wired)")
    print()
    print("Permission settings were NOT touched -- defaultMode and your ask/deny")
    print("lists are yours. Review them if you changed them for away mode.")
    return 0


COMMANDS = {"setup": cmd_setup, "check": cmd_check, "unwire": cmd_unwire}

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    if cmd not in COMMANDS:
        print("usage: setup.py [setup|check|unwire]", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(COMMANDS[cmd](sys.argv[2:]))
