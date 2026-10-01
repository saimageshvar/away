#!/usr/bin/env python3
"""Tests for the permission audit and hook wiring.

A false positive here is not cosmetic: setup offers to DELETE the rule it flags.

Run: python3 tests/audit_cases.py
"""

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "bin"))
os.environ.setdefault("AWAY_HOME", str(REPO))

import setup as audit  # noqa: E402

PASS, FAIL = [], []


def check(name, got, want):
    if got == want:
        PASS.append(name)
        print("  ok   %s" % name)
    else:
        FAIL.append(name)
        print("  FAIL %s\n       want %r, got %r" % (name, want, got))


def test_broad_bash():
    print("\nrules matching EVERY Bash call:")
    for rule in ("Bash", "Bash(*)", "Bash(:*)", "Bash(*:*)"):
        check(rule, audit.is_broad_bash(rule), True)

    print("\nnarrow rules are not broad:")
    for rule in ("Bash(git status:*)", "Bash(npm test)", "Bash(rm:*)",
                 "Read(*)", "Bash(ls *)"):
        check(rule, audit.is_broad_bash(rule), False)


def test_mode_audit():
    print("\ndefaultMode verdicts:")
    for mode in ("auto", "bypassPermissions", "dontAsk"):
        f = audit.Findings()
        audit.audit_permissions({"permissions": {"defaultMode": mode}}, f)
        check("%s is accepted" % mode, f.failed, False)
    for mode in ("default", "plan", "acceptEdits"):
        f = audit.Findings()
        audit.audit_permissions({"permissions": {"defaultMode": mode}}, f)
        check("%s is a failure" % mode, f.failed, True)
    f = audit.Findings()
    audit.audit_permissions({"permissions": {}}, f)
    check("an unset mode warns but does not fail", (f.failed, f.warned),
          (False, True))


def test_deny_is_left_alone():
    print("\ndeny rules:")
    f = audit.Findings()
    audit.audit_permissions({"permissions": {
        "defaultMode": "auto", "deny": ["Bash(rm:*)", "Bash(curl:*)"]}}, f)
    check("a deny list is clean", (f.failed, f.warned), (False, False))
    settings = {"permissions": {"defaultMode": "auto", "deny": ["Bash(rm:*)"]}}
    audit.apply_permissions(settings)
    check("apply never edits deny", settings["permissions"]["deny"], ["Bash(rm:*)"])


def test_apply_is_surgical():
    """Only the conflicting rules go; everything else is left exactly as-is."""
    print("\napply_permissions:")
    settings = {"permissions": {
        "defaultMode": "default",
        "allow": ["Bash(git status:*)", "Bash(terraform *)"],
        "ask": ["Bash(rm:*)", "Bash(terraform *)", "Bash(sudo:*)", "Bash(*)"],
        "deny": ["Bash(curl:*)"],
    }}
    audit.apply_permissions(settings)
    p = settings["permissions"]
    check("mode was fixed", p["defaultMode"], "auto")
    check("a delete ask is the harness's, and stays", "Bash(rm:*)" in p["ask"], True)
    check("the broad ask went", "Bash(*)" in p["ask"], False)
    check("terraform survived in ask", "Bash(terraform *)" in p["ask"], True)
    check("sudo survived in ask", "Bash(sudo:*)" in p["ask"], True)
    check("allow was untouched", p["allow"],
          ["Bash(git status:*)", "Bash(terraform *)"])
    check("deny was untouched", p["deny"], ["Bash(curl:*)"])


def test_hook_identity():
    print("\nhook identity:")
    ours = {"command": "bash '/Users/x/.claude/away/hooks/guard.sh' pretooluse"}
    renamed = {"command": "bash '/opt/tools/claude-autonomy/hooks/guard.sh' stop"}
    other = {"command": "bash '/Users/x/.claude/hooks/ask-preview-backfill.sh'"}
    someone_else = {"command": "bash '/other/project/hooks/guard.sh' validate"}
    check("a default install is ours", audit.is_our_hook(ours), True)
    check("a renamed home is still ours", audit.is_our_hook(renamed), True)
    check("an unrelated hook is not ours", audit.is_our_hook(other), False)
    # Another project's guard.sh with an argument we never pass must not be
    # rewritten or removed by setup.
    check("a foreign guard.sh is not ours", audit.is_our_hook(someone_else), False)
    check("an empty command is not ours", audit.is_our_hook({"command": ""}), False)
    check("a missing command is not ours", audit.is_our_hook({}), False)


def test_retired_push_guard():
    """A registered push_guard.py whose file is gone exits 2 and blocks every Bash call."""
    print("\nretired push_guard hook:")
    retired = {"type": "command", "command": "python3 '/x/.claude/away/hooks/push_guard.py'"}
    neighbour = {"type": "command", "command": "bash /somewhere/else.sh"}
    settings = {"hooks": {
        "PreToolUse": [{"matcher": "Bash", "hooks": [retired, neighbour]}],
        "Stop": [{"hooks": [dict(retired)]}],
    }}
    f = audit.Findings()
    audit.audit_hooks(settings, f)
    check("doctor fails on it", any("push_guard" in r[1] for r in f.rows if r[0] == "fail"), True)
    changes = audit.apply_hooks(settings)
    flat = [e for gs in settings["hooks"].values() for g in gs for e in g.get("hooks") or []]
    check("setup removes it everywhere", any("push_guard" in e["command"] for e in flat), False)
    check("its neighbour survives", neighbour in flat, True)
    check("setup says so", any("push_guard" in c for c in changes), True)
    settings = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [dict(retired)]}]}}
    audit.remove_hooks(settings)
    check("uninstall removes it too", settings.get("hooks", {}), {})


def main():
    print("away audit cases")
    print()
    test_broad_bash()
    test_mode_audit()
    test_deny_is_left_alone()
    test_apply_is_surgical()
    test_hook_identity()
    test_retired_push_guard()
    print()
    if FAIL:
        print("away audit cases: %d failed, %d passed." % (len(FAIL), len(PASS)),
              file=sys.stderr)
        return 1
    print("away audit cases: %d passed." % len(PASS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
