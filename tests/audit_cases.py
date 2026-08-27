#!/usr/bin/env python3
"""Tests for the permission audit's rule matching.

A false positive here is not cosmetic: setup offers to DELETE the rule it flags.
`Bash(terraform *)` was flagged as a delete rule on a real machine, because the
first version matched "rm" as a substring of "terraform".

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


def test_deletion_matching():
    print("rules that DO gate a delete:")
    # The invariant is consistency with guard.py's own DELETION_HINT, not a
    # hand-tuned word list: the audit must flag exactly what the guard gates.
    # That is why a hyphen-adjacent `rm` (`git rm --cached`) counts.
    for rule in ("Bash(rm:*)", "Bash(rm -rf:*)", "Bash(rmdir:*)",
                 "Bash(unlink:*)", "Bash(shred:*)", "Bash(srm:*)",
                 "Bash(find . -delete)", "Bash(RM:*)", "Bash(git rm --cached:*)"):
        check(rule, audit.touches_deletion(rule), True)

    print("\nrules that merely CONTAIN those letters:")
    # Every one of these is a real rule somebody has, and removing any of them
    # would be silent damage to their setup.
    for rule in ("Bash(terraform *)", "Bash(terraform apply:*)",
                 "Bash(npm run format:*)", "Bash(rman:*)",
                 "Bash(charm:*)", "Bash(swarm:*)",
                 "Bash(confirm:*)", "Bash(alarm-check)", "Bash(normalize:*)"):
        check(rule, audit.touches_deletion(rule), False)

    print("\nnon-Bash tools are never delete rules:")
    for rule in ("Read(~/rm-notes.md)", "WebFetch(domain:rm.example.com)",
                 "Edit(shred.txt)"):
        check(rule, audit.touches_deletion(rule), False)


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
    check("the delete ask went", "Bash(rm:*)" in p["ask"], False)
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


def main():
    print("away audit cases")
    print()
    test_deletion_matching()
    test_broad_bash()
    test_mode_audit()
    test_apply_is_surgical()
    test_hook_identity()
    print()
    if FAIL:
        print("away audit cases: %d failed, %d passed." % (len(FAIL), len(PASS)),
              file=sys.stderr)
        return 1
    print("away audit cases: %d passed." % len(PASS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
