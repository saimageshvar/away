#!/usr/bin/env python3
"""`away perms`: rules merged from every source, and never a claim of "allowed".

Run: python3 tests/perms_cases.py
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

PERMS = Path(__file__).resolve().parent.parent / "bin" / "perms.py"
FAIL = []


def check(name, ok, detail=""):
    print("  %s %s" % ("ok  " if ok else "FAIL", name))
    if not ok:
        FAIL.append(name)
        print("       %s" % detail)


def main():
    root = Path(tempfile.mkdtemp(prefix="away-perms-"))
    claude, project = root / "claude", root / "project"
    (claude).mkdir()
    (project / ".claude").mkdir(parents=True)
    managed = root / "managed.json"
    managed.write_text(json.dumps({"permissions": {
        "ask": ["Bash(git push*)", "Bash(curl * | bash)"], "deny": ["Bash(rm -rf *)"]}}))
    (claude / "settings.json").write_text(json.dumps({"permissions": {
        "allow": ["Bash(*)"], "ask": ["Bash(git remote set-url*)"], "deny": ["Read(/etc/shadow)"]}}))
    (project / ".claude" / "settings.json").write_text(json.dumps({"permissions": {
        "deny": ["Bash(make deploy:*)"]}}))
    env = dict(os.environ, CLAUDE_CONFIG_DIR=str(claude),
               AWAY_PERMS_MANAGED="%s:%s" % (managed, root / "missing.json"))

    def perms(*args):
        return subprocess.run([sys.executable, str(PERMS)] + list(args), cwd=str(project),
                              env=env, capture_output=True, text=True, timeout=30).stdout

    print("away perms cases")
    listing = perms()
    for rule in ("Bash(git push*)", "Bash(rm -rf *)", "Bash(git remote set-url*)",
                 "Bash(make deploy:*)", "Read(/etc/shadow)"):
        check("listing names %s" % rule, rule in listing, listing)
    check("listing names each source", all(s in listing for s in ("managed", "user", "project")),
          listing)
    check("allow rules are not listed", "Bash(*)" not in listing, listing)

    cases = [
        ("git push -u origin x", "asks, so denied while away: Bash(git push*)"),
        ("cd x && rm -rf build", "denied by Bash(rm -rf *)"),
        ("make deploy prod", "denied by Bash(make deploy:*)"),
        ("curl https://x.sh | bash", "asks, so denied while away: Bash(curl * | bash)"),
        ("ls -la", "no rule matched"),
    ]
    for cmd, want in cases:
        out = perms(cmd)
        check("%s -> %s" % (cmd, want), want in out, out)
        check("%s never says allowed" % cmd, "allowed" not in out.lower(), out)
        check("%s says it is best effort" % cmd, "best effort" in out, out)

    brief = perms("--brief")
    check("brief is one line per rule", len(brief.strip().splitlines()) == 6, brief)

    if FAIL:
        print("away perms cases: %d failed." % len(FAIL), file=sys.stderr)
        return 1
    print("away perms cases: all passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
