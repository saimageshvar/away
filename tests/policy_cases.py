#!/usr/bin/env python3
"""Away-mode decision tests. Run: python3 ~/.claude/away/tests/policy_cases.py

Every case runs against a sandboxed AWAY_HOME, so the live event log is never
touched and no test can be mistaken for a real incident.

A case asserts on the DECISION, and "defer" means the empty output that lets the
command run. Read defer as "permitted", never as "nothing happened".
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HOME = Path(os.environ.get("AWAY_HOME") or (Path.home() / ".claude" / "away"))
GUARD = HOME / "hooks" / "guard.py"

DENY, ALLOW, ASK, DEFER = "deny", "allow", "ask", "defer"


def decide(sandbox, cmd, cwd, armed=True, tool="Bash", tool_input=None):
    flag = sandbox / "state" / "active.json"
    if armed:
        flag.write_text('{"on":true,"since_epoch":1,"note":"test"}')
    elif flag.exists():
        flag.unlink()
    payload = {"session_id": "policytest", "cwd": str(cwd), "tool_name": tool,
               "tool_input": tool_input if tool_input is not None
               else {"command": cmd}}
    proc = subprocess.run(
        [sys.executable, str(GUARD), "pretooluse"], input=json.dumps(payload),
        capture_output=True, text=True, timeout=60,
        env=dict(os.environ, AWAY_HOME=str(sandbox), AWAY_TEST="1"))
    if proc.returncode != 0:
        return "error:%s" % proc.stderr.strip().splitlines()[-1:], proc
    if not proc.stdout.strip():
        return DEFER, proc
    out = json.loads(proc.stdout)["hookSpecificOutput"]
    return out["permissionDecision"], proc


def events(sandbox):
    log = sandbox / "state" / "events.jsonl"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines() if line.strip()]


# (label, command, expected, armed)
CASES = [
    # --- the arm-time selftest depends on these two, so they come first
    ("shell -c hides the delete", 'sh -c "rm -rf /Users/x"', DENY, True),
    ("plain in-tree delete", "rm scratch.txt", ALLOW, True),

    # --- conduits: the payload is opaque, so it must fail closed
    ("container shell -lc, source dir",
     'docker compose exec web sh -lc "rm -rf /app/src"', DENY, True),
    ("container shell -lc, regenerable",
     'docker compose exec web sh -lc "rm -rf node_modules"', DEFER, True),
    ("pipe into a shell", 'echo "rm -rf /" | sh', DENY, True),
    ("here-string into bash", 'bash <<< "rm -rf /"', DENY, True),
    ("command substitution", "echo $(rm -rf src)", DENY, True),
    ("backtick substitution", "echo `rm -rf src`", DENY, True),
    ("interpreter payload", "python3 -c \"os.system('rm -rf /')\"", DENY, True),
    ("eval", 'eval "$CLEANUP"', DEFER, True),   # no deletion hint at all
    ("eval naming rm", 'eval "rm -rf src"', DENY, True),
    ("xargs rm", "find . -name '*.orig' | xargs rm", DENY, True),
    ("find -delete", "find . -name '*.orig' -delete", DENY, True),

    # --- shape must survive prefixes and loops
    ("env assignment prefix", "FOO=bar rm -rf src", DENY, True),
    ("timeout prefix", "timeout 5 rm -rf src", DENY, True),
    ("nice with numeric arg", "nice -n 10 rm -rf src", DENY, True),
    ("shell loop", 'for f in a b; do rm -rf "src/$f"; done', DENY, True),
    ("second line of a script", "echo starting\nrm -rf src", DENY, True),
    ("ssh remote delete", "ssh host rm -rf /", DENY, True),

    # --- false positives that used to deny ordinary work
    ("docker run --rm", "docker run --rm -it ubuntu bash", DEFER, True),
    ("compose run --rm", "docker compose run --rm web rails c", DEFER, True),
    ("rm inside a filename", "cat rm-notes.txt", DEFER, True),
    ("rm as an echo argument", 'echo "use rm carefully"', DEFER, True),
    ("rm as a grep pattern", "grep -n rm README-away", DEFER, True),
    ("find that only lists", "find . -name '*.orig' -print", DEFER, True),

    # --- containment
    ("tilde into a regenerable name", "rm -rf ~/logs", DENY, True),
    ("tilde into a nested dist", "rm -rf ~/projects/other/dist", DENY, True),
    ("unknown user home", "rm '~nosuchuser/file'", DENY, True),
    ("variable target", "rm -rf $HOME/logs", DENY, True),
    ("cd outside then delete", "cd ~/elsewhere && rm -rf node_modules", DENY, True),
    ("absolute path outside", "rm -rf /Users/other/logs", DENY, True),
    ("in-tree node_modules", "rm -rf node_modules", ALLOW, True),
    ("recursive source dir", "rm -rf src", DENY, True),

    # --- scratch roots are regenerable by definition
    ("delete under /tmp", "rm -rf /tmp/away-policy-scratch", ALLOW, True),
    ("/tmp itself", "rm -rf /tmp", DENY, True),

    # --- outward
    ("git push", "git push origin HEAD", DENY, True),
    ("git config alias", "git config alias.nuke '!rm -rf /'", DENY, True),
    ("git config read", "git config --get user.email", DEFER, True),
    ("gh pr create", "gh pr create --fill", DENY, True),
    ("gh pr comment", "gh pr comment 123 --body hi", DENY, True),
    ("gh api field forces POST", "gh api repos/o/r/issues -f title=x", DENY, True),
    ("gh api glued method", "gh api -XPOST repos/o/r/issues", DENY, True),
    ("gh pr view", "gh pr view 1", DEFER, True),
    ("gh with repo flag", "gh -R o/r pr list", DEFER, True),
    ("gh api read", "gh api repos/o/r/pulls", DEFER, True),

    # --- away OFF: only real deletes may interrupt the operator
    ("off: compose run --rm", "docker compose run --rm web rails c", DEFER, False),
    ("off: rm as an argument", "grep -n rm README-away", DEFER, False),
    ("off: a real delete", "rm scratch.txt", ASK, False),
]


def cli_cases(tree):
    """A session-scoped absence has to behave like a real one end to end.

    The policy cases above cannot see this: they drive guard.py directly, while
    every one of these bugs lived in the CLI's own idea of whether away is on.
    """
    sandbox = Path(tempfile.mkdtemp(prefix="away-cli-"))
    (sandbox / "state").mkdir(parents=True)
    for name in ("hooks", "bin"):
        shutil.copytree(HOME / name, sandbox / name)
    env = dict(os.environ, AWAY_HOME=str(sandbox), AWAY_TEST="1",
               CLAUDE_CODE_SESSION_ID="clitest")
    away = [str(sandbox / "bin" / "away")]

    def run(*args):
        return subprocess.run(["bash"] + away + list(args), capture_output=True,
                              text=True, cwd=str(tree), env=env, timeout=90)

    found = []
    if "on for THIS session" not in run("on", "--here", "note").stdout:
        found.append("away on --here did not arm the session")
    # FIX 2: the decision ledger has to work for the scope the /away skill uses.
    if "decision recorded" not in run("decision", "chose X because Y").stdout:
        found.append("away decision dropped a decision during a --here absence")
    out = run("off", "--here").stdout
    if "off for THIS session" not in out:
        found.append("away off --here did not disarm the session")
    # The decision is tagged synthetic here (AWAY_TEST), so the digest hides it
    # and says so — which is itself the behaviour worth asserting.
    if "synthetic test event" not in out:
        found.append("away off --here gave no hand-back digest of its own events")
    shutil.rmtree(sandbox, ignore_errors=True)
    return found


def resilience_cases(tree):
    """A broken guard must not stall the machine.

    This is the outage that motivated the fallback: a rename left one call site
    behind, and every armed session blocked on every tool call until the file
    was repaired — which no agent is allowed to do while away mode is on.
    """
    sandbox = Path(tempfile.mkdtemp(prefix="away-resilience-"))
    (sandbox / "state").mkdir(parents=True)
    shutil.copytree(HOME / "hooks", sandbox / "hooks")
    (sandbox / "state" / "active.json").write_text('{"on":true,"since_epoch":1}')
    good = sandbox / "hooks" / "guard.py.good"
    shutil.copy2(HOME / "hooks" / "guard.py", good)
    broken = (sandbox / "hooks" / "guard.py")
    broken.write_text(broken.read_text().replace(
        "deletes, _conduit = delete_shaped(cmd)", "deletes = undefined_name(cmd)"))

    def probe(cmd):
        payload = json.dumps({"session_id": "res", "cwd": str(tree),
                              "tool_name": "Bash", "tool_input": {"command": cmd}})
        return subprocess.run(
            ["bash", str(sandbox / "hooks" / "guard.sh"), "pretooluse"],
            input=payload, capture_output=True, text=True, timeout=60,
            env=dict(os.environ, AWAY_HOME=str(sandbox), AWAY_TEST="1"))

    found = []
    proc = probe("make help")
    if proc.returncode != 0:
        found.append("a broken guard blocked an ordinary command despite the fallback")
    proc = probe("git push origin HEAD")
    if "deny" not in proc.stdout:
        found.append("the fallback ran but stopped enforcing policy")
    if "guard.py is broken" not in proc.stderr:
        found.append("the fallback was silent about being a fallback")
    good.unlink()
    if probe("make help").returncode != 2:
        found.append("with no fallback the guard must fail closed, and did not")
    shutil.rmtree(sandbox, ignore_errors=True)
    return found


def main():
    failures, ran = [], 0
    sandbox = Path(tempfile.mkdtemp(prefix="away-policy-"))
    (sandbox / "state").mkdir(parents=True)
    tree = Path(tempfile.mkdtemp(prefix="away-tree-"))
    subprocess.run(["git", "init", "-q", str(tree)], check=True)
    (tree / "scratch.txt").write_text("scratch\n")
    (tree / "README-away").write_text("mentions rm\n")
    (tree / "node_modules").mkdir()
    (tree / "src").mkdir()
    (tree / "src" / "a.rb").write_text("x\n")
    Path("/tmp/away-policy-scratch").mkdir(exist_ok=True)

    for label, cmd, want, armed in CASES:
        ran += 1
        got, proc = decide(sandbox, cmd, tree, armed=armed)
        if got != want:
            reason = ""
            if proc.stdout.strip():
                try:
                    reason = json.loads(proc.stdout)["hookSpecificOutput"].get(
                        "permissionDecisionReason", "")[:150].replace("\n", " ")
                except Exception:
                    reason = proc.stdout[:150]
            failures.append("%-34s want %-6s got %-6s  %s\n%s%s"
                            % (label, want, got, cmd, " " * 8, reason))

    # A misread command must not leave a snapshot behind either.
    got, _ = decide(sandbox, "grep -n rm README-away", tree)
    if any(rec.get("event") == "rm_allowed"
           and "grep" in (rec.get("detail") or {}).get("command", "")
           for rec in events(sandbox)):
        failures.append("grep -n rm README-away logged an rm_allowed event")
    ran += 1

    failures += cli_cases(tree)
    failures += resilience_cases(tree)
    ran += 7

    shutil.rmtree(sandbox, ignore_errors=True)
    shutil.rmtree(tree, ignore_errors=True)

    if failures:
        print("FAILED %d of %d\n" % (len(failures), ran))
        for line in failures:
            print("  " + line)
        raise SystemExit(1)
    print("ok — %d cases" % ran)


if __name__ == "__main__":
    main()
