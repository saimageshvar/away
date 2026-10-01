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
    # --- the harness decides what runs: away judges no command of its own
    ("push to a protected branch", "git push origin HEAD:main", DEFER, True),
    ("recursive delete", "rm -rf src", DEFER, True),
    ("shell payload delete", 'sh -c "rm -rf /Users/x"', DEFER, True),
    ("gh pr merge", "gh pr merge 1 --squash", DEFER, True),
    ("deploy", "cap production deploy", DEFER, True),
    ("git config write", "git config alias.nuke '!rm -rf /'", DEFER, True),

    # --- away's own CLI is how an agent reports, and it was denying itself.
    # rules.md tells agents to call it by absolute path; that path matches
    # SELF_PATHS, and MUTATES then matched an ordinary word in the DECISION TEXT,
    # so 5 of 6 realistic decisions read as tampering. The words below are the
    # ones that did it.
    ("decision, plain", '~/.claude/away/bin/away decision "chose option 2"', DEFER, True),
    ("decision naming python3",
     '~/.claude/away/bin/away decision "used python3 to regenerate fixtures"', DEFER, True),
    ("decision naming rm and cp",
     '~/.claude/away/bin/away decision "removed it with rm, then cp the fixture"', DEFER, True),
    ("decision containing a quoted >",
     '~/.claude/away/bin/away decision "wrote build output > /tmp/out.log"', DEFER, True),
    ("decision containing a semicolon",
     '~/.claude/away/bin/away decision "ran rubocop; deferred the ruby upgrade"', DEFER, True),
    ("away report", "away report", DEFER, True),
    ("away trash", "~/.claude/away/bin/away trash", DEFER, True),
    # ...and the exemption must not become a way in.
    ("decision chained to a delete",
     '~/.claude/away/bin/away decision "x" && rm -rf ~/.claude/away', DENY, True),
    ("decision wrapping a substitution",
     'away decision "$(rm -rf ~/.claude/away)"', DENY, True),
    # All three redirect forms: only the spaced one was checked, so shlex kept
    # `>~/...` and `2>~/...` as single tokens that matched nothing in the list.
    ("decision redirected over the guard",
     "away decision x > ~/.claude/away/hooks/guard.py", DENY, True),
    ("decision redirected, glued",
     "away decision x >~/.claude/away/hooks/guard.py", DENY, True),
    ("decision redirected, fd-prefixed",
     "away decision x 2>~/.claude/away/hooks/guard.py", DENY, True),
    ("away off is not a safe subcommand", "away off", DENY, True),
    ("agent purges the log", "away purge", DENY, True),
    ("agent rewires setup", "~/.claude/away/bin/away setup --yes", DENY, True),
    ("agent updates away", "away update", DENY, True),
    ("agent uninstalls", "bash ~/.claude/away/uninstall.sh", DENY, True),
    ("off: purge is the operator's own", "away purge", DEFER, False),
    ("session arm with a note naming python3",
     '~/.claude/away/bin/away on --here "regenerate with python3"', DEFER, True),
    ("session arm chained to a guard write",
     '~/.claude/away/bin/away on --here x && rm ~/.claude/away/hooks/guard.py', DENY, True),

    # --- away OFF: the guard does nothing at all
    ("off: away off", "away off", DEFER, False),
    ("off: write to the guard", "echo x > ~/.claude/away/hooks/guard.py", DEFER, False),
    ("off: recursive delete", "rm -rf src", DEFER, False),
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
        "rest = strip_away_cli(cmd)", "rest = undefined_name(cmd)"))

    def probe(cmd):
        payload = json.dumps({"session_id": "res", "cwd": str(tree),
                              "tool_name": "Bash", "tool_input": {"command": cmd}})
        return subprocess.run(
            ["bash", str(sandbox / "hooks" / "guard.sh"), "pretooluse"],
            input=payload, capture_output=True, text=True, timeout=60,
            env=dict(os.environ, AWAY_HOME=str(sandbox), AWAY_TEST="1"))

    found = []
    # Both name away, so the fast path hands them to python and the broken guard.
    proc = probe("ls ~/.claude/away")
    if proc.returncode != 0:
        found.append("a broken guard blocked an ordinary command despite the fallback")
    if "guard.py is broken" not in proc.stderr:
        found.append("the fallback was silent about being a fallback")
    proc = probe("away off && ls ~/.claude/away")
    if "deny" not in proc.stdout:
        found.append("the fallback ran but stopped enforcing policy")
    good.unlink()
    if probe("ls ~/.claude/away").returncode != 2:
        found.append("with no fallback the guard must fail closed, and did not")
    shutil.rmtree(sandbox, ignore_errors=True)
    return found


def permission_prompt_cases(tree):
    """Every prompt while away is denied with a way forward, and never interrupts."""
    sandbox = Path(tempfile.mkdtemp(prefix="away-prompt-"))
    (sandbox / "state").mkdir(parents=True)
    flag = sandbox / "state" / "active.json"
    log = sandbox / "state" / "events.jsonl"

    def ask(event, tool, tool_input, armed=True):
        if armed:
            flag.write_text('{"on":true,"since_epoch":1}')
        elif flag.exists():
            flag.unlink()
        payload = {"session_id": "prompttest", "cwd": str(tree), "tool_name": tool,
                   "tool_input": tool_input}
        proc = subprocess.run(
            [sys.executable, str(GUARD), event], input=json.dumps(payload),
            capture_output=True, text=True, timeout=60,
            env=dict(os.environ, AWAY_HOME=str(sandbox), AWAY_TEST="1"))
        if not proc.stdout.strip():
            return None
        return json.loads(proc.stdout)["hookSpecificOutput"]["decision"]

    cases = [
        ("push", "git push -u origin x", "Keep committing locally"),
        ("push after cd", "cd sub && git push", "Keep committing locally"),
        ("push with git -C", "git -C repo push origin x", "Keep committing locally"),
        ("delete with env prefix", "FOO=1 rm x", "not done:"),
        ("rmdir", "rmdir d", "not done:"),
        ("push beats delete", "rm x && git push", "Keep committing locally"),
        ("anything else", "make deploy", "Route around it"),
    ]
    found = []
    for label, cmd, want in cases:
        log.unlink(missing_ok=True)
        got = ask("permissionrequest", "Bash", {"command": cmd})
        if not got or got.get("behavior") != "deny" or want not in got.get("message", ""):
            found.append("prompt: %-24s want deny with %r, got %r" % (label, want, got))
        elif "interrupt" in got:
            found.append("prompt: %-24s set interrupt, which ends the turn" % label)
    got = ask("permissionrequest", "WebFetch", {"url": "https://x.example"})
    if not got or "Route around it" not in got.get("message", ""):
        found.append("prompt: a non-Bash tool did not get the general message: %r" % got)
    got = ask("permissionrequest", "ExitPlanMode", {"plan": "p"})
    if not got or got.get("behavior") != "allow":
        found.append("prompt: plan exit was not approved: %r" % got)

    log.unlink(missing_ok=True)
    if ask("permissiondenied", "Bash", {"command": "rm -rf /x"}) is not None:
        found.append("permissiondenied: emitted output, which the harness ignores")
    if [r.get("event") for r in events(sandbox)] != ["auto_denied"]:
        found.append("permissiondenied: did not log auto_denied: %r" % events(sandbox))
    ask("permissiondenied", "Bash", {"command": "rm -rf /y"})
    got = ask("permissionrequest", "Bash", {"command": "make x"})
    if "degraded" not in (got or {}).get("message", ""):
        found.append("prompt: three quick blocks did not flag the session degraded")
    log.unlink(missing_ok=True)
    got = ask("permissionrequest", "Bash", {"command": "make x"})
    if "degraded" in (got or {}).get("message", ""):
        found.append("prompt: one block flagged the session degraded")

    for event in ("permissionrequest", "permissiondenied"):
        if ask(event, "Bash", {"command": "git push"}, armed=False) is not None:
            found.append("%s: emitted output with away mode off" % event)
    shutil.rmtree(sandbox, ignore_errors=True)
    return found


def report_cases():
    """The report opens with what was not done, and only that."""
    sandbox = Path(tempfile.mkdtemp(prefix="away-report-"))
    (sandbox / "state").mkdir(parents=True)
    recs = [
        {"event": "deferred", "tool": "Bash", "detail": {"command": "git push origin x"}},
        {"event": "auto_denied", "tool": "Bash", "detail": {"command": "rm -rf build"}},
        {"event": "self_reported_decision", "detail": {"decision": "not done: drop table t"}},
        {"event": "self_reported_decision", "detail": {"decision": "chose option 2"}},
    ]
    with open(sandbox / "state" / "events.jsonl", "w") as log:
        for rec in recs:
            log.write(json.dumps(dict(rec, ts="2026-10-01T00:00:00Z", session="s")) + "\n")
    out = subprocess.run([sys.executable, str(HOME / "bin" / "report.py"), "digest"],
                         capture_output=True, text=True, timeout=30,
                         env=dict(os.environ, AWAY_HOME=str(sandbox))).stdout
    block = out.split("Not done — needs you:")[-1].split("\n\n")[0]
    found = []
    for want in ("git push origin x", "rm -rf build", "not done: drop table t"):
        if want not in block:
            found.append("report: %r missing from Not done" % want)
    if "chose option 2" in block:
        found.append("report: an ordinary decision was listed as not done")
    shutil.rmtree(sandbox, ignore_errors=True)
    return found


def ping_cases(tree):
    """The hand-back report: asked for once per stop, sent from the hook, never looped."""
    import http.server
    import threading

    received = []

    class Hook(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Hook)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    sandbox = Path(tempfile.mkdtemp(prefix="away-ping-"))
    (sandbox / "state").mkdir(parents=True)
    ping = sandbox / "slack-ping"
    ping.mkdir()
    (ping / "user_id").write_text("U0TEST\n")
    (ping / "webhook_url").write_text("http://127.0.0.1:%d/hook\n" % server.server_port)
    transcript = sandbox / "t.jsonl"
    transcript.write_text(json.dumps({"type": "assistant", "message": {"content": [
        {"type": "text", "text": "✅ repo: done\n\nPROGRESS\n• shipped"}]}}) + "\n")

    def stop(active, armed=True):
        flag = sandbox / "state" / "active.json"
        if armed:
            flag.write_text('{"on":true,"since_epoch":1}')
        elif flag.exists():
            flag.unlink()
        payload = {"session_id": "pingtest", "cwd": str(tree), "stop_hook_active": active,
                   "transcript_path": str(transcript)}
        proc = subprocess.run(
            [sys.executable, str(GUARD), "stop"], input=json.dumps(payload),
            capture_output=True, text=True, timeout=60,
            env=dict(os.environ, AWAY_HOME=str(sandbox), AWAY_TEST="1",
                     SLACK_PING_HOME=str(ping)))
        return "block" if '"block"' in proc.stdout else "allow"

    found = []
    if stop(False, armed=False) != "allow" or received:
        found.append("ping: a stop with away mode off was touched")
    if stop(False) != "block":
        found.append("ping: the hand-back did not ask for a status report")
    if stop(True) != "allow":
        found.append("ping: the stop after the report was not accepted")
    if [r.get("userId") for r in received] != ["U0TEST"] \
            or not received[0].get("message", "").startswith("✅ repo: done"):
        found.append("ping: the report was not sent to the operator: %r" % received)
    if stop(True) != "block":
        found.append("ping: a later hand-back did not ask again")
    transcript.write_text("")
    if stop(True) != "allow" or len(received) != 1:
        found.append("ping: an empty report was sent, or the stop was held")
    (ping / "webhook_url").unlink()
    if stop(False) != "allow":
        found.append("ping: without Slack Ping set up, the stop was held")
    server.shutdown()
    shutil.rmtree(sandbox, ignore_errors=True)
    return found


def main():
    failures, ran = [], 0
    sandbox = Path(tempfile.mkdtemp(prefix="away-policy-"))
    (sandbox / "state").mkdir(parents=True)
    tree = Path(tempfile.mkdtemp(prefix="away-tree-"))
    subprocess.run(["git", "init", "-q", str(tree)], check=True)

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

    tool_cases = [
        ("question", "AskUserQuestion", {"questions": [{"question": "q"}]}, DENY),
        ("plan exit", "ExitPlanMode", {"plan": "p"}, ALLOW),
        ("edit the guard", "Edit", {"file_path": str(Path.home() / ".claude/away/hooks/guard.py")}, DENY),
        ("edit settings", "Write", {"file_path": str(Path.home() / ".claude/settings.json")}, DENY),
        ("edit project code", "Edit", {"file_path": str(tree / "a.rb")}, DEFER),
    ]
    for label, tool, tool_input, want in tool_cases:
        ran += 1
        got, _ = decide(sandbox, "", tree, tool=tool, tool_input=tool_input)
        if got != want:
            failures.append("%-34s want %-6s got %-6s" % (label, want, got))

    failures += cli_cases(tree)
    failures += resilience_cases(tree)
    failures += ping_cases(tree)
    failures += permission_prompt_cases(tree)
    failures += report_cases()
    ran += 33
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
