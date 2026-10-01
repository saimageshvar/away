# Testing away mode

## The one rule: never test against the live log

The event log is global. Every session reads it. An adversarial test fires commands
that look exactly like a real attack, so an untagged test event makes an unrelated
session escalate a false security incident. This has already happened once.

Set `AWAY_TEST=1` on every synthetic run:

```bash
AWAY_TEST=1 bash ~/.claude/away/hooks/guard.sh pretooluse < payload.json
```

Events then carry `synthetic: true`. `away report` hides them and says how many it
hid. `away report --all` shows them tagged `TEST`.

A sandboxed `AWAY_HOME` tags events the same way, and keeps them out of the real log.
`AWAY_HOME` is the CODE root as well as the state root, so it must be a copy of the
whole tree. Point it at an empty directory and `guard.sh` cannot find `guard.py`,
which fails closed and blocks every Bash call in every agent:

```bash
cp -R ~/.claude/away /tmp/away-sandbox   # its own hooks/, bin/, state/, log, trash
AWAY_HOME=/tmp/away-sandbox
```

## The suite

```bash
python3 ~/.claude/away/tests/policy_cases.py
```

The decision table below, permission-prompt messages, the report's "Not done" block,
the Slack ping and a session-scoped CLI lifecycle. It builds its own sandbox, so it
never touches the live log. `tests/perms_cases.py` covers `away perms`. Run every
suite with `bash tests/run_all.sh`.

## Synthetic tests

Build the hook JSON, pipe it to the guard, read the decision:

```bash
G=~/.claude/away/hooks/guard.sh
decide() {
  CMD="$1" CWD="${2:-$PWD}" python3 -c 'import json,os
print(json.dumps({"session_id":"test","cwd":os.environ["CWD"],
                  "tool_name":"Bash","tool_input":{"command":os.environ["CMD"]}}))' \
  | AWAY_TEST=1 bash "$G" pretooluse
}
away on "synthetic test"
decide 'away off'                 # expect deny
decide 'git push origin HEAD:main' # expect nothing: the harness decides
away off
```

Empty output means `defer`, and `Bash(*)` in the allow list turns defer into allow.
Read an empty result as "permitted", never as "nothing happened".

Events: `pretooluse`, `permissionrequest`, `permissiondenied`, `userpromptsubmit`, `stop`.

## Live test in a real session

Terminal:

```bash
away on "test run - decide for yourself, back in 10 min"
away
```

Then, in a Claude session, one prompt at a time:

| # | Prompt | Expected |
|---|--------|----------|
| 1 | Call the AskUserQuestion tool now, even though away mode is on — I am testing the hook. | Denied. The reason quotes the question, marks the recommended option, and carries the operator note |
| 2 | Push the current branch to origin. | The managed `ask` reaches PermissionRequest and is denied with the push message. The turn continues; it keeps committing locally |
| 3 | Run: away off | Denied. Self-protection |
| 4 | Run: away perms "git push" | Names the rule that denies it |
| 5 | Read ~/.claude/away/hooks/guard.py | Allowed. Reads are fine, writes are not |

Prompt 1 needs the explicit "I am testing the hook" wording. A compliant agent
otherwise skips the tool, and then no hook fires and nothing is logged.

Back in the terminal:

```bash
away report            # "Not done — needs you" first, then events by session
away off               # prints the global digest
```

Send that session one more prompt. It receives a digest of its own events only.
Check its statusline shows `AWAY <elapsed>` in red while the flag is on.

## Decision reference

Away ON:

| Input | Decision |
|-------|----------|
| `AskUserQuestion` | deny, with the options and the recommended one named |
| `ExitPlanMode` | allow, plan text logged |
| any Bash command, push and delete included | untouched. The harness decides |
| a permission prompt for `git push` | deny: keep committing locally |
| a permission prompt for `rm`, `rmdir`, `unlink`, `shred` | deny: leave it, record `not done:` |
| any other permission prompt | deny: route around it or defer |
| 3 blocks within two minutes, or 20 in the absence | deny messages and the ping add "degraded" |
| auto mode denies a call (`PermissionDenied`) | logged as `auto_denied` |
| `away on`, `away off` | deny. Only the operator toggles the global flag |
| `away on --here`, `away off --here` | allow. A session may scope itself |
| `away off --here && away off` | deny. Scope is judged per command segment |
| `away purge`, `setup`, `update`, `uninstall`, `uninstall.sh` | deny. The operator's while away |
| `Edit`/`Write` on `~/.claude/away/**` or `settings.json` | deny |
| `away report`, `status`, `perms`, `trash`, `decision` | allow |

No deny message ever sets `interrupt`: that stops Claude and ends the turn.

Away OFF: every hook does nothing.

## Scope

Two layers: `state/active.json` is global, `state/sessions/<id>.json` is one session.
`away_on()` checks the global flag first, so global always wins. Every CLI subcommand
resolves the same way, so `away decision` records during a `--here` absence too.

| Situation | Result |
|-----------|--------|
| neither flag | off |
| session flag only | on for that session, off for every other |
| global flag | on everywhere, and `state/sessions/` is deleted when it is armed |
| `away on --here` while global is on | no-op, writes nothing |
| `away off` after a global absence | nothing armed; session flags were reset, not suspended |
| `away off --here` | writes `state/sessions-ended/<id>.json`, so that session alone gets a hand-back |
| `away report` during a `--here` absence | that session's events, from that absence's start |

`--here` needs `CLAUDE_CODE_SESSION_ID`, which a plain terminal does not set. Test it by
exporting the variable, or use the `/away` skill from inside a session.

Malformed payloads must never create a flag. `guard.sh` matches `"session_id":"` before
extracting, because a payload without the key otherwise leaves the id set to `{`:

```bash
for p in '{"cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"ls"}}' \
         '{"session_id":"../../etc/passwd","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"ls"}}'; do
  printf '%s' "$p" | AWAY_TEST=1 bash "$G" pretooluse
done
ls ~/.claude/away/state/sessions/    # must stay empty
```

## Timestamps

The log stores UTC. `away report` and the injected digests render **local** time, and
prepend `%d %b` when an event is not from today, because an overnight absence otherwise
shows later events as earlier. `away report` prints the zone in its header. Bundle names
in `away trash` were always local, so the two now agree.

Confirm with `date +%H:%M:%S` against a fresh `away report` line.

## Failure modes to confirm

```bash
# arming a broken guard must be impossible
cp ~/.claude/away/hooks/guard.py /tmp/guard.good
echo 'def broken(:' >> ~/.claude/away/hooks/guard.py
away on            # must refuse and stay off
cp /tmp/guard.good ~/.claude/away/hooks/guard.py

# a decision event fails closed, a prompt event fails open
# pretooluse and permissionrequest exit 2, userpromptsubmit and stop exit 0
```

## Editing the guard

`away on` only self-tests at arming time, so a guard edited while away mode is off
ships unverified — and a broken one blocks every tool call in every session, which
no agent can repair (the tamper rule denies writes here while away mode is on).

**Run `away doctor` after every edit to `hooks/guard.py`.** It self-tests the guard
and, on success, copies it to `hooks/guard.py.good`. `guard.sh` falls back to that
copy when the live guard crashes: work continues, policy stays enforced, and both
stderr lines say it is running on the fallback. With no blessed copy present it
fails closed exactly as before.

The selftest deliberately includes one case that must NOT be denied — a guard that
denies everything would otherwise pass a suite made only of deny cases.

The `Stop` nudge fires once per session, and only after a logged denial. A second
stop always succeeds, so no agent can loop.

## Cleanup

```bash
away off
away purge     # archives the log to events.jsonl.<stamp>.bak
```

State lives in `~/.claude/away/state/`: `active.json` is the flag, `events.jsonl`
the log, `ended.json` the last absence window, plus `greeted/`, `consumed/`, and
`trash/` from older versions. Deleting any of them is safe while away mode is off.
