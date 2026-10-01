# Thin away: the harness is the only policy

Date: 2026-10-01 · Status: approved design, pre-plan

## Why

Org managed settings (`~/.claude/remote-settings.json`) carry `ask: Bash(git push*)` and
`deny: Bash(rm -rf *)`, `Bash(git*-f *)`, `Bash(git*--force*)` among others. Permission rules
outrank hook decisions, so away's attempts to approve a feature-branch push always lose, and its
delete snapshots run before a managed deny blocks the command — the report then names deletes
that never happened.

Away stops being a second policy engine. The operator keeps their own settings as open as
possible (`Bash(*)`, `defaultMode: auto`); the harness (managed rules + auto-mode classifier)
decides what runs. Away's job is narrower:

1. The agent never asks and never waits.
2. When the harness blocks something, the agent is told how to carry on safely.
3. The operator gets a list of what was not done, on return.
4. Agents can look up which commands the rules deny, so they plan around them.

## Success criteria

- No away code path approves, snapshots or judges a Bash command.
- Every permission prompt raised while away is denied with a message the agent can act on, and
  does not end the turn.
- `away report` opens with "Not done — needs you", covering prompt denials, auto-mode denials and
  agent-recorded `not done:` decisions.
- `away perms [cmd]` reports rules from every settings source and never claims a command is
  allowed.
- Upgrading an install that has `push_guard.py` registered never leaves Bash calls failing.

## Accepted risks

- With away off, the guard does nothing. The only delete protection is the harness's
  `rm -rf *` deny and the auto-mode classifier.
- The operator's narrow allow rules `Bash(git restore*)`, `Bash(git stash*)`, `Bash(git clean*)`
  and `Bash(*/tmp/*)` resolve before the classifier. With `git_destructive` and its undo bundle
  gone, an away agent can discard uncommitted work with no undo, and a command mentioning
  `/tmp/` (e.g. `gh pr merge --body-file /tmp/b`) skips the classifier. Operator chose to keep
  the rules and accept this.

## Facts the design rests on

- PermissionRequest `decision` supports `behavior`, `message`, `interrupt`. `interrupt: true`
  stops Claude (ends the turn, fires Stop) — never send it. `message` tells Claude why.
- Managed `deny` rules fire no hook. `rules.md` is the only channel for those.
- `PermissionDenied` fires on auto-mode denials, may return only `retry`, cannot message the model.
- In auto mode `Bash(*)` is dropped, so unmatched commands reach the classifier. Narrow allow
  rules stay in effect and resolve first.
- Auto mode pauses after 3 consecutive or 20 total blocks and prompts for everything; only an
  approval resumes it. A blanket deny never does.

## Section 1: the denial contract

**Prompted denials** (a managed or user `ask`, or auto-mode fallback, reaching PermissionRequest
while away). The hook returns `behavior: deny` with a `message` and no `interrupt`. The message is
picked from the command word of every segment (`segments()` / `command_word()`, so
`cd x && git push` and `FOO=1 rm x` are recognised). Precedence when segments differ: push, then
delete, then other.

| Kind | Message (gist) |
|---|---|
| `git push` | Push needs approval nobody can give. Don't retry. Keep committing locally; the branch stays unpushed for the operator. |
| `rm` / `rmdir` / `unlink` / `shred` / `srm` | Delete denied. Leave the files, run `away decision "not done: <cmd> — <why>"`, continue. |
| anything else | Needs the operator. Don't retry. Route around it, or defer it with evidence, options and a recommendation. |

Non-Bash tools get the "anything else" message. `ExitPlanMode` stays auto-allowed.

**Auto-mode fallback.** A `PermissionDenied` handler logs `auto_denied` and the guard counts, per
session, consecutive and total blocks (prompt denials and `auto_denied` both count; whether the
harness counts prompt denials toward its 3/20 limit is verified during implementation). At 3
consecutive or 20 total, every deny message and the Stop ping add: "auto mode has likely paused;
this session is degraded — land your work, record what is not done, and stop."

**Hard denials.** `rules.md` gains "When the harness says no": the same three rules, the fallback
note, and a pointer to `away perms`.

**Report.** `away report` opens with "Not done — needs you": `deferred` events from
PermissionRequest, `auto_denied` events, and `self_reported_decision` events whose text starts
with `not done:`, each with its command and time.

**`away perms [cmd]`.**
- Sources, labelled in output: managed (`~/.claude/remote-settings.json`,
  `/Library/Application Support/ClaudeCode/managed-settings.json`, `/etc/claude-code/managed-settings.json`),
  user (`~/.claude/settings.json`, `settings.local.json`), project (`<cwd>/.claude/settings.json`,
  `.claude/settings.local.json`).
- No argument: prints every `ask` and `deny` rule, grouped by source, each marked "denied while
  away".
- With a command: split into segments, each matched against the rules (`Bash(x*)`, `Bash(x:*)`,
  `Bash(x)` shapes, `*` as a wildcard). The verdict is one of:
  - `denied by <rule> (<source>)`
  - `asks — denied while away: <rule> (<source>)`
  - `no rule matched — the auto-mode classifier decides`
  It never prints "allowed". Output ends with "best effort: the harness has the final word".
- The UserPromptSubmit full-rules injection appends the no-argument listing, condensed.

## Section 2: components

**`hooks/guard.py`** (~2200 → ~500 lines)
- Keep: primitives (logging, flags, session ctx, emitters), tamper guard (`TAMPER_TOOLS`,
  `SELF_PATHS`/`MUTATES`, `away_toggle_scope`, `strip_away_cli`), AskUserQuestion deny + retry
  reasons, ExitPlanMode allow, `handle_stop` + Slack ping, `handle_userpromptsubmit`.
- Keep, slimmed: `segments()`, `command_index()`, `command_word()`.
- Change: `handle_permissionrequest` per Section 1; `emit_permreq` gains `message`.
- Add: `handle_permissiondenied` and the per-session block counter.
- Remove: `OUTWARD`, `GIT_OUTWARD`, `GH_*`, `GH_AWAY_WRITES`, all `FM_*` and `fm_*`,
  `push_verdict`, `away_approvable`, `relax_base`, `effective_base`, delete classification,
  `rm_invocations`, `delete_shaped`, `hidden_delete`, `handle_rm`, `judge_delete`,
  container exec/mount mapping, `git_destructive`, `handle_git_destructive`, snapshot/bundle code,
  `prune_trash`. The away-off branch of `handle_pretooluse` goes entirely.

**`hooks/guard.sh`.** The armed PreToolUse fast path starts python only for `AskUserQuestion`,
`ExitPlanMode` and tamper paths, not every Bash call; `permissionrequest`, `permissiondenied`,
`stop`, `userpromptsubmit` always start it. `permissiondenied` fails open (the denial already
happened).

**`hooks/push_guard.py`.** Deleted, after setup unregisters it.

**`bin/away`.**
- Add `perms [cmd]` → `bin/perms.py`.
- `trash` keeps list and restore only, marked for removal once existing snapshots age out
  (after 2026-10-15). No new snapshots are written; the `mkdir -p state/trash` goes.
- Selftest drops cases for removed policy.

**`bin/setup.py`.**
- `HOOK_EVENTS` adds `("PermissionDenied", "permissiondenied", "*", 10)`.
- Setup and uninstall remove any hook entry whose command references `push_guard.py`, before the
  file can be missing.
- Permission audit keeps two checks: `defaultMode` must be auto-like, and no `ask` rule may match
  every Bash call. Delete-collision checks, delete-deny warnings and `touches_deletion` go.
- `audit_payload` drops removed files, adds `bin/perms.py`.

**`bin/report.py`.** Adds the "Not done — needs you" section and an `auto_denied` label. Labels for
removed events stay so old logs read correctly.

**`rules.md`.** "Nothing can be approved" becomes "When the harness says no". The outward-command
and model paragraphs go. Push guidance: commit locally and continue.

**Docs.** README, CHANGELOG, TESTING rewritten to match; "The model pass" and "Where a delete may
happen" sections removed.

**The uncommitted diff on `main`** (`away_approvable`, `GH_AWAY_WRITES`, `permission_prompt_cases`)
is discarded: it is the code that fought the harness.

## Section 3: testing

- `tests/policy_cases.py`, rewritten:
  - AskUserQuestion denied; ExitPlanMode allowed.
  - Tamper denied (Edit of `~/.claude/away/*`, `away on` global from an agent).
  - PermissionRequest: the right message for `git push`, `cd x && git push`, `FOO=1 rm x`,
    `make deploy`, a non-Bash tool; `interrupt` is never set.
  - The degraded note appears once the counter passes 3 consecutive / 20 total.
  - With away off, every hook emits nothing.
  - Stop ping cases and the fallback-guard resilience case stay.
- `perms` cases: rule merge across managed/user/project/local in a sandboxed `HOME`; each of the
  three verdicts; never "allowed"; chained commands split.
- `tests/audit_cases.py`: the two remaining checks, plus `push_guard` entry removal.
- `tests/install_e2e.sh`: five hooks registered, `push_guard` entry gone, Bash not blocked.
- Deleted: `tests/push_guard.sh`, model cases, checkout cases, deletion-hint drift cases.
- `tests/run_all.sh` drops removed suites and files.
- Live checks during implementation (cannot be unit-tested):
  - A deny with `message` and no `interrupt` reaches the agent and does not end its turn.
  - Whether prompt denials count toward auto mode's 3/20 pause limit; adjust the counter if not.
