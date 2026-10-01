# away

Autonomous mode for Claude Code. You leave the keyboard; your agents keep working
instead of stalling on a permission prompt nobody is there to answer.

A file flag is the switch. Hooks enforce it. Every running session picks up a
change on its next tool call — no restart, no re-prompt.

```bash
away on "if blocked on push, commit and move on"
# ... go to lunch ...
away off        # prints a digest of every decision and denial
```

## What it actually does

Away mode is not a second permission system. Your permission rules, your org's managed
settings and auto mode's classifier decide what runs. Away mode makes sure an agent never
waits on a prompt nobody will answer, and tells it how to carry on when something is refused.

- **`AskUserQuestion` is denied.** The agent must decide, not ask.
- **Plan approval is auto-approved.** No agent waits at a checkpoint.
- **Every permission prompt is denied with a way forward.** A prompt means an `ask` rule
  matched, and nobody is there to answer it. The denial carries a message the agent acts on:
  - a push: keep committing locally, the branch stays unpushed for you;
  - a delete: leave the files and record it as `not done:`;
  - anything else: route around it or defer it with evidence.
  No message sets `interrupt`, which would end the agent's turn.
- **Auto-mode refusals are logged.** After repeated blocks auto mode pauses, and only an
  approval resumes it. Once a session looks paused, its denials and its hand-back ping
  say it is degraded, so it wraps up rather than looping.
- **`away perms` shows what will be refused** before an agent tries, from every settings
  source, managed included. The same list rides with the injected rules.
- **Away guards itself.** An agent may not switch the global flag or edit away's own files
  or `settings.json`.
- **Every denial and decision is logged**, and `away report` opens with
  **Not done — needs you**: denied prompts, auto-mode refusals, and `not done:` decisions.
- **Hand-backs reach your phone**, if you use a Slack Ping workflow. Before the stop
  that is accepted, the agent is asked once to end on a status report, and the hook
  sends that message to you as a Slack DM. The hook sends it, not the agent, so the
  recipient is always you. To turn it on, put the workflow's webhook URL in
  `~/.config/slack-ping/webhook_url` and your Slack member ID in
  `~/.config/slack-ping/user_id`. The workflow takes `{"message", "userId"}`.

With away mode off, the hooks do nothing.

### What this leaves to you

Away mode no longer snapshots deletes or judges pushes, deploys and remote writes. That is
the harness's job now. Two things follow:

- A narrow `allow` rule is decided before auto mode's classifier. `Bash(git restore*)`,
  `Bash(git stash*)` or `Bash(git clean*)` lets an agent discard uncommitted work with no
  undo; `Bash(*/tmp/*)` lets any command that mentions `/tmp/` skip the classifier.
- A `deny` rule fires no hook, so the agent learns about it only from the refusal itself
  and from `rules.md`.

The rules the agents follow are in [`rules.md`](rules.md). The hooks inject them,
so they reach every repo and every subagent without you restating anything.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/saimageshvar/away/main/install.sh | bash
away setup
```

Or download a release tarball, unpack it anywhere, and run `bash bin/away setup`.

The two steps are separate on purpose. Downloading is safe to pipe from the
internet; editing `~/.claude/settings.json` is not, so `away setup` runs in your
own terminal where it can ask before it changes anything.

**Requirements:** macOS or Linux, `bash`, `python3`, and Claude Code.

### What `away setup` does

1. Links `away` onto your PATH (`~/.local/bin` by default).
2. Installs the `/away` skill globally, so any session can scope away mode to itself.
3. Registers five hooks in `~/.claude/settings.json` — `PreToolUse`,
   `PermissionRequest`, `PermissionDenied`, `Stop`, `UserPromptSubmit` — merging into
   whatever hooks you already have, and backing the file up first. A `push_guard.py`
   hook left by an older install is removed.
4. **Audits your permission settings** and tells you what would make away mode
   stall (see below). It asks before changing any of it.
5. Runs the guard's self-test and blesses the passing copy as the crash fallback.

It is idempotent. Re-run it after an update, after moving the install, or any time
something looks wrong.

## Permission settings that break away mode

`away doctor` and `away setup` both check for these. Each one leaves an unattended agent
stuck or refused at every step.

| Setting | Why it breaks | Fix |
|---|---|---|
| `permissions.defaultMode` is `default`, `plan`, or `acceptEdits` | Claude Code raises approval prompts for anything not pre-allowed. Away denies each one, so the agent can do almost nothing. | `"auto"` |
| `ask` matching every Bash call (`Bash`, `Bash(*)`, `Bash(*:*)`) | Every shell command is denied while away. | narrow or remove |

Other `ask` and `deny` rules, managed or yours, are left alone: they are the policy now.
`away perms` lists them.

`settings.local.json` is checked too — project-local settings win, so a conflict
there is not fixed by editing `settings.json`.

## Commands

```
away on [note]           turn away mode ON globally, with an optional note
away off                 turn it OFF globally and print the digest
away on --here [note]    turn it ON for the calling session only
away off --here [id]     drop a session's own flag
away                     status: global state, plus any per-session flags
away report              digest for the current or last absence
away report --since 2h   digest for a time window (m/h/d)
away perms               every ask/deny rule the harness applies, by source
away perms "<cmd>"       best-effort: would the harness deny this command?
away trash               list snapshots older versions took (read-only)
away trash restore <id>  restore one of them
away decision "..."      record a call made without asking (for agents)
away purge               archive the event log and start a fresh one

away setup               wire the hooks, skill and PATH; audit permissions
away doctor              self-test the guard AND audit the whole install
away update              update to the latest release
away update --check      what the latest release is, without installing it
away version             installed version and home directory
away uninstall           unwire the hooks and skill (keeps your state)
```

### The note is an instruction, not a label

It rides on every denial the agent reads. Write it as guidance:

```bash
away on "finish the migration before the refactor"
away on "prefer shipping the smaller fix over waiting for me"
```

### Two layers

The **global** flag covers every session and is yours alone, from your own
terminal. A **session** flag covers one session, and an agent may set or drop its
own with `away on --here` — which is what the `/away` skill does.

Arming globally deletes every session flag, so the two layers can never disagree.
An agent can never free itself from a real absence: the resolver checks the global
flag first, and the guard denies an agent's attempt to switch it.

## `away perms`

```bash
away perms                        # every ask/deny rule, grouped by source
away perms "cd x && rm -rf build" # a verdict per segment
```

Sources: managed (`~/.claude/remote-settings.json`,
`/Library/Application Support/ClaudeCode/managed-settings.json`,
`/etc/claude-code/managed-settings.json`), user (`~/.claude/settings.json`,
`settings.local.json`) and project (`.claude/settings.json`, `.claude/settings.local.json`).

A verdict is one of *denied by `<rule>`*, *asks, so denied while away* or *no rule
matched — auto mode's classifier decides*. It never says "allowed": an unmatched command
still meets the classifier, and the matching is a best-effort copy of Claude Code's.

## Updates

Every `away` command checks for a newer release, at most once a day, and offers to
install it. The check is skipped when:

- away mode is **on** — an absence is never interrupted, and swapping the guard
  mid-absence is exactly when you least want a surprise;
- the terminal is **not interactive** — so an agent calling `away decision` never
  sees a prompt it might answer on your behalf;
- `AWAY_NO_UPDATE_CHECK=1` is set.

`away update` downloads the release, **runs the new guard's self-test before
installing it**, keeps your `state/` directory, moves the old install aside to
`~/.claude/away.away-previous`, and re-runs setup so hook paths and the skill match
the new payload.

## Health checks

```bash
away doctor
```

Reports on: python3, payload completeness and permissions, the fallback guard,
`away` on PATH (and whether it resolves to *this* install), the `/away` skill, all
five hook registrations pointing at this home, permission conflicts,
`settings.local.json` overrides, state writability, and whether an update is
available. Exits non-zero on anything fatal.

Two failures are worth knowing by name:

- **A hook registered but pointing elsewhere.** Happens after moving the install.
  The guard is healthy, no hook calls it, and everything looks fine from the CLI.
- **The retired `push_guard.py` hook is still registered.** Its script is gone, so every
  Bash call it runs on fails. `away setup` removes it.
- **No fallback guard.** `guard.py` crashing blocks *every* tool call in *every*
  session, because `PreToolUse` fails closed. `guard.py.good` is the last copy that
  passed the self-test, and `guard.sh` falls back to it loudly. It is blessed per
  machine, never shipped.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `AWAY_HOME` | `~/.claude/away` | Install root. Also the state root — a sandbox must be a copy of the whole tree. |
| `AWAY_BIN_DIR` | `~/.local/bin` | Where the CLI is linked. |
| `AWAY_REPO` | `saimageshvar/away` | Release source for install and update. |
| `AWAY_VERSION` | latest release | Pin the installer to a tag. |
| `AWAY_NO_UPDATE_CHECK` | unset | Silence the daily release check. |
| `AWAY_TEST` | unset | Tag events as synthetic. **Set this on every test run.** |
| `AWAY_PERMS_MANAGED` | the managed paths above | Colon-separated managed settings files for `away perms`. Tests only. |
| `CLAUDE_CONFIG_DIR` | `~/.claude` | Where `settings.json` and `skills/` live. |
| `SLACK_PING_HOME` | `~/.config/slack-ping` | Holds `webhook_url` and `user_id` for the hand-back report. Neither file present = off. |

## Adapting the rules to your team

`rules.md` is generic on purpose. Repo-specific guidance — what counts as
mechanical in your codebase, which branches are yours to push — belongs in your
project's `CLAUDE.md` or `CLAUDE.local.md`, not in `rules.md`. An update replaces
`rules.md`; it will never touch your project files.

## Testing

```bash
bash tests/run_all.sh
```

| Suite | What it covers |
|---|---|
| `tests/policy_cases.py` | The decision table, permission-prompt messages, the degraded flag, the report's "Not done" block, the Slack ping, and a session-scoped CLI lifecycle. |
| `tests/perms_cases.py` | `away perms`: rules merged from every source, each verdict, and never "allowed". |
| `tests/audit_cases.py` | The permission audit and hook wiring, including removal of the retired `push_guard.py` hook. A false positive here is not cosmetic — setup offers to *delete* the rule it flags. |
| `tests/update_cases.py` | The self-update path, mostly its refusals: a guard that fails its self-test, an incomplete release, a path-escaping tarball, an absence in progress. |
| `tests/install_e2e.sh` | `setup` / `doctor` / `uninstall` against a throwaway `HOME` that already has hooks and conflicting permissions — including a hook left pointing at a moved install. |
| `tests/installer_e2e.sh` | `install.sh` itself, against a locally built tarball: clean install, upgrade over existing history, and both refusal paths. |

Every suite builds its own sandbox and never touches your live log.

**One rule, and it has bitten before:** always set `AWAY_TEST=1` on synthetic runs.
The event log is global. An untagged test event that looks like an attack makes an
unrelated session escalate a false security incident. See [`TESTING.md`](TESTING.md).

## Uninstall

```bash
bash ~/.claude/away/uninstall.sh            # unwire, keep history
bash ~/.claude/away/uninstall.sh --purge    # also delete ~/.claude/away
```

Permission settings are never reverted — setup may have changed `defaultMode` for
you, and only you know whether you want it back.

## License

MIT. See [LICENSE](LICENSE).
