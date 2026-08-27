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

When away mode is on, four hooks change how an agent behaves:

- **`AskUserQuestion` is denied.** The agent must decide, not ask.
- **Plan approval is auto-approved.** No agent waits at a checkpoint.
- **Outward actions are denied** — `git push`, PR creation, anything that leaves
  the machine. The agent commits and leaves the work unpushed.
- **Unrecoverable deletes are snapshotted first**, into `away trash`, then allowed.
- **Every denial and decision is logged**, so `away report` tells you what happened
  while you were gone.

The rules the agents follow are in [`rules.md`](rules.md). The hooks inject them,
so they reach every repo and every subagent without you restating anything.

> **This hands an agent autonomy on your own machine.** That is the point, and it
> is also the risk. The guard is the only thing standing between an unattended
> agent and an action you would have wanted to see. Read `rules.md` and
> `hooks/guard.py` before you trust it with a long absence.

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
3. Registers four hooks in `~/.claude/settings.json` — `PreToolUse`,
   `PermissionRequest`, `Stop`, `UserPromptSubmit` — merging into whatever hooks you
   already have, and backing the file up first.
4. **Audits your permission settings** and tells you what would make away mode
   stall (see below). It asks before changing any of it.
5. Runs the guard's self-test and blesses the passing copy as the crash fallback.

It is idempotent. Re-run it after an update, after moving the install, or any time
something looks wrong.

## Permission settings that break away mode

`away doctor` and `away setup` both check for these. They are not style
preferences — each one leaves an unattended agent stuck.

**Permission rules outrank the guard.** This is the fact the whole table below turns
on, and it is documented:

> Hook decisions don't bypass permission rules. Claude Code evaluates deny and ask
> rules regardless of what a PreToolUse hook returns: a matching deny rule blocks the
> call, and a matching ask rule still prompts even when the hook returned `"allow"` or
> `"ask"`.
>
> — [Configure permissions](https://code.claude.com/docs/en/permissions#extend-permissions-with-hooks)

So the guard cannot loosen anything you have locked down, and an `ask` rule the guard
was meant to replace does not go away just because the guard answered.

| Setting | Why it breaks | Fix |
|---|---|---|
| `permissions.defaultMode` is `default`, `plan`, or `acceptEdits` | Claude Code raises approval prompts for anything not pre-allowed. Nobody answers them, so the agent stalls instead of routing around. | `"auto"` |
| An `ask` rule matching `rm` / `unlink` / `shred` / `-delete` | The guard already gates deletes — snapshot to `away trash`, then `allow`. The `ask` rule **still prompts on top of that decision**, and while away nothing answers it, so the agent stalls on its first delete. | remove the rule |
| `ask` matching every Bash call (`Bash`, `Bash(*)`, `Bash(*:*)`) | Every shell command waits for an answer that never comes. | narrow or remove |

### `deny` rules are safe, and setup never touches them

A `deny` rule wins over the guard, so anything you deny stays denied — stricter than
away mode, never looser. Keep them.

One caveat if you deny deletes specifically (`deny: ["Bash(rm:*)"]` or similar):
`PreToolUse` runs *before* the permission rule is evaluated, so the guard has already
snapshotted the targets and logged the delete as allowed by the time `deny` blocks it.
Nothing is lost — the delete genuinely does not happen — but **`away report` will name
deletes that never occurred, and `away trash` will hold snapshots of files still on
disk.** `away doctor` warns when it sees this, because a misleading digest defeats the
point of the log.

`allow` rules are also left alone. An allow rule skips the *prompt*; it does not skip
the guard, which runs first on every tool call.

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
away trash               list snapshots taken while away
away trash restore <id>  restore one snapshot
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
away on "if blocked on push, commit and move on"
away on "prefer shipping the smaller fix over waiting for me"
```

### Two layers

The **global** flag covers every session and is yours alone, from your own
terminal. A **session** flag covers one session, and an agent may set or drop its
own with `away on --here` — which is what the `/away` skill does.

Arming globally deletes every session flag, so the two layers can never disagree.
An agent can never free itself from a real absence: the resolver checks the global
flag first, and the guard denies an agent's attempt to switch it.

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
four hook registrations pointing at this home, permission conflicts,
`settings.local.json` overrides, state writability, and whether an update is
available. Exits non-zero on anything fatal.

Two failures are worth knowing by name:

- **A hook registered but pointing elsewhere.** Happens after moving the install.
  The guard is healthy, no hook calls it, and everything looks fine from the CLI.
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
| `CLAUDE_CONFIG_DIR` | `~/.claude` | Where `settings.json` and `skills/` live. |

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
| `tests/policy_cases.py` | The decision table — 56 cases, plus a session-scoped CLI lifecycle. |
| `tests/audit_cases.py` | The permission audit's rule matching. A false positive here is not cosmetic — setup offers to *delete* the rule it flags. |
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
