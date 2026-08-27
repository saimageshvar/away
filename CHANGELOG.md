# Changelog

## 1.0.2

Both fixes came from watching the real `away update 1.0.0 -> 1.0.1` run, not from a test.

- The release-asset download 404'd while the workflow was still uploading it, and the
  updater silently fell back to GitHub's source archive. Falling back is correct; doing
  it silently is not, when the thing being swapped is the guard every tool call depends
  on. Every failed URL is now reported, and a total failure names all of them.
- That fallback also revealed that `swap()` installed whatever the archive contained,
  so `.github/` and `.gitignore` landed in `~/.claude/away` -- a release workflow living
  inside an install. `install.sh` had always excluded them; the two paths had diverged.
  Both now share one exclusion list, `NOT_INSTALLED`. `tests/` is still shipped on
  purpose, since the README tells people to run it.

## 1.0.1

Corrects what the permission audit *says*. The behaviour it applies was already right;
two of its explanations were not, and one real consequence went unmentioned.

The governing fact, now quoted in the README:

> Hook decisions don't bypass permission rules. Claude Code evaluates deny and ask
> rules regardless of what a PreToolUse hook returns.

- The `ask`-on-deletes failure is now stated for the right reason. It is not that a
  second prompt appears; it is that the rule prompts **on top of the guard's `allow`**,
  and while away nothing answers it.
- `deny` rules covering deletes now raise a warning instead of being folded into
  "deny never conflicts". They are still never modified, and they are still safe --
  deny wins, so nothing is deleted. But `PreToolUse` runs before the rule is
  evaluated, so the guard has already snapshotted and logged the delete as allowed.
  `away report` would name deletes that never happened and `away trash` would hold
  snapshots of files still on disk, which defeats the purpose of the log.
- The `allow`-rule note no longer claims the guard's denial outranks an allow rule.
  The documented precedence over allow rules is for a hook that exits 2; the guard
  denies with a JSON decision instead, so it can hand the agent a reason to act on.
  The note now says only what is true: an allow rule skips the prompt, not the guard.

## 1.0.0

First packaged release. The guard and CLI were already in use; this turns them into
something another person can install.

Added:

- `install.sh` — curl-able installer that resolves the latest release, verifies the
  downloaded guard against its own self-test **before** installing it, and preserves
  an existing `state/` directory on upgrade.
- `away setup` — end-to-end wiring: PATH link, global `/away` skill, idempotent hook
  registration into `settings.json` (backed up first, merged with existing hooks),
  and a permission audit that asks before changing anything.
- Permission conflict detection for the three settings that leave an unattended
  agent stalled: an unsafe `permissions.defaultMode`, an `ask` rule colliding with
  the guard on deletes, and an `ask` rule matching every Bash call. Also checks
  `settings.local.json`, which wins over `settings.json`.
- `away doctor` — now audits the whole install, not just the guard: payload
  completeness, PATH resolution (including a PATH `away` belonging to a *different*
  install), the skill, all four hook registrations pointing at this home, permission
  conflicts, state writability, and available updates.
- Daily release check ahead of every command, with an offer to update. Skipped while
  away mode is on, skipped when stdin is not a terminal, and disabled by
  `AWAY_NO_UPDATE_CHECK=1`.
- `away update` — self-update that self-tests the new guard first, keeps `state/`,
  and re-runs setup so hook paths match the new payload.
- `away version`, `away selftest`, `away uninstall`, and `uninstall.sh`.
- `VERSION`, `README.md`, `LICENSE`, and a release workflow.

Fixed while packaging, all three found by testing rather than review:

- Hook identity matched the literal directory name `away`, so an install under any
  other `AWAY_HOME` was never recognised and `setup` appended a duplicate
  registration on every run.
- The delete-rule audit matched `rm` as a substring, so `Bash(terraform *)` was
  flagged as a delete rule and offered up for removal. It now uses the same token
  boundaries as the guard's own `DELETION_HINT` — the audit flags exactly what the
  guard gates, no more.
- The daily release check sat on the path of `away status`, which a statusline polls
  on every render. It now runs on an allowlist of human-typed commands only.

Notes:

- `guard.py.good`, the crash fallback, is blessed per machine by the self-test and is
  never shipped in a release.
- Uninstall does not revert permission settings. Setup may have changed
  `defaultMode`, and only the operator knows whether they want it back.
