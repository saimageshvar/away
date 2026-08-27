# Changelog

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
