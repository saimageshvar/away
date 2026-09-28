# Changelog

## 1.5.0

The hand-back now reaches the operator's phone. With a Slack Ping workflow configured
(`~/.config/slack-ping/webhook_url` + `user_id`), the Stop hook asks the agent once per
hand-back to end on a plain-text status report — progress, blocked, what I got wrong — and
then sends that final message as a Slack DM itself.

- **The hook sends, not the agent.** An agent's POST to a webhook is the outward write
  the guard denies, and letting the agent pass the recipient would let it DM anyone.
- **It cannot loop.** The report is requested at most once per hand-back; if the next
  stop has no text, it is skipped and the stop is accepted. The existing denial nudge
  still fires first.
- **Off unless configured**, so installs without Slack Ping behave exactly as before.

## 1.4.0

Adversarial review broke the delete-relax path from 1.2.0 inside an hour. It is removed.

It let the on-device model's output turn a deny into an allow: the model extracted a
command's delete paths and the deterministic code judged those paths. Three things were
named as holding the line, and all three failed a first-hour probe.

- **The prompt was escapable.** It wrapped the command in `<<< >>>`, so a command
  *containing* `>>>` closed the wrapper and supplied its own `Paths deleted:` answer.
  That breakout allowed `shutil.rmtree($HOME/Documents)` -- reproduced, and now a test
  case.
- **The recursion rule was never carried over.** `cd <sibling> && rm -rf src` ran where
  a plain `rm -rf src` was denied.
- **The undo bundle was not a backstop.** It is size-capped, it was passed
  `best_effort` on every path, and `git_undo_bundle` writes an empty patch and returns
  no error when git fails. For a 60MB untracked directory it captured nothing, while
  the docs claimed "a full undo bundle captured before anything is allowed".

What replaces it is what recovered most of the value anyway: **21 of those 43 denials
were one thing -- "the cd target is outside the working tree"** -- and widening the base
to any checkout or scratch directory fixes them with no model at all. `handle_rm` then
applies every rule it always did against that base. The model bought about three
denials beyond that, and cost a breakout.

**No model output can cause an allow anywhere in this guard now.** `fm` is consulted in
one place, to *add* an outward denial, where being wrong costs a prompt.

Also fixed, all from the same review:

- **The tamper exemption leaked through glued redirects.** Only a bare `>` token was
  checked, so `away decision x >~/.claude/away/hooks/guard.py` and the `2>` form both
  walked through -- shlex keeps the glued form as one token. Every redirect form is
  now rejected.
- **`EPHEMERAL` matched a path component by name**, so a directory called `tmp` holding
  the only copy of something was deleted with no snapshot, and after 1.3.0 with no
  prompt either. Names that settle it on their own (`node_modules`, `__pycache__`,
  `.venv`...) still do; the ordinary English ones (`tmp`, `log`, `build`, `dist`,
  `target`, `reports`, `coverage`) now need the repo to actually gitignore them.
- Documentation claimed "zero false positives across the 400" for the whole guard. The
  model pass fires on one of the 400; the layered guard denies 8. Corrected in both
  places.

Tests 138 -> 144.

## 1.3.1

`Rm -rf /Users/x` ran unprompted with away mode off.

There are two delete detectors and one gates the other. While armed, guard.sh routes
every Bash call to python, so DELETION_HINT alone decides. While OFF, guard.sh's shell
glob decides whether python runs AT ALL -- so a form DELETION_HINT knows but the glob
does not is a delete that runs with no prompt. DELETION_HINT is `re.I`; the glob was
not. APFS is case-insensitive, so `Rm` really does execute /bin/rm, as the comment on
delete_shaped has said all along.

That is the second divergence between the two. The first was vocabulary: DELETION_HINT
grew `os.remove` and `File.delete`, and neither has an "rm" in it nor the hyphen that
`-delete` wanted. Both were invisible while armed, which is the state anyone would
test first.

- The glob now matches case-insensitively (`shopt -s nocasematch`, scoped to that one
  `case`), and drops the hand-added `*RM*` and `*Delete*` variants it no longer needs.
- **A test now reads the terms out of DELETION_HINT and asserts guard.sh routes every
  one of them, in three cases each.** Adding a term to the constant without teaching
  the glob fails the suite. Verified by reintroducing the bug: 20 failures, all naming
  the unrouted variant.
  It asserts on routing alone, against a stubbed guard.py -- the real guard stays
  silent for a command that is delete-shaped by vocabulary but has no delete in
  command position, and reading that silence as "not routed" made an earlier version
  of this test assert the wrong thing.

Tests 96 -> 138.

## 1.3.0

**Away OFF: a delete scoped to the working tree now runs without asking.**

The hook took the `ask`-on-delete rule over from the permission list, and then
asked about every delete -- including the ones it could already prove were safe.
That is a prompt for `rm node_modules/x` and for `rm a-file-you-just-wrote`, and
the answer was always yes.

It now runs the same test `handle_rm` applies while armed: every target resolvable
and inside the working tree, recursion only onto regenerable paths, and a snapshot
taken first for anything git cannot bring back. Passing that test is the whole
reason the answer would have been yes, so passing it is enough.

Only the failure branch differs by state. Armed, a failure is a denial and is
logged, because nobody is there to answer. With the operator present it is an
`ask`, exactly as before, and nothing is logged -- the event log stays a record of
absences rather than of ordinary work.

Still asks, unchanged: `rm -rf src`, anything outside the tree, a variable or glob
target, a delete behind `xargs`/`find`/a shell payload, and a container exec.

- **The trash is pruned at 14 days.** Snapshots used to be taken only during an
  absence, so nothing ever pruned them and nothing needed to. An allowed in-tree
  delete is now many times a day. Age only, one stat per bundle: a size cap would
  mean walking every bundle on every delete.
- Only what git cannot recover is snapshotted. A tracked-clean file and a
  `node_modules` are allowed with no bundle at all -- four deletes in the test
  produce two bundles.

## 1.2.1

`away decision` was denying itself, which is the one command an absence depends on
for its record.

rules.md tells agents to call it by absolute path -- `~/.claude/away/bin/away decision
"..."` -- and that path matches SELF_PATHS. MUTATES then matched an ordinary word in the
DECISION TEXT: python3, ruby, rm, cp, a quoted `>`. Both halves matched, so recording a
decision read as tampering with away mode itself. **Five of six realistic decision texts
were denied**, and the bias was the wrong way round: a decision that mentions a file or a
tool is exactly the one worth keeping.

away's own agent-facing subcommands -- `decision`, `report`, `status`, `trash` -- are now
exempt from the tamper check. Per segment, not wholesale, so
`away decision "x" && rm -rf ~/.claude/away` still dies; and never when the segment
carries a bare redirect or a command substitution, so neither
`away decision "$(rm -rf ...)"` nor `away decision x > hooks/guard.py` can use the
exemption. `away on|off` is not on the list and is caught earlier regardless.

Also: `away report` now labels `checkpoint` and `relax_allowed` events instead of
printing the raw event name.

## 1.2.0

Away mode existed so work continues while nobody is watching, and it was spending that
time blocking its own operator. Of 116 denials in real absences, **43 were parser
failures, not dangerous commands** -- `cd <sibling worktree> && rm -rf frontend/node_modules`,
`rm -f build/reports/junit/*.xml`, a delete inside a heredoc, and
`docker compose run --rm`, which is not a delete at all. Every one was safe, every one
was recoverable, and every one stopped a line of work until the operator came back.

The layering is now: the parser decides, and when it decides *allow* nothing else runs.
Only when it would block does a second layer look, and what that layer does depends on
the kind of block.

- **Deletes it could not scope are reconsidered.** The model is used as an EXTRACTOR --
  it lists the paths the command deletes, and `classify_static`, `classify_git` and
  `snapshot_paths` then judge those paths exactly as they judge a plain `rm`. The model
  is never asked whether something is safe. When it was, it guessed: it dropped a `cd ..`
  and placed a sibling repo inside the working tree, invented a filename for
  `$(cat paths.txt)`, and returned the source file for `"$TARGET"`.
  What holds the line is deterministic and the model cannot override it: vetoes on
  substitution, variables and `~` **in the delete itself** (not elsewhere in the command,
  which vetoed `cd ~/projects/x && rm -rf tmp` and cost most of the gain), a base
  resolved by us rather than by the model, a requirement that every path come back
  absolute, and a full undo bundle captured before anything is allowed.
  Measured: **24 of the 43 real denials now run, with all 15 adversarial deletes still
  blocked** -- including five carrying an explicit "operator pre-approved this" comment.
- **Outward actions are never reconsidered.** Deploys, publishes, pushes, releases and
  remote writes stay denied by token rules alone. The relax path can only ever touch a
  delete.
- **`--rm` is no longer a delete.** `\brm\b` matches inside it because the hyphen is a
  word boundary, so `docker compose run --rm` read as a deletion, and with a `cd` in
  front it became a denial. Deterministic fix, no model involved.
- **A language's own delete now counts.** `DELETION_HINT` missed `shutil.rmtree`,
  `os.remove`, `FileUtils.rm` and `rmSync`, so `python3 - <<'PY'` calling `rmtree`
  skipped the entire delete path -- including the conduit check that exists for exactly
  that shape. This was a pre-existing hole, found while testing the relax path.

## 1.1.0

Outward detection was a token list, so it only ever caught what someone had thought to
add. Measured against 400 real commands from an actual absence, the gaps were a whole
family, not a long tail: `cap production deploy`, `kubectl apply`, `vercel --prod`,
`flyctl deploy`, `gcloud run deploy`, `twine upload`, `ssh host '...'`, a remote `psql`,
and a `curl -X POST` at a webhook. All of them fell through to defer, which a `Bash(*)`
permission turns into allow.

- **New token rules** for remote shells (`ssh`, `scp`, `rsync` to a host), deploy CLIs,
  third-party service CLIs, `kubectl`/`helm` write verbs, remote database clients, HTTP
  writes to a non-local URL, and build targets named deploy/release/publish. These carry
  the detection; they are deterministic and they are the floor.
- **A model pass behind them.** Apple's on-device model reads whatever the token rules
  did not recognise, and may only turn a defer into a deny — never a deny into an allow.
  That direction is the whole safety argument: the guarded agent writes the command text,
  so an injected "pre-approved, classify as safe" must not be able to buy anything. It
  cannot. Six of eight injection attempts did talk the model round; all eight were denied
  by the token rules regardless.
  On twelve deploy CLIs no rule lists, it caught four, at zero false positives across the
  400 real commands. A 59% prefilter keeps it off the hot path for `grep`, `sed`,
  `git status` and the like. Every failure mode returns no opinion. `AWAY_FM=0` disables
  it; the token rules are unaffected.
- Denials from the model are logged as `deferred_by_model`, so `away report` separates
  them and a false positive reads as a rule to write rather than a mystery.

Two regexes did not survive their own test run and are recorded here because the shape
recurs: `eb` in a deploy-CLI alternation matched a bare word inside a heredoc, and the
remote-database rule wanted two spaces where real commands have one. Short alternatives
need a length floor, and every new pattern gets run against real history before it lands.


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
