---
name: away
description: Scope away mode to THIS session. Use when the user types /away with on, off, status, or report. Arms or disarms away mode for the current session only, never globally.
---

# away

Away mode makes an agent decide for itself instead of asking. Hooks enforce it; this
skill only scopes it to the current session.

Two layers exist. The operator arms the **global** flag from their own terminal, and it
covers every session. This skill touches only the **session** layer. A global absence
takes precedence and deletes session flags, so the two never disagree.

## Args

- `on [note]` — arm away mode for this session only
- `off` — disarm this session's own flag
- `status` or empty — report the effective state and which layer set it
- `report` — print the away log

## Steps

Run the matching command with the Bash tool, then reply with its output verbatim plus at
most one line of context. Do not paraphrase the state.

| Arg | Command |
|-----|---------|
| `on [note]` | `away on --here "<note>"` (omit the quotes when there is no note) |
| `off` | `away off --here` |
| `status` / empty | `away status` |
| `report` | `away report` |

## What this skill will not do

Never run `away on` or `away off` without `--here`. Those switch every session on this
machine, they belong to the operator alone, and the guard denies them. If the user asks
for a global change, tell them to run `away on` or `away off` in their own terminal.

## Notes that matter

- A note is not a label. It rides on every denial the agent reads, so write it as an
  instruction: `/away on if blocked on push, commit and move on`.
- `off` cannot free this session from a global absence. It only removes a flag this
  session set for itself. Say so plainly if the user expects otherwise.
- `--here` needs `CLAUDE_CODE_SESSION_ID`, which exists inside a session but not in a
  plain terminal. That is why this skill exists.
- Every scope change is logged, so `away report` shows when a session armed or disarmed
  itself.

The full rules an armed session must follow live in `~/.claude/away/rules.md`. Testing
notes live in `~/.claude/away/TESTING.md`.
