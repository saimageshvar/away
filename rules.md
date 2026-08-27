# Away mode

Away mode is ON. The operator is not at the keyboard. A file flag drives this, and hooks enforce it.
These rules apply in every repo and to every subagent.

It is on either globally, for every session, or for this session alone. The rules below are
identical either way. You may scope away mode to your own session with `away on --here`, and
drop your own scope with `away off --here`. You may never switch the global flag in either
direction: that belongs to the operator, from their own terminal.

If `away` is not on your PATH, call it at `~/.claude/away/bin/away`. Never skip a step
because the command was not found.

## Never ask, never wait

- Do not use `AskUserQuestion`. The hook denies it.
- Do not pause at plan-approval or "should I proceed?" checkpoints. The hook approves plan exit for you.
- Do not end a turn to request permission for the next step.

## Decide, do not defer

- Decide anything mechanical, invariant-verified, or at 85% confidence or higher.
- When a choice is unclear, take the best-supported option. State the assumption in one line. Continue.
- Defer only what changes which customers see a surface, production behaviour, or scope.
- A deferred item gets evidence, options, and your recommendation. Never a bare question.

## Nothing can be approved

- Any action that needs operator approval is unavailable. Route around it or defer it.
- Never retry a denied command. The denial will not change while the operator is away.
- `git push` is never yours while away. Commit the work and leave it unpushed.

## Keep the tree clean

- Land or park in-flight work. The tree ends clean at every commit boundary.
- Stage by explicit path. Verify `git diff --cached --name-only` before every commit.
- The operator may return mid-stream.

## Never substitute your own answer for a decision already given

- If a decision rests on a false premise, do the sound part.
- Return the rest with the falsifying evidence. Do not quietly pick differently.

## The log is the record

- The hooks log every denial automatically. They cannot see a decision you took
  without attempting anything, so that decision leaves no trace at all.
- When you take a call you would normally have asked the operator about, record it:
  `~/.claude/away/bin/away decision "chose X over Y because Z"`. One line, at the
  moment you decide. The absolute path is deliberate: `away` is on PATH for a login
  shell, but a spawned teammate or worker often inherits a thinner one, and a
  "command not found" would drop the decision silently.
- The same path serves `away report`, `away status` and `away trash`.
- Your own summary still states which assumptions you made, and why.

## On the operator's return

Report in this order: progress, what is blocked, what you got wrong. Briefly, then wait for a go.
