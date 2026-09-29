#!/usr/bin/env python3
"""PreToolUse(Bash): deny git push to protected branches; every other push goes through."""
import json, os, shlex, subprocess, sys

PROTECTED = {"main", "master", "develop", "staging"}
SEPARATORS = {";", "&&", "||", "|", "&", "\n", "(", ")"}
VALUE_OPTS = {"-o", "--push-option", "--repo", "--receive-pack", "--exec"}
PUSHES_EVERYTHING = {"--all", "--mirror", "--branches"}


def git(cwd, *args):
    r = subprocess.run(["git", "-C", cwd, *args], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ""


def current_targets(cwd):
    names = {git(cwd, "rev-parse", "--abbrev-ref", "HEAD")}
    push = git(cwd, "rev-parse", "--abbrev-ref", "@{push}")
    if push:
        names.add(push.split("/", 1)[-1])
    return names - {"", "HEAD"}


def branch_of(ref, cwd):
    ref = ref.lstrip("+").removeprefix("refs/heads/")
    return current_targets(cwd) if ref in ("HEAD", "@") else {ref}


def push_targets(args, cwd):
    """Branch names a `git push <args>` would update, or None if unknowable."""
    positional, skip = [], False
    for a in args:
        if skip:
            skip = False
        elif a in PUSHES_EVERYTHING:
            return set(PROTECTED)
        elif a in VALUE_OPTS:
            skip = True
        elif not a.startswith("-"):
            positional.append(a)
    refspecs = positional[1:]
    if not refspecs:
        return current_targets(cwd) or None
    targets = set()
    for spec in refspecs:
        src, _, dst = spec.partition(":")
        targets |= branch_of(dst or src, cwd)
    return targets


def segments(command):
    lex = shlex.shlex(command, posix=True, punctuation_chars=";&|()\n")
    lex.whitespace_split = True
    seg = []
    for tok in lex:
        if tok in SEPARATORS:
            yield seg
            seg = []
        else:
            seg.append(tok)
    yield seg


def check(command, cwd):
    """Returns (decision, reason) for the first risky push, else None."""
    try:
        segs = list(segments(command))
    except ValueError:
        return None
    for seg in segs:
        for tok in seg:
            if " " in tok and "push" in tok:
                hit = check(tok, cwd)
                if hit:
                    return hit
        if len(seg) >= 2 and seg[0] == "cd":
            cwd = os.path.join(cwd, os.path.expanduser(seg[1]))
            continue
        if not seg or os.path.basename(seg[0]) != "git":
            continue
        i, repo = 1, cwd
        while i < len(seg) and seg[i].startswith("-"):
            if seg[i] == "-C" and i + 1 < len(seg):
                repo = os.path.join(repo, os.path.expanduser(seg[i + 1]))
                i += 1
            elif seg[i] == "-c":
                i += 1
            i += 1
        if i >= len(seg) or seg[i] != "push":
            continue
        targets = push_targets(seg[i + 1:], repo)
        if targets is None:
            return "ask", "git push: couldn't tell which branch this pushes to"
        hit = sorted(targets & PROTECTED)
        if hit:
            return "deny", f"git push to protected branch {', '.join(hit)} is blocked"
    return None


def main():
    data = json.load(sys.stdin)
    command = data.get("tool_input", {}).get("command", "")
    if "push" not in command:
        return
    hit = check(command, data.get("cwd") or os.getcwd())
    if hit:
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": hit[0],
            "permissionDecisionReason": hit[1],
        }}))


if __name__ == "__main__":
    main()
