#!/usr/bin/env python3
"""PreToolUse(Bash): ask before git push to protected branches; every other push goes through.

Allows only what it can prove. A push it cannot fully read (a wrapper it does not
know, a variable, a glob, config that picks the target) is an ask, never a pass.
"""
import json, os, re, shlex, subprocess, sys

PROTECTED = {"main", "master", "develop", "staging"}
PUNCT = ";&|()<>\n"
VALUE_OPTS = {"-o", "--push-option", "--repo", "--receive-pack", "--exec"}
PUSHES_EVERYTHING = {"--all", "--mirror", "--branches"}
GIT_OPTS_WITH_ARG = {"-C", "-c", "--git-dir", "--work-tree", "--namespace",
                     "--exec-path", "--config-env"}
# Config that changes what a push updates, or whether a pre-push hook runs.
PUSH_CONFIG = re.compile(r"^(push|remote|branch|core\.hookspath)", re.I)
WRAPPERS = {"sudo", "env", "nice", "time", "nohup", "command", "builtin", "exec",
            "timeout", "stdbuf", "then", "do", "else", "elif", "if", "while",
            "until", "{", "}", "!"}
ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z_0-9]*=")
DURATION = re.compile(r"^\d+(\.\d+)?[smhd]?$")
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
UNRESOLVED_REF = re.compile(r"[*?\[~^]|@\{")
RANK = {"allow": 0, "ask": 1, "deny": 2}
UNKNOWN = ("ask", "git push: couldn't tell which branch this pushes to")


def git(cwd, *args):
    r = subprocess.run(["git", "-C", cwd, *args], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ""


def nonliteral(tok):
    return "$" in tok or "`" in tok


def current_targets(cwd):
    names = {git(cwd, "rev-parse", "--abbrev-ref", "HEAD")}
    push = git(cwd, "rev-parse", "--abbrev-ref", "@{push}")
    if push:
        names.add(push.split("/", 1)[-1])
    return names - {"", "HEAD"}


def config_picks_target(cwd):
    """push.default=matching or a remote.*.push refspec decides the target, not the command."""
    return (git(cwd, "config", "push.default") == "matching"
            or bool(git(cwd, "config", "--get-regexp", r"^remote\..*\.push$")))


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
        if cwd is None or config_picks_target(cwd):
            return None
        return current_targets(cwd) or None
    targets = set()
    for spec in refspecs:
        src, _, dst = spec.partition(":")
        ref = (dst or src).lstrip("+").removeprefix("refs/heads/")
        if UNRESOLVED_REF.search(ref):
            return None
        if ref in ("HEAD", "@"):
            if cwd is None or not current_targets(cwd):
                return None
            targets |= current_targets(cwd)
        else:
            targets.add(ref)
    return targets


def segments(command):
    """Yield each simple command's words; redirects and their targets are dropped."""
    lex = shlex.shlex(command, posix=True, punctuation_chars=PUNCT)
    lex.whitespace_split = True
    lex.whitespace = " \t\r"  # a newline ends a command, so it must reach PUNCT
    seg, drop_next = [], False
    for tok in lex:
        if drop_next:
            drop_next = False
        elif tok and all(c in PUNCT for c in tok):
            if "<" in tok or ">" in tok:
                if seg and seg[-1].isdigit():
                    seg.pop()
                drop_next = tok[-1] in "<>"
            else:
                yield seg
                seg = []
        else:
            seg.append(tok)
    yield seg


def command_index(seg):
    for i, tok in enumerate(seg):
        if ENV_ASSIGN.match(tok) or tok in WRAPPERS or tok.startswith("-") or DURATION.match(tok):
            continue
        return i
    return None


def shell_payload(seg, i):
    """The script of `sh -c '…'` / `bash -lc '…'`, else None."""
    for j in range(i + 1, len(seg) - 1):
        if seg[j].startswith("-") and "c" in seg[j] and not seg[j].startswith("--"):
            return seg[j + 1]
    return None


def check_push(seg, i, cwd):
    j, repo = i + 1, cwd
    while j < len(seg) and seg[j].startswith("-"):
        opt = seg[j]
        if opt in GIT_OPTS_WITH_ARG:
            if j + 1 >= len(seg):
                return UNKNOWN
            val = seg[j + 1]
            if opt == "-c" and PUSH_CONFIG.match(val):
                return "ask", "git push with push/remote/hook config on the command line"
            if opt == "-C":
                repo = None if repo is None or nonliteral(val) else os.path.join(repo, os.path.expanduser(val))
            if opt in ("--git-dir", "--work-tree"):
                repo = None
            j += 1
        elif opt.startswith(("--git-dir=", "--work-tree=")):
            repo = None
        j += 1
    if j >= len(seg):
        return None
    sub = seg[j]
    if nonliteral(sub) or sub == "subtree":
        return UNKNOWN
    if sub != "push":
        return None
    args = seg[j + 1:]
    if any(nonliteral(a) for a in args):
        return UNKNOWN
    targets = push_targets(args, repo)
    if targets is None:
        return UNKNOWN
    hit = sorted(targets & PROTECTED)
    if hit:
        return "ask", f"git push to protected branch {', '.join(hit)} needs your approval"
    return "allow", "git push to an unprotected branch"


def check(command, cwd):
    """(decision, reason) for the pushes in command, worst first; None when there are none."""
    try:
        segs = list(segments(command))
    except ValueError:
        return UNKNOWN if re.search(r"\bpush\b", command) else None
    worst = None

    def take(verdict):
        nonlocal worst
        if verdict and (worst is None or RANK[verdict[0]] > RANK[worst[0]]):
            worst = verdict

    for seg in segs:
        i = command_index(seg)
        if i is None:
            continue
        word = os.path.basename(seg[i])
        if word in SHELLS and (payload := shell_payload(seg, i)) is not None:
            take(check(payload, cwd))
            continue
        if word == "eval":
            take(check(" ".join(seg[i + 1:]), cwd))
            continue
        if word == "cd":
            target = seg[i + 1] if i + 1 < len(seg) else "~"
            cwd = None if cwd is None or nonliteral(target) or target == "-" \
                else os.path.join(cwd, os.path.expanduser(target))
            continue
        if "push" not in seg[i:]:
            continue
        if word == "git":
            take(check_push(seg, i, cwd))
        elif word == "push" or nonliteral(seg[i]) or any(os.path.basename(t) == "git" for t in seg[i:]):
            take(("ask", f"git push behind `{seg[i]}` can't be read"))
    return worst


def main():
    data = json.load(sys.stdin)
    command = data.get("tool_input", {}).get("command", "")
    if "push" not in command:
        return
    hit = check(command, data.get("cwd") or os.getcwd())
    if hit and hit[0] != "allow":
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": hit[0],
            "permissionDecisionReason": hit[1],
        }}))


if __name__ == "__main__":
    main()
