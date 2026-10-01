#!/usr/bin/env python3
"""What the permission rules will refuse, so an away agent can plan around it.

    perms.py            every ask and deny rule, by source
    perms.py --brief    the same, one line each, for the injected rules
    perms.py <command>  a best-effort verdict per segment

Never says "allowed": a command no rule matches still goes to auto mode's
classifier, and Claude Code's own matcher has the final word.
"""

import json
import os
import re
import shlex
import sys
from pathlib import Path

CLAUDE = Path(os.environ.get("CLAUDE_CONFIG_DIR") or (Path.home() / ".claude"))
MANAGED = os.environ.get("AWAY_PERMS_MANAGED")
MANAGED = [Path(p) for p in MANAGED.split(":") if p] if MANAGED is not None else [
    CLAUDE / "remote-settings.json",
    Path("/Library/Application Support/ClaudeCode/managed-settings.json"),
    Path("/etc/claude-code/managed-settings.json"),
]
SEPARATORS = {"&&", "||", ";", "|", "&", ";;"}
BRIEF_CAP = 60


def sources():
    project = Path.cwd() / ".claude"
    return ([("managed", p) for p in MANAGED] +
            [("user", CLAUDE / "settings.json"), ("user", CLAUDE / "settings.local.json"),
             ("project", project / "settings.json"),
             ("project", project / "settings.local.json")])


def rules():
    found, seen = [], set()
    for label, path in sources():
        try:
            perms = json.loads(path.read_text(encoding="utf-8")).get("permissions") or {}
        except Exception:
            continue
        for kind in ("deny", "ask"):
            for rule in perms.get(kind) or []:
                if isinstance(rule, str) and (kind, rule, label) not in seen:
                    seen.add((kind, rule, label))
                    found.append((kind, rule, "%s (%s)" % (label, path)))
    return found


def bash_pattern(rule):
    m = re.fullmatch(r"Bash\((.*)\)", rule.strip(), re.S)
    if not m:
        return None
    arg = m.group(1).strip()
    if arg.endswith(":*"):
        arg = arg[:-2] + "*"
    return re.compile("^" + ".*".join(re.escape(part) for part in arg.split("*")) + "$",
                      re.S)


def segments(cmd):
    out = []
    for line in re.split(r"[\n\r]+", cmd):
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
            lexer.whitespace_split = True
            toks = list(lexer)
        except ValueError:
            toks = line.split()
        current = []
        for tok in toks + [";"]:
            if tok in SEPARATORS:
                if current:
                    out.append(" ".join(current))
                current = []
            else:
                current.append(tok)
    return out


def verdict(text, all_rules):
    for wanted in ("deny", "ask"):
        for kind, rule, source in all_rules:
            pattern = bash_pattern(rule) if kind == wanted else None
            if pattern and pattern.match(text):
                if kind == "deny":
                    return "denied by %s — %s" % (rule, source)
                return "asks, so denied while away: %s — %s" % (rule, source)
    return "no rule matched — auto mode's classifier decides"


def main(argv):
    all_rules = rules()
    if argv and argv[0] == "--brief":
        lines = sorted({"%-4s %s" % (k, r) for k, r, _s in all_rules})
        print("\n".join(lines[:BRIEF_CAP]))
        if len(lines) > BRIEF_CAP:
            print("... %d more: run `away perms`" % (len(lines) - BRIEF_CAP))
        return 0
    if argv:
        cmd = " ".join(argv)
        checks = [cmd] + [s for s in segments(cmd) if s != cmd]
        for text in checks:
            print("%s\n  %s" % (text, verdict(text, all_rules)))
        print("best effort: the harness has the final word.")
        return 0
    if not all_rules:
        print("No ask or deny rules found. Auto mode's classifier decides everything.")
        return 0
    current = None
    for kind, rule, source in all_rules:
        if source != current:
            print("\n%s" % source)
            current = source
        print("  %-4s %s   denied while away" % (kind, rule))
    print("\nA command no rule matches goes to auto mode's classifier. "
          "Check one with `away perms \"<command>\"`.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
