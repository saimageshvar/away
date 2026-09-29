#!/bin/bash
# Run: bash tests/push_guard.sh
set -u
HOOK="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/hooks/push_guard.py"
REPO=$(mktemp -d); trap 'rm -rf "$REPO"' EXIT
git -C "$REPO" init -q -b master && git -C "$REPO" -c user.name=t -c user.email=t@t commit -q --allow-empty -m x
git -C "$REPO" branch feature/x
fail=0
t() {
    local got; got=$(jq -nc --arg c "$2" --arg cwd "$REPO" '{cwd:$cwd, tool_input:{command:$c}}' \
        | python3 "$HOOK" | jq -rs ".[0].hookSpecificOutput.permissionDecision // \"allow\"")
    if [ "$got" = "$1" ]; then printf 'ok   %-6s %s\n' "$1" "$2"
    else printf 'FAIL want %s got %s: %s\n' "$1" "$got" "$2"; fail=1; fi
}

# on master
t deny  "git push"
t deny  "git push -f origin"
t deny  "git push origin master"
t deny  "git push origin HEAD:main"
t deny  "git push origin +feature/x:develop"
t deny  "git push --force origin refs/heads/staging"
t deny  "git push origin --delete main"
t deny  "git push origin :main"
t deny  "git push --all origin"
t deny  "git push -o ci.skip origin master"
t deny  "git add . && git commit -m 'x' && git push -u origin master"
t deny  "git -C $REPO push"
t deny  "git --git-dir .git push origin master"
t deny  "/usr/bin/git push origin master"
t deny  "bash -c 'git push origin main'"
t deny  "bash -lc 'git push origin main'"
t deny  "eval \"git push origin master\""
t deny  "FOO=1 git push origin master"
t deny  "command git push origin master"
t deny  "env git push origin master"
t deny  "time git push origin master"
t deny  "nohup git push origin master"
t deny  "timeout 60 git push origin master"
t deny  "{ git push origin master; }"
t deny  "if true; then git push origin master; fi"
t deny  "! git push origin master"
t deny  "git push origin master>/dev/null 2>&1"
t deny  "git push origin feature/x master"
t deny  "git log -1 && git push origin master 2>&1 | tail -1"
t deny  $'bash <<\'EOF\'\ngit push origin master\nEOF'

# can't be read: ask, never allow
t ask   "echo master | xargs git push origin"
t ask   "\$(echo git) push origin master"
t ask   "g=git; \$g push origin master"
t ask   "git push origin \$BR"
t ask   "git push origin 'refs/heads/*:refs/heads/*'"
t ask   "git push origin master~0"
t ask   "git push origin @{u}"
t ask   "git -c push.default=matching push"
t ask   "git -c remote.origin.push=HEAD:refs/heads/master push"
t ask   "git subtree push --prefix lib origin master"
t ask   "sudo -u root git push origin master"
t ask   "cd \$DIR && git push"
t ask   "git push origin master; echo \$'it\\'s'"

# not a push, or not a protected one
t allow "git push origin feature/x"
t allow "git push -f origin feature/x"
t allow "git push --force-with-lease origin HEAD:feature/x"
t allow "git push origin v1.0"
t allow "git log --grep push"
t allow "echo \"git push origin master\""
t allow "git commit -m \"then git push origin master\""
t allow "FOO=1 git push origin feature/x > /tmp/log 2>&1"
t allow "echo exit=\$?; git push origin feature/x 2>&1 | tail -1"

git -C "$REPO" checkout -q feature/x
t allow "git push"
t allow "git push --force"
t allow "git push origin HEAD"
t ask   "git -C $REPO -c push.default=matching push"
git -C "$REPO" config push.default matching
t ask   "git push origin"
git -C "$REPO" config --unset push.default
exit $fail
