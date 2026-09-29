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
t deny  "git push"
t deny  "git push -f origin"
t deny  "git push origin master"
t deny  "git push origin HEAD:main"
t deny  "git push origin +feature/x:develop"
t deny  "git push --force origin refs/heads/staging"
t deny  "git push origin --delete main"
t deny  "git push --all origin"
t deny  "git add . && git commit -m 'x' && git push -u origin master"
t deny  "git -C $REPO push"
t deny  "bash -c 'git push origin main'"
t allow "git push origin feature/x"
t allow "git push -f origin feature/x"
t allow "git push --force-with-lease origin HEAD:feature/x"
t allow "git push origin v1.0"
t allow "git log --grep push"
git -C "$REPO" checkout -q feature/x
t allow "git push"
t allow "git push --force"
t deny  "git push origin feature/x master"
exit $fail
