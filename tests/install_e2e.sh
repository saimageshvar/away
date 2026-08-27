#!/bin/bash
# End-to-end install test against a throwaway HOME.
#
# This is the path a new colleague takes, and it is the one that broke every time
# the install was done by hand: settings.json already has hooks in it, the
# permission list already conflicts, and a stale absolute path survives a move.
#
# Nothing here touches the real ~/.claude. Run it from the repo root.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# cd through it: $TMPDIR often ends in a slash, and the doubled separator that
# survives in $HOME makes every path assertion below differ from Python's
# normalized form for no real reason.
FAKE="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/away-e2e.XXXXXX")" && pwd -P)"
trap 'rm -rf "$FAKE"' EXIT

export HOME="$FAKE"
export AWAY_TEST=1            # never let a test event read as a real incident
export AWAY_NO_UPDATE_CHECK=1 # no network in a test
unset AWAY_HOME AWAY_BIN_DIR CLAUDE_CONFIG_DIR

HOME_AWAY="$FAKE/.claude/away"
SETTINGS="$FAKE/.claude/settings.json"
PASS=0 FAIL=0

ok()   { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "want $3, got $2"; fi; }

# settings.json probe. Prints a python expression over the parsed document.
q() { python3 -c "
import json,sys
d=json.load(open('$SETTINGS'))
def hooks(ev):
    return [e for g in (d.get('hooks') or {}).get(ev) or [] for e in g.get('hooks') or []]
def mine(ev,arg):
    # Same identity rule as setup.py: the path suffix, not the directory name,
    # because AWAY_HOME is configurable.
    return [e for e in hooks(ev) if '/hooks/guard.sh' in (e.get('command') or '')
            and (e.get('command') or '').rsplit(None,1)[-1]==arg]
print($1)
" 2>/dev/null || echo "ERR"; }

echo "away install e2e  (HOME=$FAKE)"
echo

# --- a machine that is already in use, not a blank one -------------------
mkdir -p "$FAKE/.claude" "$FAKE/.local/bin"
cat > "$SETTINGS" <<'EOF'
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "AskUserQuestion",
        "hooks": [ { "type": "command", "command": "bash /somewhere/unrelated.sh" } ] }
    ]
  },
  "permissions": {
    "defaultMode": "default",
    "allow": ["Bash(git status:*)"],
    "ask": ["Bash(rm:*)", "Bash(sudo:*)"],
    "deny": ["Bash(curl:*)"]
  }
}
EOF

cp -R "$REPO" "$HOME_AWAY"
rm -rf "$HOME_AWAY/.git" "$HOME_AWAY/state"
chmod +x "$HOME_AWAY/bin/"* "$HOME_AWAY/hooks/"*.sh "$HOME_AWAY/hooks/"*.py

AWAY="bash $HOME_AWAY/bin/away"

# --- setup ---------------------------------------------------------------
echo "setup:"
out=$($AWAY setup --yes 2>&1); rc=$?
check "setup exits 0" "$rc" "0"

for pair in "PreToolUse pretooluse" "PermissionRequest permissionrequest" \
            "Stop stop" "UserPromptSubmit userpromptsubmit"; do
  set -- $pair
  check "hook $1 registered once" "$(q "len(mine('$1','$2'))")" "1"
done

check "hook path points at this home" \
  "$(q "mine('PreToolUse','pretooluse')[0]['command']")" \
  "bash '$HOME_AWAY/hooks/guard.sh' pretooluse"

check "the unrelated PreToolUse hook survived" \
  "$(q "sum(1 for e in hooks('PreToolUse') if 'unrelated' in (e.get('command') or ''))")" "1"

check "defaultMode was fixed" "$(q "d['permissions']['defaultMode']")" "auto"
check "the delete ask rule was removed" \
  "$(q "'Bash(rm:*)' in d['permissions']['ask']")" "False"
check "an unrelated ask rule was kept" \
  "$(q "'Bash(sudo:*)' in d['permissions']['ask']")" "True"
check "allow list untouched" "$(q "d['permissions']['allow']")" "['Bash(git status:*)']"
check "deny list untouched" "$(q "d['permissions']['deny']")" "['Bash(curl:*)']"

[ -f "$SETTINGS.away-backup" ] && ok "settings.json was backed up" \
  || bad "settings.json was backed up"
[ -f "$FAKE/.claude/skills/away/SKILL.md" ] && ok "the /away skill was installed" \
  || bad "the /away skill was installed"
[ -L "$FAKE/.local/bin/away" ] && ok "the CLI was linked" || bad "the CLI was linked"
[ -f "$HOME_AWAY/hooks/guard.py.good" ] && ok "the fallback guard was blessed" \
  || bad "the fallback guard was blessed"

# --- doctor --------------------------------------------------------------
echo
echo "doctor:"
out=$($AWAY doctor 2>&1); rc=$?
check "doctor exits 0 on a good install" "$rc" "0"
case "$out" in *FAIL*) bad "doctor reports no FAIL" "$out" ;; *) ok "doctor reports no FAIL" ;; esac

# --- idempotence ---------------------------------------------------------
echo
echo "idempotence:"
$AWAY setup --yes >/dev/null 2>&1
check "a second setup does not duplicate the hook" \
  "$(q "len(mine('PreToolUse','pretooluse'))")" "1"
check "a second setup leaves defaultMode alone" \
  "$(q "d['permissions']['defaultMode']")" "auto"

# --- the failure that looks like success ---------------------------------
# A hook registered but pointing at an old path: the guard is fine, the CLI is
# fine, and nothing enforces anything.
echo
echo "stale hook path:"
python3 - <<PY
import json
p = "$SETTINGS"
d = json.load(open(p))
for g in d["hooks"]["PreToolUse"]:
    for e in g.get("hooks") or []:
        if "away/hooks/guard.sh" in (e.get("command") or ""):
            e["command"] = "bash '/old/place/away/hooks/guard.sh' pretooluse"
json.dump(d, open(p, "w"), indent=2)
PY
out=$($AWAY doctor 2>&1); rc=$?
check "doctor exits non-zero on a stale hook path" "$([ $rc -ne 0 ] && echo yes || echo no)" "yes"
case "$out" in *"points somewhere else"*) ok "doctor names the stale path" ;;
  *) bad "doctor names the stale path" "$out" ;; esac
$AWAY setup --yes >/dev/null 2>&1
check "setup repairs it" \
  "$(q "mine('PreToolUse','pretooluse')[0]['command']")" \
  "bash '$HOME_AWAY/hooks/guard.sh' pretooluse"

# --- a conflicting permission mode is caught, not ignored ----------------
echo
echo "permission drift:"
python3 -c "
import json
p='$SETTINGS'; d=json.load(open(p))
d['permissions']['defaultMode']='default'
d['permissions']['ask'].append('Bash(*)')
json.dump(d, open(p,'w'), indent=2)"
out=$($AWAY doctor 2>&1); rc=$?
check "doctor exits non-zero on drift" "$([ $rc -ne 0 ] && echo yes || echo no)" "yes"
case "$out" in *"defaultMode"*) ok "doctor names defaultMode" ;;
  *) bad "doctor names defaultMode" "$out" ;; esac
case "$out" in *"every Bash command"*) ok "doctor names the broad ask rule" ;;
  *) bad "doctor names the broad ask rule" "$out" ;; esac

# --- arming refuses to run on a broken guard -----------------------------
echo
echo "broken guard:"
$AWAY setup --yes >/dev/null 2>&1
cp "$HOME_AWAY/hooks/guard.py" "$FAKE/guard.py.orig"
printf 'import sys\nsys.exit(3)\n' > "$HOME_AWAY/hooks/guard.py"
out=$($AWAY on "should refuse" 2>&1); rc=$?
check "away on refuses a broken guard" "$([ $rc -ne 0 ] && echo yes || echo no)" "yes"
[ -f "$HOME_AWAY/state/active.json" ] && bad "no flag was written" || ok "no flag was written"
out=$($AWAY doctor 2>&1); rc=$?
check "doctor exits non-zero on a broken guard" "$([ $rc -ne 0 ] && echo yes || echo no)" "yes"
cp "$FAKE/guard.py.orig" "$HOME_AWAY/hooks/guard.py"

# --- lifecycle -----------------------------------------------------------
echo
echo "lifecycle:"
$AWAY on "e2e" >/dev/null 2>&1
[ -f "$HOME_AWAY/state/active.json" ] && ok "away on writes the flag" || bad "away on writes the flag"
case "$($AWAY status 2>&1)" in *"on globally"*) ok "status reports on" ;;
  *) bad "status reports on" "$($AWAY status 2>&1)" ;; esac
out=$($AWAY uninstall 2>&1); rc=$?
check "uninstall refuses while armed" "$([ $rc -ne 0 ] && echo yes || echo no)" "yes"
$AWAY off >/dev/null 2>&1
[ -f "$HOME_AWAY/state/active.json" ] && bad "away off clears the flag" || ok "away off clears the flag"

# --- a custom AWAY_HOME ---------------------------------------------------
# Hook identity once matched the literal directory name "away", so an install
# anywhere else registered a second copy on every setup instead of being found.
echo
echo "custom AWAY_HOME:"
CUSTOM="$FAKE/tools/claude-autonomy"
mkdir -p "$(dirname "$CUSTOM")"
cp -R "$HOME_AWAY" "$CUSTOM"
rm -rf "$CUSTOM/state"
AWAY_HOME="$CUSTOM" bash "$CUSTOM/bin/away" setup --yes >/dev/null 2>&1
check "the custom home registered its hook" \
  "$(q "sum(1 for e in hooks('PreToolUse') if '$CUSTOM' in (e.get('command') or ''))")" "1"
AWAY_HOME="$CUSTOM" bash "$CUSTOM/bin/away" setup --yes >/dev/null 2>&1
check "a second setup did not duplicate it" \
  "$(q "len(mine('PreToolUse','pretooluse'))")" "1"
out=$(AWAY_HOME="$CUSTOM" bash "$CUSTOM/bin/away" doctor 2>&1); rc=$?
check "doctor is clean for the custom home" "$rc" "0"
# Put the canonical home back in charge for the uninstall checks below.
$AWAY setup --yes >/dev/null 2>&1

# --- uninstall -----------------------------------------------------------
echo
echo "uninstall:"
$AWAY uninstall >/dev/null 2>&1
check "hooks were unregistered" "$(q "len(mine('PreToolUse','pretooluse'))")" "0"
check "the unrelated hook still survives" \
  "$(q "sum(1 for e in hooks('PreToolUse') if 'unrelated' in (e.get('command') or ''))")" "1"
check "permissions were NOT reverted" "$(q "d['permissions']['defaultMode']")" "auto"
[ -f "$FAKE/.claude/skills/away/SKILL.md" ] && bad "the skill was removed" \
  || ok "the skill was removed"
[ -d "$HOME_AWAY/state" ] && ok "state was kept" || bad "state was kept"

echo
if [ "$FAIL" -eq 0 ]; then
  echo "away e2e: $PASS passed."
  exit 0
fi
echo "away e2e: $FAIL failed, $PASS passed." >&2
exit 1
