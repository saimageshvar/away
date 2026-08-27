#!/bin/bash
# Exercise install.sh itself, against a tarball built from this checkout.
#
# The installer is the one path a checkout cannot test by running the code
# in place: it downloads, unpacks, verifies, and preserves an existing state/
# directory. Each of those has broken at least once.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/away-installer.XXXXXX")" && pwd -P)"
trap 'rm -rf "$WORK"' EXIT

PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "want $3, got $2"; fi; }

echo "away installer e2e  ($WORK)"
echo

# --- build a release tarball, shaped like the workflow's -----------------
STAGE="$WORK/stage/away-v9.9.9"
mkdir -p "$STAGE"
if command -v rsync >/dev/null 2>&1; then
  rsync -a --exclude '.git' --exclude '.github' --exclude 'state' \
        --exclude 'guard.py.good' "$REPO/" "$STAGE/"
else
  (cd "$REPO" && tar -cf - --exclude .git --exclude .github --exclude state \
     --exclude guard.py.good .) | (cd "$STAGE" && tar -xf -)
fi
printf '9.9.9\n' > "$STAGE/VERSION"
ARCHIVE="$WORK/away-v9.9.9.tar.gz"
tar -czf "$ARCHIVE" -C "$WORK/stage" away-v9.9.9
[ -s "$ARCHIVE" ] && ok "built the release tarball" || bad "built the release tarball"

# --- a clean machine ------------------------------------------------------
echo
echo "clean install:"
FAKE="$WORK/clean"
mkdir -p "$FAKE"
out=$(HOME="$FAKE" AWAY_TEST=1 AWAY_NO_UPDATE_CHECK=1 AWAY_NO_SETUP=1 \
        AWAY_ARCHIVE="file://$ARCHIVE" bash "$REPO/install.sh" 2>&1); rc=$?
check "installer exits 0" "$rc" "0"
case "$out" in *"self-test passed"*) ok "the guard was verified before install" ;;
  *) bad "the guard was verified before install" "$out" ;; esac
[ -f "$FAKE/.claude/away/bin/away" ] && ok "the payload landed" || bad "the payload landed"
[ -L "$FAKE/.local/bin/away" ] && ok "the CLI was linked" || bad "the CLI was linked"
check "VERSION came from the archive" \
  "$(cat "$FAKE/.claude/away/VERSION" 2>/dev/null | tr -d '[:space:]')" "9.9.9"
[ -d "$FAKE/.claude/away/state/trash" ] && ok "state was created" || bad "state was created"
# .github holds a release workflow that is meaningless once installed.
[ -d "$FAKE/.claude/away/.github" ] && bad "the workflow dir was excluded" \
  || ok "the workflow dir was excluded"

# --- setup on top of that install ---------------------------------------
echo
echo "setup after install:"
out=$(HOME="$FAKE" AWAY_TEST=1 AWAY_NO_UPDATE_CHECK=1 \
        bash "$FAKE/.claude/away/bin/away" setup --yes 2>&1); rc=$?
check "setup exits 0" "$rc" "0"
out=$(HOME="$FAKE" AWAY_TEST=1 AWAY_NO_UPDATE_CHECK=1 \
        bash "$FAKE/.claude/away/bin/away" doctor 2>&1); rc=$?
check "doctor exits 0" "$rc" "0"

# --- upgrade over an install with history --------------------------------
echo
echo "upgrade keeps history:"
printf '{"event":"from the last absence"}\n' > "$FAKE/.claude/away/state/events.jsonl"
printf 'x\n' > "$FAKE/.claude/away/state/trash/snapshot-1"
printf '1.0.0\n' > "$FAKE/.claude/away/VERSION"
out=$(HOME="$FAKE" AWAY_TEST=1 AWAY_NO_UPDATE_CHECK=1 AWAY_NO_SETUP=1 \
        AWAY_ARCHIVE="file://$ARCHIVE" bash "$REPO/install.sh" 2>&1); rc=$?
check "the upgrade exits 0" "$rc" "0"
check "the event log survived" \
  "$(cat "$FAKE/.claude/away/state/events.jsonl")" '{"event":"from the last absence"}'
[ -f "$FAKE/.claude/away/state/trash/snapshot-1" ] && ok "the trash survived" \
  || bad "the trash survived"
check "VERSION was replaced" \
  "$(cat "$FAKE/.claude/away/VERSION" | tr -d '[:space:]')" "9.9.9"
[ -d "$FAKE/.claude/away.away-previous" ] && ok "the previous install was kept" \
  || bad "the previous install was kept"

# --- a payload whose guard is broken never lands -------------------------
echo
echo "broken payload:"
BAD="$WORK/stage-bad/away-v9.9.9"
mkdir -p "$BAD"
(cd "$STAGE" && tar -cf - .) | (cd "$BAD" && tar -xf -)
printf 'import sys\nsys.exit(7)\n' > "$BAD/hooks/guard.py"
BADARC="$WORK/away-bad.tar.gz"
tar -czf "$BADARC" -C "$WORK/stage-bad" away-v9.9.9
FAKE2="$WORK/reject"
mkdir -p "$FAKE2"
out=$(HOME="$FAKE2" AWAY_TEST=1 AWAY_NO_SETUP=1 AWAY_ARCHIVE="file://$BADARC" \
        bash "$REPO/install.sh" 2>&1); rc=$?
check "the installer refuses it" "$([ $rc -ne 0 ] && echo yes || echo no)" "yes"
case "$out" in *"failed its self-test"*) ok "it says why" ;; *) bad "it says why" "$out" ;; esac
[ -d "$FAKE2/.claude/away" ] && bad "nothing was installed" || ok "nothing was installed"

# --- an archive that is not away at all ----------------------------------
echo
echo "wrong archive:"
JUNK="$WORK/junk.tar.gz"
mkdir -p "$WORK/junkdir/whatever" && printf 'hi\n' > "$WORK/junkdir/whatever/file"
tar -czf "$JUNK" -C "$WORK/junkdir" whatever
FAKE3="$WORK/junkhome"
mkdir -p "$FAKE3"
out=$(HOME="$FAKE3" AWAY_TEST=1 AWAY_NO_SETUP=1 AWAY_ARCHIVE="file://$JUNK" \
        bash "$REPO/install.sh" 2>&1); rc=$?
check "the installer refuses a non-away archive" \
  "$([ $rc -ne 0 ] && echo yes || echo no)" "yes"
[ -d "$FAKE3/.claude/away" ] && bad "nothing was installed" || ok "nothing was installed"

echo
if [ "$FAIL" -eq 0 ]; then
  echo "away installer e2e: $PASS passed."
  exit 0
fi
echo "away installer e2e: $FAIL failed, $PASS passed." >&2
exit 1
