#!/bin/bash
# Every suite, in the order that fails fastest.
#
# AWAY_TEST=1 is set for all of them. The event log is global: an untagged
# synthetic event makes an unrelated session escalate a false security incident.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export AWAY_TEST=1
export AWAY_NO_UPDATE_CHECK=1

fail=0
run() {
  printf '\n\033[1m== %s\033[0m\n' "$1"; shift
  if "$@"; then return 0; fi
  fail=1
}

run "syntax" bash -n "$REPO/install.sh" "$REPO/uninstall.sh" "$REPO/bin/away" \
    "$REPO/hooks/guard.sh"
run "python syntax" python3 -m py_compile "$REPO/bin/setup.py" "$REPO/bin/update.py" \
    "$REPO/bin/report.py" "$REPO/hooks/guard.py"
run "guard self-test" env AWAY_HOME="$REPO" bash "$REPO/bin/away" selftest
run "policy cases" env AWAY_HOME="$REPO" python3 "$REPO/tests/policy_cases.py"
run "audit cases" python3 "$REPO/tests/audit_cases.py"
run "update cases" python3 "$REPO/tests/update_cases.py"
run "install e2e" bash "$REPO/tests/install_e2e.sh"
run "installer e2e" bash "$REPO/tests/installer_e2e.sh"

echo
if [ "$fail" -eq 0 ]; then
  echo "all suites passed."
else
  echo "one or more suites failed." >&2
fi
exit "$fail"
