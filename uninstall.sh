#!/bin/bash
# Remove away mode from Claude Code.
#
#   bash ~/.claude/away/uninstall.sh          unwire, keep the payload and history
#   bash ~/.claude/away/uninstall.sh --purge  also delete ~/.claude/away entirely
#
# Unwiring is the part that matters: it pulls the hooks out of settings.json so
# Claude Code stops calling a guard that may no longer be there. Your permission
# settings are never touched -- setup may have changed defaultMode for you, and
# only you know whether you want it back.
set -euo pipefail

AWAY_HOME="${AWAY_HOME:-$HOME/.claude/away}"
PURGE=0
for a in "$@"; do [ "$a" = "--purge" ] && PURGE=1; done

if [ -t 1 ]; then B=$'\033[1m'; Y=$'\033[33m'; O=$'\033[0m'; else B=""; Y=""; O=""; fi

if [ ! -f "$AWAY_HOME/bin/away" ]; then
  echo "away: nothing installed at $AWAY_HOME" >&2
  exit 1
fi

bash "$AWAY_HOME/bin/away" uninstall

if [ "$PURGE" = "1" ]; then
  echo
  echo "${Y}--purge: this deletes the event log and every trash snapshot.${O}"
  if [ -t 0 ]; then
    read -r -p "Delete $AWAY_HOME? [y/N] " answer
    case "$answer" in y|Y|yes|YES) ;; *) echo "Kept."; exit 0 ;; esac
  fi
  rm -rf "$AWAY_HOME"
  echo "Removed $AWAY_HOME."
fi

echo
echo "${B}Restart any running Claude Code sessions${O} so they stop calling the hooks."
