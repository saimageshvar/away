#!/bin/bash
# away installer.
#
#   curl -fsSL https://raw.githubusercontent.com/saimageshvar/away/main/install.sh | bash
#
# Downloads the latest release into ~/.claude/away, then hands off to
# `away setup` for the wiring. Installing and wiring are deliberately separate:
# a download is safe to pipe from the internet, editing your Claude settings is
# not, so setup runs interactively in your own terminal.
#
# Env:
#   AWAY_REPO     owner/repo to install from   (default saimageshvar/away)
#   AWAY_VERSION  tag to install              (default: latest release)
#   AWAY_HOME     install directory           (default ~/.claude/away)
#   AWAY_BIN_DIR  where the CLI is linked     (default ~/.local/bin)
#   AWAY_NO_SETUP set to 1 to skip the setup handoff
#   AWAY_ARCHIVE  install from this tarball instead of downloading one. Any curl
#                 URL, file:// included -- which is how an airgapped machine and
#                 the installer's own test both get a payload.
set -euo pipefail

REPO="${AWAY_REPO:-saimageshvar/away}"
AWAY_HOME="${AWAY_HOME:-$HOME/.claude/away}"
BIN_DIR="${AWAY_BIN_DIR:-$HOME/.local/bin}"
VERSION="${AWAY_VERSION:-}"

if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; D=$'\033[2m'; O=$'\033[0m'
else B=""; G=""; Y=""; R=""; D=""; O=""; fi

die() { printf '%saway-install: %s%s\n' "$R" "$*" "$O" >&2; exit 1; }
say() { printf '%s\n' "$*"; }

command -v curl >/dev/null 2>&1 || die "curl is required."
command -v tar  >/dev/null 2>&1 || die "tar is required."

PY=""
for c in /opt/homebrew/bin/python3 /usr/bin/python3 python3; do
  if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
[ -n "$PY" ] || die "python3 is required (the guard is written in Python)."

case "$(uname -s)" in
  Darwin|Linux) ;;
  *) die "unsupported platform $(uname -s). away needs bash, python3 and Claude Code." ;;
esac

say "${B}away — autonomous mode for Claude Code${O}"
say ""

# ---------------------------------------------------------------- resolve
if [ -n "${AWAY_ARCHIVE:-}" ]; then
  ASSET="$AWAY_ARCHIVE"
  VERSION="${VERSION:-local}"
elif [ -z "$VERSION" ]; then
  say "Resolving the latest release of $REPO..."
  api="https://api.github.com/repos/$REPO/releases/latest"
  auth=()
  [ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ] && \
    auth=(-H "Authorization: Bearer ${GH_TOKEN:-$GITHUB_TOKEN}")
  body=$(curl -fsSL --max-time 20 "${auth[@]+"${auth[@]}"}" \
           -H 'Accept: application/vnd.github+json' "$api" 2>/dev/null) \
    || die "could not reach GitHub. Set AWAY_VERSION=vX.Y.Z to install a specific tag."
  VERSION=$(printf '%s' "$body" | "$PY" -c \
    'import json,sys; print(json.load(sys.stdin).get("tag_name") or "")')
  ASSET=$(printf '%s' "$body" | "$PY" -c '
import json, sys
data = json.load(sys.stdin)
for a in data.get("assets") or []:
    if (a.get("name") or "").endswith(".tar.gz"):
        print(a["browser_download_url"]); break
')
  [ -n "$VERSION" ] || die "no published release found for $REPO."
else
  ASSET=""
fi

say "Installing ${B}$VERSION${O} into $AWAY_HOME"
say ""

# ---------------------------------------------------------------- download
tmp=$(mktemp -d "${TMPDIR:-/tmp}/away-install.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

# An explicit AWAY_ARCHIVE is the only source: silently falling back to GitHub
# would install a different payload than the one that was asked for.
if [ -n "${AWAY_ARCHIVE:-}" ]; then
  candidates=("$AWAY_ARCHIVE")
else
  candidates=(${ASSET:-} "https://github.com/$REPO/archive/refs/tags/$VERSION.tar.gz")
fi

fetched=""
for url in "${candidates[@]}"; do
  [ -n "$url" ] || continue
  if curl -fsSL --max-time 120 -o "$tmp/away.tar.gz" "$url"; then fetched="$url"; break; fi
done
[ -n "$fetched" ] || die "could not download $VERSION from ${candidates[*]}"

mkdir -p "$tmp/unpacked"
tar -xzf "$tmp/away.tar.gz" -C "$tmp/unpacked"

# Release assets and GitHub's source archive both nest one directory deep, but a
# hand-rolled tarball may be flat. Check both rather than assuming either.
src="$tmp/unpacked"
if [ ! -f "$src/bin/away" ]; then
  for candidate in "$tmp/unpacked"/*; do
    if [ -f "$candidate/bin/away" ]; then src="$candidate"; break; fi
  done
fi
[ -f "$src/bin/away" ] || die "the archive does not look like an away release."

# ------------------------------------------------------------------ verify
# Prove the guard works BEFORE it is installed. PreToolUse fails closed, so a
# broken guard on disk blocks every tool call in every agent on this machine.
say "Verifying the guard..."
chmod +x "$src/bin/away" "$src/hooks/guard.sh" "$src/hooks/guard.py" 2>/dev/null || true
if ! out=$(AWAY_HOME="$src" bash "$src/bin/away" selftest 2>&1) || [ "$out" != "ok" ]; then
  printf '%s\n' "$out" >&2
  die "the downloaded guard failed its self-test. Nothing was installed."
fi
say "  ${G}ok${O}  guard self-test passed"

# ------------------------------------------------------------------- place
# state/ is history: the event log, the digests and the trash snapshots. An
# upgrade must never take it.
if [ -d "$AWAY_HOME" ]; then
  prev="$AWAY_HOME.away-previous"
  rm -rf "$prev"; mkdir -p "$prev"
  for item in "$AWAY_HOME"/*; do
    [ -e "$item" ] || continue
    case "$(basename "$item")" in state) continue ;; esac
    mv "$item" "$prev/"
  done
  say "  ${D}previous install moved to $prev${O}"
fi

mkdir -p "$AWAY_HOME"
for item in "$src"/* "$src"/.[!.]*; do
  [ -e "$item" ] || continue
  case "$(basename "$item")" in state|.git|.github) continue ;; esac
  cp -R "$item" "$AWAY_HOME/"
done
mkdir -p "$AWAY_HOME/state/trash"
chmod +x "$AWAY_HOME/bin/"* "$AWAY_HOME/hooks/"*.sh "$AWAY_HOME/hooks/"*.py 2>/dev/null || true

# For a tagged install the tag is truth: a source archive built from a branch can
# carry a stale VERSION file. A local archive keeps whatever it shipped with.
if [ -z "${AWAY_ARCHIVE:-}" ]; then
  printf '%s\n' "${VERSION#v}" > "$AWAY_HOME/VERSION"
fi

mkdir -p "$BIN_DIR"
ln -sf "$AWAY_HOME/bin/away" "$BIN_DIR/away"
say "  ${G}ok${O}  installed, and linked $BIN_DIR/away"
say ""

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    say "${Y}$BIN_DIR is not on your PATH.${O} Add this to your shell profile:"
    say "  ${B}export PATH=\"\$HOME/.local/bin:\$PATH\"${O}"
    say ""
    ;;
esac

# ------------------------------------------------------------------- setup
if [ "${AWAY_NO_SETUP:-}" = "1" ]; then
  say "Skipped setup. Finish with:  ${B}away setup${O}"
  exit 0
fi

# Piped from curl, stdin is the script itself, so setup cannot ask anything and
# would silently decline every permission fix. Tell the user to run it instead.
if [ ! -t 0 ]; then
  say "${B}One step left.${O} Run this in your terminal:"
  say ""
  say "  ${B}away setup${O}"
  say ""
  say "It registers the hooks, installs the ${B}/away${O} skill, and checks your"
  say "Claude permission settings for anything that would make away mode stall."
  say "${D}(Not run automatically: it edits ~/.claude/settings.json, and piped${O}"
  say "${D} stdin cannot answer the confirmation.)${O}"
  exit 0
fi

say "Running setup..."
say ""
exec bash "$AWAY_HOME/bin/away" setup
