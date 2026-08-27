#!/usr/bin/env python3
"""Tests for the self-update path.

This is the riskiest code in the project: it replaces the guard that every tool
call in every agent depends on. The cases that matter are the refusals -- a
broken payload, a hostile archive, an absence in progress -- because each of
those, if it got through, blocks the whole machine or loses the user's history.

Run: python3 tests/update_cases.py
"""

import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "bin"))

PASS, FAIL = [], []


def check(name, got, want):
    if got == want:
        PASS.append(name)
        print("  ok   %s" % name)
    else:
        FAIL.append(name)
        print("  FAIL %s\n       want %r, got %r" % (name, want, got))


def truthy(name, cond, detail=""):
    check(name, bool(cond), True)
    if not cond and detail:
        print("       %s" % detail)


def fresh_home(tmp, version="1.0.0"):
    """A realistic installed tree: code, a VERSION, and state worth keeping."""
    home = tmp / "home"
    shutil.copytree(REPO, home, ignore=shutil.ignore_patterns(
        ".git", ".github", "state", "guard.py.good"))
    (home / "VERSION").write_text(version + "\n")
    state = home / "state"
    state.mkdir(exist_ok=True)
    (state / "events.jsonl").write_text('{"event":"precious"}\n')
    (state / "trash").mkdir(exist_ok=True)
    (state / "trash" / "keepme").write_text("snapshot")
    (home / "hooks" / "guard.py.good").write_text("# blessed locally\n")
    return home


def make_archive(tmp, name, version="2.0.0", break_guard=False, incomplete=False):
    """A release tarball, nested one directory deep like a real one."""
    staging = tmp / ("stage-" + name)
    top = staging / ("away-v" + version)
    shutil.copytree(REPO, top, ignore=shutil.ignore_patterns(
        ".git", ".github", "state", "guard.py.good"))
    (top / "VERSION").write_text(version + "\n")
    if break_guard:
        (top / "hooks" / "guard.py").write_text("import sys\nsys.exit(9)\n")
    if incomplete:
        (top / "rules.md").unlink()
    archive = tmp / (name + ".tar.gz")
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(top, arcname=top.name)
    return archive


def run_update(home, archive, extra=(), env_extra=None):
    env = dict(os.environ, AWAY_HOME=str(home), AWAY_TEST="1",
               AWAY_NO_UPDATE_CHECK="1", AWAY_ARCHIVE=str(archive),
               HOME=str(home.parent / "fakehome"))
    (home.parent / "fakehome").mkdir(exist_ok=True)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, str(home / "bin" / "update.py"), "apply", *extra],
        capture_output=True, text=True, timeout=180, env=env)


# ------------------------------------------------------------ pure logic

def test_version_compare():
    import update
    check("1.0.1 is newer than 1.0.0", update.newer("1.0.1", "1.0.0"), True)
    check("v1.2.0 is newer than 1.1.9", update.newer("v1.2.0", "1.1.9"), True)
    check("1.10.0 is newer than 1.9.0", update.newer("1.10.0", "1.9.0"), True)
    check("equal is not newer", update.newer("1.0.0", "1.0.0"), False)
    check("older is not newer", update.newer("0.9.0", "1.0.0"), False)
    check("2.0 beats 1.9.9", update.newer("2.0", "1.9.9"), True)
    # A garbled tag must never look like an upgrade: that would swap the guard
    # for whatever a malformed release name pointed at.
    check("unparseable is not newer", update.newer("banana", "1.0.0"), False)
    check("empty is not newer", update.newer("", "1.0.0"), False)


def test_cache_ttl(tmp):
    import importlib
    home = tmp / "ttl"
    (home / "state").mkdir(parents=True)
    os.environ["AWAY_HOME"] = str(home)
    import update
    importlib.reload(update)

    update.write_cache({"latest": "v9.9.9", "checked_epoch": time.time()})
    tag, _asset, cached = update.resolve_latest()
    check("a fresh cache is used without network", (tag, cached), ("v9.9.9", True))

    update.write_cache({"latest": "v9.9.9",
                        "checked_epoch": time.time() - update.CACHE_TTL - 1})
    stale = json.loads((home / "state" / "update-check.json").read_text())
    truthy("the TTL boundary is one day", update.CACHE_TTL == 86400)
    truthy("a stale cache is recognised",
           time.time() - stale["checked_epoch"] > update.CACHE_TTL)

    del os.environ["AWAY_HOME"]
    importlib.reload(update)


def test_unsafe_archive(tmp):
    """A tarball that escapes its own directory is refused, not extracted."""
    import update
    evil = tmp / "evil.tar.gz"
    payload = tmp / "payload.txt"
    payload.write_text("pwned")
    with tarfile.open(evil, "w:gz") as tf:
        tf.add(payload, arcname="../../escaped.txt")
    into = tmp / "extract-evil"
    into.mkdir()
    try:
        update.extract_payload(evil, into)
        check("a path-escaping archive is refused", "extracted", "refused")
    except RuntimeError as exc:
        check("a path-escaping archive is refused",
              "refusing unsafe path" in str(exc), True)
    truthy("nothing escaped to disk", not (tmp.parent / "escaped.txt").exists())


# --------------------------------------------------------------- apply

def test_good_update(tmp):
    home = fresh_home(tmp / "good")
    archive = make_archive(tmp / "good", "rel", version="2.0.0")
    proc = run_update(home, archive)
    check("a good update exits 0", proc.returncode, 0)
    check("VERSION was bumped", (home / "VERSION").read_text().strip(), "2.0.0")
    check("the event log survived",
          (home / "state" / "events.jsonl").read_text(), '{"event":"precious"}\n')
    truthy("the trash survived", (home / "state" / "trash" / "keepme").exists())
    truthy("the local fallback guard was carried over",
           (home / "hooks" / "guard.py.good").exists())
    truthy("the previous install was kept",
           (home.parent / (home.name + ".away-previous") / "VERSION").exists())


def test_broken_payload_refused(tmp):
    """The whole point: a guard that fails its selftest never reaches disk."""
    home = fresh_home(tmp / "broken")
    before = (home / "hooks" / "guard.py").read_bytes()
    archive = make_archive(tmp / "broken", "rel", version="2.0.0", break_guard=True)
    proc = run_update(home, archive)
    check("a failing guard aborts the update", proc.returncode, 1)
    check("the message names the selftest",
          "failed its selftest" in (proc.stdout + proc.stderr), True)
    check("the installed guard is unchanged",
          (home / "hooks" / "guard.py").read_bytes(), before)
    check("VERSION is unchanged", (home / "VERSION").read_text().strip(), "1.0.0")


def test_incomplete_payload_refused(tmp):
    home = fresh_home(tmp / "incomplete")
    archive = make_archive(tmp / "incomplete", "rel", version="2.0.0", incomplete=True)
    proc = run_update(home, archive)
    check("an incomplete release aborts the update", proc.returncode, 1)
    check("the message names the missing file",
          "missing rules.md" in (proc.stdout + proc.stderr), True)
    check("VERSION is unchanged", (home / "VERSION").read_text().strip(), "1.0.0")


def test_refuses_while_armed(tmp):
    """Swapping the guard mid-absence is the worst possible moment for it."""
    home = fresh_home(tmp / "armed")
    (home / "state" / "active.json").write_text('{"on":true,"since_epoch":1}')
    archive = make_archive(tmp / "armed", "rel", version="2.0.0")
    proc = run_update(home, archive)
    check("an armed absence blocks the update", proc.returncode, 1)
    check("the message says how to proceed",
          "away off" in (proc.stdout + proc.stderr), True)
    check("VERSION is unchanged", (home / "VERSION").read_text().strip(), "1.0.0")

    proc = run_update(home, archive, extra=["--force"])
    check("--force overrides it", proc.returncode, 0)
    check("VERSION was bumped under --force",
          (home / "VERSION").read_text().strip(), "2.0.0")


def test_session_flag_also_blocks(tmp):
    home = fresh_home(tmp / "session")
    sessions = home / "state" / "sessions"
    sessions.mkdir(parents=True)
    (sessions / "abc123.json").write_text('{"on":true,"since_epoch":1}')
    archive = make_archive(tmp / "session", "rel", version="2.0.0")
    proc = run_update(home, archive)
    check("a session-scoped absence also blocks", proc.returncode, 1)


def test_notify_is_silent_when_piped(tmp):
    """An agent's shell is not a terminal, and must never see a prompt."""
    home = fresh_home(tmp / "notify")
    (home / "state").mkdir(exist_ok=True)
    (home / "state" / "update-check.json").write_text(json.dumps(
        {"latest": "v9.9.9", "checked_epoch": time.time()}))
    proc = subprocess.run(
        [sys.executable, str(home / "bin" / "update.py"), "notify"],
        capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL,
        env=dict(os.environ, AWAY_HOME=str(home), AWAY_TEST="1"))
    check("notify says nothing on a pipe", proc.stdout.strip(), "")
    check("notify exits 0 on a pipe", proc.returncode, 0)

    proc = subprocess.run(
        [sys.executable, str(home / "bin" / "update.py"), "check"],
        capture_output=True, text=True, timeout=30,
        env=dict(os.environ, AWAY_HOME=str(home), AWAY_TEST="1",
                 AWAY_REPO="example/nonexistent-repo-away"))
    check("check still reports the cached version",
          "9.9.9" in proc.stdout, True)


def main():
    print("away update cases")
    print()
    with tempfile.TemporaryDirectory(prefix="away-update-test-") as raw:
        tmp = Path(raw)
        for sub in ("good", "broken", "incomplete", "armed", "session", "notify"):
            (tmp / sub).mkdir()
        print("version comparison:")
        test_version_compare()
        print("\ncache:")
        test_cache_ttl(tmp)
        print("\narchive safety:")
        test_unsafe_archive(tmp)
        print("\na good update:")
        test_good_update(tmp)
        print("\nrefusals:")
        test_broken_payload_refused(tmp)
        test_incomplete_payload_refused(tmp)
        test_refuses_while_armed(tmp)
        test_session_flag_also_blocks(tmp)
        print("\nnotify:")
        test_notify_is_silent_when_piped(tmp)

    print()
    if FAIL:
        print("away update cases: %d failed, %d passed." % (len(FAIL), len(PASS)),
              file=sys.stderr)
        return 1
    print("away update cases: %d passed." % len(PASS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
