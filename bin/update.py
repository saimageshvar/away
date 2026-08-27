#!/usr/bin/env python3
"""Release check and self-update for away mode.

    update.py notify        refresh the cached latest version, offer to update
    update.py check         print the cached/refreshed comparison, no prompt
    update.py apply [tag]   download, verify, and swap the payload in

`notify` runs ahead of every away command, so it is built to be invisible: it
never blocks longer than NET_TIMEOUT, never prompts anything that is not an
interactive terminal, and never speaks while an absence is in progress.
"""

import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

AWAY = Path(os.environ.get("AWAY_HOME") or (Path.home() / ".claude" / "away"))
STATE = AWAY / "state"
CACHE = STATE / "update-check.json"
REPO = os.environ.get("AWAY_REPO", "saimageshvar/away")

CACHE_TTL = 86400  # one day, per the design: a release check is not urgent
NET_TIMEOUT = 3    # `away on` must never hang on a network stall

YEL, GRN, DIM, OFF = "\033[33m", "\033[32m", "\033[2m", "\033[0m"
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    YEL = GRN = DIM = OFF = ""


def installed_version():
    vf = AWAY / "VERSION"
    try:
        return vf.read_text().strip()
    except OSError:
        return "0.0.0"


def norm(v):
    return (v or "").strip().lstrip("vV")


def newer(latest, current):
    """Compare dotted numeric versions; unparseable means 'not newer'."""
    def parts(v):
        out = []
        for chunk in norm(v).split("."):
            digits = "".join(c for c in chunk if c.isdigit())
            out.append(int(digits) if digits else 0)
        return out
    try:
        a, b = parts(latest), parts(current)
    except (TypeError, ValueError):
        return False
    a += [0] * (len(b) - len(a))
    b += [0] * (len(a) - len(b))
    return a > b


def away_is_on():
    """Global flag, or any session flag. Mirrors the guard's own resolution."""
    if (STATE / "active.json").exists():
        return True
    sessions = STATE / "sessions"
    return sessions.is_dir() and any(sessions.glob("*.json"))


def read_cache():
    try:
        return json.loads(CACHE.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def write_cache(data):
    try:
        STATE.mkdir(parents=True, exist_ok=True)
        CACHE.write_text(json.dumps(data, indent=2))
    except OSError:
        pass  # a cache we cannot write is a slower check, never an error


def fetch_latest():
    """Latest release tag, or None. Never raises: this is a background nicety."""
    url = "https://api.github.com/repos/%s/releases/latest" % REPO
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "away-cli",
    })
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", "Bearer %s" % token)
    try:
        with urllib.request.urlopen(req, timeout=NET_TIMEOUT) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError):
        return None
    tag = body.get("tag_name")
    assets = [a.get("browser_download_url") for a in body.get("assets") or []
              if (a.get("name") or "").endswith(".tar.gz")]
    return {"latest": tag, "asset": assets[0] if assets else None} if tag else None


def resolve_latest(force=False):
    """Cached tag if fresh, else refresh. Returns (tag, asset_url, from_cache)."""
    cache = read_cache()
    age = time.time() - float(cache.get("checked_epoch") or 0)
    if not force and cache.get("latest") and age < CACHE_TTL:
        return cache["latest"], cache.get("asset"), True
    fresh = fetch_latest()
    if not fresh:
        # Record the attempt so a network outage does not retry on every command.
        cache["checked_epoch"] = time.time()
        write_cache(cache)
        return cache.get("latest"), cache.get("asset"), True
    fresh["checked_epoch"] = time.time()
    write_cache(fresh)
    return fresh["latest"], fresh.get("asset"), False


def download(tag, asset_url, dest):
    """Prefer the release asset; fall back to GitHub's source archive.

    AWAY_ARCHIVE overrides both, and is the ONLY source when set -- an airgapped
    update must not silently reach GitHub instead.
    """
    override = os.environ.get("AWAY_ARCHIVE")
    if override:
        urls = [override if "://" in override else Path(override).resolve().as_uri()]
    else:
        urls = [u for u in (asset_url,
                            "https://github.com/%s/archive/refs/tags/%s.tar.gz"
                            % (REPO, tag)) if u]
    last = None
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "away-cli"})
            with urllib.request.urlopen(req, timeout=60) as resp, \
                    open(dest, "wb") as fh:
                shutil.copyfileobj(resp, fh)
            return url
        except (urllib.error.URLError, OSError) as exc:
            last = exc
    raise RuntimeError("could not download %s: %s" % (tag, last))


def extract_payload(archive, into):
    """Unpack and return the directory holding bin/ and hooks/."""
    with tarfile.open(archive) as tf:
        # Refuse absolute or parent-escaping members rather than trusting a tarball.
        for member in tf.getmembers():
            name = Path(member.name)
            if name.is_absolute() or ".." in name.parts:
                raise RuntimeError("refusing unsafe path in archive: %s" % member.name)
        tf.extractall(into)
    if (into / "bin" / "away").exists():
        return into
    for child in sorted(into.iterdir()):
        if child.is_dir() and (child / "bin" / "away").exists():
            return child
    raise RuntimeError("archive has no bin/away -- not an away release")


def verify(tree):
    """A new guard must pass its own selftest BEFORE it can serve a session.

    PreToolUse fails closed, so shipping a broken guard would block every tool
    call in every agent on this machine.
    """
    for rel in ("bin/away", "bin/setup.py", "hooks/guard.sh", "hooks/guard.py",
                "rules.md", "VERSION"):
        if not (tree / rel).exists():
            raise RuntimeError("incomplete release: missing %s" % rel)
    for rel in ("bin/away", "hooks/guard.sh", "hooks/guard.py"):
        (tree / rel).chmod(0o755)
    proc = subprocess.run(["bash", str(tree / "bin" / "away"), "selftest"],
                          capture_output=True, text=True, timeout=120,
                          env=dict(os.environ, AWAY_HOME=str(tree)))
    if proc.returncode != 0 or "ok" not in proc.stdout:
        raise RuntimeError("the downloaded guard failed its selftest:\n%s%s"
                           % (proc.stdout, proc.stderr))


def swap(tree):
    """Replace code, keep state. The event log and trash are the user's history."""
    keep = {"state"}
    backup = AWAY.parent / (AWAY.name + ".away-previous")
    if backup.exists():
        shutil.rmtree(backup, ignore_errors=True)
    backup.mkdir(parents=True)
    for item in AWAY.iterdir():
        if item.name in keep:
            continue
        shutil.move(str(item), str(backup / item.name))
    for item in tree.iterdir():
        if item.name in keep:
            continue
        shutil.move(str(item), str(AWAY / item.name))
    # guard.py.good is blessed per machine by the selftest, never shipped.
    old_good = backup / "hooks" / "guard.py.good"
    if old_good.exists():
        shutil.copy2(old_good, AWAY / "hooks" / "guard.py.good")
    return backup


def cmd_apply(argv):
    force_tag = argv[0] if argv and not argv[0].startswith("-") else None
    if away_is_on() and "--force" not in argv:
        print("away: an absence is in progress, so the guard will not be replaced.",
              file=sys.stderr)
        print("      Run `away off` first, or `away update --force` if you are sure.",
              file=sys.stderr)
        return 1

    if os.environ.get("AWAY_ARCHIVE"):
        # The archive IS the payload, so there is nothing to resolve and no
        # reason to touch the network.
        tag, asset = force_tag or "local", None
    elif force_tag:
        tag, asset = force_tag, None
    else:
        tag, asset, _cached = resolve_latest(force=True)
    if not tag:
        print("away: could not reach GitHub to find the latest release.",
              file=sys.stderr)
        return 1
    current = installed_version()
    explicit = bool(force_tag or os.environ.get("AWAY_ARCHIVE"))
    if not explicit and not newer(tag, current):
        print("away: already on %s (latest is %s)." % (current, tag))
        return 0

    print("away: updating %s -> %s" % (current, norm(tag)))
    with tempfile.TemporaryDirectory(prefix="away-update-") as tmp:
        tmp = Path(tmp)
        archive = tmp / "release.tar.gz"
        try:
            url = download(tag, asset, archive)
            tree = extract_payload(archive, tmp / "unpacked")
            verify(tree)
        except RuntimeError as exc:
            print("away: update aborted -- %s" % exc, file=sys.stderr)
            print("away: nothing was changed.", file=sys.stderr)
            return 1
        print("      verified %s" % url)
        backup = swap(tree)

    print("      previous install kept at %s" % backup)
    # Re-run setup so hook paths, the skill and the fallback guard all match the
    # new payload. --yes is safe here: permissions were already reconciled once.
    rc = subprocess.call(["bash", str(AWAY / "bin" / "away"), "setup", "--yes"])
    print()
    # The payload landed either way. Say that plainly before the exit code, or a
    # setup warning reads as a failed update and invites a pointless retry.
    print("%saway: updated to %s.%s Restart running sessions to pick it up."
          % (GRN, norm(tag), OFF))
    if rc != 0:
        print("away: the update landed, but setup reported problems above.",
              file=sys.stderr)
        print("      Run `away doctor` -- do not re-run the update.", file=sys.stderr)
    return rc


def cmd_check(argv):
    tag, _asset, cached = resolve_latest(force="--force" in argv)
    current = installed_version()
    if not tag:
        print("away: version %s (could not reach GitHub)" % current)
        return 0
    where = "cached" if cached else "fetched"
    if newer(tag, current):
        print("away: version %s -- %s is available (%s)" % (current, norm(tag), where))
    else:
        print("away: version %s is current (%s: %s)" % (current, where, norm(tag)))
    return 0


def cmd_notify(argv):
    """The pre-command hook. Silent unless there is something worth saying."""
    if os.environ.get("AWAY_NO_UPDATE_CHECK"):
        return 0
    # An agent's shell is not a terminal. Prompting there would either hang or
    # be answered by a model, and neither belongs in a self-update path.
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return 0
    # Never interrupt an absence, and never swap the guard out from under it.
    if away_is_on():
        return 0

    tag, _asset, _cached = resolve_latest()
    current = installed_version()
    if not tag or not newer(tag, current):
        return 0

    print("%saway: %s is available (you have %s).%s"
          % (YEL, norm(tag), current, OFF))
    try:
        answer = input("      Update now? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return 0
    if answer in ("y", "yes"):
        cmd_apply([])
        print()
        print("%s      Re-run your command.%s" % (DIM, OFF))
        raise SystemExit(0)
    print("%s      Skipped. `away update` when you are ready;"
          " AWAY_NO_UPDATE_CHECK=1 to silence.%s" % (DIM, OFF))
    return 0


COMMANDS = {"notify": cmd_notify, "check": cmd_check, "apply": cmd_apply}

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    if cmd not in COMMANDS:
        print("usage: update.py [notify|check|apply]", file=sys.stderr)
        raise SystemExit(2)
    try:
        raise SystemExit(COMMANDS[cmd](sys.argv[2:]))
    except KeyboardInterrupt:
        raise SystemExit(130)
