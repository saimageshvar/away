#!/usr/bin/env python3
"""Reporting side of away mode: digests, event counts, and snapshot recovery."""

import json
import os
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

AWAY = Path(os.environ.get("AWAY_HOME") or (Path.home() / ".claude" / "away"))
STATE = AWAY / "state"
EVENTS = STATE / "events.jsonl"
TRASH = STATE / "trash"
CMUX_BINDINGS = Path.home() / ".cache" / "cmux" / "agent-bindings.jsonl"

LABELS = {
    "decision_forced": "decided for itself",
    "deferred": "DEFERRED",
    "plan_self_approved": "plan self-approved",
    "rm_allowed": "delete allowed",
    "git_destructive_allowed": "git destroy allowed",
    "container_delete_allowed": "container delete",
    "stop_blocked": "early stop blocked",
    "self_reported_decision": "DECIDED (self-reported)",
}


SKIPPED_SYNTHETIC = 0


def to_local(ts):
    """Timestamps are stored in UTC. An operator reads local time.

    Duplicated in guard.py rather than shared: a failed import there exits
    non-zero, guard.sh then fails closed, and every Bash call in every agent is
    blocked. A pure formatter is not worth that risk.
    """
    try:
        stamp = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc).astimezone()
    except Exception:
        return (ts or "")[11:19]
    # Time alone is ambiguous once an absence crosses midnight, and an overnight
    # absence is the normal case.
    if stamp.date() != datetime.now().astimezone().date():
        return stamp.strftime("%d %b %H:%M:%S")
    return stamp.strftime("%H:%M:%S")


def zone_header():
    now = datetime.now().astimezone()
    return "times in %s (%s)" % (now.tzname(), now.strftime("%z"))


def read_events(since_epoch, include_synthetic=False):
    """Real events only by default.

    Synthetic events come from adversarial tests, which by design fire commands
    that look identical to a real bypass attempt. Mixing them into the digest
    once caused an unrelated session to escalate a false security incident.
    """
    global SKIPPED_SYNTHETIC
    out = []
    if not EVENTS.exists():
        return out
    for line in EVENTS.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        try:
            stamp = datetime.strptime(rec["ts"], "%Y-%m-%dT%H:%M:%SZ")
            rec["_epoch"] = stamp.replace(tzinfo=timezone.utc).timestamp()
        except Exception:
            rec["_epoch"] = 0
        if rec["_epoch"] < since_epoch:
            continue
        if rec.get("synthetic") and not include_synthetic:
            SKIPPED_SYNTHETIC += 1
            continue
        out.append(rec)
    return out


def cmux_labels():
    """Map session id to its cmux surface, so a digest names panes not UUIDs."""
    found = {}
    if not CMUX_BINDINGS.exists():
        return found
    for line in CMUX_BINDINGS.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            rec = json.loads(line)
        except Exception:
            continue
        sid = (rec.get("session_id") or "").replace("claude-", "", 1)
        surface = rec.get("surface_id") or rec.get("tab_id")
        if sid and surface:
            found[sid] = str(surface)[:12]
    return found


def summarize(rec):
    detail = rec.get("detail")
    tool = rec.get("tool") or "?"
    if tool == "Bash" and isinstance(detail, dict):
        text = (detail.get("command") or "").strip().replace("\n", " ")
    elif tool == "AskUserQuestion" and isinstance(detail, list) and detail:
        text = (detail[0] or {}).get("question", "")
    elif tool == "ExitPlanMode" and isinstance(detail, dict):
        plan = (detail.get("plan") or "").strip().replace("\n", " ")
        text = plan
    elif isinstance(detail, dict) and "decision" in detail:
        text = detail["decision"]
    elif isinstance(detail, dict):
        text = json.dumps(detail, ensure_ascii=False)
    else:
        text = str(detail or "")
    return text[:96] + ("..." if len(text) > 96 else "")


def roster(since_epoch=0):
    """Sessions that ran under away mode IN THIS WINDOW, including silent ones.

    A compliant agent never triggers a denial, so the event log alone cannot show
    that it was working at all. Markers outlive an absence, so without the window
    a digest listed sessions from previous ones as if they had just run.
    """
    seen = STATE / "greeted"
    if not seen.is_dir():
        return []
    out = []
    for marker in sorted(seen.iterdir()):
        try:
            entry = json.loads(marker.read_text())
        except Exception:
            entry = {"session": marker.name}
        if float(entry.get("at") or 0) < since_epoch:
            continue
        out.append(entry)
    return out


def synthetic_note():
    if not SKIPPED_SYNTHETIC:
        return ""
    return ("\n\n%d synthetic test event(s) were hidden. They are labelled tests, "
            "not real denials. Use `away report --all` to see them." % SKIPPED_SYNTHETIC)


def digest_all(since_epoch):
    """Digest including synthetic test events, each marked as such."""
    events = read_events(since_epoch, include_synthetic=True)
    if not events:
        return "no away-mode events recorded."
    lines = []
    for rec in events:
        tag = "TEST " if rec.get("synthetic") else "     "
        lines.append("%s%s  %-20s %-14s %s" % (
            tag, to_local(rec.get("ts")),
            LABELS.get(rec.get("event"), rec.get("event")),
            rec.get("tool", "?"), summarize(rec)))
    return "\n".join([zone_header()] + lines)


def digest(since_epoch, only_session=None):
    events = read_events(since_epoch)
    if only_session:
        events = [r for r in events if r.get("session") == only_session]
    if not events:
        return "no away-mode events recorded." + synthetic_note()
    surfaces = cmux_labels()
    by_session = {}
    for rec in events:
        by_session.setdefault(rec.get("session", "unknown"), []).append(rec)

    tally = {}
    for rec in events:
        tally[rec.get("event", "?")] = tally.get(rec.get("event", "?"), 0) + 1
    head = "  ".join("%s %d" % (LABELS.get(k, k), v) for k, v in sorted(tally.items()))

    lines = [head, zone_header(), "-" * max(28, min(len(head), 78))]
    seen = roster(since_epoch)
    active = {r.get("session") for r in seen}
    if only_session:
        active &= {only_session}
    silent = sorted(active - set(by_session))
    if silent:
        lines.append("sessions that ran under away mode but logged NOTHING:")
        for s_id in silent:
            info = next((r for r in seen if r.get("session") == s_id), {})
            lines.append("  %s  %s" % (info.get("label", s_id),
                                       info.get("branch") or ""))
        lines.append("  (they complied without ever being blocked, so nothing "
                     "was denied. Ask them what they decided.)")
        lines.append("")
    for session, recs in by_session.items():
        first = recs[0]
        pane = surfaces.get(session)
        title = "%s  %s" % (first.get("label", session), first.get("branch") or "")
        if pane:
            title += "  [cmux %s]" % pane
        lines.append(title.rstrip())
        for rec in recs:
            when = to_local(rec.get("ts"))
            agent = rec.get("agent_type") or rec.get("agent") or "main"
            agent = "" if agent == "main" else "  <%s>" % agent
            lines.append("  %s  %-20s %-14s %s%s" % (
                when, LABELS.get(rec.get("event"), rec.get("event")),
                rec.get("tool", "?"), summarize(rec), agent))
            snap = (rec.get("detail") or {}).get("snapshot") \
                if isinstance(rec.get("detail"), dict) else None
            if snap:
                lines.append("        snapshot: %s" % Path(snap).name)
        lines.append("")
    return "\n".join(lines).rstrip() + synthetic_note()


def bundles():
    if not TRASH.exists():
        return []
    found = []
    for path in sorted(TRASH.iterdir()):
        if not path.is_dir():
            continue
        meta = {}
        try:
            meta = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
        except Exception:
            pass
        size = 0
        for root, _dirs, files in os.walk(path):
            for name in files:
                try:
                    size += (Path(root) / name).stat().st_size
                except OSError:
                    continue
        found.append((path, meta, size))
    return found


def trash_list():
    found = bundles()
    if not found:
        print("no snapshots.")
        return
    print("%-4s %-20s %-6s %-9s %s" % ("id", "when", "kind", "size", "command"))
    for index, (path, meta, size) in enumerate(found, 1):
        print("%-4d %-20s %-6s %-9s %s" % (
            index, path.name[:19], meta.get("kind", "?"),
            "%.1fMB" % (size / 1048576) if size > 1048576 else "%dKB" % (size // 1024),
            (meta.get("command") or "")[:60]))
    print("\nrestore with: away trash restore <id>")


def trash_restore(raw_id):
    found = bundles()
    try:
        path, meta, _size = found[int(raw_id) - 1]
    except Exception:
        print("away: no snapshot with id %r (see `away trash`)" % raw_id, file=sys.stderr)
        raise SystemExit(2)

    kind = meta.get("kind")
    if kind == "rm":
        files_root = path / "files"
        restored, displaced = 0, 0
        # A restore can land on work newer than the snapshot, so anything about to
        # be overwritten is kept rather than silently lost.
        clobbered = path / "clobbered"
        for root, _dirs, names in os.walk(files_root):
            for name in names:
                src = Path(root) / name
                rel = src.relative_to(files_root)
                dest = Path("/") / rel
                if dest.exists():
                    keep = clobbered / rel
                    keep.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(dest, keep)
                    displaced += 1
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dest)
                restored += 1
        print("restored %d file(s) from %s" % (restored, path.name))
        if displaced:
            print("%d existing file(s) were overwritten; the previous contents are "
                  "kept in %s" % (displaced, clobbered))
        return

    if kind == "git":
        repo = meta.get("repo")
        print("git undo bundle: %s" % path)
        print("  repo: %s" % repo)
        print("  command that ran: %s" % meta.get("command"))
        print("\nreplay it yourself, so you stay in control of the work tree:")
        print("  git -C %s apply %s" % (repo, path / "tracked.patch"))
        if (path / "untracked.tar").exists():
            print("  tar -C %s -xf %s" % (repo, path / "untracked.tar"))
        print("\nreview %s first." % (path / "status.txt"))
        return

    print("away: unknown bundle kind %r" % kind, file=sys.stderr)
    raise SystemExit(2)


def main():
    raw = sys.argv[1:]
    only_session = None
    if "--session" in raw:
        index = raw.index("--session")
        only_session = raw[index + 1] if index + 1 < len(raw) else None
        raw = raw[:index] + raw[index + 2:]
    argv = [a for a in raw if a != "--all"]
    show_all = "--all" in raw
    cmd = argv[0] if argv else "digest"
    since = float(argv[1]) if len(argv) > 1 else 0
    if cmd == "digest":
        if show_all:
            print(digest_all(since))
        else:
            print(digest(since, only_session))
    elif cmd == "count":
        print(len(read_events(since, include_synthetic=show_all)))
    elif cmd == "trash-list":
        trash_list()
    elif cmd == "trash-restore":
        trash_restore(sys.argv[2] if len(sys.argv) > 2 else "")
    else:
        print("report.py [digest|count|trash-list|trash-restore] ...", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
