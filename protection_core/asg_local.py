#!/usr/bin/env python3
"""
ASG Local Protection Core 0.2
Local-only approval ledger, file-integrity baseline, and approval-gated quarantine copy.

Safety properties:
- No network calls.
- No execution of target code.
- No automatic remediation.
- Quarantine is COPY-only; original remains untouched.
- Every quarantine copy requires an interactive, exact, one-time approval.
- Baseline monitoring reports changes; it does not block writes.
"""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, sys, time, uuid
from pathlib import Path
from datetime import datetime, timezone

VERSION = "0.2.0"

def now():
    return datetime.now(timezone.utc).isoformat()

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def ensure_local_state(state: Path):
    state.mkdir(parents=True, exist_ok=True)
    for name in ("requests", "quarantine", "baselines"):
        (state/name).mkdir(exist_ok=True)
    return state

def append_audit(state: Path, event: dict):
    """Append a tamper-evident hash-chained event. This is tamper-evident, not WORM storage."""
    log = state / "audit.jsonl"
    previous = "GENESIS"
    if log.exists():
        try:
            last = log.read_text(encoding="utf-8").splitlines()[-1]
            previous = json.loads(last).get("event_hash", "GENESIS")
        except Exception:
            previous = "CHAIN_READ_ERROR"
    payload = dict(event)
    payload["timestamp"] = payload.get("timestamp", now())
    payload["previous_hash"] = previous
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    payload["event_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    with log.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    return payload["event_hash"]

def verify_audit(state: Path):
    log = state / "audit.jsonl"
    if not log.exists():
        return {"valid": True, "events": 0, "message": "No audit events yet."}
    previous = "GENESIS"
    count = 0
    for raw in log.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        item = json.loads(raw)
        claimed = item.pop("event_hash", None)
        if item.get("previous_hash") != previous:
            return {"valid": False, "events": count, "message": "Previous-hash mismatch."}
        canonical = json.dumps(item, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        actual = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if actual != claimed:
            return {"valid": False, "events": count, "message": "Event hash mismatch."}
        previous = claimed
        count += 1
    return {"valid": True, "events": count, "message": "Hash chain verified. Local file permissions still matter."}

def inventory(root: Path):
    root = root.resolve(strict=True)
    entries = {}
    for base, dirs, files in os.walk(root, followlinks=False):
        basep = Path(base)
        dirs[:] = [d for d in dirs if not (basep/d).is_symlink() and d not in {".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "node_modules"}]
        for name in files:
            p = basep/name
            try:
                if p.is_symlink() or not p.is_file():
                    continue
                rel = str(p.relative_to(root))
                st = p.stat()
                entries[rel] = {"sha256": sha256(p), "size": st.st_size, "mtime_ns": st.st_mtime_ns}
            except (OSError, PermissionError):
                continue
    return entries

def baseline_create(root: Path, state: Path):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Baseline target must be a real directory, not a symlink.")
    data = {
        "version": VERSION, "created_at": now(),
        "root": str(root.resolve()), "files": inventory(root.resolve())
    }
    name = hashlib.sha256(str(root.resolve()).encode()).hexdigest()[:16] + ".json"
    path = state/"baselines"/name
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    append_audit(state, {"type": "baseline_created", "root": data["root"], "file_count": len(data["files"]), "baseline": name})
    return path, len(data["files"])

def baseline_path(root: Path, state: Path):
    name = hashlib.sha256(str(root.resolve()).encode()).hexdigest()[:16] + ".json"
    return state/"baselines"/name

def compare_baseline(root: Path, state: Path):
    bp = baseline_path(root, state)
    if not bp.exists():
        raise FileNotFoundError("No baseline exists. Run the baseline command first.")
    old = json.loads(bp.read_text(encoding="utf-8"))
    if str(root.resolve()) != old["root"]:
        raise ValueError("Baseline root mismatch.")
    current = inventory(root.resolve())
    before, after = old["files"], current
    events = []
    for rel in sorted(set(before) | set(after)):
        if rel not in before:
            events.append({"kind": "ADDED", "path": rel, "new_sha256": after[rel]["sha256"]})
        elif rel not in after:
            events.append({"kind": "REMOVED", "path": rel, "old_sha256": before[rel]["sha256"]})
        elif before[rel]["sha256"] != after[rel]["sha256"]:
            events.append({"kind": "MODIFIED", "path": rel, "old_sha256": before[rel]["sha256"], "new_sha256": after[rel]["sha256"]})
    append_audit(state, {"type": "integrity_check", "root": str(root.resolve()), "changes": len(events)})
    return events

def propose_quarantine(target: Path, state: Path):
    if target.is_symlink() or not target.is_file():
        raise ValueError("Only a regular, non-symlink file can be proposed for quarantine.")
    resolved = target.resolve(strict=True)
    digest = sha256(resolved)
    request_id = uuid.uuid4().hex[:12]
    destination = state/"quarantine"/f"{digest}_{resolved.name}"
    request = {
        "request_id": request_id, "action": "COPY_TO_QUARANTINE",
        "created_at": now(), "expires_at_epoch": int(time.time()) + 900,
        "source": str(resolved), "source_sha256": digest,
        "destination": str(destination), "status": "PENDING",
        "effect": "Create a copy in the local ASG quarantine. The original file will not be deleted or modified.",
        "requires_exact_confirmation": f"APPROVE {request_id}"
    }
    path = state/"requests"/f"{request_id}.json"
    path.write_text(json.dumps(request, indent=2, ensure_ascii=False), encoding="utf-8")
    append_audit(state, {"type": "action_proposed", "request_id": request_id, "action": request["action"], "source_sha256": digest})
    return request

def approve_request(request_id: str, state: Path):
    req_path = state/"requests"/f"{request_id}.json"
    if not req_path.exists():
        raise FileNotFoundError("Approval request not found.")
    req = json.loads(req_path.read_text(encoding="utf-8"))
    if req["status"] != "PENDING":
        raise ValueError(f"Request is not pending (status={req['status']}).")
    if int(time.time()) > req["expires_at_epoch"]:
        req["status"] = "EXPIRED"
        req_path.write_text(json.dumps(req, indent=2), encoding="utf-8")
        append_audit(state, {"type": "approval_expired", "request_id": request_id})
        raise ValueError("Approval request expired. Create a new proposal.")
    src = Path(req["source"])
    if src.is_symlink() or not src.is_file() or sha256(src) != req["source_sha256"]:
        req["status"] = "STALE_TARGET"
        req_path.write_text(json.dumps(req, indent=2), encoding="utf-8")
        append_audit(state, {"type": "approval_rejected_stale_target", "request_id": request_id})
        raise ValueError("Target changed or is unavailable. No action taken.")
    dest = Path(req["destination"])
    if dest.exists():
        raise FileExistsError("Quarantine destination already exists. No overwrite is allowed.")
    if not sys.stdin.isatty():
        raise RuntimeError("Interactive terminal required. No action taken.")
    print("\nASG ACTION APPROVAL")
    print(f"Action: {req['action']}")
    print(f"Source: {src}")
    print(f"SHA-256: {req['source_sha256']}")
    print(f"Destination: {dest}")
    print(req["effect"])
    print("The original will remain in place.")
    print(f"Type exactly: {req['requires_exact_confirmation']}")
    answer = input("> ").strip()
    if answer != req["requires_exact_confirmation"]:
        append_audit(state, {"type": "approval_denied_or_cancelled", "request_id": request_id})
        raise PermissionError("Approval not confirmed. No action taken.")
    # Recheck immediately before copy.
    if src.is_symlink() or not src.is_file() or sha256(src) != req["source_sha256"]:
        raise ValueError("Target changed immediately before action. No action taken.")
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    copied_hash = sha256(dest)
    if copied_hash != req["source_sha256"]:
        try: dest.unlink()
        except OSError: pass
        raise IOError("Quarantine copy verification failed.")
    req["status"] = "APPROVED_AND_COPIED"
    req["completed_at"] = now()
    req["copied_sha256"] = copied_hash
    req_path.write_text(json.dumps(req, indent=2, ensure_ascii=False), encoding="utf-8")
    append_audit(state, {"type": "action_executed", "request_id": request_id, "action": req["action"], "source_sha256": req["source_sha256"], "destination": str(dest), "copied_sha256": copied_hash})
    return dest

def main():
    ap = argparse.ArgumentParser(description="ASG local approval and integrity core")
    ap.add_argument("--state", default=str(Path.home()/".asg-security-guardian"), help="Local ASG state directory")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("baseline"); b.add_argument("root")
    c = sub.add_parser("check"); c.add_argument("root")
    w = sub.add_parser("watch"); w.add_argument("root"); w.add_argument("--interval", type=int, default=10)
    p = sub.add_parser("propose-quarantine"); p.add_argument("file")
    a = sub.add_parser("approve"); a.add_argument("request_id")
    v = sub.add_parser("verify-audit")
    args = ap.parse_args()
    state = ensure_local_state(Path(args.state).expanduser())
    try:
        if args.cmd == "baseline":
            path, count = baseline_create(Path(args.root).expanduser(), state)
            print(f"Baseline created: {path}\nFiles: {count}\nNo target files modified.")
        elif args.cmd == "check":
            events = compare_baseline(Path(args.root).expanduser(), state)
            print(json.dumps(events, indent=2, ensure_ascii=False))
            print(f"Changes detected: {len(events)}. No automatic action taken.")
        elif args.cmd == "watch":
            root = Path(args.root).expanduser()
            if not baseline_path(root, state).exists():
                print("No baseline found. Create one first with the baseline command.", file=sys.stderr); return 2
            print(f"Watching integrity (polling every {args.interval}s): {root}")
            print("This reports changes only; it does not block writes or remediate.")
            seen = set()
            while True:
                for ev in compare_baseline(root, state):
                    key = (ev["kind"], ev["path"], ev.get("new_sha256"))
                    if key not in seen:
                        print(json.dumps(ev, ensure_ascii=False), flush=True); seen.add(key)
                time.sleep(max(2, args.interval))
        elif args.cmd == "propose-quarantine":
            req = propose_quarantine(Path(args.file).expanduser(), state)
            print(json.dumps(req, indent=2, ensure_ascii=False))
            print("No file was moved, deleted or modified. Approval is required.")
        elif args.cmd == "approve":
            dest = approve_request(args.request_id, state)
            print(f"Approved copy created and verified: {dest}")
            print("Original file remains unchanged.")
        elif args.cmd == "verify-audit":
            print(json.dumps(verify_audit(state), indent=2))
    except Exception as e:
        print(f"ASG ERROR: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
