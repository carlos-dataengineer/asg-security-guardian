#!/usr/bin/env python3
"""
`asg` — single entry point for ASG Security Guardian.

    asg scan PATH [--out DIR] [--max-files N]   read-only static scan (report + dashboard refresh)
    asg dashboard [--open | --actions]          build / open the local dashboard (Scans and Actions tabs)
    asg log [--limit N] [--type TYPE]           recent actions: blocks, confirmations, scans, quarantine
    asg baseline PATH | check PATH | watch PATH [--interval S]
    asg propose-quarantine FILE | approve REQUEST_ID | verify-audit
    asg doctor                                  installation and integrity check
    asg uninstall                               remove hooks, skills, app and launcher
    asg version
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
STATE = Path(os.environ.get("ASG_STATE", str(Path.home() / ".asg-security-guardian"))).expanduser()
LOCAL_CMDS = {"baseline", "check", "watch", "propose-quarantine", "approve", "verify-audit"}


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run(script: str, args: list[str]) -> int:
    return subprocess.call([sys.executable, "-X", "utf8", str(HERE / script)] + args)


def cmd_scan(args: list[str]) -> int:
    if not args or args[0] in {"-h", "--help"}:
        return _run("asg_guard.py", ["--help"])
    if "--out" not in args:
        args = args + ["--out", str(STATE / "reports")]
    started = time.time()
    rc = _run("asg_guard.py", args)
    out_dir = Path(args[args.index("--out") + 1]).expanduser()
    try:
        newest = max(out_dir.glob("asg-*.json"), key=lambda p: p.stat().st_mtime)
        if newest.stat().st_mtime >= started - 1:
            report = json.loads(newest.read_text(encoding="utf-8"))
            local, dash = _load("asg_local"), _load("asg_dashboard")
            local.append_audit(local.ensure_local_state(STATE), {
                "type": "manual_scan", "target": report.get("target", ""), "source": "asg scan",
                "scan_id": report.get("scan_id"), "counts": report.get("counts", {}),
                "verdict": dash.verdict(report), "report": str(newest), "client": "cli"})
    except (ValueError, OSError, json.JSONDecodeError):
        pass
    try:
        print(f"Dashboard: {_load('asg_dashboard').build(STATE)}")
    except Exception as e:  # pragma: no cover
        print(f"(dashboard not updated: {type(e).__name__})")
    return rc


LOG_LABELS = {
    "install_gate": "INSTALL", "install_ran": "RAN", "auto_scan": "SCAN", "manual_scan": "SCAN",
    "baseline_created": "BASELINE", "integrity_check": "CHECK", "action_proposed": "PROPOSE",
    "action_executed": "QUARANTINE", "approval_denied_or_cancelled": "DENIED", "approval_expired": "EXPIRED",
    "approval_rejected_stale_target": "STALE",
}


def cmd_log(args: list[str]) -> int:
    limit, kind = 20, None
    if "--limit" in args:
        limit = int(args[args.index("--limit") + 1])
    if "--type" in args:
        kind = args[args.index("--type") + 1]
    dash = _load("asg_dashboard")
    events = [e for e in dash.load_events(STATE) if not kind or e.get("type") == kind][:limit]
    if not events:
        print("No actions recorded yet.")
        return 0
    for ev in events:
        t = ev.get("type", "")
        when = str(ev.get("timestamp", ""))[:19].replace("T", " ")
        label = LOG_LABELS.get(t, t.upper())
        if t == "install_gate":
            label = "BLOCKED" if ev.get("decision") == "deny" else "ASKED"
            detail = f"{ev.get('what', '')}: {ev.get('command', '')}"
        elif t == "install_ran":
            detail = f"{ev.get('what', '')}: {ev.get('command', '')}"
        elif t in ("auto_scan", "manual_scan"):
            detail = f"{str(ev.get('verdict', '')).upper():12} {dash._tilde(str(ev.get('target', '')))}"
        elif t in ("baseline_created", "integrity_check"):
            detail = f"{dash._tilde(str(ev.get('root', '')))}" + (f"  ({ev.get('changes')} changes)" if t == "integrity_check" else "")
        else:
            detail = str(ev.get("request_id", ""))
        client = f"[{ev['client']}]" if ev.get("client") else ""
        print(f"{when}  {label:10} {client:9} {detail}")
    chain = dash.chain_status(STATE)
    if chain is not None:
        forks = f", {chain['forks']} simultaneous write(s), nothing lost" if chain.get("valid") and chain.get("forks") else ""
        print(f"\naudit chain: {'OK' if chain.get('valid') else 'ALTERED'} ({chain.get('events', 0)} events{forks})")
    return 0


def cmd_doctor() -> int:
    hook = _load("asg_hook")
    problem = hook.verify_install()
    manifest = {}
    try:
        manifest = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))
    except Exception:
        pass
    home = Path.home()
    codex = Path(os.environ.get("CODEX_HOME", str(home / ".codex")))
    checks = [
        ("version", manifest.get("version", "source checkout")),
        ("core integrity", "OK" if not problem else f"FAIL ({problem})"),
        ("state", str(STATE)),
        ("Claude skill", "OK" if (home / ".claude/skills/asg-security-guardian/SKILL.md").exists() else "-"),
        ("Claude hooks", "OK" if "asg_hook.py" in _read(home / ".claude/settings.json") else "-"),
        ("Codex skill", "OK" if (home / ".agents/skills/asg-security-guardian/SKILL.md").exists() else "-"),
        ("Codex hooks", "OK (trust them with /hooks)" if "asg_hook.py" in _read(codex / "hooks.json") else "-"),
        ("reports", str(len(list((STATE / "reports").glob("asg-*.json")))) if (STATE / "reports").exists() else "0"),
        ("dashboard", str(STATE / "dashboard.html")),
    ]
    width = max(len(k) for k, _ in checks)
    for k, v in checks:
        print(f"{k.ljust(width)}  {v}")
    return 1 if problem else 0


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8")
    except Exception:
        return ""


def main(argv: list[str]) -> int:
    if not argv or argv[0] in {"-h", "--help", "help"}:
        print(__doc__.strip())
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd == "scan":
        return cmd_scan(rest)
    if cmd == "dashboard":
        return _run("asg_dashboard.py", rest)
    if cmd == "log":
        return cmd_log(rest)
    if cmd in LOCAL_CMDS:
        return _run("asg_local.py", [cmd] + rest)
    if cmd == "doctor":
        return cmd_doctor()
    if cmd == "version":
        print(_load("asg_guard").VERSION)
        return 0
    if cmd == "uninstall":
        installer = HERE / "asg_install.py"
        if not installer.exists():
            print("Installer copy not found; run `python install.py --uninstall` from the repository.", file=sys.stderr)
            return 2
        return subprocess.call([sys.executable, str(installer), "--uninstall"])
    print(f"Unknown command: {cmd}\n\n{__doc__.strip()}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
