#!/usr/bin/env python3
"""
ASG Security Guardian — installer for Claude Code and OpenAI Codex (Windows, Linux, macOS).

    python install.py                     # auto-detect Claude Code / Codex, Portuguese messages
    python install.py --target claude     # only Claude Code   (claude | codex | all | auto)
    python install.py --lang en           # English messages
    python install.py --no-hooks          # core + skill + dashboard, no automatic hooks
    python install.py --uninstall         # remove hooks, skills, app and launcher (reports are kept)

What it does, and nothing else:
  1. Copies the Protection Core to ~/.asg-security-guardian/app/ with a SHA-256 manifest.
  2. Creates the `asg` command in ~/.asg-security-guardian/bin/ (asg / asg.cmd).
  3. Claude Code: skill -> ~/.claude/skills/asg-security-guardian/
                  hooks -> ~/.claude/settings.json      (backup written first)
     Codex:       skill -> ~/.agents/skills/asg-security-guardian/
                  hooks -> $CODEX_HOME/hooks.json       (backup written first; trust once with /hooks)
  4. Scans the plugins/skills you already have, once, and builds the local dashboard
     ~/.asg-security-guardian/dashboard.html

Requires Python 3.10+. No third-party packages. No network access. Never runs scanned code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent
HOME = Path.home()
STATE = Path(os.environ.get("ASG_STATE", str(HOME / ".asg-security-guardian"))).expanduser()
APP = STATE / "app"
BIN = STATE / "bin"
CLAUDE = Path(os.environ.get("CLAUDE_CONFIG_DIR", str(HOME / ".claude"))).expanduser()
CODEX = Path(os.environ.get("CODEX_HOME", str(HOME / ".codex"))).expanduser()
CLAUDE_SETTINGS = CLAUDE / "settings.json"
CODEX_HOOKS = CODEX / "hooks.json"
CLAUDE_SKILL = CLAUDE / "skills" / "asg-security-guardian"
CODEX_SKILL = HOME / ".agents" / "skills" / "asg-security-guardian"
CORE_FILES = ["asg_guard.py", "asg_local.py", "asg_hook.py", "asg_dashboard.py", "asg_cli.py"]
MARK = "asg_hook.py"
IS_WIN = os.name == "nt"


def say(msg: str) -> None:
    print(msg, flush=True)


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def version() -> str:
    for line in (REPO / "protection_core" / "asg_guard.py").read_text(encoding="utf-8").splitlines():
        if line.startswith("VERSION"):
            return line.split("=")[1].strip().strip('"')
    return "unknown"


def _q(path: str) -> str:
    # Unquoted paths work in bash, cmd and PowerShell alike; quote only when unavoidable.
    return f'"{path}"' if " " in path else path


def hook_command(client: str) -> str:
    return f'{_q(Path(sys.executable).as_posix())} -X utf8 {_q((APP / "asg_hook.py").as_posix())} --client {client}'


# ----------------------------------------------------------------------------- json config files
def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    return json.loads(text) if text.strip() else {}


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        backup = path.with_name(f"{path.name}.asg-backup-{time.strftime('%Y%m%d-%H%M%S')}")
        shutil.copy2(path, backup)
        say(f"    backup: {backup}")
    tmp = path.with_name(path.name + ".asg-tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    json.loads(tmp.read_text(encoding="utf-8"))  # validate before replacing
    tmp.replace(path)


def strip_asg(hooks: dict) -> dict:
    for event in list(hooks):
        kept = []
        for group in hooks[event]:
            inner = [h for h in group.get("hooks", []) if MARK not in h.get("command", "") and MARK not in h.get("commandWindows", "")]
            if inner:
                kept.append(dict(group, hooks=inner))
        if kept:
            hooks[event] = kept
        else:
            del hooks[event]
    return hooks


def asg_hooks(client: str) -> dict:
    cmd = hook_command(client)
    entry = {"type": "command", "command": cmd}
    if client == "codex":
        entry["commandWindows"] = cmd
        entry["statusMessage"] = "ASG: checking download"
        shell_matcher = "Bash"
        session_matcher = None
    else:
        shell_matcher = "Bash|PowerShell"
        session_matcher = "startup|resume"
    groups = {
        "PreToolUse": {"matcher": shell_matcher, "hooks": [dict(entry, timeout=15)]},
        "PostToolUse": {"matcher": shell_matcher, "hooks": [dict(entry, timeout=180)]},
        "SessionStart": {"hooks": [dict(entry, timeout=120)]},
    }
    if session_matcher:
        groups["SessionStart"]["matcher"] = session_matcher
    return groups


def register(path: Path, client: str) -> None:
    data = load_json(path)
    hooks = strip_asg(data.get("hooks", {}))
    for event, group in asg_hooks(client).items():
        hooks.setdefault(event, []).append(group)
    data["hooks"] = hooks
    write_json(path, data)


def unregister(path: Path) -> None:
    if not path.exists():
        return
    data = load_json(path)
    hooks = strip_asg(data.get("hooks", {}))
    if hooks:
        data["hooks"] = hooks
    else:
        data.pop("hooks", None)
    write_json(path, data)
    say(f"  hooks removed from {path}")


# ----------------------------------------------------------------------------- launcher
def write_launchers() -> None:
    BIN.mkdir(parents=True, exist_ok=True)
    py, cli = Path(sys.executable), APP / "asg_cli.py"
    (BIN / "asg.cmd").write_text(f'@echo off\r\n"{py}" -X utf8 "{cli}" %*\r\n', encoding="utf-8")
    sh = BIN / "asg"
    sh.write_text(f'#!/usr/bin/env sh\nexec "{py.as_posix()}" -X utf8 "{cli.as_posix()}" "$@"\n', encoding="utf-8")
    try:
        sh.chmod(0o755)
    except OSError:
        pass


def on_path() -> bool:
    return any(Path(p).resolve() == BIN.resolve() for p in os.environ.get("PATH", "").split(os.pathsep) if p)


def add_to_path() -> str:
    """Add BIN to the *user* PATH (no admin rights). Returns a human-readable result."""
    if on_path():
        return "already on PATH"
    if IS_WIN:
        import winreg  # noqa: PLC0415 - Windows only
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE) as k:
            try:
                current, kind = winreg.QueryValueEx(k, "Path")
            except FileNotFoundError:
                current, kind = "", winreg.REG_EXPAND_SZ
            parts = [p for p in current.split(";") if p]
            if str(BIN) not in parts:
                winreg.SetValueEx(k, "Path", 0, kind, ";".join(parts + [str(BIN)]))
        return "added to the user PATH (open a new terminal)"
    rc = HOME / (".zshrc" if os.environ.get("SHELL", "").endswith("zsh") else ".bashrc")
    line = f'export PATH="$PATH:{BIN.as_posix()}"  # ASG Security Guardian\n'
    if rc.exists() and line in rc.read_text(encoding="utf-8", errors="replace"):
        return f"already in {rc}"
    with rc.open("a", encoding="utf-8") as f:
        f.write("\n" + line)
    return f"added to {rc} (open a new terminal)"


# ----------------------------------------------------------------------------- targets
def detect(target: str) -> list[str]:
    if target == "all":
        return ["claude", "codex"]
    if target in ("claude", "codex"):
        return [target]
    found = []
    if CLAUDE.exists() or shutil.which("claude"):
        found.append("claude")
    if CODEX.exists() or shutil.which("codex"):
        found.append("codex")
    return found or ["claude", "codex"]


def copy_skill(dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(REPO / ".claude" / "skills" / "asg-security-guardian", dst)


# ----------------------------------------------------------------------------- commands
def install(lang: str, hooks: bool, target: str, path_opt: bool) -> int:
    if sys.version_info < (3, 10):
        say("ASG requires Python 3.10+")
        return 2
    clients = detect(target)
    v = version()
    say(f"\nASG Security Guardian {v} — installing for: {', '.join(clients)}\n")

    say(f"[1/5] Protection Core -> {APP}")
    APP.mkdir(parents=True, exist_ok=True)
    manifest = {"version": v, "installed_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "clients": clients, "files": {}}
    for name in CORE_FILES:
        shutil.copy2(REPO / "protection_core" / name, APP / name)
        manifest["files"][name] = sha256(APP / name)
    shutil.copy2(REPO / "config" / "policy.json", APP / "policy.json")
    manifest["files"]["policy.json"] = sha256(APP / "policy.json")
    shutil.copy2(Path(__file__), APP / "asg_install.py")  # used by `asg uninstall`
    (APP / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    cfg_path = STATE / "config.json"
    cfg = load_json(cfg_path)
    cfg.update({"lang": lang, "clients": clients})
    cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

    say(f"[2/5] Command `asg` -> {BIN}")
    write_launchers()
    if path_opt:
        say(f"      PATH: {add_to_path()}")

    say("[3/5] Skills")
    if "claude" in clients:
        copy_skill(CLAUDE_SKILL)
        say(f"      Claude Code: {CLAUDE_SKILL}")
    if "codex" in clients:
        copy_skill(CODEX_SKILL)
        say(f"      Codex:       {CODEX_SKILL}")

    if hooks:
        say("[4/5] Automatic hooks")
        if "claude" in clients:
            register(CLAUDE_SETTINGS, "claude")
            say(f"      Claude Code: {CLAUDE_SETTINGS}")
        if "codex" in clients:
            register(CODEX_HOOKS, "codex")
            say(f"      Codex:       {CODEX_HOOKS}")
        say("      Scanning the plugins/skills already installed (once)...")
        subprocess.run([sys.executable, "-X", "utf8", str(APP / "asg_hook.py"), "--register-existing"], check=False)
    else:
        say("[4/5] Hooks skipped (--no-hooks)")

    say("[5/5] Dashboard")
    sys.path.insert(0, str(APP))
    import asg_dashboard  # noqa: PLC0415
    dash = asg_dashboard.build(STATE)
    r = subprocess.run([sys.executable, str(APP / "asg_hook.py"), "--self-test"], capture_output=True, text=True)
    say(f"      {dash}\n      {r.stdout.strip()}")

    asg = f"{BIN / ('asg.cmd' if IS_WIN else 'asg')}"
    say("\n✅ Installed. Next steps:")
    if "claude" in clients:
        say("   • Claude Code: restart it (or open a new session). Try: /asg-security-guardian")
    if "codex" in clients:
        say("   • Codex: restart it and run /hooks once to TRUST the ASG hooks (Codex skips untrusted hooks).")
        say("            Then try: $asg-security-guardian")
    say(f"   • Dashboard: {asg} dashboard --open")
    if not on_path() and not path_opt:
        say(f"   • Tip: add {BIN} to your PATH to type just `asg` (or reinstall with --add-to-path).")
    return 0


def uninstall() -> int:
    say("Removing ASG Security Guardian...")
    unregister(CLAUDE_SETTINGS)
    unregister(CODEX_HOOKS)
    for d in (CLAUDE_SKILL, CODEX_SKILL, APP, BIN):
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)
            say(f"  removed {d}")
    say(f"Kept reports, dashboard and audit ledger in {STATE} (delete it manually if you want).")
    return 0


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="Install ASG Security Guardian for Claude Code and Codex")
    ap.add_argument("--target", choices=["auto", "claude", "codex", "all"], default="auto")
    ap.add_argument("--lang", choices=["pt", "en"], default="pt")
    ap.add_argument("--no-hooks", action="store_true")
    ap.add_argument("--add-to-path", action="store_true", help="add the `asg` command folder to your user PATH")
    ap.add_argument("--uninstall", action="store_true")
    args = ap.parse_args()
    return uninstall() if args.uninstall else install(args.lang, not args.no_hooks, args.target, args.add_to_path)


if __name__ == "__main__":
    raise SystemExit(main())
