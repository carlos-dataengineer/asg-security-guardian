"""ASG Security Center (0.5): views, shield status, protection detection and escaping."""
import importlib.util
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parents[1] / "protection_core"
spec = importlib.util.spec_from_file_location("asg_dashboard_d", ROOT / "asg_dashboard.py")
dash = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dash)

NOW = datetime.now(timezone.utc).isoformat()
EVIL = "<img src=x onerror=alert(1)>"


def _report(verdict_kind="review", when=NOW):
    findings = {
        "review": [{"id": "PIPE001", "severity": "HIGH", "title": "pipe", "path": "setup.sh", "line": 2, "evidence": EVIL}],
        "clean": [],
    }[verdict_kind]
    counts = {"HIGH": len(findings)} if findings else {}
    return {"scan_id": "abc", "created_at": when, "target": "/t/" + EVIL, "counts": counts,
            "files_inventoried": 3, "findings": findings, "_md": str(Path(tempfile.gettempdir()) / "x.md")}


ALL_ON = {"clients": {"claude": {"hooks": ["PostToolUse", "PreToolUse", "SessionStart"], "skill": True}},
          "integrity": True, "version": "0.5.0"}


def test_all_views_render_and_escape_untrusted_text():
    page = dash.render([_report()], "en", [], {"valid": True, "events": 0}, ALL_ON,
                       [{"request_id": "r1", "status": "PENDING", "source": "/x/" + EVIL, "created_at": NOW}])
    for view in ("overview", "scans", "threats", "actions", "quarantine", "protection"):
        assert f"id='view-{view}'" in page
    assert EVIL not in page and "&lt;img src=x" in page
    assert "Content-Security-Policy" in page and "http://" not in page.replace("http://www.w3.org", "")


def test_shield_status_levels():
    ok = dash.render([_report("clean")], "en", [], {"valid": True}, ALL_ON)
    assert "You are protected" in ok
    warn = dash.render([_report("review")], "en", [], {"valid": True}, ALL_ON)
    assert "Attention needed" in warn
    off = dict(ALL_ON, clients={"claude": {"hooks": ["SessionStart"], "skill": True}})
    assert "Protection incomplete" in dash.render([], "en", [], {"valid": True}, off)
    bad_integrity = dict(ALL_ON, integrity=False)
    assert "Protection incomplete" in dash.render([], "en", [], {"valid": True}, bad_integrity)
    assert "Protection incomplete" in dash.render([], "en", [], {"valid": False}, ALL_ON)


def test_old_review_does_not_keep_warning_forever():
    old = _report("review", when="2020-01-01T00:00:00+00:00")
    assert "You are protected" in dash.render([old], "en", [], {"valid": True}, ALL_ON)


def test_protection_status_reads_agent_configs():
    with tempfile.TemporaryDirectory() as td:
        home = Path(td)
        (home / ".claude" / "skills" / "asg-security-guardian").mkdir(parents=True)
        (home / ".claude" / "skills" / "asg-security-guardian" / "SKILL.md").write_text("x")
        hook = {"type": "command", "command": "python asg_hook.py --client claude"}
        (home / ".claude" / "settings.json").write_text(json.dumps(
            {"hooks": {"PostToolUse": [{"hooks": [hook]}], "Stop": [{"hooks": [{"type": "command", "command": "other"}]}]}}))
        (home / ".codex").mkdir()
        old = {k: os.environ.get(k) for k in ("CLAUDE_CONFIG_DIR", "CODEX_HOME")}
        os.environ["CLAUDE_CONFIG_DIR"], os.environ["CODEX_HOME"] = str(home / ".claude"), str(home / ".codex")
        try:
            st = dash.protection_status()
        finally:
            for k, v in old.items():
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        assert st["clients"]["claude"] == {"hooks": ["PostToolUse"], "skill": True}
        assert st["clients"]["codex"]["hooks"] == []


def test_charts_handle_empty_and_populated_data():
    empty = dash.render([], "pt", [], None, None)
    assert "Atividade dos últimos 14 dias" in empty and "<svg" in empty
    full = dash.render([_report(), _report("clean")], "pt", [{"type": "install_gate", "decision": "deny", "timestamp": NOW}], None, ALL_ON)
    assert "<rect" in full and "stroke-dasharray" in full
