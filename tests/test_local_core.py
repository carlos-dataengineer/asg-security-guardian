import importlib.util, tempfile, json
from pathlib import Path

MODULE = Path(__file__).parents[1] / "protection_core" / "asg_local.py"
spec = importlib.util.spec_from_file_location("asg_local", MODULE)
asg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(asg)

def test_baseline_detects_modification():
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)/"project"; base.mkdir()
        (base/"a.txt").write_text("one")
        state = asg.ensure_local_state(Path(td)/"state")
        asg.baseline_create(base, state)
        (base/"a.txt").write_text("two")
        changes = asg.compare_baseline(base, state)
        assert any(x["kind"] == "MODIFIED" and x["path"] == "a.txt" for x in changes)

def test_proposal_does_not_move_original():
    with tempfile.TemporaryDirectory() as td:
        target = Path(td)/"sample.txt"; target.write_text("synthetic")
        state = asg.ensure_local_state(Path(td)/"state")
        req = asg.propose_quarantine(target, state)
        assert target.exists()
        assert req["status"] == "PENDING"
        assert not Path(req["destination"]).exists()

def test_audit_chain_verifies():
    with tempfile.TemporaryDirectory() as td:
        state = asg.ensure_local_state(Path(td)/"state")
        asg.append_audit(state, {"type":"test"})
        asg.append_audit(state, {"type":"test2"})
        assert asg.verify_audit(state)["valid"]

def test_stale_target_cannot_be_approved():
    with tempfile.TemporaryDirectory() as td:
        target = Path(td)/"sample.txt"; target.write_text("before")
        state = asg.ensure_local_state(Path(td)/"state")
        req = asg.propose_quarantine(target, state)
        target.write_text("after")
        try:
            asg.approve_request(req["request_id"], state)
            assert False, "expected stale target failure"
        except ValueError as e:
            assert "changed" in str(e).lower() or "unavailable" in str(e).lower()
