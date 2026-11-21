import importlib.util
from pathlib import Path

MODULE = Path(__file__).parents[1] / "protection_core" / "asg_guard.py"
spec = importlib.util.spec_from_file_location("asg_guard", MODULE)
asg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(asg)

def test_secret_value_redacted():
    data = b'API_KEY = "EXAMPLE_NOT_A_REAL_SECRET_123456789"\n'
    findings = asg.scan_text("fixture.py", data)
    assert findings
    assert all("EXAMPLE_NOT_A_REAL_SECRET" not in f["evidence"] for f in findings)

def test_dynamic_execution_indicator():
    findings = asg.scan_text("fixture.py", b"eval(user_input)\n")
    assert any(f["id"] == "EXEC001" for f in findings)

def test_no_execution_claim():
    result = asg.scan(Path(__file__).parent / "fixtures")
    assert result["execution_performed"] is False
    assert result["network_access_performed"] is False


def test_secret_is_redacted_from_other_findings_on_same_line():
    secret = b'API_KEY = "EXAMPLE_NOT_A_REAL_SECRET_123456789"; eval(user_input)\n'
    findings = asg.scan_text("fixture.py", secret)
    assert any(f["id"] == "SECRET" for f in findings)
    assert all("EXAMPLE_NOT_A_REAL_SECRET" not in f["evidence"] for f in findings)
