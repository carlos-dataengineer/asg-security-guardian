#!/usr/bin/env python3
"""Dependency-free test runner (use `pytest` instead if you have it installed)."""
import importlib.util
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).parent
failed = passed = 0
for path in sorted(HERE.glob("test_*.py")):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for name in sorted(n for n in dir(mod) if n.startswith("test_")):
        try:
            getattr(mod, name)()
            passed += 1
            print(f"PASS {path.stem}.{name}")
        except Exception:
            failed += 1
            print(f"FAIL {path.stem}.{name}")
            traceback.print_exc()
print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
