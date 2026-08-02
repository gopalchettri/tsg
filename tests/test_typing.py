"""The repo's type gate. No CI exists, so the test suite is the only automation — this is
what keeps `mypy app` at zero errors after the 2026-07-31 cleanup. A regression fails the
suite with mypy's own error list in the assertion message.

Subprocess on purpose (not mypy.api): it reproduces the exact CLI invocation developers
run (`python -m mypy app`, cwd = repo root), so pyproject's [tool.mypy] + pydantic plugin
resolve identically. ~20-40s cold; fast once .mypy_cache is warm.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_mypy_app_is_clean():
    root = Path(__file__).resolve().parents[1]
    res = subprocess.run([sys.executable, "-m", "mypy", "app"], cwd=root,
                        capture_output=True, text=True, timeout=300)
    assert res.returncode == 0, f"mypy regressions:\n{res.stdout}{res.stderr}"
