"""Run every offline-safe scripts/test_*.py self-check under pytest.

The self-checks are standalone `python scripts/test_x.py` scripts (assert-based, main()-driven
— pytest collects nothing from them directly), and pyproject's testpaths = ["tests"] never
looks at scripts/. Twice that combination let a suite die silently for multiple commits: a
signature change (set -> dict _semantic_duplicates; the _present_status 3-tuple) broke the
assertions and nothing noticed until a review ran the file by hand. This file makes plain
`pytest` execute each script end-to-end — a non-zero exit fails the suite, so a rotted
self-check now fails CI/local runs instead of rotting.

Only scripts that need no DB / LLM / network belong in the list.
test_promotion_retry_flow.py is excluded until its hardcoded sys.path is made portable;
test_db_connectivity.py and test_otx_feed.py need live services by design.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_SCRIPTS = [
    "test_build_results_workbook.py",
    "test_build_treatment_plans_workbook.py",
    "test_next_set_overfetch.py",
    "test_pipeline_guards.py",
    "test_prompt_no_db_keys.py",
    "test_scenario_flatten.py",
]


@pytest.mark.parametrize("name", _SCRIPTS)
def test_script_selfcheck(name: str) -> None:
    script = Path(__file__).resolve().parents[1] / "scripts" / name
    result = subprocess.run([sys.executable, str(script)],
                            capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, f"{name} failed:\n{result.stdout}\n{result.stderr}"
