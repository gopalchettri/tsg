"""Run every offline-safe scripts/test_*.py self-check under pytest.

The self-checks are standalone `python scripts/test_x.py` scripts (assert-based, main()-driven
— pytest collects nothing from them directly), and pyproject's testpaths = ["tests"] never
looks at scripts/. Twice that combination let a suite die silently for multiple commits: a
signature change (set -> dict _semantic_duplicates; the _present_status 3-tuple) broke the
assertions and nothing noticed until a review ran the file by hand. This file makes plain
`pytest` execute each script end-to-end — a non-zero exit fails the suite, so a rotted
self-check now fails CI/local runs instead of rotting.

Only scripts that need no DB / LLM / network belong in the list.
test_db_connectivity.py and test_otx_feed.py need live services by design.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_SCRIPTS = [
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


def test_env_comment_blocks_match_their_single_source() -> None:
    """The .env comment blocks are GENERATED from scripts/env_comments.py, and nothing checked it.

    apply_env_comments.py states the rule — "the description lives in ONE place ... hand-editing
    four files is what caused the drift" — but it is a tool someone must remember to run, so a
    hand-edit to a generated block survives indefinitely and is then silently REVERTED the next
    time anyone runs it. That happened here: the whole operator documentation of the control-map
    sweep switch, including its admin drain route, was hand-written into four files while the
    generator still held the superseded text. `--check` already exits non-zero for exactly this;
    it simply had no caller. This is the caller, so the drift fails the build instead of waiting
    quietly to be undone."""
    script = Path(__file__).resolve().parents[1] / "scripts" / "apply_env_comments.py"
    result = subprocess.run([sys.executable, str(script), "--check"],
                            capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, (
        "a .env comment block differs from scripts/env_comments.py — edit the description THERE "
        f"and run `python scripts/apply_env_comments.py`:\n{result.stdout}\n{result.stderr}")
