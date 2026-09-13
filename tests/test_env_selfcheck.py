"""env_selfcheck's REVERSE check: a live line that matches no setting.

WHY THIS EXISTS. `extra="ignore"` (config.py) drops an unrecognised env name with no error and no
log line, so a wrongly-spelled variable silently reverts to its default. The checker only ever
asked "is every FIELD documented in every file?" — never "does every LIVE line correspond to a
field?", which is the direction an operator actually gets wrong.

Not hypothetical: `control_map_sweep_enabled` accepted a bare `CONTROL_MAP_SWEEP_ENABLED` while its
neighbour `control_map_sweep_interval_seconds` required the `TSG_` prefix. Copying the first
spelling onto the second lost the interval, silently, with a green deploy.
"""
from __future__ import annotations

from pathlib import Path

from app.core.env_selfcheck import check


def _reverse_hits(root: Path) -> list[str]:
    return [p for p in check(root)[0] if "silently discarded" in p]


def test_catches_a_live_line_that_matches_no_setting(tmp_path: Path):
    """The exact pair that motivated this: prefixed switch honoured, bare interval discarded."""
    (tmp_path / ".env").write_text(
        "TSG_CONTROL_MAP_SWEEP_ENABLED=false\n"
        "CONTROL_MAP_SWEEP_INTERVAL_SECONDS=60\n", encoding="utf-8")
    hits = _reverse_hits(tmp_path)
    assert any("CONTROL_MAP_SWEEP_INTERVAL_SECONDS" in h for h in hits)
    assert not any("TSG_CONTROL_MAP_SWEEP_ENABLED" in h for h in hits)


def test_ignores_commented_lines_and_prose(tmp_path: Path):
    """A commented unknown name does nothing, so flagging it is noise — and these files are mostly
    prose. `# lease = timeout x (retries+1)` must not read as a setting named `lease`, and
    `# EMBEDDING/RERANKER_PROVIDER=x` must not read as one named `EMBEDDING`."""
    (tmp_path / ".env").write_text(
        "# COMMENTED_UNKNOWN=x\n"
        "# lease = timeout x (retries+1) x 2\n"
        "# EMBEDDING/RERANKER_PROVIDER=litellm_proxy\n", encoding="utf-8")
    assert _reverse_hits(tmp_path) == []


def test_the_repos_own_env_files_have_no_discarded_lines():
    """Regression guard on the real files. Passes today; if it ever fails, someone has added a
    variable the application is silently ignoring."""
    assert _reverse_hits(Path(__file__).resolve().parents[1]) == []
