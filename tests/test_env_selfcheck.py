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

from app.core.env_selfcheck import DEPLOYMENT_POSTURE, POSTURE_FILE, check


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


# --- The SECRET half of the same check ----------------------------------------------------
# The reverse check above globs `.env*`, so it could not see deploy/secrets.yaml -- the one file
# that actually reaches the cluster. Five settings deleted from Settings long ago were still
# being shipped to every pod and discarded there, TSG_VALIDATOR_BATCH_SIZE having outlived the
# LLM validator itself. Same defect, one directory over.


def _secret_hits(root: Path) -> list[str]:
    return [p for p in check(root)[0] if p.startswith("deploy/")]


def _make(root: Path, name: str, body: str) -> None:
    (root / ".env").write_text("TSG_DB_DSN=x\n", encoding="utf-8")   # check() needs one .env*
    d = root / "deploy"
    d.mkdir(exist_ok=True)
    (d / f"{name}.yaml").write_text(
        f"apiVersion: v1\nkind: Secret\nmetadata:\n  name: {name}\n"
        f"  namespace: ns\ntype: Opaque\nstringData:\n{body}", encoding="utf-8")


def test_a_dead_key_in_our_secret_is_flagged(tmp_path: Path):
    """The real one: TSG_VALIDATOR_BATCH_SIZE names a setting that no longer exists."""
    _make(tmp_path, "tsg-api-secrets",
          "  TSG_VALIDATOR_BATCH_SIZE: '40'\n  TSG_DB_DSN: 'x'\n")
    hits = _secret_hits(tmp_path)
    assert any("TSG_VALIDATOR_BATCH_SIZE" in h for h in hits)
    assert not any("TSG_DB_DSN" in h for h in hits)


def test_another_teams_secret_is_left_alone(tmp_path: Path):
    """deploy/ also holds celery-exporter-secrets, whose CE_BROKER_URL is read by a different
    image. Flagging it would teach the reader to ignore this check."""
    _make(tmp_path, "celery-exporter-secrets", "  CE_BROKER_URL: 'redis://x'\n")
    assert _secret_hits(tmp_path) == []


def test_the_metadata_block_is_not_read_as_settings(tmp_path: Path):
    """`name:` and `namespace:` sit at the same indent as the stringData entries."""
    _make(tmp_path, "tsg-api-secrets", "  TSG_DB_DSN: 'x'\n")
    assert _secret_hits(tmp_path) == []


def test_the_repos_own_secrets_carry_no_dead_keys():
    """Regression guard on the real generated Secrets. Skips where they are absent -- both are
    gitignored, so CI and fresh clones have nothing to check."""
    root = Path(__file__).resolve().parents[1]
    if not (root / "deploy" / "secrets.yaml").exists():
        return
    assert _secret_hits(root) == []


# --- DEPLOYMENT_POSTURE: the value nobody was checking ------------------------------------
# The three checks above all ask "is this setting PRESENT and SPELLED right?". None could see a
# setting that is present, correctly spelled and simply WRONG -- and that gap swallowed a real
# instruction. control_map_sweep_enabled was set to false; a later alias change rewrote the line
# carrying the DOCUMENTED DEFAULT instead of the operator's value. .env* is gitignored, so there
# was no diff, no history and no review. For an untracked file, asserting the value is the only
# detection there is.

def _posture_hits(root: Path) -> list[str]:
    return [p for p in check(root)[0] if "this deployment" in p]


def _write_posture(root: Path, **override: str) -> None:
    """A POSTURE_FILE satisfying every decided value, minus/plus whatever the test changes.

    Built FROM the table rather than hardcoding the six values, so adding a decision does not
    silently leave these tests asserting a stale one."""
    vals = {f"TSG_{k.upper()}": v for k, (v, _) in DEPLOYMENT_POSTURE.items()}
    vals.update(override)
    (root / POSTURE_FILE).write_text(
        "".join(f"{k}={v}\n" for k, v in vals.items() if v is not None), encoding="utf-8")


def test_a_decided_value_set_wrong_is_flagged(tmp_path: Path):
    """THE regression: the sweep switch reading true when this deployment decided false."""
    _write_posture(tmp_path, TSG_CONTROL_MAP_SWEEP_ENABLED="true")
    hits = _posture_hits(tmp_path)
    assert any("control_map_sweep_enabled" in h and "`true`" in h for h in hits), hits
    assert len(hits) == 1, f"only the wrong one should fire: {hits}"


def test_a_decided_value_left_UNSET_is_also_flagged(tmp_path: Path):
    """Absent is not a pass. control_map_sweep_enabled defaults to True, so DELETING the line
    re-enables the sweep exactly as silently as overwriting it did."""
    _write_posture(tmp_path, TSG_CONTROL_MAP_SWEEP_ENABLED=None)
    assert any("control_map_sweep_enabled" in h and "unset" in h for h in _posture_hits(tmp_path))


def test_the_decided_values_pass(tmp_path: Path):
    _write_posture(tmp_path)
    assert _posture_hits(tmp_path) == []


def test_an_inline_comment_does_not_defeat_the_comparison(tmp_path: Path):
    """.env.uat really does carry `TSG_LLM_MAX_RETRIES=1 # 1 here mean 2 attemts`. Comparing the
    raw line would read the comment as part of the value and fail a correct file."""
    want = DEPLOYMENT_POSTURE["llm_max_retries"][0]
    _write_posture(tmp_path, TSG_LLM_MAX_RETRIES=f"{want}   # 1 here mean 2 attempts")
    assert _posture_hits(tmp_path) == []


def test_the_operators_own_env_is_not_policed(tmp_path: Path):
    """Only POSTURE_FILE is checked -- it is the tested source the Secret derives from. A
    developer's .env pins whatever their machine needs, the same exemption DERIVED_SETTINGS
    already grants it."""
    _write_posture(tmp_path)
    (tmp_path / ".env").write_text("TSG_CONTROL_MAP_SWEEP_ENABLED=true\n", encoding="utf-8")
    assert _posture_hits(tmp_path) == []


def test_the_real_env_uat_matches_every_decision():
    """Regression guard on the actual deployed source. Skips where it is absent (gitignored)."""
    root = Path(__file__).resolve().parents[1]
    if not (root / POSTURE_FILE).exists():
        return
    assert _posture_hits(root) == []
