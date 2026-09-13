"""Pins scripts/gen_secret_from_env.py — the generator, and the file it generates.

WHY THIS EXISTS. The script's own docstring says drift between .env.uat and deploy/secrets.yaml
is "structurally impossible" because the Secret is DERIVED. That was never enforced: the script
had no test, so nothing noticed when someone (me, this session) hand-edited the generated file.
The drift that followed was bidirectional and outlived several deploys -- five settings that no
longer exist in Settings at all were still being shipped to every pod, and
TSG_INTEL_REFRESH_INTERVAL_SECONDS existed ONLY in the generated file, so "regenerate from
source" would have silently switched off daily threat-intel refresh.

test_the_checked_in_secret_matches_its_source is the guard that makes the docstring true.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "gen_secret_from_env", _ROOT / "scripts" / "gen_secret_from_env.py")
mod = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(mod)

#: Every generated Secret and the namespace it is generated for. Both derive from the ONE env
#: file, which is the entire point -- ai-remediation silently sat on the pre-swap models (glm-5
#: primary, 180s, 3 retries) until it was regenerated alongside its sibling.
SECRETS = [("deploy/secrets.yaml", "ai-threatgen"),
           ("deploy/secrets.ai-remediation.yaml", "ai-remediation")]


def _run(monkeypatch, env_path: Path, out_path: Path, namespace: str | None = None) -> str:
    argv = ["gen_secret_from_env.py"]
    if namespace:
        argv += ["--namespace", namespace]
    monkeypatch.setattr(sys, "argv", [*argv, str(env_path), str(out_path)])
    assert mod.main() == 0
    return out_path.read_text(encoding="utf-8")


@pytest.fixture
def env_file(tmp_path: Path) -> Path:
    p = tmp_path / ".env.fixture"
    p.write_text(
        "TSG_DB_DSN=mssql+pyodbc://u:p@host/EYShield?driver=X\n"
        "TSG_MONGO_URL=mongodb://u:p@host:27017/tsg?authSource=admin\n"
        "TSG_LITELLM_BYPASS_PROXY=true\n"      # jump-server value; must be flipped for pods
        "TSG_LLM_TIMEOUT_SECONDS=180.0\n"      # must NOT emit as a bare YAML float
        "LOG_FILE=/var/log/tsg.log\n",         # DROP: pods log to stdout
        encoding="utf-8")
    return p


def test_jump_server_only_keys_never_reach_the_pods(monkeypatch, tmp_path, env_file):
    out = _run(monkeypatch, env_file, tmp_path / "s.yaml")
    assert "LOG_FILE" not in out


def test_cluster_overrides_are_applied(monkeypatch, tmp_path, env_file):
    """Both deltas the generator declares. Bypass=true would leave the pod unable to reach the
    LLM at all; directConnection is what makes a single external mongod usable."""
    out = _run(monkeypatch, env_file, tmp_path / "s.yaml")
    assert "TSG_LITELLM_BYPASS_PROXY: 'false'" in out
    assert "directConnection=true" in out


def test_every_value_is_a_quoted_string(monkeypatch, tmp_path, env_file):
    """Secret stringData REJECTS non-string scalars: 180.0 is an API-server error, '180.0' is
    fine. A bare numeric is not a cosmetic slip -- the whole apply fails."""
    out = _run(monkeypatch, env_file, tmp_path / "s.yaml")
    assert "TSG_LLM_TIMEOUT_SECONDS: '180.0'" in out
    body = out.split("stringData:\n", 1)[1]
    for line in body.splitlines():
        if line.strip():
            assert line.split(": ", 1)[1].startswith("'"), line


def test_namespace_flag_targets_the_other_copy(monkeypatch, tmp_path, env_file):
    out = _run(monkeypatch, env_file, tmp_path / "s.yaml", namespace="ai-remediation")
    assert "namespace: ai-remediation" in out


def test_the_wrong_env_file_is_refused(monkeypatch, tmp_path):
    """Pointed at a file with no TSG_DB_DSN the script must fail, not emit a Secret missing
    every real value -- which would apply cleanly and break the pods."""
    bad = tmp_path / ".env.bad"
    bad.write_text("SOMETHING_ELSE=1\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["x", str(bad), str(tmp_path / "s.yaml")])
    assert mod.main() == 1
    assert not (tmp_path / "s.yaml").exists()


@pytest.mark.parametrize("rel,namespace", SECRETS)
def test_the_checked_in_secret_matches_its_source(monkeypatch, tmp_path, rel, namespace):
    """THE ANTI-HAND-EDIT GUARD. Both files are gitignored, so CI and fresh clones skip -- but
    every machine that actually deploys has them, and that is where a hand-edit gets made."""
    src, out = _ROOT / ".env.uat", _ROOT / rel
    if not src.exists() or not out.exists():
        pytest.skip(f"{rel} or .env.uat absent (both gitignored)")
    expected = _run(monkeypatch, src, tmp_path / "regen.yaml", namespace=namespace)
    assert out.read_text(encoding="utf-8") == expected, (
        f"{rel} is not what the generator produces from .env.uat. Do NOT hand-edit it: "
        f"change .env.uat, then re-run "
        f"`python scripts/gen_secret_from_env.py --namespace {namespace} .env.uat {rel}`")
