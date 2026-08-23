"""Guards for `deploy/deploy.yaml` — the k8s manifest nothing was checking.

WHY THIS FILE EXISTS: a production audit found the API's readiness probe pointed at `/health`,
which returns 200 unconditionally by design (app/api/health.py). Readiness therefore never
gated on anything, and a pod with a dead database stayed in the Service endpoints serving 500s.
It also found `tsg-beat` reading a different Secret than the api and worker it schedules for —
drift the manifest's own header comment already admitted to.

Both are the same class of defect: the manifest is hand-edited and nothing verified it. These
tests are cheap, need no cluster, and fail loudly the moment the wiring drifts again.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

_MANIFEST = Path(__file__).resolve().parents[1] / "deploy" / "deploy.yaml"


def _docs() -> list[dict]:
    with _MANIFEST.open(encoding="utf-8") as fh:
        return [d for d in yaml.safe_load_all(fh) if d]


def _deployments() -> dict[str, dict]:
    return {d["metadata"]["name"]: d for d in _docs() if d.get("kind") == "Deployment"}


def _containers(dep: dict) -> list[dict]:
    return dep["spec"]["template"]["spec"]["containers"]


def test_manifest_parses_and_has_the_expected_workloads() -> None:
    assert set(_deployments()) == {"tsg-api", "celery-worker", "tsg-beat"}


# --- probes -------------------------------------------------------------------------------------
def test_api_readiness_probes_ready_not_health() -> None:
    """/health is an unconditional 200 (app/api/health.py) — using it for READINESS means a pod
    with an unreachable database still receives traffic. /ready is the dependency check."""
    (api,) = [c for c in _containers(_deployments()["tsg-api"]) if c["name"] == "fastapi"]
    assert api["readinessProbe"]["httpGet"]["path"] == "/ready", (
        "readinessProbe must target /ready; /health cannot fail and so gates nothing")


def test_api_liveness_probes_health_not_ready() -> None:
    """Inverse of the above, and just as important: probing /ready for LIVENESS turns a transient
    database blip into a rolling restart of every API pod."""
    (api,) = [c for c in _containers(_deployments()["tsg-api"]) if c["name"] == "fastapi"]
    assert "livenessProbe" in api, "tsg-api must declare a livenessProbe"
    assert api["livenessProbe"]["httpGet"]["path"] == "/health", (
        "livenessProbe must target /health; /ready would restart pods over dependency outages")


# --- image policy ---------------------------------------------------------------------------------
def test_mutable_image_tags_always_repull() -> None:
    """`:latest` with IfNotPresent never repulls a re-pushed tag, so a rollout can silently keep
    running the previous image. Either pin an immutable tag (a git SHA) or pull Always."""
    for name, dep in _deployments().items():
        for c in _containers(dep):
            tag = c["image"].rsplit(":", 1)[-1] if ":" in c["image"].rsplit("/", 1)[-1] else ""
            if tag in ("latest", ""):
                assert c.get("imagePullPolicy") == "Always", (
                    f"{name}/{c['name']} uses mutable tag '{tag or 'none'}' but "
                    f"imagePullPolicy={c.get('imagePullPolicy')!r}; use Always or pin a digest/SHA")


def test_all_workloads_share_one_image() -> None:
    """beat schedules the sweeps the workers execute — different builds between them means the
    scheduler and the executors disagree about what the tasks are."""
    images = {c["image"] for dep in _deployments().values() for c in _containers(dep)}
    assert len(images) == 1, f"workloads run different images: {sorted(images)}"


# --- configuration parity -------------------------------------------------------------------------
def test_every_workload_reads_the_same_env_sources() -> None:
    """tsg-beat previously read a standalone `tsg-uat-env` Secret while api/worker read
    tsg-api-config + tsg-api-secrets, so the scheduler could run with different settings than
    the workers executing its schedule."""
    seen: dict[str, set[str]] = {}
    for name, dep in _deployments().items():
        for c in _containers(dep):
            sources = {f"{kind}:{body['name']}"
                    for ref in c.get("envFrom", []) for kind, body in ref.items()}
            seen[f"{name}/{c['name']}"] = sources
    distinct = {frozenset(v) for v in seen.values()}
    assert len(distinct) == 1, f"env sources differ across workloads: {seen}"


# --- beat singleton -------------------------------------------------------------------------------
def test_beat_is_a_strict_singleton() -> None:
    """Two concurrent beats double-fire every scheduled task. The manifest says 'never scale this
    above 1'; this is what makes that more than a comment."""
    beat = _deployments()["tsg-beat"]
    assert beat["spec"]["replicas"] == 1, "tsg-beat must never run more than one replica"
    assert beat["spec"]["strategy"]["type"] == "Recreate", (
        "tsg-beat needs strategy Recreate — RollingUpdate briefly runs two beats at once")


@pytest.mark.parametrize("name", ["tsg-api", "celery-worker", "tsg-beat"])
def test_every_container_declares_resources(name: str) -> None:
    """An unbounded container competes with its own siblings for the node."""
    for c in _containers(_deployments()[name]):
        assert c.get("resources", {}).get("requests"), f"{name}/{c['name']} has no resource requests"
        assert c.get("resources", {}).get("limits"), f"{name}/{c['name']} has no resource limits"
