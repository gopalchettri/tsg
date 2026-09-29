"""Guards for the `deploy/` k8s manifests — the files nothing was checking.

WHY THIS FILE EXISTS: a production audit found the API's readiness probe pointed at `/health`,
which returns 200 unconditionally by design (app/api/health.py). Readiness therefore never
gated on anything, and a pod with a dead database stayed in the Service endpoints serving 500s.
It also found `tsg-beat` reading a different Secret than the api and worker it schedules for —
drift the manifest's own header comment already admitted to.

Both are the same class of defect: the manifest is hand-edited and nothing verified it. These
tests are cheap, need no cluster, and fail loudly the moment the wiring drifts again.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

_DEPLOY = Path(__file__).resolve().parents[1] / "deploy"
_MANIFEST = _DEPLOY / "deploy.yaml"
_FLOWER = _DEPLOY / "flower.yaml"
_OBSERVABILITY = _DEPLOY / "observability.yaml"

# The only registry this cluster's nodes can pull from. Everything else — docker.io, quay.io,
# ghcr.io, gcr.io — is unreachable through the corporate proxy, and the symptom is a bare
# ImagePullBackOff that says nothing about why.
_PRIVATE_REGISTRY = "quay-quay-registry.apps.dda-desc-az1-01.desccii.local/"


def _docs(path: Path = _MANIFEST) -> list[dict]:
    with path.open(encoding="utf-8") as fh:
        return [d for d in yaml.safe_load_all(fh) if d]


def _deployments(path: Path = _MANIFEST) -> dict[str, dict]:
    return {d["metadata"]["name"]: d for d in _docs(path) if d.get("kind") == "Deployment"}


def _containers(dep: dict) -> list[dict]:
    return dep["spec"]["template"]["spec"]["containers"]


def test_manifest_parses_and_has_the_expected_workloads() -> None:
    # celery-worker-admin consumes the `admin` queue (celery_app.py::task_routes). It is a
    # SEPARATE workload on purpose: its jobs are CPU-bound and were measured dragging live
    # generation from ~355s to 967s when they shared the default queue. If it disappears from
    # this manifest, the API accepts those jobs and they never run.
    assert set(_deployments()) == {"tsg-api", "celery-worker", "celery-worker-admin", "tsg-beat"}


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


# --- PodDisruptionBudgets -------------------------------------------------------------------------
def _pdbs() -> list[dict]:
    return [d for d in _docs() if d.get("kind") == "PodDisruptionBudget"]


def test_api_and_worker_have_component_scoped_pdbs() -> None:
    """Replicas without a PDB do not survive the node maintenance they exist for. The selector
    must be COMPONENT-scoped: every workload shares app=tsg-api, so an app-only selector covers
    beat and double-covers the workers — and a pod matched by more than one PDB makes the
    eviction API refuse outright, wedging every node drain. Existence-by-name would pass on
    that broken selector; this asserts the exact selectors."""
    selectors = {frozenset(p["spec"]["selector"]["matchLabels"].items()) for p in _pdbs()}
    assert frozenset({("app", "tsg-api"), ("component", "fastapi")}) in selectors, (
        "tsg-api needs a PDB selecting {app: tsg-api, component: fastapi}")
    assert frozenset({("app", "tsg-api"), ("component", "celery")}) in selectors, (
        "celery-worker needs a PDB selecting {app: tsg-api, component: celery}")
    for pdb in _pdbs():
        assert pdb["spec"].get("minAvailable") == 1, (
            f"{pdb['metadata']['name']}: PDBs here use minAvailable 1 — anything stricter "
            "blocks drains on a 2-replica deployment")


def test_no_pdb_covers_beat() -> None:
    """A minAvailable PDB over the beat singleton blocks every node drain forever — its
    availability story is strategy Recreate + the schedule-mtime liveness probe. Checked
    against the SELECTOR (what eviction actually evaluates), not PDB names."""
    beat_labels = _deployments()["tsg-beat"]["spec"]["template"]["metadata"]["labels"]
    for pdb in _pdbs():
        sel = pdb["spec"]["selector"]["matchLabels"]
        assert not all(beat_labels.get(k) == v for k, v in sel.items()), (
            f"PDB {pdb['metadata']['name']} selector {sel} matches tsg-beat's pod labels "
            f"{beat_labels} — a singleton under a minAvailable PDB wedges node drains")


# --- the newer manifests: flower.yaml / observability.yaml ---------------------------------------
# These arrived after deploy.yaml and are hand-edited the same way. A malformed one has to fail
# here, in CI, rather than at `oc apply` — or worse, apply cleanly and misbehave in the cluster.
def _collect(node: object, key: str) -> list:
    """Every value of `key` anywhere in a parsed doc.

    Kind-agnostic on purpose: a StatefulSet, DaemonSet, CronJob or an initContainer holds
    `image:`/`env:` just as a Deployment does, and enumerating kinds is how a new one slips
    through unchecked.
    """
    found: list = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key:
                found.append(v)
            else:
                found.extend(_collect(v, key))
    elif isinstance(node, list):
        for v in node:
            found.extend(_collect(v, key))
    return found


def _assert_bounded_and_probed(path: Path) -> None:
    deps = _deployments(path)
    assert deps, f"{path.name} declares no Deployment — nothing in it would ever run"
    for name, dep in deps.items():
        for c in _containers(dep):
            assert c.get("resources", {}).get("limits"), (
                f"{path.name}: {name}/{c['name']} has no resource limits — it can starve the "
                "api and workers it shares nodes with, and a quota'd namespace rejects it at "
                "admission rather than merely scheduling it late")
            assert any(p in c for p in ("readinessProbe", "livenessProbe", "startupProbe")), (
                f"{path.name}: {name}/{c['name']} declares no probe — nothing would ever restart "
                "it once it wedged, and the two failure shapes are different: a SERVICED workload "
                "stays in the endpoints and reads as a broken dependency, while a QUEUE CONSUMER "
                "(the celery workers) is in no Service at all, so there is no endpoint to remove "
                "and the only symptom is a queue that quietly stops draining. The second is worse "
                "— it presents as a slow provider or a database problem while `oc get pods` shows "
                "every replica Running with zero restarts. Both need a probe; a queue consumer "
                "needs `celery inspect ping`, which round-trips the broker and the worker's own "
                "event loop, because `is the process alive` is exactly the question that stays "
                "true while it is wedged.")


def test_flower_manifest_workloads_are_bounded_and_probed() -> None:
    _assert_bounded_and_probed(_FLOWER)


def test_observability_manifest_workloads_are_bounded_and_probed() -> None:
    if not _OBSERVABILITY.exists():
        pytest.skip(f"deploy/{_OBSERVABILITY.name} is not in this tree — nothing to validate")
    _assert_bounded_and_probed(_OBSERVABILITY)




# --- registry + credential policy, across EVERY manifest -----------------------------------------
def _manifests() -> list[Path]:
    """Every manifest except the gitignored `*secrets*.yaml` — those exist to hold credentials."""
    return [p for p in sorted(_DEPLOY.glob("*.yaml")) if "secrets" not in p.name]


@pytest.mark.parametrize("path", _manifests(), ids=lambda p: p.name)
def test_no_manifest_pulls_from_a_public_registry(path: Path) -> None:
    """Nodes here cannot reach docker.io/quay.io/ghcr.io through the corporate proxy. The failure
    presents as ImagePullBackOff with no hint about the cause, so it has to be caught in review:
    mirror the image into the private registry first (deploy/monitoring.yaml's header shows how)."""
    for image in _collect(_docs(path), "image"):
        assert image.startswith(_PRIVATE_REGISTRY) or "MIRROR-ME" in image, (
            f"{path.name}: image {image!r} is not on {_PRIVATE_REGISTRY} — nodes cannot pull it "
            "and the pod will sit in ImagePullBackOff; mirror it first, or leave an explicit "
            "MIRROR-ME placeholder so the gap is visible instead of looking deployable")


# A key literally NAMED password/token/etc. carrying a value, or a URL with credentials baked into
# it (redis://user:pass@host). Comments are stripped before this runs — prose explaining where a
# credential comes from is not a leak.
_SECRET_KEY = re.compile(r"(?i)^\s*-?\s*[\w.\-]*(?:password|passwd|token|api_?key|basic_auth)\s*:\s*\S")
_CREDENTIALED_URL = re.compile(r"[a-z][a-z0-9+.\-]*://[^\s/:@]+:[^\s/@]+@")
_SECRETISH_ENV = re.compile(r"(?i)(password|passwd|token|api_?key|secret|basic_auth)")


@pytest.mark.parametrize("path", _manifests(), ids=lambda p: p.name)
def test_no_credential_is_inline_in_a_non_secret_manifest(path: Path) -> None:
    """Only the gitignored `*secrets*.yaml` files may carry credential values. Anywhere else the
    value is committed, and rotating it then means rewriting git history rather than replacing a
    Secret. Checks both the literal text and the env shape, because the usual leak in a k8s
    manifest is `- name: X_PASSWORD` followed by a plain `value:` rather than a `valueFrom:`."""
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0] if not raw.lstrip().startswith("#") else ""
        assert not _SECRET_KEY.search(line), (
            f"{path.name}:{n} sets a credential inline: {raw.strip()!r} — this file is committed, "
            f"so move it to a gitignored *secrets*.yaml and reference it with secretRef/secretKeyRef")
        assert not _CREDENTIALED_URL.search(line), (
            f"{path.name}:{n} embeds credentials in a URL: {raw.strip()!r} — a committed "
            f"connection string cannot be rotated without rewriting git history")

    for env in _collect(_docs(path), "env"):
        for entry in env if isinstance(env, list) else []:
            if isinstance(entry, dict) and _SECRETISH_ENV.search(str(entry.get("name", ""))):
                assert "value" not in entry, (
                    f"{path.name}: env {entry['name']} carries a literal `value:` — a credential-"
                    f"shaped variable must use valueFrom/secretKeyRef, or its value is committed")


def _manifests_with_workloads() -> list[Path]:
    """Every manifest that declares at least one Deployment/DaemonSet. The two NetworkPolicy files
    declare no workload, and asserting "declares no Deployment" against them would be a false
    failure rather than a caught gap."""
    out = []
    for path in _manifests():
        try:
            if _deployments(path):
                out.append(path)
        except Exception:  # noqa: BLE001 - a malformed manifest is caught by the parse tests
            continue
    return out


@pytest.mark.parametrize("path", _manifests_with_workloads(), ids=lambda p: p.name)
def test_every_workload_in_every_manifest_is_bounded_and_probed(path: Path) -> None:
    """THE CAUSE, not the symptom. The two tests above covered only the manifests added alongside
    them, so `deploy.yaml` — the file holding the actual application — was exempt. Under that
    exemption all three celery workers shipped with NO probe of any kind, in both namespaces, and
    nothing anywhere said so.

    That is what made it survive: the gap was not a wrong value someone could spot in review, it
    was an absent key in a file no assertion looked at. A dashboard would have shown the queue
    growing; only this makes the next probe-less worker impossible to merge.

    Parametrised over every manifest rather than named one by one, for the same reason: a fourth
    deployment file added later is covered with nothing to remember."""
    _assert_bounded_and_probed(path)
