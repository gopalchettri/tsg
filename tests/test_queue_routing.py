"""Every routed queue must have a worker subscribed to it, in EVERY launch surface.

WHY THIS FILE EXISTS: the app now routes its heavy operator jobs (technique rebuild, library
import, embeddings, grounding calibration) to a dedicated `admin` queue, because sharing one
queue with user-facing work was measured dragging live generation from ~355s to 967s while the
rebuild itself was killed at its time limit.

That split introduces a failure mode the single-queue design could not have: if no worker
consumes a routed queue, the API still returns 202 and the job NEVER RUNS. No error, no
timeout, no log — a silent black hole. And there are FIVE places a worker is launched
(start.ps1, two compose files, the OpenShift manifest, plus the handbook that documents them),
so "updated compose, forgot deploy.yaml" is the obvious way for that to happen.

These tests are cheap, need no services, and fail loudly on exactly that mistake.
"""
from __future__ import annotations

import pathlib
import re

import yaml

from app.pipeline.celery_app import ADMIN_QUEUE, DEFAULT_QUEUE, celery_app

_ROOT = pathlib.Path(__file__).resolve().parents[1]


def _routed_queues() -> set[str]:
    """Every queue a task can land on: the routed ones plus the default."""
    routes = celery_app.conf.task_routes or {}
    return {r["queue"] for r in routes.values()} | {DEFAULT_QUEUE}


def _queues_from_command(argv: list[str]) -> set[str]:
    """Queues a `celery worker` argv subscribes to. No -Q means ALL queues."""
    out: set[str] = set()
    for i, tok in enumerate(argv):
        if tok in ("-Q", "--queues") and i + 1 < len(argv):
            out.update(q.strip() for q in str(argv[i + 1]).split(","))
        elif str(tok).startswith("--queues="):
            out.update(q.strip() for q in str(tok).split("=", 1)[1].split(","))
    return out


def _compose_workers(path: str) -> dict[str, list[str]]:
    doc = yaml.safe_load((_ROOT / path).read_text(encoding="utf-8"))
    return {name: svc["command"] for name, svc in doc["services"].items()
            if "command" in svc and "worker" in svc["command"]}


def _k8s_workers() -> dict[str, list[str]]:
    """EVERY manifest under deploy/, not just deploy.yaml.

    This globs on purpose. The first version of this test read deploy/deploy.yaml alone and
    passed while deploy/deploy.ai-remediation.yaml ran a second celery-worker with no -Q at all
    — consuming the SAME external Redis broker, so it silently drained the `admin` queue and the
    split was fake in that namespace. A path list is a promise to remember; a glob is not.
    """
    out = {}
    for path in sorted((_ROOT / "deploy").glob("*.yaml")):
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if not doc or doc.get("kind") != "Deployment":
                continue
            containers = doc["spec"]["template"]["spec"].get("containers") or []
            if not containers:
                continue
            cmd = containers[0].get("command") or []
            if "worker" in cmd:
                out[f"{path.name}:{doc['metadata']['name']}"] = [str(c) for c in cmd]
    return out


def test_the_admin_queue_is_actually_routed_to():
    """If this fails the split was undone — everything is back on one queue."""
    assert ADMIN_QUEUE in _routed_queues()
    assert ADMIN_QUEUE != DEFAULT_QUEUE


def test_every_routed_queue_has_a_consumer_in_docker_compose():
    for path in ("docker/compose.prod.yml", "docker/compose.demo.yml"):
        covered: set[str] = set()
        for argv in _compose_workers(path).values():
            covered |= _queues_from_command(argv)
        missing = _routed_queues() - covered
        assert not missing, f"{path}: no worker consumes {sorted(missing)} — jobs would vanish"


def test_every_routed_queue_has_a_consumer_in_openshift():
    covered: set[str] = set()
    for argv in _k8s_workers().values():
        covered |= _queues_from_command(argv)
    missing = _routed_queues() - covered
    assert not missing, f"deploy/deploy.yaml: no worker consumes {sorted(missing)}"


def test_every_routed_queue_has_a_consumer_in_start_ps1():
    """Read the WORKER LAUNCH LINES, not the whole file.

    A file-wide regex passes on `-Q celery` appearing anywhere — including inside one of this
    repo's (many, long) explanatory comments. That would let the real launch line lose its -Q
    while the test stayed green.
    """
    launch_lines = [ln for ln in (_ROOT / "start.ps1").read_text(encoding="utf-8").splitlines()
                    if "-m celery" in ln and " worker " in ln and not ln.strip().startswith("#")]
    assert launch_lines, "no celery worker launch line found in start.ps1"
    covered: set[str] = set()
    for ln in launch_lines:
        for group in re.findall(r"-Q\s+([A-Za-z0-9_,-]+)", ln):
            covered.update(group.split(","))
    missing = _routed_queues() - covered
    assert not missing, (
        f"start.ps1: no worker LAUNCH LINE consumes {sorted(missing)} "
        f"(found {len(launch_lines)} launch lines)")

    unscoped = [ln.strip()[:80] for ln in launch_lines if "-Q" not in ln]
    assert not unscoped, f"start.ps1 worker line with no -Q consumes every queue: {unscoped}"


def test_no_launch_surface_leaves_a_worker_unscoped():
    """A worker with no -Q consumes EVERY queue, which silently re-merges the split — the
    pipeline worker would go back to picking up 51 MB rebuilds. Catching this is the whole
    point: it looks harmless in a diff and undoes the change completely."""
    surfaces = {
        **{f"compose.prod:{k}": v for k, v in _compose_workers("docker/compose.prod.yml").items()},
        **{f"compose.demo:{k}": v for k, v in _compose_workers("docker/compose.demo.yml").items()},
        **{f"openshift:{k}": v for k, v in _k8s_workers().items()},
    }
    unscoped = [name for name, argv in surfaces.items() if not _queues_from_command(argv)]
    assert not unscoped, f"worker(s) with no -Q consume every queue: {unscoped}"


# --- the gevent bootstrap belongs ONLY to the gevent worker ---------------------------------
# Cost a live hang to learn: the admin worker was pointed at app.pipeline.celery_worker, which
# runs gevent's monkey.patch_all() before any other import. With -P solo/prefork there is no
# gevent hub to drive those patched calls, so the worker connected, registered its tasks,
# completed mingle — and then hung forever inside worker_init's blocking model load. It never
# printed "ready", and /ready correctly showed workers_admin: error.
#
# The rule: `celery_worker` is the -A target for the GEVENT pool only. Everything else (beat,
# and the admin worker) uses the unpatched `celery_app`. start.ps1 already documents this for
# beat; this test makes it enforceable.

def _pool_of(argv: list[str]) -> str:
    for i, tok in enumerate(argv):
        if tok in ("-P", "--pool") and i + 1 < len(argv):
            return str(argv[i + 1])
        if str(tok).startswith("--pool="):
            return str(tok).split("=", 1)[1]
    return "prefork"


def _app_target(argv: list[str]) -> str:
    for i, tok in enumerate(argv):
        if tok == "-A" and i + 1 < len(argv):
            return str(argv[i + 1])
    return ""


def test_only_gevent_workers_use_the_gevent_bootstrap():
    surfaces = {
        **{f"compose.prod:{k}": v for k, v in _compose_workers("docker/compose.prod.yml").items()},
        **{f"compose.demo:{k}": v for k, v in _compose_workers("docker/compose.demo.yml").items()},
        **{f"openshift:{k}": v for k, v in _k8s_workers().items()},
    }
    wrong = [
        f"{name} (pool={_pool_of(argv)}, -A {_app_target(argv)})"
        for name, argv in surfaces.items()
        if "celery_worker" in _app_target(argv) and _pool_of(argv) != "gevent"
    ]
    assert not wrong, (
        "non-gevent worker(s) using the gevent bootstrap — these hang silently during boot: "
        f"{wrong}")


def test_start_ps1_admin_worker_avoids_the_gevent_bootstrap():
    line = next(ln for ln in (_ROOT / "start.ps1").read_text(encoding="utf-8").splitlines()
                if "-Q admin" in ln)
    assert "celery_worker" not in line, (
        "start.ps1's admin worker uses the gevent bootstrap with a non-gevent pool — it will "
        "hang after 'mingle: sync complete' and never become ready")


# --- documented commands count as launch surfaces too ---------------------------------------
# The runbooks are how a human starts the stack by hand. Three of them documented ONE unscoped
# worker and no admin worker long after the executable surfaces were fixed, so anyone following
# them re-merged the queues on their own machine and saw the pre-split behaviour. A command in a
# README that people paste is a launch surface whether or not a script runs it.

_RUNBOOKS = ("README.md", "readme_to_run.txt", "readme_to_run_uat_prod.txt")


def _documented_worker_lines(name: str) -> list[str]:
    text = (_ROOT / name).read_text(encoding="utf-8")
    return [ln for ln in text.splitlines()
            if "celery" in ln and " worker" in ln
            and not ln.lstrip().startswith("#") and "inspect" not in ln]


def test_runbooks_document_a_consumer_for_every_routed_queue():
    for name in _RUNBOOKS:
        lines = _documented_worker_lines(name)
        assert lines, f"{name}: no worker command found — did it move?"
        covered: set[str] = set()
        for ln in lines:
            for group in re.findall(r"-Q\s+([A-Za-z0-9_,-]+)", ln):
                covered.update(group.split(","))
        missing = _routed_queues() - covered
        assert not missing, f"{name} documents no worker for {sorted(missing)}"


def test_runbooks_never_document_an_unscoped_worker():
    for name in _RUNBOOKS:
        unscoped = [ln.strip()[:90] for ln in _documented_worker_lines(name) if "-Q" not in ln]
        assert not unscoped, (
            f"{name} documents a worker with no -Q — anyone pasting it consumes every queue "
            f"and undoes the split locally: {unscoped}")


# --- the prefork boot guard must ask the RIGHT question --------------------------------------
# This one nearly shipped. The guard raised on ANY prefork pool, with a message about gevent
# already being monkey-patched — a condition it never actually tested. That was harmless while
# every worker ran -P gevent, and became a boot-killer the moment the `admin` queue's worker
# started running -P prefork against the UNPATCHED celery_app (compose.prod.yml, compose.demo.yml,
# deploy.yaml all launch it that way). Correct configuration, refused at startup, and the failure
# mode is the silent one: the API keeps returning 202 for jobs nothing will ever run.
# Caught only because a prefork worker was simulated; the local dev worker uses -P solo.

def test_prefork_is_refused_only_when_gevent_is_actually_patched(monkeypatch):
    from gevent import monkey

    from app.pipeline.celery_app import forking_a_patched_process

    # gevent NOT patched — the admin worker's real configuration. Must be allowed.
    monkeypatch.setattr(monkey, "is_module_patched", lambda _m: False)
    assert forking_a_patched_process("celery.concurrency.prefork") is False

    # gevent patched (i.e. launched via celery_worker) — the genuine hazard. Must be refused.
    monkeypatch.setattr(monkey, "is_module_patched", lambda _m: True)
    assert forking_a_patched_process("celery.concurrency.prefork") is True

    # Non-forking pools are never the hazard, patched or not.
    for pool in ("celery.concurrency.gevent", "celery.concurrency.solo"):
        assert forking_a_patched_process(pool) is False


def test_the_guard_consults_the_patch_state_not_just_the_pool():
    """Structural backstop: if the is_module_patched call is ever dropped, the guard silently
    reverts to refusing every prefork worker — including the admin one."""
    import inspect

    from app.pipeline import celery_app as mod

    src = inspect.getsource(mod.forking_a_patched_process)
    assert "is_module_patched" in src, (
        "the prefork guard no longer checks whether gevent is patched — it will refuse the "
        "admin worker, which legitimately runs -P prefork on the unpatched app")


# --- a launched worker must also be STOPPABLE -----------------------------------------------
# Symmetric to the launch-surface tests above, and it earns its place from history: Flower was
# added to start.ps1 with no stop.ps1 entry and "survived every stop.ps1 and kept running
# indefinitely" (stop.ps1's own comment). The admin worker was the same — launched by start.ps1,
# invisible to stop.ps1 — until this guard. Every worker start.ps1 opens a window for must have a
# matching label in stop.ps1's kill list AND stop_run.ps1's verification list, or a stop leaves
# it running and reports success.

def _start_ps1_window_titles() -> set[str]:
    text = (_ROOT / "start.ps1").read_text(encoding="utf-8")
    # Start-InNewWindow ... -WindowTitle 'tsg-xxx'
    return set(re.findall(r"-WindowTitle\s+'([^']+)'", text))


def _stop_labels(filename: str) -> set[str]:
    text = (_ROOT / filename).read_text(encoding="utf-8")
    # the [ordered]@{ 'label' = @(...) } keys
    block = text[text.index("[ordered]@{"):]
    block = block[: block.index("}")]
    return set(re.findall(r"^\s*'([^']+)'\s*=", block, re.M))


def test_every_started_window_can_be_stopped():
    started = _start_ps1_window_titles()
    assert "tsg-celery-admin" in started, "start.ps1 no longer opens the admin worker window?"
    for filename in ("stop.ps1", "stop_run.ps1"):
        labels = _stop_labels(filename)
        missing = started - labels
        assert not missing, (
            f"{filename} has no entry for window(s) start.ps1 opens: {sorted(missing)} — "
            f"a stop would leave them running (see the Flower note in stop.ps1)")


def test_the_admin_worker_is_matched_by_its_unique_queue_flag():
    """The window match only catches a live launcher; an orphaned worker whose window was closed
    is caught by '-Q admin'. Pin that token so the orphan path is not silently dropped."""
    for filename in ("stop.ps1", "stop_run.ps1"):
        text = (_ROOT / filename).read_text(encoding="utf-8")
        assert "'-Q admin'" in text or '"-Q admin"' in text, (
            f"{filename} no longer matches the admin worker by its -Q admin flag — an orphaned "
            "admin worker (window closed by hand) would survive the stop")
