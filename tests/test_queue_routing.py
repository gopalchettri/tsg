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


#: The admin-authenticated API modules. Every Celery job they enqueue is an operator job by
#: definition — it is reachable only with the admin key — so it belongs on the admin queue.
_ADMIN_API_MODULES = ("app/api/admin.py", "app/api/threat_intel.py")

#: Tasks an admin route can enqueue that nevertheless BELONG on the default queue. Each one is
#: listed with its reason, because an unexplained entry here is indistinguishable from the accident
#: this test exists to catch — and the first version of this test found BOTH of these, which is how
#: the reasoning came to be written down at all.
#:
#: `tsg.intel_refresh_feed` — quoted from celery_app.py's own queue-split comment: "deliberately
#:   STAYS on the default queue -- it is short and I/O-bound, exactly what gevent is for, and beat
#:   schedules its fan-out."
#: `tsg.map_controls_sweep` — NOT an operator job despite having an admin route. It is the RETRY
#:   mechanism that finishes user-facing work: a scenario whose mapping pass was interrupted has no
#:   controls until the sweep maps them, so this is pipeline completion, not maintenance. Beat
#:   publishes it on a timer (`map-controls-sweep`) so it runs on the default queue regardless of the
#:   admin route, and routing the admin path elsewhere would make one trigger behave differently
#:   from the other for no reason. It is bounded by `control_mapping.SWEEP_LIMIT` (5 scenarios), so
#:   it cannot monopolise a worker the way an unbounded calibration or a 51 MB STIX parse can.
_ADMIN_TASKS_ALLOWED_ON_THE_DEFAULT_QUEUE = {"tsg.intel_refresh_feed", "tsg.map_controls_sweep"}


def _task_names_by_function() -> dict[str, str]:
    """`calibrate_control_map_task` -> `tsg.calibrate_control_map`, read from the decorators.

    Static, from the source text, so this needs no broker and cannot be satisfied by a task that
    merely got imported. The decorator and its `def` can be several lines apart (bind, autoretry_for
    and time limits all wrap), so the name is carried forward to the next function definition."""
    source = (_ROOT / "app" / "pipeline" / "celery_app.py").read_text(encoding="utf-8")
    out: dict[str, str] = {}
    pending: str | None = None
    for line in source.splitlines():
        found = re.search(r'name="(tsg\.[a-z_]+)"', line)
        if found:
            pending = found.group(1)
        defined = re.match(r"def ([a-z_]+_task)\(", line)
        if defined and pending:
            out[defined.group(1)] = pending
            pending = None
    return out


def _tasks_enqueued_from(module: str) -> set[str]:
    """Every `<something>_task.delay(...)` / `.apply_async(...)` in one module, as function names."""
    source = (_ROOT / module).read_text(encoding="utf-8")
    return set(re.findall(r"\b([a-z_]+_task)\s*\.\s*(?:delay|apply_async)\s*\(", source))


def test_every_task_an_admin_route_enqueues_runs_on_the_admin_queue() -> None:
    """THE OTHER DIRECTION. Every other test in this file checks route -> worker: that a queue named
    in `task_routes` has a consumer somewhere. None of them could see a heavy admin job that was
    never ROUTED at all — it simply lands on the default queue and competes with live generation,
    which is the exact harm the split exists to prevent (measured: generation 355s -> 967s).

    That hole was not theoretical. `tsg.calibrate_control_map` shipped with no `task_routes` entry
    and was caught on 2026-09-25 running 20+ minutes on the DEFAULT queue — holding a user-facing
    worker slot — while its identical sibling `tsg.calibrate_grounding` was routed correctly. Every
    test in this file passed throughout, because "is it routed?" was nobody's question.

    Derived from what the admin modules ACTUALLY enqueue, never from a hand-maintained list, so the
    next admin job is covered the day someone writes its route handler rather than the day someone
    remembers this file."""
    names = _task_names_by_function()
    assert len(names) >= 10, (
        f"only {len(names)} task names parsed from celery_app.py — the decorator regex has drifted, "
        "and this test would then pass by finding nothing to check")

    routes = celery_app.conf.task_routes or {}
    unrouted: list[str] = []
    for module in _ADMIN_API_MODULES:
        enqueued = _tasks_enqueued_from(module)
        assert enqueued, f"no enqueue call found in {module} — the call regex has drifted"
        for func in sorted(enqueued):
            task = names.get(func)
            assert task, (f"{module} enqueues {func}, which has no @celery_app.task name in "
                          "celery_app.py — one of the two regexes is wrong")
            if task in _ADMIN_TASKS_ALLOWED_ON_THE_DEFAULT_QUEUE:
                continue
            if (routes.get(task) or {}).get("queue") != ADMIN_QUEUE:
                unrouted.append(f"{task} (enqueued by {module}::{func})")
    assert not unrouted, (
        "admin-only jobs are publishing to the DEFAULT queue, where they compete with user-facing "
        f"generation: {sorted(unrouted)}. Add each to celery_app.task_routes with "
        "{'queue': ADMIN_QUEUE}, or — if it is genuinely short and I/O-bound — name it in "
        "_ADMIN_TASKS_ALLOWED_ON_THE_DEFAULT_QUEUE with the reason.")


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


# --- the API must actually RELOAD ------------------------------------------------------------
# Auto-reload used to be opt-in (`if ($Reload.IsPresent)`), so a plain .\start.ps1 served whatever
# the code looked like at launch. That is not a comfort feature: a whole session's fixes can be
# correct on disk and green in this suite while the running API still answers with the old code,
# which reads as "the fix does not work" rather than "the server was never restarted".
#
# There are TWO entry points and they must agree. run.ps1 forwards `-Reload:$Reload`, binding the
# switch EXPLICITLY — so expressing the default as `[switch]$Reload = $true` in start.ps1 would be
# silently cancelled on every plain .\run.ps1, which is the launcher that skips Docker and the one
# most likely to be used. The default therefore lives in a computed $useReload, and these tests
# pin both halves.


def _ps_code(filename: str) -> str:
    """PowerShell source with comments stripped — the <# .. #> help block and every `#` line.

    These scripts are ~60% commentary and the word "reload" appears all over it. A substring test
    against the raw text would pass on the help block alone, exactly the trap the worker-launch
    test at the top of this file documents.
    """
    text = (_ROOT / filename).read_text(encoding="utf-8")
    text = re.sub(r"<#.*?#>", "", text, flags=re.S)
    return "\n".join(ln for ln in text.splitlines() if not ln.strip().startswith("#"))


def test_the_api_reloads_by_default_and_never_via_uvicorns_own_reloader():
    """Two things, and the second is the one that bites.

    (1) Auto-reload is ON by default for '.env'. Without it a plain .\\start.ps1 serves whatever
        the code looked like at launch, so a fix can be correct on disk and green in this suite
        while the running API still answers with the old code.

    (2) It must NOT be uvicorn's `--reload`. Measured 2026-09-24: uvicorn's in-process reloader
        dies on its FIRST restart on this machine, taking the console process group with it and
        leaving nothing on the port — with and without the Tee pipe, with
        WATCHFILES_FORCE_POLLING=1, and with --reload-delay 1. A five-line ASGI app failed the
        same way, so it is the environment, not TSG. `watchfiles` supervising uvicorn from
        outside survives repeated reloads, so that is what the launcher uses.

    Reaching for `--reload` again is the regression this stops: it looks obviously right in a
    diff and turns the first save of the day into a silent outage.
    """
    code = _ps_code("start.ps1")

    launch = [ln for ln in code.splitlines() if "-m uvicorn" in ln]
    assert launch, "no uvicorn launch line found in start.ps1 — did it move?"

    assert not re.search(r"--reload\b", code), (
        "start.ps1 passes uvicorn's own --reload. It does not survive a restart on this machine "
        "(see the -NoReload help); supervise uvicorn with `watchfiles` instead.")
    assert "-m watchfiles" in code, (
        "start.ps1 no longer supervises the server with watchfiles — reload is either gone or "
        "back on uvicorn's broken in-process reloader")

    decision = [ln for ln in code.splitlines()
                if "$useReload" in ln and "=" in ln and "if (" not in ln]
    assert decision, "start.ps1 no longer computes $useReload — did the launch shape change?"
    assert "$isDefaultEnvFile" in decision[0], (
        f"reload is no longer on by default for .env: {decision[0]}")

    assert re.search(r"\[switch\]\$NoReload", code), (
        "start.ps1 lost -NoReload; there must be a way to turn the reloader off")
    assert not re.search(r"\[switch\]\$Reload\s*=\s*\$true", code), (
        "`[switch]$Reload = $true` cannot express a default: run.ps1 binds `-Reload:$Reload` "
        "explicitly, so a plain .\\run.ps1 passes -Reload:$false and cancels it. Compute it into "
        "$useReload instead.")


def test_the_run_docs_describe_the_reload_mechanism_that_is_actually_used():
    """SETUP_AND_RUN_GUIDE.md advertised `uvicorn --reload` as the dev web server. That was
    accurate once, wrong after the switch to a watchfiles supervisor, and pinned by nothing — so
    a reader following the guide would reach for the one mechanism that breaks here.

    Docs that describe a launch mechanism have to move with it, the same way the runbooks are
    already pinned to the queue consumers above.
    """
    for name in ("SETUP_AND_RUN_GUIDE.md", "readme_to_run.txt"):
        text = (_ROOT / name).read_text(encoding="utf-8")
        if "--reload" not in text:
            continue
        assert "watchfiles" in text, (
            f"{name} still presents `uvicorn --reload` as the way the dev server reloads, with no "
            "mention of the watchfiles supervisor that start.ps1 actually uses — and uvicorn's "
            "own reloader does not survive a restart here")


def test_the_run_wrapper_cannot_cancel_the_reload_default():
    code = _ps_code("run.ps1")

    delegation = [ln for ln in code.splitlines() if "start.ps1" in ln]
    assert delegation, "run.ps1 no longer delegates to start.ps1 — did it move?"

    assert re.search(r"\[switch\]\$NoReload", code), (
        "run.ps1 lost -NoReload, so the wrapper cannot turn the reloader off at all")
    assert "-NoReload:$NoReload" in code, (
        "run.ps1 does not forward -NoReload to start.ps1 — .\\run.ps1 -NoReload would be accepted "
        "and then silently ignored, which is worse than not offering the switch")


def test_the_admin_worker_is_matched_by_its_unique_queue_flag():
    """The window match only catches a live launcher; an orphaned worker whose window was closed
    is caught by '-Q admin'. Pin that token so the orphan path is not silently dropped."""
    for filename in ("stop.ps1", "stop_run.ps1"):
        text = (_ROOT / filename).read_text(encoding="utf-8")
        assert "'-Q admin'" in text or '"-Q admin"' in text, (
            f"{filename} no longer matches the admin worker by its -Q admin flag — an orphaned "
            "admin worker (window closed by hand) would survive the stop")
