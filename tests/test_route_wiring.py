"""Admin write routes that no test used to enter.

scripts/audit_route_wiring.py asks one question: does any test execute this route's body? For ten
WRITE routes the answer was no — so the line where each hands work to Celery was covered by
nothing. Delete it and the endpoint answers 202 with a job id while nothing is ever queued, and
the whole suite stays green. That is this codebase's characteristic defect: an operation that
reports success and does nothing. It cost a year on promote-to-library, and three more instances
turned up in 2026-09.

The route under test is ALWAYS the thing being driven; only the broker is faked. Each test records
what reached `apply_async` and asserts the ARGUMENTS, not the status code — a 202 is exactly what
a disconnected route returns.

WHY FAKING THE BROKER IS NOT FAKING THE TEST. These routes' whole job is to validate, then enqueue
the right work. The work itself belongs to the Celery task and has its own tests. What was
untested is the handoff, and the handoff is observable precisely as "these arguments reached
apply_async".

NEVER set celery_app.conf.task_always_eager in this file. Eager mode would RUN the queued task:
the embeddings 'delete' and 'recreate' branches reach embeddings.delete_cached, which issues a
real delete_many against the Mongo vector store, and 'recreate' would then re-embed the whole
library through the live provider. The destructive step lives inside the task, which a route test
must never invoke.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.api import admin as admin_api
from app.api import threat_intel as intel_api
from app.api.deps import Principal
from app.api.schemas import (
    EmbeddingActionBody,
    LibraryImportBody,
    TechniqueRebuildBody,
)


class _Request:
    """FastAPI Request stand-in — these routes read .client.host for their audit log only."""
    client = None


def _principal() -> Principal:
    return Principal(claims={"sub": "admin-1"}, entities=set(),
                    client_id="admin", tenant_id=None)


@pytest.fixture
def queued(monkeypatch):
    """Record what reaches the broker instead of reaching it. Returns the call list.

    Patches every enqueue seam these routes use, plus mark_admin_job (Redis) and the advisory
    is_held probe (Redis), so a test needs no broker, no Redis and no network.
    """
    calls: list[tuple[str, dict]] = []

    def _fake_task(name: str):
        return SimpleNamespace(apply_async=lambda *a, **k: (
            calls.append((name, k)), SimpleNamespace(id=f"job-{name}"))[1])

    monkeypatch.setattr(admin_api, "admin_embedding_action_task", _fake_task("embeddings"))
    monkeypatch.setattr(admin_api, "calibrate_grounding_task", _fake_task("calibrate"))
    monkeypatch.setattr(admin_api, "mark_admin_job", lambda *a, **k: None)
    monkeypatch.setattr(intel_api, "import_threat_library_task", _fake_task("import"))
    monkeypatch.setattr(intel_api, "rebuild_technique_reference_task", _fake_task("techniques"))
    monkeypatch.setattr(intel_api, "mark_admin_job", lambda *a, **k: None)
    monkeypatch.setattr(intel_api, "is_held", lambda *a, **k: False)
    monkeypatch.setattr(intel_api, "dispatch_refresh",
                        lambda feeds, user_id: (calls.append(("refresh", {"feeds": feeds})),
                                                {f: f"job-{f}" for f in feeds})[1])
    return calls


# --------------------------------------------------------------- embeddings admin (4 routes)

def _enqueued_action(queued) -> tuple[str, str | None, list | None]:
    """The (action, group, names) triple that reached the broker, or fail loudly."""
    assert len(queued) == 1, "the route must reach the broker exactly once"
    name, kwargs = queued[0]
    assert name == "embeddings"
    return kwargs["args"][0], kwargs["args"][1], kwargs["args"][2]


# One test per route rather than a parametrized loop over getattr(admin_api, name). Two reasons:
# each of the four has a DIFFERENT contract (update ignores names, recreate demands a group when
# names are given, delete refuses a bare {}), and scripts/audit_route_wiring.py can only see a
# route it is called by name — a getattr-dispatched call reads as "nobody enters this route",
# which is the very alarm this file exists to silence honestly.

def test_create_enqueues_the_create_action(queued):
    """The ACTION STRING is the whole payload of these four routes: they share one task and differ
    only in the verb. A route sending the wrong verb is indistinguishable at the HTTP layer — same
    202, same job-id shape — while 'recreate' wipes and re-embeds where 'update' only fills gaps."""
    resp = admin_api.create(EmbeddingActionBody(group="threat_type", names=["ACME-1"]),
                            _Request(), _principal())
    assert resp.job_id == "job-embeddings"
    assert _enqueued_action(queued) == ("create", "threat_type", ["ACME-1"])


def test_update_enqueues_the_update_action(queued):
    """Whole-group sync: fills what is missing, rebuilds nothing. group=None means every group."""
    admin_api.update(EmbeddingActionBody(group="threat_type"), _Request(), _principal())
    assert _enqueued_action(queued) == ("update", "threat_type", None)


def test_recreate_enqueues_the_recreate_action(queued):
    """Wipes then re-embeds. Sending 'update' here would leave stale vectors in place and report
    success; sending 'recreate' where 'update' was meant re-embeds the library for real money."""
    admin_api.recreate(EmbeddingActionBody(group="threat_type"), _Request(), _principal())
    assert _enqueued_action(queued) == ("recreate", "threat_type", None)


def test_delete_enqueues_the_delete_action(queued):
    """Wipes without re-embedding — the one action with no self-heal."""
    admin_api.delete(EmbeddingActionBody(group="threat_type", names=["ACME-1"]),
                    _Request(), _principal())
    assert _enqueued_action(queued) == ("delete", "threat_type", ["ACME-1"])


def test_delete_refuses_to_wipe_the_whole_cache(queued):
    """`{}` would mean 'every group, every name' — the entire cross-tenant vector cache. Unlike
    update and recreate, delete does not rebuild, so there is no self-heal. Validation must happen
    BEFORE the enqueue, or the refusal is a background job nobody is watching."""
    with pytest.raises(admin_api.AdminValidationError):
        admin_api.delete(EmbeddingActionBody(), _Request(), _principal())
    assert queued == [], "nothing may reach the broker when validation refused"


def test_create_requires_what_it_claims_to(queued):
    """create is the targeted action: without names there is nothing to target, and falling
    through to the task would queue a no-op the caller reads as success."""
    with pytest.raises(admin_api.AdminValidationError):
        admin_api.create(EmbeddingActionBody(group="threat_type"), _Request(), _principal())
    assert queued == []


# --------------------------------------------------------------- threat-intel admin

def test_import_library_enqueues_the_named_source(queued):
    """The source name decides which adapter runs and which Source tag every imported row
    carries. Enqueue the wrong one and hundreds of rows land mislabelled."""
    resp = intel_api.import_library(LibraryImportBody(dry_run=True), _Request(), "pytm",
                                    _principal())

    assert resp.job_id == "job-import"
    name, kwargs = queued[0]
    assert name == "import"
    assert kwargs["args"][0] == "pytm"
    assert kwargs["args"][1] is True, "dry_run must survive the handoff, or a dry run writes"


def test_import_library_rejects_an_unknown_source_before_enqueueing(queued):
    """Validation belongs on this call, not in a background job the caller has to go and poll."""
    with pytest.raises(admin_api.AdminValidationError):
        intel_api.import_library(LibraryImportBody(), _Request(), "not-a-source", _principal())
    assert queued == []


def test_refresh_all_feeds_fans_out(queued):
    """One job per feed, deliberately: a slow or broken feed must neither delay nor fail the
    others. A route that enqueued one job for all of them would lose that."""
    intel_api.refresh_all_feeds(_Request(), _principal())
    assert [n for n, _ in queued] == ["refresh"]
    assert queued[0][1]["feeds"], "at least one enabled feed must be dispatched"


def test_rebuild_techniques_enqueues_validated_sources(queued):
    """Unknown source names are a 422 here rather than a job that fails minutes later."""
    resp = intel_api.rebuild_techniques(TechniqueRebuildBody(), _Request(), _principal())
    assert resp.job_id == "job-techniques"
    assert [n for n, _ in queued] == ["techniques"]

    queued.clear()
    with pytest.raises(admin_api.AdminValidationError):
        intel_api.rebuild_techniques(TechniqueRebuildBody(sources=["nope"]), _Request(),
                                    _principal())
    assert queued == []


def test_calibrate_enqueues_a_sweep(queued, monkeypatch):
    """A sweep is 10-15 minutes and ~100 billed LLM calls, and this route is the ONLY way one ever
    starts — nothing schedules it. A disconnected route means calibration silently never happens
    and the grounding threshold quietly stays at whatever it already was."""
    # The ledger row is a DB dependency, not the seam under test: the route opens it BEFORE
    # queueing because the row IS the concurrency lock. Stub the write, leave the enqueue real —
    # patching apply_async instead would be patching the thing this test exists to pin.
    monkeypatch.setattr(admin_api.grounding, "record_calibration_started",
                        lambda *a, **k: "run-1")
    monkeypatch.setattr(admin_api, "_attach_job_id", lambda *a, **k: None)

    resp = admin_api.calibrate(_Request(), None, _principal())

    assert [n for n, _ in queued] == ["calibrate"]
    assert resp.job_id == "job-calibrate"
    assert resp.run_id == "run-1"
    args = queued[0][1]["args"]
    assert args[0] is False, "force must survive the handoff"
    assert args[3] == "run-1", "the task must be told which ledger row it owns"


def test_refresh_feed_dispatches_only_that_feed(queued):
    """Per-feed refresh exists so one broken feed can be re-pulled without touching the others.
    A route that fanned out to everything would be indistinguishable at the HTTP layer."""
    feed = next(iter(intel_api.enabled_feed_names()))
    intel_api.refresh_feed(feed, _Request(), _principal())
    assert [n for n, _ in queued] == ["refresh"]
    assert queued[0][1]["feeds"] == [feed], "only the named feed"
