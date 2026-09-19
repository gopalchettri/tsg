"""A live scenario run never embeds the technique corpus; a background warm does, to completion.

THE BUG (18 Sep): the corpus's 900 passage vectors were not cached, so the first scenario lookup
embedded all of them inline — 14+ minutes on a CPU box before the run's first LLM call — and the
run was reaped while working. Now lookup is cache-only: not fully cached -> no technique block
this once (its documented fail-open) plus a throttled request for the admin-queue warm task, which
re-queues itself while it makes progress. "Cached" always means the SHARED store, the only one a
pipeline worker can read — never the warming process's own memory.
"""
from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from app.core.config import get_settings
from app.intel import technique_reference as tr
from app.pipeline import celery_app as ca
from app.pipeline import embeddings

_ENTRIES = [
    {"id": "T0831", "name": "Manipulation of Control", "description": "ot tampering",
     "source": "mitre_attack_ics", "stride": ["Tampering"], "applies_to": ["OT"]},
    {"id": "T1566", "name": "Phishing", "description": "it spoofing",
     "source": "mitre_attack", "stride": ["Spoofing"], "applies_to": ["IT"]},
    {"id": "T9999", "name": "Other", "description": "other",
     "source": "mitre_attack", "stride": ["Repudiation"], "applies_to": ["IT"]},
]
_TEXTS = [tr.passage_text(e, 1000) for e in _ENTRIES]
_UNIT = {t: v for t, v in zip(_TEXTS, ([1.0, 0, 0], [0, 1.0, 0], [0, 0, 1.0]))}


class _LLM:
    def __init__(self):
        self.embedded: Counter[str] = Counter()

    def embed(self, texts, *, kind):
        self.embedded.update(kind for _ in texts)
        return [_UNIT[t] if kind == "passage" else [1.0, 0.9, 0.8] for t in texts]


class _SharedStore:
    """Just enough of the Mongo `embeddings` collection: $in reads, upserts, $in counts."""

    def __init__(self):
        self.docs: dict[str, dict] = {}
        self.refuse_writes = False

    def find(self, q, *_a):
        return [self.docs[k] for k in q["k"]["$in"] if k in self.docs]

    def count_documents(self, q):
        return sum(k in self.docs for k in q["k"]["$in"])

    def bulk_write(self, ops):
        if self.refuse_writes:
            raise RuntimeError("write refused")
        for op in ops:
            self.docs[op._filter["k"]] = op._doc["$set"]


def _store_mode(monkeypatch, mode: str) -> None:
    monkeypatch.setenv("EMBEDDING_STORE", mode)
    get_settings.cache_clear()


@pytest.fixture
def shared(monkeypatch):
    _store_mode(monkeypatch, "mongo")
    store = _SharedStore()
    monkeypatch.setattr(embeddings, "_store_if_healthy", lambda: store)
    return store


@pytest.fixture
def corpus(monkeypatch):
    sent: list[str] = []
    monkeypatch.setattr(tr, "_corpus", lambda: (_ENTRIES, _TEXTS))
    monkeypatch.setattr(tr, "_warm_requested_at", None)
    monkeypatch.setattr(ca.celery_app, "send_task", lambda name, *a, **k: sent.append(name))
    return sent


@pytest.fixture
def no_redis(monkeypatch):
    """warm_live_corpus without Redis: the one-warmer lock always granted, and a fake model."""
    from app.core import joblock
    from app.pipeline import llm as llm_mod

    @contextmanager
    def _granted(_key, *, ttl, busy, redis_factory):
        yield

    fake = _LLM()
    monkeypatch.setattr(joblock, "job_lock", _granted)
    monkeypatch.setattr(llm_mod, "get_llm", lambda: fake)
    return fake


def test_a_cold_corpus_is_never_embedded_by_a_live_lookup(shared, corpus) -> None:
    llm = _LLM()
    assert tr.lookup(llm, "tampering with a PLC") == []          # fail-open: no block this once
    assert tr.lookup(llm, "phishing an operator") == []
    assert llm.embedded["passage"] == 0, "a live lookup embedded the corpus"
    assert corpus == [tr.WARM_TASK], "the warm must be requested exactly once (throttled)"


def test_once_warmed_the_lookup_hits_without_embedding_the_corpus(shared, corpus) -> None:
    llm = _LLM()
    assert tr.warm(llm, _TEXTS, budget_s=60) == (3, True)
    llm.embedded.clear()
    hits = tr.lookup(llm, "tampering with a PLC")
    assert [h["id"] for h in hits][:1] == ["T0831"]
    assert llm.embedded == Counter(query=1)
    assert corpus == []


def test_a_warm_that_runs_out_of_budget_resumes_where_it_stopped(shared, monkeypatch) -> None:
    llm = _LLM()
    clock = iter([0.0, 1.0, 100.0])                   # deadline, batch 1 ok, batch 2 too late
    # A NESTED patch context: monkeypatch.undo() would also revert conftest's Mongo stub and let
    # the second warm write to the real store. Only this module's clock is faked, not time's.
    with monkeypatch.context() as mp:
        mp.setattr(tr, "_WARM_BATCH", 1)
        mp.setattr(tr, "time", SimpleNamespace(monotonic=lambda: next(clock)))
        assert tr.warm(llm, _TEXTS, budget_s=10) == (1, False)
    assert tr.warm(llm, _TEXTS, budget_s=60) == (3, True)
    assert llm.embedded["passage"] == 3, "the resumed warm re-embedded what was already paid for"


def test_a_warm_is_judged_by_the_shared_store_not_its_own_memory(shared, corpus, no_redis) -> None:
    """Mongo refuses the writes: the vectors exist only in the warming process. That is NOT warm —
    no pipeline worker can read them — and the chain must stop rather than recompute the whole
    budget every few seconds. Once writes work again, the next warm persists them even though its
    own memory already held every vector (it used to count those as done, for good)."""
    shared.refuse_writes = True
    out = tr.warm_live_corpus(budget_s=60)
    assert (out["warmed"], out["complete"], out["continue"]) == (0, False, False)
    shared.refuse_writes = False
    no_redis.embedded.clear()
    out = tr.warm_live_corpus(budget_s=60)
    assert (out["warmed"], out["complete"], out["progress"]) == (3, True, 3)
    assert no_redis.embedded["passage"] == 3, "vectors held only in memory were never persisted"


def test_without_a_shared_store_the_worker_warms_itself(monkeypatch, corpus) -> None:
    """EMBEDDING_STORE=memory: a warm in another process could never reach this one, so the
    lookup computes the corpus here (once per process) and never asks the admin queue."""
    _store_mode(monkeypatch, "memory")
    llm = _LLM()
    hits = tr.lookup(llm, "tampering with a PLC")
    assert [h["id"] for h in hits][:1] == ["T0831"]
    assert llm.embedded["passage"] == 3
    assert corpus == []


@pytest.mark.parametrize("cont, requeued", [(True, 1), (False, 0)])
def test_the_warm_task_requeues_itself_only_while_it_progresses(monkeypatch, cont, requeued) -> None:
    queued = []
    monkeypatch.setattr(tr, "warm_live_corpus", lambda *, budget_s: {
        "total": 3, "warmed": 1, "progress": 1 if cont else 0, "complete": False, "continue": cont})
    monkeypatch.setattr(ca.warm_technique_reference_task, "apply_async",
                        lambda **kw: queued.append(kw))
    ca.warm_technique_reference_task.apply(throw=True)
    assert len(queued) == requeued


def test_only_one_warmer_runs_at_a_time(monkeypatch) -> None:
    """A warm that finds the lock held does no work, reports complete=None and queues nothing."""
    from app.core import joblock

    @contextmanager
    def _held(_key, *, ttl, busy, redis_factory):
        raise busy
        yield

    monkeypatch.setattr(tr, "_corpus", lambda: (_ENTRIES, _TEXTS))
    monkeypatch.setattr(joblock, "job_lock", _held)
    monkeypatch.setattr(tr, "warm", lambda *a, **k: pytest.fail("warmed without the lock"))
    out = tr.warm_live_corpus(budget_s=60)
    assert out["complete"] is None and out["continue"] is False


def test_status_reports_warm_only_when_the_shared_store_holds_every_passage(shared, monkeypatch) -> None:
    """Counted over the live corpus read, not this process's snapshot: an empty snapshot used to
    compare 0 >= 0 and report warm=true for a corpus no scenario could use."""

    class _Corpus(list):
        def sort(self, *_a):
            return self

        def limit(self, n):
            return _Corpus(self[:n])

    monkeypatch.setattr(tr, "_store_if_healthy",
                        lambda: SimpleNamespace(find=lambda *_a, **_k: _Corpus(_ENTRIES)))
    monkeypatch.setattr(tr, "_corpus", lambda: ([], []))          # empty/stale snapshot
    cold = tr.stats()
    assert (cold["total"], cold["vectors_cached"], cold["warm"]) == (3, 0, False)
    tr.warm(_LLM(), _TEXTS, budget_s=60)
    hot = tr.stats()
    assert (hot["vectors_cached"], hot["warm"]) == (3, True)
