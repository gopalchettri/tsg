"""embeddings.get_vectors: concurrent callers missing the same texts embed them ONCE.

THE BUG (18 Sep): four scenario workers each missed the same 900 cold technique passages and each
embedded all of them — 3,600 embeddings for 900 texts, 16 torch jobs on 12 cores. Now the first
caller fills the cache under a per-(model, group, kind) lock; the rest re-check it and reuse.
"""
from __future__ import annotations

import threading
import time
from collections import Counter

from app.core.config import get_settings
from app.pipeline import embeddings

TEXTS = ["alpha", "beta", "gamma"]


class _CountingLLM:
    def __init__(self):
        self.embedded: Counter[str] = Counter()
        self._lock = threading.Lock()

    def embed(self, texts, *, kind):
        with self._lock:
            self.embedded.update(texts)
        time.sleep(0.3)                      # a slow model: plenty of time for a peer to race
        return [[float(len(t)), 1.0] for t in texts]


def test_concurrent_callers_embed_each_text_once() -> None:
    llm, barrier, results = _CountingLLM(), threading.Barrier(3), []

    def caller():
        barrier.wait()                       # all three miss the cache at the same instant
        results.append(embeddings.get_vectors(llm, TEXTS, model_id="m", group="sf", kind="passage"))

    threads = [threading.Thread(target=caller) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert llm.embedded == Counter(TEXTS), f"texts embedded more than once: {llm.embedded}"
    assert all(r == results[0] and set(r) == set(TEXTS) for r in results)


def test_callers_missing_different_texts_never_wait_on_each_other() -> None:
    """Single-flight is per TEXT. A group-wide lock queued every scenario's own (unique) technique
    query behind the others — each holding it through an LLM-slot wait and a remote call — so
    N concurrent lookups took N x one embed instead of one."""
    class _Slow(_CountingLLM):
        def embed(self, texts, *, kind):
            time.sleep(0.2)                  # 0.5 s per embed in all: 3 in parallel ~0.5 s, in a row 1.5 s
            return super().embed(texts, kind=kind)

    get_settings()                           # build Settings outside the timed window
    llm, barrier = _Slow(), threading.Barrier(3)

    def caller(text):
        barrier.wait()
        embeddings.get_vectors(llm, [text], model_id="m", group="dj", kind="query")

    threads = [threading.Thread(target=caller, args=(t,)) for t in TEXTS]
    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert time.monotonic() - t0 < 1.0, "disjoint misses were serialised behind one lock"
    assert llm.embedded == Counter(TEXTS)


def test_a_failed_filler_never_strands_its_waiters() -> None:
    """The first caller's embed fails; the one waiting on the same texts must wake and fill them
    itself instead of returning short or waiting forever."""
    calls = []

    class _FailsFirst(_CountingLLM):
        def embed(self, texts, *, kind):
            calls.append(list(texts))
            if len(calls) == 1:
                time.sleep(0.2)
                raise RuntimeError("provider down")
            return super().embed(texts, kind=kind)

    llm, barrier, got, errors = _FailsFirst(), threading.Barrier(2), [], []

    def caller():
        barrier.wait()
        try:
            got.append(embeddings.get_vectors(llm, TEXTS, model_id="m", group="ff", kind="passage"))
        except RuntimeError as exc:
            errors.append(exc)

    threads = [threading.Thread(target=caller) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)
    assert len(errors) == 1 and len(got) == 1 and set(got[0]) == set(TEXTS)
    assert not embeddings._IN_FLIGHT, "an in-flight marker leaked"


def test_cache_only_mode_embeds_nothing() -> None:
    """compute=False (the technique lookup's mode) returns what is cached and pays for nothing."""
    llm = _CountingLLM()
    embeddings.get_vectors(llm, ["alpha"], model_id="m", group="co", kind="passage")
    got = embeddings.get_vectors(llm, TEXTS, model_id="m", group="co", kind="passage",
                                 compute=False)
    assert set(got) == {"alpha"}
    assert llm.embedded == Counter(["alpha"])
