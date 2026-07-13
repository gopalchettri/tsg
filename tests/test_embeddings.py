"""Unit tests for the master-library embedding cache (`embeddings.get_vectors`) — M2.

Model-free and Mongo-free: `EMBEDDING_STORE=memory` disables L2, and an in-test stub
supplies deterministic vectors. Covers the paths whose failures are silent (wrong values,
not crashes): each text maps to its OWN vector (the H1 alignment risk), the L1 hit path
(embed runs at most once per text), dedupe of repeated inputs, the M1 length guard, and
`clear_cache()` group scoping. The autouse `_clear_embed_cache` fixture (conftest) resets L1.
"""
from __future__ import annotations

import pytest

from app.pipeline import embeddings


def _vec(t: str) -> list[float]:
    """Deterministic, text-specific vector — distinct texts get distinct vectors, so a
    mis-alignment (a text paired with the wrong vector) is detectable by equality."""
    return [float(len(t)), float(sum(map(ord, t)))]


class _Stub:
    """Records every batch handed to `embed` so tests can assert dedupe / at-most-once."""

    def __init__(self, vecs: list[list[float]] | None = None):
        self.calls: list[list[str]] = []
        self._vecs = vecs  # fixed override (length-mismatch test); else one _vec per text

    def embed(self, texts, *, model=None, kind="query"):
        texts = list(texts)
        self.calls.append(texts)
        return self._vecs if self._vecs is not None else [_vec(t) for t in texts]


@pytest.fixture()
def mem_store(monkeypatch):
    """`EMBEDDING_STORE=memory` → `get_vectors` never touches Mongo (pure L1 + compute)."""
    monkeypatch.setenv("EMBEDDING_STORE", "memory")
    from app.core.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_each_text_maps_to_its_own_vector(mem_store):
    out = embeddings.get_vectors(_Stub(), ["alpha", "bb", "c"], model_id="m", group="g")
    assert out == {"alpha": _vec("alpha"), "bb": _vec("bb"), "c": _vec("c")}


def test_l1_hit_computes_at_most_once(mem_store):
    stub = _Stub()
    embeddings.get_vectors(stub, ["x", "y"], model_id="m", group="g")
    embeddings.get_vectors(stub, ["x", "y"], model_id="m", group="g")  # all L1 hits
    assert stub.calls == [["x", "y"]]  # second call embeds nothing


def test_dedupes_repeated_inputs_before_embedding(mem_store):
    stub = _Stub()
    out = embeddings.get_vectors(stub, ["x", "x", "y", "x"], model_id="m", group="g")
    assert stub.calls == [["x", "y"]]               # embed sees each unique text once
    assert out == {"x": _vec("x"), "y": _vec("y")}  # return still keyed by every input text


def test_length_mismatch_fails_loud(mem_store):
    stub = _Stub(vecs=[[1.0]])  # 1 vector for 2 texts → M1 guard, not an opaque KeyError
    with pytest.raises(RuntimeError, match="2 texts"):
        embeddings.get_vectors(stub, ["x", "y"], model_id="m", group="g")


def test_clear_cache_scopes_to_group(mem_store):
    stub = _Stub()
    embeddings.get_vectors(stub, ["x"], model_id="m", group="g1")
    embeddings.get_vectors(stub, ["x"], model_id="m", group="g2")
    embeddings.clear_cache(group="g1")                                 # drop only g1's L1
    embeddings.get_vectors(stub, ["x"], model_id="m", group="g1")      # recomputes g1
    embeddings.get_vectors(stub, ["x"], model_id="m", group="g2")      # g2 still cached
    assert stub.calls == [["x"], ["x"], ["x"]]  # g1 computed twice, g2 once


# ── L2 (MongoDB) tier ──────────────────────────────────────────────────────────
# `_vector_store()` is monkeypatched to a fake so these stay Mongo-free. They lock in the
# DEFAULT store path and, crucially, the two SILENT degradations: read/write failures are
# swallowed by design (a Mongo outage must never break grounding), so a regression there is
# invisible at runtime unless a test pins it.
class _FakeCol:
    """Minimal stand-in for the pymongo `embeddings` collection."""

    def __init__(self, docs=None, *, fail_read=False, fail_write=False):
        self.store = {d["k"]: d for d in (docs or [])}
        self.fail_read, self.fail_write = fail_read, fail_write
        self.writes = 0

    def find(self, query):
        if self.fail_read:
            raise RuntimeError("mongo read down")
        wanted = set(query["k"]["$in"])
        return [d for k, d in self.store.items() if k in wanted]

    def bulk_write(self, ops):
        if self.fail_write:
            raise RuntimeError("mongo write down")
        self.writes += len(ops)


@pytest.fixture()
def mongo_store(monkeypatch):
    """`EMBEDDING_STORE=mongo` → the L2 branch is live (with `_vector_store` faked per test)."""
    monkeypatch.setenv("EMBEDDING_STORE", "mongo")
    from app.core.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_l2_hit_serves_from_mongo_without_embedding(mongo_store, monkeypatch):
    k = embeddings._cache_key("m", "g", "passage", "x")  # get_vectors's default kind is 'passage'
    col = _FakeCol([{"k": k, "vector": [9.0, 9.0]}])
    monkeypatch.setattr(embeddings, "_vector_store", lambda: col)
    stub = _Stub()
    out = embeddings.get_vectors(stub, ["x"], model_id="m", group="g")
    assert out == {"x": [9.0, 9.0]}  # served the Mongo vector, not _vec("x")
    assert stub.calls == []          # embed never ran — L2 hit


def test_l2_miss_computes_and_writes_through(mongo_store, monkeypatch):
    col = _FakeCol([])  # empty store → every text misses
    monkeypatch.setattr(embeddings, "_vector_store", lambda: col)
    stub = _Stub()
    out = embeddings.get_vectors(stub, ["x", "y"], model_id="m", group="g")
    assert out == {"x": _vec("x"), "y": _vec("y")}
    assert stub.calls == [["x", "y"]]  # both computed
    assert col.writes == 2             # both upserted (write-through)


def test_l2_read_failure_degrades_to_compute(mongo_store, monkeypatch):
    # find() raises → swallowed → compute in-process, correct vectors still returned, no write.
    col = _FakeCol([], fail_read=True)
    monkeypatch.setattr(embeddings, "_vector_store", lambda: col)
    stub = _Stub()
    out = embeddings.get_vectors(stub, ["x"], model_id="m", group="g")
    assert out == {"x": _vec("x")} and stub.calls == [["x"]]
    assert col.writes == 0  # read failure flipped use_mongo off → no best-effort write attempt


def test_l2_write_failure_is_best_effort(mongo_store, monkeypatch):
    # bulk_write() raises → swallowed → caller still gets vectors (grounding never breaks).
    col = _FakeCol([], fail_write=True)
    monkeypatch.setattr(embeddings, "_vector_store", lambda: col)
    stub = _Stub()
    out = embeddings.get_vectors(stub, ["x"], model_id="m", group="g")
    assert out == {"x": _vec("x")} and stub.calls == [["x"]]


def test_l2_connect_failure_opens_breaker_so_outage_is_not_retried_per_call(mongo_store, monkeypatch):
    # _vector_store() itself failing (the connect+create_index handshake, not a query)
    # must trip the breaker: further calls within the cooldown skip _vector_store()
    # entirely instead of re-paying the handshake on every get_vectors() call.
    calls = {"n": 0}

    def _boom():
        calls["n"] += 1
        raise RuntimeError("mongo unreachable")

    monkeypatch.setattr(embeddings, "_vector_store", _boom)
    stub = _Stub()
    embeddings.get_vectors(stub, ["x"], model_id="m", group="g")
    embeddings.get_vectors(stub, ["y"], model_id="m", group="g")
    embeddings.get_vectors(stub, ["z"], model_id="m", group="g")
    assert calls["n"] == 1  # one handshake attempt for the whole outage window, not one per call
    assert stub.calls == [["x"], ["y"], ["z"]]  # grounding still gets vectors throughout
