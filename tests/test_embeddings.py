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

    def delete_many(self, filt):
        group = filt["group"]
        before = len(self.store)
        self.store = {k: d for k, d in self.store.items() if d.get("group") != group}
        return type("Result", (), {"deleted_count": before - len(self.store)})()


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


# ── delete_cached (admin "recreate" path — scripts/refresh_embeddings.py) ─────
def test_delete_cached_clears_l1_and_mongo_for_group(mongo_store, monkeypatch):
    col = _FakeCol([{"k": "a", "group": "g1"}, {"k": "b", "group": "g1"}, {"k": "c", "group": "g2"}])
    monkeypatch.setattr(embeddings, "_vector_store", lambda: col)
    stub = _Stub()
    embeddings.get_vectors(stub, ["x"], model_id="m", group="g1")  # populate L1 for g1
    embeddings.get_vectors(stub, ["y"], model_id="m", group="g2")  # populate L1 for g2

    deleted = embeddings.delete_cached("g1")

    assert deleted == 2  # both g1 Mongo docs gone
    assert list(col.store) == ["c"]  # g2's Mongo doc untouched
    embeddings.get_vectors(stub, ["x"], model_id="m", group="g1")  # L1 was cleared -> recomputes
    embeddings.get_vectors(stub, ["y"], model_id="m", group="g2")  # g2's L1 untouched -> no recompute
    assert stub.calls == [["x"], ["y"], ["x"]]


def test_delete_cached_returns_zero_when_mongo_unreachable(mongo_store, monkeypatch):
    monkeypatch.setattr(embeddings, "_vector_store", lambda: (_ for _ in ()).throw(RuntimeError("down")))
    assert embeddings.delete_cached("g1") == 0  # best-effort, never raises


# ── admin action functions (Part B — create/update/recreate/delete) ──────────
def test_active_names_returns_only_active_rows(db):
    from app.db import models as m

    names = embeddings._active_names(db, m.Threat_Type, m.Threat_Type.ThreatTypeName)
    assert "Firmware Tampering" in names and "Config Tampering" in names


def test_update_group_embeds_every_active_row(db, mem_store):
    stub = _Stub()
    count = embeddings.update_group(db, stub, "threat_type")
    assert count == 2
    assert set(stub.calls[0]) == {"Firmware Tampering", "Config Tampering"}


def test_create_items_embeds_only_the_named_items(db, mem_store):
    stub = _Stub()
    # names are now resolved against the ACTIVE master rows (see the canonicalization test
    # below), so this must name a real seeded catalogue row rather than an arbitrary string
    count = embeddings.create_items(db, stub, "threat_catalogue", ["Bootloader implant"])
    assert count == 1
    assert stub.calls == [["Bootloader implant"]]


def test_resolve_names_returns_every_stored_spelling_not_just_the_first():
    """[review-fix] The Mongo unique key is sha256(...|text), so two spellings of one name coexist
    as separate docs — exactly the duplicate the pre-fix create_items produced. Collapsing the fold
    index to one spelling deleted one doc and left the other live while reporting success, i.e. it
    re-created the silent-success symptom inside the fix itself."""
    stored = ["Denial of Service", "denial of service", "Firmware Tampering"]
    resolved, unmatched = embeddings._resolve_names(stored, ["DENIAL OF SERVICE"])
    assert sorted(resolved) == ["Denial of Service", "denial of service"]  # BOTH, not one
    assert unmatched == []


def test_group_lock_ttl_is_an_int_redis_rejects_floats():
    """[review-fix] redis-py raises DataError on a float for SET ex= / EXPIRE, so a float TTL made
    _group_lock raise on every acquire, hit its own fail-open handler, and never serialize anything
    — the per-group mutex was inert against a real Redis (the test fake tolerates floats)."""
    assert isinstance(embeddings._GROUP_LOCK_TTL_SECONDS, int)


def test_named_admin_actions_resolve_case_insensitively_and_reject_unknown_names(db, mem_store):
    """[canonicalization] The names come from MSSQL NVARCHAR columns (case- AND trailing-space-
    insensitive) but were used as byte-exact Mongo keys / cache-key text. So a name that looks
    identical in every UI matched nothing: create embedded an orphan vector under a key grounding
    never looks up, and delete/recreate removed nothing — all three reporting SUCCESS. Resolve to
    the master spelling, and make a genuinely unknown name an explicit failure."""
    import pytest

    stub = _Stub()
    # differently-cased + space-padded spelling of the seeded "Bootloader implant"
    count = embeddings.create_items(db, stub, "threat_catalogue", ["  bootloader IMPLANT "])
    assert count == 1
    assert stub.calls == [["Bootloader implant"]]  # embedded under the MASTER spelling, not the caller's

    # a name matching no master row must fail loudly instead of reporting a success count
    with pytest.raises(embeddings.UnknownEmbeddingNames, match="No Such Threat"):
        embeddings.create_items(db, stub, "threat_catalogue", ["No Such Threat"])
    with pytest.raises(embeddings.UnknownEmbeddingNames, match="No Such Threat"):
        embeddings.recreate_group(db, stub, "threat_catalogue", names=["No Such Threat"])


def test_recreate_group_clears_cache_then_reembeds(db, mem_store):
    from app.core.config import get_settings

    stub = _Stub()
    model_id = get_settings().embedding_model
    embeddings.get_vectors(stub, ["Firmware Tampering"], model_id=model_id, group="threat_type")
    assert stub.calls == [["Firmware Tampering"]]

    count = embeddings.recreate_group(db, stub, "threat_type")
    assert count == 2
    assert len(stub.calls) == 2  # a SECOND embed call proves the cache was cleared first
    assert "Firmware Tampering" in stub.calls[1]


def test_delete_group_clears_cache_without_reembedding(db, mem_store):
    from app.core.config import get_settings

    stub = _Stub()
    model_id = get_settings().embedding_model
    embeddings.get_vectors(stub, ["Firmware Tampering"], model_id=model_id, group="threat_type")
    assert stub.calls == [["Firmware Tampering"]]

    embeddings.delete_group(db, "threat_type")
    assert stub.calls == [["Firmware Tampering"]]  # delete_group never embeds

    embeddings.get_vectors(stub, ["Firmware Tampering"], model_id=model_id, group="threat_type")
    assert len(stub.calls) == 2  # cache was actually cleared — this had to recompute


class _FakeMongoCol:
    """Just enough of a pymongo collection for delete_cached: distinct() + delete_many()."""

    def __init__(self, texts):
        self.texts = list(texts)

    def distinct(self, field, query):
        return list(self.texts)

    def delete_many(self, query):
        wanted = query.get("text", {}).get("$in") if "text" in query else None
        hit = [t for t in self.texts if wanted is None or t in wanted]
        self.texts = [t for t in self.texts if t not in hit]

        class _R:
            deleted_count = len(hit)
        return _R()


def test_delete_of_already_clean_master_name_is_idempotent(db, mem_store, monkeypatch):
    """[fix 12] A name with no cached vector but a REAL active master row is 'already clean' —
    deleting it (again) must succeed with 0, not error. An operator's cleanup script may
    legitimately run twice; only genuine typos deserve a failure."""
    monkeypatch.setattr(embeddings, "_store_if_healthy", lambda: _FakeMongoCol([]))
    assert embeddings.delete_group(db, "threat_catalogue", names=["  bootloader IMPLANT "]) == 0
    assert embeddings.delete_group(db, "threat_catalogue", names=["Bootloader implant"]) == 0  # repeatable


def test_delete_of_totally_unknown_name_still_fails_loudly(db, mem_store, monkeypatch):
    """[fix 12] Unknown to BOTH the vector store and the masters = a typo. The loud failure that
    replaced the silent no-op-with-SUCCESS must survive the idempotency fix."""
    monkeypatch.setattr(embeddings, "_store_if_healthy", lambda: _FakeMongoCol([]))
    with pytest.raises(embeddings.UnknownEmbeddingNames, match="No Such Threat"):
        embeddings.delete_group(db, "threat_catalogue", names=["No Such Threat"])


def test_non_strict_delete_tolerates_a_name_that_is_no_longer_a_master_row(db, mem_store, monkeypatch):
    """The library CRUD API retires a vector AFTER renaming or soft-deleting its row, so the old
    text is by then neither a cached vector (if the group was never embedded) nor an ACTIVE
    master row — indistinguishable from a typo, and the strict path raised. That turned a
    curator's successful edit into a FAILED job on /embeddings/status.

    strict=False is the contract for machine-derived names: delete it if it is there, say nothing
    if it isn't. The typo check above still guards the human-facing admin route."""
    monkeypatch.setattr(embeddings, "_store_if_healthy", lambda: _FakeMongoCol([]))
    assert embeddings.delete_group(db, "threat_catalogue",
                                   names=["A Name Nothing Knows About"], strict=False) == 0


def test_delete_of_orphan_vector_without_master_row_still_works(db, mem_store, monkeypatch):
    """[fix 12] A vector can outlive its master row; clearing exactly that orphan is a legitimate
    delete and must not require a master row to exist."""
    fake = _FakeMongoCol(["Ghost Threat"])
    monkeypatch.setattr(embeddings, "_store_if_healthy", lambda: fake)
    assert embeddings.delete_group(db, "threat_catalogue", names=["ghost threat"]) == 1
    assert fake.texts == []  # the stored spelling was the one deleted


class _FakeLockRedis:
    """In-memory stand-in for the SET NX EX / GET / DELETE primitives _group_lock needs."""
    def __init__(self):
        self.store: dict[str, str] = {}

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.store:
            return False
        self.store[key] = value
        return True

    def get(self, key):
        return self.store.get(key)

    def delete(self, key):
        self.store.pop(key, None)


def test_group_lock_raises_embedding_busy_when_already_held(monkeypatch):
    fake = _FakeLockRedis()
    monkeypatch.setattr(embeddings, "_slot_redis", lambda: fake)
    with embeddings._group_lock("threat_type"):
        with pytest.raises(embeddings.EmbeddingBusy):
            with embeddings._group_lock("threat_type"):
                pass


def test_group_lock_releases_cleanly_after_use(monkeypatch):
    fake = _FakeLockRedis()
    monkeypatch.setattr(embeddings, "_slot_redis", lambda: fake)
    with embeddings._group_lock("threat_type"):
        pass
    assert fake.store == {}


def test_group_lock_never_deletes_a_different_holders_lock(monkeypatch):
    # TOCTOU guard: if our lock's TTL expired and a DIFFERENT process already re-acquired
    # the same key with a different token before we release, our release must not steal it.
    fake = _FakeLockRedis()
    monkeypatch.setattr(embeddings, "_slot_redis", lambda: fake)
    with embeddings._group_lock("threat_type"):
        fake.store["tsg:embed-lock:threat_type"] = "someone-elses-token"
    assert fake.store["tsg:embed-lock:threat_type"] == "someone-elses-token"


def test_group_lock_fails_open_when_redis_unavailable(monkeypatch):
    monkeypatch.setattr(embeddings, "_slot_redis", lambda: (_ for _ in ()).throw(ConnectionError("down")))
    with embeddings._group_lock("threat_type"):
        pass  # must not raise


def test_for_each_group_resolves_none_to_every_group():
    seen = []
    results = embeddings._for_each_group(None, lambda g: (seen.append(g), 1)[1])
    assert set(seen) == set(embeddings._GROUPS)
    assert results == {g: 1 for g in embeddings._GROUPS}


def test_for_each_group_isolates_one_groups_failure_from_the_other():
    def fn(g):
        if g == "threat_type":
            raise RuntimeError("boom")
        return 5

    results = embeddings._for_each_group(None, fn)
    assert results["threat_catalogue"] == 5
    assert results["threat_type"].startswith("error:")


def test_for_each_group_single_group_untouched():
    assert embeddings._for_each_group("threat_type", lambda g: 42) == {"threat_type": 42}


def test_for_each_group_propagates_embedding_busy_instead_of_swallowing_it():
    # EmbeddingBusy is a real conflict the HTTP layer must turn into a 409 (app/api/errors.py)
    # — unlike a generic per-group failure, it must NOT be caught into a results-dict string.
    def fn(g):
        raise embeddings.EmbeddingBusy("locked")

    with pytest.raises(embeddings.EmbeddingBusy):
        embeddings._for_each_group("threat_type", fn)


def test_for_each_group_propagates_llm_slot_unavailable_instead_of_swallowing_it():
    # A CONFIRMED, transient "no free LLM call slot" must reach admin_embedding_action_task's
    # autoretry_for (celery_app.py) — swallowing it into "error: ..." would misreport a
    # self-healing capacity squeeze as a permanent per-group failure.
    from app.pipeline.llm import LLMSlotUnavailable

    def fn(g):
        raise LLMSlotUnavailable("no free slot")

    with pytest.raises(LLMSlotUnavailable):
        embeddings._for_each_group("threat_type", fn)


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
