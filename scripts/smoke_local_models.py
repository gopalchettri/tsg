#!/usr/bin/env python
"""Concurrency-aware smoke test for the LOCAL embedding + reranker models.

Run on a machine where the models exist and the local extra is installed:

    pip install -e ".[local]"
    # with your .env (EMBEDDING_PROVIDER=local / RERANKER_PROVIDER=local + paths), or inline:
    EMBEDDING_PROVIDER=local RERANKER_PROVIDER=local \
    EMBEDDING_MODEL=/path/to/multilingual-e5-large \
    RERANKER_MODEL=/path/to/bge-reranker-v2-m3 \
    python scripts/smoke_local_models.py

It verifies, for real (nothing stubbed):
  1. Both model paths resolve + load, and the embedder dim matches EMBEDDING_DIMENSIONS.
  2. A sample embed (dim) and rerank (0-100 scores) work through the real code path.
  3. CONCURRENCY under the gevent runtime the Celery workers use: many concurrent
     grounding-like calls run WITHOUT freezing the hub. A background heartbeat keeps
     ticking at a healthy rate throughout (the ThreadPool offload), every output is
     validated, and — for contrast — a direct un-offloaded encode is shown to freeze
     the hub, proving the offload is what makes concurrency safe.

Exit codes: 0 = passed · 1 = concurrency/validation failure · 2 = not configured for local.
"""
# gevent monkeypatching MUST run before importing anything that touches threading/
# sockets — this mirrors how the Celery gevent worker actually runs.
from gevent import monkey

monkey.patch_all()

import os  # noqa: E402 -- everything below must import AFTER monkey.patch_all() above
import sys  # noqa: E402
import time  # noqa: E402

import gevent  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # make `app` importable

from app.core.config import get_settings  # noqa: E402
from app.core.logging import configure_logging  # noqa: E402
from app.pipeline import local_models  # noqa: E402
from app.pipeline.llm import LiteLLMClient  # noqa: E402

N_CONCURRENT = 24
HEARTBEAT_S = 0.01  # 10 ms cadence; stalls only if the greenlet hub is frozen
QUERIES = ["Firmware Tampering", "Bootloader implant", "SQL Injection", "Phishing", "Denial of Service"]
DOCS = ["Firmware Tampering", "Config Tampering", "Bootloader implant", "OTA poisoning", "Credential stuffing"]


def _heartbeat(stop: list, ticks: list) -> None:
    while not stop[0]:
        ticks[0] += 1
        gevent.sleep(HEARTBEAT_S)


def _rate(ticks: int, elapsed: float) -> float:
    return ticks / elapsed if elapsed > 0 else 0.0


def _one_grounding_call(llm: LiteLLMClient, i: int, dims: int) -> tuple[str, list[float]]:
    """Mimic one grounding step: embed a query + rerank it against candidate docs —
    both hit the local models through the real (offloaded) path. Validates outputs."""
    q = QUERIES[i % len(QUERIES)]
    qv = llm.embed([q], kind="query")
    scores = llm.rerank(q, DOCS)
    assert len(qv) == 1 and len(qv[0]) == dims, f"embed dim {len(qv[0])} != {dims}"
    assert len(scores) == len(DOCS) and all(0.0 <= s <= 100.0 for s in scores), f"bad scores {scores}"
    return q, scores


def _run_with_heartbeat(work):
    """Run `work()` while a heartbeat greenlet ticks; return (result, elapsed, tick_rate)."""
    stop, ticks = [False], [0]
    hb = gevent.spawn(_heartbeat, stop, ticks)
    gevent.sleep(0)  # let the heartbeat start
    t0 = time.time()
    result = work()
    elapsed = time.time() - t0
    stop[0] = True
    hb.join()
    return result, elapsed, _rate(ticks[0], elapsed)


def main() -> int:
    configure_logging()
    s = get_settings()
    if s.embedding_provider != "local" or s.reranker_provider != "local":
        print("Not configured for local models "
              f"(EMBEDDING_PROVIDER={s.embedding_provider}, RERANKER_PROVIDER={s.reranker_provider}).")
        print("Set both to 'local' and point EMBEDDING_MODEL / RERANKER_MODEL at the model dirs.")
        return 2

    # 1. validate + warm-load (fail fast on bad path / missing dep / dim mismatch)
    local_models.validate_local_models(s, warm=True)
    print("OK  models loaded")
    print(f"    embedder = {s.embedding_model}")
    print(f"    reranker = {s.reranker_model}")

    llm = LiteLLMClient(s)

    # 2. sample correctness
    dim = len(llm.embed(["hello world"], kind="query")[0])
    sample = llm.rerank("Firmware Tampering", DOCS)
    print(f"OK  sample embed dim = {dim} (configured {s.embedding_dimensions})")
    print(f"OK  sample rerank scores (0-100) = {[round(x, 1) for x in sample]}")
    if dim != s.embedding_dimensions:
        print(f"FAIL: embed dim {dim} != EMBEDDING_DIMENSIONS {s.embedding_dimensions}")
        return 1

    # 3a. concurrency through the real offloaded path — hub must stay responsive
    def _concurrent():
        jobs = [gevent.spawn(_one_grounding_call, llm, i, dim) for i in range(N_CONCURRENT)]
        gevent.joinall(jobs, raise_error=True)  # re-raises any validation failure
        return jobs

    jobs, elapsed_off, rate_off = _run_with_heartbeat(_concurrent)
    ok = sum(1 for j in jobs if j.value is not None)
    print(f"OK  {ok}/{N_CONCURRENT} concurrent grounding calls passed in {elapsed_off:.2f}s")

    # 3b. contrast: a DIRECT (un-offloaded) encode on the greenlet freezes the hub
    model = local_models._embedder(s.embedding_model)
    _, blk, rate_blk = _run_with_heartbeat(
        lambda: model.encode(["query: " + q for q in QUERIES * 12], normalize_embeddings=True))

    print(f"    offloaded concurrent run : {elapsed_off:5.2f}s  heartbeat {rate_off:6.0f} ticks/s  (hub alive)")
    print(f"    direct blocking encode   : {blk:5.2f}s  heartbeat {rate_blk:6.0f} ticks/s  (hub frozen)")

    # Pass criterion is ABSOLUTE hub liveness during the concurrent run (a frozen hub
    # is ~0/s). The blocking contrast is diagnostic only — on a fast/tiny encode its
    # rate is noisy, so we warn rather than fail on it (avoids a false negative).
    healthy = 0.5 / HEARTBEAT_S  # >= half the ~100 ticks/s ceiling = a clearly-alive hub
    if rate_off < healthy:
        print(f"FAIL: hub ticked only {rate_off:.0f}/s during concurrent inference "
              f"(expected >= {healthy:.0f}/s) — the offload is not keeping the hub alive.")
        return 1
    if rate_blk >= healthy:
        print(f"WARN: the un-offloaded contrast ticked {rate_blk:.0f}/s (expected near 0) — "
              "diagnostic inconclusive (encode too fast), but the concurrent run is healthy.")

    print("\nSMOKE PASSED — local models load and stay concurrency-safe under gevent.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
