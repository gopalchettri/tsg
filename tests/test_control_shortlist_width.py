"""Control mapping must size its own shortlist — never borrow threat grounding's.

THE MEASURED BUG. `ground_control_queries` reranks only what the CHEAP shortlist stage hands it
(cosine top-K union BM25 top-K). Control mapping used to read `grounding_shortlist_k`, which is 10,
so **14-20 of 557 OT controls** ever reached the reranker. Against the real library, a real
Historian-exfiltration scenario scored best 51.99 at K=10 and nothing cleared the 55.0 cutoff — but
at K=60 it reranked 102 candidates and `Access Agreements` scored **65.86**. Same library, same
reranker, same threshold: the correct control existed and was thrown away before it could be
scored, and the empty result published as `controls: []`, which schemas.py documents in three
places as a genuine library gap.

The two knobs answer different questions. `grounding_shortlist_k` serves THREAT grounding — a short
label against a small candidate set, with thresholds auto-calibrated at its current value. Widening
that shared number to fix control mapping would silently move calibrated threat behaviour. So
control mapping got its own, and these tests pin that they cannot be re-merged by accident.
"""
from __future__ import annotations

import pytest

from app.core.config import get_settings
from app.pipeline import embeddings, grounding

CORPUS = 200


@pytest.fixture
def library(monkeypatch):
    """A 200-row fake control library whose vectors decay, so cosine order is deterministic."""
    rows = [{"ControlLibraryID": i, "ControlName": f"Control {i}",
             "text": f"Control {i} covering privileged access and audit logging"}
            for i in range(CORPUS)]
    # Force the dict path (no cached matrix), then hand it one vector per control.
    monkeypatch.setattr(embeddings, "get_matrix", lambda *a, **k: None)
    monkeypatch.setattr(embeddings, "get_vectors",
                        lambda llm, names, **k: {n: [1.0 - i / (CORPUS * 2), 0.1]
                                                for i, n in enumerate(names)})
    return rows


class _RecordingLLM:
    """Records how many documents the reranker was actually asked to score."""
    def __init__(self):
        self.widths: list[int] = []

    def embed(self, texts, kind=None):
        return [[1.0, 0.1] for _ in texts]

    def rerank_many(self, items, *, model=None):
        self.widths = [len(docs) for _q, docs in items]
        return [[float(len(docs) - i) for i in range(len(docs))] for _q, docs in items]


def _run(library, *, control_k: int, threat_k: int) -> int:
    """Return how many documents reached the reranker for one control-mapping query."""
    s = get_settings()
    llm = _RecordingLLM()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(s, "control_map_shortlist_k", control_k, raising=False)
        mp.setattr(s, "grounding_shortlist_k", threat_k, raising=False)
        mp.setattr(s, "semantic_match_threshold", 0.0, raising=False)
        grounding.ground_control_queries(llm, [("privileged access audit logging", [1.0, 0.1])],
                                        library, s)
    return llm.widths[0]


def test_control_mapping_reranks_its_own_width_not_the_threat_one(library):
    """THE regression. With the shared knob tiny and the control knob wide, control mapping must
    follow the CONTROL knob — that difference is the whole fix. Revert it and the reranker sees
    5 candidates out of 200, which is exactly how a 65.86 control got discarded unscored."""
    wide = _run(library, control_k=60, threat_k=5)
    assert wide >= 60, (
        f"reranker saw only {wide} of {CORPUS} controls — control mapping is still borrowing "
        "grounding_shortlist_k, so the accurate stage never sees most of the library")


def test_threat_groundings_knob_cannot_move_control_mapping(library):
    """The other half: `grounding_shortlist_k` is calibrated for threat grounding, so changing it
    must have NO effect here. If it does, the two knobs are still coupled and tuning one silently
    retunes the other."""
    assert _run(library, control_k=25, threat_k=5) == _run(library, control_k=25, threat_k=150)


def test_widening_the_control_knob_widens_what_gets_reranked(library):
    """Guards against a hard-coded width passing the test above by accident."""
    assert _run(library, control_k=10, threat_k=10) < _run(library, control_k=80, threat_k=10)


def test_boot_refuses_a_shortlist_narrower_than_the_controls_it_must_return():
    """The validator has to guard the CONTROL knob now. Checking grounding_shortlist_k would pass
    while the real limit silently capped every scenario below control_map_top_k."""
    from app.core.config import Settings
    with pytest.raises(ValueError, match="control_map_shortlist_k"):
        Settings(control_map_shortlist_k=2, control_map_top_k=5)
