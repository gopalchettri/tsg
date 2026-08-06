"""Runnable proof that coverage-driven variant eligibility TERMINATES.

    python -m app.db.coverage_selfcheck

Why this file exists: removing `max_scenarios_per_threat` removed the only thing that guaranteed
"generate next set" ever stops. The replacement — an identity stays eligible while it has an
uncovered plausible entry point — terminates only because of two properties that cannot be
verified by reading dal.variant_eligible_primaries:

  1. plausibility is FROZEN at first declaration, so the target set never grows while it is being
     filled (union-growth livelocks: fill one cell, declare another, forever);
  2. an attempts bound closes an identity whose scenarios keep re-using one entry point.

There is no test suite in this repo, so this is the only executable guard on that proof. It
drives the REAL dal fold through a fake session — no DB, no network, no test framework.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

from app.core.enums import ScenarioStatus
from app.db.dal import _entry_ids, variant_eligible_primaries


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _FakeSession:
    """Answers the ONE SELECT variant_eligible_primaries still issues (Scoped_Threat). The
    scenario rows are passed in by the caller now — that is the single-read change, and this
    fake would break loudly if a second query were ever reintroduced."""

    def __init__(self, scoped_rows):
        self._responses = [scoped_rows]

    def execute(self, _stmt):
        return _FakeResult(self._responses.pop(0) if self._responses else [])


def _output(identity, number, entry_id, plausible, status=ScenarioStatus.complete):
    payload = {}
    if entry_id is not None:
        payload["entry_point_id"] = entry_id
    if plausible is not None:
        payload["plausible_entry_point_ids"] = plausible
    return SimpleNamespace(IdentityHash=identity, ScenarioNumber=number, Status=status,
                        ScopedThreatID=f"scoped-{identity}", ScenarioJSON=json.dumps(payload))


def _scoped(identity):
    return SimpleNamespace(ScopedThreatID=f"scoped-{identity}", ThreatID=f"threat-{identity}",
                        Score=50.0, ScopeRank=1, Reason="", FactorsJSON=None,
                        SelectionKind=None)  # cloned like Reason — None on legacy primaries


def _eligible(rows, *, slack=2, n=10):
    sess = _FakeSession([_scoped(r.IdentityHash) for r in rows])
    return variant_eligible_primaries(sess, "sess", n, rows=rows, attempt_slack=slack)


def demo() -> None:
    # 1. TERMINATION — a threat with 3 plausible entry points closes after all 3 are used, and
    #    earns exactly 3 scenarios: the depth is the architecture's, not a constant's.
    rows = [_output("A", 1, 11, [11, 22, 33])]
    for round_no in range(2, 12):
        used = {e for r in rows for e in _entry_ids(r.ScenarioJSON, "entry_point_id")}
        nxt = next(iter(sorted({11, 22, 33} - used)), None)
        if nxt is None:
            break  # nothing left to cover; eligibility is asserted false after the loop
        # An OPEN cell exists, so this must still be eligible — that is the "no arbitrary cap"
        # property: a 3-entry-point threat is never cut short at 2.
        assert _eligible(rows), f"closed at round {round_no} with cell {nxt} still open"
        rows.append(_output("A", round_no, nxt, None))
    assert not _eligible(rows), "all 3 entry points covered but still eligible — DOES NOT TERMINATE"
    assert len(rows) == 3, f"expected 3 scenarios (one per entry point), got {len(rows)}"

    # 2. NO LIVELOCK — a later scenario declaring NEW plausible ids must not reopen the target.
    grown = [_output("B", 1, 11, [11, 22]),
            _output("B", 2, 22, [11, 22, 33, 44, 55])]  # model tries to widen the target
    assert not _eligible(grown), ("plausibility grew after first declaration — every round would "
                                "fill one cell and open another, looping forever")

    # 3. ATTEMPTS BOUND — the model keeps answering with the SAME entry point.
    stuck = [_output("C", 1, 11, [11, 22, 33])]
    guard = 0
    while _eligible(stuck):
        guard += 1
        assert guard < 100, "attempts bound never fired — unbounded generation on a stuck cell"
        stuck.append(_output("C", len(stuck) + 1, 11, None))  # never reaches 22 or 33
    assert len(stuck) == 3 + 2, f"expected len(plausible)+slack=5 rows, got {len(stuck)}"

    # 4. MONOTONICITY — the uncovered count strictly decreases as scenarios accumulate.
    seq, prev = [_output("D", 1, 11, [11, 22, 33, 44])], 4
    for i, eid in enumerate((22, 33, 44), start=2):
        seq.append(_output("D", i, eid, None))
        used = {e for r in seq for e in _entry_ids(r.ScenarioJSON, "entry_point_id")}
        now = len({11, 22, 33, 44} - used)
        assert now < prev, f"uncovered went {prev} -> {now}: not monotone, may not converge"
        prev = now
    assert prev == 0 and not _eligible(seq)

    # 5. FAIL CLOSED — a row with no declared coverage target (written before coverage existed,
    #    or one where the model honestly evidenced no entry point) earns NO further variants.
    #    It must never fall back to "every system in the session is plausible": that would hand
    #    the deepest analysis to the threats with the least evidence, and the vocabulary is
    #    rebuilt per call from live curator data, so the target would not be frozen either.
    legacy = [_output("E", 1, None, None)]
    assert not _eligible(legacy), "undeclared target must fail closed, not inherit a vocabulary"

    # 6. FROZEN ACROSS REGENERATION — replacing scenario #1 must not re-open a covered threat.
    #    Drives the PRODUCTION WRITER (tasks._ground_entry_points must copy the frozen
    #    declaration onto a regenerated primary, ignoring the wider live vocabulary), not just
    #    the read side — the previous version of this case asserted the same hand-built list
    #    twice, so deleting `frozen` from the writer passed every check.
    from app.pipeline.tasks import _ground_entry_points  # local: heavy deps stay off module load
    covered = [_output("G", 1, 5, [5, 7]), _output("G", 2, 7, [5, 7])]
    assert not _eligible(covered), "both cells filled - should be closed"
    vocab = {"db": 5, "hmi": 7, "vpn": 12, "jump": 14}  # live vocab has GROWN since the freeze
    fresh = {"entry_point": "db", "other_plausible_entry_points": ["vpn", "jump"]}
    _ground_entry_points(fresh, vocab, frozen=[5, 7])
    assert fresh["plausible_entry_point_ids"] == [5, 7], (
        f"regenerated primary re-derived {fresh['plausible_entry_point_ids']} from the live "
        "vocabulary instead of inheriting the frozen [5, 7]")
    regenerated = [_output("G", 1, fresh["entry_point_id"], fresh["plausible_entry_point_ids"]),
                _output("G", 2, 7, [5, 7])]
    assert not _eligible(regenerated), ("a regenerated primary re-opened a fully covered threat - "
                                        "the declaration was re-derived instead of inherited")
    # NEGATIVE CONTROL — the same write WITHOUT the freeze must widen the target and re-open
    # the threat; if it doesn't, the assertion above is vacuous and guards nothing.
    unfrozen = {"entry_point": "db", "other_plausible_entry_points": ["vpn", "jump"]}
    _ground_entry_points(unfrozen, vocab, frozen=None)
    widened = [_output("G", 1, unfrozen["entry_point_id"], unfrozen["plausible_entry_point_ids"]),
            _output("G", 2, 7, [5, 7])]
    assert _eligible(widened), "negative control failed: an unfrozen write must re-open coverage"

    # 7. A failure card alone earns no variant — no sibling text to steer against.
    only_error = [_output("F", 1, 11, [11, 22], status=ScenarioStatus.error)]
    assert not _eligible(only_error)

    print("coverage self-check OK: terminates, no livelock, attempts bounded, monotone, "
        "legacy rows degrade safely")


if __name__ == "__main__":
    demo()
