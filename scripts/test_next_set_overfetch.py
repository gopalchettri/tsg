"""Self-check: the next-set additive ask is buffered and the exclusion list is uncapped.

Run:  .venv/Scripts/python.exe scripts/test_next_set_overfetch.py

Assert-based, no framework — same style as the other scripts/ self-checks.

Guards the two halves of the one-call duplicate fix:
  1 _coverage_exclusions sends the FULL session history (no 50-item truncation), newest-first,
    deduped, blanks dropped — the model can never re-propose a threat it wasn't told about.
  2 _buffered_ask sizes the single additive call to survive dedup loss: 2x the shortfall,
    capped at max_threats_per_asset, floored at the shortfall.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.pipeline.cascade import _buffered_ask, _coverage_exclusions  # noqa: E402


def main() -> None:
    # 1 — uncapped: every distinct label of a 120-threat session reaches the prompt.
    threats = [{"threat_name": f"Threat {i}"} for i in range(120)]
    labels = _coverage_exclusions(threats)
    assert len(labels) == 120, f"expected 120 labels, got {len(labels)} — truncation is back"
    assert labels[0] == "Threat 0" and labels[-1] == "Threat 119", "input order not preserved"
    print("1 OK  120/120 labels pass through, order preserved — no truncation")

    # 2 — dedup keeps first occurrence, blanks dropped, library label preferred (threat_label).
    mixed = [{"library_threat_name": "Lib A", "threat_name": "Raw A"},
             {"threat_name": "B"}, {"threat_name": "B"}, {"threat_name": ""}]
    assert _coverage_exclusions(mixed) == ["Lib A", "B"], _coverage_exclusions(mixed)
    print("2 OK  dedup first-wins, blank dropped, library label preferred")

    # 3 — buffered ask arithmetic: 2x shortfall, capped, floored.
    assert _buffered_ask(3, 10) == 6    # normal: double the shortfall
    assert _buffered_ask(5, 10) == 10   # defaults: 2x5 hits the cap exactly
    assert _buffered_ask(5, 8) == 8     # cap binds
    assert _buffered_ask(5, 3) == 5     # floor: never below the shortfall (cap < shortfall tuning)
    assert _buffered_ask(1, 10) == 2    # smallest shortfall still gets headroom
    print("3 OK  ask=2x shortfall, capped at per-asset ceiling, floored at shortfall")

    print("\nnext-set overfetch self-check OK")


if __name__ == "__main__":
    main()
