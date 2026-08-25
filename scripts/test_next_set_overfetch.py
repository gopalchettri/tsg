"""Self-check: the next-set additive ask is buffered and the exclusion list is uncapped.

Run:  .venv/Scripts/python.exe scripts/test_next_set_overfetch.py

Assert-based, no framework — same style as the other scripts/ self-checks.

Guards the two halves of the one-call duplicate fix:
  1 _coverage_exclusions sends the FULL session history (no 50-item truncation), newest-first,
    deduped, blanks dropped — the model can never re-propose a threat it wasn't told about.
  2 tasks._gap_ask sizes the GENERATION call to survive dedup loss: a multiple of the shortfall,
    floored at the shortfall, with NO foreign cap.

    Revised deliberately. This half used to read "cascade._buffered_ask ... capped at
    max_threats_per_asset". That cap silently defeated the buffer whenever
    max_threats_per_asset < 2 x next_set_size (the shipped dev config), because it clamped a
    DELIVERY buffer with a per-call IDENTIFICATION ceiling. The buffer now lives inside
    find_threats' Stage 1b, where the loss actually happens, so every caller benefits and no two
    settings have to be kept in a ratio.
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import get_settings
from app.pipeline.cascade import _coverage_exclusions
from app.pipeline.tasks import _gap_ask


def main() -> None:
    budget = get_settings().exclusions_char_budget
    # 1 — uncapped: every distinct label of a 120-threat session reaches the prompt.
    threats = [{"threat_name": f"Threat {i}"} for i in range(120)]
    labels = _coverage_exclusions(threats)
    assert len(labels) == 120, f"expected 120 labels, got {len(labels)} — truncation is back"
    assert labels[0] == "Threat 0" and labels[-1] == "Threat 119", "input order not preserved"
    print("1 OK  120/120 labels pass through, order preserved — no truncation")

    # 1b — anti-runaway ceiling: admission is newest-first under the configured budget, so a
    # runaway session keeps its NEWEST labels (the list head) and drops only the oldest tail.
    big = [{"threat_name": f"Threat {i:04d} " + "x" * 60} for i in range(600)]
    capped = _coverage_exclusions(big)
    assert 0 < len(capped) < 600, f"budget did not bind ({len(capped)})"
    names = [t["threat_name"] for t in big]
    assert capped == names[:len(capped)], "must keep the newest prefix, drop only the oldest"
    assert sum(len(lbl) + 2 for lbl in capped) <= budget
    print(f"1b OK  600-threat runaway trimmed to newest {len(capped)} within the char budget")

    # 2 — dedup keeps first occurrence, blanks dropped, library label preferred (threat_label).
    mixed = [{"library_threat_name": "Lib A", "threat_name": "Raw A"},
             {"threat_name": "B"}, {"threat_name": "B"}, {"threat_name": ""}]
    assert _coverage_exclusions(mixed) == ["Lib A", "B"], _coverage_exclusions(mixed)
    print("2 OK  dedup first-wins, blank dropped, library label preferred")

    # 3 — generation ask arithmetic: a multiple of the shortfall, floored, uncapped.
    factor = get_settings().gap_generation_buffer
    assert _gap_ask(0) == 0                                  # nothing needed, nothing asked
    assert _gap_ask(3) == max(3, math.ceil(3 * factor))       # normal: buffered
    assert _gap_ask(1) >= 1                                   # smallest shortfall still valid
    assert _gap_ask(5) >= 5 and _gap_ask(50) >= 50             # NEVER below the shortfall
    # THE regression: the ask must not be clamped by max_threats_per_asset. That clamp is what
    # made "show more 5" deliver 4 whenever the ceiling was below 2 x next_set_size.
    assert _gap_ask(5) > get_settings().max_threats_per_asset or factor == 1.0         or 5 * factor <= get_settings().max_threats_per_asset,         "gap ask must be sized by the shortfall alone, never by max_threats_per_asset"
    print(f"3 OK  ask={factor}x shortfall, floored at shortfall, no per-asset cap")

    print("\nnext-set overfetch self-check OK")


if __name__ == "__main__":
    main()
