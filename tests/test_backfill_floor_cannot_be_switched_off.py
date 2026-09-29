"""No loadable configuration may leave backfill without a floor.

WHY THIS EXISTS. Backfill trades precision for coverage: when too few controls clear the cutoff, the
best remaining ones are attached until `control_map_min_count` is reached. The FLOOR is what stops
that becoming "attach whatever ranked last" — a control with no relation to the scenario, shown to a
reviewer exactly like a genuine match.

That floor is now `control_map_backfill_ratio`, a fraction of the cutoff ACTUALLY in force, and its
`gt=0.0, lt=1.0` bounds ARE the guarantee: a fraction strictly between 0 and 1 of any positive cutoff
is strictly below it, so the band can never be empty, whichever of the three cutoff sources produced
the number (config.py cannot see two of them).

THE HOLE THIS PINS. The deprecated absolute that OUT-VOTES the ratio was bounded `ge=0.0`, so 0.0 was
an accepted pin — the replacement knob could not express "no floor" and the deprecated one it defers
to could. `TSG_CONTROL_MAP_BACKFILL_MIN_SCORE=0` is a natural reading of "the lowest score a control
may have" for an operator who wants maximum coverage, and it was honoured: `_backfill_floor` obeys any
pinned value strictly below the cutoff, and 0.0 always is. Worse, that is the branch that does NOT
log — unlike an override at or above the cutoff, a run with no floor at all was byte-identical in the
logs to a clean one. One asymmetric bound, silently undoing the guarantee the other two bounds make.
"""
from __future__ import annotations

import pytest

from app.core.config import Settings
from app.pipeline.control_mapping import _backfill_floor

_FLOOR_NAMES = ("TSG_CONTROL_MAP_BACKFILL_MIN_SCORE", "TSG_CONTROL_MAP_BACKFILL_RATIO")


def _from_env(monkeypatch, **env: str) -> Settings:
    """Real environment variables, not kwargs: the pinned-or-not distinction `_backfill_floor` reads
    is `model_fields_set`, and the environment is the only way an operator reaches it."""
    for name in _FLOOR_NAMES:
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return Settings(_env_file=None)


def test_a_pinned_absolute_floor_of_zero_is_refused_at_boot(monkeypatch):
    """THE regression. Zero is not a low floor, it is NO floor, and it was accepted in silence."""
    with pytest.raises(ValueError, match="control_map_backfill_min_score"):
        _from_env(monkeypatch, TSG_CONTROL_MAP_BACKFILL_MIN_SCORE="0")


def test_a_real_pinned_absolute_floor_still_loads_and_still_wins(monkeypatch):
    """The setting stays USABLE — it is deprecated, not withdrawn, and an operator who pinned a
    number keeps it. Refusing zero must not cost them that."""
    s = _from_env(monkeypatch, TSG_CONTROL_MAP_BACKFILL_MIN_SCORE="10")
    assert "control_map_backfill_min_score" in s.model_fields_set
    assert _backfill_floor(60.0, s) == 10.0


def test_the_ratio_cannot_express_no_floor_or_no_band(monkeypatch):
    """The bounds that ARE the guarantee, from both ends: 0 removes the floor, 1 empties the band by
    putting the floor level with the cutoff. Neither is loadable, at any cutoff."""
    for refused in ("0", "0.0", "1", "1.0"):
        with pytest.raises(ValueError, match="control_map_backfill_ratio"):
            _from_env(monkeypatch, TSG_CONTROL_MAP_BACKFILL_RATIO=refused)


def test_the_resolved_floor_is_positive_for_every_loadable_configuration(monkeypatch):
    """The behaviour itself, through the real resolver, at the cutoff this deployment runs on.

    Both branches: the ratio when the deprecated absolute is unset, and the absolute when it is
    pinned below the cutoff. The smallest values either knob will now accept still leave a floor."""
    cutoff = 50.0
    assert _backfill_floor(cutoff, _from_env(monkeypatch)) == pytest.approx(21.0)
    for pinned, ratio in (("0.1", None), ("49.9", None), (None, "0.001")):
        env = {k: v for k, v in (("TSG_CONTROL_MAP_BACKFILL_MIN_SCORE", pinned),
                                 ("TSG_CONTROL_MAP_BACKFILL_RATIO", ratio)) if v is not None}
        assert _backfill_floor(cutoff, _from_env(monkeypatch, **env)) > 0.0, env
