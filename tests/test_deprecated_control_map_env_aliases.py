"""A RETIRED control-map env spelling must REFUSE THE BOOT, never be silently ignored.

WHY THIS EXISTS. `TSG_CONTROL_MAP_TOP_K` and `TSG_REMEDIATION_CONTROL_MIN_COUNT` used to be
`AliasChoices` entries on `control_map_max_count` and `control_map_min_count`, and this module pinned
that mapping because nothing else did: reorder either `AliasChoices`, drop an entry, or attach
`TSG_CONTROL_MAP_TOP_K` to the MINIMUM instead of the maximum, and the whole suite stayed green.

THE ALIASES ARE NOW GONE, on the repo owner's instruction — "this is confusing, the deprecated
TSG_CONTROL_MAP_TOP_K name is now an alias for the ceiling, not the floor ... delete it, and refuse to
boot if it is still set." The trap the aliases carried is why. `TSG_CONTROL_MAP_TOP_K` meant a hard cap
of 5 applied as `sorted(...)[:5]`; as an alias it supplied the CEILING, default 25. So the name said
"top 5" while feeding a bound five times larger, and an inherited `TSG_CONTROL_MAP_TOP_K=5` line
silently reinstated the 5-control truncation the min/max pair exists to remove. THAT ALREADY BIT THIS
DEPLOYMENT ONCE. A name that means the opposite of what it says cannot be documented safe.

DELETING AN ALIAS IS NOT ENOUGH ON ITS OWN, WHICH IS THE OTHER HALF OF THIS FILE. `extra="ignore"`
drops an undeclared env name with no exception, no warning and no log line, so a retired spelling left
in a `.env` or a cluster Secret would lose the operator's value to the code default and produce a run
byte-identical to a clean one. A retired name that is silently ignored is worse than one that is
wrong. So `Settings._refuse_retired_env_names` refuses the boot, naming the replacement, and these
tests pin that refusal.

EVERY TEST HERE SETS A REAL ENVIRONMENT VARIABLE, and for this refusal that is not a style
preference, it is the only thing that can fail. Constructor kwargs bypass validation aliases entirely
— `model_config` sets `populate_by_name=True`, so `Settings(control_map_max_count=7)` succeeds no
matter which alias is attached where, and an earlier probe of this exact area passed for that wrong
reason. A retired name is worse still: it has no field and no alias, so pydantic-settings'
`EnvSettingsSource` (which iterates the MODEL'S FIELDS and asks the environment for each) never looks
it up at all — it reaches neither `model_fields_set` nor `model_extra`. `os.environ` is the only place
a real boot's retired name exists, which is why the refusal lives in a `mode="before"` validator that
reads it, and why a test that does not touch the environment cannot see the refusal work or fail.
"""
from __future__ import annotations

import pytest

from app.core.config import RETIRED_ENV_NAMES, Settings

#: Every env spelling that touches the count pair, retired ones included. Cleared before each
#: construction so an ambient value in the developer's shell — or a .env line — cannot decide the
#: outcome of a test about precedence. `_env_file=None` covers the file; this covers the process
#: environment, and for a RETIRED name the process environment is the whole point.
_COUNT_NAMES = (
    "TSG_CONTROL_MAP_MIN_COUNT", "TSG_REMEDIATION_CONTROL_MIN_COUNT",
    "TSG_CONTROL_MAP_MAX_COUNT", "TSG_CONTROL_MAP_TOP_K",
    "TSG_CONTROL_MAP_SHORTLIST_K",
)


def _from_env(monkeypatch, **env: str) -> Settings:
    for name in _COUNT_NAMES:
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return Settings(_env_file=None)


@pytest.mark.parametrize(("retired", "replacement"), sorted(RETIRED_ENV_NAMES.items()))
def test_every_retired_env_name_refuses_the_boot(monkeypatch, retired: str, replacement: str):
    """THE regression, driven from the table so the next retirement is pinned the day it lands.

    The message must name BOTH the retired name (so the operator can find the line) and the
    REPLACEMENT (so they move the value instead of deleting it, which is the loss the refusal
    exists to prevent). Each table entry opens with its replacement's env name."""
    with pytest.raises(ValueError) as boom:
        _from_env(monkeypatch, **{retired: "5"})
    message = str(boom.value)
    assert retired in message
    assert replacement.split(",")[0] in message


def test_the_retired_top_k_is_not_quietly_accepted_as_either_bound(monkeypatch):
    """The specific inversion the aliases made possible, asserted as an absence.

    Were the alias ever restored — on the ceiling as it was, or on the floor by a slip — this would
    be a 5-control cap or a 5-control pad instead of a refusal. Both are silent; the refusal is not.
    """
    with pytest.raises(ValueError) as boom:
        _from_env(monkeypatch, TSG_CONTROL_MAP_TOP_K="5")
    assert "TSG_CONTROL_MAP_MAX_COUNT" in str(boom.value)


def test_the_replacement_names_still_work(monkeypatch):
    """The other side of the retirement: the surviving spellings are the ONLY spellings, and they
    land on the bound they name. A refusal that also broke the replacement would be a worse bug."""
    s = _from_env(monkeypatch, TSG_CONTROL_MAP_MAX_COUNT="7", TSG_CONTROL_MAP_SHORTLIST_K="60")
    assert s.control_map_max_count == 7
    assert s.control_map_min_count == 5, "the ceiling must not move the floor"
    assert "control_map_max_count" in s.model_fields_set, (
        "the env name must mark the FIELD as supplied — control_mapping keys several decisions on "
        "model_fields_set, and a value that arrives without being recorded is invisible there")
    assert _from_env(monkeypatch, TSG_CONTROL_MAP_MIN_COUNT="8").control_map_min_count == 8


def test_a_clean_environment_still_boots(monkeypatch):
    """The refusal reads os.environ on EVERY construction, so a bug there would refuse every boot in
    the project. This is the canary for that: no retired name set, no error, defaults intact."""
    s = _from_env(monkeypatch)
    assert (s.control_map_min_count, s.control_map_max_count) == (5, 25)


def test_a_minimum_above_the_ceiling_still_refuses(monkeypatch):
    """The coupled-count guard, which the retirement did NOT replace. It used to be reachable by
    accident through the alias (an old top_k=5 pinning the ceiling under a raised minimum); that
    route is now a refusal of its own, but a deliberate minimum above a deliberate ceiling is still
    a target that can never be met, and must still refuse."""
    with pytest.raises(ValueError, match="control_map_min_count"):
        _from_env(monkeypatch, TSG_CONTROL_MAP_MIN_COUNT="10", TSG_CONTROL_MAP_MAX_COUNT="5")


def test_a_minimum_equal_to_the_maximum_is_allowed(monkeypatch):
    """The bound is `<=`, not `<`. "Exactly N controls per scenario" is a coherent instruction, and
    a refusal here would be the validator inventing a policy nothing asked for."""
    assert _from_env(monkeypatch, TSG_CONTROL_MAP_MIN_COUNT="25",
                     TSG_CONTROL_MAP_MAX_COUNT="25").control_map_min_count == 25
