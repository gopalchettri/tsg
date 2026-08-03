"""Contract tests for the codes and settings this API publishes.

None of these exercise behaviour — they pin the things that drift SILENTLY:

- a reason code whose `_REASON_INFO` entry is missing renders as `{detail: None, message: None}`
  rather than raising, so a typo ships an event with no user-facing text and nothing fails;
- a gate reason that acquires a `_REASON_INFO` entry would quietly reshape every 409 body;
- a new `Settings` field that nobody adds to the env files is invisible until an environment
  behaves differently from the one it was tested in.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.core.config import Settings
from app.core.enums import ClickOutcomeReason, ReviewGateReason
from app.pipeline import cascade


def test_every_click_outcome_reason_has_user_facing_text():
    """A code with no entry degrades to a null message instead of raising (see
    cascade._reason_info's docstring), so only this test can catch the omission."""
    missing = [r for r in ClickOutcomeReason if r not in cascade._REASON_INFO]
    assert not missing, f"ClickOutcomeReason members with no _REASON_INFO entry: {missing}"
    for reason in ClickOutcomeReason:
        info = cascade._reason_info(reason)
        assert info["detail"], f"{reason} has no developer-facing detail"
        assert info["message"], f"{reason} has no end-user message"


def test_reason_info_has_no_orphan_keys():
    """The other direction: an entry whose code no longer exists is dead text that reads as
    supported. Every key must be a real member."""
    known = {str(r) for r in ClickOutcomeReason}
    orphans = sorted(set(cascade._REASON_INFO) - known)
    assert not orphans, f"_REASON_INFO keys matching no ClickOutcomeReason member: {orphans}"


def test_gate_reasons_stay_out_of_reason_info():
    """Deliberate, and easy to undo by accident. Gate 409s carry `reason` plus the exception's own
    message and NO detail/message pair (errors.py merges only non-None values), so adding entries
    here would silently change the shape of every accept/regenerate conflict body."""
    leaked = [r for r in ReviewGateReason if str(r) in cascade._REASON_INFO]
    assert not leaked, f"ReviewGateReason members must not have _REASON_INFO entries: {leaked}"


def test_reason_lookup_works_with_plain_strings():
    """_REASON_INFO is consulted with a `reason` read off an exception — a plain str, never an
    enum member. StrEnum makes that work; this pins it so a future switch to a plain Enum (whose
    members do NOT compare equal to their value) can't silently blank every message."""
    assert cascade._reason_info(str(ClickOutcomeReason.no_new_threats_found))["message"]
    assert cascade._reason_info(ClickOutcomeReason.no_new_threats_found)["message"]
    assert cascade._reason_info("not-a-real-code") == {"detail": None, "message": None}
    assert cascade._reason_info(None) == {"detail": None, "message": None}


# --- config <-> env parity ----------------------------------------------------------------------
_ENV_FILES = (".env", ".env.example", ".env.uat", ".env.prod.example")

# Fields deliberately absent from the env files. KEEP THIS EMPTY where possible: every entry is a
# setting an operator cannot discover without reading config.py, which is how `.env.uat` ended up
# tuning pool sizes and concurrency caps that no other environment documented.
_UNDOCUMENTED: set[str] = set()


def _settings_fields() -> set[str]:
    return set(Settings.model_fields)


def _env_keys(path: Path) -> set[str]:
    """Keys present in an env file, INCLUDING commented-out ones — a documented default a reader
    can see and uncomment is the point; being live is not."""
    return set(re.findall(r"^\s*#?\s*([A-Z][A-Z0-9_]*)\s*=", path.read_text(encoding="utf-8"), re.M))


def _accepted_names(field: str) -> set[str]:
    """Every env spelling that resolves this field: the TSG_-prefixed default plus any explicit
    AliasChoices name (several settings are read from unprefixed vars for back-compat)."""
    names = {f"TSG_{field}".upper(), field.upper()}
    alias = getattr(Settings.model_fields[field], "validation_alias", None)
    if isinstance(alias, str):
        names.add(alias.upper())
    for choice in getattr(alias, "choices", None) or ():
        names.add(str(choice).upper())
    return names


@pytest.mark.parametrize("env_file", _ENV_FILES)
def test_every_setting_is_documented_in_each_env_file(env_file):
    """Each environment must document the same KEY SET; values are expected to differ. Without
    this, a setting added today is discoverable in dev and simply absent in uat/prod, and the
    difference surfaces only as divergent runtime behaviour."""
    path = Path(__file__).resolve().parents[1] / env_file
    if not path.exists():
        pytest.skip(f"{env_file} not present in this checkout")
    keys = _env_keys(path)
    missing = sorted(f for f in _settings_fields() - _UNDOCUMENTED if not (_accepted_names(f) & keys))
    assert not missing, f"{env_file} does not document {len(missing)} setting(s): {missing}"


def test_undocumented_allowlist_has_no_stale_entries():
    """Guards the guard: an allow-list entry for a field that no longer exists silently exempts
    nothing and hides that the real exemption was never revisited."""
    stale = sorted(_UNDOCUMENTED - _settings_fields())
    assert not stale, f"_UNDOCUMENTED names fields that no longer exist: {stale}"
