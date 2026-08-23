"""Session tuning: business calibration editable without a restart.

`get_settings()` is `@lru_cache`d, so a `.env` edit reaches nothing until every process
restarts — and the pipeline runs in Celery WORKERS, whose beat schedule even freezes settings
at import. `Config_Tuning` rows override config; the API resolves them ONCE at session
creation and freezes the result onto `Scenario_Session.TuningJSON`. Every later stage reads
the snapshot (`from_session`), so an edit applies to the NEXT session while a running
assessment keeps its rulebook — one assessment is never scored under two rulebooks, and "what
configuration produced this report?" is a stored column, not an inference.

An EMPTY Config_Tuning table resolves to pure config values — byte-identical behaviour, so
the rollout is a no-op until someone inserts a row.

HARD RULE: a tuning value may only be read inside SESSION-SCOPED work. Session-less work (the
intel-refresh beat task, the reaper) has no snapshot and takes its values from config.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from pydantic import ValidationError

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.core.messages import ApiMessage

log = get_logger(__name__)

#: Settings fields a Config_Tuning row may override — business calibration only ("how much
#: analysis, how strict"). Infrastructure, LLM/embedding model config and worker timing stay
#: in .env: they are needed before a DB connection exists, or a wrong value yields stuck jobs
#: rather than a worse report.
TUNABLE_KEYS: tuple[str, ...] = (
    "scoping_score_threshold", "base_score", "default_rule_weight", "max_threats_per_asset",
    "next_set_size", "coverage_attempt_slack",
    "variant_sibling_prompt_k", "prompt_intel_limit", "sibling_similarity_ratio",
    "semantic_near_duplicate_threshold", "triage_auto_reject_cosine",
    "triage_auto_approve_cosine",
)

#: Keys whose value is EMBEDDING-MODEL-SPECIFIC: an override row should name the model it was
#: tuned on (Config_Tuning.EmbeddingModel); on mismatch with the running model the row is
#: skipped with a warning and the config default applies — a number derived on another model
#: is noise, and a model swap must never brick session creation.
EMBEDDING_COUPLED_KEYS: frozenset[str] = frozenset({
    "semantic_near_duplicate_threshold", "triage_auto_reject_cosine",
    "triage_auto_approve_cosine",
})

#: The tunable keys whose canonical type is int. NOT derived from ResolvedTuning annotations
#: (strings under `from __future__ import annotations`) nor from config defaults (a None
#: default has no type) — an explicit list, checked by the selfcheck below.
_INT_KEYS: frozenset[str] = frozenset({
    "max_threats_per_asset", "next_set_size", "coverage_attempt_slack",
    "variant_sibling_prompt_k", "prompt_intel_limit",
})


def _coerce(key: str, value: Any) -> Any:
    """One value to its key's canonical type, or raise ValueError. int keys reject fractional
    floats (40.5 threats is nonsense, and int(40.5) would silently invent a policy); float
    keys accept ints; scoping_score_threshold accepts None ("no cutoff"). Without this, a
    Config_Tuning row declared ValueType='float' for an int key froze e.g. 40.0 into
    TuningJSON — and a float reaching pymongo's cursor.limit() or a slice made intel silently
    vanish from every scenario or errored the next-set stage."""
    if value is None and key == "scoping_score_threshold":
        return None
    if key in _INT_KEYS:
        iv = int(value)
        if iv != value:
            raise ValueError(f"{key} must be a whole number, got {value!r}")
        return iv
    return float(value)


@dataclass(frozen=True)
class ResolvedTuning:
    """The one immutable rulebook a session is assessed under. Built once per worker entry
    point from the session's TuningJSON snapshot (config fallback) and threaded as plain
    parameters into the helpers that consume each value — helpers never read get_settings()
    for these, or a Config_Tuning row would apply to some values and silently not others (a
    half-applied rulebook: the unreproducible-assessment failure the freeze exists to
    prevent)."""
    scoping_score_threshold: float | None
    base_score: float
    default_rule_weight: float
    max_threats_per_asset: int
    next_set_size: int
    coverage_attempt_slack: int
    variant_sibling_prompt_k: int
    prompt_intel_limit: int
    sibling_similarity_ratio: float
    semantic_near_duplicate_threshold: float
    triage_auto_reject_cosine: float
    triage_auto_approve_cosine: float


def _from_config(s: Settings) -> dict[str, Any]:
    return {k: getattr(s, k) for k in TUNABLE_KEYS}


def resolve_snapshot(overrides: Mapping[str, tuple[Any, str | None]]) -> dict[str, Any]:
    """Config defaults + active Config_Tuning overrides → the dict frozen onto
    `Scenario_Session.TuningJSON` at session creation. `overrides` maps
    key → (typed value, embedding_model) — see dal.active_tuning_overrides. Unknown keys,
    wrong-typed values, and embedding-coupled rows tuned on a different model are skipped with
    a warning (config default applies).

    Validation is the FULL Settings model re-run on the overridden values — every pydantic
    Field bound (ge/le) and every model_validator (scoring-floor invariant, triage bands, the
    top_n bind, …), never a hand-copied subset that drifts: a percent-scale triage band (80
    instead of 0.80) or a negative next_set_size must fail session creation exactly as it
    would fail startup from .env. Raises ValueError with the pydantic detail, surfacing to
    whoever edited the row. The returned dict carries the VALIDATED (coerced) values, so what
    gets frozen is what the pipeline will actually read."""
    s = get_settings()
    resolved = _from_config(s)
    for key, (value, emb_model) in overrides.items():
        if key not in resolved:
            log.warning("tuning.unknown_key_skipped", key=key)
            continue
        if key in EMBEDDING_COUPLED_KEYS and emb_model and emb_model != s.embedding_model:
            log.warning("tuning.embedding_model_mismatch", key=key, row_model=emb_model,
                        running_model=s.embedding_model,
                        note="override tuned on a different embedding model — config default "
                            "applies; re-derive the value on the current model")
            continue
        try:
            resolved[key] = _coerce(key, value)
        except (TypeError, ValueError) as exc:
            log.warning("tuning.value_wrong_type", key=key, value=value, error=str(exc),
                        note="config default applies")
    try:
        validated = Settings.model_validate({**s.model_dump(), **resolved})
    except ValidationError as exc:
        # loc + msg ONLY, never pydantic's str(exc): a model-level validator failure embeds
        # `input=<the whole settings dict>` — DSNs, API keys and all — and this message goes
        # into an HTTP 422 body. Template lives in core.messages, the one place for wording.
        detail = "; ".join(
            f"{'.'.join(str(p) for p in e['loc']) or 'settings'}: {e['msg']}"
            for e in exc.errors())
        raise ValueError(ApiMessage.CONFIG_TUNING_INVALID.format(detail=detail)) from exc
    return {k: getattr(validated, k) for k in TUNABLE_KEYS}


@lru_cache(maxsize=64)
def _parse_snapshot(raw: str) -> tuple[tuple[str, Any], ...] | None:
    """Parse + type-heal one TuningJSON blob, memoized on the raw string — from_session runs
    per scenario, and re-parsing an identical frozen snapshot N times per batch is waste. Also
    the healing point for snapshots frozen BEFORE _coerce existed (a float in an int key):
    a bad value is dropped here (config default applies) rather than crashing a worker stage.
    Returns a hashable tuple of (key, value) pairs, or None when unreadable."""
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    out: list[tuple[str, Any]] = []
    for k in TUNABLE_KEYS:
        if k not in data:
            continue
        try:
            out.append((k, _coerce(k, data[k])))
        except (TypeError, ValueError):
            log.warning("tuning.snapshot_value_wrong_type", key=k, value=data[k],
                        note="config default applies for this key")
    return tuple(out)


def from_session(scenario_session: Mapping[str, Any] | None) -> ResolvedTuning:
    """The worker-side read: the session's frozen TuningJSON, config fallback per key.
    NULL/absent TuningJSON (a pre-feature session) → pure config values; a corrupt blob or a
    wrong-typed value is logged and degrades to config — a session must fall back to the
    config rulebook, never crash mid-pipeline over calibration."""
    base = _from_config(get_settings())
    raw = (scenario_session or {}).get("TuningJSON")
    if raw:
        parsed = _parse_snapshot(raw)
        if parsed is None:
            log.warning("tuning.snapshot_unreadable",
                        session_id=(scenario_session or {}).get("SessionID"))
        else:
            base.update(dict(parsed))
    return ResolvedTuning(**base)
