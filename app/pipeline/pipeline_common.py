"""Primitives shared by every pipeline stage (threat identification AND scenario
generation): the audited LLM call wrapper, SSE stage updates, progress-row setup, and the
text-normalization/identity helpers both stages fold threat names through.

Extracted VERBATIM from tasks.py (structure pass — tasks.py had grown into a god file);
tasks.py re-exports every name here, so external consumers (dal.identity_hash's lazy
import, promote.py, cascade.py, tests) keep importing via `app.pipeline.tasks` unchanged.
Layering is one-directional: this module never imports threat_identification or tasks.
"""
from __future__ import annotations

import json
import re
from typing import Any, overload

from sqlalchemy import insert
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.core.enums import InfraErrorKind, SSEEventType, StageStatus, SubsystemLevel
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.dal import guid, now
from app.pipeline import grounding, prompts, validation
from app.pipeline.llm import LLMClient, Provenance
from app.sse import bus

log = get_logger(__name__)

#: Exception classes that mean "the infrastructure hiccuped — retry the stage", never
#: "the work is wrong". Re-raised past the per-subsystem failure handlers so Celery's
#: autoretry_for re-runs the stage cleanly (the same contract as LLMSlotUnavailable; the
#: stage CAS makes the retry idempotent). Deliberately ONLY OperationalError: anything
#: broader (DBAPIError) would also retry genuine SQL bugs — ProgrammingError is a
#: DBAPIError — and those must keep failing loudly.
TRANSIENT_INFRA_ERRORS: tuple[type[Exception], ...] = (OperationalError,)


def log_transient_infra_retry(*, site: str, session_id: str, subsystem_id: int | None,
                            exc: Exception) -> None:
    """Log one transient-infrastructure failure, with full detail, before it is re-raised.

    One shared emitter so the retry sites cannot drift into vague one-off messages: the
    event name is stable for log queries, `error_kind` is enum-valued, and the exception
    class, message and traceback all travel with it — the failure stays fully
    diagnosable even though the stage retries and (usually) succeeds."""
    log.warning("pipeline.transient_infra_error_retrying",
                site=site, session_id=session_id, subsystem=subsystem_id,
                error_kind=str(InfraErrorKind.database_transient),
                error_class=type(exc).__name__,
                error_detail=str(exc)[:500],
                action="re-raised for Celery autoretry (stage CAS resumes cleanly)",
                # The instance, not True: this helper is called from OUTSIDE the except
                # block, where True has no current exception to capture (ruff LOG014).
                exc_info=exc)


_EPOCH = 1
_WORK_LEVELS = (SubsystemLevel.THREATS, SubsystemLevel.SCENARIOS)
ASSET_UNIT_ID = 0

#: Prepositions that can appear right before an asset name (e.g. "of X", "from X").
#: Used by both cleanup steps in asset_agnostic_name so they can't drift out of sync —
#: they used to be two separate lists that disagreed, which left leftover words like
#: "from" dangling after the asset name was removed.
_ASSET_PREPOSITIONS = "of|from|to|in|on|for|against|at"

#: Placeholder values the model sends when it has no real name. Compared after stripping
#: brackets/quotes/punctuation and lowercasing, so "N/A", '["N/A"]', "(none)", "NULL" etc.
#: all match something here. Add new placeholders to this list only.
_JUNK_NAME_TOKENS = frozenset({
    "", "na", "n a", "none", "null", "nil", "tbd", "unknown", "not applicable",
    "not available", "no name", "no threat", "empty", "NA", "N/A", "N A", "None", "NULL",
    "Nil", "TBD", "Unknown", "Not Applicable", "[]","{}", "['']", '[""]', "['N/A']",
    '["N/A"]', "['None']", '["None"]', "['NULL']", '["NULL"]',
})


def _normalize(s: str) -> str:
    """Lowercase text and strip punctuation for comparisons."""
    return re.sub(r"\s+", " ", re.sub(r"[^\w\s]", " ", s)).strip().casefold()


def threat_label(t: dict) -> str:
    """Get the best available display label for a threat."""
    return (t.get("library_threat_name") or t.get("threat_name")
            or t.get("library_threat_type") or t.get("threat_type") or "")


def _ask_ai(sess: Session, llm: LLMClient, messages: list[dict], *, scenario_session: dict,
            subsystem_id: int, stage: str, level: SubsystemLevel | None = None,
            epoch: int | None = None, task_id: str | None = None,
            correlation_id: str | None = None,
            expected_type: type, temperature: float | None = None) -> tuple[Any, Provenance | None]:
    """Call the LLM and store the full prompt/response receipt in Prompt_Log."""
    sid = scenario_session["SessionID"]
    if level is not None and epoch is not None and task_id is not None:
        # All three travel together: renew_lease needs every one of them, so guarding on
        # `level` alone would hand it None for epoch/task_id on any caller that omitted them.
        if not dal.renew_lease(sess, sid, subsystem_id, level, epoch, task_id):
            log.warning("stage.lease_renewal_failed", session_id=sid,
                        subsystem=subsystem_id, level=str(level))
        if not dal.renew_lock_lease(sess, sid, subsystem_id, task_id):
            log.debug("lock.lease_renewal_skipped", session_id=sid, subsystem=subsystem_id)
    sess.commit()
    # expected_type controls the LLM provider's JSON mode. Getting this wrong breaks things:
    # "json_object" mode forces a top-level object, so the threats stage (which expects a
    # list) would fail every call once JSON mode is on. This parameter is the single source
    # of truth for which shape is expected.
    text, prov = llm.chat(messages, temperature=temperature, expected_type=expected_type)
    if prov is not None:
        prov.prompt_version = prompts.PROMPT_VERSION
    row = {
        "LogID": guid(), "SessionID": scenario_session["SessionID"], "TenantID": scenario_session["TenantID"],
        "EntityID": scenario_session["EntityID"], "UserID": scenario_session.get("UserID"),
        "SubsystemID": subsystem_id, "Stage": stage, "PromptVersion": prompts.PROMPT_VERSION,
        "Messages": json.dumps(messages),
        "Prompt": "\n\n".join(f"[{msg['role']}]\n{msg.get('content') or ''}" for msg in messages),
        "ResponseText": text,
        "Model": prov.model if prov else None, "ModelVersion": prov.model_version if prov else None,
        "CreatedAt": now(),
        # Links this log row to one specific item (e.g. a plan ID) so audits can find the
        # exact attempt without guessing by timestamp. Left as None for stage-level callers.
        "CorrelationID": correlation_id,
    }
    try:
        parsed = validation.parse_json(text, stage=stage, expected_type=expected_type)
    except validation.LLMResponseParseError:
        sess.rollback()
        dal.insert_row(sess, m.Prompt_Log, {**row, "ParseSucceeded": False})
        sess.commit()
        log.warning("llm_response.parse_failed", session_id=scenario_session["SessionID"],
                    subsystem=subsystem_id, stage=stage)
        raise
    dal.insert_row(sess, m.Prompt_Log, {**row, "ParseSucceeded": True})
    sess.commit()
    return parsed, prov


def _summarize_ai_call(p: Provenance | None) -> dict | None:
    """Summarize which model and settings produced a response."""
    return None if p is None else {"model": p.model, "version": p.model_version,
                                "params": p.params, "prompt_version": p.prompt_version}


def _send_live_update(session_id: str, sse_type: SSEEventType, subsystem_id: int,
        level: SubsystemLevel, status: StageStatus, epoch: int = _EPOCH) -> None:
    """Publish a stage progress event to the session's live stream."""
    bus.publish(session_id, {
        "type": str(sse_type), "session_id": session_id, "subsystem_id": subsystem_id,
        "stage": str(level), "status": str(status), "generation_epoch": epoch,
        "ts": now().isoformat(),
    })


def set_up_progress_tracking(sess: Session, session_id: str, tenant_id: str, entity_id: str) -> None:
    """Create the progress-tracking rows for a new session."""
    rows = [{
        "StateID": guid(), "SessionID": session_id, "TenantID": tenant_id, "EntityID": str(entity_id),
        "SubsystemID": ASSET_UNIT_ID, "Level": level, "Status": StageStatus.IDLE,
        "GenerationEpoch": _EPOCH, "UpdatedAt": now(), "CreatedAt": now(),
    } for level in (*_WORK_LEVELS, SubsystemLevel.LOCK)]
    sess.execute(insert(m.Subsystem_Stage_State), rows)


@overload
def _safe_text(v: Any, default: str) -> str: ...
@overload
def _safe_text(v: Any, default: None) -> str | None: ...
def _safe_text(v: Any, default: str | None) -> str | None:
    """Return the value as text, or the default if it is not a string.

    Overloaded so a non-None `default` is typed as returning `str`: callers slice the
    result immediately (`[:300]`), which a `str | None` return would make a type error at
    every call site rather than here, where the guarantee actually lives."""
    if default is None:
        return v if isinstance(v, str) else None
    return grounding.ensure_text(v, default)


def _asset_boundary_pattern(asset_name: str) -> re.Pattern | None:
    """Build a regex that finds the asset name inside text.

    Build one regex pattern for matching/removing an asset name from text, used everywhere
    this needs to happen. Uses lookarounds instead of \\b word boundaries because asset names
    can start or end with non-word characters (like "(PGS)"). A plain substring match would
    also match INSIDE unrelated words — asset name "CIS" once matched inside "decision",
    corrupting text to "Loss of de ion integrity" and poisoning grounding, GenericName, and
    triage downstream."""
    # Handles three cases a plain literal match would miss — each one a real way the asset
    # name used to leak through into GenericName and the shared library:
    #   * trailing punctuation on the name ("ACME Corp.") not matching "ACME Corp systems"
    #   * extra/missing whitespace ("Power  Plant" vs "Power Plant")
    #   * a possessive right after the match ("Citizen Portal's credentials") leaving a
    #     dangling "'s"
    a = (asset_name or "").strip().rstrip(".,;:!")
    if not a:
        return None
    body = r"\s+".join(re.escape(tok) for tok in a.split())
    return re.compile(r"(?<!\w)" + body + r"(?:'s)?(?!\w)", re.IGNORECASE)


def asset_agnostic_name(name: str | None, asset_name: str) -> str | None:
    """Remove the asset name from a threat label. Returns None (never the original text) if
    nothing but the asset name is left — returning the original would let an asset-specific
    name slip through into the shared, cross-tenant threat library. Every caller already
    handles None safely."""
    if not name or not asset_name:
        return name
    pat = _asset_boundary_pattern(asset_name)
    if pat:
        # Also remove a preposition right before the asset name, so removing the name from
        # the middle of a sentence doesn't leave it dangling: "Compromise of X leading to
        # outage" used to become "Compromise of leading to outage" (the cleanup below only
        # fixes trailing prepositions, not ones in the middle).
        combined = re.compile(rf"(?:\b(?:{_ASSET_PREPOSITIONS})\s+)?" + pat.pattern, pat.flags)
        stripped = combined.sub(" ", name)
    else:
        stripped = name
    stripped = re.sub(r"\s+", " ", stripped).strip(" ,;:-.'")
    stripped = re.sub(rf"\s+({_ASSET_PREPOSITIONS})$", "", stripped, flags=re.IGNORECASE)
    return stripped or None


def clean_library_name(name: str | None) -> str | None:
    """Clean up a name so it's fit to enter the shared library, or return None if it isn't.
    Rejects empty values, bracket/quote junk ('N/A', ['NA'], [], '"None"'), known filler
    words, and anything without at least two real words. This matters because meaningless
    text embeds far from anything in the library, making it the MOST likely junk to sneak
    past auto-approval — the one path a human curator never reviews. Checked both when a
    threat is first saved and again at auto-approve time, as a second safety net."""
    if not name:
        return None
    core = re.sub(r"""[\[\]{}()<>'"`,;:._\-/\\]+""", " ", name)
    core = re.sub(r"\s+", " ", core).strip()
    if core.casefold() in _JUNK_NAME_TOKENS:
        return None
    if len([w for w in core.split() if any(ch.isalpha() for ch in w)]) < 2:
        return None
    # Return the name with only its wrapping junk removed, not the raw input as-is. It used
    # to validate the cleaned-up `core` text but then return the untouched original, so
    # '"Data exfiltration"' passed validation but got stored WITH the quotes — becoming the
    # literal library entry text. Punctuation inside the name (like "e-mail" or "command &
    # control") is left alone; only the outer wrapping is stripped.
    display = re.sub(r"""^[\s\[\]{}()<>'"`]+|[\s\[\]{}()<>'"`]+$""", "", name)
    display = display.strip(" ,;:.-")
    return display or None


# Builds a dedup key for a threat: prefers the catalogue ID, then type ID + name, then falls
# back to normalized type/name text. Used to catch duplicate threats both within a batch
# and against threats already active in the session. The first rung is cat:{ThreatCatalogueID}
# (back on the catalogue, 2026-08-28); core tables are recreated on deploy, so no mixed-era
# hashes coexist.
def _dedup_key(info: dict) -> str:

    """Build the identity key used to spot duplicate threats."""
    key_type = _normalize(info.get("threat_type") or "")
    key_name = _normalize(info.get("threat_name") or "")
    catalogue_id = info.get("catalogue_id")
    if catalogue_id is not None:
        return f"cat:{catalogue_id}"
    type_id = info.get("threat_type_id")
    if type_id is not None:
        return f"type:{type_id}|{key_name}" if key_name else f"type:{type_id}"
    if not key_type and not key_name:
        return "txt:tid:" + str(info.get("threat_id"))
    return "txt:" + key_type + "|" + key_name
