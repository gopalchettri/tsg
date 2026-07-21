"""OPT-IN live-model integration tests — they hit a REAL Azure OpenAI deployment.

Every other test in this suite injects the deterministic conftest `StubLLM`, so the real
model + our own parsing/grounding have never actually been exercised together. These four do,
WHEN Azure is configured, and SKIP cleanly otherwise (same shape as test_llm.py's live-Redis
`test_llm_slot_against_real_redis_end_to_end`).

To ENABLE (operator, in their own environment with their own keys):
    set LLM_PROVIDER=azure_openai
    set AZURE_OPENAI_ENDPOINT / AZURE_OPENAI_API_KEY / AZURE_OPENAI_DEPLOYMENT_NAME
(TSG_-prefixed variants also work — see app/core/config.py's AliasChoices.) Then run:
    ./.venv/Scripts/python.exe -m pytest -q tests/test_live_llm.py

No credentials are read, printed, or hard-coded here — only queried from Settings/env; if
any are absent the whole module skips. Prompts are kept tiny to stay fast and cheap.
"""
from __future__ import annotations

import json

import pytest
from sqlalchemy import func, select, update

from app.core.config import Settings, get_settings
from app.core.enums import WorkflowStage
from app.db import models as m
from app.db.dal import load_session, now
from app.pipeline import grounding, prompts, validation
from app.pipeline.llm import get_llm
from app.pipeline.tasks import _process_all_supporting_systems


def _azure_configured() -> bool:
    """True only when this process is actually pointed at a real Azure OpenAI chat deployment —
    LLM_PROVIDER=azure_openai AND every credential the azure branch of llm._chat_kwargs() needs
    (endpoint + key + deployment) is non-empty. Reads a fresh Settings() (env-backed), so the
    gate reflects the operator's real environment, not a test fixture's overrides."""
    s = Settings()
    return (s.llm_provider == "azure_openai"
            and bool(s.azure_openai_endpoint)
            and bool(s.azure_openai_api_key)
            and bool(s.azure_openai_deployment_name))


# Gates EVERY test below. In a normal `pytest -q` run with no Azure config these skip cleanly
# (llm_provider defaults to azure_openai but the credentials are empty), so collection and the
# rest of the suite are unaffected.
pytestmark = pytest.mark.skipif(
    not _azure_configured(),
    reason="Azure OpenAI not configured — set LLM_PROVIDER=azure_openai plus "
        "AZURE_OPENAI_ENDPOINT / AZURE_OPENAI_API_KEY / AZURE_OPENAI_DEPLOYMENT_NAME to run "
        "these opt-in live-model tests")


# Small synthetic subsystem reused across the chat tests: an internet-facing login service
# handling PII. Only allowlisted fields (prompts._ASSET_CONTEXT_ALLOWED / _SUB_ALLOWED) are set,
# so nothing is silently dropped before the real call.
_ASSET_NAME = "Customer Identity Platform"
_ASSET_CONTEXT = {
    "cii_asset_description": "Internet-facing customer login and identity service",
    "critical_service": ["Customer Authentication"],
    "data_handled": "Personally identifiable information (names, emails, national IDs)",
    "sector": "Financial",
}
_SUBSYSTEM = {
    "name": "Customer login service",
    "technology_used": "OIDC authorization server behind a public HTTPS endpoint",
    "targeted_users": "External customers",
    "accessability_channel": "Public Internet",
    "user_base_count": 500000,
}


def _norm(text: str) -> str:
    """Whitespace/case-normalized form for tolerant set-membership comparison."""
    return " ".join(str(text or "").split()).lower()


def _looks_like_a_threat(item: object) -> bool:
    """Structural check against the threats_prompt contract: a {category, type, name, actors:[]}
    object with non-empty category/type/name and a list of actors. Tolerant of model wording —
    asserts shape, never specific strings."""
    if not isinstance(item, dict):
        return False
    has_text = all(isinstance(item.get(k), str) and item[k].strip() for k in ("category", "type", "name"))
    return has_text and isinstance(item.get("actors"), list)


def test_live_chat_proposes_parseable_threats():
    """Real model + our parser agree: threats_prompt -> chat() -> parse_json yields a non-empty
    list of well-formed {category, type, name, actors} threats."""
    llm = get_llm()
    messages = prompts.threats_prompt(_ASSET_NAME, _ASSET_CONTEXT, _SUBSYSTEM, max_threats=6)
    # No temperature override: some deployments (e.g. gpt-5 on Azure) only accept temperature=1,
    # and this test verifies parseability, not temperature handling — let the provider default.
    text, prov = llm.chat(messages)
    assert prov.model  # provenance recorded which deployment answered

    threats = validation.parse_json(text, stage="threats", expected_type=list)
    assert threats, "real model returned an empty threat list"
    assert all(_looks_like_a_threat(t) for t in threats), (
        "at least one returned threat did not match the {category, type, name, actors:[]} contract")


def test_live_coverage_aware_returns_new_threats():
    """HIGHEST VALUE: the core untested assumption behind cascade.run_next_set's additive
    'generate next set'. With ~8 already-covered threat names passed as `exclude`, the model
    should propose PREDOMINANTLY NEW threats, not repeats. Tolerant of imperfect obedience —
    asserts a strict majority are new, not zero overlap."""
    already_covered = [
        "Credential stuffing",
        "Brute-force password guessing",
        "Phishing for login credentials",
        "Session hijacking",
        "SQL injection on the login form",
        "Man-in-the-middle interception of credentials",
        "Account takeover via password reset abuse",
        "Denial of service against the login endpoint",
    ]
    excluded = [_norm(e) for e in already_covered]

    llm = get_llm()
    messages = prompts.threats_prompt(
        _ASSET_NAME, _ASSET_CONTEXT, _SUBSYSTEM, max_threats=6, exclude=already_covered)
    # Provider-default temperature (see test_live_chat_proposes_parseable_threats).
    text, _ = llm.chat(messages)
    threats = validation.parse_json(text, stage="threats", expected_type=list)
    assert threats, "real model returned an empty threat list"

    def overlaps(name: str) -> bool:
        # Near-duplicate = an exclude entry that is (or contains, or is contained by) this name,
        # so "Credential stuffing attack" still counts as a repeat of "Credential stuffing".
        return any(name == e or name in e or e in name for e in excluded)

    new = [t for t in threats if not overlaps(_norm(t.get("name")))]
    assert len(new) > len(threats) - len(new), (
        f"coverage-aware prompt did not yield a majority of new threats: "
        f"{len(new)}/{len(threats)} new")


def test_live_scenario_generation_validates():
    """Real scenario-generation path: scenario_prompt -> chat() -> parse_json -> validate_scenario.
    Asserts the 5 required narrative fields are present and the statement actually mentions the
    threat it narrates. A distinctive, universally-known threat is used so the model reliably
    echoes its name (validate_scenario's threat-reference proxy)."""
    threat_type = "Tampering"
    threat_name = "SQL Injection"

    llm = get_llm()
    messages = prompts.scenario_prompt(_ASSET_NAME, _ASSET_CONTEXT, _SUBSYSTEM, threat_type, threat_name)
    text, _ = llm.chat(messages)
    scenario = validation.parse_json(text, stage="scenario", expected_type=dict)

    report = validation.validate_scenario(scenario, threat_type, threat_name)
    missing = [e for e in report["errors"] if e.startswith("missing ")]
    assert not missing, f"scenario missing required field(s): {missing}"
    unreferenced = [e for e in report["errors"] if "does not reference the threat" in e]
    assert not unreferenced, f"scenario_statement never mentions the threat: {unreferenced}"


def test_live_grounding_maps_paraphrase():
    """A paraphrased threat grounds (real embed + rerank) to the same library type as its
    canonical form. Uses find_closest_match with an in-memory candidate list so no DB is needed
    — this isolates the embed/rerank behavior. Embeddings/reranking run via EMBEDDING_PROVIDER/
    RERANKER_PROVIDER (default 'local' for an Azure chat deployment), so this test is
    additionally gated on those actually being reachable in this environment."""
    llm = get_llm()
    s = get_settings()

    # Only embed/rerank reachability is in question here (chat/Azure is already gated above).
    # Probe cheaply; skip — not fail — if the local model (or proxy) isn't available.
    try:
        llm.embed(["reachability probe"], kind="query")
        llm.rerank("reachability probe", ["a", "b"])
    except Exception as exc:  # noqa: BLE001 — reachability probe, mirrors _real_redis_reachable
        pytest.skip(f"embed/rerank backend ({s.embedding_provider}/{s.reranker_provider}) "
                    f"not reachable for grounding: {exc!r}")

    rows = [
        {"ThreatTypeName": "Credential Theft"},
        {"ThreatTypeName": "Denial of Service"},
        {"ThreatTypeName": "Data Tampering"},
        {"ThreatTypeName": "Privilege Escalation"},
    ]
    canonical_row, _ = grounding.find_closest_match(
        llm, "Credential Theft", rows, "ThreatTypeName", s, group="live_threat_type")
    paraphrase_row, _ = grounding.find_closest_match(
        llm, "attacker grabs sign-in credentials", rows, "ThreatTypeName", s, group="live_threat_type")

    assert canonical_row is not None and paraphrase_row is not None
    assert paraphrase_row["ThreatTypeName"] == canonical_row["ThreatTypeName"] == "Credential Theft", (
        f"paraphrase grounded to {paraphrase_row['ThreatTypeName']!r}, "
        f"canonical to {canonical_row['ThreatTypeName']!r} — expected both to be 'Credential Theft'")


# An internet-facing login service handling PII, seeded with the same id (1019) the shared
# `_seed_session`/`_next_set` helpers key on, so the whole DB-backed pipeline + next-set plumbing
# is reused verbatim (only the subsystem/asset CONFIG differs — the real point of this test).
_LOGIN_SUB = {
    "id": 1019, "name": "Customer login service", "criticality": 1, "asset_type": "IT System",
    "technology_used": "OIDC authorization server behind a public HTTPS endpoint",
    "accessability_channel": "Public Internet", "targeted_users": "External customers",
    "user_base_count": 500000, "past_incidents": "None",
}
_LOGIN_ASSET_NAME = "Customer Identity Platform"
_LOGIN_ASSET_CONTEXT = {
    "cii_asset_description": "Internet-facing customer login and identity service",
    "critical_service": ["Customer Authentication"],
    "data_handled": "Personally identifiable information (names, emails, national IDs)",
    "sector": "Financial",
}


def test_live_end_to_end_threats_scenarios_next_set(db, monkeypatch):
    """FULL pipeline against the REAL Azure model + REAL local embeddings, driven through the
    exact DB-backed path the stub tests use (`_process_all_supporting_systems` then
    cascade.run_next_set via test_next_set's `_next_set`), with the stub swapped for `get_llm()`.

    Exercises, end to end: real threat generation (threat_identification_temperature=0.0, so the
    drop_params fix is on the hot path) -> real grounding (local e5/bge) -> deterministic scoring
    -> real scenario generation -> "generate next set" accumulation. Assertions are STRUCTURAL and
    tolerant of model variation, never exact-string."""
    # conftest's `engine` fixture forces EMBEDDING/RERANKER_PROVIDER=litellm_proxy so stub tests
    # never load torch; the real pipeline needs real embeddings, so flip both back to local (the
    # .env / config default) and rebuild the cached settings + client. Chat stays on Azure.
    monkeypatch.setenv("EMBEDDING_PROVIDER", "local")
    monkeypatch.setenv("RERANKER_PROVIDER", "local")
    get_settings.cache_clear()
    get_llm.cache_clear()
    llm = get_llm()

    # Local embed/rerank reachability probe — skip (not fail) if the on-disk models can't load in
    # this environment, exactly like test_live_grounding_maps_paraphrase. A local-model gap is an
    # environment issue, not a real-model quality signal.
    try:
        llm.embed(["reachability probe"], kind="query")
        llm.rerank("reachability probe", ["a", "b"])
    except Exception as exc:  # noqa: BLE001 — reachability probe
        pytest.skip(f"local embed/rerank backend not reachable for the live pipeline: {exc!r}")

    from tests.test_next_set import _active_scenarios, _next_set  # noqa: PLC0415 — test-helper reuse
    from tests.test_slice import _seed_session  # noqa: PLC0415

    # Seed a real session with the login subsystem, then point the asset context at the same
    # login/PII service (the seed helper hardcodes the CAD asset context) so the real model gets a
    # coherent internet-facing-login prompt, not a CAD/login mash-up.
    session = _seed_session(db, subs=[_LOGIN_SUB])
    sid = session["SessionID"]
    db.execute(update(m.Scenario_Session).where(m.Scenario_Session.SessionID == sid).values(
        AssetName=_LOGIN_ASSET_NAME, AssetContextJSON=json.dumps(_LOGIN_ASSET_CONTEXT), UpdatedAt=now()))
    db.commit()

    # ---- run the real first pass (real threat-gen -> grounding -> scoring -> scenario-gen) ----
    _process_all_supporting_systems(db, sid, llm, "a1a1a1a1-1111-4111-8111-111111111111")

    session_row = load_session(db, sid)
    assert session_row["CurrentStage"] == WorkflowStage.REVIEW, (
        f"session did not reach REVIEW (got {session_row['CurrentStage']})")

    identified = db.execute(select(m.Identified_Threat).where(
        m.Identified_Threat.SessionID == sid, m.Identified_Threat.Superseded == 0)).scalars().all()
    assert identified, "real model produced no Identified_Threat rows"

    selected = db.execute(select(func.count()).select_from(m.Scoped_Threat).where(
        m.Scoped_Threat.SessionID == sid, m.Scoped_Threat.Selected == 1,
        m.Scoped_Threat.Superseded == 0)).scalar()
    assert selected >= 1, "no Scoped_Threat was selected"

    first = _active_scenarios(db, sid)
    assert first, "real model produced no scenarios in the first batch"
    for row in first:
        scen = json.loads(row.ScenarioJSON)
        assert str(scen.get("scenario_statement") or "").strip(), "scenario_statement is empty"
        # required-field check only (threat_type/name=None skips the reference proxy) — a real
        # model legitimately varies its wording; we assert completeness, not phrasing.
        report = validation.validate_scenario(scen, None, None)
        missing = [e for e in report["errors"] if e.startswith("missing ")]
        assert not missing, f"scenario missing required field(s): {missing}"

    first_ids = {r.OutputID for r in first}
    first_hashes = {r.IdentityHash for r in first}
    assert len(first_hashes) == len(first), "duplicate IdentityHash within the first batch"

    # ---- "generate next set": real additive path, must accumulate + stay unique ----
    session = dict(load_session(db, sid))  # fresh dict carrying the updated login asset context
    outcome = _next_set(db, session, llm, "b2b2b2b2-2222-4222-8222-222222222222")

    after = _active_scenarios(db, sid)
    after_ids = {r.OutputID for r in after}
    after_hashes = {r.IdentityHash for r in after}
    added = len(after) - len(first)

    assert first_ids <= after_ids, "next-set superseded/dropped a prior scenario (must accumulate)"
    assert len(after_hashes) == len(after), "duplicate IdentityHash among active scenarios after next-set"
    if outcome == "no_new_threats_this_round":
        assert added == 0, "reported no_new but the active scenario count changed"
    else:
        assert added >= 1, "next-set neither added scenarios nor reported no_new_threats_this_round"
        assert len(after_hashes - first_hashes) == added, "new scenarios are not unique vs the first batch"
    assert load_session(db, sid)["CurrentStage"] == WorkflowStage.REVIEW

    # ---- surface the REAL model's actual output so a human can judge quality, not just green.
    # Written to a file (survives the tmp-DB teardown) AND printed; set LIVE_E2E_DUMP to override
    # the path. Purely diagnostic — never asserted on.
    def _title(row):
        return json.loads(row.ScenarioJSON).get("scenario_title", "")

    sample_scen = json.loads(first[0].ScenarioJSON)
    summary = {
        "threat_names_sample": [t.ThreatName for t in identified][:6],
        "grounding_statuses": sorted({str(t.GroundingStatus) for t in identified}),
        "first_batch_count": len(first),
        "first_batch_titles": [_title(r) for r in first],
        "sample_scenario_title": sample_scen.get("scenario_title"),
        "sample_scenario_statement": str(sample_scen.get("scenario_statement"))[:400],
        "next_set_outcome": outcome,
        "next_set_added": added,
        "total_after_next_set": len(after),
        "after_titles": [_title(r) for r in after],
    }
    import os  # noqa: PLC0415
    dump_path = os.environ.get("LIVE_E2E_DUMP")
    if dump_path:
        with open(dump_path, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2, ensure_ascii=False)
    print("\n===== LIVE END-TO-END (gpt-5-mini) =====")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print("========================================")
