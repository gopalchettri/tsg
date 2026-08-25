#!/usr/bin/env python
"""UAT/production pre-flight — verifies everything that CANNOT be checked from a dev machine.

Run it ON the UAT host/pod, with the same environment a worker gets:

    python scripts/uat_preflight.py

It exercises the real SQL Server, Redis, MongoDB and the litellm proxy through the app's own
code paths (not re-implementations), prints one PASS/FAIL/SKIP line per check plus the detail
worth pasting back, and exits 1 if anything failed.

Read-only apart from two self-cleaning probes: a temporary Redis key (deleted immediately) and,
if grounding thresholds are not yet calibrated for the configured model pair, one real
calibration pass — which is exactly the work a worker does at boot anyway, and its result is
what you want to see.

WHY EACH CHECK EXISTS (all are things a green test suite provably cannot tell you — the suite
runs on SQLite + fake Redis + stub models, which is how an inert Redis lock survived hundreds of
passing runs):
  A  which .env actually loaded          - config.py reads ".env" only; a file named .env.uat is
                                            NOT auto-loaded, so UAT can silently run dev settings
  B  SQL Server + GUID matching          - the uppercase-GUID bug was MSSQL collation semantics
  C  Redis + INTEGER lock TTL            - redis-py rejects float ex=/EXPIRE; a float TTL made the
                                            admin mutex silently never engage in production
  D  MongoDB + threshold store           - vector cache and calibrated thresholds live here
  E  proxy model registration            - all three configured models actually served?
  F  REAL chat call                      - glm-5 pins "stream": true; proves chat() returns a
                                            completed string, not a stream wrapper
  G  REAL embed + dimension              - qwen3-embedding-8b returns 4096, not the 1024 default
  H  REAL rerank                         - the 8B reranker on a MIG slice actually answers
  I  grounding thresholds                - prints the calibrated cutoffs for THIS model pair

Exit codes: 0 = all checks passed (or skipped as not-applicable) - 1 = at least one FAILED.
"""
from __future__ import annotations

import os
import sys
import traceback
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # make `app` importable

_FAILED: list[str] = []
_WIDTH = 62


class SkipCheck(Exception):
    """Raised by a check that does not apply to this configuration (not a failure)."""


def _line(status: str, name: str, detail: str = "") -> None:
    print(f"  [{status:^4}] {name:<{_WIDTH}} {detail}".rstrip())


def check(name: str):
    """Decorator: run one check, print PASS/FAIL, never let an exception escape the script.
    A check returns a detail string (PASS) or raises (FAIL) — so each is independent and a
    single broken dependency never hides the rest of the report."""
    def wrap(fn):
        try:
            detail = fn() or ""
            _line("PASS", name, detail)
        except SkipCheck as exc:
            _line("SKIP", name, str(exc))
        except Exception as exc:  # noqa: BLE001 — one failed check must not abort the report
            _FAILED.append(name)
            _line("FAIL", name, f"{type(exc).__name__}: {exc}")
            if os.environ.get("PREFLIGHT_TRACEBACKS"):
                traceback.print_exc()
        return fn
    return wrap


def main() -> int:
    from app.core.config import get_settings
    from app.core.logging import configure_logging

    configure_logging()
    s = get_settings()

    print("\n" + "=" * 90)
    print("TSG UAT PRE-FLIGHT")
    print("=" * 90)

    # ---- A. which configuration actually loaded -------------------------------------------
    # If this prints azure_openai / gpt-5-mini / 1024 on a UAT host, then .env.uat was NOT
    # loaded and the app is running your DEV settings (including the auth bypass).
    print("\nA. Configuration actually in effect")
    _line("INFO", "app_env", s.app_env)
    _line("INFO", "verify_membership",
        str(s.verify_membership) + ("" if s.verify_membership
                                    else "  <- (user,entity) taken on trust; key still required"))
    _line("INFO", "llm_provider", s.llm_provider)
    _line("INFO", "inference_model", s.inference_model)
    _line("INFO", "embedding_model / provider", f"{s.embedding_model}  ({s.embedding_provider})")
    _line("INFO", "embedding_dimensions", str(s.embedding_dimensions))
    _line("INFO", "reranker_model / provider", f"{s.reranker_model}  ({s.reranker_provider})")
    _line("INFO", "mongo_db", s.mongo_db)
    _line("INFO", "admin_api_key", "SET" if s.admin_api_key else "NOT SET  <- admin routes will 401")
    _line("INFO", "max_active_sessions", str(s.max_active_sessions))
    _line("INFO", "max_active_sessions_per_entity",
        str(s.max_active_sessions_per_entity) + ("  <- 0 = one tenant can take every slot"
                                                if not s.max_active_sessions_per_entity else ""))
    _line("INFO", "max_concurrent_llm_calls",
        str(s.max_concurrent_llm_calls) + ("  <- 0 = unlimited" if not s.max_concurrent_llm_calls else ""))
    _line("INFO", "grounding threshold (static)", f"verified>={s.grounding_match_threshold}")

    print("\nB-D. Infrastructure")

    @check("SQL Server reachable")
    def _db():
        from sqlalchemy import text

        from app.db.engine import db_session
        with db_session() as sess:
            sess.execute(text("SELECT 1"))
        return "connected"

    @check("SQL Server matches an UPPERCASE GUID (the original 409 bug)")
    def _guid():
        from sqlalchemy import func, select

        from app.db import models as m
        from app.db.engine import db_session
        with db_session() as sess:
            oid = sess.execute(select(m.Threat_Scenario_Output.OutputID).limit(1)).scalar()
            if oid is None:
                raise SkipCheck("no Threat_Scenario_Output rows yet — run one session first")
            hits = sess.execute(select(func.count()).select_from(m.Threat_Scenario_Output)
                                .where(m.Threat_Scenario_Output.OutputID == str(oid).upper())).scalar()
        if hits != 1:
            raise RuntimeError(f"uppercase form of {oid} matched {hits} rows, expected 1")
        return "uppercase form resolves to the same row"

    @check("Redis reachable + INTEGER lock TTL accepted")
    def _redis():
        from app.core.config import get_settings
        from app.pipeline.llm import _slot_redis
        ttl = get_settings().embedding_group_lock_ttl_seconds
        if not isinstance(ttl, int):
            raise RuntimeError(f"embedding_group_lock_ttl_seconds is {type(ttl).__name__}, "
                            "must be int or redis-py rejects it and the mutex never engages")
        r = _slot_redis()
        key = f"tsg:preflight:{uuid.uuid4()}"
        try:
            if not r.set(key, "1", nx=True, ex=ttl):
                raise RuntimeError("SET NX EX failed")
            r.expire(key, ttl)  # the call that raised on a float TTL
        finally:
            try:
                r.delete(key)
            except Exception:  # noqa: BLE001 — probe cleanup only
                pass
        return f"SET/EXPIRE accepted ex={ttl}s"

    @check("MongoDB reachable (vector + threshold store)")
    def _mongo():
        from app.pipeline import embeddings
        col = embeddings._store_if_healthy()
        if col is None:
            raise RuntimeError("vector store unavailable — embedding cache and calibrated "
                            "thresholds will not persist")
        return f"db={col.database.name} collection={col.name}"

    print("\nE-H. Models (through the app's own client)")

    @check("proxy has every configured model registered")
    def _models():
        import httpx
        if s.llm_provider != "litellm_proxy":
            raise SkipCheck(f"llm_provider={s.llm_provider} — no proxy in use")
        wanted = {s.inference_model}
        # The fallback model is warn-only (mirrors boot): preflight must not fail a green
        # deployment over an optional resilience layer — but it DOES surface the state below.
        if s.embedding_provider == "litellm_proxy":
            wanted.add(s.embedding_model)
        if s.reranker_provider == "litellm_proxy":
            wanted.add(s.reranker_model)
        from app.pipeline.llm import _ensure_litellm_proxy_bypassed, _litellm_http_headers
        # Proxy posture must MATCH the app's own. bypass=true (jump server): ignore env proxies
        # entirely — the corporate proxy's CONNECT tunnel never completes for this host.
        # bypass=false (cluster pods): the proxy is the ONLY route to the LLM gateway, so
        # trust_env must honor HTTP_PROXY/HTTPS_PROXY or this check false-fails in-pod against
        # a perfectly healthy deployment.
        _ensure_litellm_proxy_bypassed(s)
        with httpx.Client(timeout=s.llm_timeout_seconds,
                        trust_env=not s.litellm_bypass_proxy) as c:
            resp = c.get(f"{s.litellm_base_url.rstrip('/')}/v1/models",
                        headers=_litellm_http_headers(s))
            resp.raise_for_status()
        available = {mdl["id"] for mdl in resp.json()["data"]}
        missing = wanted - available
        if missing:
            raise RuntimeError(f"not registered on the proxy: {sorted(missing)}")
        note = ""
        if s.inference_fallback_model:
            note = (f"; fallback {s.inference_fallback_model!r} "
                    + ("registered" if s.inference_fallback_model in available
                    else "NOT registered — boot will warn and the fallback stays inert"))
        return f"registered: {sorted(wanted)}{note}"

    @check("REAL chat call returns a COMPLETED string (glm-5 stream:true)")
    def _chat():
        from app.pipeline.llm import get_llm
        # PINNED on the proxy path: with a fallback configured, an unpinned call would let a
        # broken primary pass this check by silently answering from the fallback — then boot's
        # pinned probe fails on the same misconfiguration preflight just blessed.
        text, prov = get_llm().chat(
            [{"role": "user", "content": 'Reply with only this json: {"ok": true}'}],
            model=s.inference_model if s.llm_provider == "litellm_proxy" else None)
        if not isinstance(text, str) or not text.strip():
            raise RuntimeError(f"expected non-empty text, got {type(text).__name__}: {text!r}")
        return f"served by {prov.model_version or prov.model!r}: {text.strip()[:60]!r}"

    @check("REAL chat call on the FALLBACK model (skipped when the feature is off)")
    def _chat_fallback():
        if not (s.llm_provider == "litellm_proxy" and s.inference_fallback_model):
            raise SkipCheck("TSG_INFERENCE_FALLBACK_MODEL unset — feature off")
        from app.pipeline.llm import get_llm
        text, prov = get_llm().chat(
            [{"role": "user", "content": 'Reply with only this json: {"ok": true}'}],
            model=s.inference_fallback_model)
        if not isinstance(text, str) or not text.strip():
            raise RuntimeError(f"expected non-empty text, got {type(text).__name__}: {text!r}")
        return f"served by {prov.model_version or prov.model!r}: {text.strip()[:60]!r}"

    @check("REAL embed call returns EMBEDDING_DIMENSIONS-wide vectors")
    def _embed():
        from app.pipeline.llm import get_llm
        vecs = get_llm().embed(["preflight dimension probe"], kind="query")
        if len(vecs) != 1:
            raise RuntimeError(f"expected 1 vector, got {len(vecs)}")
        if len(vecs[0]) != s.embedding_dimensions:
            raise RuntimeError(f"model returned {len(vecs[0])}-dim vectors but "
                            f"EMBEDDING_DIMENSIONS={s.embedding_dimensions} — fix .env before "
                            "starting; a mismatch corrupts grounding similarity silently")
        return f"{len(vecs[0])} dimensions, matches config"

    @check("REAL rerank call returns one score per document")
    def _rerank():
        from app.pipeline.llm import get_llm
        docs = ["unauthorized firmware update", "flooding of a control network"]
        scores = get_llm().rerank("malicious firmware modification", docs)
        if len(scores) != len(docs):
            raise RuntimeError(f"{len(scores)} scores for {len(docs)} docs")
        return f"scores={[round(float(x), 1) for x in scores]}"

    print("\nI. Grounding threshold for THIS model pair")

    @check("threshold resolved (calibrating now if not stored)")
    def _thresholds():
        from app.db.engine import db_session
        from app.pipeline import grounding
        from app.pipeline.llm import get_llm
        if "grounding_match_threshold" in s.model_fields_set:
            raise SkipCheck(f"pinned in env: verified>={s.grounding_match_threshold} "
                            "(auto-calibration disabled)")
        # Report what ACTUALLY happened. This used to guess from a pre-read
        # (`"already stored" if was_stored else "CALIBRATED NOW and stored"`), so when
        # calibration silently failed - library under 5 entries, class overlap, Mongo down -
        # it printed "CALIBRATED NOW and stored" over a static fallback. The one check whose
        # purpose is confirming provenance, asserting the opposite of the truth, in exactly
        # the failure mode it exists to catch.
        with db_session() as sess:
            th = grounding.resolve_thresholds(sess, get_llm(), allow_calibration=True)
        if th.origin == "static_default":
            raise SkipCheck(f"NOT calibrated: verified>={th.value:.1f} is the static default, "
                            "tuned for a DIFFERENT model pair. Seed the threat library "
                            "(>=5 entries) so boot can calibrate, or pin it deliberately.")
        return f"verified>={th.value:.1f}  ({th.origin})"

    print("\n" + "=" * 90)
    if _FAILED:
        print(f"RESULT: {len(_FAILED)} check(s) FAILED -> {', '.join(_FAILED)}")
        print("Re-run with PREFLIGHT_TRACEBACKS=1 for full tracebacks.")
    else:
        print("RESULT: all checks passed.")
    print("=" * 90 + "\n")
    return 1 if _FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
