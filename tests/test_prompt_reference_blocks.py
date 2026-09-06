"""Which prompt builders may render fenced REFERENCE-DATA blocks -- and which must never.

TSG runs the model twice with different jobs, and reference material belongs to only one of them:

  Stage 1  threats_prompt      proposes threat CONDITIONS in enterprise-risk language
                               ("Loss of audit trail for configuration changes"), which are then
                               grounded against a library written the same way.
  Stage 2  scenario_prompt     writes the technical narrative for ONE already-chosen threat.

threats_prompt's own RULE 3 says: "Defensive, enterprise risk language only: no vulnerabilities,
exploits, malware, CVEs, payloads or procedural attack steps." MITRE ATT&CK and CAPEC descriptions
are exactly procedural attack steps naming malware and CVEs, so injecting them into Stage 1 tells
the model to violate a rule stated in the same prompt. The likely output --
"T0872 Indicator Removal on Host" -- is a technique name, not a threat, and grounds against
nothing in the library.

This is an existing pattern, not an oversight: threat INTEL has never reached Stage 1 either
(tasks._fetch_intel has exactly one call site, the scenario path).

That reasoning lived only in a prompt rule and a call-site count, so it had to be re-derived --
which is how it gets "helpfully" undone later. This file makes the decision self-enforcing, the
same way tests/test_retired_features.py stops a removed feature creeping back. Checked at the AST
level, so prose mentioning a block is naturally exempt: only real calls and real parameters count.
"""
from __future__ import annotations

import ast
from pathlib import Path

_PROMPTS = Path(__file__).resolve().parents[1] / "app" / "pipeline" / "prompts.py"

#: The functions that RENDER a fenced reference block into a prompt.
_BLOCK_RENDERERS = {"_intel_block", "_technique_block"}

#: Builders allowed to call them. variant_scenario_prompt is absent on purpose: it delegates to
#: scenario_prompt rather than assembling blocks itself, so there is ONE assembly point.
_MAY_RENDER = {"scenario_prompt"}

#: Builders that must NOT, mapped to the reason -- printed in the failure so whoever trips this
#: learns why here instead of going digging.
_MUST_NOT_RENDER = {
    "threats_prompt":
        "Stage 1 proposes threat CONDITIONS in enterprise-risk language and its own RULE 3 "
        "forbids 'procedural attack steps'; ATT&CK/CAPEC text is exactly that, and technique-"
        "shaped proposals ground against nothing in the library. Threat intel is excluded here "
        "for the same reason. Put reference material in scenario_prompt (Stage 2) instead.",
    "treatment_prompt":
        "Treatment planning consumes the already-written scenario and its mapped controls; it "
        "needs no attack-side reference material, and its context is JSON-escaped so it carries "
        "no fenced block at all.",
}

#: Parameters that carry reference material into a builder. Checked as well as the call, so a
#: builder that merely ACCEPTS and forwards them is caught one level earlier.
_REFERENCE_PARAMS = {"intel_items", "technique_items"}


def _tree() -> ast.AST:
    return ast.parse(_PROMPTS.read_text(encoding="utf-8"), filename=str(_PROMPTS))


def _renderers_called(fn: ast.FunctionDef) -> set[str]:
    """Reference-block renderers called anywhere inside `fn`."""
    return {n.func.id for n in ast.walk(fn)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id in _BLOCK_RENDERERS}


def _functions() -> dict[str, ast.FunctionDef]:
    return {n.name: n for n in ast.walk(_tree())
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _param_names(fn: ast.FunctionDef) -> set[str]:
    a = fn.args
    return {p.arg for p in (*a.posonlyargs, *a.args, *a.kwonlyargs)}


def test_only_approved_builders_render_reference_blocks() -> None:
    offenders = []
    for name, fn in _functions().items():
        if name in _BLOCK_RENDERERS or name in _MAY_RENDER:
            continue
        called = _renderers_called(fn)
        if called:
            reason = _MUST_NOT_RENDER.get(
                name, "not an approved reference-block call site; add it to _MAY_RENDER with a "
                        "rationale if that is a deliberate change")
            offenders.append(f"{name}() calls {sorted(called)} at line {fn.lineno} -- {reason}")
    assert not offenders, (
        "a prompt builder started rendering reference-data blocks:\n  " + "\n  ".join(offenders))


def test_forbidden_builders_do_not_even_accept_reference_parameters() -> None:
    """Catches the wiring before the block call: a builder that accepts `technique_items` and
    forwards it is already wrong, even if it never calls the renderer itself."""
    offenders = []
    for name, reason in _MUST_NOT_RENDER.items():
        fn = _functions().get(name)
        assert fn is not None, f"{name} no longer exists -- update this tripwire deliberately"
        taken = _param_names(fn) & _REFERENCE_PARAMS
        if taken:
            offenders.append(f"{name}() accepts {sorted(taken)} -- {reason}")
    assert not offenders, (
        "a prompt builder gained a reference-material parameter:\n  " + "\n  ".join(offenders))


def test_scenario_prompt_still_renders_both_blocks() -> None:
    """The opposite regression, and a quieter one: dropping a block degrades every scenario with
    no error, no log and no failing behaviour test -- only worse output nobody attributes."""
    fn = _functions().get("scenario_prompt")
    assert fn is not None, "scenario_prompt no longer exists -- update this tripwire deliberately"
    missing = sorted(_BLOCK_RENDERERS - _renderers_called(fn))
    assert not missing, (
        f"scenario_prompt no longer renders {missing}. Stage 2 is the ONE place reference "
        "material reaches the model; if this removal is deliberate, delete the entry from "
        "_BLOCK_RENDERERS with a rationale.")


def test_variant_delegates_rather_than_assembling_its_own_blocks() -> None:
    """One assembly point is why adding a future reference channel is a single edit. If the
    variant path ever builds its own blocks, the two can drift apart silently."""
    fn = _functions().get("variant_scenario_prompt")
    assert fn is not None
    assert not _renderers_called(fn), (
        "variant_scenario_prompt should forward technique_items/intel_items to scenario_prompt, "
        "not render blocks itself -- otherwise the two scenario paths can diverge.")
    assert _REFERENCE_PARAMS <= _param_names(fn), (
        "variant_scenario_prompt must accept and forward every reference parameter: a variant "
        "regenerates the SAME threat, so it must not be written with less grounding than the "
        "scenario it varies.")
