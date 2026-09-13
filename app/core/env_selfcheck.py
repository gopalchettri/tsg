"""Runnable env-template sync check: `python -m app.core.env_selfcheck`.

Manual sync rots — this repo proved it (.env documented TSG_MAX_SCENARIOS_PER_THREAT long
after the setting was deleted, and .env.uat still did months later). This check — not
discipline — is what keeps `Settings` and the env files in step:

  1. EVERY `Settings` field must appear (commented or live) in EVERY `.env*` file. Expected
     names derive from the model itself — `TSG_<FIELD>` via env_prefix plus each field's
     `validation_alias` choices (admin_api_key/auth_dev_mode accept UN-prefixed names, and the
     templates use those spellings; a naive TSG_<FIELD> check false-fails on day one).
  2. DERIVED settings must never be a LIVE line in a template. Detection is
     `model_fields_set`: pydantic records whether a value was SUPPLIED, not whether it differs
     from the default — so pinning one at its own default still silently disables the
     derivation. (grounding_match_threshold used to be the canonical example, until its
     resolution order was flipped DB-first in 2026-08 — a live line there is now a harmless
     pre-calibration bootstrap, so it left this list.)
     The operator's own `.env` is exempt from THIS rule only (a deliberate pin is their call);
     it still owes every field a documented entry.
  3. Every LIVE line must correspond to a real field — in the `.env*` files AND in the
     generated Secret, the file that actually reaches the cluster.
  4. The values this deployment DECIDED must still be the values in the tested source.

The file list comes from globbing `.env*`, never from pinned names, so a new template is
covered the day it appears. Exit code 1 with a per-file listing on any problem.
"""
from __future__ import annotations

import io
import re
import sys
from pathlib import Path

from dotenv import dotenv_values
from pydantic import AliasChoices, TypeAdapter, ValidationError

from app.core.config import Settings

#: Settings whose value DERIVES from other settings when left unset (model_fields_set
#: detection) — a live line freezes the derivation. Documented COMMENTED with "LEAVE UNSET".
DERIVED_SETTINGS: tuple[str, ...] = (
    "stage_lease_seconds", "reaper_stale_grace_seconds",
    # Derived per environment by Settings._derive_subsystem_task_limits (lease x 2, capped at
    # 90% of broker_visibility_timeout_seconds). A constant cannot be right in both dev and UAT.
    "subsystem_task_soft_limit_seconds",
    # control_map_min_score is DELIBERATELY NOT LISTED, though it does derive when unset. Its
    # derivation resolves to the GROUNDING threshold — calibrated label-vs-label, while Step-4
    # matches a scenario PARAGRAPH against control labels. Left unset against a 90 grounding pin
    # it dropped every match and published `controls: []` as a healthy "library gap": 7 of 13
    # mapped scenarios came back empty. Pinning it is now the CORRECT posture, so warning that a
    # live line "disables its derivation" would push an operator straight back into that bug.
)

#: The env file this deployment TESTS and derives its Secret from (scripts/gen_secret_from_env.py
#: defaults to the same file), hence the only one whose values reach production.
POSTURE_FILE = ".env.uat"

#: Values THIS deployment has DECIDED, each with the evidence that decided it.
#:
#: WHY A LIST IN SOURCE. Everything else here checks that a setting is PRESENT and SPELLED right;
#: nothing could see a setting that is present, correctly spelled and simply WRONG. That gap cost
#: a real instruction: `control_map_sweep_enabled` was set to false, a later alias change rewrote
#: the line carrying the DOCUMENTED DEFAULT instead of the operator's value, and because .env* is
#: gitignored there was no diff, no history and no review to catch it. For an untracked file an
#: assertion about the value is the only possible detection.
#:
#: The precedent is deliberate: gen_secret_from_env.py already declares its cluster deltas "in one
#: reviewed place" rather than trusting them to memory. These six were decided from a 1,271s
#: production trace, so changing one should cost a reviewed edit, not a stray keystroke.
#:
#: Values are compared AS THE APPLICATION PARSES THEM, so write whichever spelling reads best —
#: "false" and "False" are the same decision. tests/test_env_selfcheck.py pins every key here to
#: a real Settings field, so a rename fails CI instead of crashing the checker.
DEPLOYMENT_POSTURE: dict[str, tuple[str, str]] = {
    "control_map_sweep_enabled":    ("false", "operator decision, given twice"),
    "canonical_types_per_category": ("0", "dark until the kimi swap is verified in production"),
    "inference_model":              ("kimi-k2.5", "glm-5 took 967s on production input; kimi 4.7s"),
    "inference_fallback_model":     ("glm-5", "safety net; reversed from primary"),
    "llm_max_retries":              ("1", "= 2 attempts; the nested SDK loop reached ~16"),
    "llm_timeout_seconds":          ("120.0", "sized for the glm-5 FALLBACK, not for kimi"),
}


def _expected_names(field_name: str, field) -> set[str]:
    """Every env spelling that supplies this field: TSG_<FIELD> plus any alias choices."""
    names = {f"TSG_{field_name.upper()}"}
    alias = getattr(field, "validation_alias", None)
    if isinstance(alias, AliasChoices):
        names |= {str(c) for c in alias.choices if isinstance(c, str)}
    elif isinstance(alias, str):
        names.add(alias)
    return names


#: A LIVE `NAME=` line. Uppercase-only, and the `=` must follow the name with nothing but spaces
#: between, so prose like "# lease = timeout x (retries+1)" or "# EMBEDDING/RERANKER_PROVIDER=x"
#: is not mistaken for a setting.
_LIVE_KEY_RE = re.compile(r"^[ \t]*([A-Z][A-Z0-9_]*)[ \t]*=", re.MULTILINE)

#: The same, but a COMMENTED entry counts too. Rule 1 asks whether a field is DOCUMENTED at all,
#: and `# TSG_FOO=bar` documents it. Rule 3 deliberately uses the LIVE pattern instead: a
#: commented unknown name does nothing, while a live one is silently discarded.
_ENTRY_KEY_RE = re.compile(r"^[ \t]*#?[ \t]*([A-Z][A-Z0-9_]*)[ \t]*=", re.MULTILINE)

#: A `stringData:` entry in a generated Secret — two-space indent, uppercase key. Deliberately
#: uppercase-anchored so the `metadata:` block's `name:`/`namespace:` are not read as settings.
_SECRET_KEY_RE = re.compile(r"^  ([A-Z][A-Z0-9_]*)\s*:", re.MULTILINE)


def _scan(text: str) -> tuple[set[str], set[str]]:
    """One file -> (keys set LIVE, keys documented at all). TWO passes, not one per name.

    The forward check used to run a whole-file `re.search` for every accepted spelling of every
    field: 164 fields, 215 spellings, 6 files — measured at 133 ms, an upper bound of ~232 MB
    scanned to answer what two passes answer in 1.7 ms. Output is identical; only the access
    pattern changed, from "search the haystack once per needle" to "index the haystack once".
    """
    return set(_LIVE_KEY_RE.findall(text)), set(_ENTRY_KEY_RE.findall(text))


def _reverse_problems(fname: str, live: set[str], known: set[str]) -> list[str]:
    """Rule 3: does every LIVE line correspond to a real field?

    extra="ignore" (config.py) drops an unrecognised name with no error and no log, so a
    wrongly-prefixed variable reverts to its default silently. Not hypothetical: the sibling pair
    CONTROL_MAP_SWEEP_ENABLED / _INTERVAL_SECONDS accepted different spellings, so an operator
    copying the first style onto the second lost the interval and never knew.
    """
    return [f"{fname}: `{k}` is set but matches NO setting — extra='ignore' means it is "
            "silently discarded (check the TSG_ prefix / spelling)"
            for k in sorted(live - known)]


def _missing_entry_problems(fname: str, documented: set[str],
                            names_by_field: dict[str, set[str]]) -> list[str]:
    """Rule 1: every field documented (commented or live) in every file."""
    return [f"{fname}: missing entry for `{field}` (any of: {', '.join(sorted(names))})"
            for field, names in names_by_field.items() if not names & documented]


def _derived_problems(fname: str, live: set[str],
                      names_by_field: dict[str, set[str]]) -> list[str]:
    """Rule 2: a derived setting pinned LIVE freezes its derivation."""
    problems = []
    for field in DERIVED_SETTINGS:
        hit = sorted(names_by_field[field] & live)   # sorted: name one spelling, deterministically
        if hit:
            problems.append(f"{fname}: derived setting `{field}` is a LIVE line ({hit[0]}=…) — "
                            "pinning disables its derivation; comment it out with a LEAVE UNSET "
                            "note")
    return problems


def _posture_problems(fname: str, text: str, fields,
                      names_by_field: dict[str, set[str]]) -> list[str]:
    """Rule 4: every DECIDED value present, live, and equal IN MEANING.

    ABSENT IS A FAILURE, not a pass: control_map_sweep_enabled defaults to True, so deleting the
    line re-enables the sweep exactly as silently as overwriting it did.

    COMPARED AS VALUES, NOT AS TEXT. `False`, `0` and `no` are all what the application reads as
    off, and a checker that rejects a file the application accepts is worse than no checker —
    people learn to skip its output, and then miss the report that matters. So both sides go
    through the field's own annotation. Where that raises, fall back to text and SAY the value
    would not parse: an unparseable value is itself the finding, not a reason to stay silent.

    dotenv over the text already read: no second open, and it is the parser
    gen_secret_from_env.py uses, so a value this check approves and the generator emits
    differently cannot happen.
    """
    values = {k.upper(): v for k, v in dotenv_values(stream=io.StringIO(text)).items()
              if v is not None}
    problems = []
    for field, (want, why) in DEPLOYMENT_POSTURE.items():
        got = next((values[n] for n in sorted(names_by_field[field]) if n in values), None)
        if got is None:
            problems.append(f"{fname}: `{field}` is unset — this deployment decided `{want}` "
                            f"({why}); the code default silently applies instead")
            continue
        adapter, note = TypeAdapter(fields[field].annotation), ""
        try:
            same = adapter.validate_strings(got.strip()) == adapter.validate_strings(want)
        except ValidationError:
            same, note = got.strip() == want, " — and it does not parse as this setting's type"
        if not same:
            problems.append(f"{fname}: `{field}` is `{got.strip()}` but this deployment decided "
                            f"`{want}` ({why}){note}")
    return problems


def _secret_problems(root: Path, known: set[str]) -> list[str]:
    """Rule 3, applied to THE FILE THAT ACTUALLY REACHES THE CLUSTER.

    The reverse check cannot see it: that one globs `.env*`, and the generated Secret lives in
    deploy/. Five removed features had left their env vars behind there — TSG_VALIDATOR_BATCH_SIZE
    outlived the LLM validator itself — and extra="ignore" discarded all five in every pod,
    silently, forever.

    Scoped to `name: tsg-api-secrets`, which the generator hardcodes in its HEADER: deploy/ also
    holds celery-exporter-secrets, whose CE_BROKER_URL a different image reads, and flagging that
    would train the reader to ignore this check. Self-scoping, so a new namespace's copy is
    covered the day it is generated. Both files are gitignored; CI has nothing to scan.
    """
    problems: list[str] = []
    for path in sorted((root / "deploy").glob("*.yaml")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if "name: tsg-api-secrets" not in text:
            continue
        problems += [f"deploy/{path.name}: `{k}` is set but matches NO setting — extra='ignore' "
                     "means EVERY POD discards it; delete it from the env file it was generated "
                     "from"
                     for k in sorted(set(_SECRET_KEY_RE.findall(text)) - known)]
    return problems


def check(root: Path) -> tuple[list[str], list[Path]]:
    """→ (problems, files checked). Pure so the verification suite can call it directly.

    Orchestration only. Each rule is its own function above, so the next one lands beside them
    instead of growing this body — which is how it reached five inlined jobs across three
    commits, and why each rule could only be tested through the aggregate.
    """
    files = sorted(p for p in root.glob(".env*") if p.is_file())
    if not files:
        return [f"no .env* files found under {root}"], []
    fields = Settings.model_fields
    # Built ONCE from the model: accepted spellings are a property of Settings, not of any file,
    # and pydantic matches env names case-insensitively. Derived from the model rather than
    # hand-listed, so a new AliasChoices cannot desynchronise it.
    names_by_field = {n: {x.upper() for x in _expected_names(n, f)} for n, f in fields.items()}
    known = {n for names in names_by_field.values() for n in names}

    problems: list[str] = []
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        live, documented = _scan(text)
        problems += _reverse_problems(path.name, live, known)
        if path.name == POSTURE_FILE:
            problems += _posture_problems(path.name, text, fields, names_by_field)
        problems += _missing_entry_problems(path.name, documented, names_by_field)
        if path.name != ".env":   # templates only — an operator's live .env may pin deliberately
            problems += _derived_problems(path.name, live, names_by_field)
    return problems + _secret_problems(root, known), files


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    problems, files = check(root)
    if problems:
        print(f"ENV TEMPLATE SYNC: {len(problems)} problem(s) across {len(files)} file(s):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"ENV TEMPLATE SYNC: OK — {len(Settings.model_fields)} settings documented in "
        f"{len(files)} file(s): {', '.join(f.name for f in files)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
