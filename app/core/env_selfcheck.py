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
     derivation (the live `TSG_GROUNDING_MATCH_THRESHOLD=90` pin was exactly this failure).
     The operator's own `.env` is exempt from THIS rule only (a deliberate pin is their call);
     it still owes every field a documented entry.

The file list comes from globbing `.env*`, never from pinned names, so a new template is
covered the day it appears. Exit code 1 with a per-file listing on any problem.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

from pydantic import AliasChoices

from app.core.config import Settings

#: Settings whose value DERIVES from other settings when left unset (model_fields_set
#: detection) — a live line freezes the derivation. Documented COMMENTED with "LEAVE UNSET".
DERIVED_SETTINGS: tuple[str, ...] = (
    "stage_lease_seconds", "reaper_stale_grace_seconds",
    "grounding_match_threshold", "control_map_min_score",
)


def _expected_names(field_name: str, field) -> set[str]:
    """Every env spelling that supplies this field: TSG_<FIELD> plus any alias choices."""
    names = {f"TSG_{field_name.upper()}"}
    alias = getattr(field, "validation_alias", None)
    if isinstance(alias, AliasChoices):
        names |= {str(c) for c in alias.choices if isinstance(c, str)}
    elif isinstance(alias, str):
        names.add(alias)
    return names


def _entry_present(text: str, names: set[str]) -> bool:
    return any(re.search(rf"^\s*#?\s*{re.escape(n)}\s*=", text, re.MULTILINE) for n in names)


def _live_line(text: str, names: set[str]) -> str | None:
    for n in names:
        if re.search(rf"^\s*{re.escape(n)}\s*=", text, re.MULTILINE):
            return n
    return None


def check(root: Path) -> tuple[list[str], list[Path]]:
    """→ (problems, files checked). Pure so the verification suite can call it directly."""
    files = sorted(p for p in root.glob(".env*") if p.is_file())
    if not files:
        return [f"no .env* files found under {root}"], []
    problems: list[str] = []
    fields = Settings.model_fields
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        for fname, f in fields.items():
            names = _expected_names(fname, f)
            if not _entry_present(text, names):
                problems.append(f"{path.name}: missing entry for `{fname}` "
                                f"(any of: {', '.join(sorted(names))})")
        if path.name != ".env":  # templates only — an operator's live .env may pin deliberately
            for fname in DERIVED_SETTINGS:
                hit = _live_line(text, _expected_names(fname, fields[fname]))
                if hit:
                    problems.append(
                        f"{path.name}: derived setting `{fname}` is a LIVE line ({hit}=…) — "
                        "pinning disables its derivation; comment it out with a LEAVE UNSET "
                        "note")
    return problems, files


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
