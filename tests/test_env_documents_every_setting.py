"""Every setting must be DISCOVERABLE: an operator description, and an entry in every shipped file.

WHY THIS EXISTS. `control_map_backfill_ratio` shipped documented NOWHERE. It decides the backfill
floor for every deployment, and it appeared in none of .env, .env.uat, .env.example or
.env.prod.example and had no entry in scripts/env_comments.py. The only backfill line an operator
could find was the DEPRECATED absolute it replaced, whose comment still described a hard floor and a
boot refusal that had both been deleted. An operator whose backfill band was wrong had no documented
knob to turn, could not reach the real one by copy-and-edit, and could not discover it by reading the
file. Because .env and .env.uat are gitignored there was no diff and no history to notice it from
either.

It could land that way because NEITHER guard could fail on it:

  * env_selfcheck rule 1 (`_missing_entry_problems`) DID report it — and was exercised by no test.
    Every real-repo test in tests/test_env_selfcheck.py filters `check()`'s output down to its own
    rule by substring, so no assertion in the suite had ever seen a `missing entry` problem.
  * `apply_env_comments.py --check`, which tests/test_script_selfchecks.py does run, structurally
    CANNOT see a setting with no entry line: `rewrite()` only replaces the comment block above a line
    that already exists, and `main()` returns 1 only when text would change — never for the `missing`
    list it merely prints.

So this file pins both halves of "discoverable", on the real files:

  1. every `Settings` field has an operator description in scripts/env_comments.py, and
  2. every `Settings` field has an entry line in every env file the project ships.

Plus the reverse of (1) — a description whose setting no longer exists. That direction rots too: a
`TSG_DEFAULT_RULE_WEIGHT` description outlived its setting and could not be spotted by reading any
env file, because the applier never writes a description for a line that is not there.
"""
from __future__ import annotations

import sys
from pathlib import Path

from app.core.config import Settings
from app.core.env_selfcheck import SHIPPED_ENV_FILES, _expected_names, check

ROOT = Path(__file__).resolve().parents[1]

#: Documented in scripts/env_comments.py but deliberately NOT `Settings` fields: docker-compose reads
#: them to bind the local model directories (docker/compose.prod.yml), and the env files carry them
#: for that reason. Their own section header in env_comments.py says so ("Infrastructure-only, not
#: read by the application"). An allowlist rather than a loosened rule — the point of the reverse
#: check is that every OTHER key names something real.
_INFRASTRUCTURE_ONLY = {"EMBEDDING_MODEL_HOST", "RERANKER_MODEL_HOST"}


def _comments() -> dict[str, str]:
    """scripts/env_comments.py's table. Imported by path because nothing under app/ may import it —
    it is operator prose with no runtime role, and keeping it un-importable is what guarantees that.
    """
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        from env_comments import COMMENTS
    finally:
        sys.path.pop(0)
    return COMMENTS


def _spellings() -> dict[str, set[str]]:
    """field -> every env name that supplies it, derived the way env_selfcheck derives it."""
    return {n: {x.upper() for x in _expected_names(n, f)}
            for n, f in Settings.model_fields.items()}


def _missing_entry_hits(root: Path) -> list[str]:
    """Rule-1 problems, restricted to the files the project SHIPS.

    check() globs `.env*` on purpose, so a new template is covered the day it appears. A working
    tree also holds scratch — `.env copy`, `.env copy.uat`, `.env.demo` here — decoupled from the
    model long ago and missing settings by the hundred. A pin that failed on day one over those
    would be deleted, and then nothing would check the four files that matter. See
    env_selfcheck.SHIPPED_ENV_FILES.
    """
    return [p for p in check(root)[0]
            if "missing entry" in p and p.split(":", 1)[0] in SHIPPED_ENV_FILES]


def test_every_setting_has_an_operator_description():
    """THE first half. A setting with no description is invisible to whoever has to operate it, and
    the applier cannot write one it does not have — so the omission shows up nowhere at all."""
    comments = {k.upper() for k in _comments()}
    undocumented = {field: sorted(names) for field, names in _spellings().items()
                    if not names & comments}
    assert not undocumented, (
        "these settings have no operator description in scripts/env_comments.py — add one keyed by "
        f"the env spelling, then run `python scripts/apply_env_comments.py`: {undocumented}")


def test_every_description_names_a_setting_that_still_exists():
    """The reverse. A description for a deleted setting is undetectable from the env files: the
    applier only rewrites the block above an EXISTING entry line, so a stale key is never rendered
    and never read. TSG_DEFAULT_RULE_WEIGHT sat here that way."""
    known = {n for names in _spellings().values() for n in names} | _INFRASTRUCTURE_ONLY
    orphans = sorted({k.upper() for k in _comments()} - known)
    assert not orphans, (
        "these scripts/env_comments.py keys match no Settings field and no documented "
        f"infrastructure variable — delete the description or fix the key: {orphans}")


def test_the_four_shipped_env_files_document_every_setting():
    """THE regression, on the real files. Fails the moment a new setting lands in Settings without
    an entry line in the files an operator actually edits."""
    assert _missing_entry_hits(ROOT) == []


def test_the_rule_this_pin_relies_on_actually_fires(tmp_path: Path):
    """Without this, the test above passes just as well with rule 1 deleted from `check()`.

    A file holding one setting is missing every other one, so the rule must name them — including
    `control_map_backfill_ratio`, the omission that motivated this module."""
    (tmp_path / ".env").write_text("TSG_DB_DSN=x\n", encoding="utf-8")
    hits = _missing_entry_hits(tmp_path)
    assert any("control_map_backfill_ratio" in h for h in hits), hits
    assert not any("db_dsn" in h for h in hits), "the one documented setting must not be reported"


def test_a_commented_out_entry_counts_as_documented(tmp_path: Path):
    """The other half of rule 1, and the reason it cannot just look for live lines: `# TSG_FOO=bar`
    is how the templates document every optional setting, and it is the CORRECT state for one an
    operator should leave unset. Flagging it would make the rule unsatisfiable."""
    names = _spellings()["control_map_backfill_ratio"]
    (tmp_path / ".env").write_text(
        f"# {sorted(names)[0]}=0.42\n", encoding="utf-8")
    assert not any("control_map_backfill_ratio" in h for h in _missing_entry_hits(tmp_path))


def test_an_alias_spelling_satisfies_the_rule(tmp_path: Path):
    """A field with an AliasChoices is documented if ANY accepted spelling is present. Requiring the
    TSG_<FIELD> form would false-fail on day one: admin_api_key is documented under its un-prefixed
    name ADMIN_API_KEY, which is the spelling all four shipped files carry.

    This used to use `# TSG_CONTROL_MAP_TOP_K=5` — an alias on control_map_max_count. That name is
    now RETIRED (config.RETIRED_ENV_NAMES) rather than aliased, so it satisfies nothing; an alias
    that still exists is the only honest fixture for this rule."""
    (tmp_path / ".env").write_text("# ADMIN_API_KEY=\n", encoding="utf-8")
    assert not any("admin_api_key" in h for h in _missing_entry_hits(tmp_path))
