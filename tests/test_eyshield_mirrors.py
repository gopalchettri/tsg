"""The eyshield_handoff SQL files are hand-maintained numbered COPIES of scripts/*.sql
(scripts/readme.txt) — the copies a customer actually provisions from. Nothing compared them
until now, and drift had already happened once (a header comment line and a trailing GO in
1. TSG_Core.sql). This test makes any one-sided edit fail pytest on the editor's own machine
instead of shipping a different physical schema to a customer site.

Content equality is line-ending-normalized (bytes with CRLF folded to LF) — still an exact
content compare, but immune to autocrlf checkout variance between clones.
"""
from __future__ import annotations

from pathlib import Path

import pytest

_SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"

_PAIRS = [
    ("0. TSG_Preflight.sql", "TSG_Preflight.sql"),
    ("1. TSG_Core.sql", "TSG_Core.sql"),
    ("2. Threat_library.sql", "Threat_library.sql"),
    ("3. Seed_to_Threat_library.sql", "Seed_to_Threat_library.sql"),
    ("4. Control_library.sql", "Control_library.sql"),
    ("5. Seed_to_Control_library.sql", "Seed_to_Control_library.sql"),
    ("6. TSG_Verify.sql", "TSG_Verify.sql"),
]


def _normalized(path: Path) -> bytes:
    return path.read_bytes().replace(b"\r\n", b"\n")


@pytest.mark.parametrize("numbered,canonical", _PAIRS, ids=[p[1] for p in _PAIRS])
def test_mirror_matches_canonical(numbered: str, canonical: str) -> None:
    mirror = _SCRIPTS_DIR / "eyshield_handoff" / numbered
    source = _SCRIPTS_DIR / canonical
    assert mirror.exists(), f"missing mirror {mirror}"
    assert source.exists(), f"missing canonical {source}"
    assert _normalized(mirror) == _normalized(source), (
        f"eyshield_handoff/{numbered} has drifted from scripts/{canonical} — "
        "apply the same edit to both (scripts/ is canonical; see scripts/readme.txt)")


def test_uat_upgrade_script_body_matches_core() -> None:
    """eyshield_handoff/TSG_Core_UAT.sql is `1. TSG_Core.sql` under a UAT-run header: same
    guarded body, different comment block. Everything from the first real statement on must
    be identical, or the UAT upgrade run applies a different schema than the install run."""
    marker = b"SET QUOTED_IDENTIFIER ON;"
    core = _normalized(_SCRIPTS_DIR / "eyshield_handoff" / "1. TSG_Core.sql")
    uat_path = _SCRIPTS_DIR / "eyshield_handoff" / "TSG_Core_UAT.sql"
    assert uat_path.exists(), f"missing {uat_path}"
    uat = _normalized(uat_path)
    assert marker in core and marker in uat
    assert core.split(marker, 1)[1] == uat.split(marker, 1)[1], (
        "eyshield_handoff/TSG_Core_UAT.sql body has drifted from 1. TSG_Core.sql — "
        "regenerate it: keep its header, replace everything below with 1. TSG_Core.sql's body.")
