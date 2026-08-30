"""The eyshield_handoff package — completeness and internal lockstep.

Since the 2026-08 dedup there is ONE copy of the deployment SQL: the numbered files in
scripts/eyshield_handoff/, which are what a DBA actually provisions from. The old design kept
unnumbered canonicals in scripts/ and byte-compared the handoff against them; that mirror pair
is gone, so this file now guards the two properties that still matter:

1. the package is COMPLETE — all seven numbered install scripts plus the readme exist, so a
   partial checkout or an accidental delete fails pytest instead of shipping a package a
   customer cannot install;
2. TSG_Core_UAT.sql stays in LOCKSTEP with `1. TSG_Core.sql` — same guarded body under a
   different header, or the UAT upgrade run applies a different schema than the install run.

Content equality is line-ending-normalized (bytes with CRLF folded to LF) — still an exact
content compare, but immune to autocrlf checkout variance between clones.
"""
from __future__ import annotations

from pathlib import Path

import pytest

_HANDOFF = Path(__file__).resolve().parents[1] / "scripts" / "eyshield_handoff"

_PACKAGE = [
    "0. TSG_Preflight.sql",
    "1. TSG_Core.sql",
    "2. Threat_library.sql",
    "3. Seed_to_Threat_library.sql",
    "4. Control_library.sql",
    "5. Seed_to_Control_library.sql",
    "6. TSG_Verify.sql",
    "TSG_Core_UAT.sql",
    "readme.txt",
]


def _normalized(path: Path) -> bytes:
    return path.read_bytes().replace(b"\r\n", b"\n")


@pytest.mark.parametrize("name", _PACKAGE)
def test_package_file_exists_and_is_nonempty(name: str) -> None:
    path = _HANDOFF / name
    assert path.exists(), f"missing from the deployment package: {path}"
    assert path.stat().st_size > 0, f"empty file in the deployment package: {path}"


def test_uat_upgrade_script_body_matches_core() -> None:
    """TSG_Core_UAT.sql is `1. TSG_Core.sql` under a UAT-run header: same guarded body,
    different comment block. Everything from the first real statement on must be identical,
    or the UAT upgrade run applies a different schema than the install run."""
    marker = b"SET QUOTED_IDENTIFIER ON;"
    core = _normalized(_HANDOFF / "1. TSG_Core.sql")
    uat = _normalized(_HANDOFF / "TSG_Core_UAT.sql")
    assert marker in core and marker in uat
    assert core.split(marker, 1)[1] == uat.split(marker, 1)[1], (
        "TSG_Core_UAT.sql body has drifted from 1. TSG_Core.sql — regenerate it: keep its "
        "header, replace everything below with 1. TSG_Core.sql's body.")


def test_no_stale_canonical_copies_reappear() -> None:
    """The dedup's own regression guard: an unnumbered copy of an install script landing back
    in scripts/ would silently recreate the two-copies problem this layout removed — someone
    edits one and ships the other."""
    scripts = _HANDOFF.parent
    stale = [n for n in ("TSG_Preflight.sql", "TSG_Core.sql", "Threat_library.sql",
                        "Seed_to_Threat_library.sql", "Control_library.sql",
                        "Seed_to_Control_library.sql", "TSG_Verify.sql")
            if (scripts / n).exists()]
    assert not stale, (
        f"unnumbered canonical copies back in scripts/: {stale} — the deployed truth lives in "
        "scripts/eyshield_handoff/; edit the numbered file there instead.")
