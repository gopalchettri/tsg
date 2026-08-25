"""Every Swagger group must be declared AND used — the two ways a group goes missing.

The regression: app/api/treatment.py tagged its routes "Treatment Plans" while main.py declared
"Remediation Plans" in openapi_tags. Swagger UI renders groups from OPERATION tags and drops a
declared tag nobody uses, so the treatment endpoints surfaced as an unlabelled group dumped
after every documented one, and the "Remediation Plans" section never rendered at all. Nothing
failed — routes mounted, auth held, only the docs lied. Same drift had already swallowed the
description for "API Clients Admin".
"""
from __future__ import annotations

from app.core.config import get_settings
from app.main import create_app

# Declared unconditionally in main.py, but its router only mounts when risk_module_enabled.
_FLAG_GATED = {"Remediation Plans"}


def _declared_and_used() -> tuple[set[str], set[str]]:
    spec = create_app().openapi()
    declared = {t["name"] for t in spec.get("tags", [])}
    used = {tag for ops in spec["paths"].values()
            for op in ops.values() for tag in op.get("tags", [])}
    return declared, used


def test_every_operation_tag_is_declared():
    """Undeclared -> the group renders last, with no description."""
    declared, used = _declared_and_used()
    assert not (used - declared), f"tagged in a router, missing from openapi_tags: {used - declared}"


def test_every_declared_tag_has_operations():
    """Declared but unused -> Swagger UI drops the group entirely."""
    declared, used = _declared_and_used()
    if not get_settings().risk_module_enabled:
        declared -= _FLAG_GATED
    assert not (declared - used), f"declared in openapi_tags, no route uses it: {declared - used}"
