"""API dependencies — JWT validation + object-level authorization ([R2], §10.1).

`get_principal` verifies the bearer token and reads the allowed-entity set from
the JWT `entities[]` claim. Tests override `get_principal` via
`app.dependency_overrides` to inject a Principal without a real IdP.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass

from fastapi import Header

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.security import AuthError, allowed_entities, validate_jwt
from app.db.dal import EntityForbidden

_log = get_logger(__name__)


@dataclass
class Principal:
    """Holds the authenticated caller's JWT claims and the set of entity IDs they're allowed to access."""
    claims: dict
    entities: set[str]

    @property
    def user_id(self) -> str | None:
        """Subject claim from the validated token; EY Shield tokens carry `userId` instead of
        `sub`, so fall back to that. `None` in dev mode if `X-Dev-User` was omitted."""
        uid = self.claims.get("sub") or self.claims.get("userId")
        return str(uid) if uid is not None else None

    def require_entity(self, entity_id) -> None:
        """[R2] Deny unless the target entity is in the caller's authorized set."""
        # str(): entity_id may arrive as an int/UUID while self.entities holds strings
        if str(entity_id) not in self.entities:
            raise EntityForbidden(f"entity {entity_id} not authorized for caller")


def get_principal(
    authorization: str = Header(default=""),
    x_dev_entities: str = Header(default=""),
    x_dev_user: str = Header(default=""),
) -> Principal:
    """Resolves the caller's `Principal` from the bearer JWT (or `X-Dev-*` headers when
    `AUTH_DEV_MODE` is on). [R2] downstream handlers still owe `require_entity`.

    `validate_jwt`'s `AuthError` is left to propagate rather than converted to an
    `HTTPException`, so it reaches the [R9] envelope handler in app/api/errors.py."""
    if get_settings().auth_dev_mode:  # DEV ONLY — no JWT; entities from a header
        _log.warning("AUTH_DEV_MODE is ON — JWT validation is BYPASSED")
        return Principal(
            claims={"sub": x_dev_user or "dev"},
            entities={e.strip() for e in x_dev_entities.split(",") if e.strip()},
        )
    token = authorization[7:] if authorization.lower().startswith("bearer ") else ""
    claims = validate_jwt(token)
    return Principal(claims=claims, entities=allowed_entities(claims))


def require_admin(x_admin_key: str = Header(default="", alias="X-Admin-Key")) -> None:
    """Gates the admin-only library/embedding endpoints. Deliberately NOT part of the JWT/entity
    model: TSG has no admin role, and these routes touch shared cross-tenant master data.

    An unconfigured `admin_api_key` ALWAYS denies — it must never become "open to everyone"
    because both sides of a naive equality check happen to be empty. `compare_digest` keeps the
    comparison constant-time."""
    key = get_settings().admin_api_key
    # Compare as BYTES: secrets.compare_digest raises TypeError on a non-ASCII str operand, so a
    # header like `X-Admin-Key: café` turned a failed auth check into an unauthenticated 500 (a
    # log-flood vector and a config oracle). The bytes overload has no ASCII restriction and
    # keeps the constant-time property.
    if not key or not secrets.compare_digest(x_admin_key.encode("utf-8"), key.encode("utf-8")):
        raise AuthError("invalid or missing X-Admin-Key")
