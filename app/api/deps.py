"""API dependencies — JWT validation + object-level authorization ([R2], §10.1).

`get_principal` verifies the bearer token and reads the allowed-entity set from
the JWT `entities[]` claim. Tests override `get_principal` via
`app.dependency_overrides` to inject a Principal without a real IdP.
"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Header

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.security import allowed_entities, validate_jwt
from app.db.dal import EntityForbidden

_log = get_logger(__name__)


@dataclass
class Principal:
    """Holds the authenticated caller's JWT claims and the set of entity IDs they're allowed to access."""
    claims: dict
    entities: set[str]

    @property
    def user_id(self) -> str | None:
        """Subject claim from the validated token, or `None` in dev mode if `X-Dev-User` was omitted."""
        return self.claims.get("sub")

    def require_entity(self, entity_id) -> None:
        """[R2] Deny unless the target entity is in the caller's authorized set."""
        # Cast to str since entity_id may arrive as an int/UUID while self.entities holds strings
        if str(entity_id) not in self.entities:
            raise EntityForbidden(f"entity {entity_id} not authorized for caller")


def get_principal(
    authorization: str = Header(default=""),
    x_dev_entities: str = Header(default=""),
    x_dev_user: str = Header(default=""),
) -> Principal:
    """FastAPI dependency that resolves the caller's `Principal` from the bearer JWT (or `X-Dev-*` headers when `AUTH_DEV_MODE` is on); [R2] downstream handlers rely on `require_entity` for object-level authorization.

    `validate_jwt`'s `AuthError` is left to propagate here (not converted to a raw
    `HTTPException`) so it reaches the registered `[R9]` envelope handler in
    app/api/errors.py — the same contract every other domain exception in this
    API already follows."""
    if get_settings().auth_dev_mode:  # DEV ONLY — no JWT; entities from a header
        _log.warning("AUTH_DEV_MODE is ON — JWT validation is BYPASSED (dev/local only)")
        return Principal(
            claims={"sub": x_dev_user or "dev"},
            # Split the comma-separated dev header into entity IDs, trimming whitespace and dropping empty entries
            entities={e.strip() for e in x_dev_entities.split(",") if e.strip()},
        )
    # Strip the "Bearer " prefix (7 chars) to get the raw token; empty string if header is missing/malformed
    token = authorization[7:] if authorization.lower().startswith("bearer ") else ""
    claims = validate_jwt(token)
    return Principal(claims=claims, entities=allowed_entities(claims))
