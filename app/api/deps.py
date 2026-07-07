"""API dependencies — JWT validation + object-level authorization ([R2], §10.1).

`get_principal` verifies the bearer token and reads the allowed-entity set from
the JWT `entities[]` claim. Tests override `get_principal` via
`app.dependency_overrides` to inject a Principal without a real IdP.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from fastapi import Header, HTTPException

from app.core.config import get_settings
from app.core.security import AuthError, allowed_entities, validate_jwt

_log = logging.getLogger("tsg")


@dataclass
class Principal:
    claims: dict
    entities: set[str]

    @property
    def user_id(self) -> str | None:
        """Subject claim from the validated token, or `None` in dev mode if `X-Dev-User` was omitted."""
        return self.claims.get("sub")

    def require_entity(self, entity_id) -> None:
        """[R2] Deny unless the target entity is in the caller's authorized set."""
        if str(entity_id) not in self.entities:
            raise HTTPException(status_code=403, detail="entity not authorized for caller")


def get_principal(
    authorization: str = Header(default=""),
    x_dev_entities: str = Header(default=""),
    x_dev_user: str = Header(default=""),
) -> Principal:
    """FastAPI dependency that resolves the caller's `Principal` from the bearer JWT (or `X-Dev-*` headers when `AUTH_DEV_MODE` is on); [R2] downstream handlers rely on `require_entity` for object-level authorization."""
    if get_settings().auth_dev_mode:  # DEV ONLY — no JWT; entities from a header
        _log.warning("AUTH_DEV_MODE is ON — JWT validation is BYPASSED (dev/local only)")
        return Principal(
            claims={"sub": x_dev_user or "dev"},
            entities={e.strip() for e in x_dev_entities.split(",") if e.strip()},
        )
    token = authorization[7:] if authorization.lower().startswith("bearer ") else ""
    try:
        claims = validate_jwt(token)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    return Principal(claims=claims, entities=allowed_entities(claims))
