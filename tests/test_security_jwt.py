"""HS256 (shared-secret) JWT validation — EY Shield WebAPI token integration.

EY Shield issues HS256 tokens (~5 min lifetime) with claims userId/entities/etc.
TSG verifies them with the shared secret (TSG_JWT_SECRET) instead of a JWKS fetch.
"""
from __future__ import annotations

import time

import jwt as pyjwt
import pytest

from app.api.deps import Principal
from app.core.config import Settings, assert_security_posture
from app.core.security import AuthError, allowed_entities, validate_jwt

# >=32 bytes: PyJWT warns below the RFC 7518 minimum HMAC key length for HS256
SECRET = "test-shared-secret-0123456789abcdef"
ISSUER = "eyshield-webapi"
AUDIENCE = "tsg-api"


def hs_settings(**over) -> Settings:
    base: dict = dict(jwt_secret=SECRET, jwt_issuer=ISSUER, jwt_audience=AUDIENCE,
                      jwt_algorithms=("HS256",))
    base.update(over)
    return Settings(**base)


def mint(secret: str = SECRET, iss: str = ISSUER, aud: str = AUDIENCE,
         exp_in: int = 300, **extra) -> str:
    """Token shaped like the EY Shield claim set (plus the agreed entities claim)."""
    payload: dict = {
        "iss": iss, "aud": aud, "exp": int(time.time()) + exp_in,
        "userId": "42", "Role": "Analyst", "Timeout": "300",
        "entities": ["5", "8"],
    }
    payload.update(extra)
    return pyjwt.encode(payload, secret, algorithm="HS256")


def test_valid_hs256_token_returns_claims():
    claims = validate_jwt(mint(), hs_settings())
    assert claims["userId"] == "42"
    assert allowed_entities(claims, hs_settings()) == {"5", "8"}


def test_wrong_secret_rejected():
    with pytest.raises(AuthError, match="invalid token"):
        validate_jwt(mint(secret="some-other-secret-0123456789abcdef"), hs_settings())


def test_wrong_issuer_rejected():
    with pytest.raises(AuthError, match="invalid token"):
        validate_jwt(mint(iss="someone-else"), hs_settings())


def test_wrong_audience_rejected():
    with pytest.raises(AuthError, match="invalid token"):
        validate_jwt(mint(aud="other-app"), hs_settings())


def test_expired_token_rejected_beyond_leeway():
    with pytest.raises(AuthError, match="invalid token"):
        validate_jwt(mint(exp_in=-3600), hs_settings())


def test_small_clock_skew_tolerated():
    # 10s "expired" is within the 30s leeway — must NOT 401 (5-minute tokens + real clocks).
    validate_jwt(mint(exp_in=-10), hs_settings())  # no raise


def test_token_without_exp_rejected():
    tok = pyjwt.encode({"iss": ISSUER, "aud": AUDIENCE, "userId": "42"},
                       SECRET, algorithm="HS256")
    with pytest.raises(AuthError, match="invalid token"):
        validate_jwt(tok, hs_settings())


def test_principal_user_id_falls_back_to_userid_claim():
    claims = validate_jwt(mint(), hs_settings())
    p = Principal(claims=claims, entities=allowed_entities(claims, hs_settings()))
    assert p.user_id == "42"  # no `sub` in EY Shield tokens


def test_security_posture_prod_ok_with_secret_and_no_jwks():
    assert_security_posture(Settings(  # no raise
        app_env="staging", auth_dev_mode=False, jwt_jwks_url="", jwt_secret=SECRET,
        jwt_issuer=ISSUER, jwt_audience=AUDIENCE))


def test_security_posture_prod_without_jwt_still_refused():
    with pytest.raises(RuntimeError, match="requires JWT verification"):
        assert_security_posture(Settings(
            app_env="staging", auth_dev_mode=False,
            jwt_jwks_url="", jwt_secret="", jwt_issuer="", jwt_audience=""))


def test_security_posture_dev_bypass_now_allowed_outside_dev():
    # AUTH_DEV_MODE is an intentional opt-in for uat/prod (jump server, OpenShift) — it must
    # skip the JWT-completeness check below it too, not just the old "refuse to boot" raise.
    assert_security_posture(Settings(  # no raise, even with every JWT field empty
        app_env="staging", auth_dev_mode=True,
        jwt_jwks_url="", jwt_secret="", jwt_issuer="", jwt_audience=""))
