"""Guards for `config.assert_security_posture` — the earliest boot gate there is.

WHY THIS FILE EXISTS: a production audit found `APP_ENV: 'dev'` set in a deployed environment's
Secret, pointed at a real SQL Server and a real Redis. APP_ENV is not a label, it is a switch:
at local/dev the app echoes raw exception text to clients (api/errors.py), mounts the
/dev/sse-test page (main.py), and skips the "at least one active API_Client" boot check
(db/invariants.py). One wrong value disabled four protections at once, silently.

Nothing prevented it, so nothing stopped it recurring. These tests pin the gate that now does.

Every DSN below is synthetic — the odd-looking passwords exist to exercise URL-hostile
characters in the parser, and are not credentials.
"""
from __future__ import annotations

import pytest

from app.core.config import Settings, _dsn_host, assert_security_posture

_REMOTE_DSN = "mssql+pyodbc://user:p%40ss@10.0.0.2:1444/DB?driver=ODBC+Driver+18+for+SQL+Server"
_LOCAL_DSN = r"mssql+pyodbc://@localhost\SQLEXPRESS/DB?driver=ODBC+Driver+17+for+SQL+Server"
_REMOTE_REDIS = "redis://user:pw@10.0.0.4:6379/0"
_LOCAL_REDIS = "redis://127.0.0.1:6379/0"


def _settings(**over) -> Settings:
    """Settings built from explicit values only, so a developer's own .env cannot change the
    outcome of these assertions."""
    base = dict(app_env="dev", db_dsn=_LOCAL_DSN, redis_url=_LOCAL_REDIS,
                allow_remote_in_dev=False, verify_membership=False)
    return Settings(**{**base, **over})


# --- host extraction --------------------------------------------------------------------------
@pytest.mark.parametrize("url,expected", [
    (_REMOTE_DSN, "10.0.0.2"),
    (_LOCAL_DSN, "localhost"),
    (_REMOTE_REDIS, "10.0.0.4"),
    (_LOCAL_REDIS, "127.0.0.1"),
    ("redis://[::1]:6379/0", "[::1]"),
    # Password containing @ : and percent-escapes — urlparse chokes on several of these, which
    # is why _dsn_host is deliberately string-level rather than urlparse-based.
    ("mssql+pyodbc://u:20M%24Y%2AJu%26Bg%402na1@10.0.0.5:1444/D?driver=x", "10.0.0.5"),
    ("", ""),                     # unparseable -> "" -> treated as loopback, never a hard fail
    ("not-a-url-at-all", "not-a-url-at-all"),
])
def test_dsn_host_extraction(url: str, expected: str) -> None:
    assert _dsn_host(url) == expected


# --- GATE 1: dev/local must not point at shared infrastructure ----------------------------------
def test_dev_against_remote_db_refuses_to_boot() -> None:
    with pytest.raises(RuntimeError, match="NON-LOOPBACK"):
        assert_security_posture(_settings(app_env="dev", db_dsn=_REMOTE_DSN))


def test_dev_against_remote_redis_refuses_to_boot() -> None:
    with pytest.raises(RuntimeError, match="TSG_REDIS_URL"):
        assert_security_posture(_settings(app_env="dev", redis_url=_REMOTE_REDIS))


def test_local_against_loopback_is_fine() -> None:
    assert_security_posture(_settings(app_env="local"))


def test_escape_hatch_allows_deliberate_remote_dev() -> None:
    """The gate must be bypassable — one that blocks normal work gets deleted. But it has to be
    DELIBERATE, which is the entire point of the flag."""
    assert_security_posture(_settings(app_env="dev", db_dsn=_REMOTE_DSN, allow_remote_in_dev=True))


def test_staging_and_prod_are_not_subject_to_gate_one() -> None:
    """Remote infrastructure is the NORMAL case for staging/prod. The gate is about dev builds
    reaching real data, not about remote hosts being suspicious in themselves."""
    for env in ("staging", "prod"):
        assert_security_posture(_settings(app_env=env, db_dsn=_REMOTE_DSN, redis_url=_REMOTE_REDIS))


# --- GATE 2: TLS posture ------------------------------------------------------------------------
_UNVERIFIED_TLS = _REMOTE_DSN + "&Encrypt=yes&TrustServerCertificate=yes"


def test_prod_refuses_unverified_server_certificate() -> None:
    with pytest.raises(RuntimeError, match="TrustServerCertificate"):
        assert_security_posture(_settings(app_env="prod", db_dsn=_UNVERIFIED_TLS,
                                        redis_url=_REMOTE_REDIS))


def test_staging_only_warns_about_unverified_certificate() -> None:
    """Staging warns rather than fails: a staging SQL Server may still be on a self-signed cert,
    and refusing that boot would be an outage, not a fix. Promotion to prod is where it bites."""
    assert_security_posture(_settings(app_env="staging", db_dsn=_UNVERIFIED_TLS,
                                    redis_url=_REMOTE_REDIS))  # must not raise


def test_prod_with_verified_certificate_passes() -> None:
    verified = _REMOTE_DSN + "&Encrypt=yes&TrustServerCertificate=no"
    assert_security_posture(_settings(app_env="prod", db_dsn=verified, redis_url=_REMOTE_REDIS))
