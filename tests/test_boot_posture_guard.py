"""Boot-posture guard: what it must block, what it must NOT block, and that it actually stops.

Two defects are pinned here, both found when the API and the Celery worker refused to start on
a developer machine whose SQL Server is addressed as MACHINENAME\\SQLEXPRESS.

1. FALSE POSITIVE. _LOOPBACK_HOSTS knew "localhost" and "127.0.0.1" but not the machine's own
   hostname, so pointing at your own box by name looked like shared infrastructure. That is a
   distinction without a difference -- the same instance is reachable via localhost, which was
   always allowed -- and it blocked the API and the worker outright.

2. THE GUARD DID NOT GUARD. celery.utils.dispatch.signal.send CATCHES whatever a receiver
   raises, logs "Signal handler ... raised", and continues. So _init_worker's
   assert_security_posture(), commented "fail-closed", was advisory: the worker logged the
   error, reported `ready`, and pulled tasks. The raise also aborted the rest of the handler,
   silently skipping verify_startup, the gevent threadpool sizing and the local-model warm-up.
"""
from __future__ import annotations

import socket

import pytest

from app.core import config as cfg


def test_own_machine_by_hostname_is_not_shared_infrastructure():
    """The regression: MACHINENAME means the same box as localhost."""
    own = socket.gethostname().strip().lower().split(".", 1)[0]
    assert cfg._is_own_machine(own)
    assert cfg._is_own_machine(own.upper())                # DSNs are written in any casing
    assert cfg._is_own_machine(f"{own}.corp.example.com")  # FQDN, matched on the short name


def test_the_classic_loopback_spellings_still_pass():
    for host in ("localhost", "127.0.0.1", "::1", "[::1]", "host.docker.internal", ""):
        assert cfg._is_own_machine(host), host


def test_genuinely_remote_hosts_are_still_blocked():
    """The gate must keep doing its job -- shipping a dev-posture app onto shared data is the
    failure its own comment records as having already happened once."""
    for host in ("db.prod.internal", "10.2.3.4", "sql-uat", "someone-elses-laptop"):
        assert not cfg._is_own_machine(host), host


def test_dev_against_a_remote_dsn_still_refuses_to_boot(monkeypatch):
    """End-to-end through the real guard, not just the predicate."""
    s = cfg.get_settings()
    monkeypatch.setattr(s, "app_env", "dev")
    monkeypatch.setattr(s, "allow_remote_in_dev", False)
    monkeypatch.setattr(s, "db_dsn", "mssql+pyodbc://u:p@db.prod.internal/EYShield?driver=X")
    with pytest.raises(RuntimeError, match="NON-LOOPBACK"):
        cfg.assert_security_posture(s)


def test_dev_against_this_machine_boots(monkeypatch):
    """The case that was broken. Same posture, DSN pointing at this box by NAME."""
    own = socket.gethostname()
    s = cfg.get_settings()
    monkeypatch.setattr(s, "app_env", "dev")
    monkeypatch.setattr(s, "allow_remote_in_dev", False)
    monkeypatch.setattr(s, "db_dsn",
                        f"mssql+pyodbc://@{own}\\SQLEXPRESS/EYShield?driver=X&Trusted_Connection=yes")
    monkeypatch.setattr(s, "redis_url", "redis://127.0.0.1:6379/1")
    cfg.assert_security_posture(s)          # must not raise


def test_the_escape_hatch_still_works(monkeypatch):
    """TSG_ALLOW_REMOTE_IN_DEV remains the deliberate opt-in for real shared infrastructure."""
    s = cfg.get_settings()
    monkeypatch.setattr(s, "app_env", "dev")
    monkeypatch.setattr(s, "allow_remote_in_dev", True)
    monkeypatch.setattr(s, "db_dsn", "mssql+pyodbc://u:p@db.prod.internal/EYShield?driver=X")
    cfg.assert_security_posture(s)          # must not raise


def test_worker_boot_guard_kills_the_process_rather_than_logging_and_continuing(monkeypatch):
    """THE second defect. Celery swallows receiver exceptions, so a guard that only raises lets
    the worker come up anyway. _init_worker must terminate the PROCESS instead.

    os._exit is patched to raise a sentinel -- the only way to observe "we would have died
    here" without actually killing pytest."""
    from app.pipeline import celery_app

    class _Exited(Exception):
        pass

    def _fake_exit(code):
        raise _Exited(code)

    monkeypatch.setattr(celery_app.os, "_exit", _fake_exit)
    monkeypatch.setattr(cfg, "assert_security_posture",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("bad posture")))

    with pytest.raises(_Exited) as caught:
        celery_app._init_worker(sender=None)
    assert caught.value.args[0] == 1, "a failed boot guard must exit non-zero"
