"""Resolve the CLUSTER pods' effective env through the real Settings class — the Step-0.5 gate.

Pods read `envFrom: [tsg-api-config (ConfigMap), tsg-api-secrets (Secret)]` in that order, so
for duplicate keys the Secret (listed last) wins. This script reproduces that merge and then
constructs `Settings` plus `assert_security_posture` on it — catching, BEFORE any `oc apply`:

  * a fatal pin hiding in the untracked ConfigMap (e.g. TSG_STAGE_LEASE_SECONDS=300, which is
    below the 720 floor once TSG_LLM_TIMEOUT_SECONDS=180 lands and raises at import — every
    workload would crash-loop on the very rollout meant to fix the APP_ENV crash-loop);
  * APP_ENV/posture problems (dev + non-loopback infra refuses to boot);
  * any invariant violation across the ~165 coupled settings.

Usage:
    python scripts/resolve_cluster_env.py [captured-configmap.yaml]

With no argument only deploy/secrets.yaml is resolved (useful while the ConfigMap is not yet
captured — but the GATE requires the merge: run `oc -n ai-threatgen get cm tsg-api-config -o
yaml > tsg-api-config.live.yaml` and pass that file). Exit 0 = safe to apply + restart.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import yaml


def _data(path: Path, *fields: str) -> dict[str, str]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    merged: dict[str, str] = {}
    for f in fields:
        merged.update(doc.get(f) or {})
    return {k: str(v) for k, v in merged.items()}


def main() -> int:
    secret = _data(Path("deploy/secrets.yaml"), "stringData")
    cm: dict[str, str] = {}
    if len(sys.argv) > 1:
        cm = _data(Path(sys.argv[1]), "data")
        print(f"ConfigMap: {len(cm)} keys from {sys.argv[1]}")
    else:
        print("WARNING: no ConfigMap file given — resolving the Secret alone. The gate needs "
            "the merge; CM-only keys are exactly the invisible drift this exists to catch.")

    # envFrom order: ConfigMap first, Secret last -> Secret wins duplicates.
    merged = {**cm, **secret}
    shadowed = sorted(k for k in cm if k in secret and cm[k] != secret[k])
    if shadowed:
        print(f"Secret overrides {len(shadowed)} differing ConfigMap key(s): {shadowed}")
    cm_only = sorted(k for k in cm if k not in secret)
    if cm_only:
        print(f"ConfigMap-ONLY keys (reach pods unshadowed — review each): {cm_only}")

    snapshot = dict(os.environ)
    try:
        # A clean slate, then exactly the pod env. Settings reads os.environ; the .env file
        # source is disabled so nothing local leaks into the simulation.
        from app.core.config import Settings, assert_security_posture  # import BEFORE clearing
        os.environ.clear()
        os.environ.update(merged)
        Settings.model_config["env_file"] = None
        try:
            s = Settings()
        except Exception as e:  # noqa: BLE001 — the gate's whole job is reporting ANY construction failure
            print(f"\nGATE FAILED — Settings() raised at construction (pods would crash-loop):"
                f"\n  {type(e).__name__}: {e}")
            return 1
        print("\nSettings constructed OK. Key resolved values:")
        for k in ("app_env", "llm_timeout_seconds", "llm_max_retries", "stage_lease_seconds",
                "reaper_stale_grace_seconds", "treatment_stale_seconds", "db_pool_size",
                "db_max_overflow", "embedding_batch_size", "embedding_concurrency",
                "control_map_shortlist_k", "max_concurrent_llm_calls", "litellm_bypass_proxy",
                "log_file", "trace_sinks"):
            print(f"  {k:28} = {getattr(s, k)!r}")
        try:
            assert_security_posture(s)
        except RuntimeError as e:
            print(f"\nGATE FAILED — security posture refuses to boot:\n  {e}")
            return 1
        print("\nGATE OK: posture passes (warnings above, if any, are non-fatal). "
            "Safe to `oc apply` and roll.")
        return 0
    finally:
        os.environ.clear()
        os.environ.update(snapshot)


if __name__ == "__main__":
    raise SystemExit(main())
