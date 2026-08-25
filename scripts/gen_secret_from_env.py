"""Generate deploy/secrets.yaml (the tsg-api-secrets Secret) FROM an env file.

WHY THIS EXISTS: the deployment strategy is one tested env file (.env.uat) reused across
environments — but cluster pods read the Secret, not the file, and every hand-merge between
the two has drifted or corrupted (values un-quoted, '=' mangled to ':', keys landing outside
stringData, cluster-only settings overwritten). Deriving the Secret from the env file makes
drift structurally impossible: edit .env.uat, re-run this, apply.

Cluster-vs-jump-server differences are DECLARED here, in one reviewed place:
  - DROPPED keys: file/trace logging (pods log to stdout; kubelet rotates; files die with
    the container — Promtail tails files only on the jump server).
  - OVERRIDDEN keys: TSG_LITELLM_BYPASS_PROXY must be 'false' in-cluster (llmapi.govai.ae is
    reachable ONLY through the corporate proxy 10.61.192.2:8080 — see deploy.yaml hostAliases
    comment); Mongo adds directConnection=true (single external mongod, skip discovery).

Every value is emitted as a single-quoted YAML string: Secret stringData REJECTS non-string
scalars ('180.0' is fine, 180.0 is an API-server error).

Usage:  python scripts/gen_secret_from_env.py [.env.uat] [deploy/secrets.yaml]
"""
from __future__ import annotations

import sys
from pathlib import Path

from dotenv import dotenv_values

# Jump-server-only keys: never ship to pods.
DROP = {
    "TRACE_SINKS", "TRACE_DIR", "TRACE_MAX_BYTES", "TRACE_BACKUPS", "LOG_FILE",
}

# Cluster-only values, applied AFTER the env file (each with the reason it differs).
CLUSTER_OVERRIDES = {
    # Pods reach llmapi.govai.ae ONLY via the corporate proxy; true (the jump-server value)
    # sets NO_PROXY and the pod cannot reach the LLM at all.
    "TSG_LITELLM_BYPASS_PROXY": "false",
    # Single external mongod: skip topology discovery.
    "TSG_MONGO_URL": None,  # filled below: env value + '&directConnection=true'
}

HEADER = """\
# UAT — REAL values. Git-ignored, never commit. Apply: oc apply -f <this file>
#
# GENERATED from .env.uat by scripts/gen_secret_from_env.py — DO NOT HAND-EDIT.
# To change a value: edit .env.uat (the tested source of truth), re-run the generator, apply.
# Cluster-vs-jump-server deltas (dropped file-logging keys, TSG_LITELLM_BYPASS_PROXY=false,
# Mongo directConnection) are declared IN THE GENERATOR, not here.
#
# Wire into all three Deployments (FastAPI + Celery + beat) with:
#   envFrom:
#     - configMapRef:
#         name: tsg-api-config
#     - secretRef:
#         name: tsg-api-secrets
# envFrom order matters: the Secret is listed LAST, so for any key present in both sources
# the Secret wins — every key here neutralizes whatever the (untracked) ConfigMap carries.
apiVersion: v1
kind: Secret
metadata:
  name: tsg-api-secrets
  namespace: {namespace}
type: Opaque
stringData:
"""


def q(v: str) -> str:
    """Single-quoted YAML scalar (the only style safe for %, #, !, *, : in these values)."""
    return "'" + v.replace("'", "''") + "'"


def main() -> int:
    # --namespace targets another namespace's copy of the SAME Secret (day-one ai-remediation
    # workers): both namespaces derive from the one tested env file, so they cannot drift.
    args = list(sys.argv[1:])
    namespace = "ai-threatgen"
    if "--namespace" in args:
        i = args.index("--namespace")
        namespace = args[i + 1]
        del args[i:i + 2]
    env_path = Path(args[0] if args else ".env.uat")
    out_path = Path(args[1] if len(args) > 1 else "deploy/secrets.yaml")

    values = {k: v for k, v in dotenv_values(env_path).items() if v is not None}
    if "TSG_DB_DSN" not in values:
        print(f"error: {env_path} has no TSG_DB_DSN — wrong file?", file=sys.stderr)
        return 1

    dropped = sorted(DROP & values.keys())
    for k in dropped:
        del values[k]

    mongo = values.get("TSG_MONGO_URL", "")
    if mongo and "directConnection" not in mongo:
        sep = "&" if "?" in mongo else "?"
        values["TSG_MONGO_URL"] = f"{mongo}{sep}directConnection=true"
    for k, v in CLUSTER_OVERRIDES.items():
        if v is not None:
            values[k] = v

    lines = [HEADER.format(namespace=namespace)]
    lines += [f"  {k}: {q(v)}\n" for k, v in values.items()]
    out_path.write_text("".join(lines), encoding="utf-8")
    print(f"{out_path}: {len(values)} keys from {env_path} (namespace {namespace}) "
        f"(dropped {dropped}; overrides: TSG_LITELLM_BYPASS_PROXY=false, Mongo directConnection)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
