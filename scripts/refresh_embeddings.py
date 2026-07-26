#!/usr/bin/env python
"""Admin tool: pre-warm or force-recreate the threat-library embedding cache.

Thin CLI over app/pipeline/embeddings.py's update_group/recreate_group/delete_group — the
same functions the UI-facing admin API (app/api/admin.py) calls, so the CLI and the UI can
never drift into refreshing different things under the same group name.

Two real ops scenarios:
  - UPDATE (default, cheap, always safe) — after importing new threats (Excel/MITRE
    seed scripts), embed whatever is missing. Rows already cached (same model + text)
    are skipped automatically; nothing to flag here.
  - RECREATE (--recreate) — after swapping EMBEDDING_MODEL, or if a master's text
    changed under the SAME model, or a vector needs regenerating. Deletes the group's
    cached vectors first, then re-embeds everything.

Usage:
    python scripts/refresh_embeddings.py                       # update, both groups
    python scripts/refresh_embeddings.py --group threat_type   # update, one group
    python scripts/refresh_embeddings.py --recreate             # full re-embed, both groups
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # make `app` importable

from app.core.logging import configure_logging  # noqa: E402
from app.db.engine import db_session  # noqa: E402
from app.pipeline import embeddings  # noqa: E402
from app.pipeline.llm import get_llm  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--group", choices=sorted(embeddings._GROUPS), help="limit to one group (default: all)")
    parser.add_argument("--recreate", action="store_true",
                        help="delete cached vectors first, forcing a full re-embed")
    args = parser.parse_args()

    configure_logging()
    embeddings.process_role = "cli"  # created_by provenance on any vectors this run computes
    llm = get_llm()
    action = embeddings.recreate_group if args.recreate else embeddings.update_group

    def run_one(group: str) -> int:
        with db_session() as sess:
            return action(sess, llm, group)

    results = embeddings._for_each_group(args.group, run_one)
    for group, result in results.items():
        print(f"{group}: {result}")
    total = sum(v for v in results.values() if isinstance(v, int))
    print(f"\nTotal rows processed: {total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
