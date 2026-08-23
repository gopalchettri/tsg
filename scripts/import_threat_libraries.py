#!/usr/bin/env python
"""Admin tool: import open-source threat libraries into the MSSQL threat library.

Thin CLI wrapper — ALL real logic lives in app/pipeline/threat_library_import.py
(shared with the tsg.import_threat_library Celery task behind
POST /v1/tsg/threat-library/sources/{source}/import, so the API and this script can
never drift).

Sources (all free/open; license: MITRE catalogs + CAPEC are free with attribution,
pytm is MIT, Threat Composer is Apache-2.0, MISP galaxy is CC0):
    pytm            OWASP pytm threats.json (SID-prefix -> STRIDE)
    threat_composer AWS Threat Composer pack (impactedGoal CIA -> STRIDE)
    capec           MITRE CAPEC STIX (Meta+Standard only; consequences -> STRIDE)
    attack          MITRE ATT&CK Enterprise STIX (tactic -> STRIDE; no sub-techniques)
    attack_ics      MITRE ATT&CK for ICS STIX (OT; same walker, ICS tactics)
    emb3d           MITRE EMB3D threats.json (OT/embedded; category -> STRIDE)
    misp_actors     MISP galaxy threat-actor cluster -> Threat_Actor table only

OT sources (attack_ics/emb3d) additionally AUTO-WRITE boost-only Config_Threat_Rule
rows (relevance_flag on asset_type='OT' — never tech_gate, so an auto-rule can only
nudge ranking, never hide a threat). The written rules are listed in the result under
"ot_rules". Unmappable rows land in the result's "skipped" list (capped; full count in
"skipped_count").

After a real (non-dry-run) import, refresh the embedding cache so grounding can match
the new rows:
    python scripts/refresh_embeddings.py
(The API path dispatches that refresh automatically; this CLI leaves it manual.)

Usage:
    python scripts/import_threat_libraries.py --source pytm --dry-run
    python scripts/import_threat_libraries.py --source pytm
    python scripts/import_threat_libraries.py --source attack --file enterprise-attack.json
    python scripts/import_threat_libraries.py --source misp_actors --max-actors 40
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # make `app` importable

from app.core.logging import configure_logging
from app.db.engine import db_session
from app.pipeline.threat_library_import import (
    URLS,
    ThreatLibraryImportError,
    run_import,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, choices=sorted(URLS))
    parser.add_argument("--file", help="local JSON file instead of downloading (offline/reproducible)")
    parser.add_argument("--via", choices=["taxii"], help="fetch ATT&CK live via TAXII instead of GitHub")
    parser.add_argument("--dry-run", action="store_true", help="show what would be imported; write nothing")
    parser.add_argument("--max-actors", type=int, default=40,
                        help="misp_actors only: cap on imported actors (they feed the prompt hint)")
    # A CLI run has no authenticated caller, so without this the only recoverable answer to
    # "who imported these rows?" would be the source tag. Defaults to the OS user rather than
    # leaving it blank — an operator running this on a server is exactly who CreatedBy means.
    parser.add_argument("--as-user", default=f"cli:{getpass.getuser()}",
                        help="recorded as CreatedBy on the rows this import creates "
                             "(default: cli:<os-user>)")
    args = parser.parse_args()

    configure_logging()
    file_content = None
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            file_content = fh.read()

    try:
        with db_session() as sess:
            result = run_import(sess, args.source, file_content=file_content,
                                via_taxii=args.via == "taxii", max_actors=args.max_actors,
                                dry_run=args.dry_run, started_by=args.as_user)
    except ThreatLibraryImportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.dry_run:
        print("\ndry-run: nothing written")
    elif args.source != "misp_actors":
        print("next: python scripts/refresh_embeddings.py   (so grounding can match the new rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
