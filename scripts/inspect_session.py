#!/usr/bin/env python
"""Read-only diagnostic dump for one Scenario_Session: session row, every
Subsystem_Stage_State row, and any Scenario_Audit rows with EventType=stage_error.

No writes. Useful when GET /v1/sessions/{id}/results shows progress=error but the
API's error_message is the sanitized generic string ("stage processing failed") --
this narrows down WHICH subsystem/level failed and how many attempts were made.
It does NOT recover the real exception: that only ever goes to the Celery worker's
console log (log.error("stage.error", ..., error=repr(exc))), never to the DB.

    python scripts/inspect_session.py <session_id>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # make `app` importable

from sqlalchemy import select

from app.db import models as m
from app.db.engine import db_session


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python scripts/inspect_session.py <session_id>")
        return 2
    sid = sys.argv[1]

    with db_session() as sess:
        session_row = sess.execute(
            select(m.Scenario_Session).where(m.Scenario_Session.SessionID == sid)
        ).scalar_one_or_none()
        if not session_row:
            print(f"No Scenario_Session found for {sid}")
            return 1

        print("=== Scenario_Session ===")
        print(f"  EntityID={session_row.EntityID}  AssetID={session_row.AssetID}  "
              f"Status={session_row.SessionStatus}  CurrentStage={session_row.CurrentStage}  "
              f"StageStatus={session_row.StageStatus}")
        print(f"  CreatedAt={session_row.CreatedAt}  UpdatedAt={session_row.UpdatedAt}")

        print("\n=== Subsystem_Stage_State ===")
        stage_rows = sess.execute(
            select(m.Subsystem_Stage_State)
            .where(m.Subsystem_Stage_State.SessionID == sid)
            .order_by(m.Subsystem_Stage_State.UpdatedAt)
        ).scalars().all()
        for r in stage_rows:
            print(f"  Subsystem={r.SubsystemID}  Level={r.Level}  Status={r.Status}  "
                  f"Attempts={r.AttemptCount}  UpdatedAt={r.UpdatedAt}")
            if r.ErrorMessage:
                print(f"    ErrorMessage={r.ErrorMessage!r}")

        print("\n=== Scenario_Audit (stage_error only) ===")
        audit_rows = sess.execute(
            select(m.Scenario_Audit)
            .where(m.Scenario_Audit.SessionID == sid, m.Scenario_Audit.EventType == "stage_error")
            .order_by(m.Scenario_Audit.CreatedAt)
        ).scalars().all()
        if not audit_rows:
            print("  (none)")
        for r in audit_rows:
            print(f"  {r.CreatedAt}  subsystem={r.SubsystemID}  {r.DetailJSON}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
