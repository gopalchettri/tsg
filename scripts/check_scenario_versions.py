"""Find scenarios that exist twice — damage the promote-to-library identity bug could leave behind.

WHY THIS EXISTS. A scenario's IdentityHash is folded from its threat's library ids, and
promote-to-library rewrites those ids. Until the fix, a regeneration after a promotion stamped its
rewrite with the NEW identity and retired "whatever row holds it" — which was nothing. The target
stayed live beside its replacement, and because the two carry different stored hashes, every later
check reads them as two unrelated scenarios: both acceptable, both plannable. One risk, two
accepted versions, two remediation plans, and a register that counts it twice.

The writer is fixed. Rows already written are not: nothing retires them retroactively, and no
constraint objects, because the pair is only wrong in a way that requires knowing both rows came
from one threat. So this is a READ-ONLY report to run once per environment after deploying. It
writes nothing and decides nothing — a pair it finds is for a human to resolve (reject the version
you do not want, or accept the one you do with replace_accepted).

    .venv/Scripts/python.exe scripts/check_scenario_versions.py

Exit code 0 = clean, 1 = something to look at, so a deploy step or CI can gate on it.
"""
from __future__ import annotations

import sys

from sqlalchemy import text

from app.db.engine import get_engine

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

#: One threat with more than one live scenario. Grouped by the THREAT, not by the hash: two rows
#: whose hashes drifted apart are exactly what this looks for, so grouping by hash would hide
#: every case it exists to find.
TWO_LIVE = text("""
SELECT s.AssetName, o.SessionID, st.ThreatID, COUNT(*) AS versions,
       MIN(CONVERT(varchar(36), o.ScenarioID)) AS one_id,
       MAX(CONVERT(varchar(36), o.ScenarioID)) AS other_id
FROM Threat_Scenario o
JOIN Scoped_Threat st ON st.ScopedThreatID = o.ScopedThreatID
JOIN Scenario_Session s ON s.SessionID = o.SessionID
WHERE o.Superseded = 0 AND o.Status = 'complete'
GROUP BY s.AssetName, o.SessionID, st.ThreatID
HAVING COUNT(*) > 1
ORDER BY s.AssetName
""")

#: The consequence that reaches the register: one threat carrying two accepted versions, each free
#: to hold its own remediation plan.
TWO_ACCEPTED = text("""
SELECT s.AssetName, o.SessionID, st.ThreatID, COUNT(*) AS accepted_versions
FROM Threat_Scenario o
JOIN Scoped_Threat st ON st.ScopedThreatID = o.ScopedThreatID
JOIN Scenario_Session s ON s.SessionID = o.SessionID
WHERE o.Accepted = 1
GROUP BY s.AssetName, o.SessionID, st.ThreatID
HAVING COUNT(*) > 1
ORDER BY s.AssetName
""")

#: Plans hanging off those doubled versions — what an auditor would see twice.
PLANS_ON_DOUBLES = text("""
SELECT p.PlanID, p.ScenarioID, p.Status, p.ReviewStatus
FROM Risk_Treatment_Plan p
JOIN Threat_Scenario o ON o.ScenarioID = p.ScenarioID
JOIN Scoped_Threat st ON st.ScopedThreatID = o.ScopedThreatID
WHERE p.Superseded = 0 AND o.Accepted = 1 AND st.ThreatID IN (
    SELECT st2.ThreatID FROM Threat_Scenario o2
    JOIN Scoped_Threat st2 ON st2.ScopedThreatID = o2.ScopedThreatID
    WHERE o2.Accepted = 1
    GROUP BY o2.SessionID, st2.ThreatID HAVING COUNT(*) > 1)
""")


def main() -> int:
    findings = 0
    with get_engine().connect() as conn:
        print(f"database: {conn.engine.url.database}\n")
        for label, stmt in (("One threat with TWO LIVE scenario versions", TWO_LIVE),
                            ("One threat with TWO ACCEPTED versions", TWO_ACCEPTED),
                            ("Plans sitting on those doubled versions", PLANS_ON_DOUBLES)):
            rows = conn.execute(stmt).mappings().all()
            findings += len(rows)
            print(f"{label}: {len(rows)}")
            for r in rows:
                print("   ", dict(r))
    if findings:
        print("\nRows to resolve by hand: keep one version per threat — reject the one you do not "
            "want, or accept the one you do with replace_accepted. Nothing was changed.")
        return 1
    print("\nClean: every threat has at most one live and one accepted scenario version.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
