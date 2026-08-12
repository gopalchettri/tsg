"""Self-check: build_treatment_plans_workbook() renders one row per accepted scenario's plan on
a single "Treatment Plans" sheet, with the two gap-analysis/action-plan lists flattened.

Run:  .venv/Scripts/python.exe scripts/test_build_treatment_plans_workbook.py

Assert-based, no framework — matches scripts/test_build_results_workbook.py's style. Builds
synthetic TreatmentPlanStatus objects (no DB/LLM) and inspects the returned openpyxl.Workbook
directly.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.api.schemas import TreatmentPlanStatus  # noqa: E402
from app.api.treatment_plan_excel import (  # noqa: E402
    _COLUMNS,
    _sanitize,
    build_treatment_plans_workbook,
)

SESSION_ID = "sess-1"

COMPLETE = TreatmentPlanStatus(
    plan_id="plan-1", session_id=SESSION_ID, output_id="out-1", status="COMPLETE",
    treatment_strategy="Mitigate",
    scenario={"scenario_title": "Ransomware via exposed RDP",
             "scenario_statement": "s", "risk_statement": "r"},
    risk_level="Critical", review_status="approved",
    risk_identification_date=None,
    plan={
        "title": "Remote Access Hardening", "treatment_plan": "Mitigate",
        "action_plan": "Harden remote access in three phases.",
        "applicable_to_all_subsystems": "No",
        "controls_to_be_implemented": [
            {"control_type": "Technical", "control_name": "MFA on RDP",
             "description": "Require MFA for all remote sessions.", "priority": "High"},
        ],
        "remediation_action_plan": [
            {"action_id": "A1", "action": "Disable direct RDP exposure", "owner": "Network Team",
             "priority": "High", "timeline": "30 days"},
        ],
        "mitigation_timeline": "90 days overall", "mitigation_owner": "OT Security Team",
        "risk_owner": "Head of OT Operations", "impacted_business_division": "Water Treatment Operations",
    },
    error_message=None, reason=None,
)

RUNNING_NO_PLAN = TreatmentPlanStatus(
    plan_id="plan-2", session_id=SESSION_ID, output_id="out-2", status="RUNNING",
    treatment_strategy="Mitigate", scenario=None, risk_level="High", review_status=None,
    risk_identification_date=None, plan=None, error_message=None, reason=None,
)


def main() -> None:
    wb = build_treatment_plans_workbook(SESSION_ID, [COMPLETE, RUNNING_NO_PLAN])

    # 1 — exactly one sheet, named "Treatment Plans"
    assert wb.sheetnames == ["Treatment Plans"], wb.sheetnames
    ws = wb["Treatment Plans"]
    print("1 OK  single sheet named 'Treatment Plans'")

    # 2 — header row matches _COLUMNS exactly, bold
    header = [c.value for c in ws[1]]
    assert header == list(_COLUMNS), header
    assert all(c.font.bold for c in ws[1])
    print(f"2 OK  header row matches _COLUMNS ({len(header)} columns), bold")

    # 3 — row count: COMPLETE + RUNNING_NO_PLAN = 2 data rows, plus header = 3
    assert ws.max_row == 3, ws.max_row
    print("3 OK  row count = 1 header + 2 plan rows")

    col = {name: i for i, name in enumerate(_COLUMNS)}
    row2 = [c.value for c in ws[2]]  # COMPLETE
    row3 = [c.value for c in ws[3]]  # RUNNING_NO_PLAN

    # 4 — scenario/plan fields land in the right cells for a COMPLETE plan
    assert row2[col["session_id"]] == SESSION_ID
    assert row2[col["scenario_title"]] == "Ransomware via exposed RDP"
    assert row2[col["plan_title"]] == "Remote Access Hardening"
    assert row2[col["mitigation_owner"]] == "OT Security Team"
    print("4 OK  identifying/scenario/plan fields land in the right cells")

    # 5 — controls_to_be_implemented flattened: one line per entry, priority/type/name/description
    controls_cell = row2[col["controls_to_be_implemented"]]
    assert controls_cell == "[High] Technical: MFA on RDP — Require MFA for all remote sessions."
    print("5 OK  controls_to_be_implemented flattened to one line per gap-analysis entry")

    # 6 — remediation_action_plan flattened: one line per action
    actions_cell = row2[col["remediation_action_plan"]]
    assert actions_cell == ("A1: Disable direct RDP exposure "
                            "(owner: Network Team, priority: High, timeline: 30 days)")
    print("6 OK  remediation_action_plan flattened to one line per action")

    # 7 — a RUNNING plan with plan=None still gets a row, plan-detail cells blank not raising
    assert row3[col["output_id"]] == "out-2"
    assert row3[col["status"]] == "RUNNING"
    assert row3[col["plan_title"]] is None
    assert row3[col["controls_to_be_implemented"]] == ""
    assert row3[col["remediation_action_plan"]] == ""
    print("7 OK  plan=None (RUNNING/ERROR) row renders blank plan-detail cells, no raise")

    # 8 — formula-injection guard: a leading '=' gets neutralized with a leading quote
    assert _sanitize("=SUM(A1:A9)") == "'=SUM(A1:A9)"
    assert _sanitize("+cmd") == "'+cmd"
    assert _sanitize("normal text") == "normal text"
    assert _sanitize(None) is None  # non-strings pass through untouched
    print("8 OK  formula-injection guard neutralizes a leading '=' / '+' without touching normal values")

    print("\nbuild_treatment_plans_workbook self-check OK")


if __name__ == "__main__":
    main()
