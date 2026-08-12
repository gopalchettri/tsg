"""Self-check: build_results_workbook() renders one row per scenario on a single "Scenarios"
sheet, with controls/supporting_system_applicability flattened per the approved plan.

Run:  .venv/Scripts/python.exe scripts/test_build_results_workbook.py

Assert-based, no framework — matches scripts/test_scenario_flatten.py's style. Builds a
synthetic SessionResults (no DB/LLM) and inspects the returned openpyxl.Workbook directly.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.api.results_excel import _COLUMNS, _sanitize, build_results_workbook  # noqa: E402
from app.api.schemas import (  # noqa: E402
    MappedControl,
    ScenarioNarrative,
    ScenarioResult,
    SessionResults,
    SupportingSystemApplicability,
    ThreatResult,
)

CONTROL_A = MappedControl(
    control_library_id=49, control_code="CII-CID-049", domain="Business Continuity & Disaster Recovery",
    control_name="Telecommunications Services Availability", rank=1, score=99.9,
    suggested_control="Out-of-band backup communications", standards=["DESC ISR v3"])
CONTROL_B = MappedControl(
    control_library_id=464, control_code="CII-CID-464", domain="Secure Engineering & Architecture",
    control_name="Fail Safe", rank=3, score=None, suggested_control=None, standards=[])

APPLICABILITY = [
    SupportingSystemApplicability(supporting_system="OT Telecom Network", applicable=True,
                                justification="Direct target of this scenario."),
    SupportingSystemApplicability(supporting_system="ICS", applicable=False,
                                justification="Local control keeps functioning."),
]

NARRATIVE = ScenarioNarrative(
    threat_category="Denial of Service", threat_type="loss of availability",
    threat_name="Loss of control and generation availability of PGS",
    threat_actors=["External attacker", "Nation-state/APT"],
    controls=[CONTROL_A, CONTROL_B],
    supporting_system_applicability=APPLICABILITY,
    scenario_title="PGS outage", scenario_statement="s", risk_statement="r",
)

CURRENT = ScenarioResult(
    output_id="out-current", threat_id="threat-1", scenario=NARRATIVE, accepted=False,
    moderation_checked=False, validation_status="ok", validation_errors=[],
    generation_epoch=1, scenario_number=1, controls_mapped=True,
    replaced_scenarios=[
        ScenarioResult(output_id="out-old", threat_id="threat-1", scenario=NARRATIVE,
                    accepted=False, moderation_checked=False, validation_status="ok",
                    validation_errors=[], generation_epoch=1, scenario_number=1,
                    controls_mapped=True, replaced_scenarios=[]),
    ],
)

FAILED = ScenarioResult(
    output_id="out-failed", threat_id="threat-2", scenario=None, accepted=False,
    moderation_checked=False, validation_status=None, validation_errors=["missing scenario_title"],
    generation_epoch=1, scenario_number=1, controls_mapped=False, replaced_scenarios=[])

RESULTS = SessionResults(
    session_id="sess-1", entity_id="78", asset_id=99, asset_name="Power Generation System (PGS)",
    user_id="gc", progress=None,
    threats=[ThreatResult(threat_id="threat-1", threat_type="loss of availability",
                        threat_name="Loss of availability", grounding_status="unverified",
                        threat_catalogue_id=None)],
    scenarios=[CURRENT, FAILED],
)


def main() -> None:
    wb = build_results_workbook(RESULTS)

    # 1 — exactly one sheet, named "Scenarios"
    assert wb.sheetnames == ["Scenarios"], wb.sheetnames
    ws = wb["Scenarios"]
    print("1 OK  single sheet named 'Scenarios'")

    # 2 — header row matches _COLUMNS exactly, bold
    header = [c.value for c in ws[1]]
    assert header == list(_COLUMNS), header
    assert all(c.font.bold for c in ws[1])
    print(f"2 OK  header row matches _COLUMNS ({len(header)} columns), bold")

    # 3 — row count: CURRENT + its 1 replaced + FAILED = 3 data rows, plus header = 4
    assert ws.max_row == 4, ws.max_row
    print("3 OK  row count = 1 header + 3 scenario rows (current, replaced, failed)")

    # 4 — is_replaced / current_output_id wiring
    col = {name: i for i, name in enumerate(_COLUMNS)}
    row2 = [c.value for c in ws[2]]  # CURRENT
    row3 = [c.value for c in ws[3]]  # its replaced entry
    row4 = [c.value for c in ws[4]]  # FAILED
    assert row2[col["is_replaced"]] is False and row2[col["current_output_id"]] is None
    assert row3[col["is_replaced"]] is True and row3[col["current_output_id"]] == "out-current"
    print("4 OK  replaced scenario flattened in with is_replaced=True, current_output_id set")

    # 5 — threat_actors joined "; "
    assert row2[col["threat_actors"]] == "External attacker; Nation-state/APT"
    print("5 OK  threat_actors joined with '; '")

    # 6 — controls cell: one line per control, domain present, "n/a" for a None score
    controls_cell = row2[col["controls"]]
    assert ("CII-CID-049 — Telecommunications Services Availability "
            "[Business Continuity & Disaster Recovery] (rank 1, score 99.9)") in controls_cell
    assert "CII-CID-464 — Fail Safe [Secure Engineering & Architecture] (rank 3, score n/a)" in controls_cell
    assert controls_cell.count("\n") == 1  # two controls, one newline between them
    print("6 OK  controls cell: one line per control, domain included, None score -> 'n/a'")

    # 7 — supporting_system_applicability: three labeled lines per entry, Yes/No, blank line
    #     between entries
    app_cell = row2[col["supporting_system_applicability"]]
    assert ("supporting_system: OT Telecom Network\napplicable: Yes\n"
            "justification: Direct target of this scenario.") in app_cell
    assert ("supporting_system: ICS\napplicable: No\n"
            "justification: Local control keeps functioning.") in app_cell
    assert "\n\n" in app_cell
    print("7 OK  supporting_system_applicability: labeled lines, Yes/No, blank-line separated")

    # 8 — scenario_title/statement/risk_statement land correctly, proving ScenarioNarrative's
    #     extra="allow" attributes are readable as plain attributes, not just via model_extra
    assert row2[col["scenario_title"]] == "PGS outage"
    assert row2[col["scenario_statement"]] == "s"
    assert row2[col["risk_statement"]] == "r"
    print("8 OK  extra-allow scenario_title/scenario_statement/risk_statement land in the right cells")

    # 9 — a scenario with scenario=None (failed generation) still gets a row, with narrative
    #     fields blank rather than raising
    assert row4[col["output_id"]] == "out-failed"
    assert row4[col["scenario_title"]] is None
    assert row4[col["controls"]] == ""
    assert row4[col["validation_errors"]] == "missing scenario_title"
    print("9 OK  failed-generation scenario (scenario=None) gets a row, narrative fields blank")

    # 10 — formula-injection guard: a leading '=' gets neutralized with a leading quote
    assert _sanitize("=SUM(A1:A9)") == "'=SUM(A1:A9)"
    assert _sanitize("normal text") == "normal text"
    assert _sanitize(True) is True  # non-strings pass through untouched
    print("10 OK formula-injection guard neutralizes a leading '=' without touching normal values")

    print("\nbuild_results_workbook self-check OK")


if __name__ == "__main__":
    main()
