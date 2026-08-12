"""Excel (.xlsx) rendering of GET /v1/sessions/{session_id}/results — one row per scenario.

Pure transform: no DB, no FastAPI. Takes the SAME SessionResults object the JSON endpoint
returns, so the two outputs can never disagree on the underlying data — only presentation
differs here.
"""
from __future__ import annotations

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.worksheet import Worksheet

from app.api.schemas import MappedControl, ScenarioResult, SessionResults, SupportingSystemApplicability

_COLUMNS = (
    "session_id", "entity_id", "asset_id", "asset_name", "user_id",
    "output_id", "threat_id", "threat_category", "threat_type", "threat_name", "threat_actors",
    "scenario_title", "scenario_statement", "risk_statement",
    "controls", "supporting_system_applicability",
    "accepted", "validation_status", "validation_errors", "controls_mapped",
    "generation_epoch", "scenario_number", "is_replaced", "current_output_id",
)

#: Multi-line/long-prose columns get wrap_text; everything else stays single-line.
_WRAP_COLUMNS = frozenset({
    "scenario_statement", "risk_statement", "controls", "supporting_system_applicability",
})

#: Starting widths — narrow for ids/flags, wide for prose/list columns. Not load-bearing; a
#: reviewer can resize in Excel same as any spreadsheet.
_COLUMN_WIDTHS = {
    "session_id": 24, "entity_id": 10, "asset_id": 10, "asset_name": 28, "user_id": 12,
    "output_id": 24, "threat_id": 24, "threat_category": 16, "threat_type": 22, "threat_name": 40,
    "threat_actors": 30, "scenario_title": 40, "scenario_statement": 50, "risk_statement": 50,
    "controls": 50, "supporting_system_applicability": 40, "accepted": 10, "validation_status": 14,
    "validation_errors": 30, "controls_mapped": 14, "generation_epoch": 12, "scenario_number": 12,
    "is_replaced": 10, "current_output_id": 24,
}

#: Leading characters Excel/LibreOffice treat as a formula trigger — a cell value starting with
#: one of these executes as a formula on open, not shown as text. Content here ultimately
#: originates from LLM output and free-text DB fields (control names, justifications), so this is
#: a real trust boundary, not a speculative guard.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _sanitize(value):
    """Prefix a formula-triggering leading character with `'` so Excel renders it as literal
    text instead of executing it."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def _controls_cell(controls: list[MappedControl]) -> str:
    """One '{code} — {name} [{domain}] (rank R, score S)' line per mapped control."""
    lines = []
    for c in controls:
        score = f"{c.score:.1f}" if c.score is not None else "n/a"
        lines.append(f"{c.control_code} — {c.control_name} [{c.domain}] (rank {c.rank}, score {score})")
    return "\n".join(lines)


def _applicability_cell(entries: list[SupportingSystemApplicability]) -> str:
    """Each entry as three labeled lines, blank-line separated from the next entry."""
    blocks = [
        f"supporting_system: {e.supporting_system}\n"
        f"applicable: {'Yes' if e.applicable else 'No'}\n"
        f"justification: {e.justification}"
        for e in entries
    ]
    return "\n\n".join(blocks)


def _row(results: SessionResults, scenario: ScenarioResult, *,
        is_replaced: bool, current_output_id: str | None) -> dict:
    narrative = scenario.scenario
    return {
        "session_id": results.session_id, "entity_id": results.entity_id,
        "asset_id": results.asset_id, "asset_name": results.asset_name, "user_id": results.user_id,
        "output_id": scenario.output_id, "threat_id": scenario.threat_id,
        "threat_category": getattr(narrative, "threat_category", None),
        "threat_type": getattr(narrative, "threat_type", None),
        "threat_name": getattr(narrative, "threat_name", None),
        "threat_actors": "; ".join(getattr(narrative, "threat_actors", None) or []),
        "scenario_title": getattr(narrative, "scenario_title", None),
        "scenario_statement": getattr(narrative, "scenario_statement", None),
        "risk_statement": getattr(narrative, "risk_statement", None),
        "controls": _controls_cell(narrative.controls) if narrative else "",
        "supporting_system_applicability": (
            _applicability_cell(narrative.supporting_system_applicability) if narrative else ""),
        "accepted": scenario.accepted,
        "validation_status": scenario.validation_status,
        "validation_errors": "; ".join(scenario.validation_errors or []),
        "controls_mapped": scenario.controls_mapped,
        "generation_epoch": scenario.generation_epoch,
        "scenario_number": scenario.scenario_number,
        "is_replaced": is_replaced,
        "current_output_id": current_output_id,
    }


def _iter_rows(results: SessionResults):
    """Every current scenario, then every scenario it replaced (only populated when the caller
    requested ?include_replaced=true) — flat, since ScenarioResult.replaced_scenarios is itself
    never nested (built one level deep by sessions.py::get_results)."""
    for scenario in results.scenarios:
        yield _row(results, scenario, is_replaced=False, current_output_id=None)
        for replaced in scenario.replaced_scenarios:
            yield _row(results, replaced, is_replaced=True, current_output_id=scenario.output_id)


def build_results_workbook(results: SessionResults) -> Workbook:
    """One 'Scenarios' sheet, one row per scenario (current, plus replaced when included)."""
    wb = Workbook()
    ws: Worksheet = wb.active
    ws.title = "Scenarios"

    header_font = Font(bold=True)
    wrap = Alignment(wrap_text=True, vertical="top")
    plain = Alignment(vertical="top")

    for col_idx, name in enumerate(_COLUMNS, start=1):
        cell = ws.cell(row=1, column=col_idx, value=name)
        cell.font = header_font
        ws.column_dimensions[get_column_letter(col_idx)].width = _COLUMN_WIDTHS[name]
    ws.freeze_panes = "A2"

    row_idx = 2
    for row in _iter_rows(results):
        for col_idx, name in enumerate(_COLUMNS, start=1):
            cell = ws.cell(row=row_idx, column=col_idx, value=_sanitize(row[name]))
            cell.alignment = wrap if name in _WRAP_COLUMNS else plain
        row_idx += 1

    return wb
