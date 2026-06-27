from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any

import xlsxwriter

from .analytics import build_analytics, count_by


DETAIL_COLUMNS = [
    "Alert ID",
    "Aggregate ID",
    "Created Timestamp",
    "Updated Timestamp",
    "Status",
    "Severity",
    "Severity Name",
    "Product",
    "Detection Type",
    "Tactic",
    "Tactic ID",
    "Technique",
    "Technique ID",
    "Objective",
    "Scenario",
    "Hostname",
    "Device ID",
    "Platform",
    "OS Version",
    "Local IP",
    "External IP",
    "Username",
    "Process Name",
    "File Name",
    "File Path",
    "Command Line",
    "SHA256",
    "MD5",
    "Assigned To",
    "Description",
    "Disposition",
    "Resolution",
    "Tags",
]


def _safe_sheet_name(name: str) -> str:
    invalid = set("[]:*?/\\")
    cleaned = "".join("_" if char in invalid else char for char in name)
    return cleaned[:31] or "Sheet"


def _write_table_sheet(
    workbook: xlsxwriter.Workbook,
    name: str,
    rows: list[dict[str, Any]],
    *,
    columns: list[str] | None = None,
) -> None:
    sheet = workbook.add_worksheet(_safe_sheet_name(name))
    header_fmt = workbook.add_format(
        {
            "bold": True,
            "font_color": "#FFFFFF",
            "bg_color": "#123A6D",
            "border": 1,
            "align": "center",
            "valign": "vcenter",
            "text_wrap": True,
        }
    )
    body_fmt = workbook.add_format({"border": 1, "valign": "top"})
    wrap_fmt = workbook.add_format(
        {"border": 1, "valign": "top", "text_wrap": True}
    )
    number_fmt = workbook.add_format(
        {"border": 1, "num_format": "0", "valign": "top"}
    )
    percent_fmt = workbook.add_format(
        {"border": 1, "num_format": "0.00%", "valign": "top"}
    )

    if columns is None:
        columns = list(rows[0].keys()) if rows else ["Information"]

    for col_idx, column in enumerate(columns):
        sheet.write(0, col_idx, column, header_fmt)

    if not rows:
        sheet.write(1, 0, "Tidak ada data pada periode/filter ini.", wrap_fmt)

    for row_idx, row in enumerate(rows, start=1):
        for col_idx, column in enumerate(columns):
            value = row.get(column, "")
            if column == "Coverage %" and isinstance(value, (int, float)):
                sheet.write_number(row_idx, col_idx, float(value) / 100, percent_fmt)
            elif isinstance(value, bool):
                sheet.write_boolean(row_idx, col_idx, value, body_fmt)
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                sheet.write_number(row_idx, col_idx, value, number_fmt)
            else:
                sheet.write(row_idx, col_idx, str(value or ""), wrap_fmt)

    last_row = max(len(rows), 1)
    sheet.freeze_panes(1, 0)
    sheet.autofilter(0, 0, last_row, len(columns) - 1)
    sheet.set_row(0, 30)

    width_map = {
        "Alert ID": 38,
        "Aggregate ID": 32,
        "Created Timestamp": 23,
        "Updated Timestamp": 23,
        "Status": 16,
        "Severity Name": 16,
        "Product": 20,
        "Detection Type": 24,
        "Tactic": 25,
        "Technique": 34,
        "Hostname": 24,
        "OS Version": 26,
        "Command Line": 60,
        "Description": 60,
        "File Path": 48,
        "SHA256": 68,
        "MD5": 36,
        "Raw JSON": 100,
        "Count": 12,
        "Coverage %": 14,
    }
    for col_idx, column in enumerate(columns):
        sheet.set_column(col_idx, col_idx, width_map.get(column, 20))


def build_detection_workbook(
    records: list[dict[str, Any]],
    *,
    metadata: dict[str, Any],
    top_n: int = 10,
    collection_pages: int = 0,
    truncated: bool = False,
    fql_filter: str = "",
) -> bytes:
    output = io.BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    workbook.set_properties(
        {
            "title": "Seraphim CrowdStrike Detection Export",
            "subject": "Standalone CrowdStrike Alerts API export",
            "author": "PT. Seraphim Digital Technology",
            "company": "PT. Seraphim Digital Technology",
        }
    )

    analytics = build_analytics(records, top_n=top_n)
    status_lookup = {
        str(item.get("Status") or "").lower(): int(item.get("Count") or 0)
        for item in analytics["status"]
    }
    in_progress = status_lookup.get("in progress", 0) + status_lookup.get("in_progress", 0)
    reopened = status_lookup.get("reopened", 0)

    summary = workbook.add_worksheet("Summary")
    title_fmt = workbook.add_format(
        {
            "bold": True,
            "font_color": "#FFFFFF",
            "bg_color": "#0B2E59",
            "font_size": 16,
            "align": "center",
            "valign": "vcenter",
        }
    )
    section_fmt = workbook.add_format(
        {
            "bold": True,
            "font_color": "#123A6D",
            "bg_color": "#DCE8F5",
            "border": 1,
        }
    )
    label_fmt = workbook.add_format(
        {"bold": True, "bg_color": "#EEF4FA", "border": 1}
    )
    value_fmt = workbook.add_format(
        {"border": 1, "text_wrap": True, "align": "left"}
    )
    integer_fmt = workbook.add_format({"border": 1, "num_format": "0"})
    pct_fmt = workbook.add_format({"border": 1, "num_format": "0.00%"})
    warning_fmt = workbook.add_format(
        {
            "bold": True,
            "font_color": "#7F6000",
            "bg_color": "#FFF4CE",
            "border": 1,
            "text_wrap": True,
        }
    )

    summary.merge_range(
        "A1:F1", "Seraphim — CrowdStrike Detection Export (Standalone)", title_fmt
    )
    summary.set_row(0, 32)
    summary.write("A3", "Extraction Information", section_fmt)
    summary.merge_range("B3:F3", "", section_fmt)

    info_rows = [
        ("Customer", metadata.get("customer_name", "")),
        ("Report Label", metadata.get("report_label", "")),
        (
            "Period",
            f"{metadata.get('start_date', '')} s.d. {metadata.get('end_date', '')}",
        ),
        ("Source", "CrowdStrike Alerts API via FalconPy (Alerts: READ)"),
        ("Falcon Cloud", metadata.get("base_url", "")),
        ("Member CID", metadata.get("member_cid", "") or "Default CID"),
        (
            "Extraction UTC",
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        ),
        ("API Pages", collection_pages),
        ("Truncated", "YES" if truncated else "NO"),
        ("FQL Filter", fql_filter),
    ]
    for row_idx, (label, value) in enumerate(info_rows, start=3):
        summary.write(row_idx, 0, label, label_fmt)
        summary.merge_range(
            row_idx,
            1,
            row_idx,
            5,
            value,
            warning_fmt if label == "Truncated" and truncated else value_fmt,
        )

    kpi_row = 15
    summary.write(kpi_row, 0, "Detection KPI", section_fmt)
    summary.merge_range(kpi_row, 1, kpi_row, 5, "", section_fmt)
    kpis = [
        ("Total Alerts", analytics["total"], integer_fmt),
        ("New/Open", analytics["new"], integer_fmt),
        ("In Progress", in_progress, integer_fmt),
        ("Reopened", reopened, integer_fmt),
        ("Closed/Resolved", analytics["closed"], integer_fmt),
        (
            "Closure Rate",
            (analytics["closure_rate_pct"] or 0) / 100,
            pct_fmt,
        ),
        ("Backlog", (analytics["backlog_pct"] or 0) / 100, pct_fmt),
    ]
    for idx, (label, value, fmt) in enumerate(kpis, start=kpi_row + 1):
        summary.write(idx, 0, label, label_fmt)
        summary.write(idx, 1, value, fmt)

    summary.set_column("A:A", 24)
    summary.set_column("B:F", 24)
    summary.freeze_panes(3, 0)

    detail_columns = DETAIL_COLUMNS + (
        ["Raw JSON"] if records and "Raw JSON" in records[0] else []
    )
    _write_table_sheet(workbook, "Alerts Detail", records, columns=detail_columns)
    _write_table_sheet(workbook, "By Status", analytics["status"])
    _write_table_sheet(workbook, "By Severity", analytics["severity"])
    _write_table_sheet(workbook, "By Product", count_by(records, "Product"))
    _write_table_sheet(
        workbook, "By Detection Type", count_by(records, "Detection Type")
    )
    _write_table_sheet(workbook, "By Platform", count_by(records, "Platform"))
    _write_table_sheet(workbook, "Top Host", analytics["top_hosts"])
    _write_table_sheet(workbook, "Top Tactic", analytics["top_tactics"])
    _write_table_sheet(workbook, "Top Technique", analytics["top_techniques"])
    _write_table_sheet(workbook, "Top File", analytics["top_files"])
    _write_table_sheet(workbook, "Top Hash", analytics["top_hashes"])
    _write_table_sheet(
        workbook, "Top Command Line", analytics["top_command_lines"]
    )
    _write_table_sheet(workbook, "Top User", analytics["top_users"])
    _write_table_sheet(workbook, "Daily Trend", analytics["daily_trend"])
    _write_table_sheet(workbook, "Field Coverage", analytics["field_coverage"])

    workbook.close()
    output.seek(0)
    return output.getvalue()
