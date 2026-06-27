from __future__ import annotations

import json
import re
from datetime import date, datetime, timezone
from io import BytesIO
from typing import Any

import pandas as pd
import xlsxwriter

from .policy_assessment import policy_summary
from .policy_mapping import disabled_items_summary, unmapped_items
from .sensor_health import sensor_health_summary


BLUE = "#123A6D"
DARK_BLUE = "#0B2E59"
LIGHT_BLUE = "#DCE8F5"
PALE_BLUE = "#EEF4FA"
GREEN = "#C6EFCE"
GREEN_DARK = "#548235"
RED = "#C00000"
YELLOW = "#FFF2CC"
BLACK = "#000000"
WHITE = "#FFFFFF"
GRID = "#9FB3C8"


HOST_EXPORT_COLUMNS = [
    "Hostname",
    "Host ID",
    "CID",
    "Customer Name",
    "Last Seen",
    "First Seen",
    "Platform",
    "OS Version",
    "Type",
    "Local IP",
    "External IP",
    "MAC Address",
    "Sensor Version",
    "Host Groups",
    "Sensor Tags",
    "Last Logged In User Account",
    "Criticality",
    "Prevention Policy",
    "Sensor Update Policy",
    "Content Update Policy",
    "USB Device Policy",
    "Host Retention Policy",
    "RFM",
    "Normalized Version",
    "Release Channel",
    "Release Date",
    "End of Support",
    "Support Status",
    "Release Age Days",
    "Release Recency",
    "RFM Status",
    "Inactive Days",
    "Inactive >14 Days",
    "Recommendation",
]

DETAIL_COLUMNS = [
    "Hostname",
    "Platform",
    "OS Version",
    "Last Seen",
    "Sensor Version",
    "Support Status",
    "Release Date",
    "End of Support",
    "Release Recency",
    "RFM Status",
    "Inactive Days",
    "Recommendation",
]


def _safe_df(df: pd.DataFrame | None) -> pd.DataFrame:
    return df.copy() if isinstance(df, pd.DataFrame) else pd.DataFrame()


def _clean_customer_filename(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "Customer").strip())
    return text.strip("_") or "Customer"


def _to_naive_datetime(value: Any) -> datetime | None:
    if value is None or value is pd.NaT:
        return None
    if isinstance(value, pd.Timestamp):
        if pd.isna(value):
            return None
        dt = value.to_pydatetime()
    elif isinstance(value, datetime):
        dt = value
    elif isinstance(value, date):
        return datetime.combine(value, datetime.min.time())
    else:
        parsed = pd.to_datetime(value, errors="coerce", utc=True)
        if pd.isna(parsed):
            return None
        dt = parsed.to_pydatetime()
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _write_scalar(ws: Any, row: int, col: int, value: Any, fmt: Any, date_fmt: Any, datetime_fmt: Any) -> None:
    if isinstance(value, bool):
        ws.write(row, col, "Yes" if value else "No", fmt)
        return
    if isinstance(value, (pd.Timestamp, datetime, date)):
        dt = _to_naive_datetime(value)
        if dt is not None:
            chosen = date_fmt if isinstance(value, date) and not isinstance(value, (pd.Timestamp, datetime)) else datetime_fmt
            ws.write_datetime(row, col, dt, chosen)
            return
    if value is None or (isinstance(value, float) and pd.isna(value)) or value is pd.NaT:
        ws.write_blank(row, col, None, fmt)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        ws.write_number(row, col, float(value), fmt)
    else:
        ws.write(row, col, str(value), fmt)


def _host_export_frame(assessment: pd.DataFrame, customer_name: str) -> pd.DataFrame:
    source = _safe_df(assessment)
    if source.empty:
        return pd.DataFrame(columns=HOST_EXPORT_COLUMNS)
    result = source.copy()
    if "Normalized Sensor Version" in result:
        result["Normalized Version"] = result["Normalized Sensor Version"]
    elif "Normalized Version" not in result:
        result["Normalized Version"] = ""
    if "Inactive >14 Days" in result:
        result["Inactive >14 Days"] = result["Inactive >14 Days"].map(
            lambda value: "Yes" if bool(value) else "No"
        )
    if "Customer Name" not in result:
        result["Customer Name"] = customer_name
    else:
        result["Customer Name"] = result["Customer Name"].replace("", pd.NA).fillna(customer_name)
    for column in HOST_EXPORT_COLUMNS:
        if column not in result:
            result[column] = ""
    return result[HOST_EXPORT_COLUMNS]


def _host_formats(workbook: xlsxwriter.Workbook) -> dict[str, Any]:
    return {
        "title": workbook.add_format(
            {
                "bold": True,
                "font_color": WHITE,
                "bg_color": DARK_BLUE,
                "font_size": 16,
                "align": "center",
                "valign": "vcenter",
                "border": 1,
            }
        ),
        "label": workbook.add_format(
            {"bold": True, "font_color": BLUE, "bg_color": PALE_BLUE, "border": 1, "valign": "vcenter"}
        ),
        "value": workbook.add_format({"border": 1, "text_wrap": True, "valign": "top"}),
        "header": workbook.add_format(
            {
                "bold": True,
                "font_color": WHITE,
                "bg_color": BLUE,
                "border": 1,
                "align": "center",
                "valign": "vcenter",
                "text_wrap": True,
            }
        ),
        "subheader": workbook.add_format(
            {"bold": True, "font_color": BLUE, "bg_color": LIGHT_BLUE, "border": 1}
        ),
        "body": workbook.add_format({"border": 1, "valign": "top"}),
        "body_wrap": workbook.add_format({"border": 1, "valign": "top", "text_wrap": True}),
        "integer": workbook.add_format({"border": 1, "num_format": "0", "valign": "top"}),
        "decimal": workbook.add_format({"border": 1, "num_format": "0.00", "valign": "top"}),
        "date": workbook.add_format({"border": 1, "num_format": "dd mmmm yyyy", "valign": "top"}),
        "datetime": workbook.add_format({"border": 1, "num_format": "dd mmm yyyy hh:mm", "valign": "top"}),
        "total": workbook.add_format(
            {"bold": True, "font_color": BLUE, "bg_color": LIGHT_BLUE, "border": 1, "num_format": "0"}
        ),
        "pass": workbook.add_format({"border": 1, "bg_color": GREEN, "font_color": "#006100"}),
        "warn": workbook.add_format({"border": 1, "bg_color": YELLOW, "font_color": "#7F6000"}),
        "bad": workbook.add_format({"border": 1, "bg_color": "#FFC7CE", "font_color": "#9C0006"}),
    }


def _write_plain_table(
    ws: Any,
    df: pd.DataFrame,
    formats: dict[str, Any],
    *,
    start_row: int = 0,
    autofilter: bool = True,
    freeze: tuple[int, int] | None = None,
    widths: dict[str, float] | None = None,
) -> None:
    data = _safe_df(df)
    for col_idx, column in enumerate(data.columns):
        ws.write(start_row, col_idx, column, formats["header"])
    for row_idx, row in enumerate(data.itertuples(index=False, name=None), start=start_row + 1):
        for col_idx, value in enumerate(row):
            column = str(data.columns[col_idx]).lower()
            fmt = formats["body_wrap"] if any(
                token in column
                for token in (
                    "recommend",
                    "policy",
                    "groups",
                    "tags",
                    "version",
                    "os ",
                    "user account",
                )
            ) else formats["body"]
            _write_scalar(ws, row_idx, col_idx, value, fmt, formats["date"], formats["datetime"])
    last_row = max(start_row + len(data), start_row + 1)
    if autofilter and len(data.columns):
        ws.autofilter(start_row, 0, last_row, len(data.columns) - 1)
    if freeze:
        ws.freeze_panes(*freeze)
    ws.set_row(start_row, 30)
    widths = widths or {}
    for col_idx, column in enumerate(data.columns):
        width = widths.get(str(column))
        if width is None:
            samples = [len(str(value)) for value in data[column].head(200) if value not in (None, "") and not pd.isna(value)]
            width = min(max([len(str(column)) + 2, *samples], default=12), 30)
            if any(token in str(column).lower() for token in ("recommend", "policy", "groups", "tags")):
                width = min(max(width, 24), 44)
        ws.set_column(col_idx, col_idx, width)


def _write_detail_sheet(
    workbook: xlsxwriter.Workbook,
    formats: dict[str, Any],
    name: str,
    title: str,
    df: pd.DataFrame,
) -> None:
    ws = workbook.add_worksheet(name[:31])
    ws.merge_range(0, 0, 0, len(DETAIL_COLUMNS) - 1, title, formats["title"])
    ws.merge_range(1, 0, 1, len(DETAIL_COLUMNS) - 1, f"Total record: {len(df):,}", formats["subheader"])
    ws.set_row(0, 30)
    data = df.copy() if not df.empty else pd.DataFrame(columns=DETAIL_COLUMNS)
    for column in DETAIL_COLUMNS:
        if column not in data:
            data[column] = ""
    data = data[DETAIL_COLUMNS]
    _write_plain_table(
        ws,
        data,
        formats,
        start_row=3,
        autofilter=True,
        freeze=(4, 0),
        widths={
            "Hostname": 24,
            "Platform": 12,
            "OS Version": 27,
            "Last Seen": 22,
            "Sensor Version": 18,
            "Support Status": 18,
            "Release Date": 17,
            "End of Support": 17,
            "Release Recency": 18,
            "RFM Status": 15,
            "Inactive Days": 15,
            "Recommendation": 60,
        },
    )
    if len(data):
        ws.conditional_format(4, 5, 3 + len(data), 5, {"type": "text", "criteria": "containing", "value": "Unsupported", "format": formats["bad"]})
        ws.conditional_format(4, 9, 3 + len(data), 9, {"type": "text", "criteria": "containing", "value": "RFM", "format": formats["bad"]})


def build_host_sensor_workbook(
    assessment: pd.DataFrame,
    matrix: pd.DataFrame,
    host_metadata: dict[str, Any],
    sensor_metadata: dict[str, Any],
    *,
    customer_name: str,
) -> bytes:
    """Generate Lampiran A exactly as one Host + Sensor Health workbook."""
    assessment = _safe_df(assessment)
    matrix = _safe_df(matrix)
    export_hosts = _host_export_frame(assessment, customer_name)
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    workbook.set_properties(
        {
            "title": f"Lampiran A - Host & Sensor Health {customer_name}",
            "author": "PT. Seraphim Digital Technology",
            "company": "PT. Seraphim Digital Technology",
        }
    )
    fmt = _host_formats(workbook)

    # Ringkasan.
    ws = workbook.add_worksheet("Ringkasan")
    ws.merge_range("A1:H1", f"Lampiran A - Host & Sensor Health {customer_name}", fmt["title"])
    ws.set_row(0, 32)
    assessment_date_text = str(sensor_metadata.get("assessment_date") or date.today().isoformat())
    extraction_utc = host_metadata.get("extraction_utc") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    info = [
        ("Sumber Data", host_metadata.get("source") or "CrowdStrike Hosts API — PostDeviceDetailsV2"),
        ("Tanggal Tarikan", extraction_utc),
        ("Assessment Date", assessment_date_text),
        ("Total Host", len(assessment)),
        ("Metode Support", "Exact match Platform + Major.Minor + Build terhadap Sensor Release Matrix"),
        (
            "Catatan Kernel",
            "Kernel Version tersedia pada API." if ("Kernel Version" in assessment and assessment["Kernel Version"].astype(str).str.strip().ne("").any()) else "Kernel Version tidak tersedia pada sebagian/seluruh record API.",
        ),
    ]
    for row, (label, value) in enumerate(info, start=2):
        ws.write(row, 0, label, fmt["label"])
        ws.write(row, 1, value, fmt["value"] if not isinstance(value, (int, float)) else fmt["integer"])
    ws.set_column("A:A", 25)
    ws.set_column("B:B", 46)

    summary = sensor_health_summary(assessment)
    summary_headers = ["Platform", "Total Host", "Supported", "Unsupported", "RFM=yes", "Inactive >14 Hari"]
    for col, value in enumerate(summary_headers):
        ws.write(9, col, value, fmt["header"])
    platform_rows: list[list[Any]] = []
    for platform in ["Windows", "Mac", "Linux"]:
        subset = assessment[assessment.get("Platform", pd.Series(dtype=str)).eq(platform)] if not assessment.empty else pd.DataFrame()
        platform_rows.append(
            [
                platform,
                len(subset),
                int(subset.get("Support Status", pd.Series(dtype=str)).eq("Supported").sum()),
                int(subset.get("Support Status", pd.Series(dtype=str)).eq("Unsupported").sum()),
                int(subset.get("RFM Status", pd.Series(dtype=str)).eq("RFM").sum()),
                int(subset.get("Inactive >14 Days", pd.Series(dtype=bool)).fillna(False).sum()),
            ]
        )
    for r, row_values in enumerate(platform_rows, start=10):
        ws.write(r, 0, row_values[0], fmt["body"])
        for c, value in enumerate(row_values[1:], start=1):
            ws.write_number(r, c, int(value), fmt["integer"])
    totals = ["TOTAL"] + [sum(row[c] for row in platform_rows) for c in range(1, 6)]
    ws.write(13, 0, totals[0], fmt["total"])
    for c, value in enumerate(totals[1:], start=1):
        ws.write_number(13, c, int(value), fmt["total"])
    ws.set_column("C:F", 18)

    ws.write(15, 0, "Metric", fmt["header"])
    ws.write(15, 1, "Value", fmt["header"])
    metrics = [
        ("RFM Unknown / blank", int(assessment.get("RFM Status", pd.Series(dtype=str)).eq("Unknown").sum()) if not assessment.empty else 0),
        ("Windows Unsupported", int(((assessment.get("Platform", pd.Series(dtype=str)) == "Windows") & (assessment.get("Support Status", pd.Series(dtype=str)) == "Unsupported")).sum()) if not assessment.empty else 0),
        ("Mac Unsupported", int(((assessment.get("Platform", pd.Series(dtype=str)) == "Mac") & (assessment.get("Support Status", pd.Series(dtype=str)) == "Unsupported")).sum()) if not assessment.empty else 0),
        ("Linux Unsupported", int(((assessment.get("Platform", pd.Series(dtype=str)) == "Linux") & (assessment.get("Support Status", pd.Series(dtype=str)) == "Unsupported")).sum()) if not assessment.empty else 0),
        ("Windows RFM", int(((assessment.get("Platform", pd.Series(dtype=str)) == "Windows") & (assessment.get("RFM Status", pd.Series(dtype=str)) == "RFM")).sum()) if not assessment.empty else 0),
        ("Linux RFM", int(((assessment.get("Platform", pd.Series(dtype=str)) == "Linux") & (assessment.get("RFM Status", pd.Series(dtype=str)) == "RFM")).sum()) if not assessment.empty else 0),
    ]
    for r, (label, value) in enumerate(metrics, start=16):
        ws.write(r, 0, label, fmt["body"])
        ws.write_number(r, 1, value, fmt["integer"])

    chart = workbook.add_chart({"type": "column"})
    colors = ["#146C94", "#ED7D31", "#548235", "#00A6D6", "#A02B93"]
    for idx, name in enumerate(summary_headers[1:], start=1):
        chart.add_series(
            {
                "name": name,
                "categories": "=Ringkasan!$A$11:$A$13",
                "values": f"=Ringkasan!${chr(65 + idx)}$11:${chr(65 + idx)}$13",
                "fill": {"color": colors[idx - 1]},
                "border": {"none": True},
            }
        )
    chart.set_title({"name": "Sensor Health per Platform"})
    chart.set_legend({"position": "bottom"})
    chart.set_y_axis({"major_gridlines": {"visible": True}})
    chart.set_style(10)
    chart.set_size({"width": 760, "height": 390})
    ws.insert_chart("H3", chart)
    ws.freeze_panes(2, 0)

    # All Hosts.
    all_ws = workbook.add_worksheet("All Hosts")
    _write_plain_table(
        all_ws,
        export_hosts,
        fmt,
        start_row=0,
        autofilter=True,
        freeze=(1, 0),
        widths={
            "Hostname": 22,
            "Host ID": 34,
            "CID": 34,
            "Customer Name": 22,
            "Last Seen": 21,
            "First Seen": 21,
            "Platform": 14,
            "OS Version": 25,
            "Type": 14,
            "Local IP": 18,
            "External IP": 20,
            "MAC Address": 18,
            "Sensor Version": 18,
            "Host Groups": 24,
            "Sensor Tags": 28,
            "Last Logged In User Account": 28,
            "Criticality": 15,
            "Prevention Policy": 28,
            "Sensor Update Policy": 28,
            "Content Update Policy": 28,
            "USB Device Policy": 28,
            "Host Retention Policy": 32,
            "RFM": 10,
            "Normalized Version": 19,
            "Release Channel": 18,
            "Release Date": 17,
            "End of Support": 17,
            "Support Status": 18,
            "Release Age Days": 18,
            "Release Recency": 18,
            "RFM Status": 15,
            "Inactive Days": 15,
            "Inactive >14 Days": 20,
            "Recommendation": 62,
        },
    )
    if len(export_hosts):
        support_col = HOST_EXPORT_COLUMNS.index("Support Status")
        rfm_col = HOST_EXPORT_COLUMNS.index("RFM Status")
        inactive_col = HOST_EXPORT_COLUMNS.index("Inactive >14 Days")
        all_ws.conditional_format(1, support_col, len(export_hosts), support_col, {"type": "text", "criteria": "containing", "value": "Unsupported", "format": fmt["bad"]})
        all_ws.conditional_format(1, rfm_col, len(export_hosts), rfm_col, {"type": "text", "criteria": "containing", "value": "RFM", "format": fmt["bad"]})
        all_ws.conditional_format(1, inactive_col, len(export_hosts), inactive_col, {"type": "text", "criteria": "containing", "value": "Yes", "format": fmt["warn"]})

    unsupported = assessment[assessment.get("Support Status", pd.Series(dtype=str)).eq("Unsupported")] if not assessment.empty else pd.DataFrame()
    rfm = assessment[assessment.get("RFM Status", pd.Series(dtype=str)).eq("RFM")] if not assessment.empty else pd.DataFrame()
    rfm_unknown = assessment[assessment.get("RFM Status", pd.Series(dtype=str)).eq("Unknown")] if not assessment.empty else pd.DataFrame()
    inactive = assessment[assessment.get("Inactive >14 Days", pd.Series(dtype=bool)).fillna(False)] if not assessment.empty else pd.DataFrame()
    _write_detail_sheet(workbook, fmt, "Unsupported", "Unsupported Sensor Detail", unsupported)
    _write_detail_sheet(workbook, fmt, "RFM", "Reduced Functionality Mode (RFM=yes)", rfm)
    _write_detail_sheet(workbook, fmt, "RFM Unknown", "RFM Blank / Unknown - Perlu Validasi", rfm_unknown)
    _write_detail_sheet(workbook, fmt, "Inactive >14 Hari", "Inactive Sensor >14 Hari", inactive)

    # Version distribution.
    if not assessment.empty:
        version_distribution = (
            assessment.groupby(["Platform", "Sensor Version", "Support Status", "Release Recency"], dropna=False)
            .size()
            .reset_index(name="Jumlah Host")
            .sort_values(["Platform", "Sensor Version"])
        )
    else:
        version_distribution = pd.DataFrame(columns=["Platform", "Sensor Version", "Support Status", "Release Recency", "Jumlah Host"])
    vd_ws = workbook.add_worksheet("Version Distribution")
    _write_plain_table(vd_ws, version_distribution, fmt, start_row=0, freeze=(1, 0), widths={"Platform": 15, "Sensor Version": 20, "Support Status": 18, "Release Recency": 18, "Jumlah Host": 14})

    # Sensor matrix as used by the assessment.
    matrix_export = matrix.copy()
    if matrix_export.empty:
        matrix_export = pd.DataFrame(columns=["Platform", "Version", "Release Channel", "Release Date", "End of Support"])
    assessment_date = pd.to_datetime(sensor_metadata.get("assessment_date"), errors="coerce").date() if sensor_metadata.get("assessment_date") else date.today()
    matrix_export[f"Status pada {assessment_date.strftime('%d %b %Y')}"] = matrix_export.get("End of Support", pd.Series(dtype=object)).map(
        lambda eos: "Unsupported" if isinstance(eos, date) and eos < assessment_date else "Supported"
    )
    matrix_ws = workbook.add_worksheet("Sensor Matrix")
    _write_plain_table(matrix_ws, matrix_export, fmt, start_row=0, freeze=(1, 0), widths={"Platform": 15, "Version": 20, "Release Channel": 20, "Release Date": 18, "End of Support": 18})

    # Data quality.
    kernel_available = int(assessment.get("Kernel Version", pd.Series(dtype=str)).astype(str).str.strip().ne("").sum()) if not assessment.empty and "Kernel Version" in assessment else 0
    missing_sensor = int(assessment.get("Sensor Version", pd.Series(dtype=str)).astype(str).str.strip().eq("").sum()) if not assessment.empty else 0
    rfm_unknown_count = int(assessment.get("RFM Status", pd.Series(dtype=str)).eq("Unknown").sum()) if not assessment.empty else 0
    platform_counts = assessment.get("Platform", pd.Series(dtype=str)).value_counts().to_dict() if not assessment.empty else {}
    dq = pd.DataFrame(
        [
            ["Total row", "Pass" if len(assessment) else "Missing", "Semua host dapat diproses", f"{len(assessment)} row"],
            ["Platform", "Pass" if len(platform_counts) else "Missing", "Pemisahan Windows/Mac/Linux tersedia", str(platform_counts)],
            ["Sensor Version", "Pass" if missing_sensor == 0 else "Partial", "Support classification tersedia", f"{missing_sensor} host tanpa sensor version; {len(unsupported)} unsupported"],
            ["RFM", "Pass" if rfm_unknown_count == 0 else "Partial", "Nilai blank tidak dianggap no", f"{rfm_unknown_count} host RFM blank/unknown"],
            ["Kernel Version", "Pass" if kernel_available == len(assessment) and len(assessment) else ("Partial" if kernel_available else "Missing"), "Informasi kernel untuk validasi Linux", f"{kernel_available}/{len(assessment)} host tersedia"],
            ["Last Seen", "Pass" if not assessment.empty and assessment.get("Last Seen", pd.Series(dtype=object)).notna().any() else "Missing", "Inactive >14 hari dapat dihitung", f"{len(inactive)} host inactive"],
        ],
        columns=["Check", "Status", "Dampak", "Catatan"],
    )
    dq_ws = workbook.add_worksheet("Data Quality")
    _write_plain_table(dq_ws, dq, fmt, start_row=0, freeze=(1, 0), widths={"Check": 22, "Status": 14, "Dampak": 45, "Catatan": 50})
    if len(dq):
        dq_ws.conditional_format(1, 1, len(dq), 1, {"type": "text", "criteria": "containing", "value": "Pass", "format": fmt["pass"]})
        dq_ws.conditional_format(1, 1, len(dq), 1, {"type": "text", "criteria": "containing", "value": "Partial", "format": fmt["warn"]})
        dq_ws.conditional_format(1, 1, len(dq), 1, {"type": "text", "criteria": "containing", "value": "Missing", "format": fmt["bad"]})

    workbook.close()
    output.seek(0)
    return output.getvalue()


def _policy_item_key(row: pd.Series | dict[str, Any]) -> str:
    value = row.get("Item Name") or row.get("Display Name") or row.get("Item Path") or ""
    return re.sub(r"\s+", " ", str(value).strip().lower())


def _policy_display_value(value: Any, status: str | None = None) -> str:
    text = str(value or "").strip()
    lowered = text.lower()
    if isinstance(value, bool):
        return "ON" if value else "OFF"
    if status == "Enabled" or lowered in {"true", "enabled", "enable", "on", "yes", "1"}:
        return "ON"
    if status == "Disabled" or lowered in {"false", "disabled", "disable", "off", "no", "0", "none"}:
        return "OFF"
    if not text:
        return ""
    return text.upper() if len(text) <= 24 else text


def _policy_sheet_name(platform: str, index: int, total: int) -> str:
    if total == 1:
        return f"{platform} Prevention Policy"[:31]
    return f"{platform} Prevention Policy {index}"[:31]


def build_policy_workbook(
    policies: pd.DataFrame,
    members: pd.DataFrame,
    assessed_settings: pd.DataFrame,
    raw_policies: pd.DataFrame,
    metadata: dict[str, Any],
) -> bytes:
    """Generate a clean prevention-policy workbook.

    One row represents one real configuration item. Structural fields from the
    API value object (type/value/detection/prevention) are deliberately kept in
    the detail sheet and never rendered as separate matrix rows.
    """
    policies = _safe_df(policies)
    members = _safe_df(members)
    settings = _safe_df(assessed_settings)
    raw_policies = _safe_df(raw_policies)
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    workbook.set_properties(
        {
            "title": "Lampiran B - Prevention Policy",
            "author": "PT. Seraphim Digital Technology",
            "company": "PT. Seraphim Digital Technology",
        }
    )
    table_fmt = _host_formats(workbook)

    fmt_title = workbook.add_format({
        "bold": True, "font_color": WHITE, "bg_color": DARK_BLUE, "font_size": 15,
        "align": "center", "valign": "vcenter", "border": 1, "text_wrap": True,
    })
    fmt_policy = workbook.add_format({
        "bold": True, "align": "center", "valign": "vcenter", "border": 1,
        "text_wrap": True, "bg_color": "#F2F2F2",
    })
    fmt_enabled = workbook.add_format({
        "bold": True, "align": "center", "valign": "vcenter", "border": 1,
        "bg_color": "#92D050",
    })
    fmt_disabled = workbook.add_format({
        "bold": True, "font_color": WHITE, "align": "center", "valign": "vcenter",
        "border": 1, "bg_color": RED,
    })
    fmt_unknown = workbook.add_format({
        "bold": True, "align": "center", "valign": "vcenter", "border": 1,
        "bg_color": YELLOW,
    })
    fmt_count = workbook.add_format({"bold": True, "align": "center", "border": 1, "num_format": "0"})
    fmt_black = workbook.add_format({"bg_color": BLACK, "border": 1})
    fmt_item = workbook.add_format({"border": 1, "align": "left", "valign": "vcenter", "text_wrap": True})
    fmt_on = workbook.add_format({"border": 1, "align": "center", "valign": "vcenter", "bg_color": GREEN, "bold": True})
    fmt_off = workbook.add_format({"border": 1, "align": "center", "valign": "vcenter", "bg_color": RED, "font_color": WHITE, "bold": True})
    fmt_config = workbook.add_format({"border": 1, "align": "center", "valign": "vcenter", "bg_color": YELLOW, "text_wrap": True})
    fmt_blank = workbook.add_format({"border": 1, "align": "center"})
    fmt_best_header = workbook.add_format({
        "bold": True, "align": "center", "valign": "vcenter", "border": 1,
        "text_wrap": True, "bg_color": "#F2F2F2",
    })
    fmt_section = workbook.add_format({
        "bold": True, "font_color": WHITE, "bg_color": BLUE, "border": 1,
        "align": "left", "valign": "vcenter",
    })

    if policies.empty:
        ws = workbook.add_worksheet("No Data")
        ws.write("A1", "Prevention Policy belum ditarik dari API.", fmt_title)
        workbook.close()
        output.seek(0)
        return output.getvalue()

    # Summary sheet.
    ws = workbook.add_worksheet("Summary")
    ws.merge_range("A1:J1", "Lampiran B - Prevention Policy Assessment", fmt_title)
    ws.set_row(0, 32)
    summary = policy_summary(policies, settings)
    info = [
        ("Collector", metadata.get("collector") or "CrowdStrike Prevention Policy API"),
        ("Policy Groups", len(policies)),
        ("Policy Members", len(members)),
        ("Configuration Records", len(settings)),
        ("Disabled Configuration Records", int(settings["Configuration Status"].eq("Disabled").sum()) if not settings.empty else 0),
        ("Mapped Labels", int(settings["Mapping Status"].eq("Mapped").sum()) if not settings.empty and "Mapping Status" in settings else 0),
        ("Humanized Fallback Labels", int(settings["Mapping Status"].ne("Mapped").sum()) if not settings.empty and "Mapping Status" in settings else 0),
    ]
    for row_idx, (label, value) in enumerate(info, start=2):
        ws.write(row_idx, 0, label, table_fmt["label"])
        if isinstance(value, (int, float)):
            ws.write_number(row_idx, 1, value, table_fmt["integer"])
        else:
            ws.write(row_idx, 1, value, table_fmt["value"])
    ws.set_column("A:A", 32)
    ws.set_column("B:B", 48)
    if not summary.empty:
        _write_plain_table(ws, summary, table_fmt, start_row=11, autofilter=False, freeze=(12, 0))
        ws.set_column(2, 9, 22)
    ws.write(20, 0, "Interpretation", table_fmt["subheader"])
    ws.write(21, 0, "ON", fmt_on)
    ws.write(21, 1, "Configuration item enabled.", table_fmt["value"])
    ws.write(22, 0, "OFF", fmt_off)
    ws.write(22, 1, "Configuration item disabled. Review against Best Practice and customer requirements.", table_fmt["value"])
    ws.write(23, 0, "Configured Value", fmt_config)
    ws.write(23, 1, "Level or compound setting such as Aggressive, Moderate, or Detection/Prevention level.", table_fmt["value"])

    # Policy group inventory.
    group_ws = workbook.add_worksheet("Policy Groups")
    group_columns = [
        "Platform", "Policy Name", "Enabled", "Member Count", "Has Hosts", "Precedence",
        "Policy ID", "Description", "Created Timestamp", "Modified Timestamp",
    ]
    group_data = policies.copy()
    for column in group_columns:
        if column not in group_data:
            group_data[column] = ""
    _write_plain_table(
        group_ws,
        group_data[group_columns],
        table_fmt,
        freeze=(1, 0),
        widths={"Policy Name": 32, "Policy ID": 38, "Description": 45, "Platform": 12},
    )

    # Matrix sheets. Up to 14 policy columns per sheet, similar to the reference.
    max_policy_columns = 14
    created_matrix_sheets = 0
    for platform in ["Windows", "Linux", "Mac"]:
        platform_policies = policies[policies["Platform"].eq(platform)].copy()
        if platform_policies.empty:
            continue
        platform_policies = platform_policies.sort_values(["Precedence", "Policy Name"], na_position="last")
        platform_settings = settings[settings["Platform"].eq(platform)].copy() if not settings.empty else pd.DataFrame()

        item_order: list[str] = []
        item_labels: dict[str, str] = {}
        item_sections: dict[str, str] = {}
        item_sort: dict[str, int] = {}
        best_practice: dict[str, str] = {}
        if not platform_settings.empty:
            ordered = platform_settings.sort_values(["Sort Order", "Section", "Display Name", "Item Key"], na_position="last")
            for _, setting in ordered.iterrows():
                key = str(setting.get("Item Key") or _policy_item_key(setting))
                if not key:
                    continue
                if key not in item_labels:
                    item_order.append(key)
                    item_labels[key] = str(setting.get("Display Name") or setting.get("Setting ID") or setting.get("Item Path") or key)
                    item_sections[key] = str(setting.get("Section") or "Other")
                    item_sort[key] = int(setting.get("Sort Order") or 9999)
                best = setting.get("Best Practice")
                if best not in (None, "") and not pd.isna(best):
                    best_practice.setdefault(key, str(best))
        item_order.sort(key=lambda key: (item_sort.get(key, 9999), item_sections.get(key, "Other"), item_labels.get(key, key)))

        chunks = [platform_policies.iloc[i:i + max_policy_columns] for i in range(0, len(platform_policies), max_policy_columns)]
        for chunk_index, chunk in enumerate(chunks, start=1):
            sheet_name = _policy_sheet_name(platform, chunk_index, len(chunks))
            matrix_ws = workbook.add_worksheet(sheet_name)
            created_matrix_sheets += 1
            policy_count = len(chunk)
            best_col = policy_count + 1
            platform_label = "WIN" if platform == "Windows" else platform.upper()
            matrix_ws.merge_range(0, 0, 2, 0, f"{platform_label} Prevention Policy\nConfiguration Item", fmt_title)
            matrix_ws.merge_range(0, best_col, 2, best_col, "Best Practice", fmt_best_header)

            for offset, (_, policy) in enumerate(chunk.iterrows(), start=1):
                matrix_ws.write(0, offset, str(policy.get("Policy Name") or "Unnamed Policy"), fmt_policy)
                enabled = policy.get("Enabled")
                enabled_bool = None if enabled is None or pd.isna(enabled) else bool(enabled)
                status_text = "Enabled" if enabled_bool is True else "Disabled" if enabled_bool is False else "Unknown"
                status_fmt = fmt_enabled if enabled_bool is True else fmt_disabled if enabled_bool is False else fmt_unknown
                matrix_ws.write(1, offset, status_text, status_fmt)
                matrix_ws.write_number(2, offset, int(policy.get("Member Count") or 0), fmt_count)
            for col in range(best_col + 1):
                matrix_ws.write_blank(3, col, None, fmt_black)

            lookup: dict[tuple[str, str], pd.Series] = {}
            if not platform_settings.empty:
                for _, setting in platform_settings.iterrows():
                    lookup[(str(setting.get("Policy ID") or ""), str(setting.get("Item Key") or _policy_item_key(setting)))] = setting

            current_section = None
            excel_row = 4
            for item_key in item_order:
                section = item_sections.get(item_key, "Other")
                if section != current_section:
                    matrix_ws.write(excel_row, 0, section, fmt_section)
                    for col in range(1, best_col + 1):
                        matrix_ws.write_blank(excel_row, col, None, fmt_section)
                    matrix_ws.set_row(excel_row, 22)
                    excel_row += 1
                    current_section = section

                matrix_ws.write(excel_row, 0, item_labels.get(item_key, item_key), fmt_item)
                for col_offset, (_, policy) in enumerate(chunk.iterrows(), start=1):
                    setting = lookup.get((str(policy.get("Policy ID") or ""), item_key))
                    if setting is None:
                        matrix_ws.write(excel_row, col_offset, "N/A", fmt_blank)
                        continue
                    value = str(setting.get("Display Value") or setting.get("Current Value") or "")
                    status = str(setting.get("Configuration Status") or "")
                    value_upper = value.upper()
                    cell_fmt = fmt_on if value_upper == "ON" else fmt_off if value_upper == "OFF" or status == "Disabled" else fmt_config
                    matrix_ws.write(excel_row, col_offset, value, cell_fmt)

                best = best_practice.get(item_key, "")
                best_display = _policy_display_value(best)
                best_lower = str(best).strip().lower()
                if best_lower in {"customer preference", "not applicable", "n/a"}:
                    best_fmt = fmt_off
                elif best_display == "ON":
                    best_fmt = fmt_on
                elif best_display == "OFF":
                    best_fmt = fmt_off
                elif best_display:
                    best_fmt = fmt_config
                else:
                    best_fmt = fmt_blank
                matrix_ws.write(excel_row, best_col, best_display or best, best_fmt)
                matrix_ws.set_row(excel_row, 24)
                excel_row += 1

            matrix_ws.freeze_panes(4, 1)
            matrix_ws.set_column(0, 0, 43)
            for col in range(1, best_col):
                matrix_ws.set_column(col, col, 18)
            matrix_ws.set_column(best_col, best_col, 21)
            matrix_ws.set_row(0, 42)
            matrix_ws.set_row(1, 22)
            matrix_ws.set_row(2, 22)
            matrix_ws.set_row(3, 8)
            matrix_ws.autofilter(3, 0, max(excel_row - 1, 4), best_col)

    if created_matrix_sheets == 0:
        ws_no = workbook.add_worksheet("No Matrix")
        ws_no.write("A1", "Tidak ada Prevention Policy Windows, Linux, atau Mac.", fmt_title)

    # Action-oriented list: which items are disabled in each policy.
    disabled = disabled_items_summary(settings)
    disabled_ws = workbook.add_worksheet("Disabled Items")
    _write_plain_table(
        disabled_ws,
        disabled,
        table_fmt,
        freeze=(1, 0),
        widths={
            "Platform": 12, "Policy Name": 30, "Configuration Item": 44,
            "Current Value": 20, "Best Practice": 20, "Assessment": 18,
            "Section": 24, "Setting ID": 34, "Item Path": 50,
        },
    )
    if not disabled.empty:
        current_col = list(disabled.columns).index("Current Value")
        assessment_col = list(disabled.columns).index("Assessment")
        disabled_ws.conditional_format(1, current_col, len(disabled), current_col, {
            "type": "text", "criteria": "containing", "value": "OFF", "format": fmt_off,
        })
        disabled_ws.conditional_format(1, assessment_col, len(disabled), assessment_col, {
            "type": "text", "criteria": "containing", "value": "Not Compliant", "format": table_fmt["bad"],
        })

    non_compliant = settings[settings.get("Baseline Status", pd.Series(index=settings.index, dtype=str)).eq("Not Compliant")].copy() if not settings.empty else pd.DataFrame()
    non_ws = workbook.add_worksheet("Non-Compliant Items")
    non_columns = [
        "Platform", "Policy Name", "Member Count", "Display Name", "Display Value",
        "Best Practice", "Assessment Reason", "Section", "Setting ID", "Item Path",
    ]
    for column in non_columns:
        if column not in non_compliant:
            non_compliant[column] = ""
    _write_plain_table(
        non_ws,
        non_compliant[non_columns].rename(columns={"Display Name": "Configuration Item", "Display Value": "Current Value"}),
        table_fmt,
        freeze=(1, 0),
        widths={"Policy Name": 30, "Configuration Item": 44, "Assessment Reason": 46, "Item Path": 50},
    )

    member_ws = workbook.add_worksheet("Policy Members")
    _write_plain_table(
        member_ws,
        members,
        table_fmt,
        freeze=(1, 0),
        widths={"Policy Name": 30, "Device ID": 38, "Hostname": 26, "OS Version": 28, "Sensor Version": 18},
    )

    detail_ws = workbook.add_worksheet("All Settings")
    detail_columns = [
        "Platform", "Policy Name", "Policy Enabled", "Member Count", "Has Hosts", "Section",
        "Display Name", "Display Value", "Configuration Status", "Best Practice", "Baseline Status",
        "Assessment Reason", "Setting ID", "Item Path", "Value Type", "Detection Value",
        "Prevention Value", "Mapping Status", "Raw Value JSON",
    ]
    detail = settings.copy()
    for column in detail_columns:
        if column not in detail:
            detail[column] = ""
    _write_plain_table(
        detail_ws,
        detail[detail_columns].rename(columns={"Display Name": "Configuration Item", "Display Value": "Current Value"}),
        table_fmt,
        freeze=(1, 0),
        widths={
            "Policy Name": 30, "Configuration Item": 44, "Current Value": 24,
            "Assessment Reason": 44, "Setting ID": 36, "Item Path": 52,
            "Raw Value JSON": 60,
        },
    )

    unmapped_ws = workbook.add_worksheet("Unmapped Items")
    _write_plain_table(
        unmapped_ws,
        unmapped_items(settings),
        table_fmt,
        freeze=(1, 0),
        widths={"Display Name": 42, "Setting ID": 36, "Item Path": 52, "Raw Value JSON": 60},
    )

    raw_ws = workbook.add_worksheet("Raw Policy API")
    _write_plain_table(raw_ws, raw_policies, table_fmt, freeze=(1, 0))

    query_ws = workbook.add_worksheet("Query Information")
    query_rows = pd.DataFrame(
        [{"Key": str(key), "Value": value} for key, value in sorted((metadata or {}).items(), key=lambda item: str(item[0]))]
    )
    _write_plain_table(query_ws, query_rows, table_fmt, freeze=(1, 0), widths={"Key": 30, "Value": 70})

    workbook.close()
    output.seek(0)
    return output.getvalue()


# Backward-compatible wrappers retained for imports from early v15 revisions.
def build_host_workbook(hosts: pd.DataFrame, raw_hosts: pd.DataFrame, metadata: dict[str, Any]) -> bytes:
    return build_host_sensor_workbook(hosts, pd.DataFrame(), metadata, {}, customer_name="Customer")


def build_sensor_health_workbook(assessment: pd.DataFrame, matrix: pd.DataFrame, metadata: dict[str, Any]) -> bytes:
    return build_host_sensor_workbook(assessment, matrix, {}, metadata, customer_name="Customer")


def build_alert_workbook(alerts: pd.DataFrame, raw_alerts: pd.DataFrame, metadata: dict[str, Any], top_n: int = 10) -> bytes:
    """Use the proven standalone detection exporter unchanged."""
    from detector.excel_exporter import build_detection_workbook

    alerts = _safe_df(alerts)
    records = alerts.where(pd.notna(alerts), None).to_dict(orient="records")
    return build_detection_workbook(
        records,
        metadata=metadata,
        top_n=top_n,
        collection_pages=int(metadata.get("collection_pages") or 0),
        truncated=bool(metadata.get("truncated")),
        fql_filter=str(metadata.get("fql_filter") or metadata.get("filter") or ""),
    )


def manifest_json(
    *,
    customer_name: str,
    connection_safe: dict[str, Any],
    host_metadata: dict[str, Any],
    policy_metadata: dict[str, Any],
    alert_metadata: dict[str, Any],
    counts: dict[str, Any],
) -> bytes:
    payload = {
        "application": "Seraphim Falcon Data Collector",
        "version": "15.0.6.2-data-collector",
        "customer_name": customer_name,
        "connection": connection_safe,
        "host_collection": host_metadata,
        "policy_collection": policy_metadata,
        "alert_collection": alert_metadata,
        "counts": counts,
        "credentials_included": False,
        "outputs": [
            f"Lampiran_A_Host_Sensor_Health_{_clean_customer_filename(customer_name)}.xlsx",
            f"Lampiran_B_Prevention_Policy_{_clean_customer_filename(customer_name)}.xlsx",
            f"Lampiran_C_Detection_Alerts_{_clean_customer_filename(customer_name)}.xlsx",
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str).encode("utf-8")


def customer_filename(value: str) -> str:
    return _clean_customer_filename(value)
