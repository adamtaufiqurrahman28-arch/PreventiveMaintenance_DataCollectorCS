from __future__ import annotations

from typing import Any

import pandas as pd


def count_table(df: pd.DataFrame, column: str, top_n: int | None = None) -> pd.DataFrame:
    if df is None or df.empty or column not in df.columns:
        return pd.DataFrame(columns=[column, "Count", "Percentage"])
    values = df[column].fillna("Unknown").replace("", "Unknown").astype(str)
    counts = values.value_counts(dropna=False)
    if top_n:
        counts = counts.head(top_n)
    result = counts.rename_axis(column).reset_index(name="Count")
    total = len(df)
    result["Percentage"] = (result["Count"] / total * 100).round(2) if total else 0
    return result


def alert_tables(alerts: pd.DataFrame, top_n: int = 10) -> dict[str, pd.DataFrame]:
    if alerts is None:
        alerts = pd.DataFrame()
    severity_column = "Severity Name" if "Severity Name" in alerts.columns else "Severity"
    tables = {
        "By Status": count_table(alerts, "Status"),
        "By Severity": count_table(alerts, severity_column),
        "Top Tactic": count_table(alerts, "Tactic", top_n),
        "Top Technique": count_table(alerts, "Technique", top_n),
        "Top Host": count_table(alerts, "Hostname", top_n),
        "Top User": count_table(alerts, "Username", top_n),
        "Top File": count_table(alerts, "File Name", top_n),
        "Top Hash": count_table(alerts, "SHA256", top_n),
        "Top Command Line": count_table(alerts, "Command Line", top_n),
        "By Platform": count_table(alerts, "Platform"),
        "By Product": count_table(alerts, "Product"),
        "By Detection Type": count_table(alerts, "Detection Type"),
    }
    if not alerts.empty and "Created Timestamp" in alerts.columns:
        created = pd.to_datetime(alerts["Created Timestamp"], utc=True, errors="coerce")
        daily = created.dt.date.value_counts().sort_index().rename_axis("Date").reset_index(name="Count")
    else:
        daily = pd.DataFrame(columns=["Date", "Count"])
    tables["Daily Trend"] = daily

    coverage_rows: list[dict[str, Any]] = []
    for column in alerts.columns:
        populated = alerts[column].notna() & alerts[column].astype(str).ne("")
        coverage_rows.append(
            {
                "Field": column,
                "Populated": int(populated.sum()),
                "Missing": int((~populated).sum()),
                "Coverage %": round(float(populated.mean() * 100), 2) if len(alerts) else 0,
            }
        )
    tables["Field Coverage"] = pd.DataFrame(coverage_rows)
    return tables


def alert_summary(alerts: pd.DataFrame, metadata: dict[str, Any]) -> pd.DataFrame:
    total = len(alerts) if alerts is not None else 0
    status = alerts["Status"].fillna("Unknown").astype(str).str.lower() if total and "Status" in alerts.columns else pd.Series(dtype=str)
    closed = int(status.isin(["closed", "resolved"]).sum())
    new = int(status.isin(["new", "open", "unreviewed"]).sum())
    in_progress = int(status.isin(["in progress", "in_progress", "investigating"]).sum())
    reopened = int(status.eq("reopened").sum())
    backlog = new + in_progress + reopened
    rows = [
        ["Total Alert", total],
        ["New / Open", new],
        ["In Progress", in_progress],
        ["Reopened", reopened],
        ["Closed / Resolved", closed],
        ["Closure Rate %", round(closed / total * 100, 4) if total else None],
        ["Backlog Rate %", round(backlog / total * 100, 4) if total else None],
        ["Collection Pages", metadata.get("collection_pages")],
        ["Truncated", metadata.get("truncated")],
        ["Collection Mode", metadata.get("mode")],
        ["UTC Start", metadata.get("start_utc")],
        ["UTC End Exclusive", metadata.get("end_exclusive_utc")],
        ["Page Size", metadata.get("page_size")],
        ["Max Records", metadata.get("max_records")],
    ]
    return pd.DataFrame(rows, columns=["Metric", "Value"])
