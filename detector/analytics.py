from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any


EMPTY_MARKERS = {"", "-", "N/A", "Unknown", "None"}


def _valid(value: Any) -> bool:
    return str(value or "").strip() not in EMPTY_MARKERS


def count_by(records: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    counter = Counter(str(row.get(field) or "").strip() for row in records)
    counter.pop("", None)
    return [{field: key, "Count": value} for key, value in counter.most_common()]


def top_by(records: list[dict[str, Any]], field: str, top_n: int) -> list[dict[str, Any]]:
    return count_by(records, field)[:top_n]


def daily_trend(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counter: Counter[str] = Counter()
    for row in records:
        value = str(row.get("Created Timestamp") or "").strip()
        if not value:
            continue
        try:
            day = datetime.fromisoformat(value.replace("Z", "+00:00")).date().isoformat()
        except ValueError:
            day = value[:10]
        counter[day] += 1
    return [{"Date": key, "Count": counter[key]} for key in sorted(counter)]


def field_coverage(records: list[dict[str, Any]], fields: list[str]) -> list[dict[str, Any]]:
    total = len(records)
    output = []
    for field in fields:
        available = sum(1 for row in records if _valid(row.get(field)))
        output.append(
            {
                "Field": field,
                "Available": available,
                "Missing": total - available,
                "Coverage %": round((available / total * 100), 2) if total else 0.0,
            }
        )
    return output


def build_analytics(records: list[dict[str, Any]], top_n: int = 10) -> dict[str, Any]:
    status = count_by(records, "Status")
    severity = count_by(records, "Severity Name")
    closed = sum(item["Count"] for item in status if item["Status"].lower() in {"closed", "resolved"})
    new = sum(item["Count"] for item in status if item["Status"].lower() in {"new", "open", "unreviewed"})
    total = len(records)
    return {
        "total": total,
        "closed": closed,
        "new": new,
        "closure_rate_pct": round(closed / total * 100, 2) if total else None,
        "backlog_pct": round(new / total * 100, 2) if total else None,
        "status": status,
        "severity": severity,
        "top_hosts": top_by(records, "Hostname", top_n),
        "top_tactics": top_by(records, "Tactic", top_n),
        "top_techniques": top_by(records, "Technique", top_n),
        "top_files": top_by(records, "File Name", top_n),
        "top_hashes": top_by(records, "SHA256", top_n),
        "top_command_lines": top_by(records, "Command Line", top_n),
        "top_users": top_by(records, "Username", top_n),
        "daily_trend": daily_trend(records),
        "field_coverage": field_coverage(
            records,
            [
                "Status",
                "Severity Name",
                "Hostname",
                "Tactic",
                "Technique",
                "File Name",
                "SHA256",
                "Command Line",
                "Username",
            ],
        ),
    }
