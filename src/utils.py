from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable, Iterator
from datetime import date, datetime
from typing import Any

import pandas as pd


FALSE_VALUES = {"false", "disabled", "disable", "off", "no", "0", "none"}
TRUE_VALUES = {"true", "enabled", "enable", "on", "yes", "1"}


def chunks(items: list[Any], size: int) -> Iterator[list[Any]]:
    if size <= 0:
        raise ValueError("size harus lebih dari 0")
    for index in range(0, len(items), size):
        yield items[index : index + size]


def body(response: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(response, dict):
        return {}
    value = response.get("body")
    return value if isinstance(value, dict) else {}


def resources(response: dict[str, Any] | None) -> list[Any]:
    value = body(response).get("resources") or []
    return value if isinstance(value, list) else []


def errors(response: dict[str, Any] | None) -> list[Any]:
    value = body(response).get("errors") or []
    return value if isinstance(value, list) else []


def status_code(response: dict[str, Any] | None) -> int:
    if not isinstance(response, dict):
        return 0
    for key in ("status_code", "statusCode", "status"):
        value = response.get(key)
        if isinstance(value, int):
            return value
    return 0


def ensure_success(response: dict[str, Any], action: str) -> None:
    code = status_code(response)
    if code and not 200 <= code < 300:
        raise RuntimeError(f"{action} gagal (HTTP {code}): {errors(response) or body(response)}")
    if errors(response):
        raise RuntimeError(f"{action} gagal: {errors(response)}")


def pagination(response: dict[str, Any] | None) -> dict[str, Any]:
    meta = body(response).get("meta") or {}
    if not isinstance(meta, dict):
        return {}
    value = meta.get("pagination") or {}
    return value if isinstance(value, dict) else {}


def pagination_after(response: dict[str, Any] | None) -> str | None:
    value = pagination(response).get("after")
    return str(value) if value not in (None, "") else None


def pagination_offset(response: dict[str, Any] | None) -> str | int | None:
    value = pagination(response).get("offset")
    return value if value not in (None, "") else None


def pagination_total(response: dict[str, Any] | None) -> int | None:
    value = pagination(response).get("total")
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def get_path(value: Any, path: str, default: Any = None) -> Any:
    current = value
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part, default)
        elif isinstance(current, list) and part.isdigit():
            index = int(part)
            current = current[index] if 0 <= index < len(current) else default
        else:
            return default
    return current


def pick(value: dict[str, Any], paths: Iterable[str], default: Any = None) -> Any:
    for path in paths:
        result = get_path(value, path, None)
        if result not in (None, "", [], {}):
            return result
    return default


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str, sort_keys=True)


def flatten_json(value: Any, prefix: str = "", separator: str = ".") -> dict[str, Any]:
    """Flatten dictionaries and small lists into report-safe scalar columns."""
    flattened: dict[str, Any] = {}

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            if not node and path:
                flattened[path] = None
            for key, child in node.items():
                child_path = f"{path}{separator}{key}" if path else str(key)
                walk(child, child_path)
        elif isinstance(node, list):
            if not node:
                flattened[path] = None
            elif all(not isinstance(item, (dict, list)) for item in node):
                flattened[path] = ", ".join(str(item) for item in node)
            else:
                flattened[path] = json_text(node)
        else:
            flattened[path] = node

    walk(value, prefix)
    return flattened


def normalize_platform(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if raw.startswith("win"):
        return "Windows"
    if raw in {"mac", "macos", "darwin"} or raw.startswith("mac"):
        return "Mac"
    if raw.startswith("lin"):
        return "Linux"
    return str(value or "Unknown").strip() or "Unknown"


def normalize_version(value: Any) -> str:
    text = str(value or "").strip()
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", text)
    if not match:
        return ""
    return ".".join(str(int(part)) for part in match.groups())


def as_datetime(value: Any, utc: bool = True) -> pd.Timestamp | pd.NaT:
    if value in (None, ""):
        return pd.NaT
    try:
        return pd.to_datetime(value, utc=utc, errors="coerce")
    except Exception:
        return pd.NaT


def scalar_status(value: Any) -> str:
    if isinstance(value, bool):
        return "Enabled" if value else "Disabled"
    text = str(value or "").strip().lower()
    if text in TRUE_VALUES:
        return "Enabled"
    if text in FALSE_VALUES:
        return "Disabled"
    if value in (None, ""):
        return "Unknown"
    return "Configured"


def safe_sheet_name(name: str, existing: set[str] | None = None) -> str:
    cleaned = re.sub(r"[\\/*?:\[\]]", "-", str(name)).strip() or "Sheet"
    cleaned = cleaned[:31]
    existing = existing or set()
    if cleaned not in existing:
        return cleaned
    base = cleaned[:27]
    counter = 2
    while f"{base}-{counter}" in existing:
        counter += 1
    return f"{base}-{counter}"[:31]


def dataframe_records(df: pd.DataFrame) -> list[dict[str, Any]]:
    if df is None or df.empty:
        return []
    safe = df.copy()
    for column in safe.columns:
        safe[column] = safe[column].map(_json_safe_value)
    return safe.to_dict(orient="records")


def _json_safe_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (datetime, date, pd.Timestamp)):
        return value.isoformat()
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return None
    if pd.isna(value):
        return None
    return value
