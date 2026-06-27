from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Iterable


def _dig(data: Any, path: str) -> Any:
    current = data
    for part in path.split("."):
        if isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError, TypeError):
                return None
        elif isinstance(current, dict):
            current = current.get(part)
        else:
            return None
        if current is None:
            return None
    return current


def _first(data: dict[str, Any], paths: Iterable[str], default: Any = "") -> Any:
    for path in paths:
        value = _dig(data, path)
        if value not in (None, "", [], {}):
            return value
    return default


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ", ".join(_text(v) for v in value if v not in (None, ""))
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return str(value).strip()


def _severity_name(raw_name: Any, raw_score: Any) -> str:
    name = _text(raw_name)
    if name:
        return name.replace("_", " ").title()
    try:
        score = float(raw_score)
    except (TypeError, ValueError):
        return "Unknown"
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    if score >= 20:
        return "Low"
    return "Informational"


def _iso_text(value: Any) -> str:
    text = _text(value)
    if not text:
        return ""
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return text


def normalize_alert(alert: dict[str, Any], *, include_raw_json: bool = False) -> dict[str, Any]:
    severity_score = _first(alert, ["severity", "max_severity", "behaviors.0.severity"], "")
    record = {
        "Alert ID": _text(_first(alert, ["composite_id", "id", "aggregate_id"])),
        "Aggregate ID": _text(_first(alert, ["aggregate_id"])),
        "Created Timestamp": _iso_text(_first(alert, ["created_timestamp", "timestamp", "behaviors.0.timestamp"])),
        "Updated Timestamp": _iso_text(_first(alert, ["updated_timestamp"])),
        "Status": _text(_first(alert, ["status", "state"])).replace("_", " ").title(),
        "Severity": severity_score,
        "Severity Name": _severity_name(
            _first(alert, ["severity_name", "max_severity_displayname", "behaviors.0.severity_name"]),
            severity_score,
        ),
        "Product": _text(_first(alert, ["product", "source_product", "behaviors.0.product"])),
        "Detection Type": _text(_first(alert, ["type", "alert_type", "behaviors.0.type"])),
        "Tactic": _text(_first(alert, ["tactic", "behaviors.0.tactic"])),
        "Tactic ID": _text(_first(alert, ["tactic_id", "behaviors.0.tactic_id"])),
        "Technique": _text(_first(alert, ["technique", "behaviors.0.technique"])),
        "Technique ID": _text(_first(alert, ["technique_id", "behaviors.0.technique_id"])),
        "Objective": _text(_first(alert, ["objective", "behaviors.0.objective"])),
        "Scenario": _text(_first(alert, ["scenario", "behaviors.0.scenario"])),
        "Hostname": _text(_first(alert, ["device.hostname", "hostname", "host_name", "behaviors.0.device.hostname"])),
        "Device ID": _text(_first(alert, ["device.device_id", "device_id", "aid", "behaviors.0.device_id"])),
        "Platform": _text(_first(alert, ["device.platform_name", "platform", "platform_name"])),
        "OS Version": _text(_first(alert, ["device.os_version", "os_version"])),
        "Local IP": _text(_first(alert, ["device.local_ip", "local_ip"])),
        "External IP": _text(_first(alert, ["device.external_ip", "external_ip"])),
        "Username": _text(_first(alert, ["user_name", "username", "user.name", "behaviors.0.user_name"])),
        "Process Name": _text(_first(alert, ["process_name", "behaviors.0.process_name", "behaviors.0.filename"])),
        "File Name": _text(_first(alert, ["filename", "file_name", "behaviors.0.filename"])),
        "File Path": _text(_first(alert, ["filepath", "file_path", "behaviors.0.filepath"])),
        "Command Line": _text(_first(alert, ["cmdline", "command_line", "behaviors.0.cmdline"])),
        "SHA256": _text(_first(alert, ["sha256", "file_sha256", "behaviors.0.sha256"])),
        "MD5": _text(_first(alert, ["md5", "file_md5", "behaviors.0.md5"])),
        "Assigned To": _text(_first(alert, ["assigned_to_name", "assigned_to", "assigned_to_uuid"])),
        "Description": _text(_first(alert, ["description", "name", "behaviors.0.description"])),
        "Disposition": _text(_first(alert, ["pattern_disposition_description", "disposition_name"])),
        "Resolution": _text(_first(alert, ["resolution", "resolution_name"])),
        "Tags": _text(_first(alert, ["tags"])),
    }
    if include_raw_json:
        record["Raw JSON"] = json.dumps(alert, ensure_ascii=False, default=str)
    return record


def normalize_alerts(
    alerts: list[dict[str, Any]], *, include_raw_json: bool = False
) -> list[dict[str, Any]]:
    return [normalize_alert(alert, include_raw_json=include_raw_json) for alert in alerts]
