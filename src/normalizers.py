from __future__ import annotations

import ast
import json
import re
from collections import Counter
from typing import Any

import pandas as pd

from .policy_mapping import normalize_key, resolve_setting_label
from .utils import as_datetime, flatten_json, normalize_platform, normalize_version, pick


def _coerce_structured(value: Any) -> Any:
    """Best-effort parser for CSV demo values that contain Python/JSON literals."""
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text or text[0] not in "[{":
        return value
    try:
        return ast.literal_eval(text)
    except (ValueError, SyntaxError):
        return value


def _list_text(value: Any, *, name_key: str = "name") -> str:
    value = _coerce_structured(value)
    if isinstance(value, list):
        items: list[str] = []
        for item in value:
            if isinstance(item, dict):
                candidate = item.get(name_key) or item.get("id") or item.get("value")
                if candidate not in (None, ""):
                    items.append(str(candidate))
            elif item not in (None, ""):
                items.append(str(item))
        return ", ".join(items)
    if isinstance(value, dict):
        return str(value.get(name_key) or value.get("id") or value.get("value") or "")
    return str(value or "")


def _policy_display(record: dict[str, Any], policy_type: str, direct_paths: list[str]) -> str:
    direct = pick(record, direct_paths, None)
    direct = _coerce_structured(direct)
    if isinstance(direct, dict):
        name = direct.get("policy_name") or direct.get("name") or direct.get("policy_id") or direct.get("id")
        if name:
            return str(name)
    elif direct not in (None, ""):
        return str(direct)

    policies = _coerce_structured(record.get("policies"))
    if isinstance(policies, dict):
        candidates = [policy_type, policy_type.replace("_", "-"), policy_type.replace("_", " ")]
        for candidate in candidates:
            item = policies.get(candidate)
            if isinstance(item, dict):
                name = item.get("policy_name") or item.get("name") or item.get("policy_id") or item.get("id")
                if name:
                    return str(name)
            elif item not in (None, ""):
                return str(item)
    elif isinstance(policies, list):
        token = policy_type.replace("_", " ").lower()
        for item in policies:
            if not isinstance(item, dict):
                continue
            kind = str(item.get("policy_type") or item.get("type") or item.get("policy_name") or "").replace("_", " ").lower()
            if token in kind:
                name = item.get("policy_name") or item.get("name") or item.get("policy_id") or item.get("id")
                if name:
                    return str(name)
    return ""


def _rfm_values(raw: Any) -> tuple[str, str]:
    text = str(raw or "").strip().lower()
    if isinstance(raw, bool):
        text = "true" if raw else "false"
    if text in {"true", "yes", "1", "enabled", "on", "rfm"}:
        return "yes", "RFM"
    if text in {"false", "no", "0", "disabled", "off", "normal"}:
        return "no", "Normal"
    return "", "Unknown"


def normalize_hosts(records: list[dict[str, Any]]) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Normalize Hosts API entities into the exact columns required by Lampiran A."""
    report_rows: list[dict[str, Any]] = []
    raw_rows: list[dict[str, Any]] = []
    for record in records:
        raw_rows.append(flatten_json(record))
        rfm_value = pick(
            record,
            [
                "reduced_functionality_mode",
                "rfm_state",
                "rfm_status",
                "RFM",
                "status.reduced_functionality_mode",
            ],
            "",
        )
        rfm_raw, rfm_status = _rfm_values(rfm_value)

        host_groups = _list_text(pick(record, ["groups", "group_names", "host_groups", "Host Groups"], []))
        tags = _list_text(pick(record, ["tags", "falcon_tags", "Sensor Tags"], []))
        sensor_version = pick(record, ["agent_version", "sensor_version", "version", "Sensor Version"], "")
        customer_name = pick(
            record,
            ["customer_name", "Customer Name", "cid_name", "organization_name", "ou"],
            "",
        )

        report_rows.append(
            {
                "Hostname": pick(record, ["hostname", "Hostname", "device.hostname"], ""),
                "Host ID": pick(record, ["device_id", "Host ID", "id", "aid"], ""),
                "CID": pick(record, ["cid", "CID", "customer_id"], ""),
                "Customer Name": customer_name,
                "Last Seen": as_datetime(pick(record, ["last_seen", "Last Seen", "last_seen_timestamp"], None)),
                "First Seen": as_datetime(pick(record, ["first_seen", "First Seen", "first_seen_timestamp"], None)),
                "Platform": normalize_platform(pick(record, ["platform_name", "Platform", "platform", "os_platform"], "")),
                "OS Version": pick(record, ["os_version", "OS Version", "os_version_string", "os_name"], ""),
                "Type": pick(record, ["product_type_desc", "Type", "device_type", "product_type"], ""),
                "Local IP": pick(record, ["local_ip", "Local IP", "local_ip_address"], ""),
                "External IP": pick(record, ["external_ip", "External IP", "external_ip_address"], ""),
                "MAC Address": pick(record, ["mac_address", "MAC Address", "connection_mac_address"], ""),
                "Sensor Version": sensor_version,
                "Host Groups": host_groups,
                "Sensor Tags": tags,
                "Last Logged In User Account": pick(
                    record,
                    [
                        "last_logged_on_user",
                        "last_login_user",
                        "last_logged_in_user_account",
                        "Last Logged In User Account",
                        "login_history.0.user_name",
                    ],
                    "",
                ),
                "Criticality": pick(record, ["criticality", "criticality_description", "Criticality"], ""),
                "Prevention Policy": _policy_display(
                    record,
                    "prevention",
                    [
                        "policies.prevention.policy_name",
                        "prevention_policy",
                        "prevention_policy_name",
                        "Prevention Policy",
                    ],
                ),
                "Sensor Update Policy": _policy_display(
                    record,
                    "sensor_update",
                    [
                        "policies.sensor_update.policy_name",
                        "sensor_update_policy",
                        "sensor_update_policy_name",
                        "Sensor Update Policy",
                    ],
                ),
                "Content Update Policy": _policy_display(
                    record,
                    "content_update",
                    [
                        "policies.content_update.policy_name",
                        "content_update_policy",
                        "content_update_policy_name",
                        "Content Update Policy",
                    ],
                ),
                "USB Device Policy": _policy_display(
                    record,
                    "device_control",
                    [
                        "policies.device_control.policy_name",
                        "device_control_policy",
                        "usb_device_policy",
                        "USB Device Policy",
                    ],
                ),
                "Host Retention Policy": _policy_display(
                    record,
                    "host_retention",
                    [
                        "policies.host_retention.policy_name",
                        "host_retention_policy",
                        "Host Retention Policy",
                    ],
                ),
                "RFM": rfm_raw,
                "Normalized Sensor Version": normalize_version(sensor_version),
                "RFM Status": rfm_status,
                # Extra API fields retained in-memory for data quality and troubleshooting.
                "Kernel Version": pick(record, ["kernel_version", "os_version.kernel", "Kernel Version"], ""),
                "Online State": pick(record, ["online_state_api", "online_state"], ""),
                "Status": pick(record, ["status", "device_status"], ""),
            }
        )

    report = pd.DataFrame(report_rows)
    raw = pd.DataFrame(raw_rows)
    if not report.empty:
        report = report.sort_values(["Platform", "Hostname"], na_position="last").reset_index(drop=True)
    return report, raw


def _humanize_setting_name(value: Any) -> str:
    # Backward-compatible wrapper used by older imports/tests.
    from .policy_mapping import humanize_setting_id

    return humanize_setting_id(value)


def _normalize_policy_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "ON" if value else "OFF"
    if value is None:
        return ""
    text = str(value).strip()
    lowered = text.lower()
    if lowered in {"true", "enabled", "enable", "on", "yes", "1"}:
        return "ON"
    if lowered in {"false", "disabled", "disable", "off", "no", "0", "none"}:
        return "OFF"
    if not text:
        return ""
    return text.upper() if len(text) <= 80 else text


def _setting_value_details(value: Any) -> dict[str, Any]:
    """Collapse a Falcon setting value into one matrix cell.

    Falcon prevention settings are commonly returned as ``settings[].id`` plus a
    scalar or object in ``settings[].value``. The object may contain helper keys
    such as ``type``, ``value``, ``detection`` and ``prevention``. These helper
    keys describe one configuration item and must never become separate rows.
    """
    raw_value = value
    value_type = ""
    detection_value = ""
    prevention_value = ""
    primary: Any = None

    if isinstance(value, dict):
        value_type = str(value.get("type") or value.get("value_type") or "")
        for key in ("value", "enabled", "level", "mode", "setting"):
            candidate = value.get(key)
            if candidate is not None and not isinstance(candidate, (dict, list)):
                primary = candidate
                break
        detection_value = _normalize_policy_scalar(value.get("detection"))
        prevention_value = _normalize_policy_scalar(value.get("prevention"))

        if primary is not None:
            display = _normalize_policy_scalar(primary)
        elif detection_value or prevention_value:
            if detection_value and prevention_value and detection_value == prevention_value:
                display = detection_value
            elif detection_value and prevention_value:
                display = f"DET: {detection_value} / PREV: {prevention_value}"
            else:
                display = detection_value or prevention_value
        else:
            scalar_parts = []
            for key, candidate in value.items():
                if isinstance(candidate, (dict, list)) or candidate in (None, ""):
                    continue
                scalar_parts.append(f"{_humanize_setting_name(key)}: {_normalize_policy_scalar(candidate)}")
            display = " | ".join(scalar_parts)
    elif isinstance(value, list):
        display = ", ".join(_normalize_policy_scalar(item) for item in value if item not in (None, ""))
    else:
        primary = value
        display = _normalize_policy_scalar(value)

    lowered = display.strip().lower()
    if lowered == "on":
        status = "Enabled"
    elif lowered == "off":
        status = "Disabled"
    elif not lowered:
        status = "Unknown"
    elif lowered.startswith("det:"):
        pieces = [detection_value.lower(), prevention_value.lower()]
        status = "Disabled" if pieces and all(piece in {"", "off"} for piece in pieces) else "Configured"
    else:
        status = "Configured"

    try:
        raw_json = json.dumps(raw_value, ensure_ascii=False, sort_keys=True, default=str)
    except TypeError:
        raw_json = str(raw_value)
    return {
        "Current Value": display,
        "Display Value": display,
        "Configuration Status": status,
        "Value Type": value_type,
        "Detection Value": detection_value,
        "Prevention Value": prevention_value,
        "Raw Value JSON": raw_json,
    }


def extract_policy_settings(
    policy: dict[str, Any],
    *,
    platform: str = "",
    label_mapping: pd.DataFrame | None = None,
) -> list[dict[str, Any]]:
    """Extract one row per real prevention-policy configuration item.

    The official API represents policy-specific configuration as a list of
    ``{"id": ..., "value": ...}`` objects. Some older tenants/sample payloads
    return nested dictionaries. Both forms are supported. Structural helper
    fields (Type/Value/Detection/Prevention) are collapsed into a single item.
    """
    roots: list[tuple[str, Any]] = []
    for key in ("settings", "prevention_settings", "policy_settings", "platform_settings", "config"):
        if key in policy and policy[key] not in (None, {}, []):
            roots.append((key, policy[key]))
    if not roots:
        return []

    rows: list[dict[str, Any]] = []

    def add_setting(
        item_id: Any,
        item_path: str,
        value: Any,
        group: str = "",
        item_name: Any = "",
    ) -> None:
        raw_id = str(item_id or item_path.split(".")[-1]).strip()
        raw_name = str(item_name or "").strip()
        key = normalize_key(raw_id or item_path)
        if not key:
            return
        label = resolve_setting_label(
            platform=platform,
            item_id=raw_id,
            item_path=item_path,
            mapping=label_mapping,
        )
        details = _setting_value_details(value)
        mapped = str(label.get("Mapping Status") or "") == "Mapped"
        display_name = str(label.get("Display Name") or "").strip()
        section = str(label.get("Section") or "").strip()
        # The API already provides user-facing setting and section names. Use
        # those names whenever no explicit override exists in the mapping file.
        if not mapped and raw_name:
            display_name = raw_name
        if not mapped and group:
            section = str(group).strip()
        rows.append(
            {
                "Item Key": key,
                "Item Path": item_path.strip("."),
                "Setting ID": raw_id,
                "Item Name": raw_name or raw_id,
                "Display Name": display_name or _humanize_setting_name(raw_name or raw_id or item_path),
                "Section": section or "Other",
                "Sort Order": label["Sort Order"],
                "Mapping Status": label["Mapping Status"],
                "Group": group or label["Section"],
                **details,
            }
        )

    def walk(node: Any, path: str, group: str = "") -> None:
        if isinstance(node, list):
            for index, item in enumerate(node):
                item_path = f"{path}[{index}]"
                if isinstance(item, dict) and (item.get("id") or item.get("name") or item.get("setting_id")):
                    item_id = item.get("id") or item.get("name") or item.get("setting_id")
                    # CrowdStrike Prevention Policy payloads use named section
                    # containers such as {"name": "Enhanced Visibility",
                    # "settings": [...]}. A section is not a configuration item;
                    # recurse into its settings and use the section name as group.
                    nested_settings = item.get("settings")
                    if isinstance(nested_settings, list):
                        section_group = str(item.get("name") or item_id or group).strip()
                        walk(nested_settings, f"{path}.{item_id}", section_group)
                    elif "value" in item:
                        add_setting(
                            item_id,
                            f"{path}.{item_id}",
                            item.get("value"),
                            group,
                            item.get("name"),
                        )
                    else:
                        payload = {k: v for k, v in item.items() if k not in {"id", "name", "setting_id", "description"}}
                        add_setting(item_id, f"{path}.{item_id}", payload, group)
                else:
                    walk(item, item_path, group)
            return

        if isinstance(node, dict):
            # A single official-style setting object.
            item_id = node.get("id") or node.get("name") or node.get("setting_id")
            if item_id and "value" in node:
                add_setting(
                    item_id,
                    f"{path}.{item_id}",
                    node.get("value"),
                    group,
                    node.get("name"),
                )
                return

            # Compound value object belongs to its parent configuration item.
            helper_keys = {"type", "value", "enabled", "level", "mode", "detection", "prevention"}
            if set(node).intersection(helper_keys) and all(
                not isinstance(node.get(key), (dict, list)) for key in set(node).intersection(helper_keys)
            ):
                add_setting(path.split(".")[-1], path, node, group)
                return

            for key, child in node.items():
                if key in {"description", "created_by", "modified_by"} and not isinstance(child, (dict, list)):
                    continue
                child_path = f"{path}.{key}" if path else str(key)
                child_group = group or path.split(".")[-1] if path else str(key)
                if isinstance(child, (dict, list)):
                    walk(child, child_path, child_group)
                else:
                    add_setting(key, child_path, child, child_group)
            return

        if path:
            add_setting(path.split(".")[-1], path, node, group)

    for root_name, root in roots:
        walk(root, root_name)

    # Prefer one row per setting key. Keep the first occurrence because API
    # traversal is stable and duplicate helper paths may be present in combined
    # and entity payloads after merge.
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        key = str(row.get("Item Key") or "")
        if key and key not in seen:
            seen.add(key)
            unique.append(row)
    return unique


def normalize_policies(
    policies: list[dict[str, Any]],
    members: list[dict[str, Any]],
    label_mapping: pd.DataFrame | None = None,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    member_counts = Counter(str(item.get("_policy_id") or "") for item in members)
    policy_rows: list[dict[str, Any]] = []
    setting_rows: list[dict[str, Any]] = []
    raw_rows: list[dict[str, Any]] = []

    for policy in policies:
        policy_id = str(policy.get("id") or policy.get("policy_id") or "")
        platform = normalize_platform(policy.get("platform_name") or policy.get("platform"))
        raw_rows.append(flatten_json(policy))
        member_count = member_counts.get(policy_id, int(policy.get("_member_count_collected") or 0))
        enabled_value = policy.get("enabled")
        if enabled_value is None:
            enabled_value = policy.get("is_enabled")
        policy_rows.append(
            {
                "Policy ID": policy_id,
                "Policy Name": policy.get("name") or "",
                "Platform": platform,
                "Enabled": bool(enabled_value) if enabled_value is not None else None,
                "Precedence": policy.get("precedence"),
                "Description": policy.get("description") or "",
                "Created Timestamp": as_datetime(policy.get("created_timestamp")),
                "Modified Timestamp": as_datetime(policy.get("modified_timestamp")),
                "Member Count": member_count,
                "Has Hosts": member_count > 0,
            }
        )
        for setting in extract_policy_settings(policy, platform=platform, label_mapping=label_mapping):
            setting_rows.append(
                {
                    "Policy ID": policy_id,
                    "Policy Name": policy.get("name") or "",
                    "Platform": platform,
                    "Policy Enabled": bool(enabled_value) if enabled_value is not None else None,
                    "Member Count": member_count,
                    "Has Hosts": member_count > 0,
                    **setting,
                }
            )

    member_rows: list[dict[str, Any]] = []
    for member in members:
        member_rows.append(
            {
                "Policy ID": member.get("_policy_id") or "",
                "Policy Name": member.get("_policy_name") or "",
                "Platform": normalize_platform(member.get("_policy_platform") or member.get("platform_name")),
                "Device ID": pick(member, ["device_id", "id", "aid"], ""),
                "Hostname": pick(member, ["hostname", "device.hostname"], ""),
                "OS Version": pick(member, ["os_version", "os_name"], ""),
                "Sensor Version": pick(member, ["agent_version", "sensor_version"], ""),
                "Last Seen": as_datetime(pick(member, ["last_seen", "last_seen_timestamp"], None)),
            }
        )

    policies_df = pd.DataFrame(policy_rows)
    members_df = pd.DataFrame(member_rows)
    settings_df = pd.DataFrame(setting_rows)
    raw_df = pd.DataFrame(raw_rows)
    if not policies_df.empty:
        policies_df = policies_df.sort_values(["Platform", "Precedence", "Policy Name"], na_position="last").reset_index(drop=True)
    if not settings_df.empty:
        settings_df = settings_df.sort_values(
            ["Platform", "Policy Name", "Sort Order", "Section", "Display Name"], na_position="last"
        ).reset_index(drop=True)
    return policies_df, members_df, settings_df, raw_df

def _first_scalar(record: dict[str, Any], candidates: list[str], default: Any = "") -> Any:
    return pick(record, candidates, default)


def normalize_alerts(records: list[dict[str, Any]]) -> tuple[pd.DataFrame, pd.DataFrame]:
    rows: list[dict[str, Any]] = []
    raw_rows: list[dict[str, Any]] = []
    for record in records:
        raw_rows.append(flatten_json(record))
        device = record.get("device") if isinstance(record.get("device"), dict) else {}
        behaviors = record.get("behaviors") if isinstance(record.get("behaviors"), list) else []
        behavior = behaviors[0] if behaviors and isinstance(behaviors[0], dict) else {}
        mitre = record.get("mitre_attack") if isinstance(record.get("mitre_attack"), dict) else {}
        rows.append(
            {
                "Alert ID": _first_scalar(record, ["composite_id", "id", "alert_id"], ""),
                "Created Timestamp": as_datetime(_first_scalar(record, ["created_timestamp", "created_time", "first_behavior"], None)),
                "Updated Timestamp": as_datetime(_first_scalar(record, ["updated_timestamp", "updated_time", "last_behavior"], None)),
                "Status": _first_scalar(record, ["status", "state"], "Unknown"),
                "Severity": _first_scalar(record, ["severity_name", "severity", "max_severity_displayname", "max_severity"], "Unknown"),
                "Severity Score": _first_scalar(record, ["severity", "max_severity"], None),
                "Tactic": _first_scalar(record, ["tactic", "tactic_name", "mitre_attack.tactic", "behaviors.0.tactic"], behavior.get("tactic") or mitre.get("tactic") or "Unknown"),
                "Technique": _first_scalar(record, ["technique", "technique_name", "mitre_attack.technique", "behaviors.0.technique"], behavior.get("technique") or mitre.get("technique") or "Unknown"),
                "Hostname": _first_scalar(record, ["hostname", "device.hostname", "computer_name"], device.get("hostname") or "Unknown"),
                "Device ID": _first_scalar(record, ["device_id", "device.device_id", "aid"], device.get("device_id") or ""),
                "Platform": normalize_platform(_first_scalar(record, ["platform", "platform_name", "device.platform_name"], device.get("platform_name") or "Unknown")),
                "Username": _first_scalar(record, ["user_name", "username", "user.name", "behaviors.0.user_name"], behavior.get("user_name") or "Unknown"),
                "File Name": _first_scalar(record, ["file_name", "filename", "behaviors.0.filename", "process.file_name"], behavior.get("filename") or "Unknown"),
                "SHA256": _first_scalar(record, ["sha256", "behaviors.0.sha256", "process.sha256"], behavior.get("sha256") or ""),
                "Command Line": _first_scalar(record, ["command_line", "behaviors.0.cmdline", "process.command_line"], behavior.get("cmdline") or ""),
                "Product": _first_scalar(record, ["product", "product_name"], "Unknown"),
                "Detection Type": _first_scalar(record, ["type", "detection_type", "alert_type"], "Unknown"),
                "Description": _first_scalar(record, ["description", "scenario", "name"], ""),
                "Objective": _first_scalar(record, ["objective", "objective_name"], ""),
                "Pattern ID": _first_scalar(record, ["pattern_id", "behaviors.0.pattern_id"], behavior.get("pattern_id") or ""),
                "Hidden": _first_scalar(record, ["hidden", "is_hidden"], False),
            }
        )
    report = pd.DataFrame(rows)
    raw = pd.DataFrame(raw_rows)
    if not report.empty:
        report = report.drop_duplicates(subset=["Alert ID"], keep="first").reset_index(drop=True)
    return report, raw
