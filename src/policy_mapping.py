from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pandas as pd

MAPPING_COLUMNS = ["Platform", "Item Match", "Display Name", "Section", "Sort Order"]


def normalize_key(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"\[[0-9]+\]", "", text)
    text = re.sub(r"[^a-z0-9]+", "_", text)
    return re.sub(r"_+", "_", text).strip("_")


def humanize_setting_id(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    # Use final path component for fallback labels.
    text = re.sub(r"\[[0-9]+\]", "", text)
    if "." in text:
        text = text.split(".")[-1]
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    text = text.replace("_", " ").replace("-", " ")
    text = re.sub(r"\s+", " ", text).strip()
    acronyms = {
        "dll": "DLL", "wsl2": "WSL2", "bios": "BIOS", "http": "HTTP", "tls": "TLS",
        "usb": "USB", "aslr": "ASLR", "dep": "DEP", "seh": "SEH", "cpu": "CPU",
        "php": "PHP", "dbus": "D-BUS", "ml": "ML", "pup": "PUP", "ndr": "NDR",
    }
    words = []
    for word in text.split():
        words.append(acronyms.get(word.lower(), word.capitalize()))
    return " ".join(words)


def load_label_mapping(source: str | Path | pd.DataFrame | None) -> pd.DataFrame:
    if source is None:
        return pd.DataFrame(columns=MAPPING_COLUMNS)
    if isinstance(source, pd.DataFrame):
        df = source.copy()
    else:
        path = Path(source)
        if not path.exists():
            return pd.DataFrame(columns=MAPPING_COLUMNS)
        df = pd.read_csv(path)
    for column in MAPPING_COLUMNS:
        if column not in df:
            df[column] = "" if column != "Sort Order" else 9999
    df = df[MAPPING_COLUMNS].copy()
    df["Platform"] = df["Platform"].fillna("All").astype(str).str.strip().replace("", "All")
    df["Item Match"] = df["Item Match"].fillna("").astype(str).str.strip()
    df["Display Name"] = df["Display Name"].fillna("").astype(str).str.strip()
    df["Section"] = df["Section"].fillna("Other").astype(str).str.strip().replace("", "Other")
    df["Sort Order"] = pd.to_numeric(df["Sort Order"], errors="coerce").fillna(9999).astype(int)
    return df[df["Item Match"].ne("")].reset_index(drop=True)


def resolve_setting_label(
    *,
    platform: str,
    item_id: Any,
    item_path: Any,
    mapping: pd.DataFrame | None,
) -> dict[str, Any]:
    raw_id = str(item_id or "").strip()
    raw_path = str(item_path or "").strip()
    id_key = normalize_key(raw_id)
    path_key = normalize_key(raw_path)
    candidates = [id_key, path_key]

    mapping_df = load_label_mapping(mapping)
    if not mapping_df.empty:
        platform_key = str(platform or "").strip().lower()
        # Exact mappings first, then contains matches. Lower sort order wins.
        matches: list[tuple[int, int, pd.Series]] = []
        for _, rule in mapping_df.iterrows():
            rule_platform = str(rule.get("Platform") or "All").strip().lower()
            if rule_platform not in {"", "all", "*", platform_key}:
                continue
            token = normalize_key(rule.get("Item Match"))
            if not token:
                continue
            exact = token in candidates
            contains = any(token in candidate or candidate in token for candidate in candidates if candidate)
            if exact or contains:
                score = 0 if exact else 1
                matches.append((score, int(rule.get("Sort Order") or 9999), rule))
        if matches:
            matches.sort(key=lambda item: (item[0], item[1]))
            rule = matches[0][2]
            return {
                "Display Name": str(rule.get("Display Name") or humanize_setting_id(raw_id or raw_path)),
                "Section": str(rule.get("Section") or "Other"),
                "Sort Order": int(rule.get("Sort Order") or 9999),
                "Mapping Status": "Mapped",
            }

    return {
        "Display Name": humanize_setting_id(raw_id or raw_path),
        "Section": "Other",
        "Sort Order": 9999,
        "Mapping Status": "Humanized fallback",
    }



def _unique_policy_column_labels(policies: pd.DataFrame) -> dict[str, str]:
    """Return a stable, unique display label for every policy ID.

    CrowdStrike may contain more than one policy with the same visible name.
    Pandas Styler requires unique columns, therefore duplicate names are
    disambiguated with a short policy ID while unique names remain unchanged.
    """
    if policies is None or policies.empty:
        return {}

    rows = []
    for position, (_, policy) in enumerate(policies.iterrows(), start=1):
        policy_id = str(policy.get("Policy ID") or "").strip()
        base_name = str(policy.get("Policy Name") or "Unnamed Policy").strip() or "Unnamed Policy"
        key = base_name.casefold()
        rows.append((position, policy_id, base_name, key))

    counts: dict[str, int] = {}
    for _, _, _, key in rows:
        counts[key] = counts.get(key, 0) + 1

    labels: dict[str, str] = {}
    used: set[str] = set()
    occurrence: dict[str, int] = {}
    for position, policy_id, base_name, key in rows:
        occurrence[key] = occurrence.get(key, 0) + 1
        if counts[key] == 1:
            candidate = base_name
        else:
            short_id = policy_id[-8:] if policy_id else str(occurrence[key])
            candidate = f"{base_name} [{short_id}]"

        # Defensive fallback for empty/repeated IDs or names that already contain
        # the same suffix. Pandas/Streamlit must never receive duplicate columns.
        original = candidate
        suffix = 2
        while candidate in used:
            candidate = f"{original} ({suffix})"
            suffix += 1
        used.add(candidate)
        labels[policy_id or f"__row_{position}"] = candidate

    return labels

def policy_matrix_dataframe(
    policies: pd.DataFrame,
    settings: pd.DataFrame,
    platform: str,
    *,
    policy_ids: list[str] | None = None,
) -> pd.DataFrame:
    if policies is None or policies.empty:
        return pd.DataFrame()
    p = policies[policies["Platform"].eq(platform)].copy()
    if policy_ids:
        p = p[p["Policy ID"].astype(str).isin([str(value) for value in policy_ids])]
    if p.empty:
        return pd.DataFrame()
    p = p.sort_values(["Precedence", "Policy Name"], na_position="last").reset_index(drop=True)
    s = settings[settings["Platform"].eq(platform)].copy() if settings is not None and not settings.empty else pd.DataFrame()
    policy_labels = _unique_policy_column_labels(p)

    rows: list[dict[str, Any]] = []
    status_row: dict[str, Any] = {"Configuration Item": "Policy Status", "Best Practice": ""}
    count_row: dict[str, Any] = {"Configuration Item": "Host Count", "Best Practice": ""}
    for position, (_, policy) in enumerate(p.iterrows(), start=1):
        policy_id = str(policy.get("Policy ID") or "").strip()
        name = policy_labels.get(policy_id or f"__row_{position}", str(policy.get("Policy Name") or "Unnamed Policy"))
        enabled = policy.get("Enabled")
        status_row[name] = "Enabled" if enabled is True else "Disabled" if enabled is False else "Unknown"
        count_row[name] = int(policy.get("Member Count") or 0)
    rows.extend([status_row, count_row])

    if s.empty:
        return pd.DataFrame(rows)

    item_meta = (
        s.sort_values(["Sort Order", "Section", "Display Name", "Item Key"], na_position="last")
        .drop_duplicates("Item Key")
        [["Item Key", "Display Name", "Section", "Sort Order", "Best Practice"]]
    )
    lookup = {
        (str(row.get("Policy ID") or ""), str(row.get("Item Key") or "")): row
        for _, row in s.iterrows()
    }
    for _, item in item_meta.iterrows():
        item_key = str(item.get("Item Key") or "")
        row: dict[str, Any] = {
            "Configuration Item": str(item.get("Display Name") or item_key),
            "Best Practice": item.get("Best Practice") or "",
        }
        for position, (_, policy) in enumerate(p.iterrows(), start=1):
            policy_id = str(policy.get("Policy ID") or "").strip()
            policy_name = policy_labels.get(policy_id or f"__row_{position}", str(policy.get("Policy Name") or "Unnamed Policy"))
            setting = lookup.get((policy_id, item_key))
            row[policy_name] = "N/A" if setting is None else str(setting.get("Display Value") or setting.get("Current Value") or "")
        rows.append(row)
    policy_columns = [
        policy_labels.get(str(policy.get("Policy ID") or "").strip() or f"__row_{position}", str(policy.get("Policy Name") or "Unnamed Policy"))
        for position, (_, policy) in enumerate(p.iterrows(), start=1)
    ]
    columns = ["Configuration Item", *policy_columns, "Best Practice"]
    matrix = pd.DataFrame(rows, columns=columns).reset_index(drop=True)
    # Final defensive guarantee required by pandas Styler/Streamlit.
    if not matrix.columns.is_unique:
        seen: dict[str, int] = {}
        unique_columns: list[str] = []
        for column in map(str, matrix.columns):
            seen[column] = seen.get(column, 0) + 1
            unique_columns.append(column if seen[column] == 1 else f"{column} ({seen[column]})")
        matrix.columns = unique_columns
    return matrix


def disabled_items_summary(settings: pd.DataFrame) -> pd.DataFrame:
    columns = [
        "Platform", "Policy Name", "Policy Enabled", "Member Count", "Configuration Item",
        "Current Value", "Best Practice", "Assessment", "Section", "Setting ID", "Item Path",
    ]
    if settings is None or settings.empty:
        return pd.DataFrame(columns=columns)
    disabled = settings[settings["Configuration Status"].eq("Disabled")].copy()
    if disabled.empty:
        return pd.DataFrame(columns=columns)
    disabled["Configuration Item"] = disabled["Display Name"]
    disabled["Current Value"] = disabled.get("Display Value", disabled.get("Current Value", ""))
    disabled["Assessment"] = disabled.get("Baseline Status", "No Baseline")
    return disabled[columns].sort_values(
        ["Platform", "Policy Name", "Section", "Configuration Item"]
    ).reset_index(drop=True)


def unmapped_items(settings: pd.DataFrame) -> pd.DataFrame:
    if settings is None or settings.empty:
        return pd.DataFrame(columns=["Platform", "Setting ID", "Item Path", "Display Name"])
    result = settings[settings["Mapping Status"].ne("Mapped")][
        ["Platform", "Setting ID", "Item Path", "Display Name", "Section", "Raw Value JSON"]
    ].drop_duplicates()
    return result.sort_values(["Platform", "Display Name"]).reset_index(drop=True)
