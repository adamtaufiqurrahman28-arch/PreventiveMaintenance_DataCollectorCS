from __future__ import annotations

from typing import Any

import pandas as pd


LEVEL_ORDER = {
    "disabled": 0,
    "off": 0,
    "none": 0,
    "cautious": 1,
    "moderate": 2,
    "moderate++": 3,
    "aggressive": 4,
    "extra aggressive": 5,
    "enabled": 1,
    "on": 1,
    "true": 1,
}


def _normalize_text(value: Any) -> str:
    return str(value or "").strip().lower()


def load_baseline(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return pd.DataFrame(columns=["Platform", "Item Match", "Best Practice", "Comparison Mode", "Exclude"])
    lookup = {str(c).strip().lower(): str(c) for c in df.columns}
    platform_col = lookup.get("platform")
    item_col = lookup.get("item match") or lookup.get("item path") or lookup.get("item name") or lookup.get("item konfigurasi")
    best_col = lookup.get("best practice") or lookup.get("best_practice") or lookup.get("recommended")
    mode_col = lookup.get("comparison mode") or lookup.get("comparison_mode")
    exclude_col = lookup.get("exclude") or lookup.get("not applicable")
    if not item_col or not best_col:
        raise ValueError("Baseline membutuhkan kolom Item Match/Item Path dan Best Practice.")
    result = pd.DataFrame(
        {
            "Platform": df[platform_col].astype(str) if platform_col else "All",
            "Item Match": df[item_col].astype(str),
            "Best Practice": df[best_col],
            "Comparison Mode": df[mode_col].astype(str) if mode_col else "Exact",
            "Exclude": df[exclude_col] if exclude_col else False,
        }
    )
    return result


def assess_settings(settings: pd.DataFrame, baseline: pd.DataFrame | None) -> pd.DataFrame:
    if settings is None or settings.empty:
        return pd.DataFrame()
    result = settings.copy()
    result["Best Practice"] = ""
    result["Comparison Mode"] = ""
    result["Baseline Status"] = "No Baseline"
    result["Assessment Reason"] = "Tidak ada baseline yang cocok."
    if baseline is None or baseline.empty:
        return result

    rules = baseline.to_dict(orient="records")
    for index, row in result.iterrows():
        platform = _normalize_text(row.get("Platform"))
        path = _normalize_text(row.get("Item Path"))
        name = _normalize_text(row.get("Item Name"))
        setting_id = _normalize_text(row.get("Setting ID"))
        display_name = _normalize_text(row.get("Display Name"))
        matched = None
        for rule in rules:
            rule_platform = _normalize_text(rule.get("Platform"))
            if rule_platform not in {"", "all", "*", platform}:
                continue
            token = _normalize_text(rule.get("Item Match"))
            if token and (token in {path, name, setting_id, display_name} or token in path or token in setting_id):
                matched = rule
                break
        if matched is None:
            continue

        best = matched.get("Best Practice")
        mode = _normalize_text(matched.get("Comparison Mode") or "exact")
        exclude = bool(matched.get("Exclude")) or _normalize_text(best) in {
            "customer preference",
            "not applicable",
            "n/a",
        }
        result.at[index, "Best Practice"] = best
        result.at[index, "Comparison Mode"] = matched.get("Comparison Mode") or "Exact"
        if exclude:
            result.at[index, "Baseline Status"] = "Excluded"
            result.at[index, "Assessment Reason"] = "Dikecualikan oleh baseline."
            continue

        current_text = _normalize_text(row.get("Display Value") or row.get("Current Value"))
        best_text = _normalize_text(best)
        if mode in {"minimum", "min", "min_level", "minimum level"}:
            level_text = _normalize_text(row.get("Prevention Value") or row.get("Detection Value") or current_text)
            level_text = level_text.replace("_", " ")
            best_level_text = best_text.replace("_", " ")
            current_level = LEVEL_ORDER.get(level_text)
            best_level = LEVEL_ORDER.get(best_level_text)
            compliant = current_level is not None and best_level is not None and current_level >= best_level
            reason = f"Level saat ini {level_text or '-'}; minimum {best_level_text or '-'}"
        elif mode in {"enabled", "boolean"}:
            compliant = row.get("Configuration Status") == "Enabled"
            reason = "Item wajib Enabled."
        else:
            compliant = current_text == best_text
            reason = f"Current={current_text or '-'}; Expected={best_text or '-'}"
        result.at[index, "Baseline Status"] = "Compliant" if compliant else "Not Compliant"
        result.at[index, "Assessment Reason"] = reason
    return result


def policy_summary(policies: pd.DataFrame, assessed_settings: pd.DataFrame) -> pd.DataFrame:
    if policies is None or policies.empty:
        return pd.DataFrame()
    rows: list[dict[str, Any]] = []
    for platform in ["Windows", "Mac", "Linux"]:
        policy_subset = policies[policies["Platform"].eq(platform)]
        setting_subset = assessed_settings[assessed_settings["Platform"].eq(platform)] if assessed_settings is not None and not assessed_settings.empty else pd.DataFrame()
        applicable = setting_subset[setting_subset["Baseline Status"].isin(["Compliant", "Not Compliant"])] if not setting_subset.empty else pd.DataFrame()
        compliant = int(applicable["Baseline Status"].eq("Compliant").sum()) if not applicable.empty else 0
        assessed = len(applicable)
        rows.append(
            {
                "Platform": platform,
                "Policy Groups": len(policy_subset),
                "Enabled Policy Groups": int(policy_subset["Enabled"].eq(True).sum()),
                "Policy Groups with Hosts": int(policy_subset["Has Hosts"].eq(True).sum()),
                "Total Policy Members": int(policy_subset["Member Count"].fillna(0).sum()),
                "Disabled Items": int(setting_subset["Configuration Status"].eq("Disabled").sum()) if not setting_subset.empty else 0,
                "Assessed Items": assessed,
                "Compliant Items": compliant,
                "Not Compliant Items": assessed - compliant,
                "Compliance %": (compliant / assessed * 100) if assessed else None,
            }
        )
    return pd.DataFrame(rows)
