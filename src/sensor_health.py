from __future__ import annotations

from datetime import date
from typing import Any

import pandas as pd

from .utils import normalize_platform, normalize_version


MATRIX_ALIASES = {
    "platform": ["platform", "os", "platform_name"],
    "version": ["version", "sensor version", "sensor_version", "build_version"],
    "release_channel": ["release channel", "channel", "release_channel", "type"],
    "release_date": ["release date", "release_date", "tanggal rilis"],
    "end_of_support": ["end of support", "end_of_support", "eos", "end-of-support date"],
}


def _find_column(df: pd.DataFrame, aliases: list[str]) -> str | None:
    lookup = {str(column).strip().lower(): str(column) for column in df.columns}
    for alias in aliases:
        if alias.lower() in lookup:
            return lookup[alias.lower()]
    return None


def normalize_sensor_matrix(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return pd.DataFrame(columns=["Platform", "Version", "Release Channel", "Release Date", "End of Support"])
    columns = {key: _find_column(df, aliases) for key, aliases in MATRIX_ALIASES.items()}
    required = ["platform", "version", "release_date", "end_of_support"]
    missing = [key for key in required if columns[key] is None]
    if missing:
        raise ValueError(f"Kolom Sensor Matrix belum lengkap: {', '.join(missing)}")
    result = pd.DataFrame(
        {
            "Platform": df[columns["platform"]].map(normalize_platform),
            "Version": df[columns["version"]].map(normalize_version),
            "Release Channel": df[columns["release_channel"]].astype(str) if columns["release_channel"] else "Regular",
            "Release Date": pd.to_datetime(df[columns["release_date"]], errors="coerce").dt.date,
            "End of Support": pd.to_datetime(df[columns["end_of_support"]], errors="coerce").dt.date,
        }
    )
    result = result[(result["Platform"] != "Unknown") & (result["Version"] != "")]
    result = result.drop_duplicates(subset=["Platform", "Version"], keep="first").reset_index(drop=True)
    return result


def classify_sensor_health(
    hosts: pd.DataFrame,
    matrix: pd.DataFrame,
    assessment_date: date,
    *,
    missing_version_policy: str = "Unknown",
    inactive_days_threshold: int = 14,
) -> pd.DataFrame:
    if hosts is None or hosts.empty:
        return pd.DataFrame()
    if matrix is None or matrix.empty:
        raise ValueError("Sensor Matrix belum tersedia.")
    if missing_version_policy not in {"Unknown", "Unsupported"}:
        raise ValueError("missing_version_policy harus Unknown atau Unsupported")

    matrix_lookup: dict[tuple[str, str], dict[str, Any]] = {}
    latest_lookup: dict[str, tuple[date, str]] = {}
    for row in matrix.to_dict(orient="records"):
        key = (normalize_platform(row.get("Platform")), normalize_version(row.get("Version")))
        matrix_lookup[key] = row
        release_date = row.get("Release Date")
        if isinstance(release_date, date):
            current = latest_lookup.get(key[0])
            if current is None or release_date > current[0]:
                latest_lookup[key[0]] = (release_date, key[1])

    result = hosts.copy()
    support_status: list[str] = []
    reason: list[str] = []
    release_dates: list[date | None] = []
    eos_dates: list[date | None] = []
    channels: list[str] = []
    ages: list[int | None] = []
    recencies: list[str] = []
    latest_flags: list[str] = []

    for row in result.to_dict(orient="records"):
        platform = normalize_platform(row.get("Platform"))
        version = normalize_version(row.get("Normalized Sensor Version") or row.get("Sensor Version"))
        item = matrix_lookup.get((platform, version))
        if item is None:
            support_status.append(missing_version_policy)
            reason.append("Versi tidak ditemukan pada Sensor Matrix yang diinput pada aplikasi.")
            release_dates.append(None)
            eos_dates.append(None)
            channels.append("Unknown")
            ages.append(None)
            recencies.append("Unknown")
            latest_flags.append("Unknown")
            continue
        release_date = item.get("Release Date")
        eos_date = item.get("End of Support")
        is_eos = isinstance(eos_date, date) and eos_date < assessment_date
        support_status.append("Unsupported" if is_eos else "Supported")
        reason.append("End of Support telah terlewati." if is_eos else "Exact match pada Sensor Matrix dan masih dalam masa dukungan.")
        release_dates.append(release_date)
        eos_dates.append(eos_date)
        channels.append(str(item.get("Release Channel") or "Regular"))
        age = (assessment_date - release_date).days if isinstance(release_date, date) else None
        ages.append(age)
        if age is None:
            recencies.append("Unknown")
        elif age <= 30:
            recencies.append("<=30 Hari")
        elif age <= 90:
            recencies.append("31-90 Hari")
        else:
            recencies.append(">90 Hari")
        latest_version = latest_lookup.get(platform, (None, ""))[1]
        latest_flags.append("Latest" if version == latest_version else "Not Latest")

    result["Support Status"] = support_status
    result["Support Reason"] = reason
    result["Release Channel"] = channels
    result["Release Date"] = release_dates
    result["End of Support"] = eos_dates
    result["Release Age Days"] = ages
    result["Release Recency"] = recencies
    result["Latest Status"] = latest_flags

    assessment_ts = pd.Timestamp(assessment_date, tz="UTC")
    last_seen = pd.to_datetime(result.get("Last Seen"), utc=True, errors="coerce")
    result["Inactive Days"] = ((assessment_ts - last_seen).dt.total_seconds() / 86400).round(2)
    result["Inactive >14 Days"] = result["Inactive Days"].gt(inactive_days_threshold).fillna(False)
    result["Health Priority"] = "Normal"
    result.loc[result["Inactive >14 Days"], "Health Priority"] = "High"
    result.loc[result["RFM Status"].eq("RFM"), "Health Priority"] = "Critical"
    result.loc[result["Support Status"].eq("Unsupported"), "Health Priority"] = "Critical"
    result.loc[result["RFM Status"].eq("Unknown"), "Health Priority"] = "Needs Review"

    def recommendation(row: pd.Series) -> str:
        items: list[str] = []
        if row.get("Support Status") == "Unsupported":
            items.append("Upgrade sensor ke versi supported yang kompatibel dengan OS.")
        elif row.get("Support Status") == "Unknown":
            items.append("Validasi versi terhadap Sensor Support Matrix resmi.")
        if row.get("RFM Status") == "RFM":
            if row.get("Platform") == "Mac":
                items.append("Validasi Full Disk Access, system extension, network extension, dan permission sensor.")
            elif row.get("Platform") == "Linux":
                items.append("Validasi kompatibilitas kernel/OS, service sensor, dan konektivitas Falcon Cloud.")
            else:
                items.append("Validasi service sensor, proxy/certificate, policy, dan konektivitas Falcon Cloud.")
        elif row.get("RFM Status") == "Unknown":
            items.append("Nilai RFM kosong; verifikasi di Falcon Console.")
        if bool(row.get("Inactive >14 Days")):
            items.append("Validasi status aset; re-onboard bila masih aktif atau decommission bila sudah tidak digunakan.")
        return " ".join(items) or "Monitoring berkala."

    result["Recommendation"] = result.apply(recommendation, axis=1)
    return result


def sensor_health_summary(assessment: pd.DataFrame) -> pd.DataFrame:
    if assessment is None or assessment.empty:
        return pd.DataFrame()
    rows: list[dict[str, Any]] = []
    for platform in ["Windows", "Mac", "Linux"]:
        subset = assessment[assessment["Platform"].eq(platform)]
        rows.append(
            {
                "Platform": platform,
                "Total Host": len(subset),
                "Supported": int(subset["Support Status"].eq("Supported").sum()),
                "Unsupported": int(subset["Support Status"].eq("Unsupported").sum()),
                "Unknown Support": int(subset["Support Status"].eq("Unknown").sum()),
                "RFM": int(subset["RFM Status"].eq("RFM").sum()),
                "RFM Unknown": int(subset["RFM Status"].eq("Unknown").sum()),
                "Inactive >14 Days": int(subset["Inactive >14 Days"].sum()),
                "<=30 Hari": int(subset["Release Recency"].eq("<=30 Hari").sum()),
                "31-90 Hari": int(subset["Release Recency"].eq("31-90 Hari").sum()),
                ">90 Hari": int(subset["Release Recency"].eq(">90 Hari").sum()),
            }
        )
    return pd.DataFrame(rows)
