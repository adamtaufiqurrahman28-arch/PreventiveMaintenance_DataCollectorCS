from __future__ import annotations

from datetime import date
import os
from io import BytesIO
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from src.alert_analytics import alert_summary, alert_tables
from src.config import FalconConnection
from src.excel_exporter import (
    build_alert_workbook,
    build_host_sensor_workbook,
    build_policy_workbook,
    customer_filename,
    manifest_json,
)
from src.falcon_collectors import (
    collect_hosts,
    collect_prevention_policies,
    test_connections,
)
from src.normalizers import normalize_hosts, normalize_policies
from src.detection_adapter import collect_alerts_standalone, normalize_alerts_standalone
from src.package_builder import build_zip
from src.policy_assessment import assess_settings, load_baseline, policy_summary
from src.policy_mapping import (
    disabled_items_summary,
    load_label_mapping,
    policy_matrix_dataframe,
    unmapped_items,
)
from src.sensor_health import classify_sensor_health, normalize_sensor_matrix, sensor_health_summary


load_dotenv()
APP_DIR = Path(__file__).parent
DATA_DIR = APP_DIR / "data"

st.set_page_config(
    page_title="Seraphim Falcon Data Collector v15.0.6.2",
    page_icon="🛡️",
    layout="wide",
)

st.markdown(
    """
    <style>
    .block-container {max-width: 1550px; padding-top: 1rem; padding-bottom: 3rem;}
    .hero {border:1px solid #dbe4ee;border-radius:18px;padding:1rem 1.2rem;background:linear-gradient(135deg,#fff,#eef6fb);margin-bottom:.8rem;}
    .hero h1 {font-size:1.75rem;margin:0;color:#0b2e59;}
    .hero p {margin:.35rem 0 0;color:#64748b;}
    div[data-testid="stMetric"] {background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:.6rem .75rem;}
    .ok {color:#166534;font-weight:700}.warn{color:#a16207;font-weight:700}.bad{color:#b91c1c;font-weight:700}
    </style>
    """,
    unsafe_allow_html=True,
)

STEPS = [
    "1. Connection",
    "2. Collect Hosts",
    "3. Sensor Health",
    "4. Prevention Policy",
    "5. Detection Alerts",
    "6. Validate Data",
    "7. Export Excel",
]


def default_sensor_matrix() -> pd.DataFrame:
    """Built-in editable matrix; no upload is required."""
    path = DATA_DIR / "sample_sensor_matrix.csv"
    matrix = normalize_sensor_matrix(pd.read_csv(path))
    return matrix


def init_state() -> None:
    defaults: dict[str, Any] = {
        "customer_name": "PT Customer",
        "auth_client_id": (os.getenv("FALCON_CLIENT_ID") or "").strip(),
        "auth_client_secret": (os.getenv("FALCON_CLIENT_SECRET") or "").strip(),
        "auth_base_url": (os.getenv("FALCON_BASE_URL") or "us-1").strip(),
        "auth_member_cid": (os.getenv("FALCON_MEMBER_CID") or "").strip(),
        "host_report": pd.DataFrame(),
        "host_raw": pd.DataFrame(),
        "host_metadata": {},
        "sensor_matrix": default_sensor_matrix(),
        "sensor_matrix_input": default_sensor_matrix(),
        "sensor_assessment": pd.DataFrame(),
        "sensor_metadata": {},
        "policy_groups": pd.DataFrame(),
        "policy_source_records": [],
        "policy_source_members": [],
        "policy_label_mapping": load_label_mapping(DATA_DIR / "policy_setting_labels.csv"),
        "policy_label_mapping_input": load_label_mapping(DATA_DIR / "policy_setting_labels.csv"),
        "policy_members": pd.DataFrame(),
        "policy_settings": pd.DataFrame(),
        "policy_raw": pd.DataFrame(),
        "policy_metadata": {},
        "policy_baseline": pd.DataFrame(),
        "alerts_report": pd.DataFrame(),
        "alerts_raw": pd.DataFrame(),
        "alert_metadata": {},
        "exports": {},
        "logs": [],
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def log(message: str) -> None:
    st.session_state["logs"].append(message)


def connection_from_ui() -> FalconConnection:
    client_id = (st.session_state.get("auth_client_id") or os.getenv("FALCON_CLIENT_ID") or "").strip()
    client_secret = (st.session_state.get("auth_client_secret") or os.getenv("FALCON_CLIENT_SECRET") or "").strip()
    if not client_id or not client_secret:
        raise ValueError(
            "Client ID dan Client Secret belum tersedia. Isi credential pada panel Connection Settings di sidebar "
            "atau melalui file .env, lalu jalankan kembali aksi yang dipilih."
        )
    return FalconConnection(
        client_id=client_id,
        client_secret=client_secret,
        base_url=(st.session_state.get("auth_base_url") or os.getenv("FALCON_BASE_URL") or "us-1").strip(),
        member_cid=(st.session_state.get("auth_member_cid") or os.getenv("FALCON_MEMBER_CID") or "").strip() or None,
    )


def read_uploaded_table(uploaded_file) -> pd.DataFrame:
    if uploaded_file is None:
        return pd.DataFrame()
    name = uploaded_file.name.lower()
    uploaded_file.seek(0)
    if name.endswith(".csv"):
        return pd.read_csv(uploaded_file)
    return pd.read_excel(uploaded_file)


def progress_logger(prefix: str):
    placeholder = st.empty()

    def callback(message: str) -> None:
        placeholder.info(f"{prefix}: {message}")
        log(f"{prefix}: {message}")

    return callback


def reset_exports() -> None:
    st.session_state["exports"] = {}


def load_offline_demo() -> None:
    hosts_path = DATA_DIR / "sample_hosts.csv"
    matrix_path = DATA_DIR / "sample_sensor_matrix.csv"
    alerts_path = DATA_DIR / "sample_alerts.csv"
    policies_path = DATA_DIR / "sample_policies.json"
    members_path = DATA_DIR / "sample_policy_members.json"
    import json

    hosts_records = pd.read_csv(hosts_path).to_dict(orient="records")
    host_report, host_raw = normalize_hosts(hosts_records)
    st.session_state["host_report"] = host_report
    st.session_state["host_raw"] = host_raw
    st.session_state["host_metadata"] = {"collector": "Offline Demo", "records_collected": len(host_report), "filter": "sample"}

    matrix = normalize_sensor_matrix(pd.read_csv(matrix_path))
    st.session_state["sensor_matrix"] = matrix
    st.session_state["sensor_matrix_input"] = matrix
    st.session_state.pop("sensor_matrix_editor_widget", None)
    st.session_state["sensor_assessment"] = classify_sensor_health(
        host_report, matrix, date.today(), missing_version_policy="Unsupported"
    )
    st.session_state["sensor_metadata"] = {
        "assessment_date": date.today().isoformat(),
        "missing_version_policy": "Unsupported",
    }

    policies = json.loads(policies_path.read_text(encoding="utf-8"))
    members = json.loads(members_path.read_text(encoding="utf-8"))
    groups, policy_members, settings, raw = normalize_policies(
        policies, members, st.session_state["policy_label_mapping"]
    )
    st.session_state["policy_source_records"] = policies
    st.session_state["policy_source_members"] = members
    st.session_state["policy_groups"] = groups
    st.session_state["policy_members"] = policy_members
    st.session_state["policy_settings"] = assess_settings(settings, pd.DataFrame())
    st.session_state["policy_raw"] = raw
    st.session_state["policy_metadata"] = {"collector": "Offline Demo", "records_collected": len(groups)}

    alert_records = pd.read_csv(alerts_path).to_dict(orient="records")
    alerts, raw_alerts = normalize_alerts_standalone(alert_records)
    st.session_state["alerts_report"] = alerts
    st.session_state["alerts_raw"] = raw_alerts
    st.session_state["alert_metadata"] = {
        "collector": "Offline Demo",
        "records_collected": len(alerts),
        "collection_pages": 0,
        "truncated": False,
        "mode": "Standalone sample data",
        "filter": "sample",
        "fql_filter": "sample",
        "include_hidden": False,
    }
    reset_exports()
    log("Offline demo dimuat.")


init_state()

st.markdown(
    '<div class="hero"><h1>Seraphim Falcon Data Collector v15.0.6.2</h1><p>Menghasilkan tiga lampiran PM: Host & Sensor Health, Prevention Policy, dan Detection Alerts API. Prevention Policy kini menampilkan satu baris per configuration item, matrix policy, serta daftar item OFF/disabled.</p></div>',
    unsafe_allow_html=True,
)

with st.sidebar:
    step = st.radio("Workflow", STEPS)
    st.divider()
    st.text_input("Customer", key="customer_name")
    with st.expander("Connection Settings", expanded=(step == "1. Connection")):
        st.text_input("Client ID", key="auth_client_id")
        st.text_input("Client Secret", key="auth_client_secret", type="password")
        st.selectbox(
            "Cloud / Base URL",
            ["us-1", "us-2", "eu-1", "us-gov-1"],
            key="auth_base_url",
        )
        st.text_input("Member CID (opsional)", key="auth_member_cid")
        st.caption("Credential tetap tersedia saat berpindah langkah workflow dan tidak disimpan ke file output.")
    if st.button("Muat Offline Demo", use_container_width=True):
        load_offline_demo()
        st.rerun()
    if st.button("Reset Data", use_container_width=True):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()
    st.divider()
    st.caption("Scope minimal: Hosts Read, Prevention Policies Read, Alerts Read.")


if step == "1. Connection":
    st.subheader("1. CrowdStrike Connection")
    st.info(
        "Isi credential pada panel **Connection Settings** di sidebar. Credential tetap tersedia saat Anda "
        "berpindah ke langkah Collect Hosts, Prevention Policy, dan Detection Alerts."
    )
    c1, c2, c3 = st.columns(3)
    c1.metric("Client ID", "Terisi" if st.session_state.get("auth_client_id") else "Belum diisi")
    c2.metric("Client Secret", "Terisi" if st.session_state.get("auth_client_secret") else "Belum diisi")
    c3.metric("Cloud", st.session_state.get("auth_base_url", "us-1"))

    if st.button("Test 3 API Scopes", type="primary"):
        try:
            checks = test_connections(connection_from_ui())
            for label, result in checks.items():
                if result["ok"]:
                    st.success(f"{label}: OK (HTTP {result['status_code']})")
                else:
                    st.error(f"{label}: gagal (HTTP {result['status_code']}) — {result['errors']}")
        except Exception as exc:
            st.error(str(exc))

    st.markdown("""
    **API scopes yang harus di-enable:**
    - `Hosts — Read`
    - `Prevention Policies — Read`
    - `Alerts — Read`

    Tidak membutuhkan NGSIEM, CQL, Alerts Write, Hosts Write, RTR, atau Prevention Policies Write.
    """)

elif step == "2. Collect Hosts":
    st.subheader("2. Tarik Detail Host")
    st.caption("Collector memakai Hosts API: query IDs dengan scroll pagination, lalu PostDeviceDetailsV2 untuk full detail.")
    c1, c2, c3 = st.columns(3)
    with c1:
        host_filter = st.text_input("Host FQL Filter (opsional)", value="")
    with c2:
        max_hosts = st.number_input("Max Records (0 = semua)", min_value=0, value=0, step=1000)
    with c3:
        include_online = st.checkbox("Ambil Online State", value=True)
    if st.button("Pull Host Data", type="primary"):
        try:
            result = collect_hosts(
                connection_from_ui(),
                fql_filter=host_filter.strip() or None,
                max_records=int(max_hosts) or None,
                include_online_state=include_online,
                progress=progress_logger("Hosts"),
            )
            report, raw = normalize_hosts(result.records)
            st.session_state["host_report"] = report
            st.session_state["host_raw"] = raw
            st.session_state["host_metadata"] = result.metadata
            st.session_state["sensor_assessment"] = pd.DataFrame()
            reset_exports()
            st.success(f"Berhasil menarik {len(report):,} host.")
        except Exception as exc:
            st.exception(exc)

    hosts = st.session_state["host_report"]
    if not hosts.empty:
        metrics = st.columns(5)
        metrics[0].metric("Total Host", f"{len(hosts):,}")
        metrics[1].metric("Windows", f"{hosts['Platform'].eq('Windows').sum():,}")
        metrics[2].metric("Mac", f"{hosts['Platform'].eq('Mac').sum():,}")
        metrics[3].metric("Linux", f"{hosts['Platform'].eq('Linux').sum():,}")
        metrics[4].metric("RFM", f"{hosts['RFM Status'].eq('RFM').sum():,}")
        st.dataframe(hosts, use_container_width=True, height=520)

elif step == "3. Sensor Health":
    st.subheader("3. Sensor Health Check")
    st.info(
        "Sensor Release Matrix sekarang tersedia sebagai tabel editable di aplikasi. "
        "Tambah, ubah, atau hapus baris langsung di bawah—tidak perlu upload CSV/XLSX."
    )
    if st.session_state["host_report"].empty:
        st.warning("Tarik Host Data terlebih dahulu.")

    matrix_source = st.session_state.get("sensor_matrix_input")
    if not isinstance(matrix_source, pd.DataFrame) or matrix_source.empty:
        matrix_source = default_sensor_matrix()

    matrix_editor = st.data_editor(
        matrix_source,
        key="sensor_matrix_editor_widget",
        num_rows="dynamic",
        use_container_width=True,
        hide_index=True,
        column_config={
            "Platform": st.column_config.SelectboxColumn(
                "Platform", options=["Windows", "Mac", "Linux"], required=True, width="small"
            ),
            "Version": st.column_config.TextColumn(
                "Version", help="Contoh: 7.38.21003", required=True, width="medium"
            ),
            "Release Channel": st.column_config.SelectboxColumn(
                "Release Channel",
                options=["Regular", "LTS", "Hotfix", "Legacy Hotfix"],
                required=True,
                width="medium",
            ),
            "Release Date": st.column_config.DateColumn(
                "Release Date", format="DD/MM/YYYY", required=True, width="medium"
            ),
            "End of Support": st.column_config.DateColumn(
                "End of Support", format="DD/MM/YYYY", required=True, width="medium"
            ),
        },
    )

    b1, b2, b3 = st.columns([1, 1, 2])
    with b1:
        if st.button("Simpan Sensor Matrix", use_container_width=True):
            try:
                normalized = normalize_sensor_matrix(matrix_editor)
                st.session_state["sensor_matrix"] = normalized
                st.session_state["sensor_matrix_input"] = normalized
                reset_exports()
                st.success(f"Sensor Matrix tersimpan: {len(normalized):,} versi.")
            except Exception as exc:
                st.error(str(exc))
    with b2:
        if st.button("Reset Matrix Default", use_container_width=True):
            default_matrix = default_sensor_matrix()
            st.session_state["sensor_matrix"] = default_matrix
            st.session_state["sensor_matrix_input"] = default_matrix
            st.session_state.pop("sensor_matrix_editor_widget", None)
            reset_exports()
            st.rerun()
    with b3:
        st.caption(
            "Status support dihitung dengan exact match Platform + Major.Minor + Build. "
            "Inactive Sensor menggunakan threshold tetap >14 hari agar sama dengan format Lampiran A."
        )

    c1, c2 = st.columns(2)
    with c1:
        assessment_date = st.date_input("Assessment Date", value=date.today())
    with c2:
        missing_policy = st.selectbox(
            "Versi tidak ditemukan di matrix",
            ["Unknown", "Unsupported"],
            help="Gunakan Unsupported hanya jika matrix memang tidak menyimpan versi yang sudah EOS.",
        )

    if st.button("Run Sensor Health Check", type="primary"):
        try:
            normalized = normalize_sensor_matrix(matrix_editor)
            st.session_state["sensor_matrix"] = normalized
            st.session_state["sensor_matrix_input"] = normalized
            st.session_state["sensor_assessment"] = classify_sensor_health(
                st.session_state["host_report"],
                normalized,
                assessment_date,
                missing_version_policy=missing_policy,
                inactive_days_threshold=14,
            )
            st.session_state["sensor_metadata"] = {
                "assessment_date": assessment_date.isoformat(),
                "missing_version_policy": missing_policy,
                "inactive_threshold": 14,
                "matrix_source": "In-app editable table",
            }
            reset_exports()
            st.success("Sensor Health Check selesai.")
        except Exception as exc:
            st.exception(exc)

    assessment = st.session_state["sensor_assessment"]
    if not assessment.empty:
        summary = sensor_health_summary(assessment)
        st.dataframe(summary, use_container_width=True)
        tabs = st.tabs(["Unsupported", "RFM", "Inactive", "All Assessment", "Sensor Matrix"])
        tabs[0].dataframe(assessment[assessment["Support Status"].eq("Unsupported")], use_container_width=True, height=400)
        tabs[1].dataframe(assessment[assessment["RFM Status"].eq("RFM")], use_container_width=True, height=400)
        tabs[2].dataframe(assessment[assessment["Inactive >14 Days"].eq(True)], use_container_width=True, height=400)
        tabs[3].dataframe(assessment, use_container_width=True, height=500)
        tabs[4].dataframe(st.session_state["sensor_matrix"], use_container_width=True, height=400)

elif step == "4. Prevention Policy":
    st.subheader("4. Prevention Policy")
    st.caption(
        "API mengambil policy group, jumlah host/member, dan settings. Engine v15.0.6 "
        "mengubah settings[].id + settings[].value menjadi satu baris Configuration Item. "
        "Type, Value, Detection, dan Prevention tidak lagi muncul sebagai baris terpisah."
    )

    policy_filter = st.text_input("Policy FQL Filter (opsional)", value="")

    with st.expander("Configuration Item Label Mapping", expanded=False):
        st.info(
            "Mapping ini mengubah API setting ID menjadi nama item yang mudah dibaca. "
            "Item yang belum dikenal tetap ditampilkan menggunakan humanized fallback dan masuk tab Unmapped Items."
        )
        edited_mapping = st.data_editor(
            st.session_state["policy_label_mapping_input"],
            key="policy_label_mapping_editor_widget",
            num_rows="dynamic",
            hide_index=True,
            use_container_width=True,
            column_config={
                "Platform": st.column_config.SelectboxColumn(
                    "Platform", options=["All", "Windows", "Mac", "Linux"], required=True
                ),
                "Item Match": st.column_config.TextColumn("API ID / Match", required=True),
                "Display Name": st.column_config.TextColumn("Configuration Item", required=True),
                "Section": st.column_config.TextColumn("Section"),
                "Sort Order": st.column_config.NumberColumn("Sort Order", min_value=0, step=10),
            },
        )
        map_c1, map_c2 = st.columns(2)
        if map_c1.button("Save Mapping", use_container_width=True):
            try:
                mapping = load_label_mapping(edited_mapping)
                st.session_state["policy_label_mapping"] = mapping
                st.session_state["policy_label_mapping_input"] = mapping
                st.success(f"Mapping tersimpan di session: {len(mapping):,} rule.")
            except Exception as exc:
                st.error(str(exc))
        if map_c2.button("Reset Built-in Mapping", use_container_width=True):
            mapping = load_label_mapping(DATA_DIR / "policy_setting_labels.csv")
            st.session_state["policy_label_mapping"] = mapping
            st.session_state["policy_label_mapping_input"] = mapping
            st.session_state.pop("policy_label_mapping_editor_widget", None)
            st.rerun()

    baseline_upload = st.file_uploader(
        "Baseline Best Practice (opsional: CSV/XLSX)",
        type=["csv", "xlsx"],
        help=(
            "Tanpa baseline, aplikasi tetap menampilkan seluruh item OFF/disabled. "
            "Dengan baseline, aplikasi juga menilai Compliant, Not Compliant, atau Excluded."
        ),
    )
    if baseline_upload is not None:
        try:
            st.session_state["policy_baseline"] = load_baseline(read_uploaded_table(baseline_upload))
            st.success(f"Baseline terbaca: {len(st.session_state['policy_baseline']):,} rule.")
        except Exception as exc:
            st.error(str(exc))

    pull_col, rebuild_col = st.columns(2)
    if pull_col.button("Pull Prevention Policies", type="primary", use_container_width=True):
        try:
            # Always use the latest mapping shown in the GUI.
            current_mapping = load_label_mapping(edited_mapping)
            st.session_state["policy_label_mapping"] = current_mapping
            st.session_state["policy_label_mapping_input"] = current_mapping
            policy_result, member_result = collect_prevention_policies(
                connection_from_ui(),
                fql_filter=policy_filter.strip() or None,
                progress=progress_logger("Policy"),
            )
            st.session_state["policy_source_records"] = policy_result.records
            st.session_state["policy_source_members"] = member_result.records
            groups, members, settings, raw = normalize_policies(
                policy_result.records,
                member_result.records,
                current_mapping,
            )
            assessed = assess_settings(settings, st.session_state["policy_baseline"])
            st.session_state["policy_groups"] = groups
            st.session_state["policy_members"] = members
            st.session_state["policy_settings"] = assessed
            st.session_state["policy_raw"] = raw
            st.session_state["policy_metadata"] = {
                **policy_result.metadata,
                "member_records": len(members),
                "baseline_rules": len(st.session_state["policy_baseline"]),
                "mapping_rules": len(current_mapping),
                "normalizer": "v15.0.6 one-setting-one-row",
            }
            reset_exports()
            st.success(
                f"Berhasil menarik {len(groups):,} policy group, {len(members):,} membership record, "
                f"dan {len(settings):,} configuration record."
            )
        except Exception as exc:
            st.exception(exc)

    if rebuild_col.button(
        "Rebuild Matrix dari Data Terakhir",
        use_container_width=True,
        disabled=not bool(st.session_state.get("policy_source_records")),
        help="Menerapkan mapping terbaru tanpa memanggil API kembali.",
    ):
        try:
            current_mapping = load_label_mapping(edited_mapping)
            st.session_state["policy_label_mapping"] = current_mapping
            st.session_state["policy_label_mapping_input"] = current_mapping
            groups, members, settings, raw = normalize_policies(
                st.session_state["policy_source_records"],
                st.session_state["policy_source_members"],
                current_mapping,
            )
            assessed = assess_settings(settings, st.session_state["policy_baseline"])
            st.session_state["policy_groups"] = groups
            st.session_state["policy_members"] = members
            st.session_state["policy_settings"] = assessed
            st.session_state["policy_raw"] = raw
            st.session_state["policy_metadata"] = {
                **st.session_state.get("policy_metadata", {}),
                "mapping_rules": len(current_mapping),
                "normalizer": "v15.0.6 one-setting-one-row",
            }
            reset_exports()
            st.success("Matrix dibangun ulang menggunakan mapping terbaru.")
        except Exception as exc:
            st.exception(exc)

    groups = st.session_state["policy_groups"]
    settings = st.session_state["policy_settings"]
    if not groups.empty:
        summary = policy_summary(groups, settings)
        disabled = disabled_items_summary(settings)
        unmapped = unmapped_items(settings)
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Policy Groups", f"{len(groups):,}")
        m2.metric("Enabled Groups", f"{groups['Enabled'].eq(True).sum():,}")
        m3.metric("Groups with Hosts", f"{groups['Has Hosts'].eq(True).sum():,}")
        m4.metric("Disabled Items", f"{len(disabled):,}")
        m5.metric("Unmapped Labels", f"{len(unmapped):,}")
        st.dataframe(summary, use_container_width=True)

        platform_tabs = st.tabs(["Windows Matrix", "Linux Matrix", "Mac Matrix"])
        for tab, platform in zip(platform_tabs, ["Windows", "Linux", "Mac"]):
            matrix = policy_matrix_dataframe(groups, settings, platform)
            if matrix.empty:
                tab.info(f"Tidak ada policy {platform}.")
                continue

            def color_policy_value(value):
                text = str(value or "").strip().upper()
                if text == "ON" or text == "ENABLED":
                    return "background-color: #C6EFCE; font-weight: 700;"
                if text == "OFF" or text == "DISABLED":
                    return "background-color: #C00000; color: white; font-weight: 700;"
                if text and text not in {"NAN"} and not text.isdigit():
                    return "background-color: #FFF2CC;"
                return ""

            # Pandas Styler requires both index and columns to be unique.
            # policy_matrix_dataframe already disambiguates duplicate policy names;
            # reset_index is retained as a final GUI safeguard.
            matrix = matrix.reset_index(drop=True)
            if not matrix.columns.is_unique:
                seen: dict[str, int] = {}
                safe_columns: list[str] = []
                for column in map(str, matrix.columns):
                    seen[column] = seen.get(column, 0) + 1
                    safe_columns.append(column if seen[column] == 1 else f"{column} ({seen[column]})")
                matrix.columns = safe_columns
            tab.dataframe(matrix.style.map(color_policy_value), use_container_width=True, height=620)

        tabs = st.tabs([
            "Policy Groups",
            "Disabled Items",
            "Not Compliant",
            "Policy Members",
            "All Settings",
            "Unmapped Items",
        ])
        tabs[0].dataframe(groups, use_container_width=True, height=420)
        tabs[1].dataframe(disabled, use_container_width=True, height=500)
        non_compliant = (
            settings[settings["Baseline Status"].eq("Not Compliant")]
            if not settings.empty and "Baseline Status" in settings
            else pd.DataFrame()
        )
        tabs[2].dataframe(non_compliant, use_container_width=True, height=500)
        tabs[3].dataframe(st.session_state["policy_members"], use_container_width=True, height=500)
        tabs[4].dataframe(settings, use_container_width=True, height=500)
        tabs[5].dataframe(unmapped, use_container_width=True, height=500)

elif step == "5. Detection Alerts":
    st.subheader("5. Detection — Standalone Alerts API Flow")
    st.success(
        "Detection sekarang memakai flow yang sama dengan "
        "seraphim_detection_export_standalone_v1.0.0 yang sudah running."
    )
    st.caption(
        "FalconPy Alerts.get_alerts_combined → FQL periode → pagination token after → "
        "normalisasi standalone. Tidak memakai Query V2, expected-total preflight, CQL, atau NGSIEM."
    )

    c1, c2, c3 = st.columns(3)
    with c1:
        start_date = st.date_input("Start Date", value=date.today().replace(day=1), key="alert_start")
        customer_for_detection = st.text_input(
            "Customer Detection",
            value=st.session_state.get("customer_name", "PT Customer"),
            key="alert_customer",
        )
    with c2:
        end_date = st.date_input("End Date", value=date.today(), key="alert_end")
        report_label = st.text_input("Report Label", value="Detection Report", key="alert_report_label")
    with c3:
        utc_offset = st.number_input(
            "UTC Offset",
            min_value=-12,
            max_value=14,
            value=7,
            step=1,
            help="Untuk WIB gunakan +7. Batas tanggal akan dikonversi ke UTC oleh flow standalone.",
        )
        time_field = st.selectbox(
            "Time Field",
            ["created_timestamp", "timestamp", "updated_timestamp"],
            index=0,
        )

    with st.expander("Advanced Detection Settings", expanded=False):
        a1, a2, a3 = st.columns(3)
        with a1:
            alert_page_size = st.number_input(
                "Page Size",
                min_value=1,
                max_value=1000,
                value=1000,
                step=100,
                help="Sama seperti standalone: maksimal 1.000 alert per page.",
            )
        with a2:
            max_alerts = st.number_input(
                "Max Records",
                min_value=1,
                max_value=1_000_000,
                value=200_000,
                step=10_000,
                help="Sama seperti standalone. Jika tercapai, hasil diberi status truncated.",
            )
        with a3:
            include_raw_json = st.checkbox(
                "Include Raw JSON in Detail",
                value=False,
                help="Dapat membuat workbook jauh lebih besar.",
            )
        additional_fql = st.text_input("Additional FQL Filter (opsional)", value="")

    if st.button("Pull Alerts — Standalone Flow", type="primary"):
        try:
            result = collect_alerts_standalone(
                connection_from_ui(),
                customer_name=customer_for_detection,
                report_label=report_label,
                start_date=start_date,
                end_date=end_date,
                utc_offset_hours=int(utc_offset),
                time_field=time_field,
                page_size=int(alert_page_size),
                max_records=int(max_alerts),
                additional_fql=additional_fql.strip() or None,
                include_raw_json=include_raw_json,
                progress=progress_logger("Alerts"),
            )
            report, raw = normalize_alerts_standalone(
                result.records,
                include_raw_json=include_raw_json,
            )
            st.session_state["alerts_report"] = report
            st.session_state["alerts_raw"] = raw
            st.session_state["alert_metadata"] = result.metadata
            reset_exports()
            st.success(
                f"Detection selesai: {len(report):,} alert dari "
                f"{result.metadata.get('collection_pages', 0):,} page."
            )
            if result.metadata.get("truncated"):
                st.warning(
                    "Hasil terpotong karena mencapai Max Records. Naikkan Max Records dan tarik ulang "
                    "bila seluruh alert harus diambil."
                )
        except Exception as exc:
            st.exception(exc)

    alerts = st.session_state["alerts_report"]
    if not alerts.empty:
        summary = alert_summary(alerts, st.session_state["alert_metadata"])
        st.dataframe(summary, use_container_width=True)
        tables = alert_tables(alerts, top_n=10)
        tabs = st.tabs(["Status", "Severity", "Tactic", "Technique", "Host", "Detail"])
        tabs[0].dataframe(tables["By Status"], use_container_width=True)
        tabs[1].dataframe(tables["By Severity"], use_container_width=True)
        tabs[2].dataframe(tables["Top Tactic"], use_container_width=True)
        tabs[3].dataframe(tables["Top Technique"], use_container_width=True)
        tabs[4].dataframe(tables["Top Host"], use_container_width=True)
        tabs[5].dataframe(alerts, use_container_width=True, height=500)

elif step == "6. Validate Data":
    st.subheader("6. Data Validation")
    host_count = len(st.session_state["host_report"])
    assessment = st.session_state["sensor_assessment"]
    policies = st.session_state["policy_groups"]
    alerts = st.session_state["alerts_report"]
    alert_meta = st.session_state["alert_metadata"]

    validation_rows = [
        ["Host Detail", "Ready" if host_count else "Missing", host_count, "Hosts API"],
        ["Sensor Matrix", "Ready" if not st.session_state["sensor_matrix"].empty else "Missing", len(st.session_state["sensor_matrix"]), "In-app editable table"],
        ["Sensor Health", "Ready" if not assessment.empty else "Missing", len(assessment), "Host + Sensor Matrix"],
        ["Prevention Policies", "Ready" if not policies.empty else "Missing", len(policies), "Prevention Policies API"],
        ["Policy Settings", "Ready" if not st.session_state["policy_settings"].empty else "Missing", len(st.session_state["policy_settings"]), "Prevention Policies API"],
        ["Alerts", "Ready" if not alerts.empty else "Missing", len(alerts), "Alerts API"],
        ["Alerts Collection", "Truncated" if alert_meta.get("truncated") else ("Collected" if len(alerts) else "Missing"), len(alerts), "Standalone Alerts API flow"],
    ]
    validation = pd.DataFrame(validation_rows, columns=["Data", "Status", "Records", "Source"])
    st.dataframe(validation, use_container_width=True)

    if not assessment.empty:
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Unsupported", f"{assessment['Support Status'].eq('Unsupported').sum():,}")
        col2.metric("RFM", f"{assessment['RFM Status'].eq('RFM').sum():,}")
        col3.metric("RFM Unknown", f"{assessment['RFM Status'].eq('Unknown').sum():,}")
        col4.metric("Inactive >14", f"{assessment['Inactive >14 Days'].sum():,}")
    if alert_meta.get("truncated"):
        st.error("Detection berhenti karena mencapai Max Records. Naikkan Max Records dan tarik ulang sebelum memakai angka untuk laporan.")

    if st.session_state["logs"]:
        with st.expander("Collection Log"):
            st.code("\n".join(st.session_state["logs"][-200:]))

elif step == "7. Export Excel":
    st.subheader("7. Export — Tiga Lampiran PM")
    st.caption(
        "Output dibuat sama seperti tiga file referensi: Lampiran A Host & Sensor Health, "
        "Lampiran B Prevention Policy, dan Lampiran C Detection Alerts."
    )
    top_n = st.number_input("Top N Detection", min_value=5, max_value=50, value=10)

    if st.button("Build 3 Excel Lampiran", type="primary"):
        try:
            customer = st.session_state["customer_name"].strip() or "Customer"
            slug = customer_filename(customer)
            excel_files: dict[str, bytes] = {}
            excel_files[f"Lampiran_A_Host_Sensor_Health_{slug}.xlsx"] = build_host_sensor_workbook(
                st.session_state["sensor_assessment"],
                st.session_state["sensor_matrix"],
                st.session_state["host_metadata"],
                st.session_state["sensor_metadata"],
                customer_name=customer,
            )
            excel_files[f"Lampiran_B_Prevention_Policy_{slug}.xlsx"] = build_policy_workbook(
                st.session_state["policy_groups"],
                st.session_state["policy_members"],
                st.session_state["policy_settings"],
                st.session_state["policy_raw"],
                st.session_state["policy_metadata"],
            )
            excel_files[f"Lampiran_C_Detection_Alerts_{slug}.xlsx"] = build_alert_workbook(
                st.session_state["alerts_report"],
                st.session_state["alerts_raw"],
                st.session_state["alert_metadata"],
                top_n=int(top_n),
            )
            counts = {
                "hosts": len(st.session_state["host_report"]),
                "sensor_assessment": len(st.session_state["sensor_assessment"]),
                "policy_groups": len(st.session_state["policy_groups"]),
                "policy_members": len(st.session_state["policy_members"]),
                "policy_settings": len(st.session_state["policy_settings"]),
                "alerts": len(st.session_state["alerts_report"]),
            }
            try:
                safe_connection = connection_from_ui().safe_dict()
            except Exception:
                safe_connection = {"base_url": st.session_state.get("auth_base_url", "us-1")}
            package_files = dict(excel_files)
            package_files["collection_manifest.json"] = manifest_json(
                customer_name=customer,
                connection_safe=safe_connection,
                host_metadata=st.session_state["host_metadata"],
                policy_metadata=st.session_state["policy_metadata"],
                alert_metadata=st.session_state["alert_metadata"],
                counts=counts,
            )
            package_files["README.txt"] = (
                "Seraphim Falcon Data Collector v15.0.6.2\n"
                "Paket berisi tiga lampiran PM: Host & Sensor Health, Prevention Policy, dan Detection Alerts API.\n"
                "Sensor Matrix diinput langsung melalui tabel aplikasi. Detection memakai flow standalone Alerts API.\n"
                "Credential CrowdStrike tidak disimpan pada output.\n"
            ).encode("utf-8")
            exports = dict(excel_files)
            exports[f"Seraphim_Falcon_PM_Data_{slug}.zip"] = build_zip(package_files)
            st.session_state["exports"] = exports
            st.success("Tiga lampiran Excel selesai dibuat.")
        except Exception as exc:
            st.exception(exc)

    exports = st.session_state["exports"]
    if exports:
        for name, content in exports.items():
            mime = "application/zip" if name.endswith(".zip") else "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            st.download_button(
                f"Download {name}",
                data=content,
                file_name=name,
                mime=mime,
                use_container_width=True,
            )

