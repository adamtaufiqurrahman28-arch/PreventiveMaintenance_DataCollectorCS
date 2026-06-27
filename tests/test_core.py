from __future__ import annotations

import json
from datetime import date
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

import pandas as pd

from src.alert_analytics import alert_summary, alert_tables
from src.excel_exporter import (
    build_alert_workbook,
    build_host_sensor_workbook,
    build_policy_workbook,
)
from src.falcon_collectors import build_alert_date_filter
from src.normalizers import normalize_alerts, normalize_hosts, normalize_policies
from src.policy_assessment import assess_settings, load_baseline, policy_summary
from src.policy_mapping import disabled_items_summary, load_label_mapping, policy_matrix_dataframe
from src.sensor_health import classify_sensor_health, normalize_sensor_matrix, sensor_health_summary


DATA = Path(__file__).parents[1] / "data"


def workbook_sheet_names(content: bytes) -> list[str]:
    import xml.etree.ElementTree as ET

    with ZipFile(BytesIO(content)) as archive:
        root = ET.fromstring(archive.read("xl/workbook.xml"))
    ns = {"a": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    return [sheet.attrib["name"] for sheet in root.find("a:sheets", ns)]


def test_host_and_sensor_health_single_lampiran() -> None:
    host_records = pd.read_csv(DATA / "sample_hosts.csv").to_dict(orient="records")
    hosts, raw = normalize_hosts(host_records)
    matrix = normalize_sensor_matrix(pd.read_csv(DATA / "sample_sensor_matrix.csv"))
    assessment = classify_sensor_health(
        hosts,
        matrix,
        date.today(),
        missing_version_policy="Unsupported",
    )
    assert len(hosts) == 15
    assert len(raw) == 15
    assert "Support Status" in assessment.columns
    assert len(sensor_health_summary(assessment)) == 3
    assert {"Host ID", "CID", "Content Update Policy", "USB Device Policy", "Host Retention Policy"}.issubset(hosts.columns)

    workbook = build_host_sensor_workbook(
        assessment,
        matrix,
        {"collector": "test", "source": "Hosts API"},
        {"assessment_date": date.today().isoformat(), "missing_version_policy": "Unsupported"},
        customer_name="PT Demo",
    )
    assert workbook[:2] == b"PK"
    assert workbook_sheet_names(workbook) == [
        "Ringkasan",
        "All Hosts",
        "Unsupported",
        "RFM",
        "RFM Unknown",
        "Inactive >14 Hari",
        "Version Distribution",
        "Sensor Matrix",
        "Data Quality",
    ]


def test_policy_extraction_and_matrix_export() -> None:
    policies = json.loads((DATA / "sample_policies.json").read_text())
    members = json.loads((DATA / "sample_policy_members.json").read_text())
    mapping = load_label_mapping(DATA / "policy_setting_labels.csv")
    groups, member_df, settings, raw = normalize_policies(policies, members, mapping)
    baseline = load_baseline(pd.read_csv(DATA / "policy_baseline_template.csv"))
    assessed = assess_settings(settings, baseline)
    summary = policy_summary(groups, assessed)
    assert len(groups) == 3
    assert len(member_df) == 15
    assert settings["Configuration Status"].eq("Disabled").sum() >= 1
    assert not set(settings["Display Name"].str.lower()).intersection({"type", "value", "detection", "prevention"})
    assert "Enhanced DLL Load Visibility" in settings["Display Name"].values
    assert "DET: AGGRESSIVE / PREV: MODERATE" in settings["Display Value"].values
    assert len(disabled_items_summary(assessed)) >= 1
    matrix = policy_matrix_dataframe(groups, assessed, "Windows")
    assert "Enhanced DLL Load Visibility" in matrix["Configuration Item"].values
    assert "Not Compliant" in assessed["Baseline Status"].values
    assert len(summary) == 3
    workbook = build_policy_workbook(groups, member_df, assessed, raw, {"collector": "test"})
    assert workbook[:2] == b"PK"
    names = workbook_sheet_names(workbook)
    assert names[0:2] == ["Summary", "Policy Groups"]
    assert "Windows Prevention Policy" in names
    assert "Linux Prevention Policy" in names
    assert "Mac Prevention Policy" in names
    assert "Disabled Items" in names
    assert "All Settings" in names
    assert "Unmapped Items" in names


def test_alert_normalization_and_export() -> None:
    records = pd.read_csv(DATA / "sample_alerts.csv").to_dict(orient="records")
    alerts, raw = normalize_alerts(records)
    metadata = {
        "customer_name": "PT Demo",
        "report_label": "Detection Report",
        "start_date": "2026-04-01",
        "end_date": "2026-06-30",
        "base_url": "us-1",
        "collection_pages": 1,
        "truncated": False,
        "fql_filter": "sample",
    }
    assert len(alerts) == 100
    assert not alert_summary(alerts, metadata).empty
    assert "Top Host" in alert_tables(alerts)
    workbook = build_alert_workbook(alerts, raw, metadata)
    assert workbook[:2] == b"PK"
    assert workbook_sheet_names(workbook)[0:2] == ["Summary", "Alerts Detail"]


def test_alert_filter_timezone() -> None:
    fql, start, end = build_alert_date_filter(
        date(2026, 4, 1),
        date(2026, 6, 30),
        timezone_name="Asia/Jakarta",
    )
    assert "created_timestamp" in fql
    assert start.isoformat().startswith("2026-03-31T17:00:00")
    assert end.isoformat().startswith("2026-06-30T17:00:00")


def test_alert_combined_page_limit_and_413_detection() -> None:
    from src.falcon_collectors import _is_request_too_large

    assert _is_request_too_large({
        "status_code": 400,
        "body": {"errors": [{"code": 413, "message": "request too large"}]},
    })
    assert not _is_request_too_large({
        "status_code": 400,
        "body": {"errors": [{"code": 400, "message": "invalid query filter"}]},
    })



def test_policy_nested_section_payload_yields_on_off_values() -> None:
    policies = [{
        "id": "policy-real-shape",
        "name": "Workstation Policy",
        "platform_name": "Windows",
        "enabled": True,
        "_member_count_collected": 12,
        "prevention_settings": [
            {
                "name": "Enhanced Visibility",
                "settings": [
                    {
                        "id": "DLLLoadVisibility",
                        "name": "Enhanced DLL Load Visibility",
                        "type": "toggle",
                        "value": {"enabled": False},
                    },
                    {
                        "id": "ScriptBasedExecutionMonitoring",
                        "name": "Script-Based Execution Monitoring",
                        "type": "toggle",
                        "value": {"configured": True, "enabled": True},
                    },
                ],
            },
            {
                "name": "Cloud Machine Learning",
                "settings": [
                    {
                        "id": "CloudAntiMalware",
                        "name": "Cloud Anti-malware",
                        "type": "mlslider",
                        "value": {"detection": "AGGRESSIVE", "prevention": "MODERATE"},
                    }
                ],
            },
        ],
    }]
    groups, _, settings, _ = normalize_policies(policies, [], pd.DataFrame())
    assessed = assess_settings(settings, None)
    assert set(settings["Setting ID"]) == {
        "DLLLoadVisibility",
        "ScriptBasedExecutionMonitoring",
        "CloudAntiMalware",
    }
    assert not settings["Display Value"].eq("").any()
    values = dict(zip(settings["Setting ID"], settings["Display Value"]))
    assert values["DLLLoadVisibility"] == "OFF"
    assert values["ScriptBasedExecutionMonitoring"] == "ON"
    assert values["CloudAntiMalware"] == "DET: AGGRESSIVE / PREV: MODERATE"
    matrix = policy_matrix_dataframe(groups, assessed, "Windows")
    assert "OFF" in matrix["Workstation Policy"].values
    assert "ON" in matrix["Workstation Policy"].values


def test_policy_matrix_duplicate_policy_names_are_safe_for_styler() -> None:
    policies = pd.DataFrame([
        {
            "Policy ID": "policy-aaaaaaaa11111111",
            "Policy Name": "Duplicate Policy",
            "Platform": "Windows",
            "Enabled": True,
            "Member Count": 10,
            "Precedence": 1,
        },
        {
            "Policy ID": "policy-bbbbbbbb22222222",
            "Policy Name": "Duplicate Policy",
            "Platform": "Windows",
            "Enabled": True,
            "Member Count": 20,
            "Precedence": 2,
        },
    ])
    settings = pd.DataFrame([
        {
            "Policy ID": "policy-aaaaaaaa11111111",
            "Policy Name": "Duplicate Policy",
            "Platform": "Windows",
            "Item Key": "enhanced_dll_load_visibility",
            "Display Name": "Enhanced DLL Load Visibility",
            "Section": "Sensor Visibility",
            "Sort Order": 1,
            "Best Practice": "ON",
            "Display Value": "OFF",
            "Current Value": False,
        },
        {
            "Policy ID": "policy-bbbbbbbb22222222",
            "Policy Name": "Duplicate Policy",
            "Platform": "Windows",
            "Item Key": "enhanced_dll_load_visibility",
            "Display Name": "Enhanced DLL Load Visibility",
            "Section": "Sensor Visibility",
            "Sort Order": 1,
            "Best Practice": "ON",
            "Display Value": "ON",
            "Current Value": True,
        },
    ])

    matrix = policy_matrix_dataframe(policies, settings, "Windows")
    assert matrix.index.is_unique
    assert matrix.columns.is_unique
    duplicate_columns = [column for column in matrix.columns if str(column).startswith("Duplicate Policy") ]
    assert len(duplicate_columns) == 2
    assert duplicate_columns[0] != duplicate_columns[1]
    # This is the exact operation used by Streamlit before marshalling Styler.
    matrix.style.map(lambda value: "")._compute()
