from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pandas as pd

from src.excel_exporter import build_alert_workbook, build_host_sensor_workbook, build_policy_workbook
from src.normalizers import normalize_hosts, normalize_policies
from src.policy_assessment import assess_settings, load_baseline
from src.policy_mapping import load_label_mapping
from src.sensor_health import classify_sensor_health, normalize_sensor_matrix
from src.detection_adapter import normalize_alerts_standalone

ROOT = Path(__file__).parent
DATA = ROOT / "data"
OUT = ROOT / "output"
OUT.mkdir(exist_ok=True)

for old in OUT.glob("*.xlsx"):
    old.unlink()

host_records = pd.read_csv(DATA / "sample_hosts.csv").to_dict(orient="records")
hosts, host_raw = normalize_hosts(host_records)
matrix = normalize_sensor_matrix(pd.read_csv(DATA / "sample_sensor_matrix.csv"))
assessment = classify_sensor_health(hosts, matrix, date.today(), missing_version_policy="Unsupported")

policies = json.loads((DATA / "sample_policies.json").read_text())
members = json.loads((DATA / "sample_policy_members.json").read_text())
mapping = load_label_mapping(DATA / "policy_setting_labels.csv")
groups, member_df, settings, policy_raw = normalize_policies(policies, members, mapping)
baseline = load_baseline(pd.read_csv(DATA / "policy_baseline_template.csv"))
assessed = assess_settings(settings, baseline)

alert_records = pd.read_csv(DATA / "sample_alerts.csv").to_dict(orient="records")
alerts, alert_raw = normalize_alerts_standalone(alert_records)
alert_meta = {
    "customer_name": "PT Demo",
    "report_label": "Detection Report",
    "start_date": "2026-04-01",
    "end_date": "2026-06-30",
    "base_url": "us-1",
    "member_cid": "",
    "collection_pages": 1,
    "truncated": False,
    "fql_filter": "sample",
}

files = {
    "Lampiran_A_Host_Sensor_Health_PT_Demo.xlsx": build_host_sensor_workbook(
        assessment,
        matrix,
        {"collector": "Demo", "records_collected": len(hosts), "source": "Demo Hosts API"},
        {"assessment_date": date.today().isoformat(), "missing_version_policy": "Unsupported"},
        customer_name="PT Demo",
    ),
    "Lampiran_B_Prevention_Policy_PT_Demo.xlsx": build_policy_workbook(
        groups, member_df, assessed, policy_raw, {"collector": "Demo"}
    ),
    "Lampiran_C_Detection_Alerts_PT_Demo.xlsx": build_alert_workbook(alerts, alert_raw, alert_meta),
}
for name, content in files.items():
    (OUT / name).write_bytes(content)
print({name: len(content) for name, content in files.items()})
