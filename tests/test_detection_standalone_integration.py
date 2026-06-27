from __future__ import annotations

from datetime import date

from detector.collector import FalconAlertCollector
from detector.config import ExportSettings, FalconCredentials
from src.detection_adapter import normalize_alerts_standalone
from src.excel_exporter import build_alert_workbook


class FakeAlertsService:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def get_alerts_combined(self, **kwargs):
        self.calls.append(kwargs)
        if not kwargs.get("after"):
            return {
                "status_code": 200,
                "body": {
                    "resources": [
                        {
                            "composite_id": "a-1",
                            "created_timestamp": "2026-04-01T00:00:00Z",
                            "status": "closed",
                            "severity": 85,
                            "device": {"hostname": "HOST-01", "platform_name": "Windows"},
                            "behaviors": [{"filename": "bad.exe", "cmdline": "bad.exe /x"}],
                        }
                    ],
                    "meta": {"pagination": {"after": "next-token"}},
                },
            }
        return {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "composite_id": "a-2",
                        "created_timestamp": "2026-04-02T00:00:00Z",
                        "status": "new",
                        "severity_name": "High",
                    }
                ],
                "meta": {"pagination": {}},
            },
        }


def test_standalone_flow_is_used_end_to_end() -> None:
    settings = ExportSettings(
        customer_name="PT Orang Tua Group",
        report_label="PM 1 2026",
        start_date=date(2026, 4, 1),
        end_date=date(2026, 6, 30),
        page_size=1000,
        max_records=200000,
    )
    credentials = FalconCredentials("id", "secret", "us-1")
    fake = FakeAlertsService()
    collected = FalconAlertCollector(credentials, service=fake).collect(settings)
    assert len(collected.alerts) == 2
    assert fake.calls[0]["limit"] == 1000
    assert fake.calls[1]["after"] == "next-token"
    assert "2026-03-31T17:00:00Z" in collected.fql_filter

    report, raw = normalize_alerts_standalone(collected.alerts)
    assert report.loc[0, "Hostname"] == "HOST-01"
    assert report.loc[0, "Severity Name"] == "Critical"
    assert len(raw) == 2

    workbook = build_alert_workbook(
        report,
        raw,
        {
            **settings.metadata(credentials),
            "collection_pages": collected.pages,
            "truncated": collected.truncated,
            "fql_filter": collected.fql_filter,
        },
    )
    assert workbook[:2] == b"PK"
