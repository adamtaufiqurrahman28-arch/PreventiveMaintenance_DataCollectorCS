from __future__ import annotations

from datetime import date
from typing import Callable

import pandas as pd

from detector import ExportSettings, FalconAlertCollector, FalconCredentials
from detector.normalize import normalize_alerts as normalize_standalone_alerts

from .config import FalconConnection
from .falcon_collectors import CollectionResult
from .utils import flatten_json


ProgressCallback = Callable[[str], None]


def collect_alerts_standalone(
    conn: FalconConnection,
    *,
    customer_name: str,
    report_label: str,
    start_date: date,
    end_date: date,
    utc_offset_hours: int = 7,
    time_field: str = "created_timestamp",
    page_size: int = 1000,
    max_records: int = 200_000,
    additional_fql: str | None = None,
    include_raw_json: bool = False,
    progress: ProgressCallback | None = None,
) -> CollectionResult:
    """Run the proven standalone detection flow inside the v15 UI.

    This adapter intentionally mirrors ``seraphim_detection_export_standalone``:
    - FalconPy ``Alerts.get_alerts_combined`` only
    - date-range FQL built with a numeric UTC offset
    - ``after`` token pagination
    - no Query V2 preflight, no expected-total request, no CQL/NGSIEM
    """

    credentials = FalconCredentials(
        client_id=conn.client_id,
        client_secret=conn.client_secret,
        base_url=conn.base_url,
        member_cid=conn.member_cid,
    )
    settings = ExportSettings(
        customer_name=customer_name,
        report_label=report_label,
        start_date=start_date,
        end_date=end_date,
        utc_offset_hours=int(utc_offset_hours),
        time_field=time_field,
        page_size=int(page_size),
        max_records=int(max_records),
        top_n=10,
        additional_fql=additional_fql,
        include_raw_json=bool(include_raw_json),
    )

    def progress_callback(page: int, total: int) -> None:
        if progress:
            progress(f"Page {page}: total alert terkumpul {total:,}")

    result = FalconAlertCollector(
        credentials,
        progress_callback=progress_callback,
    ).collect(settings)

    metadata = {
        **settings.metadata(credentials),
        "collector": "Standalone Detection Flow",
        "mode": "Alerts.get_alerts_combined + after pagination",
        "collection_pages": result.pages,
        "records_collected": len(result.alerts),
        "truncated": result.truncated,
        "fql_filter": result.fql_filter,
        "filter": result.fql_filter,
        "include_hidden": False,
        "source_package": "seraphim_detection_export_standalone_v1.0.0",
    }
    return CollectionResult(records=result.alerts, metadata=metadata)


def normalize_alerts_standalone(
    records: list[dict],
    *,
    include_raw_json: bool = False,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Normalize alerts with the exact standalone normalizer.

    The first DataFrame is the report-ready detail. The second is a flattened raw
    API table retained for validation and troubleshooting.
    """

    normalized = normalize_standalone_alerts(
        records,
        include_raw_json=include_raw_json,
    )
    report = pd.DataFrame(normalized)
    raw = pd.DataFrame(flatten_json(item) for item in records)
    return report, raw
